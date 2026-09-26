"""INFO-001: bounded, deterministic error and information disclosure detection."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ..Authentication.authentication import AuthenticationConfig
from ..Discovery.discovery import ResolvedEndpoint
from ..Core.http_client import (
    get_with_authentication,
    redact_sensitive_text,
    sanitize_url,
)
from ..Core.models import AssessmentResult

TEST_ID = "INFO-001"
TEST_NAME = "Error and Information Disclosure Detection Test"
MAX_RESPONSE_BYTES = 65536
MAX_PREVIEW_CHARS = 220

STACK_TRACE_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PYTHON_TRACEBACK", re.compile(r"(?is)traceback\s*\(most recent call last\)|\bRuntimeError\b|\bNameError\b|\bValueError\b|\bTypeError\b|\bAttributeError\b")),
    ("JAVA_STACK_TRACE", re.compile(r"(?is)java\.(?:lang|util)\.|\b(?:Exception|Error)\s*:\s*.*\n\s+at\s+.*\(.+:\d+\)|\bat\s+.*\(.+\.java:\d+\)")),
    ("DOTNET_STACK_TRACE", re.compile(r"(?is)System\.[A-Za-z]+Exception|\bNullReferenceException\b|\bInvalidOperationException\b|\bIndexOutOfRangeException\b|\b.*\.cs:\d+")),
    ("NODE_STACK_TRACE", re.compile(r"(?is)(?:\bError:\s+.*\n\s+at\s+.*\(|\bnode:internal\b|\bECONNREFUSED\b|\bReferenceError\b|\bTypeError\b)")),
    ("PHP_STACK_TRACE", re.compile(r"(?is)(?:PHP\s+(?:Fatal|Warning|Notice)|\bStack trace:|#\d+\s+.*\(.+:\d+\))")),
    ("RUBY_STACK_TRACE", re.compile(r"(?is)(?:NameError|NoMethodError|SyntaxError|StandardError|\.rb:\d+:in|/tmp/.*\.rb:\d+)")),
)

INTERNAL_PATH_RE = re.compile(
    r"(?is)(?:/(?:home|var|opt|srv|app|workspace|root|usr|etc|tmp|sandbox)|[A-Za-z]:\\(?:Users|ProgramData|Windows|tmp|var|srv|app)|(?:[A-Za-z0-9_./-]+\.(?:py|js|ts|java|cs|php|rb|go|rs|c|cpp|h|sql)):\d+)"
)
DATABASE_ERROR_RE = re.compile(
    r"(?is)(?:PostgreSQL|MySQL|SQLite|Microsoft SQL Server|Oracle|SQLSTATE\[[A-Z0-9]+\]|syntax error at or near|ORA-\d+|SQLServer|sqlite3\.DatabaseError)"
)
INTERNAL_NETWORK_RE = re.compile(
    r"(?is)(?:\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b|\b(?:[a-z0-9-]+\.)?(?:internal|local|svc|corp|lan|home|db)\.(?:local|internal|corp|lan)\b|\b(?:db|api|web|cache|app|service|postgres|mysql)\.(?:internal|local|svc|corp|lan)\b|\b(?:host|server|service)\s*[:=]\s*(?:[a-z0-9-]+\.)?(?:internal|local|svc|corp|lan)\b)"
)
RUNTIME_DISCLOSURE_RE = re.compile(
    r"(?is)(?:debug mode|runtime\s+v?\d+\.\d+|python\s+\d+\.\d+|node\s+v?\d+\.\d+|php\s+v?\d+\.\d+|\.NET\s+runtime|aspnetcore|gunicorn|uwsgi|mod_wsgi|framework\s+.*(?:exception|error))"
)


class ErrorDisclosureTest:
    """Check GET responses for excessive internal implementation information."""

    test_id = TEST_ID
    test_name = TEST_NAME
    supported_methods = frozenset({"GET"})
    requires_authentication = False

    def execute(self, target: str) -> AssessmentResult:
        try:
            response, _ = get_with_authentication(target, AuthenticationConfig())
        except (httpx.TimeoutException, httpx.RequestError):
            return _result(
                target,
                "INCONCLUSIVE",
                "The response could not be safely analyzed because the bounded request timed out or failed.",
                {"reason": "request_failed", "request_count": 1},
            )
        return _analyze_response(target, response, method="GET")

    def execute_context(self, context: Any) -> AssessmentResult:
        return _execute_endpoint(context.endpoint, context.authentication)

    def execute_endpoint(self, endpoint: ResolvedEndpoint) -> AssessmentResult:
        return _execute_endpoint(endpoint, AuthenticationConfig())


def _execute_endpoint(endpoint: ResolvedEndpoint, authentication: AuthenticationConfig) -> AssessmentResult:
    if endpoint.method != "GET":
        return _result(
            endpoint.target,
            "UNSUPPORTED_OPERATION",
            "INFO-001 only supports GET endpoints and leaves unsupported methods unchanged.",
            {"reason": "unsupported_http_method", "request_count": 0},
        )
    if endpoint.security_defined and endpoint.security and authentication.mode == "none":
        return _result(
            endpoint.target,
            "NO_INFORMATION_DISCLOSURE_INDICATED",
            "No disclosure check was performed because the endpoint requires authenticated access and the assessment context was not supplied; the result remains conservative and non-invasive.",
            {"reason": "authentication_context_missing", "request_count": 0},
        )
    try:
        response, _ = get_with_authentication(endpoint.target, authentication)
    except (httpx.TimeoutException, httpx.RequestError):
        return _result(
            endpoint.target,
            "INCONCLUSIVE",
            "The bounded GET request timed out or failed before the response could be safely analyzed.",
            {"reason": "request_failed", "request_count": 1},
        )
    return _analyze_response(endpoint.target, response, method=endpoint.method)


def _analyze_response(target: str, response: httpx.Response, *, method: str) -> AssessmentResult:
    status_code = response.status_code
    content_type = response.headers.get("content-type", "")
    response_text = response.text or ""
    if len(response_text.encode("utf-8")) > MAX_RESPONSE_BYTES:
        return _result(
            target,
            "INCONCLUSIVE",
            "The response exceeded the safe analysis budget, so only a bounded preview could be inspected.",
            {
                "reason": "response_too_large",
                "content_type": content_type,
                "status_code": status_code,
                "request_count": 1,
            },
        )

    payload_text = _candidate_text(response_text)
    findings = _scan_for_excessive_information(payload_text, status_code)
    preview = _safe_preview(findings)
    evidence = {
        "endpoint": target,
        "http_method": method,
        "status_code": status_code,
        "content_type": content_type,
        "findings": findings,
        "request_count": 1,
        "preview": preview,
    }
    if findings:
        return _result(
            target,
            "POTENTIAL_INFORMATION_DISCLOSURE",
            "The bounded response exposed excessive internal implementation details or infrastructure information in a non-generic error context.",
            evidence,
            observed_status_code=status_code,
            content_type=content_type,
        )
    return _result(
        target,
        "NO_INFORMATION_DISCLOSURE_INDICATED",
        "The bounded response did not expose excessive internal implementation details under conservative evidence-based rules.",
        evidence,
        observed_status_code=status_code,
        content_type=content_type,
    )


def _candidate_text(response_text: str) -> str:
    if not response_text:
        return ""
    try:
        payload = json.loads(response_text)
    except (TypeError, ValueError):
        return response_text
    if isinstance(payload, (dict, list)):
        return json.dumps(payload, default=str, separators=(",", ":"))
    return str(payload)


def _scan_for_excessive_information(text: str, status_code: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not text.strip():
        return findings
    combined = text.strip()
    if status_code in {400, 401, 403, 404} and not _looks_internal_error_context(combined):
        return findings
    if status_code == 500 and not _looks_internal_error_context(combined):
        return findings
    for category, pattern in STACK_TRACE_RULES:
        if pattern.search(combined):
            indicator = _indicator_for_category(category)
            findings.append({
                "category": category,
                "indicator": indicator,
                "rule": "stack_trace_pattern",
                "path": "response_text",
            })
    if INTERNAL_PATH_RE.search(combined):
        indicator = _indicator_for_category("INTERNAL_PATH_DISCLOSURE")
        findings.append({
            "category": "INTERNAL_PATH_DISCLOSURE",
            "indicator": indicator,
            "rule": "internal_path_pattern",
            "path": "response_text",
        })
    if DATABASE_ERROR_RE.search(combined):
        indicator = _indicator_for_category("DATABASE_ERROR_DISCLOSURE")
        findings.append({
            "category": "DATABASE_ERROR_DISCLOSURE",
            "indicator": indicator,
            "rule": "database_error_pattern",
            "path": "response_text",
        })
    if INTERNAL_NETWORK_RE.search(combined):
        indicator = _indicator_for_category("INTERNAL_NETWORK_DISCLOSURE")
        findings.append({
            "category": "INTERNAL_NETWORK_DISCLOSURE",
            "indicator": indicator,
            "rule": "internal_network_pattern",
            "path": "response_text",
        })
    if RUNTIME_DISCLOSURE_RE.search(combined) and _looks_internal_error_context(combined):
        indicator = _indicator_for_category("FRAMEWORK_RUNTIME_DISCLOSURE")
        findings.append({
            "category": "FRAMEWORK_RUNTIME_DISCLOSURE",
            "indicator": indicator,
            "rule": "runtime_disclosure_pattern",
            "path": "response_text",
        })
    return _deduplicate_findings(findings)


def _indicator_for_category(category: str) -> str:
    return category.lower().replace("_", "-") + "-detected"


def _looks_internal_error_context(text: str) -> bool:
    normalized = text.lower()
    signals = (
        "traceback",
        "exception",
        "stack",
        "debug",
        "runtime",
        "failed at",
        "connect",
        "connectionerror",
        "db.",
        "internal",
        "host=",
        "service=",
        "config",
        "startup",
        "sqlstate",
        "error:",
        "exception:",
    )
    return any(signal in normalized for signal in signals)


def _bounded_indicator(value: str) -> str:
    normalized = redact_sensitive_text(value).strip()
    return normalized[:80] + ("..." if len(normalized) > 80 else "")


def _safe_preview(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "[redacted: no excessive internal indicators observed]"
    indicator_list = [str(item.get("indicator", "")).strip() for item in findings if item.get("indicator")]
    preview = " | ".join(indicator_list[:3])
    if not preview:
        return "[redacted: internal implementation detail]"
    if len(preview) <= MAX_PREVIEW_CHARS:
        return preview
    return preview[:MAX_PREVIEW_CHARS] + " ... [truncated]"


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in findings:
        key = (item.get("category", ""), item.get("indicator", ""), item.get("rule", ""), item.get("path", ""))
        if key in seen:
            continue
        seen.add(key)
        ordered.append(item)
    return ordered


def _result(
    target: str,
    status: str,
    reason: str,
    evidence: dict[str, Any] | None = None,
    *,
    observed_status_code: int | None = None,
    content_type: str | None = None,
) -> AssessmentResult:
    return AssessmentResult(
        test_id=TEST_ID,
        test_name=TEST_NAME,
        target=sanitize_url(target),
        method="GET",
        status=status,
        observed_status_code=observed_status_code,
        severity=None,
        reason=reason,
        evidence=evidence or {},
        recommendation="Review the error handling path and remove internal stack traces, private infrastructure details, and database implementation details from API responses.",
    )
