"""DATA-001: bounded, deterministic sensitive-data exposure detection."""

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
    response_evidence,
    sanitize_url,
)
from ..Core.models import AssessmentResult

TEST_ID = "DATA-001"
TEST_NAME = "Sensitive Data Exposure Detection Test"
MAX_RESPONSE_BYTES = 65536
MAX_JSON_DEPTH = 8

SENSITIVE_KEY_MAP: dict[str, set[str]] = {
    "authentication_secret": {"password", "password_hash", "passwd", "passphrase"},
    "api_token": {"access_token", "refresh_token", "id_token", "auth_token", "api_key", "secret_key"},
    "session_credential": {"session_token", "session_id", "session_secret"},
    "private_credential": {"private_key", "privatekey", "client_secret"},
    "database_credential": {"database_password", "db_password", "connection_string", "database_url"},
    "cloud_credential": {"access_key", "secret_access_key", "service_account_key"},
    "internal_infrastructure": {"internal_ip", "internal_host", "internal_hostname", "internal_service"},
}

JWT_PATTERN = re.compile(r"(?i)\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*\b")
PRIVATE_KEY_PATTERN = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
DATABASE_URL_PATTERN = re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb|redis|amqp|mssql|oracle|postgresql)://[^\s]+@")
STACKTRACE_PATTERN = re.compile(r"(?i)Traceback|File\s+\"(?:/|[A-Za-z]:\\|\\\\)")
INTERNAL_PATH_PATTERN = re.compile(r"(?i)(?:/(?:srv|var|etc|home|opt|usr|root|workspace|app)|[A-Za-z]:\\(?:Users|ProgramData|Windows|srv|var|tmp)|\\\\(?:server|internal|corp|dc))")


class SensitiveDataExposureTest:
    """Check GET responses for obvious credential-like data exposure."""

    test_id = TEST_ID
    test_name = TEST_NAME
    supported_methods = frozenset({"GET"})
    requires_authentication = False

    def execute(self, target: str) -> AssessmentResult:
        try:
            response, _ = get_with_authentication(target, AuthenticationConfig())
        except httpx.TimeoutException:
            return _result(
                target,
                "INCONCLUSIVE",
                "The bounded GET request timed out before the response could be analyzed.",
                {"reason": "timeout", "request_count": 1},
            )
        except httpx.RequestError:
            return _result(
                target,
                "NO_SENSITIVE_DATA_EXPOSURE_INDICATED",
                "The target was not reachable for the response-content scan, so no data-exposure evidence was observed.",
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
            "DATA-001 only supports GET endpoints and leaves other methods unchanged.",
            {"reason": "unsupported_http_method", "request_count": 0},
        )

    try:
        response, _ = get_with_authentication(endpoint.target, authentication)
    except httpx.TimeoutException:
        return _result(
            endpoint.target,
            "INCONCLUSIVE",
            "The bounded GET request timed out before the response could be analyzed.",
            {"reason": "timeout", "request_count": 1},
        )
    except httpx.RequestError:
        return _result(
            endpoint.target,
            "NO_SENSITIVE_DATA_EXPOSURE_INDICATED",
            "The target was not reachable for the response-content scan, so no data-exposure evidence was observed.",
            {"reason": "request_failed", "request_count": 1},
        )
    return _analyze_response(endpoint.target, response, method=endpoint.method)


def _analyze_response(target: str, response: Any, *, method: str) -> AssessmentResult:
    status_code = response.status_code
    content_type = response.headers.get("content-type", "")
    response_text = response.text or ""
    payload: Any | None = None
    if len(response_text.encode("utf-8")) > MAX_RESPONSE_BYTES:
        return _result(
            target,
            "INCONCLUSIVE",
            "The response exceeded the safe analysis budget and was not inspected beyond the bounded preview.",
            {
                "reason": "response_too_large",
                "response_size_bytes": len(response_text.encode("utf-8")),
                "content_type": content_type,
                "request_count": 1,
            },
            observed_status_code=status_code,
            content_type=content_type,
        )

    findings: list[dict[str, Any]] = []
    if response.headers.get("content-type", "").lower().startswith("application/json") or response_text.lstrip().startswith("{") or response_text.lstrip().startswith("["):
        try:
            payload = response.json()
        except (TypeError, ValueError):
            payload = None
        if payload is not None:
            findings.extend(_inspect_json(payload, depth=0))
    if not findings:
        findings.extend(_inspect_text(response_text))

    if findings:
        evidence = {
            "endpoint": target,
            "http_method": method,
            "content_type": content_type,
            "response_status": status_code,
            "findings": findings,
            "detected_category": findings[0]["category"],
            "request_count": 1,
            "analysis_mode": "json" if payload is not None else "text",
        }
        return _result(
            target,
            "POTENTIAL_SENSITIVE_DATA_EXPOSURE",
            "The bounded response contained evidence of sensitive values that are not typically intended for ordinary API consumers.",
            evidence,
            observed_status_code=status_code,
            content_type=content_type,
        )

    evidence = {
        "endpoint": target,
        "http_method": method,
        "content_type": content_type,
        "response_status": status_code,
        "findings": [],
        "detected_category": None,
        "request_count": 1,
        "analysis_mode": "json" if response_text.lstrip().startswith(("{", "[")) else "text",
    }
    return _result(
        target,
        "NO_SENSITIVE_DATA_EXPOSURE_INDICATED",
        "The bounded response did not reveal sensitive credential material under conservative evidence-based rules.",
        evidence,
        observed_status_code=status_code,
        content_type=content_type,
    )


def _inspect_json(value: Any, path: str = "", depth: int = 0) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if depth > MAX_JSON_DEPTH:
        return findings
    if isinstance(value, dict):
        for key, nested_value in value.items():
            key_path = f"{path}.{key}" if path else str(key)
            normalized = _normalize_key(key)
            category = _category_for_key(normalized)
            if category is not None and _looks_sensitive_value(normalized, nested_value):
                findings.append(_finding(category, key=str(key), path=key_path, redacted=True))
            findings.extend(_inspect_json(nested_value, key_path, depth + 1))
        return findings
    if isinstance(value, list):
        for index, item in enumerate(value):
            item_path = f"{path}[{index}]" if path else f"[{index}]"
            findings.extend(_inspect_json(item, item_path, depth + 1))
        return findings
    if isinstance(value, str):
        for category, rule in _text_rules(value).items():
            findings.append(_finding(category, key="value", path=path, redacted=True, rule=rule))
    return findings


def _inspect_text(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for category, rule in _text_rules(text).items():
        findings.append(_finding(category, key="text", path="response_text", redacted=True, rule=rule))
    return findings


def _text_rules(value: str) -> dict[str, str]:
    normalized = value.strip()
    result: dict[str, str] = {}
    if not normalized:
        return result
    if JWT_PATTERN.search(normalized):
        result["api_token"] = "jwt_like_token"
    if BEARER_PATTERN.search(normalized):
        result["api_token"] = "bearer_token_like"
    if PRIVATE_KEY_PATTERN.search(normalized):
        result["private_credential"] = "private_key_block"
    if DATABASE_URL_PATTERN.search(normalized):
        result["database_credential"] = "database_url_with_embedded_credentials"
    if STACKTRACE_PATTERN.search(normalized) and INTERNAL_PATH_PATTERN.search(normalized):
        result["internal_infrastructure"] = "stack_trace_with_internal_path"
    return result


def _category_for_key(normalized_key: str) -> str | None:
    for category, names in SENSITIVE_KEY_MAP.items():
        if normalized_key in { _normalize_key(item) for item in names }:
            return category
    return None


def _normalize_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _looks_sensitive_value(normalized_key: str, value: Any) -> bool:
    if isinstance(value, (dict, list)):
        return False
    text = str(value).strip()
    if not text or text in {"null", "none", "[REDACTED]"}:
        return False
    if normalized_key in { _normalize_key(item) for item in SENSITIVE_KEY_MAP["authentication_secret"] }:
        return True
    if normalized_key in { _normalize_key(item) for item in SENSITIVE_KEY_MAP["api_token"] }:
        return True
    if normalized_key in { _normalize_key(item) for item in SENSITIVE_KEY_MAP["session_credential"] }:
        return True
    if normalized_key in { _normalize_key(item) for item in SENSITIVE_KEY_MAP["private_credential"] }:
        return "private" in text.lower() or "-----BEGIN" in text or len(text) > 16
    if normalized_key in { _normalize_key(item) for item in SENSITIVE_KEY_MAP["database_credential"] }:
        return "@" in text and ("://" in text or ":" in text)
    if normalized_key in { _normalize_key(item) for item in SENSITIVE_KEY_MAP["cloud_credential"] }:
        return len(text) >= 8
    if normalized_key in { _normalize_key(item) for item in SENSITIVE_KEY_MAP["internal_infrastructure"] }:
        return bool(re.search(r"(?i)(?:\d+\.\d+\.\d+\.\d+|localhost|internal|svc|\.local)$", text)) or "/" in text or "\\" in text
    return False


def _finding(category: str, *, key: str, path: str, redacted: bool, rule: str | None = None) -> dict[str, Any]:
    return {
        "category": category,
        "field_name": key,
        "path": path,
        "redacted": redacted,
        "rule": rule or "key_name_or_value_pattern",
    }


def _result(
    target: str,
    status: str,
    reason: str,
    evidence: dict[str, Any],
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
        evidence=evidence,
        recommendation="Review the response schema and remove secret-bearing fields from ordinary API payloads.",
        endpoint_path=None,
        operation_id=None,
        security=None,
        authentication_mode="none",
        authentication_configured=False,
    )
