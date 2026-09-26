"""CONFIG-003: bounded API misconfiguration assessment based on discovered metadata and safe responses."""

from __future__ import annotations

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

TEST_ID = "CONFIG-003"
TEST_NAME = "API Misconfiguration Assessment"
_DEBUG_HEADER_NAMES = {
    "x-debug",
    "x-debug-token",
    "x-debug-token-link",
    "x-debug-mode",
    "x-framework-debug",
    "x-application-debug",
    "server-timing",
}
_DEVELOPMENT_PATHS = {"/debug", "/test", "/internal", "/dev"}
_RESPONSE_HEADER_NAMES = {"server", "x-powered-by", "content-type"}


class ApiMisconfigurationTest:
    """Assess observable API configuration defects without brute-force or destructive probing."""

    test_id = TEST_ID
    test_name = TEST_NAME
    supported_methods = frozenset({"GET"})
    requires_authentication = False
    uses_authentication_context = True

    def execute(self, target: str) -> AssessmentResult:
        return _run_endpoint(target, "GET", AuthenticationConfig())

    def execute_context(self, context: Any) -> AssessmentResult:
        return _run_endpoint(context.endpoint.target, context.endpoint.method, context.authentication, context.endpoint)

    def execute_endpoint(self, endpoint: ResolvedEndpoint) -> AssessmentResult:
        return _run_endpoint(endpoint.target, endpoint.method, AuthenticationConfig(), endpoint)


def _run_endpoint(
    target: str,
    method: str,
    authentication: AuthenticationConfig,
    endpoint: ResolvedEndpoint | None = None,
) -> AssessmentResult:
    if endpoint is not None:
        metadata_finding = _metadata_method_observation(endpoint)
        if metadata_finding is not None:
            return metadata_finding

        if endpoint.path in _DEVELOPMENT_PATHS:
            return _result(
                endpoint.target,
                endpoint.method,
                "POTENTIAL_API_MISCONFIGURATION",
                f"The discovered API metadata explicitly exposes a development-oriented endpoint {endpoint.path}; this is an observation only and not proof of vulnerability.",
                {
                    "endpoint": sanitize_url(endpoint.target),
                    "http_method": endpoint.method,
                    "operation_id": endpoint.operation_id,
                    "request_count": 0,
                    "classification": "development_endpoint_exposed",
                    "path": endpoint.path,
                },
            )

        if (
            endpoint.global_security is not None
            and endpoint.security_defined
            and endpoint.security == []
            and endpoint.global_security
        ):
            return _result(
                target,
                method,
                "SECURITY_CONFIGURATION_EXCEPTION",
                "The API defines global security requirements, but this operation explicitly disables them with security: []. This is a noteworthy configuration exception that should be reviewed separately from authentication testing.",
                {
                    "endpoint": sanitize_url(target),
                    "http_method": method,
                    "operation_id": endpoint.operation_id,
                    "global_security_state": endpoint.global_security,
                    "operation_security_state": endpoint.security,
                    "request_count": 0,
                },
            )

        if endpoint.method.upper() not in {"GET"} and endpoint.method.upper() in {"POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            return _result(
                target,
                endpoint.method,
                "NO_API_MISCONFIGURATION_INDICATED",
                "This normal REST method was not treated as a misconfiguration because the bounded assessment only checks for explicit metadata and response anomalies.",
                {
                    "endpoint": sanitize_url(target),
                    "http_method": endpoint.method,
                    "request_count": 0,
                    "classification": "normal_rest_method",
                },
            )

    if method != "GET":
        return _result(
            target,
            method,
            "UNSUPPORTED_OPERATION",
            "CONFIG-003 only supports GET endpoints and leaves other methods unchanged.",
            {"reason": "unsupported_http_method", "request_count": 0},
        )

    if endpoint is not None and ("{" in endpoint.path or "}" in endpoint.path or "{" in endpoint.target or "}" in endpoint.target):
        return _result(
            target,
            method,
            "INVALID_TEST_CONFIGURATION",
            "The discovered endpoint contains unresolved path parameters, so no request was sent.",
            {"reason": "unresolved_path_parameters", "request_count": 0},
        )

    if endpoint is not None and endpoint.security_defined and endpoint.security and authentication.mode == "none":
        return _result(
            target,
            method,
            "AUTHENTICATION_REQUIRED",
            "This endpoint requires an explicitly supplied authenticated assessment context.",
            {"reason": "authentication_context_required", "request_count": 0},
        )

    try:
        response, _ = get_with_authentication(target, authentication)
    except (httpx.TimeoutException, httpx.RequestError):
        return _result(
            target,
            method,
            "INCONCLUSIVE",
            "A bounded API configuration request timed out or failed before structured evidence could be collected.",
            {"reason": "request_failed", "request_count": 1},
        )

    return _analyze_response(target, method, response, endpoint)


def _metadata_method_observation(endpoint: ResolvedEndpoint | None) -> AssessmentResult | None:
    if endpoint is None:
        return None
    if endpoint.method.upper() in {"TRACE", "CONNECT"}:
        return _result(
            endpoint.target,
            endpoint.method,
            "POTENTIAL_API_MISCONFIGURATION",
            f"The discovered OpenAPI metadata explicitly exposes HTTP {endpoint.method.upper()} on {endpoint.path}; this is an observable API misconfiguration signal and no request was sent.",
            {
                "endpoint": sanitize_url(endpoint.target),
                "http_method": endpoint.method,
                "operation_id": endpoint.operation_id,
                "request_count": 0,
                "classification": "observed_http_method_exposure",
                "path": endpoint.path,
            },
        )
    if endpoint.method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        return None
    return None


def _analyze_response(
    target: str,
    method: str,
    response: httpx.Response,
    endpoint: ResolvedEndpoint | None,
) -> AssessmentResult:
    evidence: dict[str, Any] = {
        "endpoint": sanitize_url(target),
        "http_method": method,
        "status_code": response.status_code,
        "headers": _sanitize_headers(response.headers),
        "request_count": 1,
    }

    if endpoint is not None:
        evidence["operation_id"] = endpoint.operation_id
        evidence["path"] = endpoint.path
        evidence["global_security_state"] = endpoint.global_security
        evidence["operation_security_state"] = endpoint.security
        evidence["security_definition_source"] = endpoint.security_requirement_source

    debug = _detect_debug_indicators(response.headers)
    if debug:
        return _result(
            target,
            method,
            "POTENTIAL_API_MISCONFIGURATION",
            "The response exposed explicit debug or development indicators in normal headers; this is a configuration weakness and not a server scan or exploitation attempt.",
            {**evidence, "debug_indicators": debug},
            observed_status_code=response.status_code,
        )

    server_version = _detect_server_information(response.headers)
    if server_version:
        return _result(
            target,
            method,
            "INFORMATIONAL_CONFIGURATION_OBSERVED",
            "The response explicitly exposes server or framework version information in a way that is informative and should be reviewed separately from the main disclosure checks.",
            {**evidence, "headers": server_version, "server_information": server_version},
            observed_status_code=response.status_code,
        )

    content_type = response.headers.get("content-type", "")
    if content_type and "application/json" in content_type.lower():
        return _result(
            target,
            method,
            "NO_API_MISCONFIGURATION_INDICATED",
            "The normal GET response used an ordinary JSON content type and no explicit debug or misconfiguration indicators were observed.",
            {**evidence, "content_type": content_type},
            observed_status_code=response.status_code,
        )

    if content_type and "text/html" in content_type.lower():
        return _result(
            target,
            method,
            "POTENTIAL_API_MISCONFIGURATION",
            "The response presented an HTML page while the API was expected to return structured data, indicating a potential content-type or debug-page misconfiguration.",
            {**evidence, "content_type": content_type, "content_type_inconsistent": True},
            observed_status_code=response.status_code,
        )

    return _result(
        target,
        method,
        "NO_API_MISCONFIGURATION_INDICATED",
        "No clear debug, discovery, security-exception, or content-type misconfiguration was observed in the bounded assessment.",
        {**evidence, "content_type": content_type},
        observed_status_code=response.status_code,
    )


def _detect_debug_indicators(headers: httpx.Headers) -> dict[str, str]:
    debug: dict[str, str] = {}
    for name, value in headers.items():
        normalized = name.lower()
        if normalized in _DEBUG_HEADER_NAMES:
            debug[name] = redact_sensitive_text(value)
        elif "debug" in normalized:
            debug[name] = redact_sensitive_text(value)
        elif normalized in {"x-powered-by", "server"}:
            continue
    return debug


def _detect_server_information(headers: httpx.Headers) -> dict[str, str]:
    disclosure: dict[str, str] = {}
    for name, value in headers.items():
        normalized = name.lower()
        if normalized in {"server", "x-powered-by"} and bool(value.strip()):
            disclosure[name] = redact_sensitive_text(value)
    return disclosure


def _sanitize_headers(headers: httpx.Headers) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for name, value in headers.items():
        normalized = name.lower()
        if normalized in _RESPONSE_HEADER_NAMES or "debug" in normalized:
            sanitized[name] = redact_sensitive_text(value)
    return sanitized


def _result(
    target: str,
    method: str,
    status: str,
    reason: str,
    evidence: dict[str, Any],
    *,
    observed_status_code: int | None = None,
) -> AssessmentResult:
    return AssessmentResult(
        test_id=TEST_ID,
        test_name=TEST_NAME,
        target=sanitize_url(target),
        method=method,
        status=status,
        observed_status_code=observed_status_code,
        severity=None,
        reason=reason,
        evidence=evidence,
        recommendation="Review the observed configuration or metadata against the API's intended deployment posture; keep this assessment bounded to configuration evidence and discovered metadata.",
    )
