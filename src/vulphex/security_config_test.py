"""CONFIG-002: bounded CORS and HTTP security configuration assessment."""

from __future__ import annotations

from typing import Any

import httpx

from .authentication import AuthenticationConfig
from .discovery import ResolvedEndpoint
from .http_client import get_with_authentication, redact_sensitive_text, sanitize_url
from .models import AssessmentResult

TEST_ID = "CONFIG-002"
TEST_NAME = "CORS and Security Configuration Assessment"
TRUSTED_ORIGIN = "https://vulphex-test.example"
UNTRUSTED_ORIGIN = "https://untrusted-vulphex.example"
CONTROLLED_ORIGINS = (TRUSTED_ORIGIN, UNTRUSTED_ORIGIN)

CORS_HEADERS = {
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-allow-private-network",
}
SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
}
DISCLOSURE_HEADERS = {"server", "x-powered-by"}


class SecurityConfigurationTest:
    """Observe CORS and related response configuration with at most two GETs."""

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
    if method != "GET":
        return _result(target, method, "UNSUPPORTED_OPERATION", "CONFIG-002 only supports GET endpoints.", {"request_count": 0})
    if endpoint is not None and ("{" in endpoint.path or "}" in endpoint.path or "{" in target or "}" in target):
        return _result(
            target,
            method,
            "INVALID_TEST_CONFIGURATION",
            "The discovered endpoint contains unresolved path parameters, so no request was sent.",
            {"request_count": 0, "reason": "unresolved_path_parameters"},
        )
    if endpoint is not None and endpoint.security_defined and endpoint.security and authentication.mode == "none":
        return _result(
            target,
            method,
            "AUTHENTICATION_REQUIRED",
            "This endpoint requires an explicitly supplied authenticated assessment context.",
            {"request_count": 0, "reason": "authentication_context_required"},
        )

    observations: list[dict[str, Any]] = []
    for origin in CONTROLLED_ORIGINS:
        try:
            response, _ = get_with_authentication(
                target,
                authentication,
                extra_headers={"Origin": origin},
            )
        except (httpx.TimeoutException, httpx.RequestError):
            return _result(
                target,
                method,
                "INCONCLUSIVE",
                "A controlled CORS request timed out or failed before configuration could be established.",
                _evidence(target, method, observations, classification="INCONCLUSIVE"),
            )
        observations.append(_observation(origin, response))

    classification, reason = _classify(target, observations)
    return _result(
        target,
        method,
        classification,
        reason,
        _evidence(target, method, observations, classification=classification),
        observed_status_code=observations[-1]["status_code"],
    )


def _observation(origin: str, response: httpx.Response) -> dict[str, Any]:
    cors_headers: dict[str, str] = {}
    security_headers: dict[str, str] = {}
    disclosure_headers: dict[str, str] = {}
    for name, value in response.headers.items():
        normalized = name.lower()
        safe_value = redact_sensitive_text(value)
        if normalized in CORS_HEADERS:
            cors_headers[name] = safe_value
        elif normalized in SECURITY_HEADERS:
            security_headers[name] = safe_value
        elif normalized in DISCLOSURE_HEADERS:
            disclosure_headers[name] = safe_value
    return {
        "origin": origin,
        "status_code": response.status_code,
        "cors_headers": cors_headers,
        "security_headers": security_headers,
        "disclosure_headers": disclosure_headers,
    }


def _classify(target: str, observations: list[dict[str, Any]]) -> tuple[str, str]:
    if any(_is_reflected_origin(observation) for observation in observations if observation["origin"] == UNTRUSTED_ORIGIN):
        credentialed = any(
            _is_reflected_origin(observation) and _header_is_true(observation, "access-control-allow-credentials")
            for observation in observations
            if observation["origin"] == UNTRUSTED_ORIGIN
        )
        if credentialed:
            return (
                "POTENTIAL_CORS_MISCONFIGURATION",
                "The controlled untrusted origin was reflected with credentialed CORS enabled, indicating a potentially unsafe policy.",
            )
        return (
            "POTENTIAL_CORS_MISCONFIGURATION",
            "The controlled untrusted origin was reflected by Access-Control-Allow-Origin, indicating a potentially unsafe policy.",
        )

    if any(_header_value(observation, "access-control-allow-origin") == "*" for observation in observations):
        if any(_header_is_true(observation, "access-control-allow-credentials") for observation in observations):
            return (
                "POTENTIAL_CORS_MISCONFIGURATION",
                "A wildcard CORS origin was observed with credentials enabled; browser enforcement still limits credentialed wildcard use.",
            )
        return (
            "CORS_CONFIGURATION_OBSERVED",
            "A wildcard CORS policy was observed without credentials; this is an observation and not a confirmed vulnerability for public resources.",
        )

    has_cors = any(observation["cors_headers"] for observation in observations)
    disclosure = any(observation["disclosure_headers"] for observation in observations)
    if disclosure:
        return (
            "INFORMATIONAL_CONFIGURATION_OBSERVED",
            "The response exposed explicit server or framework identification headers; this is an informational configuration observation.",
        )
    if target.lower().startswith("http://"):
        return (
            "HTTP_ENDPOINT_OBSERVED",
            "The assessed endpoint uses HTTP; transport configuration was observed without attempting TLS attacks or downgrades.",
        )
    if has_cors:
        return (
            "NO_CORS_MISCONFIGURATION_INDICATED",
            "The controlled origins did not reveal an unsafe CORS policy under the bounded assessment.",
        )
    return (
        "NO_CORS_MISCONFIGURATION_INDICATED",
        "The controlled origins did not reveal an unsafe CORS policy; missing browser-oriented headers are not treated as API vulnerabilities.",
    )


def _is_reflected_origin(observation: dict[str, Any]) -> bool:
    return _header_value(observation, "access-control-allow-origin") == observation["origin"]


def _header_value(observation: dict[str, Any], name: str) -> str | None:
    for header_name, value in observation["cors_headers"].items():
        if header_name.lower() == name:
            return value.strip()
    return None


def _header_is_true(observation: dict[str, Any], name: str) -> bool:
    return _header_value(observation, name).lower() == "true" if _header_value(observation, name) else False


def _evidence(target: str, method: str, observations: list[dict[str, Any]], *, classification: str) -> dict[str, Any]:
    return {
        "endpoint": sanitize_url(target),
        "http_method": method,
        "request_count": len(observations),
        "observations": observations,
        "configuration_classification": classification,
        "http_endpoint_observed": target.lower().startswith("http://"),
    }


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
        recommendation="Review CORS and response-header policy separately from API authorization; this bounded result is observational only.",
    )