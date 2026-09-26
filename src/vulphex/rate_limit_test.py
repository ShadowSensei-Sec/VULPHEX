"""CONFIG-001: bounded, deterministic rate-limiting observation."""

from __future__ import annotations

from typing import Any

import httpx

from .authentication import AuthenticationConfig
from .discovery import ResolvedEndpoint
from .http_client import get_with_authentication, redact_sensitive_text, sanitize_url
from .models import AssessmentResult

TEST_ID = "CONFIG-001"
TEST_NAME = "Rate Limiting Detection Test"
MAX_REQUESTS = 5

_RATE_LIMIT_HEADER_NAMES = {
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-rate-limit-limit",
    "x-rate-limit-remaining",
    "x-rate-limit-reset",
}


class RateLimitTest:
    """Observe explicit rate-limit behavior using at most five sequential GETs."""

    test_id = TEST_ID
    test_name = TEST_NAME
    supported_methods = frozenset({"GET"})
    requires_authentication = False
    uses_authentication_context = True

    def execute(self, target: str) -> AssessmentResult:
        return _run_sequence(target, AuthenticationConfig())

    def execute_context(self, context: Any) -> AssessmentResult:
        return _run_endpoint(context.endpoint, context.authentication)

    def execute_endpoint(self, endpoint: ResolvedEndpoint) -> AssessmentResult:
        return _run_endpoint(endpoint, AuthenticationConfig())


def _run_endpoint(endpoint: ResolvedEndpoint, authentication: AuthenticationConfig) -> AssessmentResult:
    if endpoint.method != "GET":
        return _result(
            endpoint.target,
            endpoint.method,
            "UNSUPPORTED_OPERATION",
            "CONFIG-001 only supports GET endpoints and leaves other methods unchanged.",
            {"reason": "unsupported_http_method", "request_count": 0},
        )
    if "{" in endpoint.target or "}" in endpoint.target or "{" in endpoint.path or "}" in endpoint.path:
        return _result(
            endpoint.target,
            endpoint.method,
            "INVALID_TEST_CONFIGURATION",
            "The discovered endpoint contains unresolved path parameters, so no request was sent.",
            {"reason": "unresolved_path_parameters", "request_count": 0},
        )
    if endpoint.security_defined and endpoint.security and authentication.mode == "none":
        return _result(
            endpoint.target,
            endpoint.method,
            "AUTHENTICATION_REQUIRED",
            "This endpoint requires an explicitly supplied authenticated assessment context.",
            {"reason": "authentication_context_required", "request_count": 0},
        )
    return _run_sequence(endpoint.target, authentication, method=endpoint.method)


def _run_sequence(
    target: str,
    authentication: AuthenticationConfig,
    *,
    method: str = "GET",
) -> AssessmentResult:
    statuses: list[int] = []
    observations: list[dict[str, Any]] = []
    stopped_early = False

    for request_number in range(1, MAX_REQUESTS + 1):
        try:
            response, _ = get_with_authentication(target, authentication)
        except (httpx.TimeoutException, httpx.RequestError):
            return _result(
                target,
                method,
                "INCONCLUSIVE",
                "A bounded request timed out or failed before rate-limiting behavior could be established.",
                _evidence(target, method, statuses, observations, stopped_early=False, indicator=None),
            )

        statuses.append(response.status_code)
        observation = _header_observation(response, request_number)
        observations.append(observation)

        if response.status_code == 429:
            stopped_early = request_number < MAX_REQUESTS
            return _result(
                target,
                method,
                "RATE_LIMITING_OBSERVED",
                "The bounded sequential check received HTTP 429 Too Many Requests.",
                _evidence(target, method, statuses, observations, stopped_early, indicator="HTTP_429"),
                observed_status_code=response.status_code,
            )
        if response.status_code >= 500:
            stopped_early = request_number < MAX_REQUESTS
            return _result(
                target,
                method,
                "INCONCLUSIVE",
                "The bounded check received a generic server failure before rate-limiting behavior could be established.",
                _evidence(target, method, statuses, observations, stopped_early, indicator=None),
                observed_status_code=response.status_code,
            )

    consistent_headers = _consistently_present_headers(observations)
    if consistent_headers:
        indicator = "RATE_LIMIT_HEADERS"
        status = "RATE_LIMITING_OBSERVED"
        reason = "Explicit rate-limit headers were present consistently during the bounded sequential check; this is an observation, not proof of global enforcement."
    else:
        indicator = None
        status = "NO_RATE_LIMITING_OBSERVED"
        reason = "No rate-limiting behavior or consistently present rate-limit headers were observed during the bounded sequential check; this does not prove the API lacks rate limiting."
    return _result(
        target,
        method,
        status,
        reason,
        _evidence(target, method, statuses, observations, stopped_early, indicator),
        observed_status_code=statuses[-1] if statuses else None,
    )


def _header_observation(response: httpx.Response, request_number: int) -> dict[str, Any]:
    headers: dict[str, str] = {}
    names: list[str] = []
    for name, value in response.headers.items():
        if name.lower() in _RATE_LIMIT_HEADER_NAMES:
            names.append(name)
            headers[name] = redact_sensitive_text(value)
    return {
        "request_sequence": request_number,
        "header_names": names,
        "headers": headers,
        "retry_after_present": "retry-after" in {name.lower() for name in names},
    }


def _consistently_present_headers(observations: list[dict[str, Any]]) -> list[str]:
    if not observations:
        return []
    present_sets = [
        {name.lower() for name in observation["header_names"]}
        for observation in observations
    ]
    common = set.intersection(*present_sets)
    return sorted(common)


def _evidence(
    target: str,
    method: str,
    statuses: list[int],
    observations: list[dict[str, Any]],
    stopped_early: bool,
    indicator: str | None,
) -> dict[str, Any]:
    header_names = sorted({name for observation in observations for name in observation["header_names"]})
    return {
        "endpoint": sanitize_url(target),
        "http_method": method,
        "request_count": len(statuses),
        "status_code_sequence": statuses,
        "rate_limit_indicator": indicator,
        "rate_limit_header_names": header_names,
        "header_observations": observations,
        "retry_after_present": any(observation["retry_after_present"] for observation in observations),
        "stopped_early": stopped_early,
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
        recommendation="Use server-side rate limits appropriate to the endpoint and monitor enforcement separately from this bounded observation.",
    )
