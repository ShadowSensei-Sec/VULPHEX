import json

import httpx
import pytest

from vulphex.authentication import AuthenticationConfig
from vulphex.discovery import ResolvedEndpoint
from vulphex.engine import AssessmentEngine
from vulphex.rate_limit_test import RateLimitTest

TARGET = "https://example.test/rate-limit"


def make_response(status_code: int = 200, headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("GET", TARGET)
    return httpx.Response(status_code, request=request, json={"status": "ok"}, headers=headers or {})


def endpoint(path: str = "/rate-limit", method: str = "GET", security: list[dict[str, object]] | None = None) -> ResolvedEndpoint:
    return ResolvedEndpoint(
        method=method,
        target=f"https://example.test{path}",
        path=path,
        operation_id="rateLimit",
        security=security,
        security_defined=bool(security),
    )


def test_rate_limit_exposes_identity() -> None:
    test = RateLimitTest()

    assert test.test_id == "CONFIG-001"
    assert test.test_name == "Rate Limiting Detection Test"
    assert test.supported_methods == frozenset({"GET"})


def test_429_is_detected_and_stops_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [make_response(), make_response(), make_response(), make_response(429, {"Retry-After": "30"}), make_response()]
    calls: list[int] = []

    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        calls.append(1)
        return responses.pop(0), 1.0

    monkeypatch.setattr("vulphex.rate_limit_test.get_with_authentication", fake_get)
    result = RateLimitTest().execute(TARGET)

    assert result.status == "RATE_LIMITING_OBSERVED"
    assert calls == [1, 1, 1, 1]
    assert result.evidence["request_count"] == 4
    assert result.evidence["status_code_sequence"] == [200, 200, 200, 429]
    assert result.evidence["stopped_early"] is True
    assert result.evidence["retry_after_present"] is True


def test_retry_after_header_is_captured_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.rate_limit_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(429, {"Retry-After": "30", "Authorization": "Bearer secret"}), 1.0),
    )

    result = RateLimitTest().execute(TARGET)
    evidence_dump = json.dumps(result.evidence)

    assert result.status == "RATE_LIMITING_OBSERVED"
    assert "retry-after" in {name.lower() for name in result.evidence["rate_limit_header_names"]}
    assert "Authorization" not in evidence_dump
    assert "secret" not in evidence_dump


def test_consistent_rate_limit_headers_are_observed_without_429(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = {
        "X-RateLimit-Limit": "10",
        "X-RateLimit-Remaining": "9",
        "X-RateLimit-Reset": "1700000000",
    }
    calls = 0

    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        nonlocal calls
        calls += 1
        return make_response(headers=headers), 1.0

    monkeypatch.setattr("vulphex.rate_limit_test.get_with_authentication", fake_get)
    result = RateLimitTest().execute(TARGET)

    assert result.status == "RATE_LIMITING_OBSERVED"
    assert calls == 5
    assert result.evidence["rate_limit_indicator"] == "RATE_LIMIT_HEADERS"


def test_five_successes_without_indicators_are_not_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        nonlocal calls
        calls += 1
        return make_response(), 1.0

    monkeypatch.setattr("vulphex.rate_limit_test.get_with_authentication", fake_get)
    result = RateLimitTest().execute(TARGET)

    assert result.status == "NO_RATE_LIMITING_OBSERVED"
    assert calls == 5
    assert "does not prove" in result.reason


def test_generic_500_is_inconclusive_not_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        nonlocal calls
        calls += 1
        return make_response(500), 1.0

    monkeypatch.setattr("vulphex.rate_limit_test.get_with_authentication", fake_get)
    result = RateLimitTest().execute(TARGET)

    assert result.status == "INCONCLUSIVE"
    assert result.evidence["request_count"] == 1
    assert calls == 1


def test_timeout_and_transport_failure_are_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("vulphex.rate_limit_test.get_with_authentication", fail)
    result = RateLimitTest().execute(TARGET)

    assert result.status == "INCONCLUSIVE"
    assert result.evidence["request_count"] == 0


def test_authentication_required_endpoint_without_credentials_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        raise AssertionError("authenticated endpoint must not be tested anonymously")

    monkeypatch.setattr("vulphex.rate_limit_test.get_with_authentication", fail)
    result = RateLimitTest().execute_endpoint(endpoint(security=[{"bearerAuth": []}]))

    assert result.status == "AUTHENTICATION_REQUIRED"
    assert result.evidence["request_count"] == 0


def test_authenticated_context_is_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    received: list[AuthenticationConfig] = []

    def fake_get(target: str, authentication: AuthenticationConfig, *args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        received.append(authentication)
        return make_response(), 1.0

    monkeypatch.setattr("vulphex.rate_limit_test.get_with_authentication", fake_get)
    auth = AuthenticationConfig(mode="bearer", token="synthetic-token")
    result = RateLimitTest().execute_context(type("Context", (), {"endpoint": endpoint(), "authentication": auth})())

    assert result.status == "NO_RATE_LIMITING_OBSERVED"
    assert all(item == auth for item in received)


def test_unsupported_methods_and_unresolved_paths_are_not_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        raise AssertionError("invalid endpoint must not be requested")

    monkeypatch.setattr("vulphex.rate_limit_test.get_with_authentication", fail)
    assert RateLimitTest().execute_endpoint(endpoint(method="POST")).status == "UNSUPPORTED_OPERATION"
    assert RateLimitTest().execute_endpoint(endpoint(path="/users/{user_id}")).status == "INVALID_TEST_CONFIGURATION"


def test_engine_preserves_config_order_and_auth_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.rate_limit_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(), 1.0),
    )
    results = AssessmentEngine([RateLimitTest()]).assess_endpoints([endpoint()])

    assert [result.test_id for result in results] == ["CONFIG-001"]
    assert results[0].authentication_mode == "none"
    assert results[0].evidence["request_count"] == 5
