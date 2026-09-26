import json

import httpx
import pytest

from vulphex.Authentication.authentication import AuthenticationConfig
from vulphex.Discovery.discovery import ResolvedEndpoint
from vulphex.Security_configuration.security_config_test import SecurityConfigurationTest

TARGET = "https://example.test/resource"


def response(status_code: int = 200, headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("GET", TARGET)
    return httpx.Response(status_code, request=request, json={"status": "ok"}, headers=headers or {})


def endpoint(path: str = "/resource", method: str = "GET", security: list[dict[str, object]] | None = None) -> ResolvedEndpoint:
    return ResolvedEndpoint(
        method=method,
        target=f"https://example.test{path}",
        path=path,
        operation_id="resource",
        security=security,
        security_defined=bool(security),
    )


def test_exposes_identity() -> None:
    test = SecurityConfigurationTest()

    assert test.test_id == "CONFIG-002"
    assert test.test_name == "CORS and Security Configuration Assessment"
    assert test.supported_methods == frozenset({"GET"})


def test_secure_cors_does_not_create_false_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        response(headers={"Access-Control-Allow-Origin": "https://vulphex-test.example"}),
        response(),
    ]
    monkeypatch.setattr(
        "vulphex.Security_configuration.security_config_test.get_with_authentication",
        lambda *args, **kwargs: (responses.pop(0), 1.0),
    )

    result = SecurityConfigurationTest().execute_endpoint(endpoint())

    assert result.status == "NO_CORS_MISCONFIGURATION_INDICATED"
    assert result.evidence["request_count"] == 2


def test_wildcard_cors_is_observed_not_confirmed_vulnerable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.Security_configuration.security_config_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Access-Control-Allow-Origin": "*"}), 1.0),
    )

    result = SecurityConfigurationTest().execute(TARGET)

    assert result.status == "CORS_CONFIGURATION_OBSERVED"
    assert result.evidence["observations"][0]["cors_headers"]["access-control-allow-origin"] == "*"


def test_untrusted_origin_reflection_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [response(), response(headers={"Access-Control-Allow-Origin": "https://untrusted-vulphex.example"})]
    monkeypatch.setattr(
        "vulphex.Security_configuration.security_config_test.get_with_authentication",
        lambda *args, **kwargs: (responses.pop(0), 1.0),
    )

    result = SecurityConfigurationTest().execute(TARGET)

    assert result.status == "POTENTIAL_CORS_MISCONFIGURATION"


def test_credentialed_reflection_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = {
        "Access-Control-Allow-Origin": "https://untrusted-vulphex.example",
        "Access-Control-Allow-Credentials": "true",
    }
    responses = [response(), response(headers=headers)]
    monkeypatch.setattr(
        "vulphex.Security_configuration.security_config_test.get_with_authentication",
        lambda *args, **kwargs: (responses.pop(0), 1.0),
    )

    result = SecurityConfigurationTest().execute(TARGET)

    assert result.status == "POTENTIAL_CORS_MISCONFIGURATION"
    assert "credentialed" in result.reason


def test_security_headers_are_captured_without_being_required(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    monkeypatch.setattr(
        "vulphex.Security_configuration.security_config_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers=headers), 1.0),
    )

    result = SecurityConfigurationTest().execute(TARGET)

    assert result.status == "NO_CORS_MISCONFIGURATION_INDICATED"
    assert set(result.evidence["observations"][0]["security_headers"]) == {name.lower() for name in headers}


def test_server_disclosure_is_informational(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.Security_configuration.security_config_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Server": "SyntheticAPI/1.0", "X-Powered-By": "Framework/2.0"}), 1.0),
    )

    result = SecurityConfigurationTest().execute(TARGET)

    assert result.status == "INFORMATIONAL_CONFIGURATION_OBSERVED"
    assert result.evidence["observations"][0]["disclosure_headers"]


def test_http_endpoint_is_observed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.Security_configuration.security_config_test.get_with_authentication",
        lambda *args, **kwargs: (response(), 1.0),
    )

    result = SecurityConfigurationTest().execute("http://example.test/resource")

    assert result.status == "HTTP_ENDPOINT_OBSERVED"
    assert result.evidence["http_endpoint_observed"] is True


def test_credentials_are_absent_from_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.Security_configuration.security_config_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Access-Control-Allow-Origin": "*", "Authorization": "Bearer secret-token"}), 1.0),
    )

    result = SecurityConfigurationTest().execute(TARGET)
    evidence_dump = json.dumps(result.evidence)

    assert "Authorization" not in evidence_dump
    assert "secret-token" not in evidence_dump


def test_two_request_budget_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, str]] = []

    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        calls.append(kwargs.get("extra_headers", {}))
        return response(), 1.0

    monkeypatch.setattr("vulphex.Security_configuration.security_config_test.get_with_authentication", fake_get)
    result = SecurityConfigurationTest().execute(TARGET)

    assert result.evidence["request_count"] == 2
    assert [item["Origin"] for item in calls] == ["https://vulphex-test.example", "https://untrusted-vulphex.example"]


def test_authentication_context_is_forwarded_and_missing_auth_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    auth = AuthenticationConfig(mode="bearer", token="synthetic-token")
    received: list[AuthenticationConfig] = []

    def fake_get(target: str, authentication: AuthenticationConfig, *args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        received.append(authentication)
        return response(), 1.0

    monkeypatch.setattr("vulphex.Security_configuration.security_config_test.get_with_authentication", fake_get)
    result = SecurityConfigurationTest().execute_context(type("Context", (), {"endpoint": endpoint(), "authentication": auth})())
    assert result.status == "NO_CORS_MISCONFIGURATION_INDICATED"
    assert all(item == auth for item in received)

    missing = SecurityConfigurationTest().execute_endpoint(endpoint(security=[{"bearerAuth": []}]))
    assert missing.status == "AUTHENTICATION_REQUIRED"
    assert missing.evidence["request_count"] == 0


def test_invalid_endpoints_are_not_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        raise AssertionError("invalid endpoint must not be requested")

    monkeypatch.setattr("vulphex.Security_configuration.security_config_test.get_with_authentication", fail)
    assert SecurityConfigurationTest().execute_endpoint(endpoint(method="POST")).status == "UNSUPPORTED_OPERATION"
    assert SecurityConfigurationTest().execute_endpoint(endpoint(path="/users/{user_id}")).status == "INVALID_TEST_CONFIGURATION"


def test_timeout_and_malformed_headers_are_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("vulphex.Security_configuration.security_config_test.get_with_authentication", fail)
    assert SecurityConfigurationTest().execute(TARGET).status == "INCONCLUSIVE"

    monkeypatch.setattr(
        "vulphex.Security_configuration.security_config_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Access-Control-Allow-Origin": "", "Access-Control-Allow-Credentials": "maybe"}), 1.0),
    )
    assert SecurityConfigurationTest().execute(TARGET).status == "NO_CORS_MISCONFIGURATION_INDICATED"
