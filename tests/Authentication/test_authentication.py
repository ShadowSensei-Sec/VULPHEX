import httpx
import pytest

from vulphex.Authentication.authentication import AuthenticationConfig, AuthenticationConfigError, authentication_config_from_environment
from vulphex.Authentication.auth_test import MissingAuthenticationTest
from vulphex.Core.http_client import get_with_authentication, redact_headers, redact_sensitive_text, response_evidence


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (AuthenticationConfig(), {}),
        (AuthenticationConfig(mode="bearer", token="synthetic-token"), {"Authorization": "Bearer synthetic-token"}),
        (AuthenticationConfig(mode="api_key", api_key_name="X-API-Key", api_key_value="synthetic-key"), {"X-API-Key": "synthetic-key"}),
        (AuthenticationConfig(mode="custom_header", header_name="X-Custom-Auth", header_value="synthetic-value"), {"X-Custom-Auth": "synthetic-value"}),
    ],
)
def test_authentication_config_builds_explicit_request_headers(config, expected) -> None:
    assert config.request_headers() == expected


@pytest.mark.parametrize(
    "config",
    [
        {"mode": "bearer"},
        {"mode": "api_key", "api_key_name": "X-API-Key"},
        {"mode": "custom_header", "header_value": "value"},
        {"mode": "custom_header", "header_name": "X-Auth"},
        {"mode": "custom_header", "header_name": "bad header", "header_value": "value"},
    ],
)
def test_authentication_config_rejects_incomplete_or_invalid_values(config) -> None:
    with pytest.raises(AuthenticationConfigError):
        AuthenticationConfig(**config)


def test_environment_configuration_is_explicit_and_validated() -> None:
    config = authentication_config_from_environment(
        {"VULPHEX_AUTH_MODE": "bearer", "VULPHEX_BEARER_TOKEN": "synthetic-token"}
    )

    assert config.safe_mode == "bearer"
    assert config.request_headers() == {"Authorization": "Bearer synthetic-token"}


def test_authenticated_http_request_applies_headers_without_leaking_values(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def get(self, url: str, headers: dict[str, str]):
            captured.update({"url": url, "headers": headers})
            return httpx.Response(200, request=httpx.Request("GET", url), json={"token": "synthetic-token"})

    monkeypatch.setattr("vulphex.Core.http_client.httpx.Client", lambda **kwargs: FakeClient())
    response, _ = get_with_authentication(
        "https://example.test/resource",
        AuthenticationConfig(mode="bearer", token="synthetic-token"),
    )

    assert captured["headers"] == {"Authorization": "Bearer synthetic-token"}
    evidence = response_evidence(response, 1.0)
    serialized = str(evidence)
    assert "synthetic-token" not in serialized


def test_redaction_removes_sensitive_headers_and_body_values() -> None:
    text = "Authorization: Bearer synthetic-token api_key=synthetic-key password=secret-value"

    assert "synthetic-token" not in redact_sensitive_text(text)
    assert "synthetic-key" not in redact_sensitive_text(text)
    assert "secret-value" not in redact_sensitive_text(text)
    assert redact_headers({"Authorization": "Bearer synthetic-token", "X-Request-ID": "safe"}) == {
        "Authorization": "[REDACTED]",
        "X-Request-ID": "safe",
    }


def test_auth001_remains_unauthenticated(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_get(url: str, timeout: float = 10.0):
        calls.append({"url": url, "timeout": timeout})
        request = httpx.Request("GET", url)
        return httpx.Response(401, request=request), 1.0

    monkeypatch.setattr("vulphex.Authentication.auth_test.get_without_authentication", fake_get)
    result = MissingAuthenticationTest().execute("https://example.test/resource")

    assert result.status == "AUTHENTICATION_ENFORCED"
    assert calls == [{"url": "https://example.test/resource", "timeout": 10.0}]