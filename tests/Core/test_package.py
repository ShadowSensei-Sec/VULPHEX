import vulphex
import httpx
import pytest

from vulphex.Authentication.auth_test import analyze_authentication_response
from vulphex.Core.http_client import sanitize_url, validate_url


def test_package_version_is_defined() -> None:
    assert vulphex.__version__ == "1.0.0"


def make_response(status_code: int, body: str = "") -> httpx.Response:
    request = httpx.Request("GET", "https://authorized.example.test/resource?token=redact-me")
    return httpx.Response(status_code, request=request, text=body)


def test_authentication_is_reported_as_enforced_for_unauthorized_response() -> None:
    result = analyze_authentication_response(make_response(401), 12.345)

    assert result.status == "AUTHENTICATION_ENFORCED"
    assert result.severity is None
    assert result.observed_status_code == 401


def test_successful_unauthenticated_response_is_a_potential_finding() -> None:
    result = analyze_authentication_response(make_response(200, "public response"), 12.345)

    assert result.status == "POTENTIAL_MISSING_AUTHENTICATION"
    assert result.severity is None
    assert "confirmed" not in result.reason.lower()
    assert result.evidence["url"] == "https://authorized.example.test/resource"


def test_non_authentication_response_is_inconclusive() -> None:
    result = analyze_authentication_response(make_response(404), 12.345)

    assert result.status == "INCONCLUSIVE"
    assert result.severity is None


def test_response_evidence_redacts_url_headers_and_body_secrets() -> None:
    request = httpx.Request(
        "GET",
        "https://user:password@authorized.example.test/resource?token=redact-me",
    )
    response = httpx.Response(
        200,
        request=request,
        headers={"Location": "/next?access_token=secret", "X-Request-ID": "request-1"},
        text='{"access_token":"secret", "message":"safe"}',
    )

    result = analyze_authentication_response(response, 12.345)

    assert result.target == "https://authorized.example.test/resource"
    assert result.evidence["url"] == "https://authorized.example.test/resource"
    assert result.evidence["headers"]["location"] == "/next"
    assert "secret" not in result.evidence["body_preview"]
    assert "safe" in result.evidence["body_preview"]


def test_invalid_url_is_rejected_without_exposing_userinfo() -> None:
    with pytest.raises(ValueError):
        validate_url("https://[invalid")

    assert sanitize_url("https://user:password@example.test/path?token=secret") == (
        "https://example.test/path"
    )
