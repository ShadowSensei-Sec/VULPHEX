import httpx
import pytest

from vulphex.Authentication.auth_test import MissingAuthenticationTest
from vulphex.Core.models import AssessmentResult


TARGET = "https://authorized.example.test/resource"


def make_response(status_code: int) -> httpx.Response:
    request = httpx.Request("GET", f"{TARGET}?token=redact-me")
    return httpx.Response(status_code, request=request, text="controlled response")


def test_authentication_test_exposes_security_test_identity() -> None:
    test = MissingAuthenticationTest()

    assert test.test_id == "AUTH-001"
    assert test.test_name == "Missing Authentication Test"


@pytest.mark.parametrize(
    ("status_code", "expected_status"),
    [
        (401, "AUTHENTICATION_ENFORCED"),
        (403, "AUTHENTICATION_ENFORCED"),
        (200, "POTENTIAL_MISSING_AUTHENTICATION"),
        (404, "INCONCLUSIVE"),
    ],
)
def test_authentication_test_executes_through_security_test_contract(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    expected_status: str,
) -> None:
    calls: list[str] = []

    def fake_get_without_authentication(target: str) -> tuple[httpx.Response, float]:
        calls.append(target)
        return make_response(status_code), 12.345

    monkeypatch.setattr(
        "vulphex.Authentication.auth_test.get_without_authentication",
        fake_get_without_authentication,
    )

    result = MissingAuthenticationTest().execute(TARGET)

    assert calls == [TARGET]
    assert isinstance(result, AssessmentResult)
    assert result.status == expected_status
    assert result.severity is None
