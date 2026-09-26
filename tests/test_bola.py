import json

import httpx
import pytest

from vulphex.authentication import AuthenticationConfig, BOLAContext
from vulphex.bola_test import BrokenObjectLevelAuthorizationTest
from vulphex.discovery import Endpoint, ResolvedEndpoint
from vulphex.engine import AssessmentContext, AssessmentEngine


def endpoint(path: str, method: str = "GET", parameter: str = "user_id") -> ResolvedEndpoint:
    return ResolvedEndpoint(
        method=method,
        target=f"https://example.test{path}",
        path=path,
        parameters=[{"name": parameter, "in": "path", "required": True}],
    )


def bola_context(reference: str | None = "123", parameter: str | None = "user_id") -> BOLAContext:
    return BOLAContext(
        identity_a=AuthenticationConfig(mode="bearer", token="identity-a-secret"),
        identity_b=AuthenticationConfig(mode="bearer", token="identity-b-secret"),
        object_reference=reference,
        parameter_name=parameter,
    )


def response(status: int, body: object, url: str = "https://example.test/users/123") -> httpx.Response:
    return httpx.Response(status, request=httpx.Request("GET", url), json=body)


def run_test(monkeypatch: pytest.MonkeyPatch, endpoint_value: ResolvedEndpoint, context: BOLAContext, responses: list[httpx.Response]):
    calls: list[tuple[str, dict[str, str]]] = []

    def fake_get(url: str, authentication: AuthenticationConfig, timeout: float = 10.0):
        calls.append((url, authentication.request_headers()))
        return responses[len(calls) - 1], 1.0

    monkeypatch.setattr("vulphex.bola_test.get_with_authentication", fake_get)
    result = BrokenObjectLevelAuthorizationTest().execute_context(AssessmentContext(endpoint_value, bola=context))
    return result, calls


def test_missing_two_identity_context_does_not_execute() -> None:
    result = BrokenObjectLevelAuthorizationTest().execute_context(AssessmentContext(endpoint("/users/{user_id}")))

    assert result.status == "INVALID_TEST_CONFIGURATION"


def test_missing_object_reference_does_not_execute(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args, **kwargs):
        raise AssertionError("no request should be made")

    monkeypatch.setattr("vulphex.bola_test.get_with_authentication", fail)
    result = BrokenObjectLevelAuthorizationTest().execute_context(
        AssessmentContext(endpoint("/users/{user_id}"), bola=bola_context(None))
    )

    assert result.status == "INVALID_TEST_CONFIGURATION"


def test_path_parameter_is_substituted_without_guessing_and_request_count_is_two(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = run_test(
        monkeypatch,
        endpoint("/users/{user_id}"),
        bola_context(),
        [response(200, {"id": 123, "name": "same"}), response(403, {"detail": "denied"})],
    )

    assert result.status == "AUTHORIZATION_ENFORCED"
    assert [call[0] for call in calls] == ["https://example.test/users/123"] * 2
    assert calls[0][1] == {"Authorization": "Bearer identity-a-secret"}
    assert calls[1][1] == {"Authorization": "Bearer identity-b-secret"}


def test_multiple_placeholders_remain_unresolved_without_inventing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = run_test(
        monkeypatch,
        endpoint("/users/{user_id}/orders/{order_id}"),
        bola_context(),
        [],
    )

    assert result.status == "INVALID_TEST_CONFIGURATION"
    assert calls == []


def test_non_get_is_not_applicable_in_engine() -> None:
    result = AssessmentEngine([BrokenObjectLevelAuthorizationTest()]).assess_endpoints(
        [endpoint("/users/{user_id}", method="POST")],
        bola_context=bola_context(),
    )[0]

    assert result.status == "NOT_APPLICABLE"


def test_identity_a_baseline_failure_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = run_test(monkeypatch, endpoint("/users/{user_id}"), bola_context(), [response(403, {}), response(200, {})])

    assert result.status == "INCONCLUSIVE"


@pytest.mark.parametrize(
    ("secondary_status", "expected"),
    [(401, "AUTHORIZATION_ENFORCED"), (403, "AUTHORIZATION_ENFORCED"), (404, "INCONCLUSIVE")],
)
def test_secondary_statuses_are_classified_conservatively(monkeypatch, secondary_status, expected) -> None:
    result, _ = run_test(
        monkeypatch,
        endpoint("/users/{user_id}"),
        bola_context(),
        [response(200, {"id": 123}), response(secondary_status, {})],
    )

    assert result.status == expected


def test_equivalent_successful_json_is_potential_bola(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = run_test(
        monkeypatch,
        endpoint("/users/{user_id}"),
        bola_context(),
        [response(200, {"id": 123, "name": "same", "timestamp": 1}), response(200, {"id": 123, "name": "same", "timestamp": 2})],
    )

    assert result.status == "POTENTIAL_BOLA"
    assert result.evidence["comparison"]["body_match"] is True


def test_ambiguous_successful_responses_are_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = run_test(
        monkeypatch,
        endpoint("/users/{user_id}"),
        bola_context(),
        [response(200, {"id": 123}), response(200, {"id": 123, "name": "different"})],
    )

    assert result.status == "INCONCLUSIVE"


def test_credentials_and_object_reference_are_not_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = run_test(
        monkeypatch,
        endpoint("/users/{user_id}"),
        bola_context("sensitive-object"),
        [response(200, {"id": "sensitive-object", "token": "response-secret"}), response(200, {"id": "sensitive-object", "token": "response-secret"})],
    )

    serialized = json.dumps(result.to_dict())
    assert "identity-a-secret" not in serialized
    assert "identity-b-secret" not in serialized
    assert "sensitive-object" not in serialized
    assert "response-secret" not in serialized


def test_parameter_identification_requires_explicit_or_unique_known_path_parameter() -> None:
    test = BrokenObjectLevelAuthorizationTest()
    context = AssessmentContext(
        endpoint("/accounts/{account_id}"),
        bola=bola_context(parameter=None),
    )

    assert test.execute_context(context).status == "INVALID_TEST_CONFIGURATION"


def test_authz_test_requires_bola_context_in_engine() -> None:
    result = AssessmentEngine([BrokenObjectLevelAuthorizationTest()]).assess_endpoints([endpoint("/users/{user_id}")])[0]

    assert result.status == "AUTHENTICATION_REQUIRED"


def test_bola_context_reports_safe_authenticated_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.bola_test.get_with_authentication",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("controlled failure")),
    )
    result = AssessmentEngine([BrokenObjectLevelAuthorizationTest()]).assess_endpoints(
        [endpoint("/users/{user_id}")],
        bola_context=bola_context(),
    )[0]

    assert result.status == "INCONCLUSIVE"
    assert result.authentication_mode == "bearer"
    assert result.authentication_configured is True
