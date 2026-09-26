import json

import httpx
import pytest

from vulphex.authentication import AuthenticationConfig, BFLAContext
from vulphex.bfla_test import BrokenFunctionLevelAuthorizationTest
from vulphex.discovery import ResolvedEndpoint
from vulphex.engine import AssessmentContext, AssessmentEngine


def endpoint(path: str = "/admin/reports", method: str = "GET") -> ResolvedEndpoint:
    return ResolvedEndpoint(method=method, target=f"https://example.test{path}", path=path)


def context(path: str | None = "/admin/reports", method: str | None = "GET") -> BFLAContext:
    return BFLAContext(
        privileged_identity=AuthenticationConfig(mode="bearer", token="admin-secret"),
        lower_privilege_identity=AuthenticationConfig(mode="bearer", token="user-secret"),
        path=path,
        method=method,
    )


def response(status: int, body: object) -> httpx.Response:
    return httpx.Response(status, request=httpx.Request("GET", "https://example.test/admin/reports"), json=body)


def run_test(monkeypatch: pytest.MonkeyPatch, endpoint_value: ResolvedEndpoint, bfla: BFLAContext, responses: list[httpx.Response]):
    calls: list[tuple[str, dict[str, str]]] = []

    def fake_get(url: str, authentication: AuthenticationConfig, timeout: float = 10.0):
        calls.append((url, authentication.request_headers()))
        return responses[len(calls) - 1], 1.0

    monkeypatch.setattr("vulphex.bfla_test.get_with_authentication", fake_get)
    result = BrokenFunctionLevelAuthorizationTest().execute_context(AssessmentContext(endpoint_value, bfla=bfla))
    return result, calls


def test_missing_bfla_context_is_not_executed() -> None:
    result = BrokenFunctionLevelAuthorizationTest().execute_context(AssessmentContext(endpoint()))

    assert result.status == "INVALID_TEST_CONFIGURATION"


def test_missing_identity_is_authentication_required() -> None:
    incomplete = BFLAContext(AuthenticationConfig(), AuthenticationConfig(), "/admin/reports", "GET")

    result = BrokenFunctionLevelAuthorizationTest().execute_context(AssessmentContext(endpoint(), bfla=incomplete))

    assert result.status == "AUTHENTICATION_REQUIRED"


def test_missing_target_path_or_method_is_invalid() -> None:
    assert BrokenFunctionLevelAuthorizationTest().execute_context(
        AssessmentContext(endpoint(), bfla=context(None, "GET"))
    ).status == "INVALID_TEST_CONFIGURATION"
    assert BrokenFunctionLevelAuthorizationTest().execute_context(
        AssessmentContext(endpoint(), bfla=context("/admin/reports", None))
    ).status == "INVALID_TEST_CONFIGURATION"


def test_target_mismatch_makes_no_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    monkeypatch.setattr("vulphex.bfla_test.get_with_authentication", lambda *args: calls.append(args))

    result = BrokenFunctionLevelAuthorizationTest().execute_context(
        AssessmentContext(endpoint("/other"), bfla=context())
    )

    assert result.status == "INVALID_TEST_CONFIGURATION"
    assert calls == []


def test_privileged_success_and_lower_denial_are_authorization_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = run_test(monkeypatch, endpoint(), context(), [response(200, {"report": "ok"}), response(403, {})])

    assert result.status == "AUTHORIZATION_ENFORCED"
    assert len(calls) == 2
    assert calls[0][0] == calls[1][0] == "https://example.test/admin/reports"
    assert calls[0][1] == {"Authorization": "Bearer admin-secret"}
    assert calls[1][1] == {"Authorization": "Bearer user-secret"}


def test_lower_identity_401_is_authorization_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = run_test(monkeypatch, endpoint(), context(), [response(200, {}), response(401, {})])

    assert result.status == "AUTHORIZATION_ENFORCED"


@pytest.mark.parametrize("status", [404, 500])
def test_ambiguous_lower_identity_status_is_inconclusive(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    result, _ = run_test(monkeypatch, endpoint(), context(), [response(200, {}), response(status, {})])

    assert result.status == "INCONCLUSIVE"


def test_lower_success_is_potential_bfla(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = run_test(monkeypatch, endpoint(), context(), [response(200, {"report": "ok"}), response(200, {"report": "ok"})])

    assert result.status == "POTENTIAL_BFLA"
    assert len(calls) == 2


def test_privileged_baseline_failure_stops_classification_but_keeps_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    result, calls = run_test(monkeypatch, endpoint(), context(), [response(403, {}), response(200, {})])

    assert result.status == "INCONCLUSIVE"
    assert len(calls) == 2


def test_post_is_not_applicable_in_engine() -> None:
    result = AssessmentEngine([BrokenFunctionLevelAuthorizationTest()]).assess_endpoints(
        [endpoint("/admin/reports", "POST")],
        bfla_context=context(),
    )[0]

    assert result.status == "NOT_APPLICABLE"


def test_bfla_requires_explicit_context_even_with_single_authentication() -> None:
    result = AssessmentEngine([BrokenFunctionLevelAuthorizationTest()]).assess_endpoints(
        [endpoint()],
        authentication=AuthenticationConfig(mode="bearer", token="single-secret"),
    )[0]

    assert result.status == "AUTHENTICATION_REQUIRED"


def test_bfla_evidence_contains_safe_function_and_identity_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    result, _ = run_test(monkeypatch, endpoint(), context(), [response(200, {"report": "ok"}), response(403, {})])

    serialized = json.dumps(result.to_dict())
    assert result.evidence["privileged_identity"] == "identity_a"
    assert result.evidence["lower_privilege_identity"] == "identity_b"
    assert "/admin/reports" in serialized
    assert "admin-secret" not in serialized
    assert "user-secret" not in serialized


def test_bfla_order_follows_existing_security_test_order() -> None:
    class Stub:
        def __init__(self, test_id: str):
            self.test_id = test_id
            self.test_name = test_id
            self.requires_authentication = False

        def execute(self, target: str):
            from vulphex.models import AssessmentResult

            return AssessmentResult(self.test_id, self.test_name, target, "GET", "INCONCLUSIVE", None, None, "test", {}, "review")

    results = AssessmentEngine([
        Stub("AUTH-001"),
        Stub("AUTH-002"),
        Stub("AUTHZ-001"),
        BrokenFunctionLevelAuthorizationTest(),
    ]).assess_endpoints([endpoint()])

    assert [result.test_id for result in results] == ["AUTH-001", "AUTH-002", "AUTHZ-001", "AUTHZ-002"]
