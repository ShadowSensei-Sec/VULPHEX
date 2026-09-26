import json

import httpx
import pytest

from vulphex.authentication import AuthenticationConfig
from vulphex.discovery import ResolvedEndpoint
from vulphex.nosql_injection_test import (
    NoSqlInjectionTest,
    detect_nosql_error_indicator,
    generate_nosql_probes,
    select_target_parameters,
)


def endpoint(parameters: list[dict], method: str = "GET") -> ResolvedEndpoint:
    return ResolvedEndpoint(
        method=method,
        target="https://example.test/search",
        path="/search",
        parameters=parameters,
        security=[{"bearerAuth": []}] if method == "GET" else None,
    )


def response(status: int, body: str, content_type: str = "application/json") -> httpx.Response:
    request = httpx.Request("GET", "https://example.test/search?q=vulphex-test")
    return httpx.Response(status, request=request, text=body, headers={"content-type": content_type})


def run_test(monkeypatch: pytest.MonkeyPatch, endpoint_value: ResolvedEndpoint, responses: list[httpx.Response]):
    calls: list[dict[str, str]] = []

    def fake_get(url: str, params: dict[str, str] | None = None, authentication=None, timeout: float = 10.0):
        calls.append(dict(params or {}))
        return responses[len(calls) - 1], 1.0

    monkeypatch.setattr("vulphex.nosql_injection_test.get_with_parameters", fake_get)
    result = NoSqlInjectionTest().execute_endpoint(endpoint_value)
    return result, calls


def test_identity_and_get_support() -> None:
    test = NoSqlInjectionTest()
    assert test.test_id == "INJ-002"
    assert test.test_name == "NoSQL Injection Detection Test"
    assert test.supported_methods == frozenset({"GET"})
    assert test.execute_endpoint(endpoint([], method="GET")).status == "NOT_APPLICABLE"


def test_unsupported_method_does_not_send_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulphex.nosql_injection_test.get_with_parameters", lambda *args, **kwargs: pytest.fail("request made"))
    result = NoSqlInjectionTest().execute_endpoint(endpoint([], method="POST"))
    assert result.status == "UNSUPPORTED_OPERATION"


def test_secure_endpoint_is_not_false_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(200, '{"result": "vulphex-test"}'),
        response(200, '{"result": "vulphex-test"}'),
    ])
    assert result.status == "NO_NOSQL_INJECTION_INDICATED"


def test_intentionally_vulnerable_fixture_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(200, '{"result": "nonexistent", "count": 12, "matches": [{"user": "alice"}]}'),
    ])
    assert result.status == "POTENTIAL_NOSQL_INJECTION"


def test_nosql_error_indicator_handles_common_mongodb_signals() -> None:
    assert detect_nosql_error_indicator("MongoServerError: E11000 duplicate key error collection") == "MONGODB_ERROR"
    assert detect_nosql_error_indicator("The query operator '$ne' is not allowed") == "NOSQL_QUERY_ERROR"
    assert detect_nosql_error_indicator("ServerError: unknown operator $gt") == "NOSQL_QUERY_ERROR"
    assert detect_nosql_error_indicator("unrelated internal failure") is None


def test_generic_http_500_is_not_auto_vulnerability(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(500, "Internal server error"),
    ])
    assert result.status == "NO_NOSQL_INJECTION_INDICATED"


def test_boolean_operator_differential_behaves_as_suspicious(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(200, '{"result": "special-user", "count": 1}'),
    ])
    assert result.status == "POTENTIAL_NOSQL_INJECTION"


def test_request_bound_stops_after_baseline_plus_four_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    parameters = [
        {"name": "q", "in": "query", "schema": {"type": "string"}},
        {"name": "category", "in": "query", "schema": {"type": "string"}},
        {"name": "page", "in": "query", "schema": {"type": "integer"}},
    ]
    result, calls = run_test(monkeypatch, endpoint(parameters), [
        response(200, '{"result": "vulphex-test"}'),
        response(400, 'bad request'),
        response(400, 'bad request'),
        response(400, 'bad request'),
        response(400, 'bad request'),
    ])
    assert result.status == "NO_NOSQL_INJECTION_INDICATED"
    assert len(calls) == 5


def test_max_selected_parameters_is_enforced() -> None:
    parameters = [
        {"name": "first", "in": "query", "schema": {"type": "string"}},
        {"name": "second", "in": "query", "schema": {"type": "string"}},
        {"name": "third", "in": "query", "schema": {"type": "string"}},
    ]
    assert [item["parameter"] for item in generate_nosql_probes(parameters)] == ["first", "second"]


def test_missing_or_invalid_parameter_metadata_is_handled_safely() -> None:
    assert select_target_parameters([{"name": "bad", "in": "query", "schema": {"type": "array"}}]) == []
    assert select_target_parameters([{"name": "ignored", "in": "path", "schema": {"type": "string"}}]) == []


def test_unresolved_path_parameters_are_not_tested() -> None:
    endpoint_value = ResolvedEndpoint(
        method="GET",
        target="https://example.test/users/123",
        path="/users/{user_id}",
        parameters=[{"name": "user_id", "in": "path", "schema": {"type": "integer"}}],
    )
    assert NoSqlInjectionTest().execute_endpoint(endpoint_value).status == "NOT_APPLICABLE"


def test_authentication_required_endpoint_without_credentials_is_handled_safely() -> None:
    secure_endpoint = ResolvedEndpoint(
        method="GET",
        target="https://example.test/protected",
        path="/protected",
        security=[{"bearerAuth": []}],
        security_defined=True,
    )
    result = NoSqlInjectionTest().execute_endpoint(secure_endpoint)
    assert result.status in {"AUTHENTICATION_REQUIRED", "NOT_APPLICABLE", "NO_NOSQL_INJECTION_INDICATED"}


def test_sensitive_credentials_are_not_present_in_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(500, "Authorization: Bearer top-secret and MongoServerError: E11000 duplicate key error collection"),
    ])
    payload = json.dumps(result.to_dict())
    assert "top-secret" not in payload
    assert "Authorization" not in payload
    assert "MONGODB_ERROR" in payload


def test_invalid_test_configuration_is_handled_safely() -> None:
    bad = ResolvedEndpoint(method="GET", target="https://example.test/search", path="/search", parameters="bad")
    result = NoSqlInjectionTest().execute_endpoint(bad)
    assert result.status in {"INVALID_TEST_CONFIGURATION", "NOT_APPLICABLE"}


def test_transport_errors_become_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}

    def fail(*args, **kwargs):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr("vulphex.nosql_injection_test.get_with_parameters", fail)
    assert NoSqlInjectionTest().execute_endpoint(endpoint([parameter])).status == "INCONCLUSIVE"


def test_sql_and_other_tests_remain_unaffected() -> None:
    from vulphex.sql_injection_test import SqlInjectionTest
    assert SqlInjectionTest().test_id == "INJ-001"
    assert NoSqlInjectionTest().test_id == "INJ-002"
