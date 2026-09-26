import json

import httpx
import pytest

from vulphex.Injection.command_injection_test import (
    CommandInjectionTest,
    detect_command_error_indicator,
    generate_command_probes,
    select_target_parameters,
)
from vulphex.Discovery.discovery import ResolvedEndpoint


def endpoint(parameters: list[dict], method: str = "GET") -> ResolvedEndpoint:
    return ResolvedEndpoint(
        method=method,
        target="https://example.test/search",
        path="/search",
        parameters=parameters,
    )


def response(status: int, body: str, content_type: str = "application/json") -> httpx.Response:
    request = httpx.Request("GET", "https://example.test/search?q=vulphex-test")
    return httpx.Response(status, request=request, text=body, headers={"content-type": content_type})


def run_test(monkeypatch: pytest.MonkeyPatch, endpoint_value: ResolvedEndpoint, responses: list[httpx.Response]):
    calls: list[dict[str, str]] = []

    def fake_get(url: str, params: dict[str, str] | None = None, authentication=None, timeout: float = 10.0):
        calls.append(dict(params or {}))
        return responses[len(calls) - 1], 1.0

    monkeypatch.setattr("vulphex.Injection.command_injection_test.get_with_parameters", fake_get)
    result = CommandInjectionTest().execute_endpoint(endpoint_value)
    return result, calls


def test_identity_and_get_support() -> None:
    test = CommandInjectionTest()
    assert test.test_id == "INJ-003"
    assert test.test_name == "OS Command Injection Detection Test"
    assert test.supported_methods == frozenset({"GET"})
    assert test.execute_endpoint(endpoint([], method="GET")).status == "NOT_APPLICABLE"


def test_unsupported_method_does_not_send_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulphex.Injection.command_injection_test.get_with_parameters", lambda *args, **kwargs: pytest.fail("request made"))
    result = CommandInjectionTest().execute_endpoint(endpoint([], method="POST"))
    assert result.status == "UNSUPPORTED_OPERATION"


def test_secure_endpoint_is_not_false_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(200, '{"result": "vulphex-test"}'),
        response(200, '{"result": "vulphex-test"}'),
    ])
    assert result.status == "NO_COMMAND_INJECTION_INDICATED"


def test_intentionally_vulnerable_simulation_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(500, 'sh: syntax error near unexpected token ";"'),
    ])
    assert result.status == "POTENTIAL_COMMAND_INJECTION"


def test_command_parser_error_indicator_detects_shell_syntax(monkeypatch: pytest.MonkeyPatch) -> None:
    assert detect_command_error_indicator("sh: syntax error near unexpected token ';'") == "UNIX_SHELL_ERROR"
    assert detect_command_error_indicator("The system cannot find the path specified") == "WINDOWS_COMMAND_ERROR"
    assert detect_command_error_indicator("parse error: unexpected token") == "SHELL_SYNTAX_ERROR"
    assert detect_command_error_indicator("unrelated internal failure") is None


def test_generic_http_500_is_not_auto_vulnerability(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(500, "Internal server error"),
    ])
    assert result.status == "NO_COMMAND_INJECTION_INDICATED"


def test_differential_response_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(200, '{"result": "shell-parse", "detail": "SHELL"}'),
    ])
    assert result.status == "POTENTIAL_COMMAND_INJECTION"


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
    assert result.status == "NO_COMMAND_INJECTION_INDICATED"
    assert len(calls) == 5


def test_max_selected_parameters_is_enforced() -> None:
    parameters = [
        {"name": "first", "in": "query", "schema": {"type": "string"}},
        {"name": "second", "in": "query", "schema": {"type": "string"}},
        {"name": "third", "in": "query", "schema": {"type": "string"}},
    ]
    assert [item["parameter"] for item in generate_command_probes(parameters)] == ["first", "second"]


def test_unsuitable_parameters_are_skipped_safely() -> None:
    assert select_target_parameters([{"name": "page", "in": "query", "schema": {"type": "integer"}}]) == []
    assert select_target_parameters([{"name": "ignored", "in": "path", "schema": {"type": "string"}}]) == []


def test_unresolved_path_parameters_are_not_tested() -> None:
    endpoint_value = ResolvedEndpoint(
        method="GET",
        target="https://example.test/users/123",
        path="/users/{user_id}",
        parameters=[{"name": "user_id", "in": "path", "schema": {"type": "integer"}}],
    )
    assert CommandInjectionTest().execute_endpoint(endpoint_value).status == "NOT_APPLICABLE"


def test_authentication_required_endpoint_without_credentials_is_handled_safely() -> None:
    secure_endpoint = ResolvedEndpoint(
        method="GET",
        target="https://example.test/protected",
        path="/protected",
        security=[{"bearerAuth": []}],
        security_defined=True,
    )
    result = CommandInjectionTest().execute_endpoint(secure_endpoint)
    assert result.status in {"AUTHENTICATION_REQUIRED", "NOT_APPLICABLE", "NO_COMMAND_INJECTION_INDICATED"}


def test_sensitive_credentials_are_absent_from_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(500, "Authorization: Bearer top-secret and sh: syntax error near unexpected token ';'"),
    ])
    payload = json.dumps(result.to_dict())
    assert "top-secret" not in payload
    assert "Authorization" not in payload
    assert "UNIX_SHELL_ERROR" in payload


def test_invalid_configuration_is_handled_safely() -> None:
    bad = ResolvedEndpoint(method="GET", target="https://example.test/search", path="/search", parameters="bad")
    result = CommandInjectionTest().execute_endpoint(bad)
    assert result.status in {"INVALID_TEST_CONFIGURATION", "NOT_APPLICABLE"}


def test_transport_errors_become_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}

    def fail(*args, **kwargs):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr("vulphex.Injection.command_injection_test.get_with_parameters", fail)
    assert CommandInjectionTest().execute_endpoint(endpoint([parameter])).status == "INCONCLUSIVE"


def test_existing_sql_and_nosql_tests_remain_unaffected() -> None:
    from vulphex.Injection.nosql_injection_test import NoSqlInjectionTest
    from vulphex.Injection.sql_injection_test import SqlInjectionTest
    assert SqlInjectionTest().test_id == "INJ-001"
    assert NoSqlInjectionTest().test_id == "INJ-002"
    assert CommandInjectionTest().test_id == "INJ-003"


def test_implementation_does_not_import_or_invoke_subprocess_shell_functions() -> None:
    import sys
    module = sys.modules.get("vulphex.Injection.command_injection_test")
    assert module is not None
    assert not hasattr(module, "subprocess")
    assert not hasattr(module, "os")
