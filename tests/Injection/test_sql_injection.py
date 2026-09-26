import json

import httpx
import pytest

from vulphex.Discovery.discovery import ResolvedEndpoint
from vulphex.Injection.sql_injection_test import (
    SqlInjectionTest,
    detect_sql_error_indicator,
    generate_sql_probes,
)

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
        calls.append(params or {})
        return responses[len(calls) - 1], 1.0

    monkeypatch.setattr("vulphex.Injection.sql_injection_test.get_with_parameters", fake_get)
    result = SqlInjectionTest().execute_endpoint(endpoint_value)
    return result, calls


def test_identity_and_get_support() -> None:
    test = SqlInjectionTest()
    assert test.test_id == "INJ-001"
    assert test.test_name == "SQL Injection Detection Test"
    assert test.supported_methods == frozenset({"GET"})
    assert test.execute_endpoint(endpoint([], method="GET")).status == "NOT_APPLICABLE"


def test_unsupported_method_does_not_send_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulphex.Injection.sql_injection_test.get_with_parameters", lambda *args, **kwargs: pytest.fail("request made"))

    result = SqlInjectionTest().execute_endpoint(endpoint([], method="POST"))

    assert result.status == "UNSUPPORTED_OPERATION"


def test_no_suitable_query_parameter_is_not_applicable() -> None:
    parameters = [{"name": "payload", "in": "query", "schema": {"type": "object"}}]

    result = SqlInjectionTest().execute_endpoint(endpoint(parameters))

    assert result.status == "NOT_APPLICABLE"


def test_baseline_generation_uses_safe_schema_values() -> None:
    parameters = [
        {"name": "q", "in": "query", "schema": {"type": "string"}},
        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
        {"name": "ratio", "in": "query", "schema": {"type": "number"}},
    ]

    values = {param["name"]: _baseline_value(param) for param in parameters}

    assert values == {"q": "vulphex-test", "limit": "1", "ratio": "1"}


def test_baseline_failure_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}

    def fail(*args, **kwargs):
        raise RuntimeError("baseline down")

    monkeypatch.setattr("vulphex.Injection.sql_injection_test.get_with_parameters", fail)

    assert SqlInjectionTest().execute_endpoint(endpoint([parameter])).status == "INCONCLUSIVE"


def test_sql_probe_generation_is_deterministic() -> None:
    parameters = [
        {"name": "q", "in": "query", "schema": {"type": "string"}},
        {"name": "page", "in": "query", "schema": {"type": "integer"}},
        {"name": "ignored", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}},
    ]

    probes = generate_sql_probes(parameters)

    assert [item["parameter"] for item in probes] == ["q", "page"]
    assert len(probes[0]["payloads"]) == 2
    assert len(probes[1]["payloads"]) == 2


def test_request_bound_stops_after_baseline_plus_four_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    parameters = [
        {"name": "q", "in": "query", "schema": {"type": "string"}},
        {"name": "category", "in": "query", "schema": {"type": "string"}},
        {"name": "page", "in": "query", "schema": {"type": "integer"}},
    ]
    result, calls = run_test(monkeypatch, endpoint(parameters), [
        response(200, '{"ok": true}'),
        response(400, 'bad request'),
        response(400, 'bad request'),
        response(400, 'bad request'),
        response(400, 'bad request'),
    ])

    assert result.status == "NO_SQL_INJECTION_INDICATED"
    assert len(calls) == 5


def test_sql_error_indicator_classifies_sql_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"ok": true}'),
        response(500, "ERROR: syntax error at or near \"'\"; PostgreSQL SQLSTATE[42601]"),
    ])

    assert result.status == "POTENTIAL_SQL_INJECTION"
    assert result.evidence["sql_error_indicator"] == "postgresql"


def test_non_sql_500_does_not_auto_become_sqli(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"ok": true}'),
        response(500, "Internal server error"),
    ])

    assert result.status == "NO_SQL_INJECTION_INDICATED"


def test_controlled_differential_behavior_is_potential_sqli(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"result": "vulphex-test"}'),
        response(200, '{"result": "vulphex-test"}'),
        response(200, '{"result": "sql-error"}'),
    ])

    assert result.status == "POTENTIAL_SQL_INJECTION"


def test_timeout_or_connection_failure_is_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}

    def fail(*args, **kwargs):
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr("vulphex.Injection.sql_injection_test.get_with_parameters", fail)

    assert SqlInjectionTest().execute_endpoint(endpoint([parameter])).status == "INCONCLUSIVE"


def test_sensitive_values_are_redacted_from_evidence() -> None:
    parameter = {"name": "token", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch := pytest.MonkeyPatch(), endpoint([parameter]), [
        response(200, '{"ok": true}'),
        response(500, "Authorization: Bearer secret-token and SQLSTATE[42000]"),
    ])

    serialized = json.dumps(result.to_dict())
    assert "secret-token" not in serialized
    assert "Authorization" not in serialized
    assert "postgresql" in serialized


def test_evidence_sanitizes_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "q", "in": "query", "schema": {"type": "string"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [
        response(200, '{"ok": true}'),
        response(500, "SQLSTATE[42000]: syntax error at or near \"' OR 1=1 --\""),
    ])

    payload_text = json.dumps(result.to_dict())
    assert "OR 1=1" not in payload_text
    assert "syntax error" in payload_text


def test_deterministic_parameter_order_is_stable() -> None:
    parameters = [
        {"name": "second", "in": "query", "schema": {"type": "string"}},
        {"name": "first", "in": "query", "schema": {"type": "integer"}},
    ]

    assert [item["parameter"] for item in generate_sql_probes(parameters)] == ["second", "first"]


def test_detect_sql_error_indicator_handles_sqlstate_patterns() -> None:
    assert detect_sql_error_indicator("SQLSTATE[42000]: syntax error at or near 'x'") == "postgresql"
    assert detect_sql_error_indicator("You have an error in your SQL syntax; MySQL server") == "mysql"
    assert detect_sql_error_indicator("SQLite error: near \"x\": syntax error") == "sqlite"
    assert detect_sql_error_indicator("unrelated internal failure") is None


def _baseline_value(parameter: dict) -> str:
    schema = parameter.get("schema", {})
    type_name = schema.get("type")
    if type_name in {"integer", "number"}:
        return "1"
    return "vulphex-test"
