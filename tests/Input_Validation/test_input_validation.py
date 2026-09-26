import json

import httpx
import pytest

from vulphex.Discovery.discovery import ResolvedEndpoint
from vulphex.Input_validation.input_validation_test import (
    InputValidationTest,
    generate_mutations,
)


def endpoint(parameters: list[dict], method: str = "GET") -> ResolvedEndpoint:
    return ResolvedEndpoint(
        method=method,
        target="https://example.test/validate",
        path="/validate",
        parameters=parameters,
    )


def response(status: int, body: object) -> httpx.Response:
    return httpx.Response(status, request=httpx.Request("GET", "https://example.test/validate"), json=body)


def run_test(monkeypatch: pytest.MonkeyPatch, endpoint_value: ResolvedEndpoint, responses: list[httpx.Response]):
    calls: list[dict[str, str]] = []

    def fake_get(url: str, params: dict[str, str], authentication=None, timeout: float = 10.0):
        calls.append(params)
        return responses[len(calls) - 1], 1.0

    monkeypatch.setattr("vulphex.Input_validation.input_validation_test.get_with_parameters", fake_get)
    result = InputValidationTest().execute_endpoint(endpoint_value)
    return result, calls


def test_identity_and_no_schema_metadata() -> None:
    test = InputValidationTest()
    assert test.test_id == "INPUT-001"
    assert test.test_name == "API Input Validation Test"
    assert test.execute_endpoint(endpoint([])).status == "NOT_APPLICABLE"


def test_required_parameter_and_invalid_primitive_mutations_are_deterministic() -> None:
    parameters = [
        {"name": "age", "in": "query", "required": True, "schema": {"type": "integer"}},
        {"name": "enabled", "in": "query", "schema": {"type": "boolean"}},
        {"name": "kind", "in": "query", "schema": {"type": "string", "enum": ["a", "b"]}},
        {"name": "ignored", "in": "header", "schema": {"type": "string"}},
    ]

    mutations = generate_mutations(parameters)

    assert [(item.parameter, item.mutation_type) for item in mutations] == [
        ("age", "missing_required"),
        ("enabled", "invalid_type"),
        ("kind", "invalid_enum"),
    ]


def test_formats_numeric_boundaries_empty_string_and_content_schema() -> None:
    parameters = [
        {"name": "email", "in": "query", "schema": {"type": "string", "format": "email"}},
        {"name": "count", "in": "query", "schema": {"type": "integer", "minimum": 1}},
        {"name": "label", "in": "query", "schema": {"type": "string"}},
        {"name": "when", "in": "query", "content": {"text/plain": {"schema": {"type": "string", "format": "date"}}}},
    ]

    mutations = generate_mutations(parameters)

    assert [(item.parameter, item.mutation_type) for item in mutations] == [
        ("email", "invalid_format"),
        ("count", "numeric_boundary"),
        ("label", "empty_string"),
    ]


def test_secure_rejection_is_enforced_and_request_bound_is_three_mutations(monkeypatch: pytest.MonkeyPatch) -> None:
    parameters = [
        {"name": "age", "in": "query", "required": True, "schema": {"type": "integer"}},
        {"name": "enabled", "in": "query", "schema": {"type": "boolean"}},
    ]
    result, calls = run_test(monkeypatch, endpoint(parameters), [response(200, {}), response(422, {}), response(422, {})])

    assert result.status == "INPUT_VALIDATION_ENFORCED"
    assert len(calls) == 3
    assert "age" in calls[0]
    assert "age" not in calls[1]
    assert result.evidence["mutations"][0]["mutation"] == ""


def test_weak_acceptance_is_potential_weakness(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "age", "in": "query", "required": True, "schema": {"type": "integer"}}
    result, calls = run_test(monkeypatch, endpoint([parameter]), [response(200, {"age": 1}), response(200, {"age": "abc"})])

    assert result.status == "POTENTIAL_INPUT_VALIDATION_WEAKNESS"
    assert len(calls) == 2


def test_unsupported_method_does_not_send_request(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulphex.Input_validation.input_validation_test.get_with_parameters", lambda *args, **kwargs: pytest.fail("request made"))

    result = InputValidationTest().execute_endpoint(endpoint([], method="POST"))

    assert result.status == "UNSUPPORTED_OPERATION"


@pytest.mark.parametrize(
    "failure",
    [RuntimeError("baseline failed"), httpx.ReadTimeout("timeout")],
)
def test_request_failure_is_inconclusive(monkeypatch: pytest.MonkeyPatch, failure: Exception) -> None:
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr("vulphex.Input_validation.input_validation_test.get_with_parameters", fail)
    parameter = {"name": "age", "in": "query", "schema": {"type": "integer"}}

    assert InputValidationTest().execute_endpoint(endpoint([parameter])).status == "INCONCLUSIVE"


def test_credentials_and_mutation_values_are_not_exposed(monkeypatch: pytest.MonkeyPatch) -> None:
    parameter = {"name": "age", "in": "query", "schema": {"type": "integer"}}
    result, _ = run_test(monkeypatch, endpoint([parameter]), [response(200, {}), response(200, {"token": "secret-response"})])

    serialized = json.dumps(result.to_dict())
    assert "secret-response" not in serialized
    assert "not-a-number" not in serialized


def test_parameter_mutation_order_is_stable() -> None:
    parameters = [
        {"name": "first", "in": "query", "schema": {"type": "string"}},
        {"name": "second", "in": "query", "schema": {"type": "boolean"}},
    ]

    assert [item.parameter for item in generate_mutations(parameters)] == ["first", "second"]
