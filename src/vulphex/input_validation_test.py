"""INPUT-001: bounded, schema-driven API input validation testing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .discovery import ResolvedEndpoint
from .http_client import get_with_parameters, response_evidence, sanitize_url
from .models import AssessmentResult

TEST_ID = "INPUT-001"
TEST_NAME = "API Input Validation Test"
MAX_MUTATIONS = 3


@dataclass(frozen=True)
class InputMutation:
    parameter: str
    location: str
    schema_type: str | None
    format: str | None
    mutation_type: str
    value: str


class InputValidationTest:
    test_id = TEST_ID
    test_name = TEST_NAME
    requires_authentication = False
    supported_methods = frozenset({"GET"})

    def execute(self, target: str) -> AssessmentResult:
        return _result(target, "INCONCLUSIVE", "Input validation requires discovered endpoint schema metadata.", {})

    def execute_endpoint(self, endpoint: ResolvedEndpoint) -> AssessmentResult:
        if endpoint.method != "GET":
            return _result(endpoint.target, "UNSUPPORTED_OPERATION", "INPUT-001 currently supports GET endpoints only.", {})
        mutations = generate_mutations(endpoint.parameters or [])[:MAX_MUTATIONS]
        if not mutations:
            return _result(endpoint.target, "NOT_APPLICABLE", "No safely mutatable supported parameter schema was discovered.", {})
        if any(item.location != "query" for item in mutations):
            return _result(endpoint.target, "NOT_APPLICABLE", "Only query parameter mutation is currently supported safely.", {})

        baseline_params = {item.parameter: _baseline_value(item) for item in mutations}
        try:
            baseline, baseline_time = get_with_parameters(endpoint.target, baseline_params)
        except Exception:
            return _result(endpoint.target, "INCONCLUSIVE", "The baseline request could not complete safely.", {})
        if baseline.status_code >= 500:
            return _result(endpoint.target, "INCONCLUSIVE", "The baseline response did not establish a reachable endpoint.", {"baseline_status": baseline.status_code})

        observations: list[dict[str, Any]] = []
        for mutation in mutations:
            try:
                mutated_params = dict(baseline_params)
                if mutation.mutation_type == "missing_required":
                    mutated_params.pop(mutation.parameter, None)
                else:
                    mutated_params[mutation.parameter] = mutation.value
                response, response_time = get_with_parameters(endpoint.target, mutated_params)
            except Exception:
                return _result(endpoint.target, "INCONCLUSIVE", "A bounded mutation request could not complete safely.", {"parameter": mutation.parameter})
            evidence = response_evidence(response, response_time)
            observations.append({
                "parameter": mutation.parameter,
                "location": mutation.location,
                "schema_type": mutation.schema_type,
                "format": mutation.format,
                "mutation_type": mutation.mutation_type,
                "mutation": "[REDACTED]" if mutation.value else "",
                "baseline_status": baseline.status_code,
                "mutated_status": response.status_code,
                "content_type": response.headers.get("content-type"),
                "response_time_ms": evidence["response_time_ms"],
                "body_preview": evidence["body_preview"],
            })

        evidence = {
            "baseline": {
                "status_code": baseline.status_code,
                "content_type": baseline.headers.get("content-type"),
                "response_time_ms": round(baseline_time * 1000, 2),
            },
            "mutations": observations,
        }
        if all(item["mutated_status"] in {400, 401, 403, 404, 422} for item in observations):
            return _result(endpoint.target, "INPUT_VALIDATION_ENFORCED", "The endpoint rejected the generated invalid input values.", evidence)
        if any(200 <= item["mutated_status"] < 300 for item in observations):
            return _result(endpoint.target, "POTENTIAL_INPUT_VALIDATION_WEAKNESS", "The API accepted an input value that conflicts with the documented schema; manual validation is recommended.", evidence)
        return _result(endpoint.target, "INCONCLUSIVE", "The responses did not establish whether documented input validation is enforced.", evidence)


def extract_parameter_schema(parameter: dict[str, Any]) -> dict[str, Any] | None:
    schema = parameter.get("schema")
    if isinstance(schema, dict):
        return schema
    content = parameter.get("content")
    if isinstance(content, dict) and len(content) == 1:
        media = next(iter(content.values()))
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            return media["schema"]
    return None


def generate_mutations(parameters: list[dict[str, Any]]) -> list[InputMutation]:
    mutations: list[InputMutation] = []
    for parameter in parameters:
        if not isinstance(parameter, dict) or parameter.get("in") != "query":
            continue
        name = parameter.get("name")
        schema = extract_parameter_schema(parameter)
        if not isinstance(name, str) or schema is None:
            continue
        if parameter.get("required") is True:
            mutations.append(InputMutation(name, "query", schema.get("type"), schema.get("format"), "missing_required", ""))
            if len(mutations) >= MAX_MUTATIONS:
                break
            continue
        schema_type = schema.get("type") if isinstance(schema.get("type"), str) else None
        declared_format = schema.get("format") if isinstance(schema.get("format"), str) else None
        enum = schema.get("enum")
        if isinstance(enum, list) and enum:
            value = "__invalid_enum__"
            mutation_type = "invalid_enum"
        elif declared_format in {"email", "uuid", "date", "date-time"}:
            value = "not-a-valid-format"
            mutation_type = "invalid_format"
        elif schema_type in {"integer", "number"}:
            boundary = schema.get("minimum", schema.get("maximum"))
            value = str(boundary) if isinstance(boundary, (int, float)) else "not-a-number"
            mutation_type = "numeric_boundary" if boundary is not None else "invalid_type"
        elif schema_type == "boolean":
            value, mutation_type = "not-a-boolean", "invalid_type"
        elif schema_type == "string":
            value, mutation_type = "", "empty_string"
        else:
            continue
        mutations.append(InputMutation(name, parameter["in"], schema_type, declared_format, mutation_type, value))
        if len(mutations) >= MAX_MUTATIONS:
            break
    return mutations


def _baseline_value(mutation: InputMutation) -> str:
    if mutation.schema_type in {"integer", "number"}:
        return "1"
    if mutation.schema_type == "boolean":
        return "true"
    if mutation.format == "email":
        return "tester@example.test"
    if mutation.format == "uuid":
        return "00000000-0000-4000-8000-000000000001"
    if mutation.format == "date":
        return "2026-01-01"
    if mutation.format == "date-time":
        return "2026-01-01T00:00:00Z"
    return "valid-value"


def _result(target: str, status: str, reason: str, evidence: dict[str, Any]) -> AssessmentResult:
    return AssessmentResult(
        test_id=TEST_ID,
        test_name=TEST_NAME,
        target=sanitize_url(target),
        method="GET",
        status=status,
        observed_status_code=None,
        severity=None,
        reason=reason,
        evidence=evidence,
        recommendation="Review documented input contracts and server-side validation behavior.",
    )
