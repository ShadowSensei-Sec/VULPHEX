"""INJ-002: bounded, deterministic NoSQL injection detection."""

from __future__ import annotations

import json
import re
from typing import Any

from ..Discovery.discovery import ResolvedEndpoint
from ..Core.http_client import (
    get_with_parameters,
    redact_sensitive_text,
    response_evidence,
    sanitize_url,
)
from ..Core.models import AssessmentResult

TEST_ID = "INJ-002"
TEST_NAME = "NoSQL Injection Detection Test"
MAX_QUERY_PARAMETERS = 2
MAX_PROBES_PER_PARAMETER = 2
MAX_REQUESTS_PER_ENDPOINT = 5


class NoSqlInjectionTest:
    """Bounded NoSQL/document-query detection for GET query parameters."""

    test_id = TEST_ID
    test_name = TEST_NAME
    requires_authentication = False
    supported_methods = frozenset({"GET"})

    def execute(self, target: str) -> AssessmentResult:
        return _result(target, "INCONCLUSIVE", "NoSQL injection assessment requires discovered endpoint metadata.", {})

    def execute_endpoint(self, endpoint: ResolvedEndpoint) -> AssessmentResult:
        if endpoint.method != "GET":
            return _result(
                endpoint.target,
                "UNSUPPORTED_OPERATION",
                "INJ-002 only supports GET endpoints and does not alter the original method.",
                {},
            )

        if endpoint.security_defined and endpoint.security:
            return _result(
                endpoint.target,
                "AUTHENTICATION_REQUIRED",
                "This endpoint requires an explicitly supplied authenticated assessment context before running the NoSQL probe.",
                {"reason": "authentication_context_required"},
            )

        if not isinstance(endpoint.parameters, list):
            return _result(
                endpoint.target,
                "INVALID_TEST_CONFIGURATION",
                "NoSQL injection assessment requires a safe list of documented endpoint parameters.",
                {"parameter_count": 0},
            )

        selected_parameters = select_target_parameters(endpoint.parameters)
        if not selected_parameters:
            return _result(
                endpoint.target,
                "NOT_APPLICABLE",
                "No safely mutatable query parameters were discovered for a bounded NoSQL injection probe.",
                {},
            )

        baseline_params = {entry["name"]: _baseline_value(entry["schema_type"]) for entry in selected_parameters}
        try:
            baseline, baseline_time = get_with_parameters(endpoint.target, baseline_params)
        except Exception:
            return _result(endpoint.target, "INCONCLUSIVE", "The baseline request could not complete safely.", {})

        if baseline.status_code >= 500:
            return _result(
                endpoint.target,
                "INCONCLUSIVE",
                "The baseline response did not establish a reachable endpoint for NoSQL injection assessment.",
                {
                    "baseline_status": baseline.status_code,
                    "baseline_content_type": baseline.headers.get("content-type"),
                    "baseline_body_preview": response_evidence(baseline, baseline_time)["body_preview"],
                },
            )

        observations: list[dict[str, Any]] = []
        probes = generate_nosql_probes(endpoint.parameters)
        requests_used = 1
        nosql_indicator: str | None = None

        for probe in probes[:MAX_QUERY_PARAMETERS]:
            for payload in probe["payloads"][:MAX_PROBES_PER_PARAMETER]:
                if requests_used >= MAX_REQUESTS_PER_ENDPOINT:
                    break
                mutated_params = dict(baseline_params)
                mutated_params[probe["parameter"]] = payload["value"]
                try:
                    response, response_time = get_with_parameters(endpoint.target, mutated_params)
                except Exception:
                    return _result(
                        endpoint.target,
                        "INCONCLUSIVE",
                        "A bounded NoSQL probe could not complete safely.",
                        {
                            "parameter": probe["parameter"],
                            "probe_identifier": payload["probe_identifier"],
                            "probe_type": payload["probe_type"],
                            "request_limit": MAX_REQUESTS_PER_ENDPOINT,
                        },
                    )

                comparison = _compare_responses(baseline, response, baseline_time, response_time)
                indicator = detect_nosql_error_indicator(response.text)
                body_preview = _sanitize_evidence_text(response_evidence(response, response_time)["body_preview"])
                observation = {
                    "parameter": probe["parameter"],
                    "location": probe["location"],
                    "schema_type": probe["schema_type"],
                    "probe_type": payload["probe_type"],
                    "probe_identifier": payload["probe_identifier"],
                    "probe_result_status": response.status_code,
                    "content_type": response.headers.get("content-type"),
                    "response_time_ms": round(response_time, 2),
                    "sanitized_body_preview": body_preview,
                    "nosql_error_indicator": indicator,
                    "comparison": comparison,
                }
                observations.append(observation)
                requests_used += 1
                if indicator is not None:
                    nosql_indicator = indicator
                    break
                if _is_meaningful_differential(comparison):
                    nosql_indicator = "differential_behavior"
                    break
                if response.status_code >= 500 and indicator is None:
                    break
            if observations and (observations[-1]["nosql_error_indicator"] is not None or _is_meaningful_differential(observations[-1]["comparison"])):
                break

        if nosql_indicator is not None:
            status = "POTENTIAL_NOSQL_INJECTION"
            reason = "The bounded NoSQL probes triggered a database-style NoSQL error indicator or a clear differential behavior pattern."
        elif any(observation["probe_result_status"] >= 500 and observation["nosql_error_indicator"] is None for observation in observations):
            status = "NO_NOSQL_INJECTION_INDICATED"
            reason = "The bounded probes returned a generic non-NoSQL 500 response and did not reveal a database-style NoSQL error indicator."
        elif any(_is_meaningful_differential(observation["comparison"]) for observation in observations):
            status = "POTENTIAL_NOSQL_INJECTION"
            reason = "The bounded NoSQL probes produced a differential response pattern consistent with operator interpretation."
        else:
            status = "NO_NOSQL_INJECTION_INDICATED"
            reason = "No NoSQL-specific error indicator or meaningful differential behavior was observed from the bounded probes."

        evidence = {
            "parameter_count": len(selected_parameters),
            "baseline": {
                "status_code": baseline.status_code,
                "content_type": baseline.headers.get("content-type"),
                "response_time_ms": round(baseline_time, 2),
                "sanitized_body_preview": _sanitize_evidence_text(response_evidence(baseline, baseline_time)["body_preview"]),
            },
            "nosql_error_indicator": nosql_indicator,
            "probes": [
                {
                    "parameter": item["parameter"],
                    "location": item["location"],
                    "schema_type": item["schema_type"],
                    "probe_type": item["probe_type"],
                    "probe_identifier": item["probe_identifier"],
                    "probe_result_status": item["probe_result_status"],
                    "content_type": item["content_type"],
                    "response_time_ms": item["response_time_ms"],
                    "sanitized_body_preview": item["sanitized_body_preview"],
                    "nosql_error_indicator": item["nosql_error_indicator"],
                    "comparison": {
                        "status_changed": item["comparison"]["status_changed"],
                        "content_type_changed": item["comparison"]["content_type_changed"],
                        "body_preview_changed": item["comparison"]["body_preview_changed"],
                        "length_changed": item["comparison"]["length_changed"],
                    },
                }
                for item in observations
            ],
            "request_limit": MAX_REQUESTS_PER_ENDPOINT,
            "selected_parameters": [
                {"parameter": item["name"], "location": item["location"], "schema_type": item["schema_type"]}
                for item in selected_parameters
            ],
        }
        return _result(endpoint.target, status, reason, evidence)


def select_target_parameters(parameters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for parameter in parameters:
        if not isinstance(parameter, dict) or parameter.get("in") != "query":
            continue
        name = parameter.get("name")
        schema = _extract_schema(parameter)
        if not isinstance(name, str) or schema is None:
            continue
        schema_type = schema.get("type")
        if schema_type not in {"string", "integer", "number", "boolean", "object"}:
            continue
        selected.append({"name": name, "location": "query", "schema_type": schema_type, "format": schema.get("format")})
        if len(selected) >= MAX_QUERY_PARAMETERS:
            break
    return selected


def generate_nosql_probes(parameters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    generated: list[dict[str, Any]] = []
    for parameter in select_target_parameters(parameters):
        schema_type = parameter["schema_type"]
        if schema_type == "object":
            payloads = [
                {"probe_type": "operator_ne", "probe_identifier": "operator_ne_1", "value": {"$ne": "nonexistent"}},
                {"probe_type": "operator_gt", "probe_identifier": "operator_gt_1", "value": {"$gt": 0}},
            ]
        elif schema_type in {"integer", "number"}:
            payloads = [
                {"probe_type": "operator_ne", "probe_identifier": "operator_ne_1", "value": {"$ne": 0}},
                {"probe_type": "operator_gt", "probe_identifier": "operator_gt_1", "value": {"$gt": 0}},
            ]
        else:
            payloads = [
                {"probe_type": "operator_ne", "probe_identifier": "operator_ne_1", "value": "nonexistent"},
                {"probe_type": "operator_regex", "probe_identifier": "operator_regex_1", "value": "^.*$"},
            ]
        generated.append({
            "parameter": parameter["name"],
            "location": parameter["location"],
            "schema_type": schema_type,
            "payloads": payloads[:MAX_PROBES_PER_PARAMETER],
        })
    return generated


def detect_nosql_error_indicator(text: str) -> str | None:
    lowered = text.lower()
    if any(token in lowered for token in ("mongoservererror", "e11000 duplicate key error", "duplicate key error collection", "mongodb")):
        return "MONGODB_ERROR"
    if any(token in lowered for token in ("nosql", "query operator", "unknown operator", "$ne", "$gt", "$regex", "document query")):
        return "NOSQL_QUERY_ERROR"
    if any(token in lowered for token in ("mongo", "bson", "bsonerror")):
        return "MONGODB_ERROR"
    return None


def _extract_schema(parameter: dict[str, Any]) -> dict[str, Any] | None:
    schema = parameter.get("schema")
    if isinstance(schema, dict):
        return schema
    content = parameter.get("content")
    if isinstance(content, dict) and len(content) == 1:
        media = next(iter(content.values()))
        if isinstance(media, dict) and isinstance(media.get("schema"), dict):
            return media["schema"]
    return None


def _baseline_value(schema_type: str | None) -> str:
    if schema_type in {"integer", "number"}:
        return "1"
    if schema_type == "boolean":
        return "true"
    return "vulphex-test"


def _compare_responses(baseline: Any, probe: Any, baseline_time_ms: float, probe_time_ms: float) -> dict[str, Any]:
    baseline_preview = _sanitize_evidence_text(response_evidence(baseline, baseline_time_ms)["body_preview"])
    probe_preview = _sanitize_evidence_text(response_evidence(probe, probe_time_ms)["body_preview"])
    baseline_type = baseline.headers.get("content-type")
    probe_type = probe.headers.get("content-type")
    comparison = {
        "status_changed": baseline.status_code != probe.status_code,
        "content_type_changed": baseline_type != probe_type,
        "body_preview_changed": baseline_preview != probe_preview,
        "length_changed": len(baseline.text) != len(probe.text),
        "baseline_status": baseline.status_code,
        "probe_status": probe.status_code,
        "baseline_body_preview": baseline_preview,
        "probe_body_preview": probe_preview,
    }
    return comparison


def _sanitize_evidence_text(value: str) -> str:
    text = redact_sensitive_text(value)
    text = re.sub(r"(?i)\b(?:authorization|proxy-authorization)\b\s*:\s*(?:bearer\s+)?[^\n\r,;]+", "[REDACTED_AUTH]", text)
    text = re.sub(r"(?i)\b(?:authorization|proxy-authorization)\b\s*[:=]\s*[^\s,;]+", "[REDACTED_AUTH]", text)
    text = re.sub(r"(?i)\b(?:authorization|proxy-authorization)\b", "[REDACTED_AUTH]", text)
    text = re.sub(r"(?i)(api[_-]?key|access_token|refresh_token|password|secret|token)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
    return text.strip()


def _is_meaningful_differential(comparison: dict[str, Any]) -> bool:
    baseline_status = comparison.get("baseline_status", 200)
    probe_status = comparison.get("probe_status", 200)
    if baseline_status in {400, 401, 403, 404, 422} or probe_status in {400, 401, 403, 404, 422}:
        return False
    if probe_status >= 500:
        return False
    if not comparison.get("body_preview_changed"):
        return False
    probe_body = str(comparison.get("probe_body_preview", "")).lower()
    baseline_body = str(comparison.get("baseline_body_preview", "")).lower()
    if not probe_body or not baseline_body:
        return True
    validation_markers = ("invalid", "bad request", "validation", "required", "missing", "must be", "not a valid")
    if any(marker in probe_body for marker in validation_markers) or any(marker in baseline_body for marker in validation_markers):
        return False
    if comparison.get("status_changed") or comparison.get("content_type_changed") or comparison.get("length_changed"):
        return True
    return False


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
        recommendation="Review the endpoint for document-query/operator handling and confirm the behavior with a manual vulnerability review.",
    )
