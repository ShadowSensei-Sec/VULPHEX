"""INJ-001: bounded, deterministic SQL injection detection."""

from __future__ import annotations

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

TEST_ID = "INJ-001"
TEST_NAME = "SQL Injection Detection Test"
MAX_QUERY_PARAMETERS = 2
MAX_PROBES_PER_PARAMETER = 2
MAX_REQUESTS_PER_ENDPOINT = 5


class SqlInjectionTest:
    """Bounded SQL injection detection for GET query parameters."""

    test_id = TEST_ID
    test_name = TEST_NAME
    requires_authentication = False
    supported_methods = frozenset({"GET"})

    def execute(self, target: str) -> AssessmentResult:
        return _result(target, "INCONCLUSIVE", "SQL injection assessment requires discovered endpoint metadata.", {})

    def execute_endpoint(self, endpoint: ResolvedEndpoint) -> AssessmentResult:
        if endpoint.method != "GET":
            return _result(
                endpoint.target,
                "UNSUPPORTED_OPERATION",
                "INJ-001 only supports GET endpoints and does not alter the original method.",
                {},
            )

        selected_parameters = select_target_parameters(endpoint.parameters or [])
        if not selected_parameters:
            return _result(
                endpoint.target,
                "NOT_APPLICABLE",
                "No supported query parameters were discovered for a bounded SQL injection probe.",
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
                "The baseline response did not establish a reachable endpoint for SQL injection assessment.",
                {
                    "baseline_status": baseline.status_code,
                    "baseline_content_type": baseline.headers.get("content-type"),
                    "baseline_body_preview": response_evidence(baseline, baseline_time)["body_preview"],
                },
            )

        observations: list[dict[str, Any]] = []
        probes = generate_sql_probes(endpoint.parameters or [])
        requests_used = 1
        sql_indicator: str | None = None

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
                        "A bounded SQL probe could not complete safely.",
                        {
                            "parameter": probe["parameter"],
                            "probe_identifier": payload["probe_identifier"],
                            "probe_type": payload["probe_type"],
                            "request_limit": MAX_REQUESTS_PER_ENDPOINT,
                        },
                    )

                comparison = _compare_responses(baseline, response, baseline_time, response_time)
                indicator = detect_sql_error_indicator(response.text)
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
                    "sql_error_indicator": indicator,
                    "comparison": comparison,
                }
                observations.append(observation)
                requests_used += 1
                if indicator is not None:
                    sql_indicator = indicator
                    break
                if _is_meaningful_differential(comparison):
                    sql_indicator = "differential_behavior"
                    break
                if response.status_code >= 500 and indicator is None:
                    break
            if observations and (observations[-1]["sql_error_indicator"] is not None or _is_meaningful_differential(observations[-1]["comparison"])):
                break

        if sql_indicator is not None:
            status = "POTENTIAL_SQL_INJECTION"
            reason = "The bounded SQL syntax probes triggered a database-style SQL error indicator or a clear differential behavior pattern."
        elif any(observation["probe_result_status"] >= 500 and observation["sql_error_indicator"] is None for observation in observations):
            status = "NO_SQL_INJECTION_INDICATED"
            reason = "The bounded probes returned a non-SQL 500 response and did not reveal a database-style SQL error indicator."
        elif any(_is_meaningful_differential(observation["comparison"]) for observation in observations):
            status = "POTENTIAL_SQL_INJECTION"
            reason = "The bounded SQL probes produced a repeatable differential response pattern that is not explained by ordinary validation rejection."
        else:
            status = "NO_SQL_INJECTION_INDICATED"
            reason = "No SQL-specific error indicator or meaningful differential behavior was observed from the bounded probes."

        evidence = {
            "parameter_count": len(selected_parameters),
            "baseline": {
                "status_code": baseline.status_code,
                "content_type": baseline.headers.get("content-type"),
                "response_time_ms": round(baseline_time, 2),
                "sanitized_body_preview": _sanitize_evidence_text(response_evidence(baseline, baseline_time)["body_preview"]),
            },
            "sql_error_indicator": sql_indicator,
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
                    "sql_error_indicator": item["sql_error_indicator"],
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
        if schema_type not in {"string", "integer", "number"}:
            continue
        selected.append({"name": name, "location": "query", "schema_type": schema_type, "format": schema.get("format")})
        if len(selected) >= MAX_QUERY_PARAMETERS:
            break
    return selected


def generate_sql_probes(parameters: list[dict[str, Any]]) -> list[dict[str, Any]]:
    generated: list[dict[str, Any]] = []
    for parameter in select_target_parameters(parameters):
        if parameter["schema_type"] == "string":
            payloads = [
                {"probe_type": "quote_break", "probe_identifier": "quote_break_1", "value": "' OR 1=1 --"},
                {"probe_type": "boolean_logic", "probe_identifier": "boolean_logic_1", "value": "' OR '1'='1 --"},
            ]
        else:
            payloads = [
                {"probe_type": "boolean_logic", "probe_identifier": "boolean_logic_1", "value": "1 OR 1=1 --"},
                {"probe_type": "numeric_break", "probe_identifier": "numeric_break_1", "value": "1 AND 1=1 --"},
            ]
        generated.append({
            "parameter": parameter["name"],
            "location": parameter["location"],
            "schema_type": parameter["schema_type"],
            "payloads": payloads[:MAX_PROBES_PER_PARAMETER],
        })
    return generated


def detect_sql_error_indicator(text: str) -> str | None:
    lowered = text.lower()
    if any(token in lowered for token in ("postgresql", "sqlstate", "pgerror")):
        return "postgresql"
    if any(token in lowered for token in ("mysql", "you have an error in your sql syntax")):
        return "mysql"
    if "sqlite error" in lowered or ("sqlite" in lowered and "syntax error" in lowered):
        return "sqlite"
    if any(token in lowered for token in ("microsoft sql server", "sqlserver", "sql server", "msg ")):
        return "mssql"
    if any(token in lowered for token in ("ora-", "oracle")):
        return "oracle"
    if "syntax error" in lowered or "sql syntax" in lowered or "database error" in lowered:
        return "sql_syntax"
    if "driver error" in lowered or "database driver" in lowered:
        return "database_driver"
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
    text = re.sub(r"(?i)\b(?:authorization|proxy-authorization)\s*:\s*", "[REDACTED]:", text)
    text = re.sub(r"(?i)\b(?:or\s+1=1|and\s+1=1|or\s+'1'='1|and\s+'1'='1)\b", "[REDACTED_SQL]", text)
    text = re.sub(r"(?i)((?:\b(?:api[_-]?key|access_token|refresh_token|password|secret|token)\b\s*[:=]\s*))[^\s,;]+", r"\1[REDACTED]", text)
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
    validation_markers = ("invalid", "bad request", "validation", "required", "missing", "must be", "not a valid", "syntax error")
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
        recommendation="Review the endpoint for SQL syntax handling and confirm the behavior with a manual vulnerability review.",
    )
