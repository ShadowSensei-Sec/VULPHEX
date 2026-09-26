"""AUTHZ-001: bounded, explicit Broken Object Level Authorization testing."""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any

from .authentication import BOLAContext
from .discovery import ResolvedEndpoint
from .engine import AssessmentContext
from .http_client import get_with_authentication, response_evidence, sanitize_url
from .models import AssessmentResult


TEST_ID = "AUTHZ-001"
TEST_NAME = "Broken Object Level Authorization Test"
OBJECT_PARAMETER_NAMES = frozenset(
    {"id", "user_id", "userid", "account_id", "accountid", "order_id", "orderid", "resource_id", "resourceid"}
)
PATH_PARAMETER_PATTERN = re.compile(r"\{([^{}]+)\}")


class BrokenObjectLevelAuthorizationTest:
    """Compare one explicitly configured object through two authorized identities."""

    test_id = TEST_ID
    test_name = TEST_NAME
    requires_authentication = True
    requires_bola_context = True
    supported_methods = frozenset({"GET"})

    def execute(self, target: str) -> AssessmentResult:
        return _result(target, "INVALID_TEST_CONFIGURATION", "BOLA requires resolved endpoint and identity context.", {})

    def execute_context(self, context: AssessmentContext) -> AssessmentResult:
        endpoint = context.endpoint
        bola = context.bola
        if bola is None:
            return _result(endpoint.target, "INVALID_TEST_CONFIGURATION", "BOLA requires two explicitly configured identities.", {})
        if bola.identity_a.mode == "none" or bola.identity_b.mode == "none":
            return _result(endpoint.target, "AUTHENTICATION_REQUIRED", "BOLA requires authenticated primary and secondary identities.", {})
        if bola.object_reference is None:
            return _result(endpoint.target, "INVALID_TEST_CONFIGURATION", "BOLA requires one explicit object reference.", {})

        parameter = _select_parameter(endpoint, bola)
        if parameter is None:
            return _result(endpoint.target, "INVALID_TEST_CONFIGURATION", "No supported explicit object-reference path parameter was identified.", {})
        request_target = _substitute_path_parameter(endpoint.path, parameter, bola.object_reference)
        if request_target is None:
            return _result(endpoint.target, "INVALID_TEST_CONFIGURATION", "The endpoint contains unresolved path parameters after the selected substitution.", {"parameter": parameter})
        url = _replace_path(endpoint.target, request_target)
        try:
            baseline, baseline_time = get_with_authentication(url, bola.identity_a)
            secondary, secondary_time = get_with_authentication(url, bola.identity_b)
        except Exception:
            return _result(endpoint.target, "INCONCLUSIVE", "The bounded BOLA comparison could not complete safely.", {"parameter": parameter})

        baseline_body = _safe_body(baseline, bola.object_reference)
        secondary_body = _safe_body(secondary, bola.object_reference)
        comparison = {
            "status_match": baseline.status_code == secondary.status_code,
            "body_match": baseline_body == secondary_body,
            "body_presence_match": bool(baseline_body) == bool(secondary_body),
        }
        evidence = {
            "parameter": parameter,
            "object_reference": "[REDACTED]",
            "baseline": _safe_response_evidence(baseline, baseline_time, "primary", bola.object_reference),
            "cross_identity": _safe_response_evidence(secondary, secondary_time, "secondary", bola.object_reference),
            "comparison": comparison,
        }
        if baseline.status_code in {401, 403}:
            return _result(endpoint.target, "INCONCLUSIVE", "The primary identity could not establish an authorized baseline.", evidence)
        if secondary.status_code in {401, 403}:
            return _result(endpoint.target, "AUTHORIZATION_ENFORCED", "The secondary identity was denied access to the primary identity's object.", evidence)
        if secondary.status_code == 404:
            return _result(endpoint.target, "INCONCLUSIVE", "The secondary identity received a not-found response; authorization enforcement cannot be confirmed.", evidence)
        if 200 <= baseline.status_code < 300 and 200 <= secondary.status_code < 300 and comparison["body_match"]:
            return _result(endpoint.target, "POTENTIAL_BOLA", "Both identities received materially equivalent successful object responses.", evidence)
        return _result(endpoint.target, "INCONCLUSIVE", "The identity responses were not sufficiently equivalent to establish cross-user object access.", evidence)


def _select_parameter(endpoint: ResolvedEndpoint, bola: BOLAContext) -> str | None:
    names = {
        parameter.get("name")
        for parameter in endpoint.parameters or []
        if isinstance(parameter, dict) and parameter.get("in") == "path" and isinstance(parameter.get("name"), str)
    }
    if bola.parameter_name is not None:
        return bola.parameter_name if bola.parameter_name in names else None
    candidates = [name for name in names if name.lower().replace("-", "_") in OBJECT_PARAMETER_NAMES]
    return candidates[0] if len(candidates) == 1 else None


def _substitute_path_parameter(path: str, parameter: str, value: str) -> str | None:
    substituted = path.replace("{" + parameter + "}", value, 1)
    return substituted if not PATH_PARAMETER_PATTERN.search(substituted) else None


def _replace_path(target: str, path: str) -> str:
    parsed = target.split("/", 3)
    return "/".join(parsed[:3]) + path


def _safe_body(response: Any, object_reference: str | None = None) -> str:
    try:
        value = response.json()
    except (ValueError, json.JSONDecodeError):
        body = response.text[:500].strip()
    else:
        body = json.dumps(_normalize_json(value), sort_keys=True, separators=(",", ":"))
    return body.replace(object_reference, "[REDACTED]") if object_reference else body


def _normalize_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _normalize_json(item)
            for key, item in value.items()
            if key.lower() not in {"timestamp", "created_at", "updated_at", "request_id", "trace_id"}
        }
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    return value


def _safe_response_evidence(
    response: Any,
    response_time: float,
    identity: str,
    object_reference: str | None = None,
) -> dict[str, Any]:
    evidence = response_evidence(response, response_time)
    return {
        "identity": identity,
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type"),
        "response_time_ms": evidence["response_time_ms"],
        "body_preview": evidence["body_preview"].replace(object_reference, "[REDACTED]")
        if object_reference
        else evidence["body_preview"],
    }


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
        recommendation="Review object-level authorization with explicitly authorized identities and controlled references.",
    )