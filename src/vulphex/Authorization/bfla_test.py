"""AUTHZ-002: bounded, explicitly targeted function-level authorization testing."""

from __future__ import annotations

from typing import Any

from ..Authentication.authentication import BFLAContext
from ..Discovery.discovery import ResolvedEndpoint
from ..Core.engine import AssessmentContext
from ..Core.http_client import (
    get_with_authentication,
    response_evidence,
    sanitize_url,
)
from ..Core.models import AssessmentResult


TEST_ID = "AUTHZ-002"
TEST_NAME = "Broken Function Level Authorization Test"


class BrokenFunctionLevelAuthorizationTest:
    """Compare one explicitly restricted function through two configured identities."""

    test_id = TEST_ID
    test_name = TEST_NAME
    requires_authentication = True
    requires_bfla_context = True
    supported_methods = frozenset({"GET"})

    def execute(self, target: str) -> AssessmentResult:
        return _result(target, "INVALID_TEST_CONFIGURATION", "BFLA requires a resolved endpoint and explicit function context.")

    def execute_context(self, context: AssessmentContext) -> AssessmentResult:
        endpoint = context.endpoint
        bfla = context.bfla
        if bfla is None:
            return _result(endpoint.target, "INVALID_TEST_CONFIGURATION", "BFLA requires an explicit restricted function context.")
        if bfla.privileged_identity.mode == "none" or bfla.lower_privilege_identity.mode == "none":
            return _result(endpoint.target, "AUTHENTICATION_REQUIRED", "BFLA requires configured privileged and lower-privilege identities.")
        if not bfla.path or not bfla.method:
            return _result(endpoint.target, "INVALID_TEST_CONFIGURATION", "BFLA requires an explicit target path and HTTP method.")
        if endpoint.path != bfla.path or endpoint.method != bfla.method.upper():
            return _result(endpoint.target, "INVALID_TEST_CONFIGURATION", "The configured BFLA function does not match this discovered endpoint.")
        if "{" in endpoint.path or "}" in endpoint.target:
            return _result(endpoint.target, "INVALID_TEST_CONFIGURATION", "BFLA cannot execute an unresolved endpoint target.")
        if endpoint.method != "GET":
            return _result(endpoint.target, "UNSUPPORTED_OPERATION", "BFLA currently supports safe GET functions only.")

        try:
            privileged, privileged_time = get_with_authentication(endpoint.target, bfla.privileged_identity)
            lower, lower_time = get_with_authentication(endpoint.target, bfla.lower_privilege_identity)
        except Exception:
            return _result(endpoint.target, "INCONCLUSIVE", "The bounded BFLA comparison could not complete safely.")

        evidence = {
            "privileged_identity": "identity_a",
            "lower_privilege_identity": "identity_b",
            "function": {"method": endpoint.method, "path": endpoint.path},
            "baseline": _safe_response_evidence(privileged, privileged_time, "identity_a"),
            "lower_privilege": _safe_response_evidence(lower, lower_time, "identity_b"),
            "comparison": {
                "privileged_success": 200 <= privileged.status_code < 300,
                "lower_privilege_status": lower.status_code,
                "content_type_match": privileged.headers.get("content-type") == lower.headers.get("content-type"),
            },
        }
        if not 200 <= privileged.status_code < 300:
            return _result(endpoint.target, "INCONCLUSIVE", "The privileged identity could not establish a successful function baseline.", evidence)
        if lower.status_code in {401, 403}:
            return _result(endpoint.target, "AUTHORIZATION_ENFORCED", "The lower-privilege identity was denied access to the explicitly restricted function.", evidence)
        if lower.status_code == 404:
            return _result(endpoint.target, "INCONCLUSIVE", "The lower-privilege identity received a not-found response; function authorization cannot be confirmed.", evidence)
        if 200 <= lower.status_code < 300:
            return _result(endpoint.target, "POTENTIAL_BFLA", "The lower-privilege identity also accessed the explicitly restricted function.", evidence)
        return _result(endpoint.target, "INCONCLUSIVE", "The lower-privilege response was ambiguous.", evidence)


def _safe_response_evidence(response: Any, response_time: float, identity: str) -> dict[str, Any]:
    evidence = response_evidence(response, response_time)
    return {
        "identity": identity,
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type"),
        "response_time_ms": evidence["response_time_ms"],
        "body_preview": evidence["body_preview"],
    }


def _result(
    target: str,
    status: str,
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> AssessmentResult:
    return AssessmentResult(
        test_id=TEST_ID,
        test_name=TEST_NAME,
        target=sanitize_url(target),
        method="GET",
        status=status,
        observed_status_code=None,
        severity=None,
        reason=reason,
        evidence=evidence or {},
        recommendation="Review the explicitly configured function authorization boundary with authorized identities.",
    )
