"""AUTH-002: OpenAPI authentication scheme analysis."""

from __future__ import annotations

from typing import Any

from .discovery import ResolvedEndpoint
from .http_client import sanitize_url
from .models import AssessmentResult


TEST_ID = "AUTH-002"
TEST_NAME = "Authentication Scheme Analysis"


class AuthenticationSchemeAnalysisTest:
    """Analyze declared OpenAPI authentication metadata without making requests."""

    test_id = TEST_ID
    test_name = TEST_NAME
    requires_authentication = False

    def execute(self, target: str) -> AssessmentResult:
        return _inconclusive_without_endpoint(target)

    def execute_endpoint(self, endpoint: ResolvedEndpoint) -> AssessmentResult:
        requirements = endpoint.security or []
        schemes = _describe_schemes(requirements, endpoint.security_schemes or {})
        missing = _missing_scheme_names(requirements, endpoint.security_schemes or {})
        evidence = {
            "authentication_declared": bool(requirements),
            "security_requirement_source": endpoint.security_requirement_source,
            "security_requirements": [list(requirement.keys()) for requirement in requirements],
            "security_schemes": schemes,
        }
        if missing:
            status = "AUTHENTICATION_CONFIGURATION_INCONSISTENT"
            reason = f"The OpenAPI security requirement references undefined scheme(s): {', '.join(missing)}."
        elif requirements:
            status = "AUTHENTICATION_DECLARED"
            reason = "The OpenAPI document declares authentication requirements for this operation; enforcement was not verified."
        else:
            status = "NO_AUTHENTICATION_DECLARED"
            reason = "The OpenAPI document does not declare an authentication requirement for this operation."
        return AssessmentResult(
            test_id=TEST_ID,
            test_name=TEST_NAME,
            target=sanitize_url(endpoint.target),
            method=endpoint.method,
            status=status,
            observed_status_code=None,
            severity=None,
            reason=reason,
            evidence=evidence,
            recommendation="Compare the declared configuration with observed endpoint behavior; this analysis does not verify enforcement.",
            endpoint_path=endpoint.path,
            operation_id=endpoint.operation_id,
            security=endpoint.security,
        )


def _missing_scheme_names(
    requirements: list[dict[str, Any]],
    schemes: dict[str, dict[str, Any]],
) -> list[str]:
    return [name for requirement in requirements for name in requirement if name not in schemes]


def _describe_schemes(
    requirements: list[dict[str, Any]],
    schemes: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    names = [name for requirement in requirements for name in requirement]
    descriptions: dict[str, dict[str, Any]] = {}
    for name in names:
        scheme = schemes.get(name)
        if not isinstance(scheme, dict):
            continue
        description: dict[str, Any] = {"type": scheme.get("type")}
        for field in ("scheme", "in", "name"):
            if isinstance(scheme.get(field), str):
                description[field] = scheme[field]
        if scheme.get("type") == "oauth2" and isinstance(scheme.get("flows"), dict):
            description["flows"] = sorted(
                flow_name for flow_name in scheme["flows"] if isinstance(flow_name, str)
            )
        if scheme.get("type") == "openIdConnect" and isinstance(scheme.get("openIdConnectUrl"), str):
            description["openIdConnectUrl"] = sanitize_url(scheme["openIdConnectUrl"])
        descriptions[name] = description
    return descriptions


def _inconclusive_without_endpoint(target: str) -> AssessmentResult:
    return AssessmentResult(
        test_id=TEST_ID,
        test_name=TEST_NAME,
        target=sanitize_url(target),
        method="GET",
        status="INCONCLUSIVE",
        observed_status_code=None,
        severity=None,
        reason="Authentication scheme analysis requires discovered OpenAPI endpoint metadata.",
        evidence={},
        recommendation="Run this test through the discovery workflow.",
    )