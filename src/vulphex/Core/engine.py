"""Reusable orchestration for sequential VULPHEX security tests."""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from ..Authentication.authentication import (
    AuthenticationConfig,
    BFLAContext,
    BOLAContext,
)
from .http_client import sanitize_url
from .models import AssessmentResult
from ..Discovery.discovery import ResolvedEndpoint


class SecurityTest(Protocol):
    """Minimal interface implemented by a VULPHEX security test."""

    test_id: str
    test_name: str
    supported_methods: frozenset[str]

    def execute(self, target: str) -> AssessmentResult:
        """Execute the test against one target URL."""


@dataclass(frozen=True)
class AssessmentContext:
    """Immutable per-endpoint context passed to explicitly authenticated tests."""

    endpoint: ResolvedEndpoint
    authentication: AuthenticationConfig = AuthenticationConfig()
    bola: BOLAContext | None = None
    bfla: BFLAContext | None = None

    @property
    def authentication_mode(self) -> str:
        if self.bola is not None:
            return self.bola.identity_a.safe_mode
        if self.bfla is not None:
            return self.bfla.privileged_identity.safe_mode
        return self.authentication.safe_mode

    @property
    def authentication_configured(self) -> bool:
        if self.bola is not None:
            return self.bola.identity_a.mode != "none" and self.bola.identity_b.mode != "none"
        if self.bfla is not None:
            return (
                self.bfla.privileged_identity.mode != "none"
                and self.bfla.lower_privilege_identity.mode != "none"
            )
        return self.authentication.mode != "none"

    def __repr__(self) -> str:
        return (
            "AssessmentContext("
            f"target={self.endpoint.target!r}, method={self.endpoint.method!r}, "
            f"path={self.endpoint.path!r}, authentication_mode={self.authentication_mode!r}, "
            f"authentication_configured={self.authentication_configured!r})"
        )


class AssessmentEngine:
    """Execute supplied security tests in their declared order."""

    def __init__(self, tests: Iterable[SecurityTest]) -> None:
        self.tests = tuple(tests)

    def assess(self, target: str) -> list[AssessmentResult]:
        """Run every test and preserve a safe result if one test fails."""
        results = []
        for test in self.tests:
            try:
                results.append(test.execute(target))
            except Exception:
                results.append(self._execution_error(target, test))
        return results

    def assess_endpoints(
        self,
        endpoints: Iterable[ResolvedEndpoint],
        authentication: AuthenticationConfig | None = None,
        bola_context: BOLAContext | None = None,
        bfla_context: BFLAContext | None = None,
    ) -> list[AssessmentResult]:
        """Assess resolved endpoints while preserving endpoint and test order."""
        results: list[AssessmentResult] = []
        configured_authentication = authentication or AuthenticationConfig()
        for endpoint in endpoints:
            context = AssessmentContext(endpoint, configured_authentication, bola_context, bfla_context)
            for test in self.tests:
                supported_methods = getattr(test, "supported_methods", None)
                if supported_methods is not None and endpoint.method not in supported_methods:
                    results.append(self._not_applicable(endpoint, test))
                    continue
                requires_authentication = getattr(test, "requires_authentication", False)
                uses_authentication_context = getattr(test, "uses_authentication_context", False)
                requires_bola_context = getattr(test, "requires_bola_context", False)
                requires_bfla_context = getattr(test, "requires_bfla_context", False)
                if (
                    requires_authentication
                    and (
                        not context.authentication_configured
                        or (requires_bola_context and context.bola is None)
                        or (requires_bfla_context and context.bfla is None)
                    )
                ):
                    results.append(self._authentication_required(endpoint, test))
                    continue
                try:
                    if requires_authentication or uses_authentication_context:
                        context_executor = getattr(test, "execute_context", None)
                        if context_executor is None:
                            results.append(self._authentication_required(endpoint, test))
                            continue
                        result = context_executor(context)
                    else:
                        endpoint_executor = getattr(test, "execute_endpoint", None)
                        result = (
                            endpoint_executor(endpoint)
                            if endpoint_executor is not None
                            else test.execute(endpoint.target)
                        )
                    results.append(
                        self._with_endpoint_context(
                            result,
                            endpoint,
                            context.authentication_mode if requires_authentication or uses_authentication_context else "none",
                            context.authentication_configured if requires_authentication or uses_authentication_context else False,
                        )
                    )
                except Exception:
                    results.append(self._execution_error_for_endpoint(endpoint, test))
        return results

    @staticmethod
    def _execution_error(target: str, test: SecurityTest) -> AssessmentResult:
        return AssessmentResult(
            test_id=test.test_id,
            test_name=test.test_name,
            target=sanitize_url(target),
            method="GET",
            status="TEST_EXECUTION_ERROR",
            observed_status_code=None,
            severity=None,
            reason="The security test could not complete because of an unexpected execution error.",
            evidence={"error": "unexpected_test_execution_error"},
            recommendation="Review the test configuration and execution logs, then repeat the assessment.",
        )

    @staticmethod
    def _with_endpoint_context(
        result: AssessmentResult,
        endpoint: ResolvedEndpoint,
        authentication_mode: str = "none",
        authentication_configured: bool = False,
    ) -> AssessmentResult:
        return AssessmentResult(
            **{
                **result.to_dict(),
                "target": sanitize_url(endpoint.target),
                "method": endpoint.method,
                "endpoint_path": endpoint.path,
                "operation_id": endpoint.operation_id,
                "security": endpoint.security,
                "authentication_mode": authentication_mode,
                "authentication_configured": authentication_configured,
            }
        )

    @staticmethod
    def _not_applicable(endpoint: ResolvedEndpoint, test: SecurityTest) -> AssessmentResult:
        return AssessmentResult(
            test_id=test.test_id,
            test_name=test.test_name,
            target=sanitize_url(endpoint.target),
            method=endpoint.method,
            status="NOT_APPLICABLE",
            observed_status_code=None,
            severity=None,
            reason=f"{test.test_id} currently supports {', '.join(sorted(getattr(test, 'supported_methods', ())))} only.",
            evidence={"reason": "unsupported_http_method"},
            recommendation="Use a security test that supports this HTTP method.",
            endpoint_path=endpoint.path,
            operation_id=endpoint.operation_id,
            security=endpoint.security,
        )

    @staticmethod
    def _authentication_required(endpoint: ResolvedEndpoint, test: SecurityTest) -> AssessmentResult:
        return AssessmentResult(
            test_id=test.test_id,
            test_name=test.test_name,
            target=sanitize_url(endpoint.target),
            method=endpoint.method,
            status="AUTHENTICATION_REQUIRED",
            observed_status_code=None,
            severity=None,
            reason="This security test requires an explicitly supplied authenticated assessment context.",
            evidence={"reason": "authentication_context_required"},
            recommendation="Provide an authorized authentication context before running this test.",
            endpoint_path=endpoint.path,
            operation_id=endpoint.operation_id,
            security=endpoint.security,
            authentication_mode="none",
            authentication_configured=False,
        )

    @staticmethod
    def _execution_error_for_endpoint(endpoint: ResolvedEndpoint, test: SecurityTest) -> AssessmentResult:
        result = AssessmentEngine._execution_error(endpoint.target, test)
        return AssessmentEngine._with_endpoint_context(result, endpoint)