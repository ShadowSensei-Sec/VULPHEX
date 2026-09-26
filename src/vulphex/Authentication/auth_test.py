"""AUTH-001: missing authentication assessment."""

import httpx

from ..Core.http_client import (
    get_without_authentication,
    response_evidence,
    sanitize_url,
)
from ..Core.models import AssessmentResult


TEST_ID = "AUTH-001"
TEST_NAME = "Missing Authentication Test"


class MissingAuthenticationTest:
    """Reusable AUTH-001 security test implementation."""

    test_id = TEST_ID
    test_name = TEST_NAME
    supported_methods = frozenset({"GET"})
    requires_authentication = False

    def execute(self, target: str) -> AssessmentResult:
        """Perform the existing unauthenticated GET assessment."""
        try:
            response, response_time_ms = get_without_authentication(target)
            return analyze_authentication_response(response, response_time_ms)
        except ValueError as exc:
            return error_result(target, f"Invalid URL: {exc}")
        except httpx.TimeoutException:
            return error_result(target, "The request timed out.")
        except httpx.ConnectError:
            return error_result(target, "The target could not be reached.")
        except httpx.TransportError:
            return error_result(target, "The HTTP/TLS connection failed.")
        except httpx.HTTPError:
            return error_result(target, "The HTTP request failed unexpectedly.")


def error_result(url: str, reason: str) -> AssessmentResult:
    """Build the existing safe inconclusive result for request failures."""
    return AssessmentResult(
        test_id=TEST_ID,
        test_name=TEST_NAME,
        target=sanitize_url(url),
        method="GET",
        status="INCONCLUSIVE",
        observed_status_code=None,
        severity=None,
        reason=reason,
        evidence={},
        recommendation="Confirm the authorized target and network configuration, then repeat the assessment.",
    )


def analyze_authentication_response(
    response: httpx.Response,
    response_time_ms: float,
) -> AssessmentResult:
    """Classify an actual unauthenticated response without assuming a finding."""
    status_code = response.status_code
    evidence = response_evidence(response, response_time_ms)
    common = {
        "test_id": TEST_ID,
        "test_name": TEST_NAME,
        "target": sanitize_url(str(response.request.url)),
        "method": response.request.method,
        "observed_status_code": status_code,
        "evidence": evidence,
    }

    if status_code in {401, 403}:
        return AssessmentResult(
            **common,
            status="AUTHENTICATION_ENFORCED",
            severity=None,
            reason=f"The unauthenticated request received HTTP {status_code}.",
            recommendation="Continue enforcing authentication and authorization on this endpoint.",
        )

    if 200 <= status_code < 300:
        return AssessmentResult(
            **common,
            status="POTENTIAL_MISSING_AUTHENTICATION",
            severity=None,
            reason=f"The unauthenticated request received successful HTTP {status_code}.",
            recommendation="Verify that this endpoint is intended to be public; otherwise require authentication and authorization.",
        )

    return AssessmentResult(
        **common,
        status="INCONCLUSIVE",
        severity=None,
        reason=f"HTTP {status_code} does not establish whether authentication is required.",
        recommendation="Review the endpoint behavior with an authorized tester and confirm its intended access requirements.",
    )