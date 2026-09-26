import json

from vulphex.Core.models import AssessmentResult
from vulphex.Reporting.output import render_json, render_text


def make_result(status: str, severity: str | None = None) -> AssessmentResult:
    return AssessmentResult(
        test_id="AUTH-001",
        test_name="Missing Authentication Test",
        target="http://127.0.0.1:8000/resource",
        method="GET",
        status=status,
        observed_status_code=200 if status == "POTENTIAL_MISSING_AUTHENTICATION" else 401,
        severity=severity,
        reason="The unauthenticated request received a controlled response.",
        evidence={
            "response_time_ms": 12.34,
            "headers": {"content-type": "application/json"},
            "body_preview": '{"access_token":"[REDACTED]"}',
        },
        recommendation="Verify the endpoint access requirements.",
    )


def test_potential_missing_authentication_renders_as_warning() -> None:
    rendered = render_text(make_result("POTENTIAL_MISSING_AUTHENTICATION"))

    assert "RESULT" in rendered
    assert "Potential missing authentication" in rendered
    assert "Severity: Not determined" in rendered


def test_authentication_enforced_renders_as_success() -> None:
    rendered = render_text(make_result("AUTHENTICATION_ENFORCED"))

    assert "Authentication enforced" in rendered
    assert "HTTP status: 401" in rendered


def test_inconclusive_renders_without_inventing_severity() -> None:
    rendered = render_text(make_result("INCONCLUSIVE"))

    assert "Inconclusive" in rendered
    assert "Severity: Not determined" in rendered


def test_json_renderer_remains_valid_and_keeps_redacted_evidence() -> None:
    rendered = render_json(make_result("POTENTIAL_MISSING_AUTHENTICATION"))
    parsed = json.loads(rendered)

    assert parsed["status"] == "POTENTIAL_MISSING_AUTHENTICATION"
    assert parsed["severity"] is None
    assert "[REDACTED]" in parsed["evidence"]["body_preview"]
    assert "secret" not in rendered