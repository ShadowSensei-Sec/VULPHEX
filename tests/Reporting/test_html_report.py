from vulphex.Reporting.html_report import render_html_report, write_html_report
from vulphex.Reporting.report import build_assessment_report
from vulphex.Core.models import AssessmentResult


def _result(status="POTENTIAL_BOLA"):
    return AssessmentResult(
        test_id="AUTHZ-001",
        test_name="BOLA Test",
        target="https://example.test/api/users/123",
        method="GET",
        status=status,
        observed_status_code=200,
        severity=None,
        reason="Controlled authorization test indicated cross-identity access.",
        evidence={
            "identity_a_status": 200,
            "identity_b_status": 200,
        },
        recommendation="Enforce object-level authorization.",
        endpoint_path="/api/users/{id}",
        operation_id="get_user",
    )


def test_html_contains_report_title():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    html = render_html_report(report)

    assert "<!DOCTYPE html>" in html
    assert "VULPHEX" in html
    assert "API Security Assessment Report" in html


def test_html_contains_target():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    html = render_html_report(report)

    assert "https://example.test" in html


def test_html_contains_finding():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    html = render_html_report(report)

    assert "AUTHZ-001" in html
    assert "BOLA Test" in html
    assert "Potential Finding" in html
    assert "Technical Evidence" in html
    assert "/api/users/{id}" in html
    assert "Enforce object-level authorization." in html


def test_html_contains_evidence():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    html = render_html_report(report)

    assert "identity_a_status" in html
    assert "identity_b_status" in html


def test_html_contains_summary():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    html = render_html_report(report)

    assert "Executive Summary" in html
    assert "Potential Findings" in html


def test_html_escapes_untrusted_finding_content():
    result = _result()
    result = AssessmentResult(
        **{
            **result.__dict__,
            "reason": "<script>alert('xss')</script>",
            "recommendation": "<img src=x onerror=alert(1)>",
        }
    )

    report = build_assessment_report(
        [result],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    html = render_html_report(report)

    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html


def test_empty_report_has_no_findings_message():
    report = build_assessment_report(
        [],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    html = render_html_report(report)

    assert "No issue-producing findings were identified." in html


def test_write_html_report(tmp_path):
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    output_path = write_html_report(
        report,
        tmp_path / "reports" / "assessment.html",
    )

    assert output_path.exists()
    assert output_path.name == "assessment.html"

    content = output_path.read_text(encoding="utf-8")

    assert "<!DOCTYPE html>" in content
    assert "VULPHEX" in content