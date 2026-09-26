from vulphex.Core.models import AssessmentResult
from vulphex.Reporting.report import (
    AssessmentReport,
    build_assessment_report,
    render_assessment_report_json,
)


def _result(
    *,
    test_id: str = "AUTHZ-001",
    status: str = "POTENTIAL_BOLA",
    endpoint_path: str = "/api/users/{id}",
) -> AssessmentResult:
    return AssessmentResult(
        test_id=test_id,
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
        endpoint_path=endpoint_path,
        operation_id="get_user",
    )


def test_build_assessment_report_contains_metadata():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    assert isinstance(report, AssessmentReport)
    assert report.tool == "VULPHEX"
    assert report.tool_version == "0.1.0"
    assert report.target == "https://example.test"
    assert report.generated_at == "2026-09-26T00:00:00+00:00"
    assert report.result_count == 1


def test_report_contains_summary_and_findings():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    data = report.to_dict()

    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["total_results"] == 1
    assert data["summary"]["total_findings"] == 1
    assert len(data["findings"]) == 1


def test_report_has_canonical_top_level_sections():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    data = report.to_dict()

    assert list(data.keys()) == [
        "report",
        "summary",
        "results",
        "findings",
        "result_count",
    ]


def test_report_metadata_is_inside_report_section():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    metadata = report.to_dict()["report"]

    assert metadata["tool"] == "VULPHEX"
    assert metadata["tool_version"] == "0.1.0"
    assert metadata["target"] == "https://example.test"
    assert metadata["generated_at"] == "2026-09-26T00:00:00+00:00"


def test_report_json_is_valid():
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    rendered = report.to_json()

    import json

    parsed = json.loads(rendered)

    assert parsed["report"]["tool"] == "VULPHEX"
    assert parsed["summary"]["total_findings"] == 1


def test_report_json_is_deterministic_when_timestamp_is_fixed():
    results = [_result()]

    first = render_assessment_report_json(
        results,
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    second = render_assessment_report_json(
        results,
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    assert first == second


def test_non_finding_results_are_not_reported_as_findings():
    report = build_assessment_report(
        [
            _result(
                status="NO_SQL_INJECTION_INDICATED",
                test_id="INJ-001",
                endpoint_path="/api/search",
            )
        ],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    assert report.result_count == 1
    assert report.summary["total_results"] == 1
    assert report.summary["total_findings"] == 0
    assert report.findings == []


def test_empty_assessment_produces_valid_report():
    report = build_assessment_report(
        [],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    assert report.result_count == 0
    assert report.summary["total_results"] == 0
    assert report.summary["total_findings"] == 0
    assert report.findings == []


def test_write_json_creates_report_file(tmp_path):
    report = build_assessment_report(
        [_result()],
        target="https://example.test",
        generated_at="2026-09-26T00:00:00+00:00",
    )

    output_path = report.write_json(tmp_path / "reports" / "assessment.json")

    assert output_path.exists()
    assert output_path.name == "assessment.json"

    import json

    data = json.loads(output_path.read_text(encoding="utf-8"))

    assert data["report"]["tool"] == "VULPHEX"
    assert data["summary"]["total_findings"] == 1