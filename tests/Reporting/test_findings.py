import json

from vulphex.Reporting.findings import FindingAggregator
from vulphex.Core.models import AssessmentResult


def make_result(
    *,
    test_id: str,
    test_name: str,
    target: str,
    method: str,
    status: str,
    reason: str = "synthetic finding",
    endpoint_path: str | None = None,
    operation_id: str | None = None,
    evidence: dict[str, object] | None = None,
) -> AssessmentResult:
    return AssessmentResult(
        test_id=test_id,
        test_name=test_name,
        target=target,
        method=method,
        status=status,
        observed_status_code=200,
        severity=None,
        reason=reason,
        evidence=evidence or {"request_count": 1},
        recommendation="Review and remediate.",
        endpoint_path=endpoint_path,
        operation_id=operation_id,
    )


def test_potential_vulnerability_becomes_finding() -> None:
    result = make_result(
        test_id="AUTHZ-001",
        test_name="Broken Object Level Authorization",
        target="https://api.example.test/users/42",
        method="GET",
        status="POTENTIAL_BOLA",
        endpoint_path="/users/42",
        operation_id="get_user",
    )

    payload = FindingAggregator([result]).aggregate()

    assert payload["summary"]["total_findings"] == 1
    assert payload["findings"][0]["status"] == "POTENTIAL_BOLA"
    assert payload["findings"][0]["severity"] == "High"


def test_non_finding_result_is_ignored() -> None:
    result = make_result(
        test_id="AUTH-001",
        test_name="Missing Authentication",
        target="https://api.example.test/public",
        method="GET",
        status="NO_MISSING_AUTHENTICATION_INDICATED",
        endpoint_path="/public",
    )

    payload = FindingAggregator([result]).aggregate()

    assert payload["findings"] == []
    assert payload["summary"]["total_findings"] == 0


def test_deterministic_finding_id() -> None:
    result = make_result(
        test_id="AUTHZ-001",
        test_name="Broken Object Level Authorization",
        target="https://api.example.test/users/{id}",
        method="GET",
        status="POTENTIAL_BOLA",
        endpoint_path="/users/{id}",
        operation_id="get_user",
    )

    finding = FindingAggregator([result]).aggregate()["findings"][0]

    assert finding["finding_id"] == "VULPHEX-AUTHZ-001-GET-users-id"


def test_duplicate_results_are_deduplicated() -> None:
    results = [
        make_result(
            test_id="AUTHZ-001",
            test_name="Broken Object Level Authorization",
            target="https://api.example.test/users/42",
            method="GET",
            status="POTENTIAL_BOLA",
            endpoint_path="/users/42",
            operation_id="get_user",
        ),
        make_result(
            test_id="AUTHZ-001",
            test_name="Broken Object Level Authorization",
            target="https://api.example.test/users/42",
            method="GET",
            status="POTENTIAL_BOLA",
            endpoint_path="/users/42",
            operation_id="get_user",
        ),
    ]

    payload = FindingAggregator(results).aggregate()

    assert len(payload["findings"]) == 1


def test_bola_and_bfla_remain_separate() -> None:
    results = [
        make_result(test_id="AUTHZ-001", test_name="BOLA", target="https://api.example.test/users/42", method="GET", status="POTENTIAL_BOLA", endpoint_path="/users/42"),
        make_result(test_id="AUTHZ-002", test_name="BFLA", target="https://api.example.test/users/42", method="GET", status="POTENTIAL_BFLA", endpoint_path="/users/42"),
    ]

    payload = FindingAggregator(results).aggregate()

    assert len(payload["findings"]) == 2
    assert {item["test_id"] for item in payload["findings"]} == {"AUTHZ-001", "AUTHZ-002"}


def test_different_vulnerabilities_on_same_endpoint_remain_separate() -> None:
    results = [
        make_result(test_id="INJ-001", test_name="SQLi", target="https://api.example.test/search", method="GET", status="POTENTIAL_SQL_INJECTION", endpoint_path="/search"),
        make_result(test_id="INPUT-001", test_name="Input Validation", target="https://api.example.test/search", method="GET", status="POTENTIAL_INPUT_VALIDATION_WEAKNESS", endpoint_path="/search"),
    ]

    payload = FindingAggregator(results).aggregate()

    assert len(payload["findings"]) == 2
    assert {item["test_id"] for item in payload["findings"]} == {"INJ-001", "INPUT-001"}


def test_severity_mapping() -> None:
    payload = FindingAggregator([
        make_result(test_id="INJ-001", test_name="SQLi", target="https://api.example.test/search", method="GET", status="POTENTIAL_SQL_INJECTION", endpoint_path="/search"),
        make_result(test_id="CONFIG-003", test_name="API Misconfiguration", target="https://api.example.test/debug", method="GET", status="POTENTIAL_API_MISCONFIGURATION", endpoint_path="/debug"),
    ]).aggregate()

    severities = {item["test_id"]: item["severity"] for item in payload["findings"]}
    assert severities["INJ-001"] == "High"
    assert severities["CONFIG-003"] == "Low"


def test_sanitized_evidence_is_preserved() -> None:
    result = make_result(
        test_id="DATA-001",
        test_name="Sensitive Data Exposure",
        target="https://api.example.test/profile",
        method="GET",
        status="POTENTIAL_SENSITIVE_DATA_EXPOSURE",
        endpoint_path="/profile",
        evidence={
            "headers": {"Authorization": "Bearer secret-token", "Content-Type": "application/json"},
            "body_preview": "password=secret",
        },
    )

    finding = FindingAggregator([result]).aggregate()["findings"][0]
    serialized = json.dumps(finding)

    assert "secret-token" not in serialized
    assert "Authorization" not in serialized or "[REDACTED]" in serialized


def test_summary_counts() -> None:
    payload = FindingAggregator([
        make_result(test_id="INJ-001", test_name="SQLi", target="https://api.example.test/search", method="GET", status="POTENTIAL_SQL_INJECTION", endpoint_path="/search"),
        make_result(test_id="CONFIG-003", test_name="API Misconfiguration", target="https://api.example.test/debug", method="GET", status="POTENTIAL_API_MISCONFIGURATION", endpoint_path="/debug"),
        make_result(test_id="AUTH-001", test_name="Missing Authentication", target="https://api.example.test/public", method="GET", status="NO_MISSING_AUTHENTICATION_INDICATED", endpoint_path="/public"),
    ]).aggregate()

    assert payload["summary"]["total_results"] == 3
    assert payload["summary"]["total_findings"] == 2
    assert payload["summary"]["findings_by_severity"]["High"] == 1
    assert payload["summary"]["findings_by_test"]["INJ-001"] == 1
    assert payload["summary"]["findings_by_endpoint"]["/search"] == 1


def test_empty_result_collection() -> None:
    payload = FindingAggregator([]).aggregate()

    assert payload["findings"] == []
    assert payload["summary"]["total_results"] == 0
    assert payload["summary"]["total_findings"] == 0


def test_deterministic_ordering() -> None:
    results = [
        make_result(test_id="CONFIG-003", test_name="API Misconfiguration", target="https://api.example.test/debug", method="GET", status="POTENTIAL_API_MISCONFIGURATION", endpoint_path="/debug"),
        make_result(test_id="INJ-001", test_name="SQLi", target="https://api.example.test/search", method="GET", status="POTENTIAL_SQL_INJECTION", endpoint_path="/search"),
    ]

    payload = FindingAggregator(results).aggregate()

    assert [item["test_id"] for item in payload["findings"]] == ["CONFIG-003", "INJ-001"]


def test_assessment_results_remain_unchanged() -> None:
    result = make_result(
        test_id="AUTHZ-001",
        test_name="Broken Object Level Authorization",
        target="https://api.example.test/users/42",
        method="GET",
        status="POTENTIAL_BOLA",
        endpoint_path="/users/42",
        evidence={"headers": {"Authorization": "Bearer secret-token"}},
    )

    before = json.dumps(result.to_dict())
    FindingAggregator([result]).aggregate()
    after = json.dumps(result.to_dict())

    assert before == after
