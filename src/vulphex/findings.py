"""Normalized security findings derived from existing VULPHEX AssessmentResult objects."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any

from .models import AssessmentResult

FINDING_PRODUCING_STATUSES = {
    "POTENTIAL_MISSING_AUTHENTICATION",
    "POTENTIAL_BOLA",
    "POTENTIAL_BFLA",
    "POTENTIAL_INPUT_VALIDATION_WEAKNESS",
    "POTENTIAL_SQL_INJECTION",
    "POTENTIAL_NOSQL_INJECTION",
    "POTENTIAL_COMMAND_INJECTION",
    "POTENTIAL_SENSITIVE_DATA_EXPOSURE",
    "POTENTIAL_INFORMATION_DISCLOSURE",
    "RATE_LIMITING_OBSERVED",
    "POTENTIAL_CORS_MISCONFIGURATION",
    "POTENTIAL_API_MISCONFIGURATION",
    "SECURITY_CONFIGURATION_EXCEPTION",
    "INFORMATIONAL_CONFIGURATION_OBSERVED",
    "HTTP_ENDPOINT_OBSERVED",
    "AUTHENTICATION_CONFIGURATION_INCONSISTENT",
}

SEVERITY_BY_STATUS = {
    "POTENTIAL_SQL_INJECTION": "High",
    "POTENTIAL_COMMAND_INJECTION": "High",
    "POTENTIAL_BOLA": "High",
    "POTENTIAL_BFLA": "High",
    "POTENTIAL_MISSING_AUTHENTICATION": "High",
    "POTENTIAL_NOSQL_INJECTION": "Medium",
    "POTENTIAL_SENSITIVE_DATA_EXPOSURE": "Medium",
    "POTENTIAL_CORS_MISCONFIGURATION": "Medium",
    "POTENTIAL_INPUT_VALIDATION_WEAKNESS": "Medium",
    "POTENTIAL_INFORMATION_DISCLOSURE": "Medium",
    "SECURITY_CONFIGURATION_EXCEPTION": "Low",
    "POTENTIAL_API_MISCONFIGURATION": "Low",
    "HTTP_ENDPOINT_OBSERVED": "Low",
    "INFORMATIONAL_CONFIGURATION_OBSERVED": "Low",
    "RATE_LIMITING_OBSERVED": "Low",
    "AUTHENTICATION_CONFIGURATION_INCONSISTENT": "Medium",
}


@dataclass(frozen=True)
class Finding:
    """Immutable, JSON-serializable normalized security finding."""

    finding_id: str
    test_id: str
    test_name: str
    title: str
    target: str
    endpoint_path: str | None
    operation_id: str | None
    method: str
    status: str
    severity: str | None
    description: str
    evidence: dict[str, Any]
    recommendation: str
    authentication_mode: str | None = None
    risk_level: str | None = None
    references: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FindingAggregator:
    """Convert VULPHEX AssessmentResult objects into normalized security findings."""

    def __init__(self, results: list[AssessmentResult] | tuple[AssessmentResult, ...] | None = None) -> None:
        self.results = list(results or [])

    def aggregate(self) -> dict[str, Any]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str, str]] = set()
        for result in self.results:
            if not self._is_finding_result(result):
                continue
            finding = self._to_finding(result)
            dedupe_key = (
                finding.test_id,
                finding.endpoint_path or "",
                finding.method,
                finding.status,
            )
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(finding)
        findings.sort(key=lambda item: (item.endpoint_path or "", item.test_id, item.method, item.status))
        return {
            "findings": [finding.to_dict() for finding in findings],
            "summary": self._build_summary(findings),
        }

    @staticmethod
    def _is_finding_result(result: AssessmentResult) -> bool:
        if result.status in {"NO_", "NOT_APPLICABLE", "UNSUPPORTED_OPERATION", "AUTHENTICATION_REQUIRED", "INVALID_TEST_CONFIGURATION", "INCONCLUSIVE"}:
            return False
        if result.status.startswith("NO_"):
            return False
        return result.status in FINDING_PRODUCING_STATUSES or result.status.startswith("POTENTIAL_")

    @staticmethod
    def _to_finding(result: AssessmentResult) -> Finding:
        endpoint_path = result.endpoint_path or _path_from_target(result.target)
        finding_id = _build_finding_id(result.test_id, endpoint_path, result.method)
        title = _title_for(result)
        severity = _severity_for(result.status)
        evidence = _sanitized_evidence(result.evidence)
        return Finding(
            finding_id=finding_id,
            test_id=result.test_id,
            test_name=result.test_name,
            title=title,
            target=result.target,
            endpoint_path=endpoint_path,
            operation_id=result.operation_id,
            method=result.method,
            status=result.status,
            severity=severity,
            description=result.reason,
            evidence=evidence,
            recommendation=result.recommendation,
            authentication_mode=result.authentication_mode,
            risk_level=_risk_level(severity),
            references=[result.test_id],
        )

    def _build_summary(self, findings: list[Finding]) -> dict[str, Any]:
        total_results = len(self.results)
        by_severity = Counter(finding.severity or "Unknown" for finding in findings)
        by_test = Counter(finding.test_id for finding in findings)
        by_endpoint = Counter(finding.endpoint_path or finding.target for finding in findings)
        return {
            "total_results": total_results,
            "total_findings": len(findings),
            "findings_by_severity": dict(sorted(by_severity.items())),
            "findings_by_test": dict(sorted(by_test.items())),
            "findings_by_endpoint": dict(sorted(by_endpoint.items())),
        }


def aggregate_findings(results: list[AssessmentResult] | tuple[AssessmentResult, ...] | None = None) -> dict[str, Any]:
    """Lightweight programmatic entry point for Step 4B consumers."""
    return FindingAggregator(results).aggregate()


def _build_finding_id(test_id: str, endpoint_path: str | None, method: str) -> str:
    safe_path = (endpoint_path or "/").strip("/")
    safe_path = safe_path.replace("{", "").replace("}", "")
    safe_path = safe_path.replace("/", "-")
    safe_path = re.sub(r"[^A-Za-z0-9\-_]+", "-", safe_path)
    safe_path = safe_path.strip("-")
    sanitized = safe_path or "root"
    return f"VULPHEX-{test_id}-{method.upper()}-{sanitized}"


def _title_for(result: AssessmentResult) -> str:
    if result.status.startswith("POTENTIAL_SQL_INJECTION"):
        return "SQL injection risk"
    if result.status.startswith("POTENTIAL_COMMAND_INJECTION"):
        return "Command injection risk"
    if result.status.startswith("POTENTIAL_BOLA"):
        return "Broken object-level authorization risk"
    if result.status.startswith("POTENTIAL_BFLA"):
        return "Broken function-level authorization risk"
    if result.status.startswith("POTENTIAL_MISSING_AUTHENTICATION"):
        return "Missing authentication"
    if result.status.startswith("POTENTIAL_SENSITIVE_DATA_EXPOSURE"):
        return "Sensitive data exposure"
    if result.status.startswith("POTENTIAL_INFORMATION_DISCLOSURE"):
        return "Information disclosure"
    if result.status.startswith("POTENTIAL_CORS_MISCONFIGURATION"):
        return "CORS misconfiguration"
    if result.status.startswith("POTENTIAL_API_MISCONFIGURATION"):
        return "API misconfiguration"
    if result.status.startswith("SECURITY_CONFIGURATION_EXCEPTION"):
        return "Security configuration exception"
    if result.status.startswith("RATE_LIMITING_OBSERVED"):
        return "Rate limiting observation"
    if result.status.startswith("HTTP_ENDPOINT_OBSERVED"):
        return "HTTP endpoint configuration observed"
    if result.status.startswith("INFORMATIONAL_CONFIGURATION_OBSERVED"):
        return "Informational configuration observed"
    return result.test_name


def _severity_for(status: str) -> str | None:
    return SEVERITY_BY_STATUS.get(status)


def _risk_level(severity: str | None) -> str | None:
    if severity is None:
        return None
    if severity == "High":
        return "high"
    if severity == "Medium":
        return "medium"
    if severity == "Low":
        return "low"
    return None


def _path_from_target(target: str) -> str | None:
    if not target:
        return None
    match = re.search(r"https?://[^/]+(/.*)?$", target)
    if match:
        return match.group(1) or "/"
    return "/"


def _sanitized_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        return {}
    sanitized = {}
    for key, value in evidence.items():
        sanitized[key] = _sanitize_value(value)
    return sanitized


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _sanitize_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, str):
        lowered = value.lower()
        if "authorization" in lowered or "bearer " in lowered or "api_key" in lowered or "password" in lowered or "secret" in lowered or "cookie" in lowered:
            return "[REDACTED]"
        return value
    return value
