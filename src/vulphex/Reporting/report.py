"""Assessment report model and JSON serialization for VULPHEX."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .findings import aggregate_findings
from ..Core.models import AssessmentResult


@dataclass(frozen=True)
class AssessmentReport:
    """Canonical machine-readable VULPHEX assessment report."""

    tool: str
    tool_version: str
    target: str
    generated_at: str
    summary: dict[str, Any]
    findings: list[dict[str, Any]]
    results: list[dict[str, Any]]
    result_count: int

    def to_dict(self) -> dict[str, Any]:
        """Return the complete report as a JSON-serializable dictionary."""
        return {
            "report": {
                "tool": self.tool,
                "tool_version": self.tool_version,
                "target": self.target,
                "generated_at": self.generated_at,
            },
            "summary": self.summary,
            "results": self.results,
            "findings": self.findings,
            "result_count": self.result_count,
        }

    def to_json(self) -> str:
        """Serialize the report to formatted JSON."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=False)

    def write_json(self, path: str | Path) -> Path:
        """Write the report to a JSON file."""
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            self.to_json() + "\n",
            encoding="utf-8",
        )
        return output_path


def build_assessment_report(
    results: list[AssessmentResult] | tuple[AssessmentResult, ...],
    *,
    target: str,
    tool_version: str = "0.1.0",
    generated_at: str | None = None,
) -> AssessmentReport:
    """Build the canonical VULPHEX assessment report from assessment results."""

    aggregation = aggregate_findings(results)

    timestamp = generated_at or datetime.now(timezone.utc).isoformat()

    return AssessmentReport(
        tool="VULPHEX",
        tool_version=tool_version,
        target=target,
        generated_at=timestamp,
        summary=aggregation["summary"],
        findings=aggregation["findings"],
        results=[asdict(result) for result in results],
        result_count=len(results),
    )


def render_assessment_report_json(
    results: list[AssessmentResult] | tuple[AssessmentResult, ...],
    *,
    target: str,
    tool_version: str = "0.1.0",
    generated_at: str | None = None,
) -> str:
    """Build and serialize a VULPHEX assessment report as JSON."""

    report = build_assessment_report(
        results,
        target=target,
        tool_version=tool_version,
        generated_at=generated_at,
    )
    return report.to_json()