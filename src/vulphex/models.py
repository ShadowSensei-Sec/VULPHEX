"""Shared result models for VULPHEX assessments."""

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class AssessmentResult:
    """Structured outcome of one security assessment test."""

    test_id: str
    test_name: str
    target: str
    method: str
    status: str
    observed_status_code: int | None
    severity: str | None
    reason: str
    evidence: dict[str, Any]
    recommendation: str
    endpoint_path: str | None = None
    operation_id: str | None = None
    security: list[dict[str, Any]] | None = None
    authentication_mode: str = "none"
    authentication_configured: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)