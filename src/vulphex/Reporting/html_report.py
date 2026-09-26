"""Professional HTML report rendering for VULPHEX assessment reports."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from html import escape
from pathlib import Path
from typing import Any

from .report import AssessmentReport


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------

_CSS = """
:root {
    --border: #d9dee7;
    --muted: #667085;
    --background: #f4f6f9;
    --surface: #ffffff;
    --text: #172033;
    --high: #b42318;
    --medium: #b54708;
    --low: #175cd3;
    --info: #475467;
    --success: #027a48;
    --warning: #b54708;
}

* {
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {
    margin: 0;
    background: var(--background);
    color: var(--text);
    font-family: Arial, Helvetica, sans-serif;
    line-height: 1.55;
}

.container {
    max-width: 1220px;
    margin: 0 auto;
    padding: 32px 24px 70px;
}

.cover {
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 52px;
    margin-bottom: 24px;
}

.cover h1 {
    margin: 0;
    font-size: 42px;
    letter-spacing: .04em;
}

.cover .subtitle {
    margin-top: 8px;
    color: var(--muted);
    font-size: 20px;
}

.cover .report-type {
    margin-top: 26px;
    font-size: 14px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .08em;
}

.metadata {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px;
    margin-top: 32px;
}

.metadata-item {
    border: 1px solid var(--border);
    padding: 15px;
    background: #fafbfc;
}

.metadata-label,
.overview-label,
.field-label {
    display: block;
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .06em;
    font-weight: 700;
}

.metadata-label {
    margin-bottom: 5px;
}

.metadata-value {
    word-break: break-word;
    font-weight: 600;
}

section {
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 30px;
    margin-bottom: 24px;
}

h2 {
    margin-top: 0;
    margin-bottom: 18px;
    font-size: 25px;
}

h3 {
    margin-top: 0;
    margin-bottom: 8px;
}

h4 {
    margin-top: 0;
}

p {
    margin-top: 0;
}

.muted {
    color: var(--muted);
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
    gap: 12px;
    margin-top: 22px;
}

.summary-card {
    border: 1px solid var(--border);
    padding: 18px;
    background: #fff;
}

.summary-number {
    display: block;
    font-size: 28px;
    font-weight: 700;
}

.summary-label {
    color: var(--muted);
    font-size: 13px;
}

.cover-note {
    margin-top: 20px;
    padding: 14px 16px;
    border-left: 4px solid #98a2b3;
    background: #f8fafc;
}

table {
    width: 100%;
    border-collapse: collapse;
}

th,
td {
    text-align: left;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
    overflow-wrap: anywhere;
}

th {
    background: #fafbfc;
    font-size: 13px;
}

.compact-table th,
.compact-table td {
    padding: 8px 10px;
}

.coverage-table td:first-child,
.coverage-table th:first-child {
    white-space: nowrap;
}

.status-text {
    font-weight: 600;
}

.status-potential {
    color: var(--high);
}

.status-good {
    color: var(--success);
}

.status-neutral {
    color: var(--muted);
}

.finding {
    border: 1px solid var(--border);
    margin-top: 24px;
    overflow: hidden;
    background: #fff;
    break-inside: avoid;
}

.finding-header {
    padding: 20px;
    border-bottom: 1px solid var(--border);
    background: #fafbfc;
}

.finding-title-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 20px;
}

.finding-header h3 {
    margin: 0 0 7px;
    font-size: 20px;
}

.finding-meta {
    color: var(--muted);
    font-size: 13px;
}

.finding-badges {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    justify-content: flex-end;
}

.severity,
.status-badge {
    display: inline-block;
    padding: 4px 9px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}

.severity-high {
    color: var(--high);
    background: #fef3f2;
}

.severity-medium {
    color: var(--medium);
    background: #fffaeb;
}

.severity-low {
    color: var(--low);
    background: #eff8ff;
}

.severity-info,
.severity-not-determined {
    color: var(--info);
    background: #f2f4f7;
}

.status-badge {
    color: #344054;
    background: #eef2f6;
}

.finding-body {
    padding: 22px;
}

.finding-overview {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 26px;
}

.overview-card {
    border: 1px solid var(--border);
    background: #fafbfc;
    padding: 14px;
}

.overview-label {
    margin-bottom: 5px;
}

.overview-card strong {
    display: block;
    overflow-wrap: anywhere;
}

.field {
    margin-bottom: 24px;
}

.field-label {
    margin-bottom: 8px;
}

.section-box {
    border: 1px solid var(--border);
    padding: 16px;
    background: #fff;
}

.assessment-box {
    border-left: 4px solid #98a2b3;
    background: #f8fafc;
    padding: 16px;
}

.recommendation-box {
    border-left: 4px solid var(--low);
    background: #f8fbff;
    padding: 16px;
}

.request-table,
.response-table,
.analysis-table {
    margin-top: 8px;
    border: 1px solid var(--border);
}

.request-table th,
.response-table th,
.analysis-table th {
    width: 190px;
}

.observation-block {
    border: 1px solid var(--border);
    margin-top: 10px;
}

.observation-title {
    padding: 10px 12px;
    background: #fafbfc;
    font-weight: 700;
    font-size: 13px;
}

.observation-body {
    padding: 12px;
}

.procedure-list {
    margin: 8px 0 0;
    padding-left: 22px;
}

.technical-details {
    margin-top: 24px;
    border: 1px solid var(--border);
    overflow: hidden;
}

.technical-details summary {
    cursor: pointer;
    padding: 14px 16px;
    background: #fafbfc;
    font-weight: 700;
}

.technical-content {
    padding: 16px;
    border-top: 1px solid var(--border);
}

pre {
    margin: 0;
    padding: 14px;
    background: #101828;
    color: #f8fafc;
    overflow-x: auto;
    border-radius: 4px;
    font-family: Consolas, Monaco, monospace;
    font-size: 12px;
    line-height: 1.5;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}

code {
    font-family: Consolas, Monaco, monospace;
}

.footer {
    text-align: center;
    color: var(--muted);
    font-size: 12px;
    padding-top: 20px;
}

.page-break {
    break-before: page;
}

@media (max-width: 760px) {
    .container {
        padding: 18px 12px 40px;
    }

    .cover,
    section {
        padding: 20px;
    }

    .finding-title-row {
        flex-direction: column;
    }

    .finding-badges {
        justify-content: flex-start;
    }

    .request-table th,
    .response-table th,
    .analysis-table th {
        width: auto;
    }
}

@media print {
    @page {
        size: A4;
        margin: 14mm;
    }

    body {
        background: white;
        font-size: 10.5pt;
    }

    .container {
        max-width: none;
        padding: 0;
    }

    section,
    .cover {
        border-color: #bbb;
    }

    .cover {
        min-height: 245mm;
        display: flex;
        flex-direction: column;
        justify-content: center;
    }

    .finding {
        break-inside: avoid;
    }

    .finding-header,
    .finding-overview,
    .field,
    .section-box,
    .technical-details {
        break-inside: avoid;
    }

    .technical-details[open] {
        break-inside: auto;
    }

    a {
        color: inherit;
        text-decoration: none;
    }
}
"""


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

_TEST_NAMES = {
    "AUTH-001": "Missing Authentication",
    "AUTH-002": "Authentication Scheme Analysis",
    "AUTHZ-001": "Broken Object Level Authorization",
    "AUTHZ-002": "Broken Function Level Authorization",
    "INPUT-001": "Input Validation",
    "INJ-001": "SQL Injection",
    "INJ-002": "NoSQL Injection",
    "INJ-003": "Command Injection",
    "DATA-001": "Sensitive Data Exposure",
    "INFO-001": "Information Disclosure",
    "CONFIG-001": "Rate Limiting",
    "CONFIG-002": "Security Configuration / CORS",
    "CONFIG-003": "API Misconfiguration",
}


def _severity_class(severity: Any) -> str:
    normalized = str(severity or "not-determined").lower().replace(" ", "-")
    if normalized in {"high", "medium", "low", "info"}:
        return f"severity-{normalized}"
    return "severity-not-determined"


def _safe_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {"details": value}


def _json(value: Any) -> str:
    return json.dumps(
        value,
        indent=2,
        ensure_ascii=False,
        default=str,
    )


def _display(value: Any, default: str = "Not observed") -> str:
    if value is None or value == "":
        return default

    if isinstance(value, (dict, list)):
        return _json(value)

    return str(value)


def _html(value: Any, default: str = "Not observed") -> str:
    return escape(_display(value, default))


def _status_label(status: str) -> str:
    return status.replace("_", " ").title()


def _business_status(status: str) -> str:
    normalized = status.upper()

    if normalized.startswith("POTENTIAL_"):
        return "Potential Finding"

    if normalized in {
        "AUTHENTICATION_ENFORCED",
        "AUTHORIZATION_ENFORCED",
        "NO_SQL_INJECTION_INDICATED",
        "NO_SENSITIVE_DATA_EXPOSURE_INDICATED",
        "NO_INFORMATION_DISCLOSURE_INDICATED",
        "NO_API_MISCONFIGURATION_INDICATED",
    }:
        return "Control Observed / No Issue Indicated"

    if normalized == "NO_RATE_LIMITING_OBSERVED":
        return "Rate Limit Not Observed in Bounded Test"

    if normalized.startswith("NO_"):
        return "No Issue Indicated"

    if normalized in {
        "INCONCLUSIVE",
        "INVALID_TEST_CONFIGURATION",
        "UNSUPPORTED_OPERATION",
        "AUTHENTICATION_REQUIRED",
        "NOT_APPLICABLE",
    }:
        return "Assessment Requires Review"

    if normalized == "INFORMATIONAL_CONFIGURATION_OBSERVED":
        return "Informational Configuration Observation"

    if normalized == "SECURITY_CONFIGURATION_EXCEPTION":
        return "Security Configuration Exception"

    return _status_label(status)


def _extract_status_codes(evidence: dict[str, Any]) -> list[Any]:
    values: list[Any] = []

    for key in (
        "observed_status_code",
        "status_code",
        "response_status",
        "http_status",
    ):
        value = evidence.get(key)
        if value is not None:
            values.append(value)

    observations = evidence.get("observations")
    if isinstance(observations, list):
        for item in observations:
            if isinstance(item, dict) and item.get("status_code") is not None:
                values.append(item["status_code"])

    for key in ("baseline", "secondary", "lower_privilege", "privileged"):
        item = evidence.get(key)
        if isinstance(item, dict):
            for status_key in (
                "status_code",
                "observed_status_code",
                "response_status",
            ):
                if item.get(status_key) is not None:
                    values.append(item[status_key])

    probes = evidence.get("probes")
    if isinstance(probes, list):
        for probe in probes:
            if isinstance(probe, dict):
                for status_key in (
                    "status_code",
                    "observed_status_code",
                    "response_status",
                ):
                    if probe.get(status_key) is not None:
                        values.append(probe[status_key])

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(values))


def _first_status(evidence: dict[str, Any]) -> Any:
    values = _extract_status_codes(evidence)
    return values[0] if values else None


def _extract_authentication(evidence: dict[str, Any]) -> Any:
    for key in (
        "authentication",
        "authentication_mode",
        "auth_mode",
        "authentication_method",
        "auth_type",
        "auth_scheme",
    ):
        if evidence.get(key) is not None:
            return evidence[key]

    return None


def _extract_url(evidence: dict[str, Any], endpoint: str) -> str:
    for key in ("url", "request_url", "target"):
        if evidence.get(key):
            return str(evidence[key])

    observations = evidence.get("observations")
    if isinstance(observations, list):
        for item in observations:
            if isinstance(item, dict) and item.get("url"):
                return str(item["url"])

    return endpoint


def _extract_method(
    evidence: dict[str, Any],
    finding_method: str,
) -> str:
    for key in ("method", "request_method"):
        if evidence.get(key):
            return str(evidence[key])

    return finding_method


def _finding_status_description(
    status: str,
    severity: Any,
) -> tuple[str, str]:
    normalized = status.upper()

    if normalized.startswith("POTENTIAL_"):
        meaning = (
            "VULPHEX observed behavior that may indicate a security weakness. "
            "The result should be manually validated before being treated as "
            "a confirmed vulnerability."
        )
    elif normalized in {
        "AUTHENTICATION_ENFORCED",
        "AUTHORIZATION_ENFORCED",
    }:
        meaning = (
            "VULPHEX observed the expected security control during the "
            "automated assessment."
        )
    elif normalized == "NO_RATE_LIMITING_OBSERVED":
        meaning = (
            "Rate limiting was not observed during the bounded request "
            "sequence. This does not establish that rate limiting is absent "
            "under all traffic conditions."
        )
    elif normalized.startswith("NO_"):
        meaning = (
            "VULPHEX did not observe the tested weakness within the bounded "
            "assessment performed."
        )
    elif normalized == "NOT_APPLICABLE":
        meaning = (
            "The selected security test could not be meaningfully applied "
            "to this endpoint using the available information."
        )
    elif normalized == "AUTHENTICATION_REQUIRED":
        meaning = (
            "The test requires an explicitly supplied authentication context "
            "before VULPHEX can safely perform the assessment."
        )
    elif normalized in {
        "INVALID_TEST_CONFIGURATION",
        "INCONCLUSIVE",
        "UNSUPPORTED_OPERATION",
    }:
        meaning = (
            "The automated assessment could not establish a definitive "
            "security result from the available test conditions."
        )
    else:
        meaning = (
            "The assessment produced an observation that should be reviewed "
            "using the technical evidence."
        )

    severity_text = str(severity or "").lower()

    if severity_text == "high":
        risk = (
            "If validated, this type of issue may enable significant "
            "unauthorized access, sensitive data exposure, or application "
            "impact depending on the affected functionality."
        )
    elif severity_text == "medium":
        risk = (
            "If validated, this type of issue may expose sensitive "
            "functionality or data or weaken an important security control."
        )
    elif severity_text == "low":
        risk = (
            "This may represent a lower-impact security weakness or "
            "configuration concern that should still be reviewed."
        )
    else:
        risk = (
            "Business impact cannot be determined automatically from the "
            "available evidence."
        )

    return meaning, risk


# ---------------------------------------------------------------------------
# Test-specific evidence normalization
# ---------------------------------------------------------------------------

def _common_response_rows(
    evidence: dict[str, Any],
) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []

    status_codes = _extract_status_codes(evidence)

    if status_codes:
        rows.append(
            (
                "HTTP Status",
                ", ".join(str(code) for code in status_codes),
            )
        )
    else:
        rows.append(("HTTP Status", "Not observed"))

    response_time = (
        evidence.get("response_time_ms")
        or evidence.get("response_time")
        or evidence.get("elapsed_ms")
    )

    if response_time is not None:
        rows.append(("Response Time", f"{response_time} ms"))

    headers = evidence.get("headers")
    if isinstance(headers, dict) and headers:
        rows.append(("Relevant Headers", _json(headers)))

    return rows


def _procedure_for_test(test_id: str) -> str:
    procedures = {
        "AUTH-001": (
            "VULPHEX sent a request to the endpoint without authentication "
            "credentials and evaluated whether the endpoint enforced an "
            "authentication requirement."
        ),
        "AUTH-002": (
            "VULPHEX analyzed the API's OpenAPI security metadata, including "
            "security schemes, operation-level declarations, global security "
            "requirements, and authentication configuration consistency."
        ),
        "AUTHZ-001": (
            "VULPHEX compared access to the same explicitly supplied object "
            "reference using two separately configured identities."
        ),
        "AUTHZ-002": (
            "VULPHEX compared access to the explicitly configured function "
            "using a privileged identity and a lower-privilege identity."
        ),
        "INPUT-001": (
            "VULPHEX established a baseline request and then applied bounded, "
            "schema-driven input mutations to supported query parameters."
        ),
        "INJ-001": (
            "VULPHEX established a baseline response and sent a small number "
            "of controlled SQL injection probes to supported parameters."
        ),
        "INJ-002": (
            "VULPHEX established a baseline response and sent bounded "
            "MongoDB-style NoSQL injection probes to supported parameters."
        ),
        "INJ-003": (
            "VULPHEX established a baseline response and sent bounded "
            "command-injection probes without executing operating-system "
            "commands."
        ),
        "DATA-001": (
            "VULPHEX inspected the bounded API response for indicators of "
            "sensitive data exposure while avoiding disclosure of sensitive "
            "values in the report."
        ),
        "INFO-001": (
            "VULPHEX inspected the response for stack traces, internal paths, "
            "database errors, internal infrastructure identifiers, and other "
            "excessive implementation details."
        ),
        "CONFIG-001": (
            "VULPHEX sent a small bounded sequence of identical requests and "
            "checked the responses and rate-limit headers for throttling "
            "behavior."
        ),
        "CONFIG-002": (
            "VULPHEX inspected security-related HTTP headers and performed "
            "controlled origin observations to evaluate CORS behavior."
        ),
        "CONFIG-003": (
            "VULPHEX inspected the normal endpoint response and available "
            "API metadata for selected security configuration indicators."
        ),
    }

    return procedures.get(
        test_id,
        "VULPHEX executed the configured security assessment for this test.",
    )


def _build_evidence_summary(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """Normalize existing finding evidence for human-readable reporting.

    This function only interprets evidence already generated by the
    assessment engine. It does not create or infer new security evidence.
    """

    test_id = str(finding.get("test_id") or "")
    evidence = _safe_dict(finding.get("evidence") or {})

    endpoint = str(
        finding.get("endpoint_path")
        or finding.get("target")
        or "Not specified"
    )

    method = str(finding.get("method") or "Not specified")
    status = str(finding.get("status") or "Unknown")

    summary: dict[str, Any] = {
        "procedure": _procedure_for_test(test_id),
        "requests": [],
        "responses": [],
        "analysis": [],
        "assessment": _status_label(status),
    }

    # ------------------------------------------------------------------
    # AUTH-001
    # ------------------------------------------------------------------
    if test_id == "AUTH-001":
        summary["requests"].append(
            {
                "label": "Unauthenticated request",
                "method": method,
                "target": _extract_url(evidence, endpoint),
                "authentication": "None",
            }
        )

        summary["responses"] = _common_response_rows(evidence)

        if evidence.get("body_preview"):
            summary["responses"].append(
                ("Body Preview", evidence["body_preview"])
            )

        summary["analysis"].append(
            str(
                evidence.get("reason")
                or finding.get("description")
                or "Authentication behavior was evaluated from the observed response."
            )
        )

    # ------------------------------------------------------------------
    # AUTH-002
    # ------------------------------------------------------------------
    elif test_id == "AUTH-002":
        summary["requests"].append(
            {
                "label": "OpenAPI metadata analysis",
                "method": "Not applicable",
                "target": endpoint,
                "authentication": "Not applicable",
            }
        )

        summary["responses"].append(
            (
                "HTTP Response",
                "Not applicable — metadata analysis only.",
            )
        )

        for key in (
            "security_schemes",
            "security",
            "operation_security",
            "global_security",
            "findings",
            "observations",
        ):
            if evidence.get(key) is not None:
                summary["analysis"].append(
                    f"{key.replace('_', ' ').title()}: "
                    f"{_display(evidence[key])}"
                )

        if not summary["analysis"]:
            summary["analysis"].append(
                str(
                    evidence.get("reason")
                    or finding.get("description")
                    or "Authentication metadata was analyzed."
                )
            )

    # ------------------------------------------------------------------
    # BOLA
    # ------------------------------------------------------------------
    elif test_id == "AUTHZ-001":
        for label, key in (
            ("Identity A / baseline", "baseline"),
            ("Identity B / secondary", "secondary"),
        ):
            item = evidence.get(key)
            if isinstance(item, dict):
                summary["requests"].append(
                    {
                        "label": label,
                        "method": method,
                        "target": _extract_url(item, endpoint),
                        "authentication": label.split(" / ")[0],
                    }
                )

                status_code = (
                    item.get("status_code")
                    or item.get("observed_status_code")
                )

                if status_code is not None:
                    summary["responses"].append(
                        (f"{label} HTTP Status", status_code)
                    )

        parameter = evidence.get("parameter")
        object_reference = (
            evidence.get("object_reference")
            or evidence.get("redacted_object_reference")
        )

        if parameter:
            summary["analysis"].append(
                f"Object parameter: {parameter}"
            )

        if object_reference:
            summary["analysis"].append(
                f"Object reference: {object_reference}"
            )

        comparison = evidence.get("comparison")
        if comparison is not None:
            summary["analysis"].append(
                f"Comparison: {_display(comparison)}"
            )

    # ------------------------------------------------------------------
    # BFLA
    # ------------------------------------------------------------------
    elif test_id == "AUTHZ-002":
        for label, key in (
            ("Privileged identity", "privileged"),
            ("Lower-privilege identity", "lower_privilege"),
        ):
            item = evidence.get(key)
            if isinstance(item, dict):
                summary["requests"].append(
                    {
                        "label": label,
                        "method": method,
                        "target": _extract_url(item, endpoint),
                        "authentication": label,
                    }
                )

                status_code = (
                    item.get("status_code")
                    or item.get("observed_status_code")
                )

                if status_code is not None:
                    summary["responses"].append(
                        (f"{label} HTTP Status", status_code)
                    )

        path = evidence.get("path")
        if path:
            summary["analysis"].append(f"Target function: {path}")

        comparison = evidence.get("comparison")
        if comparison is not None:
            summary["analysis"].append(
                f"Comparison: {_display(comparison)}"
            )

    # ------------------------------------------------------------------
    # INPUT-001
    # ------------------------------------------------------------------
    elif test_id == "INPUT-001":
        baseline = evidence.get("baseline")

        if isinstance(baseline, dict):
            summary["requests"].append(
                {
                    "label": "Baseline request",
                    "method": method,
                    "target": _extract_url(baseline, endpoint),
                    "authentication": _extract_authentication(
                        baseline
                    ) or "Not specified",
                }
            )

            if baseline.get("status_code") is not None:
                summary["responses"].append(
                    (
                        "Baseline HTTP Status",
                        baseline["status_code"],
                    )
                )

        mutations = evidence.get("mutations") or evidence.get(
            "observations"
        )

        if isinstance(mutations, list):
            for index, mutation in enumerate(mutations, 1):
                if not isinstance(mutation, dict):
                    continue

                parameter = mutation.get("parameter", "Unknown")
                mutation_type = mutation.get(
                    "mutation_type",
                    "Mutation",
                )

                mutated_status = (
                    mutation.get("mutated_status")
                    or mutation.get("status_code")
                    or mutation.get("observed_status_code")
                )

                baseline_status = mutation.get("baseline_status")

                summary["analysis"].append(
                    f"Mutation {index}: parameter={parameter}; "
                    f"type={mutation_type}; "
                    f"baseline={baseline_status}; "
                    f"mutated={mutated_status}"
                )

    # ------------------------------------------------------------------
    # Injection tests
    # ------------------------------------------------------------------
    elif test_id in {"INJ-001", "INJ-002", "INJ-003"}:
        baseline = evidence.get("baseline")

        if isinstance(baseline, dict):
            summary["requests"].append(
                {
                    "label": "Baseline request",
                    "method": method,
                    "target": _extract_url(baseline, endpoint),
                    "authentication": _extract_authentication(
                        baseline
                    ) or "Not specified",
                }
            )

            if baseline.get("status_code") is not None:
                summary["responses"].append(
                    (
                        "Baseline HTTP Status",
                        baseline["status_code"],
                    )
                )

        probes = evidence.get("probes") or evidence.get("observations")

        if isinstance(probes, list):
            for index, probe in enumerate(probes, 1):
                if not isinstance(probe, dict):
                    continue

                status_code = (
                    probe.get("status_code")
                    or probe.get("observed_status_code")
                )

                parameter = probe.get("parameter")
                indicator = (
                    probe.get("indicator")
                    or probe.get("detected_indicator")
                    or probe.get("detection")
                )

                parts = [f"Probe {index}"]

                if parameter:
                    parts.append(f"parameter={parameter}")

                if status_code is not None:
                    parts.append(f"status={status_code}")

                if indicator:
                    parts.append(f"indicator={indicator}")

                summary["analysis"].append("; ".join(parts))

    # ------------------------------------------------------------------
    # DATA-001
    # ------------------------------------------------------------------
    elif test_id == "DATA-001":
        summary["requests"].append(
            {
                "label": "Normal endpoint request",
                "method": method,
                "target": _extract_url(evidence, endpoint),
                "authentication": _extract_authentication(evidence)
                or "Not specified",
            }
        )

        summary["responses"] = _common_response_rows(evidence)

        for key in (
            "sensitive_categories",
            "categories",
            "sensitive_fields",
            "locations",
            "paths",
            "findings",
        ):
            value = evidence.get(key)
            if value:
                summary["analysis"].append(
                    f"{key.replace('_', ' ').title()}: {_display(value)}"
                )

        if not summary["analysis"]:
            summary["analysis"].append(
                str(
                    evidence.get("reason")
                    or "Response content was inspected for sensitive-data indicators."
                )
            )

    # ------------------------------------------------------------------
    # INFO-001
    # ------------------------------------------------------------------
    elif test_id == "INFO-001":
        summary["requests"].append(
            {
                "label": "Normal endpoint request",
                "method": method,
                "target": _extract_url(evidence, endpoint),
                "authentication": _extract_authentication(evidence)
                or "Not specified",
            }
        )

        summary["responses"] = _common_response_rows(evidence)

        for key in (
            "categories",
            "disclosure_categories",
            "indicators",
            "locations",
        ):
            value = evidence.get(key)
            if value:
                summary["analysis"].append(
                    f"{key.replace('_', ' ').title()}: {_display(value)}"
                )

        if not summary["analysis"]:
            summary["analysis"].append(
                str(
                    evidence.get("reason")
                    or "The response was inspected for information-disclosure indicators."
                )
            )

    # ------------------------------------------------------------------
    # CONFIG-001
    # ------------------------------------------------------------------
    elif test_id == "CONFIG-001":
        summary["requests"].append(
            {
                "label": "Bounded sequential request sequence",
                "method": method,
                "target": _extract_url(evidence, endpoint),
                "authentication": _extract_authentication(evidence)
                or "Not specified",
            }
        )

        sequence = (
            evidence.get("requests")
            or evidence.get("observations")
            or evidence.get("responses")
        )

        if isinstance(sequence, list):
            statuses: list[Any] = []

            for index, item in enumerate(sequence, 1):
                if not isinstance(item, dict):
                    continue

                code = (
                    item.get("status_code")
                    or item.get("observed_status_code")
                    or item.get("response_status")
                )

                if code is not None:
                    statuses.append(code)

                summary["responses"].append(
                    (
                        f"Request {index} HTTP Status",
                        code if code is not None else "Not observed",
                    )
                )

            if statuses:
                summary["analysis"].append(
                    "Observed status sequence: "
                    + " → ".join(str(value) for value in statuses)
                )

        for key in (
            "rate_limit_headers",
            "headers",
            "retry_after",
        ):
            value = evidence.get(key)
            if value:
                summary["analysis"].append(
                    f"{key.replace('_', ' ').title()}: {_display(value)}"
                )

    # ------------------------------------------------------------------
    # CONFIG-002
    # ------------------------------------------------------------------
    elif test_id == "CONFIG-002":
        observations = evidence.get("observations")

        if isinstance(observations, list):
            for index, observation in enumerate(observations, 1):
                if not isinstance(observation, dict):
                    continue

                origin = observation.get("origin", "Not specified")
                code = (
                    observation.get("status_code")
                    or observation.get("observed_status_code")
                )

                summary["requests"].append(
                    {
                        "label": f"Origin observation {index}",
                        "method": method,
                        "target": _extract_url(
                            observation,
                            endpoint,
                        ),
                        "authentication": _extract_authentication(
                            observation
                        ) or "Not specified",
                        "origin": origin,
                    }
                )

                summary["responses"].append(
                    (
                        f"Origin {origin} HTTP Status",
                        code if code is not None else "Not observed",
                    )
                )

                for key in (
                    "cors_headers",
                    "security_headers",
                    "headers",
                ):
                    value = observation.get(key)
                    if value:
                        summary["analysis"].append(
                            f"Origin {origin} — "
                            f"{key.replace('_', ' ').title()}: "
                            f"{_display(value)}"
                        )

        if not summary["requests"]:
            summary["requests"].append(
                {
                    "label": "Security configuration observation",
                    "method": method,
                    "target": _extract_url(evidence, endpoint),
                    "authentication": _extract_authentication(evidence)
                    or "Not specified",
                }
            )

        if not summary["analysis"]:
            for key in (
                "cors",
                "security_headers",
                "headers",
                "observations",
            ):
                if evidence.get(key):
                    summary["analysis"].append(
                        f"{key.replace('_', ' ').title()}: "
                        f"{_display(evidence[key])}"
                    )

    # ------------------------------------------------------------------
    # CONFIG-003
    # ------------------------------------------------------------------
    elif test_id == "CONFIG-003":
        summary["requests"].append(
            {
                "label": "Configuration inspection request",
                "method": method,
                "target": _extract_url(evidence, endpoint),
                "authentication": _extract_authentication(evidence)
                or "Not specified",
            }
        )

        summary["responses"] = _common_response_rows(evidence)

        for key in (
            "indicators",
            "configuration_indicators",
            "observations",
            "headers",
        ):
            value = evidence.get(key)
            if value:
                summary["analysis"].append(
                    f"{key.replace('_', ' ').title()}: {_display(value)}"
                )

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------
    else:
        summary["requests"].append(
            {
                "label": "Assessment request",
                "method": method,
                "target": _extract_url(evidence, endpoint),
                "authentication": _extract_authentication(evidence)
                or "Not specified",
            }
        )

        summary["responses"] = _common_response_rows(evidence)

        reason = evidence.get("reason") or finding.get("description")

        if reason:
            summary["analysis"].append(str(reason))

    return summary


# ---------------------------------------------------------------------------
# Page sections
# ---------------------------------------------------------------------------

def _render_metadata(report: AssessmentReport) -> str:
    metadata = report.to_dict()["report"]

    return f"""
    <div class="metadata">
        <div class="metadata-item">
            <span class="metadata-label">Target</span>
            <span class="metadata-value">{escape(str(metadata["target"]))}</span>
        </div>

        <div class="metadata-item">
            <span class="metadata-label">Generated</span>
            <span class="metadata-value">{escape(str(metadata["generated_at"]))}</span>
        </div>

        <div class="metadata-item">
            <span class="metadata-label">Tool Version</span>
            <span class="metadata-value">{escape(str(metadata["tool_version"]))}</span>
        </div>

        <div class="metadata-item">
            <span class="metadata-label">Assessment Results</span>
            <span class="metadata-value">{report.result_count}</span>
        </div>
    </div>
    """


def _render_summary(report: AssessmentReport) -> str:
    summary = report.summary
    by_severity = summary.get("findings_by_severity", {})

    cards = [
        (
            "Assessment Results",
            summary.get("total_results", report.result_count),
        ),
        (
            "Potential Findings",
            summary.get("total_findings", len(report.findings)),
        ),
        ("High", by_severity.get("High", 0)),
        ("Medium", by_severity.get("Medium", 0)),
        ("Low", by_severity.get("Low", 0)),
        ("Informational", by_severity.get("Informational", 0)),
    ]

    rendered = "".join(
        f"""
        <div class="summary-card">
            <span class="summary-number">{escape(str(value))}</span>
            <span class="summary-label">{escape(label)}</span>
        </div>
        """
        for label, value in cards
    )

    return f"""
    <section>
        <h2>Executive Summary</h2>

        <p>
            VULPHEX performed bounded automated API security assessments
            covering authentication, authorization, input validation,
            injection, sensitive data exposure, information disclosure,
            rate limiting, CORS and API security configuration where
            applicable.
        </p>

        <div class="summary-grid">
            {rendered}
        </div>

        <div class="cover-note">
            <strong>Interpretation:</strong>
            Assessment results represent individual automated test outcomes.
            Potential findings are observations requiring appropriate manual
            validation before being treated as confirmed vulnerabilities.
        </div>
    </section>
    """


def _collect_coverage(report: AssessmentReport) -> dict[str, dict[str, int]]:
    coverage: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "results": 0,
            "potential": 0,
            "not_applicable": 0,
            "inconclusive": 0,
        }
    )

    # Count every actual AssessmentResult retained by AssessmentReport.
    # No per-test execution counts are inferred or invented.
    for result in report.results:
        test_id = str(result.get("test_id") or "UNKNOWN")
        status = str(result.get("status") or "").upper()

        coverage[test_id]["results"] += 1

        if status.startswith("POTENTIAL_"):
            coverage[test_id]["potential"] += 1

        if status == "NOT_APPLICABLE":
            coverage[test_id]["not_applicable"] += 1

        if status == "INCONCLUSIVE":
            coverage[test_id]["inconclusive"] += 1

    return coverage


def _render_coverage(report: AssessmentReport) -> str:
    coverage = _collect_coverage(report)

    rows = []

    for test_id, test_name in _TEST_NAMES.items():
        item = coverage.get(
            test_id,
            {
                "results": 0,
                "potential": 0,
                "not_applicable": 0,
                "inconclusive": 0,
            },
        )

        rows.append(
            f"""
            <tr>
                <td><strong>{escape(test_id)}</strong></td>
                <td>{escape(test_name)}</td>
                <td>{item["results"]}</td>
                <td>{item["potential"]}</td>
                <td>{item["not_applicable"]}</td>
                <td>{item["inconclusive"]}</td>
            </tr>
            """
        )

    return """
    <section>
        <h2>Assessment Coverage</h2>

        <p class="muted">
            The table shows the actual assessment results produced by each
            security test. Counts are derived directly from the recorded
            assessment outcomes.
        </p>

        <table class="compact-table coverage-table">
            <thead>
                <tr>
                    <th>Test ID</th>
                    <th>Assessment</th>
                    <th>Results</th>
                    <th>Potential Findings</th>
                    <th>Not Applicable</th>
                    <th>Inconclusive</th>
                </tr>
            </thead>
            <tbody>
                """ + "".join(rows) + """
            </tbody>
        </table>
    </section>
    """


def _render_findings_summary(report: AssessmentReport) -> str:
    if not report.findings:
        return """
        <section>
            <h2>Findings Summary</h2>
            <p class="muted">No issue-producing findings were identified.</p>
        </section>
        """

    rows = []

    for finding in report.findings:
        status = str(finding.get("status") or "Unknown")
        severity = finding.get("severity")
        method = str(finding.get("method") or "—")
        endpoint = str(
            finding.get("endpoint_path")
            or finding.get("target")
            or "Not specified"
        )

        rows.append(
            f"""
            <tr>
                <td>{escape(str(finding.get("finding_id", "Unknown")))}</td>
                <td>{escape(str(finding.get("test_id", "Unknown")))}</td>
                <td>
                    <span class="severity {_severity_class(severity)}">
                        {escape(str(severity or "Not determined"))}
                    </span>
                </td>
                <td>{escape(_business_status(status))}</td>
                <td>{escape(method)}</td>
                <td>{escape(endpoint)}</td>
            </tr>
            """
        )

    return """
    <section>
        <h2>Findings Summary</h2>

        <table class="compact-table">
            <thead>
                <tr>
                    <th>Finding ID</th>
                    <th>Test</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Method</th>
                    <th>Endpoint</th>
                </tr>
            </thead>
            <tbody>
                """ + "".join(rows) + """
            </tbody>
        </table>
    </section>
    """


def _render_key_value_table(
    rows: list[tuple[str, Any]],
    css_class: str = "analysis-table",
) -> str:
    if not rows:
        return '<p class="muted">No additional evidence was recorded.</p>'

    rendered = []

    for label, value in rows:
        rendered.append(
            f"""
            <tr>
                <th>{escape(str(label))}</th>
                <td>{escape(_display(value))}</td>
            </tr>
            """
        )

    return f"""
    <table class="{css_class}">
        <tbody>
            {"".join(rendered)}
        </tbody>
    </table>
    """


def _render_requests(requests: list[dict[str, Any]]) -> str:
    if not requests:
        return '<p class="muted">No request details were recorded.</p>'

    blocks = []

    for request in requests:
        rows = [
            ("Method", request.get("method")),
            ("Target", request.get("target")),
            ("Authentication", request.get("authentication")),
        ]

        if request.get("origin") is not None:
            rows.append(("Origin", request["origin"]))

        blocks.append(
            f"""
            <div class="observation-block">
                <div class="observation-title">
                    {escape(str(request.get("label", "Request")))}
                </div>
                <div class="observation-body">
                    {_render_key_value_table(rows, "request-table")}
                </div>
            </div>
            """
        )

    return "".join(blocks)


def _render_responses(responses: list[tuple[str, Any]]) -> str:
    if not responses:
        return '<p class="muted">No response details were recorded.</p>'

    return _render_key_value_table(responses, "response-table")


def _render_analysis(analysis: list[str]) -> str:
    if not analysis:
        return (
            '<p class="muted">'
            "No additional detection indicators were recorded."
            "</p>"
        )

    items = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in analysis
    )

    return f'<ul class="procedure-list">{items}</ul>'


def _render_finding(finding: dict[str, Any]) -> str:
    severity = finding.get("severity")
    severity_text = str(severity or "Not determined")

    status = str(finding.get("status") or "Unknown")
    business_status = _business_status(status)

    endpoint = str(
        finding.get("endpoint_path")
        or finding.get("target")
        or "Not specified"
    )

    method = str(finding.get("method") or "Not specified")
    finding_id = str(finding.get("finding_id", "Unknown ID"))
    test_id = str(finding.get("test_id", "Not specified"))
    test_name = str(
        finding.get("test_name")
        or _TEST_NAMES.get(test_id, "")
    )

    description = str(
        finding.get("description")
        or "No description was provided."
    )

    recommendation = str(
        finding.get("recommendation")
        or "No recommendation was provided."
    )

    evidence = _safe_dict(finding.get("evidence") or {})
    normalized = _build_evidence_summary(finding)

    meaning, risk = _finding_status_description(
        status,
        severity,
    )

    evidence_text = _json(evidence)

    operation_id = finding.get("operation_id")
    target = finding.get("target") or endpoint

    return f"""
    <article class="finding">

        <div class="finding-header">
            <div class="finding-title-row">
                <div>
                    <h3>{escape(str(finding.get("title", "Untitled Finding")))}</h3>

                    <div class="finding-meta">
                        <strong>{escape(finding_id)}</strong>
                        &nbsp;·&nbsp;
                        {escape(test_id)}
                        &nbsp;·&nbsp;
                        {escape(method)} {escape(endpoint)}
                    </div>
                </div>

                <div class="finding-badges">
                    <span class="severity {_severity_class(severity)}">
                        {escape(severity_text)}
                    </span>

                    <span class="status-badge">
                        {escape(business_status)}
                    </span>
                </div>
            </div>
        </div>

        <div class="finding-body">

            <div class="finding-overview">

                <div class="overview-card">
                    <span class="overview-label">Finding ID</span>
                    <strong>{escape(finding_id)}</strong>
                </div>

                <div class="overview-card">
                    <span class="overview-label">Test</span>
                    <strong>{escape(test_id)} — {escape(test_name)}</strong>
                </div>

                <div class="overview-card">
                    <span class="overview-label">Severity</span>
                    <strong>{escape(severity_text)}</strong>
                </div>

                <div class="overview-card">
                    <span class="overview-label">Status</span>
                    <strong>{escape(business_status)}</strong>
                </div>

                <div class="overview-card">
                    <span class="overview-label">Endpoint</span>
                    <strong>{escape(method)} {escape(endpoint)}</strong>
                </div>

                <div class="overview-card">
                    <span class="overview-label">Operation ID</span>
                    <strong>{escape(str(operation_id or "Not specified"))}</strong>
                </div>

            </div>

            <div class="field">
                <div class="field-label">What Does This Mean?</div>
                <div class="section-box">
                    <p>{escape(description)}</p>
                    <p class="muted">{escape(meaning)}</p>
                </div>
            </div>

            <div class="field">
                <div class="field-label">Why Does This Matter?</div>
                <div class="section-box">
                    <p>{escape(risk)}</p>
                    <p class="muted">
                        Business impact requires target-specific validation
                        and appropriate security review.
                    </p>
                </div>
            </div>

            <div class="field">
                <div class="field-label">Assessment Procedure</div>
                <div class="section-box">
                    <p>{escape(str(normalized["procedure"]))}</p>
                </div>
            </div>

            <div class="field">
                <div class="field-label">Requests Performed</div>
                <div class="section-box">
                    {_render_requests(normalized["requests"])}
                </div>
            </div>

            <div class="field">
                <div class="field-label">Observed Responses</div>
                <div class="section-box">
                    {_render_responses(normalized["responses"])}
                </div>
            </div>

            <div class="field">
                <div class="field-label">Detection / Analysis</div>
                <div class="section-box">
                    {_render_analysis(normalized["analysis"])}
                </div>
            </div>

            <div class="field">
                <div class="field-label">Assessment</div>
                <div class="assessment-box">
                    <strong>{escape(_status_label(status))}</strong>
                    <p class="muted">
                        Technical status:
                        <code>{escape(status)}</code>
                    </p>
                </div>
            </div>

            <div class="field">
                <div class="field-label">Recommended Action</div>
                <div class="recommendation-box">
                    <p>{escape(recommendation)}</p>
                </div>
            </div>

            <details class="technical-details">
                <summary>Technical Evidence</summary>

                <div class="technical-content">
                    <p class="muted">
                        Raw structured evidence generated by VULPHEX.
                        Sensitive values should already be sanitized by
                        the assessment engine.
                    </p>

                    <pre>{escape(evidence_text)}</pre>
                </div>
            </details>

        </div>
    </article>
    """


def _render_findings(report: AssessmentReport) -> str:
    if not report.findings:
        return """
        <section>
            <h2>Detailed Findings</h2>
            <p class="muted">
                No issue-producing findings were identified.
            </p>
        </section>
        """

    rendered = "".join(
        _render_finding(finding)
        for finding in report.findings
    )

    return f"""
    <section>
        <h2>Detailed Findings</h2>
        <p class="muted">
            Each finding below presents the assessment procedure,
            observed evidence, automated analysis and recommended action.
        </p>
        {rendered}
    </section>
    """


def _render_methodology() -> str:
    return """
    <section>
        <h2>Assessment Methodology</h2>

        <p>
            VULPHEX performs bounded API security assessments against
            discovered or explicitly supplied API endpoints. Individual
            security tests generate structured assessment results which
            are normalized into findings for reporting.
        </p>

        <p>
            The assessment covers authentication, authorization, input
            validation, injection, sensitive-data exposure, information
            disclosure, rate limiting and security configuration controls
            where applicable to the endpoint.
        </p>

        <p>
            Automated findings represent observed behavior and evidence
            from the configured assessment. They should be manually
            validated before being treated as confirmed vulnerabilities.
        </p>
    </section>
    """


def _render_limitations() -> str:
    return """
    <section>
        <h2>Limitations</h2>

        <ul>
            <li>
                Automated findings do not establish definitive business
                impact.
            </li>
            <li>
                Bounded tests do not prove the absence of a vulnerability.
            </li>
            <li>
                Authentication and authorization assessments depend on
                the explicitly supplied test context.
            </li>
            <li>
                Some endpoint tests are not applicable when required
                schema, parameter, method or authorization context is
                unavailable.
            </li>
            <li>
                Evidence is intentionally bounded and sanitized to avoid
                exposing credentials, tokens or other sensitive values.
            </li>
            <li>
                Only authorized targets should be assessed.
            </li>
        </ul>
    </section>
    """


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def render_html_report(report: AssessmentReport) -> str:
    """Render an AssessmentReport as a complete standalone HTML document."""

    metadata = report.to_dict()["report"]

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="generator"
          content="VULPHEX {escape(str(metadata["tool_version"]))}">
    <title>VULPHEX API Security Assessment</title>

    <style>
        {_CSS}
    </style>
</head>

<body>
    <main class="container">

        <header class="cover">
            <div class="report-type">
                API Security Assessment
            </div>

            <h1>VULPHEX</h1>

            <div class="subtitle">
                API Security Assessment Report
            </div>

            {_render_metadata(report)}

            <div class="cover-note">
                This report contains automated security assessment
                observations generated by VULPHEX. Potential findings
                require appropriate technical validation before being
                treated as confirmed vulnerabilities.
            </div>
        </header>

        {_render_summary(report)}

        {_render_coverage(report)}

        {_render_findings_summary(report)}

        {_render_findings(report)}

        {_render_methodology()}

        {_render_limitations()}

        <div class="footer">
            Generated by VULPHEX
            {escape(str(metadata["tool_version"]))}
        </div>

    </main>
</body>
</html>
"""


def write_html_report(
    report: AssessmentReport,
    path: str | Path,
) -> Path:
    """Write a standalone HTML report to disk."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        render_html_report(report),
        encoding="utf-8",
    )

    return output_path