"""Output renderers for VULPHEX assessment results."""

import json
from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..Core.models import AssessmentResult


# ============================================================
# STATUS PRESENTATION
# ============================================================

STATUS_STYLES = {
    "POTENTIAL_MISSING_AUTHENTICATION": (
        "Potential missing authentication",
        "yellow",
    ),
    "AUTHENTICATION_ENFORCED": (
        "Authentication enforced",
        "green",
    ),
    "POTENTIAL_BOLA": (
        "Potential Broken Object Level Authorization",
        "red",
    ),
    "POTENTIAL_BFLA": (
        "Potential Broken Function Level Authorization",
        "red",
    ),
    "AUTHORIZATION_ENFORCED": (
        "Authorization enforced",
        "green",
    ),
    "POTENTIAL_SQL_INJECTION": (
        "Potential SQL injection",
        "red",
    ),
    "POTENTIAL_NOSQL_INJECTION": (
        "Potential NoSQL injection",
        "red",
    ),
    "POTENTIAL_COMMAND_INJECTION": (
        "Potential command injection",
        "red",
    ),
    "POTENTIAL_SENSITIVE_DATA_EXPOSURE": (
        "Potential sensitive data exposure",
        "red",
    ),
    "POTENTIAL_INFORMATION_DISCLOSURE": (
        "Potential information disclosure",
        "yellow",
    ),
    "RATE_LIMITING_OBSERVED": (
        "Rate limiting observed",
        "green",
    ),
    "NO_RATE_LIMITING_OBSERVED": (
        "No rate limiting observed",
        "yellow",
    ),
    "POTENTIAL_API_MISCONFIGURATION": (
        "Potential API misconfiguration",
        "yellow",
    ),
    "SECURITY_CONFIGURATION_EXCEPTION": (
        "Security configuration exception",
        "yellow",
    ),
    "INFORMATIONAL_CONFIGURATION_OBSERVED": (
        "Informational configuration observed",
        "cyan",
    ),
    "NO_API_MISCONFIGURATION_INDICATED": (
        "No API misconfiguration indicated",
        "green",
    ),
    "NO_SQL_INJECTION_INDICATED": (
        "No SQL injection indicated",
        "green",
    ),
    "NO_SENSITIVE_DATA_EXPOSURE_INDICATED": (
        "No sensitive data exposure indicated",
        "green",
    ),
    "NO_INFORMATION_DISCLOSURE_INDICATED": (
        "No information disclosure indicated",
        "green",
    ),
    "AUTHENTICATION_DECLARED": (
        "Authentication declared",
        "green",
    ),
    "NO_AUTHENTICATION_DECLARED": (
        "No authentication declared",
        "yellow",
    ),
    "AUTHENTICATION_CONFIGURATION_INCONSISTENT": (
        "Authentication configuration inconsistent",
        "yellow",
    ),
    "AUTHENTICATION_REQUIRED": (
        "Authentication required",
        "yellow",
    ),
    "INVALID_TEST_CONFIGURATION": (
        "Invalid test configuration",
        "red",
    ),
    "NOT_APPLICABLE": (
        "Not applicable",
        "cyan",
    ),
    "UNSUPPORTED_OPERATION": (
        "Unsupported operation",
        "cyan",
    ),
    "INCONCLUSIVE": (
        "Inconclusive",
        "yellow",
    ),
}


SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "cyan",
}


# ============================================================
# JSON OUTPUT
# ============================================================

def render_json(result: AssessmentResult) -> str:
    """Render an assessment as machine-readable JSON."""
    return json.dumps(
        result.to_dict(),
        indent=2,
    )


def render_json_results(
    results: list[AssessmentResult],
) -> str:
    """Render multiple assessments as a machine-readable JSON array."""
    return json.dumps(
        [
            result.to_dict()
            for result in results
        ],
        indent=2,
    )


# ============================================================
# SINGLE RESULT
# ============================================================

def render_text(
    result: AssessmentResult,
) -> str:
    """
    Render one assessment result as a human-readable
    terminal report.
    """

    output = StringIO()

    console = Console(
        file=output,
        no_color=True,
        width=120,
    )

    status_label, status_style = (
        _status_display(result.status)
    )

    severity = (
        result.severity
        or "Not determined"
    )

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    console.print(
        "VULPHEX API SECURITY ASSESSMENT",
        style="bold",
    )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    summary = Table.grid(
        padding=(0, 2),
    )

    summary.add_column(
        style="bold",
    )

    summary.add_column()

    summary.add_row(
        "Target",
        result.target,
    )

    summary.add_row(
        "Method",
        result.method,
    )

    summary.add_row(
        "Test",
        result.test_name,
    )

    summary.add_row(
        "Status",
        status_label,
    )

    summary.add_row(
        "Severity",
        severity,
    )

    console.print(
        Panel(
            summary,
            title="ASSESSMENT",
        )
    )

    # --------------------------------------------------------
    # ENDPOINT
    # --------------------------------------------------------

    if result.endpoint_path:

        endpoint_context = Table.grid(
            padding=(0, 2),
        )

        endpoint_context.add_column(
            style="bold",
        )

        endpoint_context.add_column()

        endpoint_context.add_row(
            "OpenAPI path",
            result.endpoint_path,
        )

        endpoint_context.add_row(
            "Operation ID",
            result.operation_id
            or "Not available",
        )

        console.print(
            Panel(
                endpoint_context,
                title="ENDPOINT",
            )
        )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    result_panel = Panel(
        Text.assemble(
            (
                "Result: ",
                "bold",
            ),
            (
                status_label,
                status_style,
            ),
            (
                "\nHTTP status: ",
                "bold",
            ),
            (
                str(
                    result.observed_status_code
                    if result.observed_status_code
                    is not None
                    else "Not observed"
                ),
            ),
            (
                "\nSeverity: ",
                "bold",
            ),
            (
                severity,
            ),
        ),
        title="RESULT",
        border_style=status_style,
    )

    console.print(
        result_panel
    )

    # --------------------------------------------------------
    # REASON
    # --------------------------------------------------------

    console.print(
        Panel(
            result.reason,
            title="WHAT VULPHEX OBSERVED",
        )
    )

    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    evidence = (
        result.evidence
        if isinstance(result.evidence, dict)
        else {}
    )

    evidence_table = Table.grid(
        padding=(0, 2),
    )

    evidence_table.add_column(
        style="bold",
    )

    evidence_table.add_column()

    if "response_time_ms" in evidence:

        evidence_table.add_row(
            "Response time",
            f"{evidence.get('response_time_ms')} ms",
        )

    if "headers" in evidence:

        evidence_table.add_row(
            "Relevant headers",
            _format_headers(
                evidence.get("headers")
            ),
        )

    if "body_preview" in evidence:

        evidence_table.add_row(
            "Body preview",
            _format_body_preview(
                evidence.get("body_preview")
            ),
        )

    # Other useful evidence fields.
    excluded = {
        "response_time_ms",
        "headers",
        "body_preview",
    }

    for key, value in evidence.items():

        if key in excluded:
            continue

        if value is None:
            continue

        evidence_table.add_row(
            _humanize_key(key),
            _format_value(value),
        )

    if evidence_table.row_count > 0:

        console.print(
            Panel(
                evidence_table,
                title="EVIDENCE",
            )
        )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    console.print(
        Panel(
            result.recommendation,
            title="RECOMMENDED ACTION",
        )
    )

    return output.getvalue()


# ============================================================
# MULTIPLE RESULTS
# ============================================================

def render_text_results(
    results: list[AssessmentResult],
) -> str:
    """
    Render a complete assessment as a structured,
    human-readable terminal report.
    """

    output = StringIO()

    console = Console(
        file=output,
        no_color=True,
        width=120,
    )

    if not results:

        console.print(
            "VULPHEX API SECURITY ASSESSMENT"
        )

        console.print(
            Panel(
                "No assessment results were produced.",
                title="RESULT",
            )
        )

        return output.getvalue()

    target = results[0].target

    # --------------------------------------------------------
    # SUMMARY COUNTS
    # --------------------------------------------------------

    findings = [
        result
        for result in results
        if _is_finding(result)
    ]

    high = _count_severity(
        findings,
        "high",
    )

    medium = _count_severity(
        findings,
        "medium",
    )

    low = _count_severity(
        findings,
        "low",
    )

    inconclusive = sum(
        1
        for result in results
        if result.status == "INCONCLUSIVE"
    )

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    console.print()

    console.print(
        "═" * 72
    )

    console.print(
        "VULPHEX API SECURITY ASSESSMENT",
        style="bold",
    )

    console.print(
        "═" * 72
    )

    # --------------------------------------------------------
    # ASSESSMENT SUMMARY
    # --------------------------------------------------------

    summary = Table.grid(
        padding=(0, 2),
    )

    summary.add_column(
        style="bold",
    )

    summary.add_column()

    summary.add_row(
        "Target",
        target,
    )

    summary.add_row(
        "Tests executed",
        str(len(results)),
    )

    summary.add_row(
        "Potential findings",
        str(len(findings)),
    )

    summary.add_row(
        "High",
        str(high),
    )

    summary.add_row(
        "Medium",
        str(medium),
    )

    summary.add_row(
        "Low",
        str(low),
    )

    summary.add_row(
        "Inconclusive",
        str(inconclusive),
    )

    console.print(
        Panel(
            summary,
            title="SUMMARY",
        )
    )

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    console.print()

    console.print(
        "─" * 72
    )

    console.print(
        "ASSESSMENT RESULTS",
        style="bold",
    )

    console.print(
        "─" * 72
    )

    for index, result in enumerate(
        results,
        start=1,
    ):

        _render_result_compact(
            console,
            result,
            index,
        )

        if index < len(results):

            console.print()

            console.print(
                "─" * 72
            )

    # --------------------------------------------------------
    # COMPLETION
    # --------------------------------------------------------

    console.print()

    console.print(
        "═" * 72
    )

    console.print(
        "Assessment completed.",
        style="bold",
    )

    console.print(
        "═" * 72
    )

    return output.getvalue()


# ============================================================
# COMPACT RESULT
# ============================================================

def _render_result_compact(
    console: Console,
    result: AssessmentResult,
    index: int,
) -> None:

    status_label, status_style = (
        _status_display(result.status)
    )

    severity = (
        result.severity
        or "Not determined"
    )

    severity_style = SEVERITY_STYLES.get(
        severity.lower(),
        "yellow",
    )

    # --------------------------------------------------------
    # FINDING HEADER
    # --------------------------------------------------------

    console.print(
        f"[{index}] ",
        end="",
    )

    console.print(
        severity.upper(),
        style=severity_style,
        end=" — ",
    )

    console.print(
        result.test_name,
        style="bold",
    )

    # --------------------------------------------------------
    # CORE DETAILS
    # --------------------------------------------------------

    details = Table.grid(
        padding=(0, 2),
    )

    details.add_column(
        style="bold",
    )

    details.add_column()

    if result.endpoint_path:

        details.add_row(
            "Endpoint",
            result.endpoint_path,
        )

    details.add_row(
        "Status",
        status_label,
    )

    if result.observed_status_code is not None:

        details.add_row(
            "HTTP status",
            str(
                result.observed_status_code
            ),
        )

    console.print(
        details
    )

    # --------------------------------------------------------
    # WHAT VULPHEX OBSERVED
    # --------------------------------------------------------

    console.print()

    console.print(
        "What VULPHEX observed:",
        style="bold",
    )

    console.print(
        result.reason
    )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    console.print()

    console.print(
        "Recommended action:",
        style="bold",
    )

    console.print(
        result.recommendation
    )

    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    evidence = (
        result.evidence
        if isinstance(
            result.evidence,
            dict,
        )
        else {}
    )

    evidence_values = []

    if "response_time_ms" in evidence:

        evidence_values.append(
            (
                "Response time",
                f"{evidence.get('response_time_ms')} ms",
            )
        )

    if "headers" in evidence:

        evidence_values.append(
            (
                "Headers",
                _format_headers(
                    evidence.get("headers")
                ),
            )
        )

    if "body_preview" in evidence:

        evidence_values.append(
            (
                "Body preview",
                _format_body_preview(
                    evidence.get("body_preview")
                ),
            )
        )

    if evidence_values:

        console.print()

        console.print(
            "Evidence:",
            style="bold",
        )

        for label, value in evidence_values:

            console.print(
                f"  {label}: {value}"
            )


# ============================================================
# STATUS HELPERS
# ============================================================

def _status_display(
    status: str,
) -> tuple[str, str]:

    return STATUS_STYLES.get(
        status,
        (
            status.replace(
                "_",
                " ",
            ).title(),
            "yellow",
        ),
    )


# ============================================================
# FINDING HELPERS
# ============================================================

def _is_finding(
    result: AssessmentResult,
) -> bool:

    finding_statuses = {
        "POTENTIAL_MISSING_AUTHENTICATION",
        "POTENTIAL_BOLA",
        "POTENTIAL_BFLA",
        "POTENTIAL_SQL_INJECTION",
        "POTENTIAL_NOSQL_INJECTION",
        "POTENTIAL_COMMAND_INJECTION",
        "POTENTIAL_SENSITIVE_DATA_EXPOSURE",
        "POTENTIAL_INFORMATION_DISCLOSURE",
        "POTENTIAL_API_MISCONFIGURATION",
        "SECURITY_CONFIGURATION_EXCEPTION",
    }

    return result.status in finding_statuses


def _count_severity(
    results: list[AssessmentResult],
    severity: str,
) -> int:

    return sum(
        1
        for result in results
        if (
            result.severity
            and result.severity.lower()
            == severity.lower()
        )
    )


# ============================================================
# VALUE FORMATTING
# ============================================================

def _format_headers(
    value: object,
) -> str:

    if not isinstance(
        value,
        dict,
    ):
        return str(value)

    if not value:
        return "None observed"

    return ", ".join(
        f"{key}: {val}"
        for key, val in value.items()
    )


def _format_body_preview(
    value: object,
) -> str:

    if value is None:
        return "Not available"

    text = str(value)

    # Keep terminal output readable.
    text = text.replace(
        "\r",
        " ",
    ).replace(
        "\n",
        " ",
    )

    if len(text) > 300:

        text = (
            text[:300]
            + "..."
        )

    return text


def _format_value(
    value: object,
) -> str:

    if isinstance(
        value,
        dict,
    ):

        return json.dumps(
            value,
            sort_keys=True,
        )

    if isinstance(
        value,
        list,
    ):

        return json.dumps(
            value,
        )

    return str(value)


def _humanize_key(
    key: str,
) -> str:

    return key.replace(
        "_",
        " ",
    ).title()