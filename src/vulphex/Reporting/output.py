"""Output renderers for VULPHEX assessment results."""

import json
from io import StringIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..Core.models import AssessmentResult


STATUS_STYLES = {
    "POTENTIAL_MISSING_AUTHENTICATION": ("Potential missing authentication", "yellow"),
    "AUTHENTICATION_ENFORCED": ("Authentication enforced", "green"),
    "INCONCLUSIVE": ("Inconclusive", "yellow"),
}


def render_json(result: AssessmentResult) -> str:
    """Render an assessment as machine-readable JSON."""
    return json.dumps(result.to_dict(), indent=2)


def render_json_results(results: list[AssessmentResult]) -> str:
    """Render multiple assessments as a machine-readable JSON array."""
    return json.dumps([result.to_dict() for result in results], indent=2)


def render_text(result: AssessmentResult) -> str:
    """Render an assessment as a concise, human-readable terminal report."""
    output = StringIO()
    console = Console(file=output, no_color=True, width=120)
    status_label, status_style = STATUS_STYLES.get(
        result.status,
        (result.status.replace("_", " ").title(), "yellow"),
    )
    severity = result.severity or "Not determined"

    console.print("VULPHEX API SECURITY ASSESSMENT", style="bold")
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Target", result.target)
    summary.add_row("Method", result.method)
    summary.add_row("Test", f"{result.test_id} - {result.test_name}")
    console.print(summary)

    if result.endpoint_path:
        endpoint_context = Table.grid(padding=(0, 2))
        endpoint_context.add_column(style="bold")
        endpoint_context.add_column()
        endpoint_context.add_row("OpenAPI path", result.endpoint_path)
        endpoint_context.add_row("Operation ID", result.operation_id or "Not available")
        console.print(Panel(endpoint_context, title="ENDPOINT"))

    result_panel = Panel(
        Text.assemble(
            ("Result: ", "bold"),
            (status_label, status_style),
            (f"\nHTTP status: {result.observed_status_code or 'Not observed'}"),
            (f"\nSeverity: {severity}"),
        ),
        title="RESULT",
        border_style=status_style,
    )
    console.print(result_panel)

    evidence = result.evidence
    evidence_table = Table.grid(padding=(0, 2))
    evidence_table.add_column(style="bold")
    evidence_table.add_column()
    evidence_table.add_row("Response time", f"{evidence.get('response_time_ms', 'Not available')} ms")
    evidence_table.add_row("Relevant headers", _format_value(evidence.get("headers", {})))
    evidence_table.add_row("Body preview", _format_value(evidence.get("body_preview", "Not available")))
    console.print(Panel(evidence_table, title="EVIDENCE"))

    console.print(Panel(result.reason, title="REASON"))
    console.print(Panel(result.recommendation, title="RECOMMENDATION"))
    return output.getvalue()


def render_text_results(results: list[AssessmentResult]) -> str:
    """Render multiple assessments as sequential human-readable reports."""
    return "\n".join(render_text(result).rstrip() for result in results)


def _format_value(value: object) -> str:
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)