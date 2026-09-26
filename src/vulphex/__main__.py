"""Command-line entry point for VULPHEX."""

import json
from pathlib import Path
import typer

from . import __version__
from .auth_test import MissingAuthenticationTest
from .api_misconfiguration_test import ApiMisconfigurationTest
from .auth_scheme_test import AuthenticationSchemeAnalysisTest
from .authentication import (
    AuthenticationConfigError,
    authentication_config_from_environment,
    bfla_context_from_environment,
    bola_context_from_environment,
)
from .bfla_test import BrokenFunctionLevelAuthorizationTest
from .bola_test import BrokenObjectLevelAuthorizationTest
from .discovery import OpenAPIDiscoveryError, discover_openapi
from .engine import AssessmentEngine
from .http_client import sanitize_url
from .command_injection_test import CommandInjectionTest
from .input_validation_test import InputValidationTest
from .nosql_injection_test import NoSqlInjectionTest
from .output import render_json, render_json_results, render_text, render_text_results
from .html_report import write_html_report
from .pdf_report import write_pdf_report
from .report import build_assessment_report
from .sensitive_data_test import SensitiveDataExposureTest
from .error_disclosure_test import ErrorDisclosureTest
from .rate_limit_test import RateLimitTest
from .security_config_test import SecurityConfigurationTest
from .sql_injection_test import SqlInjectionTest

app = typer.Typer(
    add_completion=False,
    help="CLI-based API Security Assessment Tool.",
)


@app.callback(invoke_without_command=True)
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Show the VULPHEX version.",
    ),
) -> None:
    """Display basic VULPHEX project information."""
    if version:
        typer.echo(f"VULPHEX {__version__}")


@app.command("auth-test")
def auth_test(
    url: str = typer.Option(..., "--url", help="Authorized API endpoint to assess."),
    output: str = typer.Option(
        "text",
        "--output",
        help="Output format: text or json.",
        case_sensitive=False,
    ),
) -> None:
    """Check whether an API endpoint responds without authentication."""
    if output.lower() not in {"text", "json"}:
        raise typer.BadParameter("must be either 'text' or 'json'", param_hint="--output")
    result = MissingAuthenticationTest().execute(url)
    typer.echo(render_json(result) if output.lower() == "json" else render_text(result))


@app.command("assess")
def assess(
    url: str = typer.Option(..., "--url", help="Authorized API endpoint to assess."),
    output: str = typer.Option(
        "text",
        "--output",
        help="Output format: text or json.",
        case_sensitive=False,
    ),
) -> None:
    """Run the configured VULPHEX security tests against an API endpoint."""
    if output.lower() not in {"text", "json"}:
        raise typer.BadParameter("must be either 'text' or 'json'", param_hint="--output")
    results = AssessmentEngine([MissingAuthenticationTest()]).assess(url)
    rendered = render_json_results(results) if output.lower() == "json" else render_text_results(results)
    typer.echo(rendered)


@app.command("discover")
def discover(
    url: str = typer.Option(..., "--url", help="Authorized API base URL to discover."),
    output: str = typer.Option(
        "text",
        "--output",
        help="Output format: text or json.",
        case_sensitive=False,
    ),
) -> None:
    """Discover a local OpenAPI or Swagger specification."""
    if output.lower() not in {"text", "json"}:
        raise typer.BadParameter("must be either 'text' or 'json'", param_hint="--output")
    try:
        result = discover_openapi(url)
    except (ValueError, OpenAPIDiscoveryError) as exc:
        raise typer.BadParameter(str(exc), param_hint="--url") from exc

    if output.lower() == "json":
        typer.echo(json.dumps(result.to_dict(), indent=2))
        return

    typer.echo("VULPHEX API DISCOVERY")
    typer.echo(f"Target: {result.target}")
    typer.echo(f"Source: {result.specification_url}")
    typer.echo(f"Endpoints discovered: {len(result.inventory)}")
    for endpoint in result.resolved_endpoints:
        typer.echo(f"{endpoint.method:<7} {endpoint.path} -> {endpoint.target}")


@app.command("assess-api")
def assess_api(
    url: str = typer.Option(..., "--url", help="Authorized API base URL to discover and assess."),
    output: str = typer.Option(
        "text",
        "--output",
        help="Output format: text or json.",
        case_sensitive=False,
    ),
    report_dir: str | None = typer.Option(
        None,
        "--report-dir",
        help="Directory where JSON, HTML and PDF assessment reports will be written.",
    ),
) -> None:
    
    """Discover an API and run currently applicable security tests."""
    if output.lower() not in {"text", "json"}:
        raise typer.BadParameter("must be either 'text' or 'json'", param_hint="--output")
    try:
        discovery = discover_openapi(url)
    except (ValueError, OpenAPIDiscoveryError) as exc:
        error = {"status": "DISCOVERY_ERROR", "target": sanitize_url(url), "error": str(exc)}
        typer.echo(json.dumps(error, indent=2) if output.lower() == "json" else f"Discovery failed: {exc}")
        return

    try:
        authentication = authentication_config_from_environment()
    except AuthenticationConfigError as exc:
        error = {"status": "AUTHENTICATION_CONFIGURATION_ERROR", "target": sanitize_url(url), "error": str(exc)}
        typer.echo(json.dumps(error, indent=2) if output.lower() == "json" else f"Authentication configuration failed: {exc}")
        return

    try:
        bola_context = bola_context_from_environment()
    except AuthenticationConfigError as exc:
        error = {"status": "BOLA_CONFIGURATION_ERROR", "target": sanitize_url(url), "error": str(exc)}
        typer.echo(json.dumps(error, indent=2) if output.lower() == "json" else f"BOLA configuration failed: {exc}")
        return

    try:
        bfla_context = bfla_context_from_environment()
    except AuthenticationConfigError as exc:
        error = {"status": "BFLA_CONFIGURATION_ERROR", "target": sanitize_url(url), "error": str(exc)}
        typer.echo(json.dumps(error, indent=2) if output.lower() == "json" else f"BFLA configuration failed: {exc}")
        return

    results = AssessmentEngine([
        MissingAuthenticationTest(),
        AuthenticationSchemeAnalysisTest(),
        BrokenObjectLevelAuthorizationTest(),
        BrokenFunctionLevelAuthorizationTest(),
        InputValidationTest(),
        SqlInjectionTest(),
        NoSqlInjectionTest(),
        CommandInjectionTest(),
        SensitiveDataExposureTest(),
        ErrorDisclosureTest(),
        RateLimitTest(),
        SecurityConfigurationTest(),
        ApiMisconfigurationTest(),
    ]).assess_endpoints(
        discovery.resolved_endpoints,
        authentication=authentication,
        bola_context=bola_context,
        bfla_context=bfla_context,
    )

    if not results:
        typer.echo("No assessable endpoints were discovered.")
        return

    if output.lower() == "json":
        typer.echo(render_json_results(results))
    else:
        typer.echo(render_text_results(results))

    if report_dir:
        report = build_assessment_report(
            results,
            target=sanitize_url(url),
            tool_version=__version__,
        )

        output_path = Path(report_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        json_path = output_path / "assessment.json"
        html_path = output_path / "assessment.html"
        pdf_path = output_path / "assessment.pdf"
        write_pdf_report(report, pdf_path)

        report.write_json(json_path)
        write_html_report(report, html_path)

        typer.echo(f"JSON report: {json_path}")
        typer.echo(f"HTML report: {html_path}")
        typer.echo(f"PDF report: {pdf_path}")

if __name__ == "__main__":
    app()