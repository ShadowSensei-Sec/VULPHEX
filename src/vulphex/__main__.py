from pathlib import Path
from typing import Optional

import typer

from .Authentication.auth_scheme_test import AuthenticationSchemeAnalysisTest
from .Authentication.auth_test import MissingAuthenticationTest
from .Authentication.authentication import (
    authentication_config_from_environment,
    bola_context_from_environment,
    bfla_context_from_environment,
)
from .Authorization.bfla_test import BrokenFunctionLevelAuthorizationTest
from .Authorization.bola_test import BrokenObjectLevelAuthorizationTest
from .Api_misconfiguration.api_misconfiguration_test import (
    ApiMisconfigurationTest,
)
from .Core.engine import AssessmentEngine
from .Data_exposure.sensitive_data_test import SensitiveDataExposureTest
from .Discovery.discovery import (
    OpenAPIDiscoveryError,
    discover_openapi,
)
from .Information_disclosure.error_disclosure_test import ErrorDisclosureTest
from .Injection.command_injection_test import CommandInjectionTest
from .Injection.nosql_injection_test import NoSqlInjectionTest
from .Injection.sql_injection_test import SqlInjectionTest
from .Input_validation.input_validation_test import InputValidationTest
from .Rate_limiting.rate_limit_test import RateLimitTest
from .Reporting.html_report import write_html_report
from .Reporting.output import render_text_results
from .Reporting.pdf_report import write_pdf_report
from .Reporting.report import build_assessment_report
from .Security_configuration.security_config_test import (
    SecurityConfigurationTest,
)


# ============================================================
# APPLICATION
# ============================================================

app = typer.Typer(
    name="vulphex",
    help="VULPHEX - CLI-based API Security Assessment Tool.",
    add_completion=False,
    no_args_is_help=True,
)


# ============================================================
# TEST REGISTRY
# ============================================================

AUTHENTICATION_TESTS = {
    "missing-authentication": MissingAuthenticationTest,
    "auth-scheme": AuthenticationSchemeAnalysisTest,
}

AUTHORIZATION_TESTS = {
    "bola": BrokenObjectLevelAuthorizationTest,
    "bfla": BrokenFunctionLevelAuthorizationTest,
}

SECURITY_TESTS = {
    "input-validation": InputValidationTest,
    "sql-injection": SqlInjectionTest,
    "nosql-injection": NoSqlInjectionTest,
    "command-injection": CommandInjectionTest,
    "data-exposure": SensitiveDataExposureTest,
    "error-disclosure": ErrorDisclosureTest,
    "rate-limiting": RateLimitTest,
    "security-configuration": SecurityConfigurationTest,
    "api-misconfiguration": ApiMisconfigurationTest,
}


# ============================================================
# HELP / OPTION GROUPS
# ============================================================

GENERAL_HELP = "General"

AUTH_HELP = "Authentication Test"

SECURITY_HELP = "Security Test"

OUTPUT_HELP = "Output Format"


# ============================================================
# VERSION
# ============================================================

VULPHEX_VERSION = "1.0.0"


# ============================================================
# GLOBAL CALLBACK
# ============================================================

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,

    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        is_eager=True,
        help="Display the VULPHEX version.",
        rich_help_panel=GENERAL_HELP,
    ),

    url: Optional[str] = typer.Option(
        None,
        "--url",
        metavar="<URL>",
        help="Authorized API base URL to assess.",
        rich_help_panel=GENERAL_HELP,
    ),

    scan: bool = typer.Option(
        False,
        "--scan",
        "-S",
        help="Run the complete VULPHEX security assessment.",
        rich_help_panel=GENERAL_HELP,
    ),

    # --------------------------------------------------------
    # AUTHENTICATION
    # --------------------------------------------------------

    all_tests: bool = typer.Option(
        False,
        "--all",
        "-a",
        help="Run all authentication and authorization tests.",
        rich_help_panel=AUTH_HELP,
    ),

    all_authorization: bool = typer.Option(
        False,
        "--all-authorization",
        "-z",
        help="Run all authorization tests.",
        rich_help_panel=AUTH_HELP,
    ),

    missing_authentication: bool = typer.Option(
        False,
        "--missing-authentication",
        "-m",
        help="Test for missing authentication.",
        rich_help_panel=AUTH_HELP,
    ),

    auth_scheme: bool = typer.Option(
        False,
        "--auth-scheme",
        "-A",
        help="Analyze API authentication schemes.",
        rich_help_panel=AUTH_HELP,
    ),

    bola: bool = typer.Option(
        False,
        "--bola",
        "-o",
        help="Test for Broken Object Level Authorization.",
        rich_help_panel=AUTH_HELP,
    ),

    bfla: bool = typer.Option(
        False,
        "--bfla",
        "-f",
        help="Test for Broken Function Level Authorization.",
        rich_help_panel=AUTH_HELP,
    ),

    # --------------------------------------------------------
    # SECURITY TESTS
    # --------------------------------------------------------

    security_all: bool = typer.Option(
        False,
        "--security-all",
        help="Run all supported security tests.",
        rich_help_panel=SECURITY_HELP,
    ),

    parse_openapi: bool = typer.Option(
        False,
        "--parse",
        "-p",
        help="Discover and parse the target's OpenAPI or Swagger specification.",
        rich_help_panel=SECURITY_HELP,
    ),

    input_validation: bool = typer.Option(
        False,
        "--input-validation",
        "-v",
        help="Test API input validation.",
        rich_help_panel=SECURITY_HELP,
    ),

    sql_injection: bool = typer.Option(
        False,
        "--sql-injection",
        "-s",
        help="Test for SQL injection.",
        rich_help_panel=SECURITY_HELP,
    ),

    nosql_injection: bool = typer.Option(
        False,
        "--nosql-injection",
        "-n",
        help="Test for NoSQL injection.",
        rich_help_panel=SECURITY_HELP,
    ),

    command_injection: bool = typer.Option(
        False,
        "--command-injection",
        "-c",
        help="Test for command injection.",
        rich_help_panel=SECURITY_HELP,
    ),

    data_exposure: bool = typer.Option(
        False,
        "--data-exposure",
        "-d",
        help="Test for sensitive data exposure.",
        rich_help_panel=SECURITY_HELP,
    ),

    error_disclosure: bool = typer.Option(
        False,
        "--error-disclosure",
        "-e",
        help="Test for error and information disclosure.",
        rich_help_panel=SECURITY_HELP,
    ),

    rate_limiting: bool = typer.Option(
        False,
        "--rate-limiting",
        "-l",
        help="Test API rate-limiting behavior.",
        rich_help_panel=SECURITY_HELP,
    ),

    security_configuration: bool = typer.Option(
        False,
        "--security-configuration",
        "-q",
        help="Test security configuration and CORS behavior.",
        rich_help_panel=SECURITY_HELP,
    ),

    api_misconfiguration: bool = typer.Option(
        False,
        "--api-misconfiguration",
        "-M",
        help="Test for API misconfiguration.",
        rich_help_panel=SECURITY_HELP,
    ),

    # --------------------------------------------------------
    # OUTPUT FORMAT
    # --------------------------------------------------------

    json_report: bool = typer.Option(
        False,
        "--json",
        "-J",
        help="Generate a JSON report.",
        rich_help_panel=OUTPUT_HELP,
    ),

    html_report: bool = typer.Option(
        False,
        "--html",
        "-W",
        help="Generate an HTML report.",
        rich_help_panel=OUTPUT_HELP,
    ),

    pdf_report: bool = typer.Option(
        False,
        "--pdf",
        "-P",
        help="Generate a PDF report.",
        rich_help_panel=OUTPUT_HELP,
    ),

    all_reports: bool = typer.Option(
        False,
        "--reports",
        "-R",
        help="Generate JSON, HTML and PDF reports.",
        rich_help_panel=OUTPUT_HELP,
    ),
) -> None:

    # --------------------------------------------------------
    # VERSION
    # --------------------------------------------------------

    if version:
        typer.echo(
            f"VULPHEX version {VULPHEX_VERSION}"
        )
        raise typer.Exit(code=0)

    # --------------------------------------------------------
    # URL
    # --------------------------------------------------------

    if url:
        target = url
    else:
        target = None

    # --------------------------------------------------------
    #  OPENAPI / SWAGGER DISCOVERY
    # --------------------------------------------------------
    
    if parse_openapi:

        target = _require_url(
            target
        )   

        _discover_and_display_openapi(
            target
        )
        
        raise typer.Exit(code=0)

    # --------------------------------------------------------
    # COMPLETE SCAN
    # --------------------------------------------------------

    if scan:

        target = _require_url(
            target
        )

        results = _run_scan(
            target
        )

        _handle_results(
            results=results,
            target=target,
            assessment_name="scan",
            json_report=json_report,
            html_report=html_report,
            pdf_report=pdf_report,
            all_reports=all_reports,
        )

        raise typer.Exit(code=0)

    # --------------------------------------------------------
    # SECURITY TEST SELECTION
    # --------------------------------------------------------

    selected_security_tests = []

    if security_all:

        selected_security_tests = list(
            SECURITY_TESTS.keys()
        )

    else:

        if input_validation:
            selected_security_tests.append(
                "input-validation"
            )

        if sql_injection:
            selected_security_tests.append(
                "sql-injection"
            )

        if nosql_injection:
            selected_security_tests.append(
                "nosql-injection"
            )

        if command_injection:
            selected_security_tests.append(
                "command-injection"
            )

        if data_exposure:
            selected_security_tests.append(
                "data-exposure"
            )

        if error_disclosure:
            selected_security_tests.append(
                "error-disclosure"
            )

        if rate_limiting:
            selected_security_tests.append(
                "rate-limiting"
            )

        if security_configuration:
            selected_security_tests.append(
                "security-configuration"
            )

        if api_misconfiguration:
            selected_security_tests.append(
                "api-misconfiguration"
            )

    # --------------------------------------------------------
    # AUTHENTICATION / AUTHORIZATION SELECTION
    # --------------------------------------------------------

    selected_auth_tests = []

    if all_tests:

        selected_auth_tests.extend(
            AUTHENTICATION_TESTS.keys()
        )

        selected_auth_tests.extend(
            AUTHORIZATION_TESTS.keys()
        )

    else:

        if missing_authentication:
            selected_auth_tests.append(
                "missing-authentication"
            )

        if auth_scheme:
            selected_auth_tests.append(
                "auth-scheme"
            )

        if all_authorization:

            selected_auth_tests.extend(
                AUTHORIZATION_TESTS.keys()
            )

        else:

            if bola:
                selected_auth_tests.append(
                    "bola"
                )

            if bfla:
                selected_auth_tests.append(
                    "bfla"
                )

    # --------------------------------------------------------
    # NOTHING SELECTED
    # --------------------------------------------------------

    if (
        not selected_auth_tests
        and not selected_security_tests
    ):

        typer.echo(ctx.get_help())
        raise typer.Exit(code=0)

    # --------------------------------------------------------
    # TARGET REQUIRED
    # --------------------------------------------------------

    target = _require_url(
        target
    )

    # --------------------------------------------------------
    # BUILD TEST LIST
    # --------------------------------------------------------

    test_instances = []

    for test_name in selected_auth_tests:

        test_class = (
            AUTHENTICATION_TESTS.get(test_name)
            or AUTHORIZATION_TESTS.get(test_name)
        )

        if test_class is not None:
            test_instances.append(
                test_class()
            )

    for test_name in selected_security_tests:

        test_class = SECURITY_TESTS.get(
            test_name
        )

        if test_class is not None:
            test_instances.append(
                test_class()
            )

    # --------------------------------------------------------
    # RUN SELECTED TESTS
    # --------------------------------------------------------

    results = _run_selected_tests(
        target=target,
        tests=test_instances,
    )

    # --------------------------------------------------------
    # ASSESSMENT NAME
    # --------------------------------------------------------

    if selected_auth_tests and selected_security_tests:
        assessment_name = "assessment"

    elif selected_auth_tests:
        assessment_name = "auth-test"

    else:
        assessment_name = "security-test"

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    _handle_results(
        results=results,
        target=target,
        assessment_name=assessment_name,
        json_report=json_report,
        html_report=html_report,
        pdf_report=pdf_report,
        all_reports=all_reports,
    )


# ============================================================
# URL VALIDATION
# ============================================================

def _require_url(
    target: Optional[str],
) -> str:

    if not target:

        typer.echo(
            "Error: --url <URL> is required."
        )

        raise typer.Exit(code=2)

    return target


# ============================================================
# OPENAPI / SWAGGER DISCOVERY
# ============================================================

def _discover_and_display_openapi(
    target: str,
) -> None:
    """
    Discover and parse an OpenAPI or Swagger specification
    exposed by the target API.
    """

    try:

        discovery = discover_openapi(
            target
        )

    except OpenAPIDiscoveryError as exc:

        typer.echo(
            f"Error: OpenAPI/Swagger discovery failed: {exc}"
        )

        raise typer.Exit(code=1)

    if not discovery.inventory:

        typer.echo(
            "No OpenAPI or Swagger endpoints discovered."
        )

        raise typer.Exit(code=1)

    typer.echo(
        f"\nOpenAPI/Swagger specification discovered for: {target}"
    )

    typer.echo(
        f"Endpoints discovered: {len(discovery.inventory)}\n"
    )

    typer.echo(
        f"{'METHOD':<8}"
        f"{'PATH':<45}"
        f"OPERATION ID"
    )

    typer.echo(
        "-" * 85
    )

    for endpoint in discovery.inventory:

        operation_id = (
            endpoint.operation_id
            or "-"
        )

        typer.echo(
            f"{endpoint.method:<8}"
            f"{endpoint.path:<45}"
            f"{operation_id}"
        )


# ============================================================
# DISCOVERY + ASSESSMENT
# ============================================================

def _run_selected_tests(
    target: str,
    tests,
):
    """
    Discover the remote OpenAPI specification,
    resolve endpoint targets and execute selected tests.
    """

    try:

        discovery = discover_openapi(
            target
        )

    except OpenAPIDiscoveryError as exc:

        typer.echo(
            f"Error: API discovery failed: {exc}"
        )

        raise typer.Exit(code=1)

    if not discovery.resolved_endpoints:

        typer.echo(
            "Error: No API endpoints discovered."
        )

        raise typer.Exit(code=1)

    # --------------------------------------------------------
    # AUTHENTICATION CONTEXT
    # --------------------------------------------------------

    authentication = (
        authentication_config_from_environment()
    )

    # --------------------------------------------------------
    # AUTHORIZATION CONTEXT
    # --------------------------------------------------------

    bola_context = (
        bola_context_from_environment()
    )

    bfla_context = (
        bfla_context_from_environment()
    )

    # --------------------------------------------------------
    # ENGINE
    # --------------------------------------------------------

    engine = AssessmentEngine(
        tests
    )

    results = engine.assess_endpoints(
        discovery.resolved_endpoints,
        authentication=authentication,
        bola_context=bola_context,
        bfla_context=bfla_context,
    )

    return results


# ============================================================
# COMPLETE SCAN
# ============================================================

def _run_scan(
    target: str,
):
    """
    Run all VULPHEX security tests.
    """

    all_test_classes = [
        MissingAuthenticationTest,
        AuthenticationSchemeAnalysisTest,
        BrokenObjectLevelAuthorizationTest,
        BrokenFunctionLevelAuthorizationTest,
        InputValidationTest,
        SqlInjectionTest,
        NoSqlInjectionTest,
        CommandInjectionTest,
        SensitiveDataExposureTest,
        ErrorDisclosureTest,
        RateLimitTest,
        SecurityConfigurationTest,
        ApiMisconfigurationTest,
    ]

    tests = [
        test_class()
        for test_class in all_test_classes
    ]

    return _run_selected_tests(
        target=target,
        tests=tests,
    )


# ============================================================
# REPORT GENERATION
# ============================================================

def _generate_reports(
    results,
    target: str,
    assessment_name: str,
    json_report: bool,
    html_report: bool,
    pdf_report: bool,
    all_reports: bool,
):
    """
    Generate requested output formats.
    """

    if all_reports:

        json_report = True
        html_report = True
        pdf_report = True

    if not any(
        [
            json_report,
            html_report,
            pdf_report,
        ]
    ):
        return []

    results_dir = Path(
        "results"
    )

    results_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = build_assessment_report(
        target=target,
        results=results,
    )

    generated_files = []

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    if json_report:

        json_path = (
            results_dir
            / f"{assessment_name}.json"
        )

        report.write_json(
            json_path
        )

        generated_files.append(
            json_path
        )

    # --------------------------------------------------------
    # HTML
    # --------------------------------------------------------

    if html_report:

        html_path = (
            results_dir
            / f"{assessment_name}.html"
        )

        write_html_report(
            report,
            html_path,
        )

        generated_files.append(
            html_path
        )

    # --------------------------------------------------------
    # PDF
    # --------------------------------------------------------

    if pdf_report:

        pdf_path = (
            results_dir
            / f"{assessment_name}.pdf"
        )

        write_pdf_report(
            report,
            pdf_path,
        )

        generated_files.append(
            pdf_path
        )

    return generated_files


# ============================================================
# RESULT HANDLING
# ============================================================

def _handle_results(
    results,
    target: str,
    assessment_name: str,
    json_report: bool,
    html_report: bool,
    pdf_report: bool,
    all_reports: bool,
) -> None:

    report_requested = (
        json_report
        or html_report
        or pdf_report
        or all_reports
    )

    # --------------------------------------------------------
    # REPORT MODE
    # --------------------------------------------------------

    if report_requested:

        generated_files = _generate_reports(
            results=results,
            target=target,
            assessment_name=assessment_name,
            json_report=json_report,
            html_report=html_report,
            pdf_report=pdf_report,
            all_reports=all_reports,
        )

        for file_path in generated_files:

            typer.echo(
                f"{assessment_name} "
                f"{file_path.suffix[1:].upper()} "
                f"report stored: {file_path}"
            )

        typer.echo(
            f"{assessment_name} assessment completed."
        )

        return

    # --------------------------------------------------------
    # TERMINAL OUTPUT
    # --------------------------------------------------------

    typer.echo(
        render_text_results(results),
        nl=False,
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    app()