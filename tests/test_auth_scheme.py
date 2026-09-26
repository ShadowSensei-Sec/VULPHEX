import json

import httpx
import pytest
from typer.testing import CliRunner

from vulphex.__main__ import app
from vulphex.auth_scheme_test import AuthenticationSchemeAnalysisTest
from vulphex.discovery import EndpointInventory, parse_openapi_document, resolve_endpoint_targets
from vulphex.engine import AssessmentEngine


def make_document(operation: dict, security: list[dict] | None = None, schemes: dict | None = None) -> dict:
    document = {
        "openapi": "3.0.3",
        "info": {"title": "Synthetic", "version": "1.0"},
        "paths": {"/users": {"get": operation}},
    }
    if security is not None:
        document["security"] = security
    if schemes is not None:
        document["components"] = {"securitySchemes": schemes}
    return document


def resolve(document: dict):
    inventory = parse_openapi_document(document)
    return resolve_endpoint_targets(
        "https://example.test",
        inventory,
        global_security=document.get("security"),
        security_schemes=document.get("components", {}).get("securitySchemes"),
    )[0]


def test_no_global_or_operation_security_is_factual_public_configuration() -> None:
    endpoint = resolve(make_document({"operationId": "listUsers"}))

    result = AuthenticationSchemeAnalysisTest().execute_endpoint(endpoint)

    assert result.status == "NO_AUTHENTICATION_DECLARED"
    assert result.evidence["authentication_declared"] is False
    assert result.evidence["security_requirement_source"] == "none"


def test_global_security_is_inherited_when_operation_security_is_absent() -> None:
    document = make_document(
        {"operationId": "listUsers"},
        security=[{"bearerAuth": []}],
        schemes={"bearerAuth": {"type": "http", "scheme": "bearer"}},
    )

    result = AuthenticationSchemeAnalysisTest().execute_endpoint(resolve(document))

    assert result.status == "AUTHENTICATION_DECLARED"
    assert result.evidence["security_requirement_source"] == "global"
    assert result.evidence["security_requirements"] == [["bearerAuth"]]
    assert result.evidence["security_schemes"] == {"bearerAuth": {"type": "http", "scheme": "bearer"}}


def test_operation_security_overrides_global_security() -> None:
    document = make_document(
        {"operationId": "listUsers", "security": [{"apiKeyAuth": []}]},
        security=[{"bearerAuth": []}],
        schemes={
            "bearerAuth": {"type": "http", "scheme": "bearer"},
            "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        },
    )

    result = AuthenticationSchemeAnalysisTest().execute_endpoint(resolve(document))

    assert result.evidence["security_requirement_source"] == "operation"
    assert result.evidence["security_requirements"] == [["apiKeyAuth"]]
    assert "bearerAuth" not in result.evidence["security_schemes"]


def test_empty_operation_security_explicitly_disables_global_security() -> None:
    document = make_document(
        {"operationId": "publicUsers", "security": []},
        security=[{"bearerAuth": []}],
        schemes={"bearerAuth": {"type": "http", "scheme": "bearer"}},
    )

    result = AuthenticationSchemeAnalysisTest().execute_endpoint(resolve(document))

    assert result.status == "NO_AUTHENTICATION_DECLARED"
    assert result.evidence["security_requirement_source"] == "operation"
    assert result.evidence["security_requirements"] == []


def test_security_alternatives_and_combined_requirements_are_preserved() -> None:
    document = make_document(
        {
            "security": [
                {"bearerAuth": []},
                {"apiKeyAuth": []},
                {"bearerAuth": [], "apiKeyAuth": []},
            ]
        },
        schemes={
            "bearerAuth": {"type": "http", "scheme": "bearer"},
            "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
        },
    )

    result = AuthenticationSchemeAnalysisTest().execute_endpoint(resolve(document))

    assert result.evidence["security_requirements"] == [
        ["bearerAuth"],
        ["apiKeyAuth"],
        ["bearerAuth", "apiKeyAuth"],
    ]


@pytest.mark.parametrize(
    ("scheme", "expected"),
    [
        ({"type": "http", "scheme": "basic"}, {"type": "http", "scheme": "basic"}),
        ({"type": "http", "scheme": "digest"}, {"type": "http", "scheme": "digest"}),
        ({"type": "apiKey", "in": "header", "name": "X-API-Key"}, {"type": "apiKey", "in": "header", "name": "X-API-Key"}),
        ({"type": "apiKey", "in": "query", "name": "api_key"}, {"type": "apiKey", "in": "query", "name": "api_key"}),
        ({"type": "oauth2", "flows": {"authorizationCode": {}, "clientCredentials": {}}}, {"type": "oauth2", "flows": ["authorizationCode", "clientCredentials"]}),
        ({"type": "openIdConnect", "openIdConnectUrl": "https://issuer.example/.well-known/openid-configuration"}, {"type": "openIdConnect", "openIdConnectUrl": "https://issuer.example/.well-known/openid-configuration"}),
    ],
)
def test_supported_security_scheme_metadata_is_safe(scheme: dict, expected: dict) -> None:
    name = "scheme"
    result = AuthenticationSchemeAnalysisTest().execute_endpoint(
        resolve(make_document({"security": [{name: []}]}, schemes={name: scheme}))
    )

    assert result.status == "AUTHENTICATION_DECLARED"
    assert result.evidence["security_schemes"][name] == expected


def test_missing_security_scheme_reference_is_configuration_inconsistency() -> None:
    result = AuthenticationSchemeAnalysisTest().execute_endpoint(
        resolve(make_document({"security": [{"missingScheme": []}]}))
    )

    assert result.status == "AUTHENTICATION_CONFIGURATION_INCONSISTENT"
    assert "missingScheme" in result.reason


def test_auth002_does_not_make_network_requests(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args, **kwargs):
        raise AssertionError("AUTH-002 must not make network requests")

    monkeypatch.setattr(httpx, "get", fail)
    monkeypatch.setattr(httpx, "Client", fail)
    result = AuthenticationSchemeAnalysisTest().execute_endpoint(
        resolve(make_document({"security": [{"bearerAuth": []}]}, schemes={"bearerAuth": {"type": "http", "scheme": "bearer"}}))
    )

    assert result.status == "AUTHENTICATION_DECLARED"


def test_engine_runs_auth001_then_auth002_for_each_endpoint() -> None:
    document = {
        "openapi": "3.0.3",
        "info": {"title": "Synthetic", "version": "1.0"},
        "security": [{"bearerAuth": []}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "paths": {"/users": {"get": {}, "post": {}}},
    }
    endpoints = resolve_endpoint_targets(
        "https://example.test",
        parse_openapi_document(document),
        global_security=document["security"],
        security_schemes=document["components"]["securitySchemes"],
    )

    class StubAuth001:
        test_id = "AUTH-001"
        test_name = "Missing Authentication Test"
        supported_methods = frozenset({"GET"})

        def execute(self, target: str):
            from vulphex.models import AssessmentResult

            return AssessmentResult("AUTH-001", self.test_name, target, "GET", "INCONCLUSIVE", None, None, "test", {}, "review")

    results = AssessmentEngine([StubAuth001(), AuthenticationSchemeAnalysisTest()]).assess_endpoints(endpoints)

    assert [result.test_id for result in results] == ["AUTH-001", "AUTH-002", "AUTH-001", "AUTH-002"]
    assert results[1].status == "AUTHENTICATION_DECLARED"
    assert results[2].status == "NOT_APPLICABLE"
    assert results[3].status == "AUTHENTICATION_DECLARED"


def test_auth002_json_cli_output_is_machine_readable(monkeypatch: pytest.MonkeyPatch) -> None:
    from vulphex.discovery import DiscoveryResult, Endpoint

    document = make_document({"security": [{"bearerAuth": []}]}, schemes={"bearerAuth": {"type": "http", "scheme": "bearer"}})
    endpoint = resolve(document)
    discovery = DiscoveryResult(
        target="https://example.test",
        specification_url="https://example.test/openapi.json",
        inventory=EndpointInventory([Endpoint(path="/users", method="GET", security=[{"bearerAuth": []}], security_defined=True)]),
        resolved_endpoints=(endpoint,),
    )
    monkeypatch.setattr("vulphex.__main__.discover_openapi", lambda url: discovery)
    for key in (
        "VULPHEX_BOLA_IDENTITY_A_AUTH_MODE",
        "VULPHEX_BOLA_IDENTITY_B_AUTH_MODE",
        "VULPHEX_BOLA_OBJECT_REFERENCE",
        "VULPHEX_BOLA_PARAMETER",
        "VULPHEX_BFLA_PRIVILEGED_AUTH_MODE",
        "VULPHEX_BFLA_LOW_AUTH_MODE",
        "VULPHEX_BFLA_PATH",
        "VULPHEX_BFLA_METHOD",
    ):
        monkeypatch.delenv(key, raising=False)
    result = CliRunner().invoke(app, ["assess-api", "--url", "https://example.test", "--output", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert [item["test_id"] for item in payload] == ["AUTH-001", "AUTH-002", "AUTHZ-001", "AUTHZ-002", "INPUT-001", "INJ-001", "INJ-002", "INJ-003", "DATA-001", "INFO-001", "CONFIG-001", "CONFIG-002", "CONFIG-003"]
    assert payload[1]["status"] == "AUTHENTICATION_DECLARED"
    assert payload[2]["status"] == "AUTHENTICATION_REQUIRED"
    assert payload[3]["status"] == "AUTHENTICATION_REQUIRED"
    assert payload[4]["status"] == "NOT_APPLICABLE"
    assert payload[5]["status"] == "NOT_APPLICABLE"
    assert payload[6]["status"] == "AUTHENTICATION_REQUIRED"
    assert payload[7]["status"] == "AUTHENTICATION_REQUIRED"
    assert payload[8]["status"] == "NO_SENSITIVE_DATA_EXPOSURE_INDICATED"
    assert payload[9]["status"] == "NO_INFORMATION_DISCLOSURE_INDICATED"
    assert payload[10]["status"] == "AUTHENTICATION_REQUIRED"
    assert payload[11]["status"] == "AUTHENTICATION_REQUIRED"
