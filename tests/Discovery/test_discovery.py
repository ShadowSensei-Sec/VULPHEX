import json

import httpx
import pytest
from typer.testing import CliRunner

from vulphex.__main__ import app
from vulphex.Discovery.discovery import (
    Endpoint,
    EndpointInventory,
    OpenAPIDiscoveryError,
    OpenAPIValidationError,
    ResolvedEndpoint,
    discover_openapi,
    load_openapi_document,
    parse_openapi_document,
    resolve_endpoint_targets,
)


OPENAPI_DOCUMENT = {
    "openapi": "3.0.3",
    "info": {"title": "Synthetic API", "version": "1.0.0"},
    "paths": {
        "/users": {
            "get": {
                "operationId": "listUsers",
                "summary": "List users",
                "description": "Returns users.",
                "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
                "security": [{"bearerAuth": []}],
            },
            "post": {
                "operationId": "createUser",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {}}}},
            },
            "parameters": [{"name": "ignored", "in": "query"}],
            "summary": "Ignored path summary",
            "description": "Ignored path description",
            "servers": [{"url": "https://ignored.example"}],
            "x-vulphex-note": "ignored metadata",
        },
        "/health": {"head": {}, "trace": {}, "$ref": "#/components/path"},
    },
}


def test_parser_builds_ordered_inventory_and_extracts_operation_data() -> None:
    inventory = parse_openapi_document(OPENAPI_DOCUMENT)

    assert isinstance(inventory, EndpointInventory)
    assert [(endpoint.method, endpoint.path) for endpoint in inventory] == [
        ("GET", "/users"),
        ("POST", "/users"),
        ("HEAD", "/health"),
        ("TRACE", "/health"),
    ]
    endpoint = inventory.find(path="/users", method="get")[0]
    assert endpoint.operation_id == "listUsers"
    assert endpoint.summary == "List users"
    assert endpoint.description == "Returns users."
    assert endpoint.parameters == OPENAPI_DOCUMENT["paths"]["/users"]["get"]["parameters"]
    assert endpoint.security == [{"bearerAuth": []}]
    assert inventory.find(path="/users", method="post")[0].request_body["required"] is True
    assert inventory.to_dict()[0]["method"] == "GET"


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"openapi": "2.0", "paths": {}},
        {"openapi": "3.0.3"},
        {"openapi": "3.0.3", "paths": []},
        {"openapi": "3.0.3", "paths": {"/bad": []}},
        {"openapi": "3.0.3", "paths": {"/bad": {"get": []}}},
    ],
)
def test_parser_rejects_malformed_documents(document: dict) -> None:
    with pytest.raises(OpenAPIValidationError):
        parse_openapi_document(document)


def test_json_document_loading(tmp_path) -> None:
    document_path = tmp_path / "openapi.json"
    document_path.write_text(json.dumps(OPENAPI_DOCUMENT), encoding="utf-8")

    assert load_openapi_document(document_path) == OPENAPI_DOCUMENT


def test_yaml_document_loading(tmp_path) -> None:
    document_path = tmp_path / "openapi.yaml"
    document_path.write_text(
        "openapi: 3.0.3\ninfo:\n  title: Synthetic API\n  version: 1.0.0\npaths:\n  /public:\n    get:\n      operationId: getPublic\n",
        encoding="utf-8",
    )

    assert load_openapi_document(document_path)["paths"]["/public"]["get"]["operationId"] == "getPublic"


def test_discovery_produces_no_assessment_findings() -> None:
    inventory = parse_openapi_document(OPENAPI_DOCUMENT)

    assert not any(hasattr(endpoint, "test_id") for endpoint in inventory)


class FakeClient:
    def __init__(self, responses: dict[str, httpx.Response | Exception], calls: list[str]) -> None:
        self.responses = responses
        self.calls = calls

    def __enter__(self) -> "FakeClient":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def get(self, url: str) -> httpx.Response:
        self.calls.append(url)
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response


def response(status_code: int, body: str, content_type: str = "application/json") -> httpx.Response:
    return httpx.Response(status_code, text=body, headers={"content-type": content_type})


def make_client_factory(responses: dict[str, httpx.Response | Exception], calls: list[str]):
    return lambda **kwargs: FakeClient(responses, calls)


def test_automatic_discovery_finds_openapi_and_stops_at_first_valid_candidate() -> None:
    calls: list[str] = []
    responses = {
        "http://api.test/openapi.json": response(200, json.dumps(OPENAPI_DOCUMENT)),
        "http://api.test/swagger.json": response(200, json.dumps(OPENAPI_DOCUMENT)),
    }

    result = discover_openapi("http://api.test", client_factory=make_client_factory(responses, calls))

    assert result.found is True
    assert result.specification_url == "http://api.test/openapi.json"
    assert [(endpoint.method, endpoint.path) for endpoint in result.inventory] == [
        ("GET", "/users"),
        ("POST", "/users"),
        ("HEAD", "/health"),
        ("TRACE", "/health"),
    ]
    assert calls == ["http://api.test/openapi.json"]


def test_automatic_discovery_continues_after_404_in_deterministic_order() -> None:
    calls: list[str] = []
    responses = {
        "http://api.test/openapi.json": response(404, "not found"),
        "http://api.test/swagger.json": response(200, json.dumps(OPENAPI_DOCUMENT)),
    }

    result = discover_openapi("http://api.test", client_factory=make_client_factory(responses, calls))

    assert result.specification_url == "http://api.test/swagger.json"
    assert calls == ["http://api.test/openapi.json", "http://api.test/swagger.json"]


@pytest.mark.parametrize("failure", [httpx.ConnectError("offline"), httpx.ReadTimeout("slow")])
def test_automatic_discovery_handles_request_failures(failure: Exception) -> None:
    calls: list[str] = []
    responses = {"http://api.test/openapi.json": failure}
    for path in ("swagger.json", "api-docs", "openapi.yaml", "swagger.yaml"):
        responses[f"http://api.test/{path}"] = response(404, "not found")

    with pytest.raises(OpenAPIDiscoveryError, match="No valid OpenAPI specification found"):
        discover_openapi("http://api.test", client_factory=make_client_factory(responses, calls))
    assert calls == [
        "http://api.test/openapi.json",
        "http://api.test/swagger.json",
        "http://api.test/api-docs",
        "http://api.test/openapi.yaml",
        "http://api.test/swagger.yaml",
    ]


def test_automatic_discovery_rejects_invalid_and_non_openapi_content() -> None:
    calls: list[str] = []
    responses = {
        "http://api.test/openapi.json": response(200, "{not-json"),
        "http://api.test/swagger.json": response(200, json.dumps({"message": "not an API spec"})),
        "http://api.test/api-docs": response(200, "openapi: 3.0.3\npaths: {}", "text/yaml"),
    }

    result = discover_openapi("http://api.test", client_factory=make_client_factory(responses, calls))

    assert result.specification_url == "http://api.test/api-docs"
    assert len(result.inventory) == 0
    assert calls == [
        "http://api.test/openapi.json",
        "http://api.test/swagger.json",
        "http://api.test/api-docs",
    ]


def test_discovery_sanitizes_target_and_specification_urls() -> None:
    calls: list[str] = []
    responses = {
        "https://api.test:8443/api/openapi.json": response(200, json.dumps(OPENAPI_DOCUMENT)),
    }

    result = discover_openapi(
        "https://user:secret@api.test:8443/api?token=private#fragment",
        client_factory=make_client_factory(responses, calls),
    )

    assert result.target == "https://api.test:8443/api"
    assert result.specification_url == "https://api.test:8443/api/openapi.json"
    assert "secret" not in result.target
    assert "token" not in result.target
    assert calls == ["https://api.test:8443/api/openapi.json"]


def test_discover_cli_json_output_is_machine_readable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.__main__.discover_openapi",
        lambda url: discover_result(),
    )

    result = CliRunner().invoke(app, ["discover", "--url", "http://api.test", "--output", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["endpoint_count"] == 4
    assert payload["specification_url"] == "http://api.test/openapi.json"
    assert "/users" in [endpoint["path"] for endpoint in payload["endpoints"]]


def test_discover_cli_text_output_lists_count_and_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("vulphex.__main__.discover_openapi", lambda url: discover_result())

    result = CliRunner().invoke(app, ["discover", "--url", "http://api.test"])

    assert result.exit_code == 0
    assert "Endpoints discovered: 4" in result.stdout
    assert "GET     /users" in result.stdout
    assert "POST    /users" in result.stdout


def discover_result():
    inventory = parse_openapi_document(OPENAPI_DOCUMENT)
    return type(
        "Result",
        (),
        {
            "target": "http://api.test",
            "specification_url": "http://api.test/openapi.json",
            "inventory": inventory,
            "resolved_endpoints": tuple(
                ResolvedEndpoint.from_endpoint(endpoint, f"http://api.test{endpoint.path}")
                for endpoint in inventory
            ),
            "to_dict": lambda self: {
                "target": self.target,
                "specification_url": self.specification_url,
                "endpoint_count": len(self.inventory),
                "endpoints": self.inventory.to_dict(),
            },
        },
    )()


def make_inventory(*paths: tuple[str, str]) -> EndpointInventory:
    return EndpointInventory(Endpoint(path=path, method=method) for method, path in paths)


def test_resolves_base_url_paths_and_preserves_method_order() -> None:
    inventory = make_inventory(("GET", "/users"), ("POST", "/users"), ("GET", "/api/accounts"))

    resolved = resolve_endpoint_targets("https://example.com/", inventory)

    assert [(endpoint.method, endpoint.target) for endpoint in resolved] == [
        ("GET", "https://example.com/users"),
        ("POST", "https://example.com/users"),
        ("GET", "https://example.com/api/accounts"),
    ]


def test_preserves_path_parameters_and_query_metadata_without_inventing_values() -> None:
    inventory = EndpointInventory(
        [
            Endpoint(
                path="/users/{id}",
                method="GET",
                parameters=[{"name": "limit", "in": "query"}],
            ),
            Endpoint(path="/accounts/{accountId}/transactions/{transactionId}", method="GET"),
        ]
    )

    resolved = resolve_endpoint_targets("https://example.com?token=secret#fragment", inventory)

    assert [endpoint.target for endpoint in resolved] == [
        "https://example.com/users/{id}",
        "https://example.com/accounts/{accountId}/transactions/{transactionId}",
    ]
    assert resolved[0].parameters == [{"name": "limit", "in": "query"}]
    assert "secret" not in resolved[0].target


def test_selects_first_valid_absolute_server() -> None:
    inventory = make_inventory(("GET", "/users"))
    servers = [
        {"url": "https://api.example.com/v1"},
        {"url": "https://other.example.com/v2"},
    ]

    resolved = resolve_endpoint_targets("https://example.com", inventory, servers)

    assert resolved[0].target == "https://api.example.com/v1/users"


def test_resolves_relative_server_and_server_variable_default() -> None:
    inventory = make_inventory(("GET", "/users"))

    relative = resolve_endpoint_targets("https://example.com", inventory, [{"url": "/v1"}])
    variable = resolve_endpoint_targets(
        "https://example.com",
        inventory,
        [{"url": "https://{region}.example.com/{version}", "variables": {
            "region": {"default": "api"},
            "version": {"default": "v2"},
        }}],
    )

    assert relative[0].target == "https://example.com/v1/users"
    assert variable[0].target == "https://api.example.com/v2/users"


def test_skips_invalid_or_unresolved_servers_and_falls_back_to_base() -> None:
    inventory = make_inventory(("GET", "/users"))
    servers = [
        {"url": "https://bad.example/{missing}", "variables": {"missing": {}}},
        {"url": "not a URL"},
        {"url": "https://valid.example/v1"},
    ]

    resolved = resolve_endpoint_targets("https://example.com", inventory, servers)

    assert resolved[0].target == "https://valid.example/v1/users"


def test_falls_back_when_all_servers_are_invalid_and_handles_empty_inventory() -> None:
    assert resolve_endpoint_targets("https://example.com/", EndpointInventory(), [{"url": "//"}]) == ()
    resolved = resolve_endpoint_targets("https://example.com", make_inventory(("GET", "/users")), [{"url": "//"}])

    assert resolved[0].target == "https://example.com/users"


@pytest.mark.parametrize("base_url", ["ftp://example.com", "example.com", "https://"])
def test_rejects_invalid_base_url(base_url: str) -> None:
    with pytest.raises(ValueError):
        resolve_endpoint_targets(base_url, EndpointInventory())