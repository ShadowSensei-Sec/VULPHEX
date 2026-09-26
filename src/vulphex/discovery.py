"""Local OpenAPI parsing and endpoint inventory models."""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator, Sequence
from copy import deepcopy
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
import yaml

from .http_client import sanitize_url, validate_url


HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
SPECIFICATION_PATHS = ("/openapi.json", "/swagger.json", "/api-docs", "/openapi.yaml", "/swagger.yaml")


class OpenAPIValidationError(ValueError):
    """Raised when a supplied document is not a supported OpenAPI document."""


class OpenAPIDiscoveryError(RuntimeError):
    """Raised when no valid OpenAPI specification can be discovered."""


@dataclass(frozen=True)
class Endpoint:
    """The operation-level information needed by future security tests."""

    path: str
    method: str
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    parameters: list[dict[str, Any]] | None = None
    request_body: dict[str, Any] | None = None
    security: list[dict[str, Any]] | None = None
    security_defined: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EndpointInventory(Sequence[Endpoint]):
    """An ordered, searchable collection of discovered endpoints."""

    def __init__(self, endpoints: Iterable[Endpoint] = ()) -> None:
        self._endpoints = tuple(endpoints)

    def __iter__(self) -> Iterator[Endpoint]:
        return iter(self._endpoints)

    def __len__(self) -> int:
        return len(self._endpoints)

    def __getitem__(self, index: int | slice) -> Endpoint | tuple[Endpoint, ...]:
        return self._endpoints[index]

    def find(self, path: str | None = None, method: str | None = None) -> list[Endpoint]:
        """Return endpoints matching the supplied path and/or HTTP method."""
        normalized_method = method.upper() if method is not None else None
        return [
            endpoint
            for endpoint in self
            if (path is None or endpoint.path == path)
            and (normalized_method is None or endpoint.method == normalized_method)
        ]

    def to_dict(self) -> list[dict[str, Any]]:
        return [endpoint.to_dict() for endpoint in self]


@dataclass(frozen=True)
class ResolvedEndpoint:
    """An endpoint operation paired with its normalized, non-requested target URL."""

    method: str
    target: str
    path: str
    operation_id: str | None = None
    summary: str | None = None
    description: str | None = None
    parameters: list[dict[str, Any]] | None = None
    request_body: dict[str, Any] | None = None
    security: list[dict[str, Any]] | None = None
    security_defined: bool = False
    global_security: list[dict[str, Any]] | None = None
    security_requirement_source: str = "none"
    security_schemes: dict[str, dict[str, Any]] | None = None

    @classmethod
    def from_endpoint(cls, endpoint: Endpoint, target: str) -> "ResolvedEndpoint":
        return cls(
            method=endpoint.method,
            target=target,
            path=endpoint.path,
            operation_id=endpoint.operation_id,
            summary=endpoint.summary,
            description=endpoint.description,
            parameters=deepcopy(endpoint.parameters),
            request_body=deepcopy(endpoint.request_body),
            security=deepcopy(endpoint.security),
            security_defined=endpoint.security_defined,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def resolve_endpoint_targets(
    base_url: str,
    inventory: EndpointInventory,
    servers: list[dict[str, Any]] | None = None,
    global_security: list[dict[str, Any]] | None = None,
    security_schemes: dict[str, dict[str, Any]] | None = None,
) -> tuple[ResolvedEndpoint, ...]:
    """Resolve an ordered endpoint inventory without substituting path parameters."""
    validate_url(base_url)
    normalized_base = _normalized_base_url(base_url)
    server_base = _select_server_base(normalized_base, servers)
    resolved: list[ResolvedEndpoint] = []
    for endpoint in inventory:
        effective_security = endpoint.security if endpoint.security_defined else global_security
        source = "operation" if endpoint.security_defined else "global" if global_security is not None else "none"
        endpoint_data = ResolvedEndpoint.from_endpoint(
            endpoint,
            _join_endpoint_url(server_base, endpoint.path),
        ).to_dict()
        endpoint_data.update(
            security=deepcopy(effective_security),
            global_security=deepcopy(global_security),
            security_requirement_source=source,
            security_schemes=deepcopy(security_schemes),
        )
        resolved.append(
            ResolvedEndpoint(**endpoint_data)
        )
    return tuple(resolved)


@dataclass(frozen=True)
class DiscoveryResult:
    """The safe, structured outcome of automatic specification discovery."""

    target: str
    specification_url: str
    inventory: EndpointInventory
    resolved_endpoints: tuple[ResolvedEndpoint, ...] = ()
    global_security: list[dict[str, Any]] | None = None
    security_schemes: dict[str, dict[str, Any]] | None = None

    @property
    def found(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "specification_url": self.specification_url,
            "endpoint_count": len(self.inventory),
            "endpoints": [endpoint.to_dict() for endpoint in self.resolved_endpoints],
        }


def discover_openapi(
    target: str,
    timeout: float = 10.0,
    client_factory: Any = httpx.Client,
) -> DiscoveryResult:
    """Find and parse the first valid OpenAPI document at common local paths."""
    validate_url(target)
    base_url = _normalized_base_url(target)
    reportable_target = sanitize_url(base_url)
    failures: list[str] = []

    try:
        with client_factory(follow_redirects=False, timeout=timeout) as client:
            for specification_url in _candidate_urls(base_url):
                try:
                    response = client.get(specification_url)
                except httpx.TimeoutException:
                    failures.append(f"{_path_for_report(specification_url)}: request timed out")
                    continue
                except httpx.RequestError:
                    failures.append(f"{_path_for_report(specification_url)}: connection failed")
                    continue

                if response.status_code < 200 or response.status_code >= 300:
                    failures.append(f"{_path_for_report(specification_url)}: HTTP {response.status_code}")
                    continue

                try:
                    document = _parse_response_document(response)
                    inventory = parse_openapi_document(document)
                except (OpenAPIValidationError, json.JSONDecodeError, yaml.YAMLError, TypeError):
                    failures.append(f"{_path_for_report(specification_url)}: invalid OpenAPI document")
                    continue

                return DiscoveryResult(
                    target=reportable_target,
                    specification_url=sanitize_url(specification_url),
                    inventory=inventory,
                    resolved_endpoints=resolve_endpoint_targets(
                        reportable_target,
                        inventory,
                        document.get("servers"),
                        document.get("security"),
                        document.get("components", {}).get("securitySchemes")
                        if isinstance(document.get("components"), dict)
                        else None,
                    ),
                    global_security=deepcopy(document.get("security")),
                    security_schemes=deepcopy(
                        document.get("components", {}).get("securitySchemes")
                        if isinstance(document.get("components"), dict)
                        else None
                    ),
                )
    except (httpx.TimeoutException, httpx.RequestError) as exc:
        raise OpenAPIDiscoveryError("Unable to access OpenAPI specification locations") from exc

    details = "; ".join(failures) if failures else "no candidates were checked"
    raise OpenAPIDiscoveryError(f"No valid OpenAPI specification found ({details})")


def _normalized_base_url(target: str) -> str:
    parsed = urlsplit(sanitize_url(target))
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def _candidate_urls(base_url: str) -> Iterator[str]:
    for specification_path in SPECIFICATION_PATHS:
        yield f"{base_url}{specification_path}"


def _path_for_report(url: str) -> str:
    return urlsplit(url).path or "/"


def _select_server_base(base_url: str, servers: list[dict[str, Any]] | None) -> str:
    if servers is None:
        return _normalized_base_url(base_url)
    if not isinstance(servers, list):
        return _normalized_base_url(base_url)

    for server in servers:
        resolved = _resolve_server(base_url, server)
        if resolved is not None:
            return resolved
    return _normalized_base_url(base_url)


def _resolve_server(base_url: str, server: Any) -> str | None:
    if not isinstance(server, dict) or not isinstance(server.get("url"), str):
        return None
    server_url = server["url"]
    if any(character.isspace() for character in server_url):
        return None
    variables = server.get("variables", {})
    if variables is None:
        variables = {}
    if not isinstance(variables, dict):
        return None

    for name, variable in variables.items():
        if not isinstance(name, str) or not isinstance(variable, dict):
            return None
        value = variable.get("default")
        if not isinstance(value, str):
            return None
        enum = variable.get("enum")
        if enum is not None and (not isinstance(enum, list) or value not in enum):
            return None
        server_url = server_url.replace("{" + name + "}", value)

    if "{" in server_url or "}" in server_url:
        return None
    try:
        candidate = urljoin(_normalized_base_url(base_url) + "/", server_url)
        validate_url(candidate)
        return _normalized_base_url(candidate)
    except ValueError:
        return None


def _join_endpoint_url(server_base: str, path: str) -> str:
    parsed = urlsplit(server_base)
    base_path = parsed.path.rstrip("/")
    endpoint_path = "/" + path.lstrip("/")
    return urlunsplit((parsed.scheme, parsed.netloc, base_path + endpoint_path, "", ""))


def _parse_response_document(response: httpx.Response) -> dict[str, Any]:
    content_type = response.headers.get("content-type", "").lower()
    if "yaml" in content_type or "yml" in content_type:
        document = yaml.safe_load(response.text)
    else:
        try:
            document = response.json()
        except (json.JSONDecodeError, ValueError):
            document = yaml.safe_load(response.text)
    if not isinstance(document, dict):
        raise OpenAPIValidationError("OpenAPI response must be a dictionary")
    return document


def parse_openapi_document(document: dict[str, Any]) -> EndpointInventory:
    """Parse a loaded OpenAPI 3 document into an ordered endpoint inventory."""
    if not isinstance(document, dict):
        raise OpenAPIValidationError("OpenAPI document must be a dictionary")

    version = document.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise OpenAPIValidationError("OpenAPI document must declare a supported 3.x version")

    paths = document.get("paths")
    if paths is None:
        raise OpenAPIValidationError("OpenAPI document is missing paths")
    if not isinstance(paths, dict):
        raise OpenAPIValidationError("OpenAPI paths must be a dictionary")

    endpoints: list[Endpoint] = []
    for path, path_item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise OpenAPIValidationError("OpenAPI path keys must be strings beginning with '/'")
        if not isinstance(path_item, dict):
            raise OpenAPIValidationError("OpenAPI path entries must be dictionaries")

        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                raise OpenAPIValidationError("OpenAPI operations must be dictionaries")
            endpoints.append(_endpoint_from_operation(path, method, operation))

    return EndpointInventory(endpoints)


def load_openapi_document(file_path: str | Path) -> dict[str, Any]:
    """Load a local JSON or YAML OpenAPI document without parsing its operations."""
    path = Path(file_path)
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise OpenAPIValidationError("Unable to read the OpenAPI document") from exc

    try:
        if path.suffix.lower() == ".json":
            document = json.loads(content)
        elif path.suffix.lower() in {".yaml", ".yml"}:
            document = yaml.safe_load(content)
        else:
            raise OpenAPIValidationError("OpenAPI document must use a .json, .yaml, or .yml extension")
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise OpenAPIValidationError("Unable to parse the OpenAPI document") from exc

    if not isinstance(document, dict):
        raise OpenAPIValidationError("Loaded OpenAPI document must be a dictionary")
    return document


def _endpoint_from_operation(path: str, method: str, operation: dict[str, Any]) -> Endpoint:
    parameters = operation.get("parameters")
    if parameters is not None and not isinstance(parameters, list):
        raise OpenAPIValidationError("OpenAPI operation parameters must be a list")

    return Endpoint(
        path=path,
        method=method.upper(),
        operation_id=_optional_string(operation, "operationId"),
        summary=_optional_string(operation, "summary"),
        description=_optional_string(operation, "description"),
        parameters=deepcopy(parameters),
        request_body=deepcopy(operation.get("requestBody")),
        security=deepcopy(operation.get("security")),
        security_defined="security" in operation,
    )


def _optional_string(operation: dict[str, Any], key: str) -> str | None:
    value = operation.get(key)
    if value is not None and not isinstance(value, str):
        raise OpenAPIValidationError(f"OpenAPI operation {key} must be a string")
    return value