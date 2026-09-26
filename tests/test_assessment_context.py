import json

import httpx
import pytest
from typer.testing import CliRunner

from vulphex.__main__ import app
from vulphex.authentication import AuthenticationConfig
from vulphex.auth_test import MissingAuthenticationTest
from vulphex.discovery import DiscoveryResult, Endpoint, EndpointInventory, ResolvedEndpoint
from vulphex.engine import AssessmentContext, AssessmentEngine
from vulphex.models import AssessmentResult


class ContextTest:
    test_id = "CTX-001"
    test_name = "Context Test"
    requires_authentication = True

    def __init__(self) -> None:
        self.contexts: list[AssessmentContext] = []

    def execute_context(self, context: AssessmentContext) -> AssessmentResult:
        self.contexts.append(context)
        return AssessmentResult(
            test_id=self.test_id,
            test_name=self.test_name,
            target=context.endpoint.target,
            method=context.endpoint.method,
            status="INCONCLUSIVE",
            observed_status_code=None,
            severity=None,
            reason="Context received.",
            evidence={},
            recommendation="No action.",
        )


class AnonymousTest:
    test_id = "ANON-001"
    test_name = "Anonymous Test"
    requires_authentication = False

    def __init__(self) -> None:
        self.targets: list[str] = []

    def execute(self, target: str) -> AssessmentResult:
        self.targets.append(target)
        return AssessmentResult(
            test_id=self.test_id,
            test_name=self.test_name,
            target=target,
            method="GET",
            status="INCONCLUSIVE",
            observed_status_code=None,
            severity=None,
            reason="Anonymous test.",
            evidence={},
            recommendation="No action.",
        )


def endpoint(path: str) -> ResolvedEndpoint:
    return ResolvedEndpoint(method="GET", target=f"https://example.test{path}", path=path)


def test_context_without_authentication_blocks_auth_required_test() -> None:
    test = ContextTest()

    results = AssessmentEngine([test]).assess_endpoints([endpoint("/users")])

    assert results[0].status == "AUTHENTICATION_REQUIRED"
    assert test.contexts == []


def test_explicit_bearer_context_is_received_without_secret_in_repr_or_result() -> None:
    test = ContextTest()
    authentication = AuthenticationConfig(mode="bearer", token="synthetic-token")

    results = AssessmentEngine([test]).assess_endpoints([endpoint("/users")], authentication)

    assert results[0].authentication_mode == "bearer"
    assert results[0].authentication_configured is True
    assert test.contexts[0].authentication is authentication
    assert "synthetic-token" not in repr(test.contexts[0])
    assert "synthetic-token" not in repr(authentication)
    assert "synthetic-token" not in json.dumps(results[0].to_dict())


@pytest.mark.parametrize(
    "authentication",
    [
        AuthenticationConfig(mode="api_key", api_key_name="X-API-Key", api_key_value="synthetic-key"),
        AuthenticationConfig(mode="custom_header", header_name="X-Custom-Auth", header_value="synthetic-value"),
    ],
)
def test_non_bearer_contexts_expose_only_safe_mode(authentication: AuthenticationConfig) -> None:
    test = ContextTest()

    results = AssessmentEngine([test]).assess_endpoints([endpoint("/users")], authentication)

    assert results[0].authentication_mode == authentication.mode
    assert results[0].authentication_configured is True
    serialized = repr(test.contexts[0]) + json.dumps(results[0].to_dict())
    assert all(secret not in serialized for secret in authentication.sensitive_values())


def test_non_auth_required_test_remains_anonymous_with_auth_context() -> None:
    test = AnonymousTest()

    results = AssessmentEngine([test]).assess_endpoints(
        [endpoint("/users")],
        AuthenticationConfig(mode="bearer", token="synthetic-token"),
    )

    assert results[0].status == "INCONCLUSIVE"
    assert test.targets == ["https://example.test/users"]
    assert results[0].authentication_mode == "none"
    assert results[0].authentication_configured is False


def test_auth001_remains_unauthenticated_when_context_is_supplied(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []

    def fake_get(url: str, timeout: float = 10.0):
        calls.append((url, timeout))
        return httpx.Response(401, request=httpx.Request("GET", url)), 1.0

    monkeypatch.setattr("vulphex.auth_test.get_without_authentication", fake_get)
    results = AssessmentEngine([MissingAuthenticationTest()]).assess_endpoints(
        [endpoint("/protected")],
        AuthenticationConfig(mode="bearer", token="synthetic-token"),
    )

    assert results[0].status == "AUTHENTICATION_ENFORCED"
    assert calls == [("https://example.test/protected", 10.0)]


def test_context_is_explicit_per_endpoint_and_not_mutated_between_endpoints() -> None:
    test = ContextTest()
    authentication = AuthenticationConfig(mode="bearer", token="synthetic-token")

    AssessmentEngine([test]).assess_endpoints([endpoint("/one"), endpoint("/two")], authentication)

    assert [context.endpoint.path for context in test.contexts] == ["/one", "/two"]
    assert all(context.authentication is authentication for context in test.contexts)


def test_assess_api_reads_existing_environment_configuration_without_echoing_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULPHEX_AUTH_MODE", "bearer")
    monkeypatch.setenv("VULPHEX_BEARER_TOKEN", "synthetic-token")
    monkeypatch.setattr(
        "vulphex.__main__.discover_openapi",
        lambda url: DiscoveryResult(
            target="https://example.test",
            specification_url="https://example.test/openapi.json",
            inventory=EndpointInventory(),
        ),
    )
    result = CliRunner().invoke(app, ["assess-api", "--url", "https://example.test", "--output", "json"])

    assert result.exit_code == 0
    assert "synthetic-token" not in result.stdout
