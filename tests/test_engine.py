import json

import pytest
from typer.testing import CliRunner

from vulphex.__main__ import app
from vulphex.discovery import DiscoveryResult, Endpoint, EndpointInventory, OpenAPIDiscoveryError, ResolvedEndpoint
from vulphex.engine import AssessmentEngine
from vulphex.models import AssessmentResult


def make_result(test_id: str, target: str) -> AssessmentResult:
    return AssessmentResult(
        test_id=test_id,
        test_name=f"Test {test_id}",
        target=target,
        method="GET",
        status="INCONCLUSIVE",
        observed_status_code=None,
        severity=None,
        reason="Controlled test result.",
        evidence={},
        recommendation="Review the result.",
    )


class FakeTest:
    def __init__(self, test_id: str, calls: list[str]) -> None:
        self.test_id = test_id
        self.test_name = f"Test {test_id}"
        self.calls = calls

    def execute(self, target: str) -> AssessmentResult:
        self.calls.append(f"{self.test_id}:{target}")
        return make_result(self.test_id, target)


class FailingTest:
    test_id = "FAIL-001"
    test_name = "Failing Test"

    def execute(self, target: str) -> AssessmentResult:
        raise RuntimeError("secret-token must not be exposed")


class MethodAwareTest(FakeTest):
    supported_methods = frozenset({"GET"})


def test_engine_executes_test_with_target_and_collects_result() -> None:
    calls: list[str] = []
    target = "http://authorized.example.test/resource"

    results = AssessmentEngine([FakeTest("TEST-001", calls)]).assess(target)

    assert calls == [f"TEST-001:{target}"]
    assert [result.test_id for result in results] == ["TEST-001"]


def test_engine_preserves_deterministic_test_order() -> None:
    calls: list[str] = []
    tests = [FakeTest("TEST-001", calls), FakeTest("TEST-002", calls)]

    results = AssessmentEngine(tests).assess("http://authorized.example.test/resource")

    assert [result.test_id for result in results] == ["TEST-001", "TEST-002"]
    assert [call.split(":", 1)[0] for call in calls] == ["TEST-001", "TEST-002"]


def test_engine_turns_test_failure_into_safe_explicit_result() -> None:
    results = AssessmentEngine([FailingTest()]).assess(
        "https://user:password@example.test/resource?token=secret"
    )

    assert results[0].status == "TEST_EXECUTION_ERROR"
    assert results[0].target == "https://example.test/resource"
    assert "secret" not in results[0].reason
    assert results[0].evidence == {"error": "unexpected_test_execution_error"}


def test_assess_cli_runs_authentication_test_in_json_mode() -> None:
    result = CliRunner().invoke(
        app,
        ["assess", "--url", "http://127.0.0.1:8000/public", "--output", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert len(payload) == 1
    assert payload[0]["test_id"] == "AUTH-001"


def resolved_endpoint(method: str, path: str, operation_id: str) -> ResolvedEndpoint:
    endpoint = Endpoint(path=path, method=method, operation_id=operation_id, security=[{"bearerAuth": []}])
    return ResolvedEndpoint.from_endpoint(endpoint, f"https://example.test{path}")


def test_assess_endpoints_preserves_endpoint_and_test_order_and_context() -> None:
    calls: list[str] = []
    endpoints = [
        resolved_endpoint("GET", "/first", "firstOperation"),
        resolved_endpoint("GET", "/second", "secondOperation"),
    ]

    results = AssessmentEngine([MethodAwareTest("TEST-001", calls)]).assess_endpoints(endpoints)

    assert calls == ["TEST-001:https://example.test/first", "TEST-001:https://example.test/second"]
    assert [(result.endpoint_path, result.operation_id) for result in results] == [
        ("/first", "firstOperation"),
        ("/second", "secondOperation"),
    ]
    assert all(result.security == [{"bearerAuth": []}] for result in results)


def test_assess_endpoints_does_not_run_get_only_test_on_post() -> None:
    calls: list[str] = []
    endpoints = [resolved_endpoint("GET", "/users", "getUsers"), resolved_endpoint("POST", "/users", "createUser")]

    results = AssessmentEngine([MethodAwareTest("TEST-001", calls)]).assess_endpoints(endpoints)

    assert calls == ["TEST-001:https://example.test/users"]
    assert [result.status for result in results] == ["INCONCLUSIVE", "NOT_APPLICABLE"]
    assert results[1].method == "POST"


def test_assess_endpoints_continues_after_test_exception() -> None:
    endpoints = [resolved_endpoint("GET", "/first", "first"), resolved_endpoint("GET", "/second", "second")]

    results = AssessmentEngine([FailingTest()]).assess_endpoints(endpoints)

    assert [result.status for result in results] == ["TEST_EXECUTION_ERROR", "TEST_EXECUTION_ERROR"]
    assert [result.endpoint_path for result in results] == ["/first", "/second"]


def test_assess_endpoints_handles_empty_inventory() -> None:
    assert AssessmentEngine([MethodAwareTest("TEST-001", [])]).assess_endpoints(EndpointInventory()) == []


def test_assess_api_cli_renders_discovered_context_in_json(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint = resolved_endpoint("GET", "/users", "listUsers")
    discovery = DiscoveryResult(
        target="https://example.test",
        specification_url="https://example.test/openapi.json",
        inventory=EndpointInventory([Endpoint(path="/users", method="GET", operation_id="listUsers")]),
        resolved_endpoints=(endpoint,),
    )
    monkeypatch.setattr("vulphex.__main__.discover_openapi", lambda url: discovery)
    monkeypatch.setattr("vulphex.__main__.MissingAuthenticationTest", lambda: MethodAwareTest("AUTH-001", []))

    result = CliRunner().invoke(app, ["assess-api", "--url", "https://example.test", "--output", "json"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload[0]["endpoint_path"] == "/users"
    assert payload[0]["operation_id"] == "listUsers"


def test_assess_api_cli_reports_sanitized_discovery_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.__main__.discover_openapi",
        lambda url: (_ for _ in ()).throw(OpenAPIDiscoveryError("discovery failed")),
    )

    result = CliRunner().invoke(
        app,
        ["assess-api", "--url", "https://user:secret@example.test/api?token=private", "--output", "json"],
    )

    assert result.exit_code == 0
    assert "secret" not in result.stdout
    assert "token" not in result.stdout