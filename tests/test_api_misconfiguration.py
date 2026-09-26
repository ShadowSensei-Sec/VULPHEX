import json

import httpx
import pytest

from vulphex.api_misconfiguration_test import ApiMisconfigurationTest
from vulphex.authentication import AuthenticationConfig
from vulphex.discovery import ResolvedEndpoint
from vulphex.engine import AssessmentEngine


def endpoint(
    path: str = "/resource",
    method: str = "GET",
    security: list[dict[str, object]] | None = None,
    *,
    security_defined: bool = False,
    global_security: list[dict[str, object]] | None = None,
) -> ResolvedEndpoint:
    return ResolvedEndpoint(
        method=method,
        target=f"https://example.test{path}",
        path=path,
        operation_id="resource",
        security=security,
        security_defined=security_defined,
        global_security=global_security,
    )


def response(status_code: int = 200, headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("GET", "https://example.test/misconfig")
    return httpx.Response(status_code, request=request, json={"status": "ok"}, headers=headers or {})


def test_trace_exposure_detection_from_metadata() -> None:
    result = ApiMisconfigurationTest().execute_endpoint(endpoint(method="TRACE"))

    assert result.status == "POTENTIAL_API_MISCONFIGURATION"
    assert "TRACE" in result.reason


def test_connect_exposure_detection_from_metadata() -> None:
    result = ApiMisconfigurationTest().execute_endpoint(endpoint(method="CONNECT"))

    assert result.status == "POTENTIAL_API_MISCONFIGURATION"
    assert "CONNECT" in result.reason


def test_normal_rest_methods_do_not_create_method_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.api_misconfiguration_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Content-Type": "application/json"}), 1.0),
    )
    for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
        result = ApiMisconfigurationTest().execute_endpoint(endpoint(method=method))
        assert result.status in {"NO_API_MISCONFIGURATION_INDICATED", "AUTHENTICATION_REQUIRED"}


def test_debug_header_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(*args: object, **kwargs: object):
        return response(headers={"X-Debug": "true", "X-Debug-Token": "synthetic-debug-token"}), 1.0

    monkeypatch.setattr("vulphex.api_misconfiguration_test.get_with_authentication", fake_get)

    result = ApiMisconfigurationTest().execute("https://example.test/misconfig-debug")

    assert result.status == "POTENTIAL_API_MISCONFIGURATION"
    assert "X-Debug" in result.reason or "debug" in result.reason.lower()


def test_normal_headers_do_not_produce_debug_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.api_misconfiguration_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Content-Type": "application/json"}), 1.0),
    )

    result = ApiMisconfigurationTest().execute("https://example.test/misconfig-normal")

    assert result.status == "NO_API_MISCONFIGURATION_INDICATED"


def test_development_debug_endpoint_metadata_observation() -> None:
    result = ApiMisconfigurationTest().execute_endpoint(endpoint(path="/debug"))

    assert result.status == "POTENTIAL_API_MISCONFIGURATION"
    assert "/debug" in result.reason


def test_global_security_with_operation_security_empty_is_detected() -> None:
    result = ApiMisconfigurationTest().execute_endpoint(
        endpoint(
            path="/public",
            security=[],
            security_defined=True,
            global_security=[{"bearerAuth": []}],
        )
    )

    assert result.status == "SECURITY_CONFIGURATION_EXCEPTION"
    assert result.evidence["global_security_state"]


def test_normal_security_inheritance_does_not_create_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.api_misconfiguration_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Content-Type": "application/json"}), 1.0),
    )
    result = ApiMisconfigurationTest().execute_endpoint(
        endpoint(
            path="/secure",
            security=[{"bearerAuth": []}],
            security_defined=False,
            global_security=[{"bearerAuth": []}],
        )
    )

    assert result.status == "NO_API_MISCONFIGURATION_INDICATED"


def test_server_version_information_is_informational_and_not_duplication(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.api_misconfiguration_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Server": "ExampleServer/1.2.3", "X-Powered-By": "Framework/2.0"}), 1.0),
    )

    result = ApiMisconfigurationTest().execute("https://example.test/server")

    assert result.status == "INFORMATIONAL_CONFIGURATION_OBSERVED"
    assert "Server" in result.evidence["headers"] or "server" in result.evidence["headers"]


def test_normal_json_content_type_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.api_misconfiguration_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Content-Type": "application/json; charset=utf-8"}), 1.0),
    )

    result = ApiMisconfigurationTest().execute("https://example.test/api")

    assert result.status == "NO_API_MISCONFIGURATION_INDICATED"


def test_inconsistent_content_type_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.api_misconfiguration_test.get_with_authentication",
        lambda *args, **kwargs: (response(headers={"Content-Type": "text/html; charset=utf-8"}), 1.0),
    )

    result = ApiMisconfigurationTest().execute("https://example.test/misconfig-content-type")

    assert result.status == "POTENTIAL_API_MISCONFIGURATION"
    assert "Content-Type" in result.reason or "HTML" in result.reason.upper()


def test_authentication_required_endpoint_without_credentials() -> None:
    endpoint_with_auth = endpoint(
        path="/secure",
        security=[{"bearerAuth": []}],
        security_defined=True,
    )

    result = ApiMisconfigurationTest().execute_endpoint(endpoint_with_auth)

    assert result.status == "AUTHENTICATION_REQUIRED"
    assert result.evidence["request_count"] == 0


def test_unsupported_method_handling() -> None:
    result = ApiMisconfigurationTest().execute_endpoint(endpoint(method="PATCH", security=[], security_defined=True))

    assert result.status == "NO_API_MISCONFIGURATION_INDICATED"


def test_unresolved_path_parameter_handling() -> None:
    result = ApiMisconfigurationTest().execute_endpoint(endpoint(path="/users/{user_id}"))

    assert result.status == "INVALID_TEST_CONFIGURATION"


def test_timeout_transport_failure_becomes_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object):
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("vulphex.api_misconfiguration_test.get_with_authentication", fail)

    result = ApiMisconfigurationTest().execute("https://example.test/slow")

    assert result.status == "INCONCLUSIVE"


def test_credentials_are_absent_from_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.api_misconfiguration_test.get_with_authentication",
        lambda *args, **kwargs: (
            response(headers={"Authorization": "Bearer secret-token", "X-Debug": "true"}),
            1.0,
        ),
    )

    result = ApiMisconfigurationTest().execute("https://example.test/secret")
    dump = json.dumps(result.evidence)

    assert "Authorization" not in dump
    assert "secret-token" not in dump


def test_one_request_per_get_endpoint_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_get(*args: object, **kwargs: object):
        calls.append(True)
        return response(headers={"Content-Type": "application/json"}), 1.0

    monkeypatch.setattr("vulphex.api_misconfiguration_test.get_with_authentication", fake_get)

    result = ApiMisconfigurationTest().execute("https://example.test/api")

    assert result.evidence["request_count"] == 1
    assert len(calls) == 1


def test_deterministic_result_ordering() -> None:
    endpoints = (
        endpoint(path="/debug"),
        endpoint(path="/normal", method="GET"),
        endpoint(path="/users", method="POST"),
    )

    results = AssessmentEngine([ApiMisconfigurationTest()]).assess_endpoints(endpoints)

    assert [result.endpoint_path for result in results] == ["/debug", "/normal", "/users"]


def test_no_destructive_http_methods_are_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = []

    def fake_get(url: str, authentication: AuthenticationConfig, *args: object, **kwargs: object):
        seen.append(url)
        return response(headers={"Content-Type": "application/json"}), 1.0

    monkeypatch.setattr("vulphex.api_misconfiguration_test.get_with_authentication", fake_get)
    ApiMisconfigurationTest().execute("https://example.test/no-delete")

    assert seen == ["https://example.test/no-delete"]
