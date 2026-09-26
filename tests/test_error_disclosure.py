import json

import httpx
import pytest

from vulphex.authentication import AuthenticationConfig
from vulphex.discovery import ResolvedEndpoint
from vulphex.engine import AssessmentEngine
from vulphex.error_disclosure_test import ErrorDisclosureTest

TARGET = "https://example.test/error"


def make_response(*, status_code: int = 200, json_body: object | None = None, text: str | None = None, headers: dict[str, str] | None = None) -> httpx.Response:
    request = httpx.Request("GET", TARGET)
    return httpx.Response(
        status_code,
        request=request,
        json=json_body,
        text=text if text is not None else json.dumps(json_body) if json_body is not None else "",
        headers=headers or {},
    )


def endpoint(method: str = "GET", path: str = "/error", security: list[dict[str, object]] | None = None) -> ResolvedEndpoint:
    return ResolvedEndpoint(
        method=method,
        target=f"https://example.test{path}",
        path=path,
        operation_id="error",
        security=security,
        security_defined=bool(security),
    )


def test_error_disclosure_exposes_identity() -> None:
    test = ErrorDisclosureTest()

    assert test.test_id == "INFO-001"
    assert test.test_name == "Error and Information Disclosure Detection Test"
    assert test.supported_methods == frozenset({"GET"})


def test_normal_400_validation_error_produces_no_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=400, json_body={"detail": "Invalid request parameter"}), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "NO_INFORMATION_DISCLOSURE_INDICATED"


def test_normal_401_error_produces_no_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=401, json_body={"error": "Authentication required"}), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "NO_INFORMATION_DISCLOSURE_INDICATED"


def test_normal_403_error_produces_no_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=403, json_body={"detail": "Forbidden"}), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "NO_INFORMATION_DISCLOSURE_INDICATED"


def test_normal_404_error_produces_no_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=404, json_body={"detail": "Not found"}), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "NO_INFORMATION_DISCLOSURE_INDICATED"


def test_generic_500_produces_no_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, json_body={"detail": "Internal server error"}), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "NO_INFORMATION_DISCLOSURE_INDICATED"


def test_python_traceback_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "Traceback (most recent call last):\n  File \"/app/services/users.py\", line 42, in <module>\nRuntimeError: startup failed"
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "POTENTIAL_INFORMATION_DISCLOSURE"
    assert any(item["category"] == "PYTHON_TRACEBACK" for item in result.evidence["findings"])


def test_java_stack_trace_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "java.lang.RuntimeException: Failed to load config\n    at com.example.config.ConfigLoader.load(ConfigLoader.java:45)"
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "POTENTIAL_INFORMATION_DISCLOSURE"
    assert any(item["category"] == "JAVA_STACK_TRACE" for item in result.evidence["findings"])


def test_dotnet_stack_trace_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "System.NullReferenceException: Object reference not set to an instance of an object\n at MyApp.Services.UserService.GetUser(UserService.cs:100)"
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "POTENTIAL_INFORMATION_DISCLOSURE"
    assert any(item["category"] == "DOTNET_STACK_TRACE" for item in result.evidence["findings"])


def test_node_stack_trace_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "Error: connect ECONNREFUSED 127.0.0.1:5432\n    at Server.<anonymous> (/app/server.js:42:13)"
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "POTENTIAL_INFORMATION_DISCLOSURE"
    assert any(item["category"] == "NODE_STACK_TRACE" for item in result.evidence["findings"])


def test_database_error_disclosure_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "PostgreSQL SQLSTATE[42601]: syntax error at or near \"SELECT\""
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "POTENTIAL_INFORMATION_DISCLOSURE"
    assert any(item["category"] == "DATABASE_ERROR_DISCLOSURE" for item in result.evidence["findings"])


def test_internal_filesystem_path_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "FileNotFoundError: /app/services/users.py:42 cannot open config"
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "POTENTIAL_INFORMATION_DISCLOSURE"
    assert any(item["category"] == "INTERNAL_PATH_DISCLOSURE" for item in result.evidence["findings"])


def test_private_ip_in_error_context_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "ConnectionError: db.internal.local failed at 10.0.0.14:5432 while connecting to internal postgres service"
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "POTENTIAL_INFORMATION_DISCLOSURE"
    assert any(item["category"] == "INTERNAL_NETWORK_DISCLOSURE" for item in result.evidence["findings"])


def test_internal_hostname_debug_information_is_detected(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "Debug info: host=api.internal.local; service=users-api; env=prod"
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "POTENTIAL_INFORMATION_DISCLOSURE"
    assert any(item["category"] == "INTERNAL_NETWORK_DISCLOSURE" for item in result.evidence["findings"])


def test_ordinary_error_message_fields_do_not_trigger_false_positive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=200, json_body={"error": "not found", "message": "safe detail"}), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "NO_INFORMATION_DISCLOSURE_INDICATED"


def test_raw_sensitive_error_contents_are_not_stored_in_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "Traceback (most recent call last):\n  File \"/app/services/users.py\", line 42, in <module>\nRuntimeError: startup failed"
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    evidence_dump = json.dumps(result.evidence)
    assert "startup failed" not in evidence_dump
    assert "Traceback" not in evidence_dump
    assert result.evidence["findings"][0]["indicator"] not in {"", None}


def test_response_preview_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = "A" * 200000
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text=payload), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status in {"INCONCLUSIVE", "NO_INFORMATION_DISCLOSURE_INDICATED"}
    assert "A" * 50 not in json.dumps(result.evidence)


def test_malformed_response_is_handled_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.error_disclosure_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(status_code=500, text="{not valid json"), 2.0),
    )

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status in {"NO_INFORMATION_DISCLOSURE_INDICATED", "INCONCLUSIVE"}


def test_unsupported_http_method_is_handled_correctly() -> None:
    result = ErrorDisclosureTest().execute_endpoint(endpoint(method="POST"))

    assert result.status == "UNSUPPORTED_OPERATION"


def test_authentication_required_endpoint_without_credentials_is_handled(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        return make_response(status_code=200, json_body={"ok": True}), 2.0

    monkeypatch.setattr("vulphex.error_disclosure_test.get_with_authentication", fake_get)
    result = ErrorDisclosureTest().execute_endpoint(endpoint(security=[{"bearerAuth": []}]))

    assert result.status == "NO_INFORMATION_DISCLOSURE_INDICATED"


def test_timeout_becomes_inconclusive(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("vulphex.error_disclosure_test.get_with_authentication", fail)

    result = ErrorDisclosureTest().execute(TARGET)

    assert result.status == "INCONCLUSIVE"


def test_request_count_is_exactly_one(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        calls.append("called")
        return make_response(status_code=200, json_body={"ok": True}), 2.0

    monkeypatch.setattr("vulphex.error_disclosure_test.get_with_authentication", fake_get)

    result = ErrorDisclosureTest().execute_endpoint(endpoint())

    assert calls == ["called"]
    assert result.evidence["request_count"] == 1


def test_error_disclosure_pipeline_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoints = [endpoint(path="/safe-error"), endpoint(path="/python-error")]
    auth = AuthenticationConfig(mode="bearer", token="test-token")

    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        target = args[0] if args else kwargs.get("url")
        if str(target).endswith("/safe-error"):
            return make_response(status_code=500, json_body={"detail": "Internal server error"}), 2.0
        if str(target).endswith("/python-error"):
            return make_response(
                status_code=500,
                text="Traceback (most recent call last):\n  File \"/app/services/users.py\", line 42, in <module>\nRuntimeError: startup failed",
            ), 2.0
        return make_response(status_code=404, json_body={"detail": "Not found"}), 2.0

    monkeypatch.setattr("vulphex.error_disclosure_test.get_with_authentication", fake_get)
    results = AssessmentEngine([ErrorDisclosureTest()]).assess_endpoints(endpoints, authentication=auth)

    assert [result.test_id for result in results] == ["INFO-001", "INFO-001"]
    assert [result.status for result in results] == ["NO_INFORMATION_DISCLOSURE_INDICATED", "POTENTIAL_INFORMATION_DISCLOSURE"]
