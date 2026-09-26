import json

import httpx
import pytest

from vulphex.discovery import Endpoint, ResolvedEndpoint
from vulphex.engine import AssessmentEngine
from vulphex.models import AssessmentResult
from vulphex.sensitive_data_test import SensitiveDataExposureTest


TARGET = "https://example.test/profile"


def make_response(
    *,
    status_code: int = 200,
    json_body: object | None = None,
    text: str | None = None,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    request = httpx.Request("GET", TARGET)
    return httpx.Response(
        status_code,
        request=request,
        json=json_body,
        text=text if text is not None else json.dumps(json_body) if json_body is not None else "",
        headers=headers or {},
    )


def endpoint(method: str = "GET", path: str = "/profile", security: list[dict[str, object]] | None = None) -> ResolvedEndpoint:
    return ResolvedEndpoint(
        method=method,
        target=f"https://example.test{path}",
        path=path,
        operation_id="profile",
        security=security,
        security_defined=bool(security),
    )


def test_sensitive_data_test_exposes_identity() -> None:
    test = SensitiveDataExposureTest()

    assert test.test_id == "DATA-001"
    assert test.test_name == "Sensitive Data Exposure Detection Test"
    assert test.supported_methods == frozenset({"GET"})


def test_sensitive_data_safe_json_response_produces_no_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        return make_response(json_body={"id": 1001, "username": "vulphex-test", "email": "tester@example.test"}), 12.3

    monkeypatch.setattr("vulphex.sensitive_data_test.get_with_authentication", fake_get)

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "NO_SENSITIVE_DATA_EXPOSURE_INDICATED"
    assert result.severity is None
    assert result.evidence["detected_category"] is None


def test_sensitive_data_detects_password_exposure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(json_body={"username": "alice", "password": "secret123"}), 5.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "POTENTIAL_SENSITIVE_DATA_EXPOSURE"
    assert result.evidence["findings"][0]["category"] == "authentication_secret"
    assert "password" in result.evidence["findings"][0]["field_name"]
    assert "secret123" not in json.dumps(result.evidence)


def test_sensitive_data_detects_api_key_exposure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(json_body={"api_key": "synthetic-api-key"}), 5.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "POTENTIAL_SENSITIVE_DATA_EXPOSURE"
    assert result.evidence["findings"][0]["category"] == "api_token"
    assert result.evidence["findings"][0]["path"] == "api_key"


def test_sensitive_data_detects_session_token_exposure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(json_body={"session_token": "synthetic-session-token"}), 5.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "POTENTIAL_SENSITIVE_DATA_EXPOSURE"
    assert result.evidence["findings"][0]["category"] == "session_credential"


def test_sensitive_data_detects_nested_private_key(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"user": {"profile": {"credentials": {"private_key": "-----BEGIN TEST PRIVATE KEY-----\nsecret\n-----END TEST PRIVATE KEY-----"}}}}
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(json_body=payload), 4.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "POTENTIAL_SENSITIVE_DATA_EXPOSURE"
    assert any(finding["path"] == "user.profile.credentials.private_key" for finding in result.evidence["findings"])


def test_sensitive_data_detects_database_connection_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(json_body={"database_url": "postgres://user:secret@example.test/app"}), 4.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "POTENTIAL_SENSITIVE_DATA_EXPOSURE"
    assert any(finding["category"] == "database_credential" for finding in result.evidence["findings"])


def test_sensitive_data_detects_obvious_jwt_bearer_pattern(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(text=f"Authorization: Bearer {token}"), 3.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "POTENTIAL_SENSITIVE_DATA_EXPOSURE"
    assert result.evidence["findings"][0]["category"] in {"api_token", "bearer_token"}
    assert token not in json.dumps(result.evidence)


def test_sensitive_data_ignores_ordinary_profile_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(json_body={"id": 1, "email": "tester@example.test", "username": "alice", "name": "Alice", "created_at": "2025-01-01"}), 2.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "NO_SENSITIVE_DATA_EXPOSURE_INDICATED"


def test_sensitive_data_does_not_flag_generic_long_string(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"note": "x" * 120, "tokenized_value": "a" * 128}
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(json_body=payload), 2.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "NO_SENSITIVE_DATA_EXPOSURE_INDICATED"
    assert result.evidence["findings"] == []


def test_sensitive_data_evidence_is_redacted_and_paths_are_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"user": {"credentials": {"password": "synthetic-secret"}}}
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(json_body=payload), 2.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    evidence_json = json.dumps(result.evidence)
    assert "synthetic-secret" not in evidence_json
    assert result.evidence["findings"][0]["path"] == "user.credentials.password"
    assert result.evidence["findings"][0]["redacted"] is True


def test_sensitive_data_handles_large_response_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    large_value = "A" * 200000
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(json_body={"message": large_value}), 1.0, ),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status in {"INCONCLUSIVE", "NO_SENSITIVE_DATA_EXPOSURE_INDICATED"}
    assert "message" not in json.dumps(result.evidence)


def test_sensitive_data_handles_unsupported_methods() -> None:
    result = SensitiveDataExposureTest().execute_endpoint(endpoint(method="POST"))

    assert result.status == "UNSUPPORTED_OPERATION"


def test_sensitive_data_handles_protected_endpoint_without_short_circuiting(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        return make_response(json_body={"id": 1, "username": "alice"}), 2.0

    monkeypatch.setattr("vulphex.sensitive_data_test.get_with_authentication", fake_get)

    result = SensitiveDataExposureTest().execute_endpoint(endpoint(security=[{"bearerAuth": []}]))

    assert result.status == "NO_SENSITIVE_DATA_EXPOSURE_INDICATED"


def test_sensitive_data_handles_transport_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        raise httpx.TimeoutException("timed out")

    monkeypatch.setattr("vulphex.sensitive_data_test.get_with_authentication", fail)

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "INCONCLUSIVE"


def test_sensitive_data_handles_malformed_json_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(text="{not valid json"), 3.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status in {"INCONCLUSIVE", "NO_SENSITIVE_DATA_EXPOSURE_INDICATED"}


def test_sensitive_data_uses_single_request_per_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_get(*args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        calls.append("called")
        return make_response(json_body={"id": 1}), 3.0

    monkeypatch.setattr("vulphex.sensitive_data_test.get_with_authentication", fake_get)

    result = SensitiveDataExposureTest().execute_endpoint(endpoint())

    assert calls == ["called"]
    assert result.evidence["request_count"] == 1


def test_sensitive_data_pipeline_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoints = [
        endpoint(path="/safe-profile"),
        endpoint(path="/exposed-profile"),
    ]

    def fake_get(target: str, *args: object, **kwargs: object) -> tuple[httpx.Response, float]:
        if "/safe-profile" in target:
            return make_response(json_body={"id": 1001, "username": "vulphex-test", "email": "tester@example.test"}), 2.0
        if "/exposed-profile" in target:
            return make_response(json_body={"id": 1001, "username": "vulphex-test", "password": "synthetic-secret", "api_key": "synthetic-api-key"}), 2.0
        return make_response(json_body={"status": "ok"}), 2.0

    monkeypatch.setattr("vulphex.sensitive_data_test.get_with_authentication", fake_get)

    results = AssessmentEngine([SensitiveDataExposureTest()]).assess_endpoints(endpoints)

    assert [result.test_id for result in results] == ["DATA-001", "DATA-001"]
    assert [result.status for result in results] == ["NO_SENSITIVE_DATA_EXPOSURE_INDICATED", "POTENTIAL_SENSITIVE_DATA_EXPOSURE"]


def test_sensitive_data_handles_text_stacktrace_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vulphex.sensitive_data_test.get_with_authentication",
        lambda *args, **kwargs: (make_response(text="Traceback (most recent call last):\nFile \"/srv/app/api/server.py\", line 42\n"), 4.0),
    )

    result = SensitiveDataExposureTest().execute(TARGET)

    assert result.status == "POTENTIAL_SENSITIVE_DATA_EXPOSURE"
    assert any(finding["category"] == "internal_infrastructure" for finding in result.evidence["findings"])
