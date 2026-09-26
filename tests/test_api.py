"""Controlled local API used only to validate VULPHEX AUTH-001 behavior."""

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient


app = FastAPI(title="VULPHEX Controlled Local Test API")

# Synthetic test data only. This token is NOT a real credential.
TEST_TOKEN = "vulphex-local-test-token"
OBJECT_TOKEN_A = "vulphex-local-identity-a"
OBJECT_TOKEN_B = "vulphex-local-identity-b"
ADMIN_TOKEN = "vulphex-local-admin-token"
USER_TOKEN = "vulphex-local-user-token"
_RATE_LIMIT_REQUESTS = 0


@app.get("/public")
def public_endpoint() -> dict[str, str]:
    """Return a deliberately unauthenticated response."""
    return {"message": "This endpoint is intentionally public."}


@app.get("/protected")
def protected_endpoint(authorization: str | None = Header(default=None)) -> dict[str, str]:
    """Require the synthetic local test token."""
    if authorization != f"Bearer {TEST_TOKEN}":
        raise HTTPException(
            status_code=401,
            detail="A valid synthetic test token is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"message": "Synthetic protected response."}


def _object_response(object_id: int, owner: str) -> dict[str, str | int]:
    return {"id": object_id, "owner": owner, "name": "Synthetic object"}


@app.get("/objects/{object_id}")
def secure_object(
    object_id: int,
    authorization: str | None = Header(default=None),
) -> dict[str, str | int]:
    """Controlled secure object fixture for AUTHZ-001."""
    if object_id != 100:
        raise HTTPException(status_code=404, detail="Object not found.")
    if authorization == f"Bearer {OBJECT_TOKEN_A}":
        return _object_response(object_id, "identity-a")
    if authorization == f"Bearer {OBJECT_TOKEN_B}":
        raise HTTPException(status_code=403, detail="Object access denied.")
    raise HTTPException(status_code=401, detail="A synthetic identity token is required.")


@app.get("/vulnerable-objects/{object_id}")
def vulnerable_object(
    object_id: int,
    authorization: str | None = Header(default=None),
) -> dict[str, str | int]:
    """Intentionally vulnerable controlled fixture for AUTHZ-001 only."""
    if object_id != 100:
        raise HTTPException(status_code=404, detail="Object not found.")
    if authorization not in {f"Bearer {OBJECT_TOKEN_A}", f"Bearer {OBJECT_TOKEN_B}"}:
        raise HTTPException(status_code=401, detail="A synthetic identity token is required.")
    return _object_response(object_id, "identity-a")


@app.get("/admin/reports")
def admin_reports(authorization: str | None = Header(default=None)) -> dict[str, str]:
    """Controlled secure function fixture for AUTHZ-002."""
    if authorization == f"Bearer {ADMIN_TOKEN}":
        return {"report": "Synthetic administrative report."}
    if authorization == f"Bearer {USER_TOKEN}":
        raise HTTPException(status_code=403, detail="Administrative access denied.")
    raise HTTPException(status_code=401, detail="A synthetic role token is required.")


@app.get("/vulnerable-admin/reports")
def vulnerable_admin_reports(authorization: str | None = Header(default=None)) -> dict[str, str]:
    """Intentionally vulnerable controlled fixture for AUTHZ-002 only."""
    if authorization in {f"Bearer {ADMIN_TOKEN}", f"Bearer {USER_TOKEN}"}:
        return {"report": "Synthetic administrative report."}
    raise HTTPException(status_code=401, detail="A synthetic role token is required.")


@app.get("/validate-age")
def validate_age(age: int) -> dict[str, int]:
    """Controlled secure input-validation fixture."""
    return {"age": age}


@app.get("/weak-validate-age")
def weak_validate_age(age: str = "1") -> dict[str, str]:
    """Intentionally weak input-validation fixture for INPUT-001 only."""
    return {"age": age}


@app.get("/sql-search")
def sql_search(q: str = "vulphex-test") -> dict[str, str]:
    """Controlled secure SQL-search fixture for INJ-001."""
    if q == "vulphex-test":
        return {"result": q}
    if "'" in q or "OR" in q.upper() or "AND" in q.upper():
        return {"error": "invalid query syntax"}
    return {"result": q}


@app.get("/vulnerable-sql-search")
def vulnerable_sql_search(q: str = "vulphex-test") -> dict[str, str]:
    """Intentionally vulnerable local fixture for INJ-001 only; it simulates a database-style SQL syntax error deterministically."""
    if q == "vulphex-test":
        return {"result": q}
    if "'" in q or "OR" in q.upper() or "AND" in q.upper():
        raise HTTPException(
            status_code=500,
            detail='PostgreSQL SQLSTATE[42601]: syntax error at or near "\'"',
        )
    return {"result": q}


@app.get("/nosql-search")
def nosql_search(request: Request) -> dict[str, object]:
    """Controlled secure NoSQL-search fixture for INJ-002."""
    q = request.query_params.get("q", "vulphex-test")
    if request.query_params.get("q[$ne]") == "nonexistent":
        return {"error": "invalid query syntax", "result": q}
    return {"result": q}


@app.get("/vulnerable-nosql-search")
def vulnerable_nosql_search(request: Request) -> dict[str, object]:
    """Intentionally vulnerable local fixture for INJ-002 only; it simulates operator interpretation deterministically."""
    q = request.query_params.get("q", "vulphex-test")
    if request.query_params.get("q[$ne]") == "nonexistent":
        return {"result": "nonexistent", "count": 12, "matches": [{"user": "alice"}]}
    return {"result": q}


@app.get("/command-search")
def command_search(request: Request) -> dict[str, object]:
    """Controlled secure command-search fixture for INJ-003."""
    q = request.query_params.get("q", "vulphex-test")
    if any(marker in q for marker in (";", "&&", "||", "|", ">", "<")):
        return {"error": "input treated as ordinary data", "result": q}
    return {"result": q}


@app.get("/vulnerable-command-search")
def vulnerable_command_search(request: Request) -> dict[str, object]:
    """Intentionally vulnerable simulation for INJ-003 only; it models shell-parser behavior without executing any real command."""
    q = request.query_params.get("q", "vulphex-test")
    if any(marker in q for marker in (";", "&&", "||", "|", ">", "<")):
        raise HTTPException(
            status_code=500,
            detail="sh: syntax error near unexpected token ';'",
        )
    return {"result": q}


@app.get("/safe-profile")
def safe_profile() -> dict[str, object]:
    """Synthetic endpoint with ordinary profile fields only."""
    return {
        "id": 1001,
        "username": "vulphex-test",
        "email": "tester@example.test",
        "display_name": "VULPHEX Test User",
    }


@app.get("/exposed-profile")
def exposed_profile() -> dict[str, object]:
    """Synthetic endpoint intentionally exposing sensitive fields for DATA-001."""
    return {
        "id": 1001,
        "username": "vulphex-test",
        "password": "synthetic-secret",
        "api_key": "synthetic-api-key",
        "session_token": "synthetic-session-token",
    }


@app.get("/nested-exposure")
def nested_exposure() -> dict[str, object]:
    """Synthetic nested response with sensitive fields embedded in an object tree."""
    return {
        "user": {
            "profile": {
                "credentials": {
                    "private_key": "-----BEGIN TEST PRIVATE KEY-----\nsynthetic-key\n-----END TEST PRIVATE KEY-----",
                }
            }
        }
    }


@app.get("/ordinary-data")
def ordinary_data() -> dict[str, object]:
    """Synthetic ordinary data without secret-bearing fields."""
    return {
        "id": 1001,
        "email": "tester@example.test",
        "username": "vulphex-test",
        "name": "VULPHEX Test User",
        "created_at": "2025-01-01T00:00:00Z",
    }


@app.get("/internal-trace")
def internal_trace() -> str:
    """Synthetic text response containing an internal filesystem path and stack trace marker."""
    return "Traceback (most recent call last):\n  File \"/srv/app/api/server.py\", line 42, in <module>\nValueError: config missing"


@app.get("/safe-error")
def safe_error() -> dict[str, str]:
    """Controlled generic validation error without internal implementation details."""
    raise HTTPException(status_code=400, detail="Invalid request parameter")


@app.get("/python-error")
def python_error() -> dict[str, str]:
    """Synthetic Python traceback fixture for INFO-001."""
    raise HTTPException(
        status_code=500,
        detail="Traceback (most recent call last):\n  File \"/app/services/users.py\", line 42, in <module>\nRuntimeError: startup failed",
    )


@app.get("/java-error")
def java_error() -> dict[str, str]:
    """Synthetic Java stack-trace fixture for INFO-001."""
    raise HTTPException(
        status_code=500,
        detail="java.lang.RuntimeException: Failed to load config\n    at com.example.config.ConfigLoader.load(ConfigLoader.java:45)\n    at com.example.api.UsersController.get(UsersController.java:18)",
    )


@app.get("/database-error")
def database_error() -> dict[str, str]:
    """Synthetic database implementation disclosure fixture for INFO-001."""
    raise HTTPException(
        status_code=500,
        detail="PostgreSQL SQLSTATE[42601]: syntax error at or near \"SELECT\"\nquery: SELECT * FROM users WHERE id = '1';",
    )


@app.get("/internal-path-error")
def internal_path_error() -> dict[str, str]:
    """Synthetic internal filesystem path fixture for INFO-001."""
    raise HTTPException(
        status_code=500,
        detail="FileNotFoundError: /app/services/users.py:42 cannot open config",
    )


@app.get("/internal-host-error")
def internal_host_error() -> dict[str, str]:
    """Synthetic internal hostname/IP disclosure fixture for INFO-001."""
    raise HTTPException(
        status_code=500,
        detail="ConnectionError: db.internal.local failed at 10.0.0.14:5432 while connecting to internal postgres service",
    )


@app.get("/generic-server-error")
def generic_server_error() -> dict[str, str]:
    """Generic 500 without internal implementation details."""
    raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/rate-limited")
def rate_limited() -> dict[str, str]:
    """Synthetic bounded rate-limit fixture: three successes, then one 429."""
    global _RATE_LIMIT_REQUESTS
    _RATE_LIMIT_REQUESTS += 1
    if _RATE_LIMIT_REQUESTS >= 4:
        _RATE_LIMIT_REQUESTS = 0
        raise HTTPException(
            status_code=429,
            detail="Synthetic rate limit reached.",
            headers={
                "Retry-After": "30",
                "X-RateLimit-Limit": "3",
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": "1700000000",
            },
        )
    return {"status": "synthetic-ok"}


@app.get("/rate-limit-headers")
def rate_limit_headers() -> dict[str, str]:
    """Synthetic successful responses with explicit rate-limit headers."""
    return JSONResponse(
        {"status": "synthetic-ok"},
        headers={
            "X-RateLimit-Limit": "10",
            "X-RateLimit-Remaining": "9",
            "X-RateLimit-Reset": "1700000000",
        },
    )


@app.get("/no-rate-limit")
def no_rate_limit() -> dict[str, str]:
    """Synthetic successful responses without rate-limit indicators."""
    return {"status": "synthetic-ok"}


@app.get("/rate-limit-error")
def rate_limit_error() -> dict[str, str]:
    """Synthetic generic server failure without rate-limit indicators."""
    raise HTTPException(status_code=500, detail="Synthetic server failure.")


@app.get("/cors-secure")
def cors_secure(request: Request) -> JSONResponse:
    """Synthetic CORS policy that allows only the controlled trusted origin."""
    headers = {
        "Access-Control-Allow-Origin": "https://vulphex-test.example",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
    }
    return JSONResponse({"status": "synthetic-ok"}, headers=headers)


@app.get("/cors-wildcard")
def cors_wildcard() -> JSONResponse:
    """Synthetic public wildcard CORS policy without credentials."""
    return JSONResponse(
        {"status": "synthetic-ok"},
        headers={"Access-Control-Allow-Origin": "*"},
    )


@app.get("/cors-reflect")
def cors_reflect(request: Request) -> JSONResponse:
    """Synthetic arbitrary-origin reflection fixture."""
    origin = request.headers.get("origin", "")
    return JSONResponse(
        {"status": "synthetic-ok"},
        headers={"Access-Control-Allow-Origin": origin} if origin else {},
    )


@app.get("/cors-credentials")
def cors_credentials(request: Request) -> JSONResponse:
    """Synthetic credentialed arbitrary-origin reflection fixture."""
    origin = request.headers.get("origin", "")
    return JSONResponse(
        {"status": "synthetic-ok"},
        headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        } if origin else {"Access-Control-Allow-Credentials": "true"},
    )


@app.get("/security-headers")
def security_headers() -> JSONResponse:
    """Synthetic response containing safe API-relevant security headers."""
    return JSONResponse(
        {"status": "synthetic-ok"},
        headers={
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Server": "VULPHEX-Test",
            "X-Powered-By": "SyntheticAPI/1.0",
        },
    )


@app.get("/misconfig-debug")
def misconfig_debug() -> JSONResponse:
    """Controlled debug indicator fixture for CONFIG-003."""
    return JSONResponse(
        {"status": "synthetic-ok"},
        headers={
            "X-Debug": "enabled",
            "X-Debug-Token": "synthetic-debug-token",
            "Content-Type": "application/json",
        },
    )


@app.get("/misconfig-content-type")
def misconfig_content_type() -> Response:
    """Controlled content-type inconsistency fixture for CONFIG-003."""
    return Response(
        content="<html><body>debug page</body></html>",
        media_type="text/html",
        headers={"X-Debug": "enabled"},
    )


@app.get("/misconfig-normal")
def misconfig_normal() -> JSONResponse:
    """Controlled secure fixture for CONFIG-003."""
    return JSONResponse({"status": "synthetic-ok"}, headers={"Content-Type": "application/json"})


_generated_openapi = app.openapi


def _controlled_openapi() -> dict:
    schema = _generated_openapi()
    for parameter in schema["paths"]["/weak-validate-age"]["get"]["parameters"]:
        if parameter.get("name") == "age":
            parameter["schema"] = {"type": "integer"}
            parameter["required"] = True
    return schema


app.openapi = _controlled_openapi


client = TestClient(app)


def test_public_endpoint_is_unauthenticated() -> None:
    response = client.get("/public")

    assert response.status_code == 200
    assert response.json()["message"] == "This endpoint is intentionally public."


def test_protected_endpoint_rejects_missing_and_invalid_authentication() -> None:
    missing_authentication = client.get("/protected")
    invalid_authentication = client.get(
        "/protected",
        headers={"Authorization": "Bearer wrong-token"},
    )

    assert missing_authentication.status_code == 401
    assert invalid_authentication.status_code == 401


def test_protected_endpoint_accepts_only_the_synthetic_test_token() -> None:
    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Synthetic protected response."


def test_secure_object_fixture_denies_secondary_identity() -> None:
    primary = client.get("/objects/100", headers={"Authorization": f"Bearer {OBJECT_TOKEN_A}"})
    secondary = client.get("/objects/100", headers={"Authorization": f"Bearer {OBJECT_TOKEN_B}"})

    assert primary.status_code == 200
    assert secondary.status_code == 403


def test_vulnerable_object_fixture_allows_secondary_identity() -> None:
    primary = client.get("/vulnerable-objects/100", headers={"Authorization": f"Bearer {OBJECT_TOKEN_A}"})
    secondary = client.get("/vulnerable-objects/100", headers={"Authorization": f"Bearer {OBJECT_TOKEN_B}"})

    assert primary.status_code == 200
    assert secondary.status_code == 200


def test_secure_function_fixture_denies_lower_privilege_identity() -> None:
    privileged = client.get("/admin/reports", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    lower_privilege = client.get("/admin/reports", headers={"Authorization": f"Bearer {USER_TOKEN}"})

    assert privileged.status_code == 200
    assert lower_privilege.status_code == 403


def test_vulnerable_function_fixture_allows_lower_privilege_identity() -> None:
    privileged = client.get("/vulnerable-admin/reports", headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    lower_privilege = client.get("/vulnerable-admin/reports", headers={"Authorization": f"Bearer {USER_TOKEN}"})

    assert privileged.status_code == 200
    assert lower_privilege.status_code == 200


def test_secure_input_validation_fixture_rejects_invalid_age() -> None:
    valid = client.get("/validate-age", params={"age": "21"})
    invalid = client.get("/validate-age", params={"age": "abc"})

    assert valid.status_code == 200
    assert invalid.status_code == 422


def test_weak_input_validation_fixture_accepts_invalid_age() -> None:
    valid = client.get("/weak-validate-age", params={"age": "21"})
    invalid = client.get("/weak-validate-age", params={"age": "abc"})

    assert valid.status_code == 200
    assert invalid.status_code == 200
