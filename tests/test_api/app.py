from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(
    title="VULPHEX Controlled Test API",
    version="1.0.0",
    description="Local controlled API used to validate VULPHEX security assessments.",
)

# Deliberately permissive CORS configuration for CORS testing.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/public")
def public_endpoint():
    return {
        "message": "Public endpoint",
        "status": "ok",
    }


@app.get("/protected")
def protected_endpoint(authorization: str | None = Header(default=None)):
    if not authorization:
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "message": "Authenticated endpoint",
        "status": "ok",
    }


@app.get("/users/{user_id}")
def get_user(
    user_id: str,
    authorization: str | None = Header(default=None),
):
    if not authorization:
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"},
        )

    # Controlled BOLA-style behavior:
    # Any authenticated identity can access any user object.
    return {
        "user_id": user_id,
        "username": f"user-{user_id}",
        "email": f"user-{user_id}@example.test",
        "role": "user",
    }


@app.get("/admin/users")
def admin_users(
    authorization: str | None = Header(default=None),
):
    if not authorization:
        return JSONResponse(
            status_code=401,
            content={"detail": "Authentication required"},
        )

    # Deliberately does not distinguish privileged from lower-privileged
    # identities. This is a controlled BFLA test target.
    return {
        "message": "Administrative endpoint",
        "users": [
            {"id": 1, "username": "alice"},
            {"id": 2, "username": "bob"},
        ],
    }


@app.get("/search")
def search(
    q: str = Query(default=""),
):
    lowered = q.lower()

    # Controlled SQL injection indicators.
    if any(
        indicator in lowered
        for indicator in (
            "' or '1'='1",
            "' or 1=1",
            "union select",
            "';--",
        )
    ):
        return JSONResponse(
            status_code=500,
            content={
                "error": "database error",
                "detail": "SQL syntax error near query",
            },
        )

    return {
        "query": q,
        "results": [],
    }


@app.get("/items")
def items(
    filter: str = Query(default=""),
):
    lowered = filter.lower()

    # Controlled NoSQL injection indicators.
    if any(
        indicator in lowered
        for indicator in (
            "$ne",
            "$gt",
            "$regex",
        )
    ):
        return {
            "query": filter,
            "matched": True,
            "items": [
                {"id": 1, "name": "test-item"},
            ],
        }

    return {
        "query": filter,
        "matched": False,
        "items": [],
    }


@app.get("/execute")
def execute(
    command: str = Query(default=""),
):
    lowered = command.lower()

    # Simulated command-injection error indicators.
    if any(
        indicator in lowered
        for indicator in (
            "|",
            "&&",
            ";",
            "`",
            "$(",
        )
    ):
        return JSONResponse(
            status_code=500,
            content={
                "error": "command execution failed",
                "detail": "/bin/sh: command not found",
            },
        )

    return {
        "command": command,
        "executed": False,
    }


@app.get("/profile")
def profile():
    # Deliberately exposed sensitive-looking fields for
    # DATA-001 validation.
    return {
        "id": 1001,
        "username": "test-user",
        "email": "test@example.test",
        "password": "TEST_ONLY_NOT_REAL",
        "api_key": "TEST_API_KEY_ONLY",
        "access_token": "TEST_ACCESS_TOKEN_ONLY",
    }


@app.get("/error")
def error_endpoint():
    # Controlled framework/runtime disclosure.
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "exception": "ValueError",
            "traceback": (
                "Traceback (most recent call last): "
                "File '/app/main.py', line 42, in process_request"
            ),
        },
    )


@app.get("/cors")
def cors_endpoint():
    return {
        "message": "CORS test endpoint",
    }


@app.get("/debug")
def debug_endpoint():
    # Controlled configuration/information disclosure.
    return {
        "debug": True,
        "environment": "development",
        "server": "uvicorn",
        "framework": "FastAPI",
        "version": "0.115.14",
    }


@app.get("/rate-limit")
def rate_limit_endpoint():
    # Intentionally does not enforce rate limiting.
    return {
        "message": "Request accepted",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
    }