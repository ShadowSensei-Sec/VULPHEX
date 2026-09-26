"""Controlled HTTP operations used by VULPHEX tests."""

import re
from time import monotonic
from urllib.parse import urlsplit, urlunsplit

import httpx

from .authentication import AuthenticationConfig


RELEVANT_RESPONSE_HEADERS = {
    "content-type",
    "location",
    "server",
    "www-authenticate",
    "x-request-id",
}
SENSITIVE_VALUE_PATTERN = re.compile(
    r'''(?i)(["']?\b(?:authorization|api[_-]?key|access_token|id_token|refresh_token|password|secret|token)\b["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;}]+)'''
)
SENSITIVE_HEADER_PATTERN = re.compile(
    r"(?i)^(authorization|proxy-authorization|.*(?:api[_-]?key|token|password|secret).*)$"
)


def sanitize_url(url: str) -> str:
    """Return a URL without credentials, query, or fragment data."""
    try:
        parsed = urlsplit(url)
        if not parsed.scheme and not parsed.netloc:
            return urlunsplit(("", "", parsed.path, "", ""))
        hostname = parsed.hostname
        if not hostname:
            return "[invalid URL]"
        host = f"[{hostname}]" if ":" in hostname else hostname
        port = f":{parsed.port}" if parsed.port is not None else ""
        return urlunsplit((parsed.scheme, f"{host}{port}", parsed.path, "", ""))
    except ValueError:
        return "[invalid URL]"


def validate_url(url: str) -> str:
    """Validate an HTTP(S) URL before making a request."""
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("URL must be a valid absolute http:// or https:// URL") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not hostname:
        raise ValueError("URL must be an absolute http:// or https:// URL")
    return url


def get_without_authentication(url: str, timeout: float = 10.0) -> tuple[httpx.Response, float]:
    """Perform a GET request without authentication and return its duration."""
    validate_url(url)
    started = monotonic()
    with httpx.Client(follow_redirects=False, timeout=timeout) as client:
        response = client.get(url)
    return response, (monotonic() - started) * 1000


def get_with_authentication(
    url: str,
    authentication: AuthenticationConfig,
    timeout: float = 10.0,
        extra_headers: dict[str, str] | None = None,
) -> tuple[httpx.Response, float]:
    """Perform an explicitly authenticated GET request."""
    validate_url(url)
    started = monotonic()
    headers = authentication.request_headers()
    headers.update(extra_headers or {})
    with httpx.Client(follow_redirects=False, timeout=timeout) as client:
        response = client.get(url, headers=headers)
    return response, (monotonic() - started) * 1000


def get_with_parameters(
    url: str,
    params: dict[str, str] | None = None,
    authentication: AuthenticationConfig | None = None,
    timeout: float = 10.0,
) -> tuple[httpx.Response, float]:
    """Perform a safe GET with explicitly supplied parameters and optional auth."""
    validate_url(url)
    started = monotonic()
    headers = authentication.request_headers() if authentication is not None else {}
    with httpx.Client(follow_redirects=False, timeout=timeout) as client:
        response = client.get(url, params=params or {}, headers=headers)
    return response, (monotonic() - started) * 1000


def response_evidence(response: httpx.Response, response_time_ms: float) -> dict[str, object]:
    """Extract limited, sanitized evidence from an HTTP response."""
    headers = {
        name: sanitize_url(value) if name.lower() == "location" else redact_sensitive_text(value)
        for name, value in response.headers.items()
        if name.lower() in RELEVANT_RESPONSE_HEADERS
    }
    body = redact_sensitive_text(response.text[:500].replace("\r", " ").replace("\n", " ").strip())
    return {
        "method": response.request.method,
        "url": sanitize_url(str(response.request.url)),
        "status_code": response.status_code,
        "response_time_ms": round(response_time_ms, 2),
        "headers": headers,
        "body_preview": body,
    }


def redact_sensitive_text(value: str) -> str:
    """Redact secret-bearing fields and authentication header values from text."""
    redacted = re.sub(
        r"(?i)(\b(?:authorization|proxy-authorization)\s*:\s*(?:bearer|basic)\s+)[^\s,;}]+",
        r"\1[REDACTED]",
        value,
    )
    return SENSITIVE_VALUE_PATTERN.sub(r"\1[REDACTED]", redacted)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return useful header names with sensitive values removed."""
    return {
        name: "[REDACTED]" if SENSITIVE_HEADER_PATTERN.match(name) else redact_sensitive_text(value)
        for name, value in headers.items()
    }