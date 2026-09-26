"""Explicit, validated authentication configuration for authorized requests."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Literal


AuthenticationMode = Literal["none", "bearer", "api_key", "custom_header"]
_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class AuthenticationConfigError(ValueError):
    """Raised when authentication configuration is incomplete or unsafe."""


@dataclass(frozen=True)
class BOLAContext:
    """Explicit two-identity, single-object configuration for bounded BOLA tests."""

    identity_a: "AuthenticationConfig"
    identity_b: "AuthenticationConfig"
    object_reference: str | None = field(default=None, repr=False)
    parameter_name: str | None = None

    def __post_init__(self) -> None:
        if self.object_reference is not None and not self.object_reference.strip():
            raise AuthenticationConfigError("BOLA object reference is required")

    def __repr__(self) -> str:
        return (
            "BOLAContext("
            f"identity_a={self.identity_a.safe_mode!r}, identity_b={self.identity_b.safe_mode!r}, "
            f"parameter_name={self.parameter_name!r}, configured={self.object_reference is not None})"
        )


@dataclass(frozen=True)
class BFLAContext:
    """Explicit privileged/lower-privilege function target configuration."""

    privileged_identity: "AuthenticationConfig"
    lower_privilege_identity: "AuthenticationConfig"
    path: str | None = field(default=None, repr=False)
    method: str | None = None

    def __repr__(self) -> str:
        return (
            "BFLAContext("
            f"privileged_identity={self.privileged_identity.safe_mode!r}, "
            f"lower_privilege_identity={self.lower_privilege_identity.safe_mode!r}, "
            f"path={self.path!r}, method={self.method!r})"
        )


@dataclass(frozen=True)
class AuthenticationConfig:
    """Validated authentication material used only while constructing requests."""

    mode: AuthenticationMode = "none"
    token: str | None = field(default=None, repr=False)
    header_name: str | None = None
    header_value: str | None = field(default=None, repr=False)
    api_key_name: str | None = None
    api_key_value: str | None = field(default=None, repr=False)
    location: Literal["header"] = "header"

    def __post_init__(self) -> None:
        if self.mode not in {"none", "bearer", "api_key", "custom_header"}:
            raise AuthenticationConfigError("Authentication mode is not supported")
        if self.mode == "bearer":
            _require_secret(self.token, "Bearer token")
        elif self.mode == "api_key":
            _require_header_name(self.api_key_name, "API key header name")
            _require_secret(self.api_key_value, "API key")
            if self.location != "header":
                raise AuthenticationConfigError("Only header-based API keys are supported")
        elif self.mode == "custom_header":
            _require_header_name(self.header_name, "Custom header name")
            _require_secret(self.header_value, "Custom header value")

    def request_headers(self) -> dict[str, str]:
        """Return headers for an explicitly authorized request."""
        if self.mode == "none":
            return {}
        if self.mode == "bearer":
            return {"Authorization": f"Bearer {self.token}"}
        if self.mode == "api_key":
            return {self.api_key_name: self.api_key_value}  # type: ignore[dict-item]
        return {self.header_name: self.header_value}  # type: ignore[dict-item]

    @property
    def safe_mode(self) -> str:
        return self.mode

    def sensitive_values(self) -> tuple[str, ...]:
        return tuple(
            value
            for value in (self.token, self.api_key_value, self.header_value)
            if value
        )

    def __repr__(self) -> str:
        return (
            "AuthenticationConfig("
            f"mode={self.mode!r}, header_name={self.header_name!r}, "
            f"api_key_name={self.api_key_name!r}, location={self.location!r}, "
            f"configured={self.mode != 'none'})"
        )


def authentication_config_from_environment(
    environ: dict[str, str] | None = None,
    prefix: str = "VULPHEX_",
) -> AuthenticationConfig:
    """Build explicit authentication configuration from safe, opt-in environment settings."""
    values = os.environ if environ is None else environ
    mode = values.get(f"{prefix}AUTH_MODE", "none").lower()
    if mode == "none":
        return AuthenticationConfig()
    if mode == "bearer":
        return AuthenticationConfig(mode="bearer", token=values.get(f"{prefix}BEARER_TOKEN"))
    if mode == "api_key":
        return AuthenticationConfig(
            mode="api_key",
            api_key_name=values.get(f"{prefix}API_KEY_HEADER"),
            api_key_value=values.get(f"{prefix}API_KEY"),
        )
    if mode == "custom_header":
        return AuthenticationConfig(
            mode="custom_header",
            header_name=values.get(f"{prefix}CUSTOM_AUTH_HEADER"),
            header_value=values.get(f"{prefix}CUSTOM_AUTH_VALUE"),
        )
    raise AuthenticationConfigError("Authentication mode is not supported")


def bola_context_from_environment(
    environ: dict[str, str] | None = None,
) -> BOLAContext | None:
    """Load BOLA identities and one object reference only when explicitly configured."""
    values = os.environ if environ is None else environ
    keys = (
        "VULPHEX_BOLA_IDENTITY_A_AUTH_MODE",
        "VULPHEX_BOLA_IDENTITY_B_AUTH_MODE",
        "VULPHEX_BOLA_OBJECT_REFERENCE",
        "VULPHEX_BOLA_PARAMETER",
    )
    if not any(key in values for key in keys):
        return None
    identity_a = authentication_config_from_environment(
        values,
        prefix="VULPHEX_BOLA_IDENTITY_A_",
    )
    identity_b = authentication_config_from_environment(
        values,
        prefix="VULPHEX_BOLA_IDENTITY_B_",
    )
    return BOLAContext(
        identity_a=identity_a,
        identity_b=identity_b,
        object_reference=values.get("VULPHEX_BOLA_OBJECT_REFERENCE"),
        parameter_name=values.get("VULPHEX_BOLA_PARAMETER"),
    )


def bfla_context_from_environment(
    environ: dict[str, str] | None = None,
) -> BFLAContext | None:
    """Load one explicit restricted function and its two configured identities."""
    values = os.environ if environ is None else environ
    keys = (
        "VULPHEX_BFLA_PRIVILEGED_AUTH_MODE",
        "VULPHEX_BFLA_LOW_AUTH_MODE",
        "VULPHEX_BFLA_PATH",
        "VULPHEX_BFLA_METHOD",
    )
    if not any(key in values for key in keys):
        return None
    return BFLAContext(
        privileged_identity=authentication_config_from_environment(
            values,
            prefix="VULPHEX_BFLA_PRIVILEGED_",
        ),
        lower_privilege_identity=authentication_config_from_environment(
            values,
            prefix="VULPHEX_BFLA_LOW_",
        ),
        path=values.get("VULPHEX_BFLA_PATH"),
        method=values.get("VULPHEX_BFLA_METHOD"),
    )


def _require_secret(value: str | None, label: str) -> None:
    if not value:
        raise AuthenticationConfigError(f"{label} is required")


def _require_header_name(value: str | None, label: str) -> None:
    if not value or not _HEADER_NAME_PATTERN.fullmatch(value):
        raise AuthenticationConfigError(f"{label} is invalid")
