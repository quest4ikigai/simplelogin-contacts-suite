from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import List

from .config import SmtpProxyConfig


LOCAL_DEVELOPMENT_HOSTS = {"127.0.0.1", "localhost", "::1"}
REMOTE_CAPABLE_ANY_HOSTS = {"", "0.0.0.0", "::"}


class StartupConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class UnsafeSetting:
    name: str
    message: str


def validate_startup_config(config: SmtpProxyConfig) -> None:
    unsafe_settings = _unsafe_settings(config)
    if _is_remote_capable_bind(config.host):
        if config.allow_unsafe_local_dry_run:
            raise StartupConfigError(
                "SMTP_PROXY_ALLOW_UNSAFE_LOCAL_DRY_RUN is only allowed with "
                "local development binds."
            )
        if unsafe_settings:
            raise StartupConfigError(
                "Unsafe SMTP proxy config for remote-capable bind "
                f"SMTP_PROXY_HOST={_safe_host(config.host)}: "
                f"{_format_unsafe_settings(unsafe_settings)}"
            )
        return

    if config.allow_unsafe_local_dry_run and not config.dry_run:
        raise StartupConfigError(
            "SMTP_PROXY_ALLOW_UNSAFE_LOCAL_DRY_RUN requires SMTP_PROXY_DRY_RUN=true."
        )

    if config.dry_run and unsafe_settings and not config.allow_unsafe_local_dry_run:
        raise StartupConfigError(
            "Unsafe local dry-run SMTP proxy config requires "
            "SMTP_PROXY_ALLOW_UNSAFE_LOCAL_DRY_RUN=true: "
            f"{_format_unsafe_settings(unsafe_settings)}"
        )


def is_local_development_bind(host: str) -> bool:
    cleaned = _clean_host(host)
    if cleaned in LOCAL_DEVELOPMENT_HOSTS:
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


def _is_remote_capable_bind(host: str) -> bool:
    cleaned = _clean_host(host)
    if cleaned in REMOTE_CAPABLE_ANY_HOSTS:
        return True
    return not is_local_development_bind(cleaned)


def _unsafe_settings(config: SmtpProxyConfig) -> List[UnsafeSetting]:
    settings: List[UnsafeSetting] = []
    if not config.require_auth:
        settings.append(UnsafeSetting("SMTP_PROXY_REQUIRE_AUTH", "must be true"))
    if not config.require_tls:
        settings.append(UnsafeSetting("SMTP_PROXY_REQUIRE_TLS", "must be true"))
    if not config.username or config.username == "user":
        settings.append(UnsafeSetting("SMTP_PROXY_USERNAME", "must not use the default value"))
    if not config.password or config.password == "change-me":
        settings.append(UnsafeSetting("SMTP_PROXY_PASSWORD", "must not use the default value"))
    if not config.user_mailboxes:
        settings.append(UnsafeSetting("USER_MAILBOXES", "must not be empty"))
    if config.allow_direct_external_send:
        settings.append(UnsafeSetting("ALLOW_DIRECT_EXTERNAL_SEND", "must be false"))
    return settings


def _format_unsafe_settings(settings: List[UnsafeSetting]) -> str:
    return "; ".join(f"{setting.name} {setting.message}" for setting in settings)


def _clean_host(host: str) -> str:
    return (host or "").strip().strip("[]").casefold()


def _safe_host(host: str) -> str:
    return _clean_host(host) or "<all-interfaces>"
