from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set

from alias_routing_core import RoutingContext


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def env_csv(name: str) -> List[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass
class SmtpProxyConfig:
    simplelogin_base_url: str = "https://app.simplelogin.io"
    simplelogin_api_key: str = ""
    simplelogin_timeout_seconds: int = 30

    host: str = "127.0.0.1"
    port: int = 2525
    require_auth: bool = True
    username: str = "user"
    password: str = "change-me"
    require_tls: bool = False
    tls_mode: str = "starttls"
    tls_cert_file: str = ""
    tls_key_file: str = ""
    auth_login_enabled: bool = True
    max_message_bytes: int = 25 * 1024 * 1024
    dry_run: bool = True

    upstream_host: str = "host.docker.internal"
    upstream_port: int = 1025
    upstream_username: str = ""
    upstream_password: str = ""
    upstream_starttls: bool = False
    upstream_timeout_seconds: int = 30

    user_mailboxes: Set[str] = field(default_factory=set)
    manual_simplelogin_aliases: Set[str] = field(default_factory=set)
    known_reverse_aliases: Set[str] = field(default_factory=set)
    alias_suffix_domains: Set[str] = field(default_factory=set)

    fail_closed: bool = True
    rewrite_headers: bool = True
    rewrite_envelope: bool = True
    keep_unknown_simplelogin_addresses: bool = True
    strip_own_aliases: bool = True
    strip_own_mailboxes: bool = True
    allow_direct_external_send: bool = False

    cache_path: str = "/data/cache.sqlite3"
    cache_alias_ttl_seconds: int = 3600
    cache_contact_ttl_seconds: int = 86400

    log_level: str = "INFO"
    log_redact_addresses: bool = True
    log_message_body: bool = False
    log_subject: bool = False

    def routing_context(
        self,
        extra_simplelogin_aliases: Optional[Iterable[str]] = None,
    ) -> RoutingContext:
        aliases = set(self.manual_simplelogin_aliases)
        if extra_simplelogin_aliases:
            aliases.update(extra_simplelogin_aliases)

        return RoutingContext(
            own_simplelogin_aliases=aliases,
            own_mailboxes=set(self.user_mailboxes),
            known_reverse_aliases=set(self.known_reverse_aliases),
            alias_suffix_domains=set(self.alias_suffix_domains),
            keep_unknown_simplelogin_addresses=self.keep_unknown_simplelogin_addresses,
            strip_own_aliases=self.strip_own_aliases,
            strip_own_mailboxes=self.strip_own_mailboxes,
            allow_direct_external_send=self.allow_direct_external_send,
            fail_closed=self.fail_closed,
        )


def load_config_from_env() -> SmtpProxyConfig:
    return SmtpProxyConfig(
        simplelogin_base_url=os.environ.get("SIMPLELOGIN_BASE_URL", "https://app.simplelogin.io"),
        simplelogin_api_key=os.environ.get("SIMPLELOGIN_API_KEY", ""),
        simplelogin_timeout_seconds=env_int("SIMPLELOGIN_TIMEOUT_SECONDS", 30),
        host=os.environ.get("SMTP_PROXY_HOST", "127.0.0.1"),
        port=env_int("SMTP_PROXY_PORT", 2525),
        require_auth=env_bool("SMTP_PROXY_REQUIRE_AUTH", True),
        username=os.environ.get("SMTP_PROXY_USERNAME", "user"),
        password=os.environ.get("SMTP_PROXY_PASSWORD", "change-me"),
        require_tls=env_bool("SMTP_PROXY_REQUIRE_TLS", False),
        tls_mode=os.environ.get("SMTP_PROXY_TLS_MODE", "starttls"),
        tls_cert_file=os.environ.get("SMTP_PROXY_TLS_CERT_FILE", ""),
        tls_key_file=os.environ.get("SMTP_PROXY_TLS_KEY_FILE", ""),
        auth_login_enabled=env_bool("SMTP_PROXY_AUTH_LOGIN_ENABLED", True),
        max_message_bytes=env_int("SMTP_PROXY_MAX_MESSAGE_BYTES", 25 * 1024 * 1024),
        dry_run=env_bool("SMTP_PROXY_DRY_RUN", True),
        upstream_host=os.environ.get("UPSTREAM_SMTP_HOST", "host.docker.internal"),
        upstream_port=env_int("UPSTREAM_SMTP_PORT", 1025),
        upstream_username=os.environ.get("UPSTREAM_SMTP_USERNAME", ""),
        upstream_password=os.environ.get("UPSTREAM_SMTP_PASSWORD", ""),
        upstream_starttls=env_bool("UPSTREAM_SMTP_STARTTLS", False),
        upstream_timeout_seconds=env_int("UPSTREAM_SMTP_TIMEOUT_SECONDS", 30),
        user_mailboxes=set(env_csv("USER_MAILBOXES")),
        manual_simplelogin_aliases=set(env_csv("MANUAL_SIMPLELOGIN_ALIASES")),
        known_reverse_aliases=set(env_csv("KNOWN_REVERSE_ALIASES")),
        alias_suffix_domains=set(env_csv("ALIAS_SUFFIX_DOMAINS")),
        fail_closed=env_bool("FAIL_CLOSED", True),
        rewrite_headers=env_bool("REWRITE_HEADERS", True),
        rewrite_envelope=env_bool("REWRITE_ENVELOPE", True),
        keep_unknown_simplelogin_addresses=env_bool("KEEP_UNKNOWN_SIMPLELOGIN_ADDRESSES", True),
        strip_own_aliases=env_bool("STRIP_OWN_ALIASES", True),
        strip_own_mailboxes=env_bool("STRIP_OWN_MAILBOXES", True),
        allow_direct_external_send=env_bool("ALLOW_DIRECT_EXTERNAL_SEND", False),
        cache_path=os.environ.get("CACHE_PATH", "/data/cache.sqlite3"),
        cache_alias_ttl_seconds=env_int("CACHE_ALIAS_TTL_SECONDS", 3600),
        cache_contact_ttl_seconds=env_int("CACHE_CONTACT_TTL_SECONDS", 86400),
        log_level=os.environ.get("LOG_LEVEL", "INFO"),
        log_redact_addresses=env_bool("LOG_REDACT_ADDRESSES", True),
        log_message_body=env_bool("LOG_MESSAGE_BODY", False),
        log_subject=env_bool("LOG_SUBJECT", False),
    )
