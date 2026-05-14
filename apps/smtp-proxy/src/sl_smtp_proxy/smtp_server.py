from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hmac
import logging
import socket
import ssl
import time
import warnings
from typing import Optional

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword, SMTP
from alias_routing_core import normalize_email_address

from .config import SmtpProxyConfig
from .forwarder import UpstreamForwardingError, UpstreamSmtpForwarder
from .logging import audit_event, plan_audit_fields, plan_summary, redact_address, safe_reason
from .message_transform import (
    apply_transform,
    build_plan_for_message,
    parse_message,
    transformed_envelope_recipients,
)
from .mime_sender_validation import validate_mime_sender
from .reverse_alias_resolver import resolver_from_config
from .safety_verifier import verify_post_transform_safety, visible_recipient_count


LOGGER = logging.getLogger(__name__)
TLS_MODES = {"starttls", "implicit"}
AIOSMTPD_AUTH_TLS_WARNING = (
    "Requiring AUTH while not requiring TLS can lead to security vulnerabilities!"
)
AIOSMTPD_AUTH_TLS_LOG_WARNING = "auth_required == True but auth_require_tls == False"


class _SmtpProxyController(Controller):
    def __init__(self, *args, suppress_auth_tls_warning: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self._suppress_auth_tls_warning = suppress_auth_tls_warning

    def factory(self):
        if not self._suppress_auth_tls_warning:
            return SMTP(self.handler, **self.SMTP_kwargs)

        with _suppress_aiosmtpd_auth_tls_warning():
            return SMTP(self.handler, **self.SMTP_kwargs)


class _AiosmtpdAuthTlsWarningFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.getMessage() != AIOSMTPD_AUTH_TLS_LOG_WARNING


@contextmanager
def _suppress_aiosmtpd_auth_tls_warning():
    mail_logger = logging.getLogger("mail.log")
    log_filter = _AiosmtpdAuthTlsWarningFilter()
    mail_logger.addFilter(log_filter)
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=AIOSMTPD_AUTH_TLS_WARNING,
                category=UserWarning,
                module="aiosmtpd.smtp",
            )
            yield
    finally:
        mail_logger.removeFilter(log_filter)


class SmtpProxyHandler:
    def __init__(self, config: SmtpProxyConfig, reverse_alias_resolver=None, forwarder=None):
        self.config = config
        self.last_plan = None
        self.reverse_alias_resolver = (
            reverse_alias_resolver
            if reverse_alias_resolver is not None
            else resolver_from_config(config)
        )
        self.forwarder = forwarder or UpstreamSmtpForwarder(config)

    async def handle_MAIL(self, server, session, envelope, address, mail_options) -> str:
        if not _sender_allowed(self.config, address):
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_sender_rejected",
                    peer=_peer_host(session),
                    sender=redact_address(address),
                    reason="sender_not_allowed",
                ),
            )
            return "550 Sender address is not allowed by SimpleLogin proxy policy"
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope) -> str:
        content = envelope.original_content
        if content is None:
            content = envelope.content
        if isinstance(content, str):
            data = content.encode("utf-8", errors="replace")
        else:
            data = bytes(content or b"")

        parsed_message = parse_message(data)
        mime_sender_validation = validate_mime_sender(parsed_message, self.config)
        if not mime_sender_validation.accepted:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_mime_sender_rejected",
                    peer=_peer_host(session),
                    policy="mime_sender_validation",
                    header=mime_sender_validation.header,
                    reason=mime_sender_validation.reason,
                    from_count=mime_sender_validation.from_count,
                    sender_count=mime_sender_validation.sender_count,
                ),
            )
            return "550 MIME sender address is not allowed by SimpleLogin proxy policy"

        extra_simplelogin_aliases = set()
        if self.config.strip_own_aliases and hasattr(self.reverse_alias_resolver, "owned_alias_emails"):
            try:
                extra_simplelogin_aliases = self.reverse_alias_resolver.owned_alias_emails()
            except Exception as exc:
                public_message = getattr(exc, "public_message", type(exc).__name__)
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_message_rejected",
                        peer=_peer_host(session),
                        policy="alias_refresh_failed",
                        reason=safe_reason(f"SimpleLogin alias refresh failed: {public_message}"),
                    ),
                )
                return f"550 SimpleLogin alias refresh failed: {public_message}"

        message, plan = build_plan_for_message(
            envelope.mail_from or "",
            list(envelope.rcpt_tos),
            data,
            self.config,
            reverse_alias_resolver=self.reverse_alias_resolver,
            extra_simplelogin_aliases=extra_simplelogin_aliases,
        )
        self.last_plan = plan
        LOGGER.info("transform_plan %s", plan_summary(plan, self.config.log_redact_addresses))
        LOGGER.info(
            "audit %s",
            audit_event(
                "smtp_transform_plan",
                peer=_peer_host(session),
                **plan_audit_fields(plan, self.config.log_redact_addresses),
            ),
        )
        if plan.rejected:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_message_rejected",
                    peer=_peer_host(session),
                    policy="transform_plan_rejected",
                    reason=safe_reason(plan.rejection_reason),
                ),
            )
            return f"550 {plan.rejection_reason or 'Message rejected by SimpleLogin proxy policy'}"

        transformed_message = apply_transform(message, plan, self.config)
        transformed_recipients = transformed_envelope_recipients(plan)
        verification = verify_post_transform_safety(
            transformed_message,
            transformed_recipients,
            self.config,
            plan,
            extra_simplelogin_aliases=extra_simplelogin_aliases,
        )
        if not verification.accepted:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_message_rejected",
                    peer=_peer_host(session),
                    policy="post_transform_safety_verifier",
                    invariant=verification.invariant,
                    location=verification.location,
                    reason=verification.reason,
                    recipient_count=len(transformed_recipients),
                    visible_recipient_count=visible_recipient_count(transformed_message),
                ),
            )
            return "550 Message rejected by SimpleLogin proxy post-transform safety verifier"
        if not transformed_recipients:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_message_rejected",
                    peer=_peer_host(session),
                    policy="no_deliverable_recipients",
                    reason="No deliverable recipients after SimpleLogin routing",
                ),
            )
            return "550 No deliverable recipients after SimpleLogin routing"
        if self.config.dry_run:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_message_rejected",
                    peer=_peer_host(session),
                    policy="dry_run",
                    reason="SimpleLogin SMTP proxy dry-run: message not forwarded",
                ),
            )
            return "550 SimpleLogin SMTP proxy dry-run: message not forwarded"

        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None,
                self.forwarder.forward,
                envelope.mail_from or "",
                transformed_recipients,
                transformed_message,
            )
        except UpstreamForwardingError as exc:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_message_rejected",
                    peer=_peer_host(session),
                    policy="upstream_unavailable",
                    reason=safe_reason(exc.public_message),
                ),
            )
            return f"550 {exc.public_message}"
        LOGGER.info(
            "audit %s",
            audit_event(
                "smtp_message_forwarded",
                peer=_peer_host(session),
                recipient_count=len(transformed_recipients),
            ),
        )
        return "250 Message accepted for delivery"

    def handle_exception(self, error: Exception) -> str:
        LOGGER.exception("SMTP proxy handler failed: %s", type(error).__name__)
        LOGGER.info(
            "audit %s",
            audit_event("smtp_internal_error", error_type=type(error).__name__),
        )
        return "451 SimpleLogin SMTP proxy internal error"


class SmtpProxyServer:
    def __init__(self, config: SmtpProxyConfig, reverse_alias_resolver=None, forwarder=None):
        self.config = config
        self.handler = SmtpProxyHandler(
            config,
            reverse_alias_resolver=reverse_alias_resolver,
            forwarder=forwarder,
        )
        self._controller: Optional[Controller] = None

    @property
    def last_plan(self):
        return self.handler.last_plan

    @property
    def port(self) -> int:
        if not self._controller or not self._controller.server:
            return self.config.port
        sockets = self._controller.server.sockets or []
        if not sockets:
            return self.config.port
        return int(sockets[0].getsockname()[1])

    async def start(self) -> None:
        controller_ssl_context, smtp_tls_context, require_starttls, auth_require_tls = (
            _tls_settings(self.config)
        )

        self._controller = _SmtpProxyController(
            self.handler,
            hostname=self.config.host,
            port=_resolve_listen_port(self.config.host, self.config.port),
            ssl_context=controller_ssl_context,
            ready_timeout=5.0,
            server_hostname="simplelogin-smtp-proxy",
            tls_context=smtp_tls_context,
            require_starttls=require_starttls,
            data_size_limit=self.config.max_message_bytes,
            decode_data=False,
            auth_required=self.config.require_auth,
            auth_require_tls=auth_require_tls,
            authenticator=_authenticator(self.config) if self.config.require_auth else None,
            auth_exclude_mechanism=_excluded_auth_mechanisms(self.config),
            command_call_limit={"RCPT": 500, "NOOP": 20, "RSET": 20, "*": 100},
            suppress_auth_tls_warning=_suppress_auth_tls_warning(
                self.config,
                controller_ssl_context,
                smtp_tls_context,
                auth_require_tls,
            ),
        )
        self._controller.start()

    async def serve_forever(self) -> None:
        if not self._controller:
            await self.start()
        while True:
            await asyncio.sleep(3600)

    async def stop(self) -> None:
        if not self._controller:
            return
        self._controller.stop(no_assert=True)
        self._controller = None


def _authenticator(config: SmtpProxyConfig):
    expected_username = config.username.encode("utf-8")
    expected_password = config.password.encode("utf-8")

    def authenticate(server, session, envelope, mechanism, auth_data) -> AuthResult:
        login = b""
        password = b""
        if isinstance(auth_data, LoginPassword):
            login = auth_data.login
            password = auth_data.password
        success = hmac.compare_digest(login, expected_username) and hmac.compare_digest(
            password,
            expected_password,
        )
        if success:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_auth_succeeded",
                    mechanism=str(mechanism or "unknown"),
                    peer=_peer_host(session),
                ),
            )
            return AuthResult(success=True)

        delay_seconds = max(0.0, config.auth_failure_delay_seconds)
        LOGGER.info(
            "audit %s",
            audit_event(
                "smtp_auth_failed",
                delay_seconds=delay_seconds,
                mechanism=str(mechanism or "unknown"),
                peer=_peer_host(session),
            ),
        )
        if delay_seconds:
            time.sleep(delay_seconds)
        return AuthResult(
            success=False,
            handled=False,
            message="535 5.7.8 Authentication credentials invalid",
        )

    return authenticate


def _excluded_auth_mechanisms(config: SmtpProxyConfig):
    if config.auth_login_enabled:
        return []
    return ["LOGIN"]


def _sender_allowed(config: SmtpProxyConfig, sender: str) -> bool:
    if not config.user_mailboxes:
        return True

    normalized_sender = normalize_email_address(sender or "")
    if not normalized_sender:
        return False

    allowed = {
        normalized
        for normalized in (
            normalize_email_address(mailbox)
            for mailbox in config.user_mailboxes
        )
        if normalized
    }
    return normalized_sender in allowed


def _peer_host(session) -> str:
    peer = getattr(session, "peer", None)
    if isinstance(peer, tuple) and peer:
        return str(peer[0])
    if peer:
        return str(peer)
    return "unknown"


def _tls_settings(config: SmtpProxyConfig):
    tls_context = _tls_context(config)
    if tls_context is None:
        return None, None, False, False

    tls_mode = config.tls_mode.strip().lower()
    if tls_mode not in TLS_MODES:
        raise RuntimeError(
            "SMTP_PROXY_TLS_MODE must be 'starttls' or 'implicit'."
        )

    if tls_mode == "implicit":
        # aiosmtpd's auth_require_tls only recognizes STARTTLS upgrades. With
        # implicit TLS, the socket is encrypted before SMTP handling begins.
        return tls_context, None, False, False

    return None, tls_context, config.require_tls, True


def _tls_context(config: SmtpProxyConfig) -> Optional[ssl.SSLContext]:
    tls_requested = config.require_tls or bool(config.tls_cert_file or config.tls_key_file)
    if not tls_requested:
        return None

    if not config.tls_cert_file or not config.tls_key_file:
        raise RuntimeError(
            "SMTP proxy TLS requires both SMTP_PROXY_TLS_CERT_FILE and SMTP_PROXY_TLS_KEY_FILE."
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if hasattr(ssl, "TLSVersion"):
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=config.tls_cert_file,
        keyfile=config.tls_key_file,
    )
    return context


def _suppress_auth_tls_warning(
    config: SmtpProxyConfig,
    controller_ssl_context: Optional[ssl.SSLContext],
    smtp_tls_context: Optional[ssl.SSLContext],
    auth_require_tls: bool,
) -> bool:
    return (
        config.require_auth
        and controller_ssl_context is not None
        and smtp_tls_context is None
        and not auth_require_tls
        and config.tls_mode.strip().lower() == "implicit"
    )


def _resolve_listen_port(host: str, port: int) -> int:
    if port != 0:
        return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
