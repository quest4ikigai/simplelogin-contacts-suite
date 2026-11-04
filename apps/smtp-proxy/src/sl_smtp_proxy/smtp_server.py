from __future__ import annotations

import asyncio
import functools
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from email import policy
from email.message import Message
import hmac
import logging
import socket
import ssl
import time
import warnings
from typing import Dict, Optional, Sequence

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword, SMTP
from alias_routing_core import normalize_email_address
from simplelogin_client import RequestStats

from .cache import SQLiteAliasCache
from .config import SmtpProxyConfig
from .config_validation import validate_startup_config
from .forwarder import UpstreamForwardingError, UpstreamSmtpForwarder
from .logging import audit_event, plan_audit_fields, plan_summary, redact_address, safe_reason
from .message_transform import (
    apply_transform,
    build_plan_for_message,
    parse_message,
    transformed_envelope_recipients,
)
from .mime_sender_validation import validate_mime_sender
from .reverse_alias_resolver import ResolutionStats, ReverseAliasResolver, resolver_from_config
from .safety_verifier import verify_post_transform_safety, visible_recipient_count


LOGGER = logging.getLogger(__name__)


def _new_correlation_id() -> str:
    return uuid.uuid4().hex[:12]


def _forward_fingerprint(sender: str, recipients: Sequence[str], message: Message) -> str:
    """Fingerprint a forwarded message for duplicate-submission suppression.

    Prefers the message's own Message-Id (set once by the originating MUA
    and normally preserved across a client-side retry of the same
    compose) and falls back to a content hash when it is absent. This is
    a best-effort defense, not a delivery guarantee: a client that
    generates a new Message-Id per retry will not be caught by it.
    """
    message_id = (message.get("Message-Id") or "").strip()
    if message_id:
        content_key = message_id
    else:
        content_key = hashlib.sha256(message.as_bytes(policy=policy.SMTP)).hexdigest()
    normalized_sender = normalize_email_address(sender) or (sender or "").casefold()
    normalized_recipients = sorted(
        normalize_email_address(recipient) or recipient.casefold() for recipient in recipients
    )
    raw = "|".join([normalized_sender, ",".join(normalized_recipients), content_key])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _swallow_task_exception(task: "asyncio.Task") -> None:
    # Safety net for the shielded forwarding task: if the client
    # disconnects, handle_DATA stops awaiting this task (though it keeps
    # running independently), so nothing else is guaranteed to retrieve
    # its result. Without this, asyncio logs "Task exception was never
    # retrieved" once the task is garbage collected. The real audit
    # logging for the outcome always happens inside the task itself.
    if task.cancelled():
        return
    task.exception()
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
        self._dedup_cache = SQLiteAliasCache(config.cache_path)
        # Separate bounded pools for resolution (SimpleLogin API/cache work)
        # and forwarding (upstream SMTP) so a burst of large messages can't
        # spawn unbounded threads, and so one stage can't starve the other.
        self._resolver_executor = ThreadPoolExecutor(
            max_workers=max(1, config.resolver_max_workers),
            thread_name_prefix="sl-resolver",
        )
        self._forward_executor = ThreadPoolExecutor(
            max_workers=max(1, config.forward_max_workers),
            thread_name_prefix="sl-forward",
        )

    def close(self) -> None:
        self._resolver_executor.shutdown(wait=False)
        self._forward_executor.shutdown(wait=False)

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
        correlation_id = _new_correlation_id()
        peer = _peer_host(session)
        loop = asyncio.get_running_loop()
        started = time.monotonic()
        phase = "parsing"
        timings: Dict[str, int] = {}
        request_stats = RequestStats()
        resolution_stats = ResolutionStats()
        try:
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
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="mime_sender_validation",
                        header=mime_sender_validation.header,
                        reason=mime_sender_validation.reason,
                        from_count=mime_sender_validation.from_count,
                        sender_count=mime_sender_validation.sender_count,
                    ),
                )
                return "550 MIME sender address is not allowed by SimpleLogin proxy policy"

            phase = "alias_refresh"
            alias_refresh_started = time.monotonic()
            extra_simplelogin_aliases = set()
            if self.config.strip_own_aliases and hasattr(self.reverse_alias_resolver, "owned_alias_emails"):
                # Only our own ReverseAliasResolver's owned_alias_emails()
                # understands request_stats; an injected/duck-typed
                # resolver (as used in tests and custom deployments) keeps
                # its original no-argument contract.
                if isinstance(self.reverse_alias_resolver, ReverseAliasResolver):
                    owned_alias_call = functools.partial(
                        self.reverse_alias_resolver.owned_alias_emails,
                        request_stats=request_stats,
                    )
                else:
                    owned_alias_call = self.reverse_alias_resolver.owned_alias_emails
                try:
                    extra_simplelogin_aliases = await loop.run_in_executor(
                        self._resolver_executor,
                        owned_alias_call,
                    )
                except Exception as exc:
                    public_message = getattr(exc, "public_message", type(exc).__name__)
                    LOGGER.info(
                        "audit %s",
                        audit_event(
                            "smtp_message_rejected",
                            peer=peer,
                            correlation_id=correlation_id,
                            policy="alias_refresh_failed",
                            reason=safe_reason(f"SimpleLogin alias refresh failed: {public_message}"),
                        ),
                    )
                    return f"550 SimpleLogin alias refresh failed: {public_message}"
            timings["alias_refresh_ms"] = int((time.monotonic() - alias_refresh_started) * 1000)

            # Recipient resolution runs in a worker thread: it can make
            # many blocking SimpleLogin HTTP requests for a bulk send, and
            # must never block the event loop (and therefore health
            # checks and other connections) while it does.
            phase = "resolution"
            resolution_started = time.monotonic()
            message, plan = await loop.run_in_executor(
                self._resolver_executor,
                functools.partial(
                    build_plan_for_message,
                    envelope.mail_from or "",
                    list(envelope.rcpt_tos),
                    data,
                    self.config,
                    reverse_alias_resolver=self.reverse_alias_resolver,
                    extra_simplelogin_aliases=extra_simplelogin_aliases,
                    request_stats=request_stats,
                    resolution_stats=resolution_stats,
                ),
            )
            timings["resolution_ms"] = int((time.monotonic() - resolution_started) * 1000)
            self.last_plan = plan
            LOGGER.info("transform_plan %s", plan_summary(plan, self.config.log_redact_addresses))
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_transform_plan",
                    peer=peer,
                    correlation_id=correlation_id,
                    simplelogin_request_count=request_stats.request_count,
                    simplelogin_request_duration_ms=int(request_stats.total_duration_seconds * 1000),
                    cache_hit_count=resolution_stats.cache_hits,
                    cache_miss_count=resolution_stats.cache_misses,
                    contacts_found=resolution_stats.contacts_found,
                    contacts_created=resolution_stats.contacts_created,
                    **timings,
                    **plan_audit_fields(plan, self.config.log_redact_addresses),
                ),
            )
            if plan.rejected:
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_message_rejected",
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="transform_plan_rejected",
                        reason=safe_reason(plan.rejection_reason),
                    ),
                )
                return f"550 {plan.rejection_reason or 'Message rejected by SimpleLogin proxy policy'}"

            phase = "transform"
            transform_started = time.monotonic()
            transformed_message = apply_transform(message, plan, self.config)
            transformed_recipients = transformed_envelope_recipients(plan)
            verification = verify_post_transform_safety(
                transformed_message,
                transformed_recipients,
                self.config,
                plan,
                extra_simplelogin_aliases=extra_simplelogin_aliases,
            )
            timings["transform_validate_ms"] = int((time.monotonic() - transform_started) * 1000)
            if not verification.accepted:
                LOGGER.info(
                    "audit %s",
                    audit_event(
                        "smtp_message_rejected",
                        peer=peer,
                        correlation_id=correlation_id,
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
                        peer=peer,
                        correlation_id=correlation_id,
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
                        peer=peer,
                        correlation_id=correlation_id,
                        policy="dry_run",
                        reason="SimpleLogin SMTP proxy dry-run: message not forwarded",
                    ),
                )
                return "550 SimpleLogin SMTP proxy dry-run: message not forwarded"

            phase = "duplicate_check"
            fingerprint = None
            if self.config.duplicate_suppression_window_seconds > 0:
                fingerprint = _forward_fingerprint(
                    envelope.mail_from or "", transformed_recipients, transformed_message
                )
                try:
                    is_duplicate = self._dedup_cache.was_recently_forwarded(
                        fingerprint, self.config.duplicate_suppression_window_seconds
                    )
                except Exception:
                    # Duplicate suppression is a best-effort safety net, not
                    # a delivery gate: a local cache/disk problem must not
                    # block legitimate mail. Fail open here and still try
                    # to forward normally.
                    LOGGER.exception("Duplicate-submission cache lookup failed; forwarding anyway")
                    is_duplicate = False
                if is_duplicate:
                    LOGGER.info(
                        "audit %s",
                        audit_event(
                            "smtp_message_rejected",
                            peer=peer,
                            correlation_id=correlation_id,
                            policy="duplicate_suppressed",
                            reason="duplicate_suppressed",
                            recipient_count=len(transformed_recipients),
                        ),
                    )
                    return (
                        "550 Duplicate submission suppressed: an identical message "
                        "was already forwarded recently"
                    )

            # Forwarding runs as an independent, shielded task: if the
            # client disconnects while this is in flight, handle_DATA's
            # own await is cancelled (as it must be, so the connection
            # teardown proceeds normally), but the forwarding task keeps
            # running to completion and always logs its real outcome --
            # an upstream send already accepted by Proton Bridge is never
            # silently dropped on the floor just because nobody is left
            # to read the SMTP response.
            phase = "forwarding"
            forward_started = time.monotonic()
            forward_task = asyncio.ensure_future(
                self._forward_and_record(
                    correlation_id=correlation_id,
                    peer=peer,
                    sender=envelope.mail_from or "",
                    recipients=transformed_recipients,
                    message=transformed_message,
                    fingerprint=fingerprint,
                    started=forward_started,
                )
            )
            forward_task.add_done_callback(_swallow_task_exception)
            try:
                await asyncio.shield(forward_task)
            except UpstreamForwardingError as exc:
                return f"550 {exc.public_message}"
            return "250 Message accepted for delivery"
        except asyncio.CancelledError:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_client_disconnected_during_processing",
                    peer=peer,
                    correlation_id=correlation_id,
                    phase=phase,
                    elapsed_ms=int((time.monotonic() - started) * 1000),
                ),
            )
            raise

    async def _forward_and_record(
        self,
        correlation_id: str,
        peer: str,
        sender: str,
        recipients,
        message: Message,
        fingerprint: Optional[str],
        started: float,
    ) -> None:
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                self._forward_executor,
                self.forwarder.forward,
                sender,
                recipients,
                message,
            )
        except UpstreamForwardingError as exc:
            LOGGER.info(
                "audit %s",
                audit_event(
                    "smtp_message_rejected",
                    peer=peer,
                    correlation_id=correlation_id,
                    policy="upstream_unavailable",
                    reason=safe_reason(exc.public_message),
                    recipient_count=len(recipients),
                    forward_duration_ms=int((time.monotonic() - started) * 1000),
                ),
            )
            raise

        if fingerprint:
            try:
                self._dedup_cache.record_forwarded(fingerprint)
            except Exception:
                LOGGER.exception("Failed to record forwarded-message dedup fingerprint")
        LOGGER.info(
            "audit %s",
            audit_event(
                "smtp_message_forwarded",
                peer=peer,
                correlation_id=correlation_id,
                recipient_count=len(recipients),
                forward_duration_ms=int((time.monotonic() - started) * 1000),
            ),
        )

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
        validate_startup_config(self.config)
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
        self.handler.close()
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
