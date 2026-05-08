from __future__ import annotations

import asyncio
import hmac
import logging
import socket
from typing import Optional

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

from .config import SmtpProxyConfig
from .forwarder import UpstreamForwardingError, UpstreamSmtpForwarder
from .logging import plan_summary
from .message_transform import apply_transform, build_plan_for_message, transformed_envelope_recipients
from .reverse_alias_resolver import resolver_from_config


LOGGER = logging.getLogger(__name__)


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

    async def handle_DATA(self, server, session, envelope) -> str:
        content = envelope.original_content
        if content is None:
            content = envelope.content
        if isinstance(content, str):
            data = content.encode("utf-8", errors="replace")
        else:
            data = bytes(content or b"")

        extra_simplelogin_aliases = set()
        if self.config.strip_own_aliases and hasattr(self.reverse_alias_resolver, "owned_alias_emails"):
            try:
                extra_simplelogin_aliases = self.reverse_alias_resolver.owned_alias_emails()
            except Exception as exc:
                public_message = getattr(exc, "public_message", type(exc).__name__)
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
        if plan.rejected:
            return f"550 {plan.rejection_reason or 'Message rejected by SimpleLogin proxy policy'}"

        transformed_message = apply_transform(message, plan, self.config)
        transformed_recipients = transformed_envelope_recipients(plan)
        if not transformed_recipients:
            return "550 No deliverable recipients after SimpleLogin routing"
        if self.config.dry_run:
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
            return f"550 {exc.public_message}"
        return "250 Message accepted for delivery"

    def handle_exception(self, error: Exception) -> str:
        LOGGER.exception("SMTP proxy handler failed: %s", type(error).__name__)
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
        if self.config.require_tls:
            raise RuntimeError(
                "SMTP_PROXY_REQUIRE_TLS is set, but TLS certificates are not configured yet."
            )

        self._controller = Controller(
            self.handler,
            hostname=self.config.host,
            port=_resolve_listen_port(self.config.host, self.config.port),
            ready_timeout=5.0,
            server_hostname="simplelogin-smtp-proxy",
            data_size_limit=self.config.max_message_bytes,
            decode_data=False,
            auth_required=self.config.require_auth,
            auth_require_tls=False,
            authenticator=_authenticator(self.config) if self.config.require_auth else None,
            auth_exclude_mechanism=["LOGIN"],
            command_call_limit={"RCPT": 500, "NOOP": 20, "RSET": 20, "*": 100},
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
            return AuthResult(success=True)
        return AuthResult(
            success=False,
            handled=False,
            message="535 5.7.8 Authentication credentials invalid",
        )

    return authenticate


def _resolve_listen_port(host: str, port: int) -> int:
    if port != 0:
        return port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
