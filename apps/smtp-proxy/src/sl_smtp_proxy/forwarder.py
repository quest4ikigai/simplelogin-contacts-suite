from __future__ import annotations

import logging
import smtplib
import ssl
from email import policy
from email.message import Message
from typing import Iterable, Optional

from .config import SmtpProxyConfig


LOGGER = logging.getLogger(__name__)
UPSTREAM_TLS_MODES = {"none", "starttls", "implicit"}


class UpstreamForwardingError(RuntimeError):
    def __init__(self, public_message: str):
        super().__init__(public_message)
        self.public_message = public_message


class UpstreamSmtpForwarder:
    def __init__(self, config: SmtpProxyConfig):
        self.config = config

    def forward(self, sender: str, recipients: Iterable[str], message: Message) -> None:
        recipient_list = list(recipients)
        if not recipient_list:
            raise UpstreamForwardingError("No deliverable recipients after SimpleLogin routing")

        tls_mode = _upstream_tls_mode(self.config)
        tls_context = _upstream_tls_context(self.config) if tls_mode != "none" else None

        try:
            with _connect_upstream(self.config, tls_mode, tls_context) as smtp:
                smtp.ehlo()
                if tls_mode == "starttls":
                    smtp.starttls(context=tls_context)
                    smtp.ehlo()
                if self.config.upstream_username or self.config.upstream_password:
                    smtp.login(self.config.upstream_username, self.config.upstream_password)
                smtp.sendmail(
                    sender,
                    recipient_list,
                    message.as_bytes(policy=policy.SMTP),
                )
        except (OSError, smtplib.SMTPException) as exc:
            LOGGER.warning(
                "upstream_smtp_forward_failed host=%s port=%s tls_mode=%s tls_verify=%s auth_configured=%s error_type=%s error=%s",
                self.config.upstream_host,
                self.config.upstream_port,
                tls_mode,
                self.config.upstream_tls_verify,
                bool(self.config.upstream_username or self.config.upstream_password),
                type(exc).__name__,
                _safe_error_message(exc),
            )
            raise UpstreamForwardingError(
                "Upstream SMTP unavailable. Message not sent to avoid unsafe delivery."
            ) from exc


def _connect_upstream(
    config: SmtpProxyConfig,
    tls_mode: str,
    tls_context: Optional[ssl.SSLContext],
):
    if tls_mode == "implicit":
        return smtplib.SMTP_SSL(
            config.upstream_host,
            config.upstream_port,
            timeout=config.upstream_timeout_seconds,
            context=tls_context,
        )

    return smtplib.SMTP(
        config.upstream_host,
        config.upstream_port,
        timeout=config.upstream_timeout_seconds,
    )


def _upstream_tls_mode(config: SmtpProxyConfig) -> str:
    tls_mode = config.upstream_tls_mode.strip().lower()
    if tls_mode not in UPSTREAM_TLS_MODES:
        raise UpstreamForwardingError(
            "Invalid upstream SMTP TLS mode. Use 'none', 'starttls', or 'implicit'."
        )
    return tls_mode


def _upstream_tls_context(config: SmtpProxyConfig) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not config.upstream_tls_verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def _safe_error_message(exc: BaseException) -> str:
    message = str(exc).replace("\n", " ").replace("\r", " ").strip()
    return message[:300] if message else type(exc).__name__
