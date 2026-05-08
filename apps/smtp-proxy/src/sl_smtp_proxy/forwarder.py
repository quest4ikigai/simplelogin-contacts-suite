from __future__ import annotations

import logging
import smtplib
from email import policy
from email.message import Message
from typing import Iterable

from .config import SmtpProxyConfig


LOGGER = logging.getLogger(__name__)


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

        try:
            with smtplib.SMTP(
                self.config.upstream_host,
                self.config.upstream_port,
                timeout=self.config.upstream_timeout_seconds,
            ) as smtp:
                smtp.ehlo()
                if self.config.upstream_starttls:
                    smtp.starttls()
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
                "upstream_smtp_forward_failed host=%s port=%s starttls=%s auth_configured=%s error_type=%s error=%s",
                self.config.upstream_host,
                self.config.upstream_port,
                self.config.upstream_starttls,
                bool(self.config.upstream_username or self.config.upstream_password),
                type(exc).__name__,
                _safe_error_message(exc),
            )
            raise UpstreamForwardingError(
                "Upstream SMTP unavailable. Message not sent to avoid unsafe delivery."
            ) from exc


def _safe_error_message(exc: BaseException) -> str:
    message = str(exc).replace("\n", " ").replace("\r", " ").strip()
    return message[:300] if message else type(exc).__name__
