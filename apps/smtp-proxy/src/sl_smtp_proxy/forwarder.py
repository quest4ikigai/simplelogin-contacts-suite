from __future__ import annotations

import logging
import smtplib
import ssl
from email import policy
from email.message import Message
from typing import Any, Dict, Iterable, Optional

from .config import SmtpProxyConfig


LOGGER = logging.getLogger(__name__)
UPSTREAM_TLS_MODES = {"none", "starttls", "implicit"}

# Ordered most-specific-first: smtplib's own exception hierarchy has several
# subclasses of SMTPResponseException (auth, connect, data, sender/recipient
# refusal, ...), so a generic SMTPResponseException check must come last
# among them or it would mask the more specific category.
_SMTP_ERROR_CATEGORIES = (
    (smtplib.SMTPRecipientsRefused, "recipients_refused"),
    (smtplib.SMTPAuthenticationError, "auth_failed"),
    (smtplib.SMTPConnectError, "connect_failed"),
    (smtplib.SMTPServerDisconnected, "server_disconnected"),
    (smtplib.SMTPResponseException, "smtp_response_error"),
    (smtplib.SMTPException, "smtp_protocol_error"),
)
_NETWORK_ERROR_CATEGORIES = (
    (TimeoutError, "timeout"),
    (ConnectionRefusedError, "connection_error"),
    (ConnectionResetError, "connection_error"),
    (ConnectionAbortedError, "connection_error"),
    (OSError, "network_error"),
)


class UpstreamForwardingError(RuntimeError):
    def __init__(self, public_message: str, *, ambiguous_delivery: bool = False):
        super().__init__(public_message)
        self.public_message = public_message
        # True when the failure occurred during or after the message bytes
        # were already handed to the upstream server (e.g. the connection
        # was lost or timed out while waiting for sendmail()'s final
        # reply): the server may have already received and accepted the
        # message, so this is not a confirmed non-delivery. False means
        # the failure is known to have happened before any message data
        # was sent (connect/EHLO/STARTTLS/AUTH, or a definitive rejection
        # reply such as SMTPRecipientsRefused/SMTPSenderRefused/
        # SMTPDataError), so nothing was delivered.
        self.ambiguous_delivery = ambiguous_delivery


class UpstreamSmtpForwarder:
    def __init__(self, config: SmtpProxyConfig):
        self.config = config

    def forward(self, sender: str, recipients: Iterable[str], message: Message) -> None:
        recipient_list = list(recipients)
        if not recipient_list:
            raise UpstreamForwardingError("No deliverable recipients after SimpleLogin routing")

        tls_mode = _upstream_tls_mode(self.config)
        tls_context = _upstream_tls_context(self.config) if tls_mode != "none" else None

        # Managed manually rather than via `with smtp:`: that context
        # manager's __exit__ sends QUIT and raises SMTPResponseException
        # if the server's reply to it isn't 221. sendmail() returning
        # without an exception already means the message was fully
        # accepted (its own final 250 reply was received), so a QUIT-phase
        # failure afterward -- a bad reply code, or the connection simply
        # dropping -- must never be allowed to turn that confirmed
        # delivery into a reported failure. It is purely post-delivery
        # session teardown, swallowed unconditionally below.
        try:
            smtp = _connect_upstream(self.config, tls_mode, tls_context)
        except (OSError, smtplib.SMTPException) as exc:
            self._raise_forwarding_error(exc, tls_mode, ambiguous_delivery=False)

        try:
            smtp.ehlo()
            if tls_mode == "starttls":
                smtp.starttls(context=tls_context)
                smtp.ehlo()
            if self.config.upstream_username or self.config.upstream_password:
                smtp.login(self.config.upstream_username, self.config.upstream_password)
            try:
                smtp.sendmail(
                    sender,
                    recipient_list,
                    message.as_bytes(policy=policy.SMTP),
                )
            except (
                smtplib.SMTPRecipientsRefused,
                smtplib.SMTPSenderRefused,
                smtplib.SMTPDataError,
            ):
                # The server gave a definitive rejection reply (refused
                # the envelope, or replied with an error code to the
                # completed DATA command): nothing was or will be
                # delivered. Confirmed, not ambiguous.
                raise
            except (OSError, smtplib.SMTPException) as exc:
                # The connection was lost or timed out while sendmail()
                # was transmitting the envelope/DATA or waiting for its
                # final reply. The message bytes may already be on the
                # wire (or even fully received and accepted) by the
                # time this happened, so whether anything was actually
                # delivered is unknown.
                self._raise_forwarding_error(exc, tls_mode, ambiguous_delivery=True)
        except (OSError, smtplib.SMTPException) as exc:
            self._raise_forwarding_error(exc, tls_mode, ambiguous_delivery=False)
        finally:
            try:
                smtp.quit()
            except Exception:
                try:
                    smtp.close()
                except Exception:
                    pass

    def _raise_forwarding_error(
        self, exc: BaseException, tls_mode: str, *, ambiguous_delivery: bool
    ) -> None:
        error_fields = safe_forwarding_error_fields(exc)
        LOGGER.warning(
            "upstream_smtp_forward_failed host=%s port=%s tls_mode=%s tls_verify=%s "
            "auth_configured=%s error_type=%s error_category=%s smtp_code=%s "
            "refused_recipient_count=%s ambiguous_delivery=%s",
            self.config.upstream_host,
            self.config.upstream_port,
            tls_mode,
            self.config.upstream_tls_verify,
            bool(self.config.upstream_username or self.config.upstream_password),
            error_fields["error_type"],
            error_fields["error_category"],
            error_fields.get("smtp_code", "none"),
            error_fields.get("refused_recipient_count", "none"),
            ambiguous_delivery,
        )
        raise UpstreamForwardingError(
            "Upstream SMTP unavailable. Message not sent to avoid unsafe delivery.",
            ambiguous_delivery=ambiguous_delivery,
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


def safe_forwarding_error_fields(exc: BaseException) -> Dict[str, Any]:
    """Structured, non-leaking classification of a forwarding exception.

    Deliberately never touches str(exc) or exception attributes that can
    carry recipient addresses, upstream response text, or credentials --
    smtplib.SMTPRecipientsRefused embeds every refused address in
    .recipients, and SMTPResponseException/subclasses carry the upstream
    server's raw response text in .smtp_error, which can itself echo an
    address back (e.g. "mailbox name not allowed: alice@example.com").
    Truncating those strings is not enough, since the sensitive content
    can appear in the first few characters. Only the exception's type
    name, a bounded category label, a numeric SMTP response code, and a
    recipient *count* are safe enough to log or audit as-is.
    """
    fields: Dict[str, Any] = {"error_type": type(exc).__name__}
    smtp_code = getattr(exc, "smtp_code", None)
    if isinstance(smtp_code, int):
        fields["smtp_code"] = smtp_code
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        fields["refused_recipient_count"] = len(exc.recipients)

    for exc_type, category in _SMTP_ERROR_CATEGORIES:
        if isinstance(exc, exc_type):
            fields["error_category"] = category
            return fields
    for exc_type, category in _NETWORK_ERROR_CATEGORIES:
        if isinstance(exc, exc_type):
            fields["error_category"] = category
            return fields
    fields["error_category"] = "unexpected"
    return fields
