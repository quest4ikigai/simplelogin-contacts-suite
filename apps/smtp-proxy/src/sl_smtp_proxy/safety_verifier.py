from __future__ import annotations

from dataclasses import dataclass
from email.message import Message
from email.utils import getaddresses
from typing import Iterable, List, Optional, Tuple

from alias_routing_core import (
    RecipientClassification,
    TransformPlan,
    classify_address,
    normalize_email_address,
)

from .config import SmtpProxyConfig


CONTROL_HEADER_PREFIX = "x-simplelogin-"
COVER_RECIPIENT_SOURCE = "cover_recipient"


@dataclass(frozen=True)
class SafetyVerificationResult:
    accepted: bool
    invariant: str = "accepted"
    location: str = "none"
    reason: str = "accepted"


def verify_post_transform_safety(
    message: Message,
    envelope_recipients: Iterable[str],
    config: SmtpProxyConfig,
    plan: TransformPlan,
    extra_simplelogin_aliases: Optional[Iterable[str]] = None,
) -> SafetyVerificationResult:
    """Verify final message state immediately before upstream forwarding."""
    if message.get_all("Bcc"):
        return _reject("no_bcc_header", "headers", "bcc_header_present")

    if _control_headers(message):
        return _reject(
            "no_simplelogin_control_headers",
            "headers",
            "simplelogin_control_header_present",
        )

    context = config.routing_context(extra_simplelogin_aliases=extra_simplelogin_aliases)
    for recipient in envelope_recipients:
        classification = classify_address(recipient, context)[0]
        if classification == RecipientClassification.EXTERNAL_RECIPIENT:
            if not config.allow_direct_external_send:
                return _reject(
                    "no_direct_external_envelope_recipients",
                    "envelope",
                    "direct_external_envelope_recipient",
                )
        elif classification == RecipientClassification.OWN_SIMPLELOGIN_ALIAS:
            return _reject(
                "no_own_identity_envelope_recipients",
                "envelope",
                "own_simplelogin_alias_envelope_recipient",
            )
        elif classification == RecipientClassification.OWN_MAILBOX:
            return _reject(
                "no_own_identity_envelope_recipients",
                "envelope",
                "own_mailbox_envelope_recipient",
            )

    preserved_cover_alias_count = 0
    for header_name, address in _visible_header_addresses(message):
        classification = classify_address(address, context)[0]
        if classification == RecipientClassification.EXTERNAL_RECIPIENT:
            if not config.allow_direct_external_send:
                return _reject(
                    "no_direct_external_visible_recipients",
                    header_name.lower(),
                    "direct_external_visible_recipient",
                )
        elif classification == RecipientClassification.OWN_SIMPLELOGIN_ALIAS:
            if _is_allowed_cover_recipient(header_name, address, plan):
                preserved_cover_alias_count += 1
                continue
            return _reject(
                "no_own_identity_visible_recipients",
                header_name.lower(),
                "own_simplelogin_alias_visible_recipient",
            )
        elif classification == RecipientClassification.OWN_MAILBOX:
            return _reject(
                "no_own_identity_visible_recipients",
                header_name.lower(),
                "own_mailbox_visible_recipient",
            )

    if preserved_cover_alias_count > 1:
        return _reject(
            "single_cover_recipient_alias",
            "to",
            "multiple_cover_recipient_aliases_visible",
        )

    return SafetyVerificationResult(accepted=True)


def visible_recipient_count(message: Message) -> int:
    return len(_visible_header_addresses(message))


def _reject(invariant: str, location: str, reason: str) -> SafetyVerificationResult:
    return SafetyVerificationResult(
        accepted=False,
        invariant=invariant,
        location=location,
        reason=reason,
    )


def _control_headers(message: Message) -> List[str]:
    return [
        header
        for header in message.keys()
        if header.lower().startswith(CONTROL_HEADER_PREFIX)
    ]


def _visible_header_addresses(message: Message) -> List[Tuple[str, str]]:
    addresses: List[Tuple[str, str]] = []
    for header_name in ("To", "Cc"):
        for _, address in getaddresses(message.get_all(header_name, [])):
            if address:
                addresses.append((header_name, address))
    return addresses


def _is_allowed_cover_recipient(header_name: str, address: str, plan: TransformPlan) -> bool:
    if header_name.lower() != "to" or plan.selected_alias_source != COVER_RECIPIENT_SOURCE:
        return False
    selected_alias = normalize_email_address(plan.selected_alias or "")
    normalized_address = normalize_email_address(address)
    return bool(selected_alias and normalized_address == selected_alias)
