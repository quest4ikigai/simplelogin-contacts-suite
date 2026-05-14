from __future__ import annotations

from dataclasses import dataclass
from email.message import Message
from email.utils import getaddresses
from typing import Iterable, List, Sequence, Set, Tuple

from alias_routing_core import normalize_email_address

from .config import SmtpProxyConfig


@dataclass(frozen=True)
class MimeSenderValidationResult:
    accepted: bool
    header: str = "none"
    reason: str = "accepted"
    from_count: int = 0
    sender_count: int = 0


def validate_mime_sender(
    message: Message,
    config: SmtpProxyConfig,
) -> MimeSenderValidationResult:
    """Validate visible sender headers when USER_MAILBOXES constrains identity."""
    if not config.user_mailboxes:
        return MimeSenderValidationResult(accepted=True)

    allowed_mailboxes = _normalized_mailboxes(config.user_mailboxes)
    from_values = message.get_all("From", [])
    from_addresses, invalid_from_count = _normalized_header_addresses(from_values)
    sender_addresses, invalid_sender_count = _normalized_header_addresses(
        message.get_all("Sender", [])
    )

    if not from_values:
        return _reject(
            "from",
            "from_missing",
            from_count=len(from_addresses),
            sender_count=len(sender_addresses),
        )
    if not from_addresses or invalid_from_count:
        return _reject(
            "from",
            "from_invalid",
            from_count=len(from_addresses),
            sender_count=len(sender_addresses),
        )
    if any(address not in allowed_mailboxes for address in from_addresses):
        return _reject(
            "from",
            "from_not_allowed",
            from_count=len(from_addresses),
            sender_count=len(sender_addresses),
        )

    sender_present = bool(message.get_all("Sender", []))
    if sender_present:
        if not sender_addresses or invalid_sender_count:
            return _reject(
                "sender",
                "sender_invalid",
                from_count=len(from_addresses),
                sender_count=len(sender_addresses),
            )
        if any(address not in allowed_mailboxes for address in sender_addresses):
            return _reject(
                "sender",
                "sender_not_allowed",
                from_count=len(from_addresses),
                sender_count=len(sender_addresses),
            )

    return MimeSenderValidationResult(
        accepted=True,
        from_count=len(from_addresses),
        sender_count=len(sender_addresses),
    )


def _normalized_mailboxes(mailboxes: Iterable[str]) -> Set[str]:
    return {
        normalized
        for normalized in (normalize_email_address(mailbox) for mailbox in mailboxes)
        if normalized
    }


def _normalized_header_addresses(values: Sequence[str]) -> Tuple[List[str], int]:
    normalized_addresses: List[str] = []
    invalid_count = 0
    for _, address in getaddresses(values):
        normalized = normalize_email_address(address)
        if normalized:
            normalized_addresses.append(normalized)
        else:
            invalid_count += 1
    return normalized_addresses, invalid_count


def _reject(
    header: str,
    reason: str,
    *,
    from_count: int,
    sender_count: int,
) -> MimeSenderValidationResult:
    return MimeSenderValidationResult(
        accepted=False,
        header=header,
        reason=reason,
        from_count=from_count,
        sender_count=sender_count,
    )
