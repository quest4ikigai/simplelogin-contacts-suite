from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Optional, Tuple

from .models import RecipientClassification, RoutingContext


EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")


def normalize_email_address(value: str) -> Optional[str]:
    if not value:
        return None
    _, parsed = parseaddr(value)
    address = (parsed or value).strip()
    if not EMAIL_RE.match(address):
        return None
    local, domain = address.rsplit("@", 1)
    return f"{local}@{domain.lower()}".casefold()


def matches_alias_suffix_domain(value: str, context: RoutingContext) -> bool:
    normalized = normalize_email_address(value)
    if not normalized:
        return False
    for suffix in context.alias_suffix_domains:
        cleaned = suffix.strip().casefold()
        if cleaned and normalized.endswith(cleaned):
            return True
    return False


def _normalized_membership(value: str, candidates) -> bool:
    normalized = normalize_email_address(value)
    if not normalized:
        return False
    return normalized in {
        candidate
        for candidate in (normalize_email_address(item) for item in candidates)
        if candidate
    }


def classify_address(value: str, context: RoutingContext) -> Tuple[RecipientClassification, Optional[str]]:
    normalized = normalize_email_address(value)
    if not normalized:
        return RecipientClassification.INVALID_OR_UNSUPPORTED, None

    if matches_alias_suffix_domain(value, context):
        return RecipientClassification.OWN_SIMPLELOGIN_ALIAS, None

    if _normalized_membership(value, context.own_simplelogin_aliases):
        return RecipientClassification.OWN_SIMPLELOGIN_ALIAS, None

    if _normalized_membership(value, context.own_mailboxes):
        return RecipientClassification.OWN_MAILBOX, None

    if _normalized_membership(value, context.known_reverse_aliases):
        return RecipientClassification.KNOWN_REVERSE_ALIAS, None

    domain = normalized.rsplit("@", 1)[1]
    probable_domains = {item.casefold() for item in context.probable_reverse_alias_domains}
    if domain in probable_domains:
        return RecipientClassification.PROBABLE_REVERSE_ALIAS, None

    return RecipientClassification.EXTERNAL_RECIPIENT, None
