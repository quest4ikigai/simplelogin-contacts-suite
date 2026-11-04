from __future__ import annotations

import logging
from collections import Counter
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import formataddr, getaddresses
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

from alias_routing_core import (
    RecipientClassification,
    TransformAction,
    TransformPlan,
    build_transform_plan,
    classify_address,
    normalize_email_address,
    select_simplelogin_alias_with_source,
)
from simplelogin_client import RequestStats

from .config import SmtpProxyConfig
from .reverse_alias_resolver import ResolutionStats


LOGGER = logging.getLogger(__name__)


CONTROL_HEADER_PREFIX = "x-simplelogin-"


def parse_message(data: bytes) -> Message:
    return BytesParser(policy=policy.default).parsebytes(data)


def _addresses_from_headers(message: Message, header_names: Sequence[str]) -> List[str]:
    values: List[str] = []
    for header in header_names:
        values.extend(message.get_all(header, []))
    return [address for _, address in getaddresses(values) if address]


def _dedupe_addresses(addresses: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for address in addresses:
        normalized = normalize_email_address(address)
        key = normalized or address.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(address)
    return result


def collect_recipients(message: Message, envelope_recipients: Iterable[str]) -> List[str]:
    return _dedupe_addresses(list(envelope_recipients) + _addresses_from_headers(message, ["To", "Cc", "Bcc"]))


def collect_bcc_selector_candidates(message: Message, envelope_recipients: Iterable[str]) -> List[str]:
    visible = Counter(
        normalized
        for normalized in (
            normalize_email_address(address)
            for address in _addresses_from_headers(message, ["To", "Cc"])
        )
        if normalized
    )
    explicit_bcc = _addresses_from_headers(message, ["Bcc"])
    envelope_counts = Counter(
        normalized
        for normalized in (normalize_email_address(address) for address in envelope_recipients)
        if normalized
    )
    envelope_exemplars = {}
    for address in envelope_recipients:
        normalized = normalize_email_address(address)
        if normalized and normalized not in envelope_exemplars:
            envelope_exemplars[normalized] = address

    envelope_only = []
    for normalized, count in envelope_counts.items():
        if count > visible.get(normalized, 0):
            envelope_only.append(envelope_exemplars[normalized])
    return _dedupe_addresses(explicit_bcc + envelope_only)


def collect_alias_selector_recipients(message: Message, envelope_recipients: Iterable[str]) -> List[str]:
    return collect_bcc_selector_candidates(message, envelope_recipients)


def collect_cover_recipient_candidates(message: Message, envelope_recipients: Iterable[str]) -> List[str]:
    to_addresses = _addresses_from_headers(message, ["To"])
    if len(to_addresses) != 1:
        return []
    if not collect_bcc_selector_candidates(message, envelope_recipients):
        return []
    return to_addresses


def _prefetch_reverse_alias_contacts(
    recipients: List[str],
    alias_selectors: List[str],
    cover_recipient_candidates: List[str],
    header_alias: Optional[str],
    config: SmtpProxyConfig,
    reverse_alias_resolver,
    extra_simplelogin_aliases: Optional[Iterable[str]],
    request_stats: Optional[RequestStats],
    resolution_stats: Optional[ResolutionStats],
) -> None:
    resolve_bulk = getattr(reverse_alias_resolver, "resolve_bulk", None)
    if resolve_bulk is None:
        return

    context = config.routing_context(extra_simplelogin_aliases=extra_simplelogin_aliases)
    selected_alias, _source, selection_error = select_simplelogin_alias_with_source(
        alias_selectors,
        context,
        header_alias=header_alias,
        cover_recipient_candidates=cover_recipient_candidates,
        alias_candidate_recipients=recipients,
    )
    if selection_error or not selected_alias:
        return

    external_recipients = [
        recipient
        for recipient in recipients
        if classify_address(recipient, context)[0] == RecipientClassification.EXTERNAL_RECIPIENT
    ]
    if not external_recipients:
        return

    try:
        result = resolve_bulk(external_recipients, selected_alias, request_stats=request_stats)
    except Exception:  # pragma: no cover - best-effort prefetch only
        LOGGER.debug("Bulk reverse-alias prefetch failed; falling back to per-recipient resolution", exc_info=True)
        return

    if resolution_stats is not None and result is not None:
        resolution_stats.cache_hits = result.cache_hits
        resolution_stats.cache_misses = result.cache_misses
        resolution_stats.contacts_found = result.contacts_found
        resolution_stats.contacts_created = result.contacts_created
        resolution_stats.list_contacts_calls = result.list_contacts_calls


def build_plan_for_message(
    envelope_sender: str,
    envelope_recipients: Iterable[str],
    data: bytes,
    config: SmtpProxyConfig,
    reverse_alias_resolver: Optional[Callable[[str, str], Optional[str]]] = None,
    extra_simplelogin_aliases: Optional[Iterable[str]] = None,
    request_stats: Optional[RequestStats] = None,
    resolution_stats: Optional[ResolutionStats] = None,
) -> Tuple[Message, TransformPlan]:
    message = parse_message(data)
    envelope_recipient_list = list(envelope_recipients)
    recipients = collect_recipients(message, envelope_recipient_list)
    alias_selectors = collect_alias_selector_recipients(message, envelope_recipient_list)
    cover_recipient_candidates = collect_cover_recipient_candidates(message, envelope_recipient_list)
    header_alias = message.get("X-SimpleLogin-Alias")

    _prefetch_reverse_alias_contacts(
        recipients,
        alias_selectors,
        cover_recipient_candidates,
        header_alias,
        config,
        reverse_alias_resolver,
        extra_simplelogin_aliases,
        request_stats,
        resolution_stats,
    )

    plan = build_transform_plan(
        recipients,
        config.routing_context(extra_simplelogin_aliases=extra_simplelogin_aliases),
        header_alias=header_alias,
        alias_selector_recipients=alias_selectors,
        cover_recipient_candidates=cover_recipient_candidates,
        reverse_alias_resolver=reverse_alias_resolver,
    )
    return message, plan


def remove_control_headers(message: Message) -> None:
    for header in list(message.keys()):
        if header.lower().startswith(CONTROL_HEADER_PREFIX):
            del message[header]


def _replacement_for(original: str, plan: TransformPlan) -> Tuple[Optional[str], bool]:
    normalized_original = normalize_email_address(original)
    for item in plan.actions:
        if normalize_email_address(item.original) != normalized_original:
            continue
        if item.action == TransformAction.REWRITE:
            return item.replacement, True
        if item.action == TransformAction.KEEP:
            return original, True
        # DROP, REJECT, and any other non-deliverable action must never
        # surface the original literal address in a rewritten header: an
        # address the plan didn't clear for delivery must not leak into
        # visible headers just because it also wasn't explicitly dropped.
        return None, True
    return original, False


def _is_cover_to_header_address(header_name: str, address: str, plan: TransformPlan) -> bool:
    if header_name.lower() != "to" or plan.selected_alias_source != "cover_recipient":
        return False
    selected_alias = normalize_email_address(plan.selected_alias or "")
    normalized_address = normalize_email_address(address)
    return bool(selected_alias and normalized_address == selected_alias)


def rewrite_address_header(message: Message, header_name: str, plan: TransformPlan) -> None:
    values = message.get_all(header_name, [])
    if not values:
        return
    rewritten = []
    for display_name, address in getaddresses(values):
        if _is_cover_to_header_address(header_name, address, plan):
            rewritten.append(formataddr((display_name, address)))
            continue
        replacement, matched = _replacement_for(address, plan)
        if not matched:
            replacement = address
        if replacement:
            rewritten.append(formataddr((display_name, replacement)))

    del message[header_name]
    if rewritten:
        message[header_name] = ", ".join(rewritten)


def apply_transform(message: Message, plan: TransformPlan, config: SmtpProxyConfig) -> Message:
    remove_control_headers(message)
    rewrite_address_header(message, "To", plan)
    rewrite_address_header(message, "Cc", plan)
    if message.get("Bcc") is not None:
        del message["Bcc"]
    return message


def transformed_envelope_recipients(plan: TransformPlan) -> List[str]:
    return plan.rewritten_recipients()
