from __future__ import annotations

from typing import Callable, Iterable, List, Optional, Tuple

from .classifier import (
    classify_address,
    matches_alias_suffix_domain,
    normalize_email_address,
)
from .models import (
    RecipientClassification,
    RoutingContext,
    TransformAction,
    TransformPlan,
    TransformPlanItem,
)


ReverseAliasResolver = Callable[[str, str], Optional[str]]

HEADER_ALIAS_SOURCE = "header"
ALIAS_SELECTOR_SOURCE = "alias_selector"
COVER_RECIPIENT_SOURCE = "cover_recipient"
RECIPIENT_ALIAS_SOURCE = "recipient_alias"
MULTIPLE_ALIAS_ERROR = "Multiple distinct SimpleLogin aliases specified"


def _selected_from_header(header_alias: Optional[str]) -> Optional[str]:
    if not header_alias:
        return None
    return normalize_email_address(header_alias)


def _matches_known_own_alias(value: str, context: RoutingContext) -> bool:
    normalized = normalize_email_address(value)
    if not normalized:
        return False
    return normalized in {
        candidate
        for candidate in (normalize_email_address(item) for item in context.own_simplelogin_aliases)
        if candidate
    }


def _is_own_alias(value: str, context: RoutingContext) -> bool:
    return matches_alias_suffix_domain(value, context) or _matches_known_own_alias(value, context)


def _normalized_aliases(values: Iterable[str], context: RoutingContext) -> List[str]:
    aliases: List[str] = []
    seen = set()
    for value in values:
        if not _is_own_alias(value, context):
            continue
        normalized = normalize_email_address(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        aliases.append(normalized)
    return aliases


def _contains_normalized(values: Iterable[str], normalized_alias: str) -> bool:
    return normalized_alias in {
        candidate
        for candidate in (normalize_email_address(value) for value in values)
        if candidate
    }


def select_simplelogin_alias_with_source(
    alias_selector_recipients: Iterable[str],
    context: RoutingContext,
    header_alias: Optional[str] = None,
    cover_recipient_candidates: Optional[Iterable[str]] = None,
    alias_candidate_recipients: Optional[Iterable[str]] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    header_selected = _selected_from_header(header_alias)
    recipient_aliases = _normalized_aliases(alias_candidate_recipients or [], context)

    distinct_aliases: List[str] = []
    seen = set()
    for alias in [header_selected] + recipient_aliases:
        if not alias or alias in seen:
            continue
        seen.add(alias)
        distinct_aliases.append(alias)

    if len(distinct_aliases) > 1:
        return None, None, MULTIPLE_ALIAS_ERROR
    if not distinct_aliases:
        return None, None, None

    selected_alias = distinct_aliases[0]
    if _contains_normalized(cover_recipient_candidates or [], selected_alias):
        return selected_alias, COVER_RECIPIENT_SOURCE, None
    if header_selected == selected_alias:
        return selected_alias, HEADER_ALIAS_SOURCE, None
    if _contains_normalized(alias_selector_recipients, selected_alias):
        return selected_alias, ALIAS_SELECTOR_SOURCE, None
    return selected_alias, RECIPIENT_ALIAS_SOURCE, None


def select_simplelogin_alias(
    alias_selector_recipients: Iterable[str],
    context: RoutingContext,
    header_alias: Optional[str] = None,
    cover_recipient_candidates: Optional[Iterable[str]] = None,
    alias_candidate_recipients: Optional[Iterable[str]] = None,
) -> Optional[str]:
    alias, _, _ = select_simplelogin_alias_with_source(
        alias_selector_recipients,
        context,
        header_alias=header_alias,
        cover_recipient_candidates=cover_recipient_candidates,
        alias_candidate_recipients=alias_candidate_recipients,
    )
    return alias


def _item_for_classification(
    original: str,
    classification: RecipientClassification,
    selected_alias: Optional[str],
    context: RoutingContext,
    reverse_alias_resolver: Optional[ReverseAliasResolver],
) -> TransformPlanItem:
    if classification == RecipientClassification.OWN_SIMPLELOGIN_ALIAS:
        action = TransformAction.DROP if context.strip_own_aliases else TransformAction.REJECT
        return TransformPlanItem(
            original=original,
            classification=classification,
            action=action,
            reason="own SimpleLogin alias",
        )

    if classification == RecipientClassification.OWN_MAILBOX:
        action = TransformAction.DROP if context.strip_own_mailboxes else TransformAction.REJECT
        return TransformPlanItem(
            original=original,
            classification=classification,
            action=action,
            reason="own mailbox",
        )

    if classification == RecipientClassification.KNOWN_REVERSE_ALIAS:
        return TransformPlanItem(original, classification, TransformAction.KEEP)

    if classification == RecipientClassification.PROBABLE_REVERSE_ALIAS:
        if context.keep_unknown_simplelogin_addresses:
            return TransformPlanItem(
                original=original,
                classification=classification,
                action=TransformAction.KEEP,
                warning=True,
                reason="unknown SimpleLogin-looking address kept",
            )
        return TransformPlanItem(
            original=original,
            classification=classification,
            action=TransformAction.REJECT,
            reason="unknown SimpleLogin-looking address",
        )

    if classification == RecipientClassification.EXTERNAL_RECIPIENT:
        if not selected_alias:
            return TransformPlanItem(
                original=original,
                classification=classification,
                action=TransformAction.REJECT,
                reason="SimpleLogin alias selection required",
            )
        if context.allow_direct_external_send:
            return TransformPlanItem(
                original=original,
                classification=classification,
                action=TransformAction.KEEP,
                warning=True,
                reason="direct external send explicitly allowed",
            )
        if not reverse_alias_resolver:
            return TransformPlanItem(
                original=original,
                classification=classification,
                action=TransformAction.REJECT,
                reason="reverse alias resolver unavailable",
            )
        try:
            replacement = reverse_alias_resolver(original, selected_alias)
        except Exception as exc:  # pragma: no cover - exact client errors live above this package.
            public_message = getattr(exc, "public_message", type(exc).__name__)
            return TransformPlanItem(
                original=original,
                classification=classification,
                action=TransformAction.REJECT,
                reason=f"reverse alias lookup failed: {public_message}",
            )
        if not replacement:
            return TransformPlanItem(
                original=original,
                classification=classification,
                action=TransformAction.REJECT,
                reason="reverse alias lookup returned no address",
            )
        return TransformPlanItem(
            original=original,
            classification=classification,
            action=TransformAction.REWRITE,
            replacement=replacement,
        )

    return TransformPlanItem(
        original=original,
        classification=RecipientClassification.INVALID_OR_UNSUPPORTED,
        action=TransformAction.REJECT,
        reason="invalid or unsupported recipient",
    )


def build_transform_plan(
    recipients: Iterable[str],
    context: RoutingContext,
    header_alias: Optional[str] = None,
    alias_selector_recipients: Optional[Iterable[str]] = None,
    cover_recipient_candidates: Optional[Iterable[str]] = None,
    reverse_alias_resolver: Optional[ReverseAliasResolver] = None,
) -> TransformPlan:
    recipient_list = list(recipients)
    selected_alias, selected_alias_source, selection_error = select_simplelogin_alias_with_source(
        list(alias_selector_recipients or []),
        context,
        header_alias=header_alias,
        cover_recipient_candidates=cover_recipient_candidates,
        alias_candidate_recipients=recipient_list,
    )

    actions = []
    warnings = []
    effective_selected_alias = None if selection_error else selected_alias
    for recipient in recipient_list:
        classification, _ = classify_address(recipient, context)
        item = _item_for_classification(
            recipient,
            classification,
            effective_selected_alias,
            context,
            reverse_alias_resolver,
        )
        actions.append(item)
        if item.warning and item.reason:
            warnings.append(item.reason)

    rejected_items = [item for item in actions if item.action == TransformAction.REJECT]
    rejected = bool(selection_error or rejected_items) and context.fail_closed
    if selection_error and rejected:
        rejection_reason = selection_error
    else:
        rejection_reason = rejected_items[0].reason if rejected else None

    return TransformPlan(
        selected_alias=selected_alias,
        selected_alias_source=selected_alias_source,
        actions=actions,
        rejected=rejected,
        rejection_reason=rejection_reason,
        warnings=warnings,
    )
