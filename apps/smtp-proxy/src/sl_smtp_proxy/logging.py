from __future__ import annotations

import json
import logging as stdlib_logging
from typing import Any, Dict, Optional

from alias_routing_core import TransformPlan, TransformAction


def redact_address(value: Optional[str]) -> str:
    if not value:
        return ""
    if "@" not in value:
        return "[REDACTED]"
    local, domain = value.rsplit("@", 1)
    if len(local) <= 2:
        redacted_local = local[:1] + "*"
    else:
        redacted_local = f"{local[0]}***{local[-1]}"
    return f"{redacted_local}@{domain}"


def safe_reason(value: Optional[str]) -> str:
    if not value:
        return "none"
    reason = " ".join(str(value).replace("\r", " ").replace("\n", " ").split())
    safe_exact = {
        "SimpleLogin alias selection required",
        "Multiple distinct SimpleLogin aliases specified",
        "own SimpleLogin alias",
        "own mailbox",
        "unknown SimpleLogin-looking address",
        "reverse alias resolver unavailable",
        "reverse alias lookup returned no address",
        "invalid or unsupported recipient",
        "selected SimpleLogin alias was not found",
        "reverse alias contact is blocked",
        "No deliverable recipients after SimpleLogin routing",
        "SimpleLogin SMTP proxy dry-run: message not forwarded",
        "Upstream SMTP unavailable. Message not sent to avoid unsafe delivery.",
    }
    if reason in safe_exact:
        return reason
    if reason.startswith("reverse alias lookup failed:"):
        return "reverse alias lookup failed"
    if reason.startswith("SimpleLogin alias refresh failed:"):
        return "SimpleLogin alias refresh failed"
    return type(value).__name__


def plan_summary(plan: TransformPlan, redact_addresses: bool = True) -> str:
    counts = plan.action_counts()
    alias = plan.selected_alias or ""
    if redact_addresses:
        alias = redact_address(alias)
    return (
        "selected_alias={alias} keep={keep} drop={drop} rewrite={rewrite} "
        "reject={reject} rejected={rejected} reason={reason}"
    ).format(
        alias=alias or "none",
        keep=counts.get("KEEP", 0),
        drop=counts.get("DROP", 0),
        rewrite=counts.get("REWRITE", 0),
        reject=counts.get("REJECT", 0),
        rejected=plan.rejected,
        reason=safe_reason(plan.rejection_reason),
    )


def plan_audit_fields(plan: TransformPlan, redact_addresses: bool = True) -> Dict[str, Any]:
    counts = plan.action_counts()
    selected_alias = plan.selected_alias or ""
    if redact_addresses:
        selected_alias = redact_address(selected_alias)
    return {
        "selected_alias": selected_alias or "none",
        "selected_alias_source": plan.selected_alias_source or "none",
        "keep_count": counts.get(TransformAction.KEEP.value, 0),
        "drop_count": counts.get(TransformAction.DROP.value, 0),
        "rewrite_count": counts.get(TransformAction.REWRITE.value, 0),
        "reject_count": counts.get(TransformAction.REJECT.value, 0),
        "rejected": plan.rejected,
        "reason": safe_reason(plan.rejection_reason),
    }


def audit_event(event: str, **fields: Any) -> str:
    payload = {"event": event}
    payload.update(fields)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def configure_logging(level: str) -> None:
    stdlib_logging.basicConfig(
        level=getattr(stdlib_logging, level.upper(), stdlib_logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
