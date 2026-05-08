from __future__ import annotations

import logging as stdlib_logging
from typing import Optional

from alias_routing_core import TransformPlan


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
        reason=plan.rejection_reason or "none",
    )


def configure_logging(level: str) -> None:
    stdlib_logging.basicConfig(
        level=getattr(stdlib_logging, level.upper(), stdlib_logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
