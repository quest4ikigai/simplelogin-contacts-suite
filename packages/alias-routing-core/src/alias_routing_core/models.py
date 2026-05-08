from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class RecipientClassification(str, Enum):
    OWN_SIMPLELOGIN_ALIAS = "OWN_SIMPLELOGIN_ALIAS"
    OWN_MAILBOX = "OWN_MAILBOX"
    KNOWN_REVERSE_ALIAS = "KNOWN_REVERSE_ALIAS"
    PROBABLE_REVERSE_ALIAS = "PROBABLE_REVERSE_ALIAS"
    EXTERNAL_RECIPIENT = "EXTERNAL_RECIPIENT"
    INVALID_OR_UNSUPPORTED = "INVALID_OR_UNSUPPORTED"


class TransformAction(str, Enum):
    KEEP = "KEEP"
    DROP = "DROP"
    REWRITE = "REWRITE"
    REJECT = "REJECT"


@dataclass
class RoutingContext:
    own_simplelogin_aliases: Set[str] = field(default_factory=set)
    own_mailboxes: Set[str] = field(default_factory=set)
    known_reverse_aliases: Set[str] = field(default_factory=set)
    alias_suffix_domains: Set[str] = field(default_factory=set)
    probable_reverse_alias_domains: Set[str] = field(default_factory=lambda: {"simplelogin.co"})
    keep_unknown_simplelogin_addresses: bool = True
    strip_own_aliases: bool = True
    strip_own_mailboxes: bool = True
    allow_direct_external_send: bool = False
    fail_closed: bool = True


@dataclass
class TransformPlanItem:
    original: str
    classification: RecipientClassification
    action: TransformAction
    replacement: Optional[str] = None
    reason: Optional[str] = None
    warning: bool = False


@dataclass
class TransformPlan:
    selected_alias: Optional[str]
    actions: List[TransformPlanItem]
    selected_alias_source: Optional[str] = None
    rejected: bool = False
    rejection_reason: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    def action_counts(self) -> Dict[str, int]:
        counts = {
            TransformAction.KEEP.value: 0,
            TransformAction.DROP.value: 0,
            TransformAction.REWRITE.value: 0,
            TransformAction.REJECT.value: 0,
        }
        for item in self.actions:
            counts[item.action.value] += 1
        return counts

    def rewritten_recipients(self) -> List[str]:
        recipients: List[str] = []
        for item in self.actions:
            if item.action == TransformAction.REWRITE and item.replacement:
                recipients.append(item.replacement)
            elif item.action == TransformAction.KEEP:
                recipients.append(item.original)
        return recipients
