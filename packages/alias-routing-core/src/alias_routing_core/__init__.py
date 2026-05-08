from .classifier import classify_address, matches_alias_suffix_domain, normalize_email_address
from .models import (
    RecipientClassification,
    RoutingContext,
    TransformAction,
    TransformPlan,
    TransformPlanItem,
)
from .planner import build_transform_plan, select_simplelogin_alias, select_simplelogin_alias_with_source

__all__ = [
    "RecipientClassification",
    "RoutingContext",
    "TransformAction",
    "TransformPlan",
    "TransformPlanItem",
    "build_transform_plan",
    "classify_address",
    "matches_alias_suffix_domain",
    "normalize_email_address",
    "select_simplelogin_alias",
    "select_simplelogin_alias_with_source",
]
