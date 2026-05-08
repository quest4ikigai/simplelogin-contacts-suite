from __future__ import annotations

from dataclasses import dataclass
from email.utils import parseaddr
from typing import Any, Dict, Optional


def parsed_email(value: str) -> str:
    _, parsed = parseaddr(value or "")
    return (parsed or value or "").strip()


def normalized_email(value: str) -> str:
    return parsed_email(value).casefold()


@dataclass(frozen=True)
class Alias:
    id: str
    email: str
    name: Optional[str] = None
    enabled: bool = True

    @classmethod
    def from_api(cls, data: Dict[str, Any]) -> "Alias":
        alias_id = data.get("id") or data.get("alias_id")
        email = data.get("email") or data.get("alias")
        if alias_id is None or not email:
            raise ValueError("SimpleLogin alias response is missing id or email")
        return cls(
            id=str(alias_id),
            email=str(email),
            name=data.get("name") or data.get("note"),
            enabled=bool(data.get("enabled", True)),
        )


@dataclass(frozen=True)
class AliasContact:
    id: str
    alias_id: str
    contact: str
    reverse_alias: Optional[str]
    reverse_alias_address: str
    block_forward: bool = False

    @classmethod
    def from_api(cls, data: Dict[str, Any], alias_id: str = "") -> "AliasContact":
        contact_id = data.get("id") or data.get("contact_id")
        contact = data.get("contact") or ""
        reverse_alias = data.get("reverse_alias")
        reverse_alias_address = data.get("reverse_alias_address") or parsed_email(reverse_alias or "")
        if contact_id is None or not contact or not reverse_alias_address:
            raise ValueError("SimpleLogin contact response is missing id, contact, or reverse alias")
        return cls(
            id=str(contact_id),
            alias_id=str(data.get("alias_id") or alias_id),
            contact=str(contact),
            reverse_alias=reverse_alias,
            reverse_alias_address=str(reverse_alias_address),
            block_forward=bool(data.get("block_forward", False)),
        )
