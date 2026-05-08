from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class GeneratedContact:
    display_name: str
    reverse_alias_address: str
    alias_email: str
    alias_id: Optional[str] = None
    contact_id: Optional[str] = None
    original_contact: Optional[str] = None
