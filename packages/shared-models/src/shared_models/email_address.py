from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Optional


EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")


def parse_email_address(value: str) -> Optional[str]:
    _, parsed = parseaddr(value or "")
    address = (parsed or value or "").strip()
    if not EMAIL_RE.match(address):
        return None
    return address


def normalize_email_address(value: str) -> Optional[str]:
    address = parse_email_address(value)
    if not address:
        return None
    local, domain = address.rsplit("@", 1)
    return f"{local}@{domain.lower()}".casefold()
