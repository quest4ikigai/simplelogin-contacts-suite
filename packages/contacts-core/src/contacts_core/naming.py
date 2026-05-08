from __future__ import annotations


def generated_contact_display_name(
    contact_name: str,
    alias_email: str,
    prefix: str = "SL",
) -> str:
    cleaned_name = (contact_name or "").strip()
    cleaned_alias = (alias_email or "").strip()
    if cleaned_name and cleaned_alias:
        return f"{prefix} · {cleaned_name} · {cleaned_alias}"
    if cleaned_name:
        return f"{prefix} · {cleaned_name}"
    if cleaned_alias:
        return f"{prefix} · {cleaned_alias}"
    return prefix
