from __future__ import annotations

from email.utils import parseaddr
from typing import Iterable, Optional, Set

from simplelogin_client import Alias, AliasContact, SimpleLoginClient

from .cache import SQLiteAliasCache
from .config import SmtpProxyConfig


class ReverseAliasResolutionError(RuntimeError):
    def __init__(self, public_message: str):
        super().__init__(public_message)
        self.public_message = public_message


class ReverseAliasResolver:
    def __init__(
        self,
        config: SmtpProxyConfig,
        cache: Optional[SQLiteAliasCache] = None,
        client: Optional[SimpleLoginClient] = None,
    ):
        self.config = config
        self.cache = cache or SQLiteAliasCache(config.cache_path)
        self.client = client or _client_from_config(config)

    def __call__(self, recipient: str, selected_alias: str) -> Optional[str]:
        alias_id = self._alias_id_for_email(selected_alias)
        contact_email = _contact_email(recipient)

        cached = self.cache.find_contact(alias_id, contact_email)
        if cached:
            reverse_alias_address, block_forward = cached
            if block_forward:
                raise ReverseAliasResolutionError("reverse alias contact is blocked")
            return reverse_alias_address

        contact = self.client.get_or_create_contact(alias_id, recipient)
        self._cache_contact(contact, alias_id, contact_email)
        if contact.block_forward:
            raise ReverseAliasResolutionError("reverse alias contact is blocked")
        return contact.reverse_alias_address

    def refresh_aliases(self) -> None:
        self._cache_aliases(self.client.list_aliases())

    def owned_alias_emails(self) -> Set[str]:
        if self.cache.aliases_need_refresh(self.config.cache_alias_ttl_seconds):
            self.refresh_aliases()
        return set(self.cache.alias_emails())

    def _alias_id_for_email(self, selected_alias: str) -> str:
        alias_id = self.cache.find_alias_id_by_email(selected_alias)
        if alias_id:
            return alias_id

        self.refresh_aliases()
        alias_id = self.cache.find_alias_id_by_email(selected_alias)
        if alias_id:
            return alias_id

        raise ReverseAliasResolutionError("selected SimpleLogin alias was not found")

    def _cache_aliases(self, aliases: Iterable[Alias]) -> None:
        for alias in aliases:
            self.cache.upsert_alias(alias.id, alias.email, alias.name or "", alias.enabled)

    def _cache_contact(self, contact: AliasContact, alias_id: str, contact_email: str) -> None:
        self.cache.upsert_contact(
            contact_id=contact.id,
            alias_id=contact.alias_id or alias_id,
            contact=contact.contact,
            contact_email=contact_email,
            reverse_alias_address=contact.reverse_alias_address,
            block_forward=contact.block_forward,
        )


def _client_from_config(config: SmtpProxyConfig) -> SimpleLoginClient:
    if not config.simplelogin_api_key:
        raise ReverseAliasResolutionError("SimpleLogin API key is not configured")
    return SimpleLoginClient(
        base_url=config.simplelogin_base_url,
        api_key=config.simplelogin_api_key,
        timeout_seconds=config.simplelogin_timeout_seconds,
    )


def resolver_from_config(config: SmtpProxyConfig) -> Optional[ReverseAliasResolver]:
    if not config.simplelogin_api_key:
        return None
    return ReverseAliasResolver(config)


def _contact_email(value: str) -> str:
    _, parsed = parseaddr(value or "")
    address = (parsed or value or "").strip()
    if not address:
        raise ReverseAliasResolutionError("recipient email address is invalid")
    return address.casefold()
