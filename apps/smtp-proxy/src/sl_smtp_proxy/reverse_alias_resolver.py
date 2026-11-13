from __future__ import annotations

from dataclasses import dataclass
from email.utils import parseaddr
from typing import Dict, Iterable, List, Optional, Set

from simplelogin_client import Alias, AliasContact, RequestStats, SimpleLoginClient
from simplelogin_client.models import normalized_email

from .cache import SQLiteAliasCache
from .config import SmtpProxyConfig


class ReverseAliasResolutionError(RuntimeError):
    def __init__(self, public_message: str):
        super().__init__(public_message)
        self.public_message = public_message


@dataclass
class ResolutionStats:
    """Counters describing how a bulk resolve_bulk() call was satisfied.

    cache_hits/cache_misses count distinct contact email addresses, not
    individual recipient list entries, so callers can see at a glance how
    much of a bulk send was served from the local SQLite cache versus the
    SimpleLogin API.
    """

    cache_hits: int = 0
    cache_misses: int = 0
    contacts_found: int = 0
    contacts_created: int = 0
    list_contacts_calls: int = 0


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

    def __call__(
        self,
        recipient: str,
        selected_alias: str,
        request_stats: Optional[RequestStats] = None,
    ) -> Optional[str]:
        alias_id = self._alias_id_for_email(selected_alias, request_stats=request_stats)
        contact_email = _contact_email(recipient)

        cached = self.cache.find_contact(alias_id, contact_email)
        if cached and not self.cache.contact_needs_refresh(
            alias_id,
            contact_email,
            self.config.cache_contact_ttl_seconds,
        ):
            reverse_alias_address, block_forward = cached
            if block_forward:
                raise ReverseAliasResolutionError("reverse alias contact is blocked")
            return reverse_alias_address

        contact = self.client.get_or_create_contact(alias_id, recipient, stats=request_stats)
        self._cache_contact(contact, alias_id, contact_email)
        if contact.block_forward:
            raise ReverseAliasResolutionError("reverse alias contact is blocked")
        return contact.reverse_alias_address

    def refresh_aliases(self, request_stats: Optional[RequestStats] = None) -> None:
        self._cache_aliases(self.client.list_aliases(stats=request_stats))

    def owned_alias_emails(self, request_stats: Optional[RequestStats] = None) -> Set[str]:
        if self.cache.aliases_need_refresh(self.config.cache_alias_ttl_seconds):
            self.refresh_aliases(request_stats=request_stats)
        return set(self.cache.alias_emails())

    def resolve_bulk(
        self,
        recipients: Iterable[str],
        selected_alias: Optional[str],
        request_stats: Optional[RequestStats] = None,
    ) -> ResolutionStats:
        """Best-effort bulk warm-up of the reverse-alias cache.

        Pre-populates the SQLite cache for every recipient in one (or a
        few, for pagination) SimpleLogin API round trips instead of one
        full contact-list fetch per recipient. This is purely a
        performance optimization: it never raises, and on any failure it
        simply leaves recipients uncached so the normal per-recipient
        __call__ path (used by build_transform_plan) falls back to its
        existing, already-correct, slower resolution and error handling.
        """
        stats = ResolutionStats()
        recipient_list = list(recipients)
        if not selected_alias or not recipient_list:
            return stats

        try:
            alias_id = self._alias_id_for_email(selected_alias, request_stats=request_stats)
        except ReverseAliasResolutionError:
            return stats

        original_by_email: Dict[str, str] = {}
        for recipient in recipient_list:
            try:
                email = _contact_email(recipient)
            except ReverseAliasResolutionError:
                continue
            original_by_email.setdefault(email, recipient)

        contact_emails = list(original_by_email.keys())
        if not contact_emails:
            return stats

        try:
            cached = self.cache.find_contacts_bulk(
                alias_id,
                contact_emails,
                self.config.cache_contact_ttl_seconds,
            )
        except Exception:
            cached = {}

        needs_fetch = [
            email for email in contact_emails if email not in cached or cached[email][2]
        ]
        stats.cache_hits = len(contact_emails) - len(needs_fetch)
        stats.cache_misses = len(needs_fetch)
        if not needs_fetch:
            return stats

        try:
            contacts = self.client.list_contacts(alias_id, stats=request_stats)
        except Exception:
            # Fall back entirely to the per-recipient slow path; it will
            # surface this same failure (and reject fail-closed) for any
            # recipient that actually needs a reverse alias.
            return stats
        stats.list_contacts_calls = 1

        by_email: Dict[str, AliasContact] = {}
        for contact in contacts:
            by_email[normalized_email(contact.contact)] = contact

        to_cache: List[tuple] = []
        for email in needs_fetch:
            contact = by_email.get(email)
            if contact is not None:
                stats.contacts_found += 1
            else:
                try:
                    contact = self.client.create_contact(
                        alias_id,
                        original_by_email[email],
                        stats=request_stats,
                    )
                except Exception:
                    # Leave this one recipient uncached; __call__ will
                    # retry it individually and raise/report the real
                    # error through the existing fail-closed path.
                    continue
                stats.contacts_created += 1
            to_cache.append(
                (
                    contact.id,
                    contact.alias_id or alias_id,
                    contact.contact,
                    email,
                    contact.reverse_alias_address,
                    contact.block_forward,
                )
            )

        if to_cache:
            try:
                self.cache.upsert_contacts_bulk(to_cache)
            except Exception:
                pass

        return stats

    def _alias_id_for_email(
        self,
        selected_alias: str,
        request_stats: Optional[RequestStats] = None,
    ) -> str:
        alias_id = self.cache.find_alias_id_by_email(selected_alias)
        if alias_id:
            return alias_id

        self.refresh_aliases(request_stats=request_stats)
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
