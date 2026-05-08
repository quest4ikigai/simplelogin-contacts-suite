from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

from .errors import SimpleLoginApiError, SimpleLoginConfigError, redact_values
from .models import Alias, AliasContact, normalized_email


PAGE_SIZE_ASSUMPTION = 20


class SimpleLoginClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout_seconds: int = 30,
        session: Optional[requests.Session] = None,
    ):
        if not base_url:
            raise SimpleLoginConfigError("SimpleLogin base URL is required")
        if not api_key:
            raise SimpleLoginConfigError("SimpleLogin API key is required")

        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds
        self.session = session or requests.Session()
        self.session.headers.update({
            "Authentication": api_key,
            "Content-Type": "application/json",
            "User-Agent": "simplelogin-alias-suite/0.1",
        })

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method,
                url,
                params=params,
                json=json,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            message = redact_values(str(exc), [self.api_key])
            raise SimpleLoginApiError(f"SimpleLogin API request failed: {message}") from exc

        if response.status_code >= 400:
            body = redact_values(response.text[:500], [self.api_key])
            raise SimpleLoginApiError(
                f"SimpleLogin API request failed: HTTP {response.status_code}: {body}",
                status_code=response.status_code,
            )

        try:
            return response.json()
        except ValueError as exc:
            raise SimpleLoginApiError("SimpleLogin API returned invalid JSON") from exc

    def list_aliases(self) -> List[Alias]:
        aliases: List[Alias] = []
        page = 0
        while True:
            data = self._request("GET", "/api/v2/aliases", params={"page_id": page})
            batch = data.get("aliases", [])
            aliases.extend(Alias.from_api(item) for item in batch)
            if len(batch) < PAGE_SIZE_ASSUMPTION:
                break
            page += 1
        return aliases

    def list_contacts(self, alias_id: str) -> List[AliasContact]:
        contacts: List[AliasContact] = []
        page = 0
        while True:
            data = self._request("GET", f"/api/aliases/{alias_id}/contacts", params={"page_id": page})
            batch = data.get("contacts", [])
            contacts.extend(AliasContact.from_api(item, alias_id=str(alias_id)) for item in batch)
            if len(batch) < PAGE_SIZE_ASSUMPTION:
                break
            page += 1
        return contacts

    def create_contact(self, alias_id: str, contact: str) -> AliasContact:
        data = self._request(
            "POST",
            f"/api/aliases/{alias_id}/contacts",
            json={"contact": contact},
        )
        payload = data.get("contact") if isinstance(data.get("contact"), dict) else data
        return AliasContact.from_api(payload, alias_id=str(alias_id))

    def get_or_create_contact(self, alias_id: str, contact: str) -> AliasContact:
        wanted = normalized_email(contact)
        for existing in self.list_contacts(alias_id):
            if normalized_email(existing.contact) == wanted:
                return existing
        return self.create_contact(alias_id, contact)


def client_from_env() -> SimpleLoginClient:
    base_url = os.environ.get("SIMPLELOGIN_BASE_URL")
    api_key = os.environ.get("SIMPLELOGIN_API_KEY")
    if not base_url:
        raise SimpleLoginConfigError("SIMPLELOGIN_BASE_URL is required")
    if not api_key:
        raise SimpleLoginConfigError("SIMPLELOGIN_API_KEY is required")
    return SimpleLoginClient(base_url=base_url, api_key=api_key)
