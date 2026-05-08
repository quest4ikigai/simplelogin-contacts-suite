import hashlib
import html
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote, urljoin, urlparse

import requests
import vobject


MANAGED_NOTE_MARKER = "Managed by simplelogin-nextcloud-contacts"
PAGE_SIZE_ASSUMPTION = 20
DEFAULT_REVERSE_ALIAS_EXCLUDE_REGEX = r"(?i)^(reply|no-reply)"
REVERSE_ALIAS_EXCLUDE_REGEX_FILE_ENV = "REVERSE_ALIAS_EXCLUDE_REGEX_FILE"


@dataclass
class Config:
    simplelogin_api_key: str
    simplelogin_base_url: str
    nextcloud_base_url: str
    nextcloud_username: str
    nextcloud_app_password: str
    addressbook_display_name: str
    addressbook_slug: str
    sync_interval_seconds: int
    dry_run: bool
    delete_stale: bool
    skip_blocked_contacts: bool
    deduplicate_contacts_by_original_email: bool
    alias_include_regex: Optional[str]
    alias_exclude_regex: Optional[str]
    reverse_alias_include_regex: Optional[str]
    reverse_alias_exclude_regexes: List[str]
    contact_name_prefix: str


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def env_regex(name: str, default: Optional[str] = None) -> Optional[str]:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw or None


def regex_file_as_alternation(name: str) -> Optional[str]:
    raw_path = os.environ.get(name)
    if not raw_path:
        return None

    path = os.path.expanduser(raw_path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            patterns = [
                line.strip()
                for line in handle
                if line.strip() and not line.lstrip().startswith("#")
            ]
    except OSError as exc:
        raise RuntimeError(f"Unable to read {name} file {raw_path!r}: {exc}") from exc

    if not patterns:
        return None

    alternatives = "|".join(f"(?:{pattern})" for pattern in patterns)
    return f"(?i)(?:{alternatives})"


def reverse_alias_exclude_regexes() -> List[str]:
    inline_regex = env_regex("REVERSE_ALIAS_EXCLUDE_REGEX")
    file_path = os.environ.get(REVERSE_ALIAS_EXCLUDE_REGEX_FILE_ENV)
    file_regex = regex_file_as_alternation(REVERSE_ALIAS_EXCLUDE_REGEX_FILE_ENV)

    if inline_regex is None and file_regex is None:
        if "REVERSE_ALIAS_EXCLUDE_REGEX" in os.environ or file_path:
            return []
        return [DEFAULT_REVERSE_ALIAS_EXCLUDE_REGEX]

    regexes = []
    if inline_regex:
        regexes.append(inline_regex)
    if file_regex:
        regexes.append(file_regex)
    return regexes


def load_config() -> Config:
    required = [
        "SIMPLELOGIN_API_KEY",
        "NEXTCLOUD_BASE_URL",
        "NEXTCLOUD_USERNAME",
        "NEXTCLOUD_APP_PASSWORD",
    ]
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

    return Config(
        simplelogin_api_key=os.environ["SIMPLELOGIN_API_KEY"],
        simplelogin_base_url=os.environ.get("SIMPLELOGIN_BASE_URL", "https://app.simplelogin.io").rstrip("/"),
        nextcloud_base_url=os.environ["NEXTCLOUD_BASE_URL"].rstrip("/"),
        nextcloud_username=os.environ["NEXTCLOUD_USERNAME"],
        nextcloud_app_password=os.environ["NEXTCLOUD_APP_PASSWORD"],
        addressbook_display_name=os.environ.get("NEXTCLOUD_ADDRESSBOOK_DISPLAY_NAME", "SimpleLogin"),
        addressbook_slug=os.environ.get("NEXTCLOUD_ADDRESSBOOK_SLUG", "simplelogin"),
        sync_interval_seconds=int(os.environ.get("SYNC_INTERVAL_SECONDS", "3600")),
        dry_run=env_bool("DRY_RUN", True),
        delete_stale=env_bool("DELETE_STALE", True),
        skip_blocked_contacts=env_bool("SKIP_BLOCKED_CONTACTS", True),
        deduplicate_contacts_by_original_email=env_bool(
            "DEDUPLICATE_CONTACTS_BY_ORIGINAL_EMAIL",
            True,
        ),
        alias_include_regex=os.environ.get("ALIAS_INCLUDE_REGEX") or None,
        alias_exclude_regex=os.environ.get("ALIAS_EXCLUDE_REGEX") or None,
        reverse_alias_include_regex=env_regex("REVERSE_ALIAS_INCLUDE_REGEX"),
        reverse_alias_exclude_regexes=reverse_alias_exclude_regexes(),
        contact_name_prefix=os.environ.get("CONTACT_NAME_PREFIX", "SL"),
    )


class SimpleLoginClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({
            "Authentication": cfg.simplelogin_api_key,
            "Content-Type": "application/json",
        })

    def get(self, path: str, params: Optional[dict] = None) -> dict:
        url = f"{self.cfg.simplelogin_base_url}{path}"
        response = self.session.get(url, params=params, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_all_aliases(self) -> List[dict]:
        aliases: List[dict] = []
        page = 0
        while True:
            data = self.get("/api/v2/aliases", params={"page_id": page})
            batch = data.get("aliases", [])
            aliases.extend(batch)
            if len(batch) < PAGE_SIZE_ASSUMPTION:
                break
            page += 1
        return aliases

    def get_all_contacts(self, alias_id: int) -> List[dict]:
        contacts: List[dict] = []
        page = 0
        while True:
            data = self.get(f"/api/aliases/{alias_id}/contacts", params={"page_id": page})
            batch = data.get("contacts", [])
            contacts.extend(batch)
            if len(batch) < PAGE_SIZE_ASSUMPTION:
                break
            page += 1
        return contacts


class NextcloudCardDavClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.auth = (cfg.nextcloud_username, cfg.nextcloud_app_password)
        self.session.headers.update({"User-Agent": "simplelogin-nextcloud-contacts/0.1"})
        escaped_user = quote(cfg.nextcloud_username, safe="")
        self.addressbooks_url = f"{cfg.nextcloud_base_url}/remote.php/dav/addressbooks/users/{escaped_user}/"
        self.addressbook_url = urljoin(self.addressbooks_url, f"{quote(cfg.addressbook_slug, safe='')}/")

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        response = self.session.request(method, url, timeout=45, **kwargs)
        if response.status_code in {401, 403}:
            raise RuntimeError(
                "Nextcloud authentication failed. Check NEXTCLOUD_USERNAME and NEXTCLOUD_APP_PASSWORD."
            )
        return response

    def ensure_addressbook(self, dry_run: bool) -> None:
        probe = self.request("PROPFIND", self.addressbook_url, headers={"Depth": "0"})
        if probe.status_code in {207, 200}:
            return
        if probe.status_code not in {404, 405}:
            raise RuntimeError(f"Failed to check address book: HTTP {probe.status_code} {probe.text[:300]}")

        body = f'''<?xml version="1.0" encoding="UTF-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav" xmlns:NC="http://nextcloud.org/ns">
  <D:set>
    <D:prop>
      <D:resourcetype>
        <D:collection/>
        <C:addressbook/>
      </D:resourcetype>
      <D:displayname>{xml_escape(self.cfg.addressbook_display_name)}</D:displayname>
    </D:prop>
  </D:set>
</D:mkcol>'''

        if dry_run:
            print(f"DRY_RUN: would create address book {self.addressbook_url}", flush=True)
            return

        created = self.request(
            "MKCOL",
            self.addressbook_url,
            headers={"Content-Type": "application/xml; charset=utf-8"},
            data=body.encode("utf-8"),
        )
        if created.status_code not in {201, 204}:
            raise RuntimeError(f"Failed to create address book: HTTP {created.status_code} {created.text[:500]}")

    def list_existing_managed_cards(self) -> Dict[str, str]:
        body = '''<?xml version="1.0" encoding="UTF-8"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:getetag/>
  </D:prop>
</D:propfind>'''
        response = self.request(
            "PROPFIND",
            self.addressbook_url,
            headers={"Depth": "1", "Content-Type": "application/xml; charset=utf-8"},
            data=body.encode("utf-8"),
        )
        if response.status_code == 404:
            return {}
        if response.status_code != 207:
            raise RuntimeError(f"Failed listing cards: HTTP {response.status_code} {response.text[:500]}")

        ns = {"D": "DAV:"}
        root = ET.fromstring(response.content)
        cards: Dict[str, str] = {}
        for resp in root.findall("D:response", ns):
            href_el = resp.find("D:href", ns)
            etag_el = resp.find(".//D:getetag", ns)
            if href_el is None or not href_el.text:
                continue
            href = href_el.text
            if not href.endswith(".vcf"):
                continue
            etag = etag_el.text if etag_el is not None and etag_el.text else ""
            filename = href.rstrip("/").split("/")[-1]
            if filename.startswith("sl-"):
                cards[filename] = etag
        return cards

    def put_card(self, filename: str, vcard_text: str, dry_run: bool) -> None:
        url = urljoin(self.addressbook_url, quote(filename, safe=""))
        if dry_run:
            print(f"DRY_RUN: would PUT {filename}", flush=True)
            return
        response = self.request(
            "PUT",
            url,
            headers={"Content-Type": "text/vcard; charset=utf-8"},
            data=vcard_text.encode("utf-8"),
        )
        if response.status_code not in {200, 201, 204}:
            raise RuntimeError(f"Failed PUT {filename}: HTTP {response.status_code} {response.text[:500]}")

    def delete_card(self, filename: str, dry_run: bool) -> None:
        url = urljoin(self.addressbook_url, quote(filename, safe=""))
        if dry_run:
            print(f"DRY_RUN: would DELETE {filename}", flush=True)
            return
        response = self.request("DELETE", url)
        if response.status_code not in {200, 202, 204, 404}:
            raise RuntimeError(f"Failed DELETE {filename}: HTTP {response.status_code} {response.text[:500]}")


def xml_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def alias_email(alias: dict) -> str:
    return alias.get("email") or alias.get("alias") or ""


def alias_display_name(alias: dict) -> str:
    return alias_email(alias) or f"alias-{alias.get('id')}"


def should_include_alias(cfg: Config, alias: dict) -> bool:
    if alias.get("enabled") is False:
        return False

    email = alias_email(alias)
    name = alias_display_name(alias)
    haystack = f"{email} {name}"
    if cfg.alias_include_regex and not re.search(cfg.alias_include_regex, haystack):
        return False
    if cfg.alias_exclude_regex and re.search(cfg.alias_exclude_regex, haystack):
        return False
    return True


def should_include_reverse_alias(cfg: Config, reverse_alias_address: str) -> bool:
    if cfg.reverse_alias_include_regex and not re.search(
        cfg.reverse_alias_include_regex,
        reverse_alias_address,
    ):
        return False
    for reverse_alias_exclude_regex in cfg.reverse_alias_exclude_regexes:
        if re.search(reverse_alias_exclude_regex, reverse_alias_address):
            return False
    return True


def normalized_original_contact_email(contact: dict) -> str:
    raw = contact.get("contact") or ""
    _, parsed = parseaddr(raw)
    return (parsed or raw).strip().casefold()


def safe_filename(alias_id: object, contact_id: object) -> str:
    digest = hashlib.sha256(f"{alias_id}:{contact_id}".encode("utf-8")).hexdigest()[:32]
    return f"sl-{digest}.vcf"


def contact_name(reverse_alias_string: str) -> str:
    if "|" not in reverse_alias_string:
        return ""
    name, _ = reverse_alias_string.split("|", 1)
    return html.unescape((name)).strip().strip('"')

def contact_display_name(name: str, email: str) -> str:
    if name:
        return f"{name} · {email}"
    return f"{email}"

def reverse_email(contact: dict) -> str:
    direct = contact.get("reverse_alias_address") or ""
    if direct:
        return direct.strip()
    _, parsed = parseaddr(contact.get("reverse_alias", ""))
    return parsed.strip()

def build_vcard(cfg: Config, alias: dict, contact: dict) -> Optional[Tuple[str, str]]:
    alias_id = alias.get("id")
    contact_id = contact.get("id")
    reverse = reverse_email(contact)
    if not alias_id or not contact_id or not reverse:
        return None

    name = contact_name(contact.get("reverse_alias"))
    real_email = contact.get("contact")
    contact_full_name = contact_display_name(name,real_email)
    alias_addr = alias_email(alias)
    uid = f"simplelogin:{alias_id}:{contact_id}"
    filename = safe_filename(alias_id, contact_id)

    display_name = f"{contact_full_name} ({alias_addr})"

    card = vobject.vCard()
    card.add("uid").value = uid

    # Apple Contacts can show a blank name if a vCard only has FN.
    # Include both FN (formatted name) and N (structured name) for broad CardDAV compatibility.
    card.add("fn").value = display_name
    card.add("n").value = vobject.vcard.Name(family=f"({alias_addr})", given=contact_full_name)
    if name:
        card.add("nickname").value = f"{name}"

    email = card.add("email")
    email.value = reverse
    email.type_param = "SimpleLogin"

    note = card.add("note")
    note.value = (
        f"{MANAGED_NOTE_MARKER}\n"
        f"SimpleLogin alias: {alias_addr}\n"
        f"SimpleLogin alias id: {alias_id}\n"
        f"SimpleLogin contact id: {contact_id}\n"
        f"\n"
        f"Original name: {name}\n"
        f"Original email: {real_email}\n"
        f"\n"
        f"Blocked: {contact.get('block_forward')}"
    )

    return filename, card.serialize()


def sync_once(cfg: Config, sl: SimpleLoginClient, nc: NextcloudCardDavClient) -> None:
    nc.ensure_addressbook(cfg.dry_run)

    aliases = sl.get_all_aliases()
    desired: Dict[str, str] = {}
    skipped_aliases = 0
    skipped_contacts = 0
    duplicate_contacts = 0

    for alias in aliases:
        if not should_include_alias(cfg, alias):
            skipped_aliases += 1
            continue
        alias_id = alias.get("id")
        if not alias_id:
            skipped_aliases += 1
            continue
        contacts = sl.get_all_contacts(alias_id)
        seen_original_contact_emails: Set[str] = set()
        for contact in contacts:
            if cfg.skip_blocked_contacts and contact.get("block_forward"):
                skipped_contacts += 1
                continue
            reverse = reverse_email(contact)
            if not reverse or not should_include_reverse_alias(cfg, reverse):
                skipped_contacts += 1
                continue
            built = build_vcard(cfg, alias, contact)
            if not built:
                skipped_contacts += 1
                continue
            original_contact_email = normalized_original_contact_email(contact)
            if cfg.deduplicate_contacts_by_original_email and original_contact_email:
                if original_contact_email in seen_original_contact_emails:
                    skipped_contacts += 1
                    duplicate_contacts += 1
                    continue
                seen_original_contact_emails.add(original_contact_email)
            filename, vcard_text = built
            desired[filename] = vcard_text

    existing = nc.list_existing_managed_cards()

    upserts = 0
    for filename, vcard_text in sorted(desired.items()):
        # MVP simplicity: PUT every desired card. CardDAV servers handle this fine at small scale.
        nc.put_card(filename, vcard_text, cfg.dry_run)
        upserts += 1

    stale = set(existing.keys()) - set(desired.keys())
    deletes = 0
    if cfg.delete_stale:
        for filename in sorted(stale):
            nc.delete_card(filename, cfg.dry_run)
            deletes += 1

    print(
        "Sync complete: "
        f"aliases={len(aliases)} desired_cards={len(desired)} upserts={upserts} "
        f"stale={len(stale)} deletes={deletes} "
        f"skipped_aliases={skipped_aliases} skipped_contacts={skipped_contacts} "
        f"duplicate_contacts={duplicate_contacts} "
        f"dry_run={cfg.dry_run}",
        flush=True,
    )


def main() -> int:
    cfg = load_config()
    sl = SimpleLoginClient(cfg)
    nc = NextcloudCardDavClient(cfg)

    print(
        f"Starting simplelogin-nextcloud-contacts. Address book: "
        f"{cfg.addressbook_display_name} ({cfg.addressbook_slug}), dry_run={cfg.dry_run}",
        flush=True,
    )

    while True:
        try:
            sync_once(cfg, sl, nc)
        except Exception as exc:
            print(f"Sync failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        time.sleep(cfg.sync_interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
