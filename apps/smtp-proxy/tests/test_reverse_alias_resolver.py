import json
import os
import threading
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
CORE_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "alias-routing-core", "src")
SIMPLELOGIN_SRC = os.path.join(os.path.dirname(__file__), "..", "..", "..", "packages", "simplelogin-client", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))
sys.path.insert(0, os.path.abspath(CORE_SRC))
sys.path.insert(0, os.path.abspath(SIMPLELOGIN_SRC))

from simplelogin_client import Alias, AliasContact, RequestStats, SimpleLoginApiError, SimpleLoginClient
from sl_smtp_proxy.cache import SQLiteAliasCache
from sl_smtp_proxy.config import SmtpProxyConfig
from sl_smtp_proxy.reverse_alias_resolver import ReverseAliasResolutionError, ReverseAliasResolver


class FakeSimpleLoginClient:
    def __init__(self, aliases=None, contacts=None, created_contact=None, fail=False):
        self.aliases = aliases or []
        self.contacts = contacts or {}
        self.created_contact = created_contact
        self.fail = fail
        self.list_aliases_calls = 0
        self.get_or_create_calls = []

    def list_aliases(self, stats=None):
        self.list_aliases_calls += 1
        if self.fail:
            raise SimpleLoginApiError("SimpleLogin API unavailable")
        return self.aliases

    def get_or_create_contact(self, alias_id, contact, stats=None):
        self.get_or_create_calls.append((alias_id, contact))
        if self.fail:
            raise SimpleLoginApiError("SimpleLogin API unavailable")
        existing = self.contacts.get((alias_id, contact.casefold()))
        if existing:
            return existing
        if self.created_contact:
            return self.created_contact
        raise SimpleLoginApiError("missing fake contact")


class FakeBulkSimpleLoginClient:
    """Fake client with list_contacts/create_contact for resolve_bulk tests."""

    def __init__(self, aliases=None, existing_contacts=None, fail_list_contacts=False, fail_create_for=None):
        self.aliases = aliases or []
        self.existing_contacts = existing_contacts or []
        self.fail_list_contacts = fail_list_contacts
        self.fail_create_for = set(fail_create_for or [])
        self.list_aliases_calls = 0
        self.list_contacts_calls = []
        self.create_contact_calls = []

    def list_aliases(self, stats=None):
        self.list_aliases_calls += 1
        return self.aliases

    def list_contacts(self, alias_id, stats=None):
        self.list_contacts_calls.append(alias_id)
        if stats is not None:
            stats.record(0.01)
        if self.fail_list_contacts:
            raise SimpleLoginApiError("SimpleLogin API timeout")
        return self.existing_contacts

    def create_contact(self, alias_id, contact, stats=None):
        self.create_contact_calls.append((alias_id, contact))
        if stats is not None:
            stats.record(0.01)
        from email.utils import parseaddr

        _, address = parseaddr(contact)
        address = (address or contact).casefold()
        if address in self.fail_create_for:
            raise SimpleLoginApiError(f"SimpleLogin API rejected contact creation for {address}")
        local = address.split("@", 1)[0]
        return AliasContact(
            id=f"created-{local}",
            alias_id=alias_id,
            contact=contact,
            reverse_alias=None,
            reverse_alias_address=f"reply+{local}@simplelogin.co",
        )

    def get_or_create_contact(self, alias_id, contact, stats=None):
        wanted = contact.casefold()
        for existing in self.list_contacts(alias_id, stats=stats):
            if existing.contact.casefold() == wanted:
                return existing
        return self.create_contact(alias_id, contact, stats=stats)


class ReverseAliasResolverBulkTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.cache_path = os.path.join(self.tmpdir.name, "cache.sqlite3")
        self.cache = SQLiteAliasCache(self.cache_path)
        self.cache.upsert_alias("123", "shopping@example.com")
        self.config = SmtpProxyConfig(cache_path=self.cache_path)

    def _recipients(self, n, offset=0):
        return [f"person{i}@example.com" for i in range(offset, offset + n)]

    def test_bulk_resolve_fetches_contact_list_once_for_many_uncached_recipients(self):
        client = FakeBulkSimpleLoginClient(existing_contacts=[])
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)
        recipients = self._recipients(45)

        stats = resolver.resolve_bulk(recipients, "shopping@example.com")

        self.assertEqual(len(client.list_contacts_calls), 1)
        self.assertEqual(len(client.create_contact_calls), 45)
        self.assertEqual(stats.cache_misses, 45)
        self.assertEqual(stats.contacts_created, 45)
        self.assertEqual(stats.contacts_found, 0)

        # Every recipient is now a fast cache hit: __call__ must not need
        # another create/list round trip.
        for recipient in recipients:
            reverse_alias = resolver(recipient, "shopping@example.com")
            local = recipient.split("@", 1)[0]
            self.assertEqual(reverse_alias, f"reply+{local}@simplelogin.co")
        self.assertEqual(len(client.list_contacts_calls), 1)
        self.assertEqual(len(client.create_contact_calls), 45)

    def test_bulk_resolve_uses_cache_for_already_known_contacts(self):
        for i in range(20):
            self.cache.upsert_contact(
                str(i), "123", f"person{i}@example.com", f"person{i}@example.com", f"reply+person{i}@simplelogin.co"
            )
        client = FakeBulkSimpleLoginClient(existing_contacts=[])
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)
        recipients = self._recipients(20) + self._recipients(25, offset=20)

        stats = resolver.resolve_bulk(recipients, "shopping@example.com")

        self.assertEqual(stats.cache_hits, 20)
        self.assertEqual(stats.cache_misses, 25)
        self.assertEqual(len(client.list_contacts_calls), 1)
        self.assertEqual(len(client.create_contact_calls), 25)

    def test_bulk_resolve_finds_existing_simplelogin_contacts_without_creating(self):
        existing = [
            AliasContact(
                id="900",
                alias_id="123",
                contact="person0@example.com",
                reverse_alias=None,
                reverse_alias_address="reply+existing0@simplelogin.co",
            )
        ]
        client = FakeBulkSimpleLoginClient(existing_contacts=existing)
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        stats = resolver.resolve_bulk(["person0@example.com"], "shopping@example.com")

        self.assertEqual(stats.contacts_found, 1)
        self.assertEqual(stats.contacts_created, 0)
        self.assertEqual(client.create_contact_calls, [])
        self.assertEqual(
            self.cache.find_reverse_alias("123", "person0@example.com"),
            "reply+existing0@simplelogin.co",
        )

    def test_bulk_resolve_tracks_request_stats_across_calls(self):
        client = FakeBulkSimpleLoginClient(existing_contacts=[])
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)
        request_stats = RequestStats()

        resolver.resolve_bulk(self._recipients(5), "shopping@example.com", request_stats=request_stats)

        # 1 list_contacts + 5 create_contact calls.
        self.assertEqual(request_stats.request_count, 6)

    def test_bulk_resolve_is_best_effort_on_list_contacts_failure(self):
        client = FakeBulkSimpleLoginClient(fail_list_contacts=True)
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)
        recipients = self._recipients(5)

        stats = resolver.resolve_bulk(recipients, "shopping@example.com")

        self.assertEqual(stats.cache_hits, 0)
        self.assertEqual(stats.contacts_created, 0)
        # Nothing is cached, but __call__ still works through its own
        # slower fallback path for each recipient individually.
        client.fail_list_contacts = False
        reverse_alias = resolver(recipients[0], "shopping@example.com")
        self.assertEqual(reverse_alias, "reply+person0@simplelogin.co")

    def test_bulk_resolve_leaves_failed_creations_uncached_for_fallback(self):
        client = FakeBulkSimpleLoginClient(existing_contacts=[], fail_create_for={"person1@example.com"})
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)
        recipients = self._recipients(3)

        stats = resolver.resolve_bulk(recipients, "shopping@example.com")

        self.assertEqual(stats.contacts_created, 2)
        self.assertIsNone(self.cache.find_reverse_alias("123", "person1@example.com"))
        self.assertIsNotNone(self.cache.find_reverse_alias("123", "person0@example.com"))

        # The one recipient whose creation failed still raises through the
        # normal per-recipient fail-closed path when actually resolved.
        with self.assertRaises(SimpleLoginApiError):
            resolver("person1@example.com", "shopping@example.com")

    def test_bulk_resolve_paginates_through_many_existing_contacts(self):
        existing = [
            AliasContact(
                id=str(i),
                alias_id="123",
                contact=f"person{i}@example.com",
                reverse_alias=None,
                reverse_alias_address=f"reply+existing{i}@simplelogin.co",
            )
            for i in range(50)
        ]
        client = FakeBulkSimpleLoginClient(existing_contacts=existing)
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        stats = resolver.resolve_bulk(["person49@example.com"], "shopping@example.com")

        self.assertEqual(stats.contacts_found, 1)
        self.assertEqual(
            self.cache.find_reverse_alias("123", "person49@example.com"),
            "reply+existing49@simplelogin.co",
        )

    def test_bulk_resolve_no_op_without_selected_alias_or_recipients(self):
        client = FakeBulkSimpleLoginClient()
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        stats_no_alias = resolver.resolve_bulk(["a@example.com"], None)
        stats_no_recipients = resolver.resolve_bulk([], "shopping@example.com")

        self.assertEqual(stats_no_alias.cache_misses, 0)
        self.assertEqual(stats_no_recipients.cache_misses, 0)
        self.assertEqual(client.list_contacts_calls, [])


class ReverseAliasResolverTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.tmpdir.name, "cache.sqlite3")
        self.cache = SQLiteAliasCache(self.cache_path)
        self.config = SmtpProxyConfig(cache_path=self.cache_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_existing_cached_contact_is_returned_without_api_contact_call(self):
        self.cache.upsert_alias("123", "shopping@example.com")
        self.cache.upsert_contact(
            "456",
            "123",
            "Alice <alice@example.com>",
            "alice@example.com",
            "reply+alice@simplelogin.co",
        )
        client = FakeSimpleLoginClient()
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        reverse_alias = resolver("alice@example.com", "shopping@example.com")

        self.assertEqual(reverse_alias, "reply+alice@simplelogin.co")
        self.assertEqual(client.get_or_create_calls, [])

    def test_stale_cached_contact_is_refreshed_from_api(self):
        self.cache.upsert_alias("123", "shopping@example.com")
        self.cache.upsert_contact(
            "456",
            "123",
            "Alice <alice@example.com>",
            "alice@example.com",
            "reply+old@simplelogin.co",
        )
        stale_time = datetime.now(timezone.utc) - timedelta(seconds=120)
        with self.cache.connect() as conn:
            conn.execute(
                "UPDATE contacts SET updated_at = ? WHERE id = ?",
                (stale_time.isoformat(), "456"),
            )
        client = FakeSimpleLoginClient(
            contacts={
                ("123", "alice@example.com"): AliasContact(
                    id="456",
                    alias_id="123",
                    contact="Alice <alice@example.com>",
                    reverse_alias=None,
                    reverse_alias_address="reply+fresh@simplelogin.co",
                ),
            },
        )
        config = SmtpProxyConfig(
            cache_path=self.cache_path,
            cache_contact_ttl_seconds=60,
        )
        resolver = ReverseAliasResolver(config, cache=self.cache, client=client)

        reverse_alias = resolver("alice@example.com", "shopping@example.com")

        self.assertEqual(reverse_alias, "reply+fresh@simplelogin.co")
        self.assertEqual(client.get_or_create_calls, [("123", "alice@example.com")])
        self.assertEqual(
            self.cache.find_reverse_alias("123", "alice@example.com"),
            "reply+fresh@simplelogin.co",
        )

    def test_missing_contact_is_created_and_cached(self):
        client = FakeSimpleLoginClient(
            aliases=[Alias(id="123", email="shopping@example.com")],
            created_contact=AliasContact(
                id="789",
                alias_id="123",
                contact="Alice <alice@example.com>",
                reverse_alias=None,
                reverse_alias_address="reply+alice@simplelogin.co",
            ),
        )
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        reverse_alias = resolver("Alice <alice@example.com>", "shopping@example.com")

        self.assertEqual(reverse_alias, "reply+alice@simplelogin.co")
        self.assertEqual(client.list_aliases_calls, 1)
        self.assertEqual(client.get_or_create_calls, [("123", "Alice <alice@example.com>")])
        self.assertEqual(
            self.cache.find_reverse_alias("123", "alice@example.com"),
            "reply+alice@simplelogin.co",
        )

    def test_owned_alias_emails_refreshes_from_simplelogin(self):
        client = FakeSimpleLoginClient(
            aliases=[
                Alias(id="123", email="shopping@example.com"),
                Alias(id="456", email="newsletters@example.com", enabled=False),
            ],
        )
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        aliases = resolver.owned_alias_emails()

        self.assertEqual(aliases, {"shopping@example.com"})
        self.assertEqual(client.list_aliases_calls, 1)

    def test_blocked_api_contact_rejects_and_is_cached(self):
        client = FakeSimpleLoginClient(
            aliases=[Alias(id="123", email="shopping@example.com")],
            created_contact=AliasContact(
                id="789",
                alias_id="123",
                contact="Alice <alice@example.com>",
                reverse_alias=None,
                reverse_alias_address="reply+alice@simplelogin.co",
                block_forward=True,
            ),
        )
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        with self.assertRaisesRegex(ReverseAliasResolutionError, "blocked"):
            resolver("Alice <alice@example.com>", "shopping@example.com")

        self.assertIsNone(self.cache.find_reverse_alias("123", "alice@example.com"))

    def test_api_unavailable_fails_closed(self):
        client = FakeSimpleLoginClient(fail=True)
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        with self.assertRaises(SimpleLoginApiError):
            resolver("alice@example.com", "shopping@example.com")

    def test_missing_selected_alias_fails_closed(self):
        client = FakeSimpleLoginClient(aliases=[Alias(id="123", email="personal@example.com")])
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        with self.assertRaisesRegex(ReverseAliasResolutionError, "selected SimpleLogin alias was not found"):
            resolver("alice@example.com", "shopping@example.com")


class ReverseAliasResolverHttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.cache_path = os.path.join(self.tmpdir.name, "cache.sqlite3")
        self.cache = SQLiteAliasCache(self.cache_path)
        self.config = SmtpProxyConfig(cache_path=self.cache_path)
        self.requests = []
        test_case = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                test_case.requests.append((self.command, self.path, self.headers.get("Authentication"), None))
                if self.path == "/api/v2/aliases?page_id=0":
                    self._json(200, {"aliases": [{"id": 123, "email": "shopping@example.com"}]})
                    return
                if self.path == "/api/aliases/123/contacts?page_id=0":
                    self._json(200, {"contacts": []})
                    return
                self._json(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                test_case.requests.append((self.command, self.path, self.headers.get("Authentication"), body))
                if self.path == "/api/aliases/123/contacts":
                    self._json(
                        201,
                        {
                            "contact": {
                                "id": 456,
                                "contact": "Alice <alice@example.com>",
                                "reverse_alias_address": "reply+alice@simplelogin.co",
                            }
                        },
                    )
                    return
                self._json(404, {"error": "not found"})

            def log_message(self, format, *args):
                return

            def _json(self, status, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.thread.join(timeout=2)
        self.httpd.server_close()
        self.tmpdir.cleanup()

    def test_real_simplelogin_client_against_fake_http_server(self):
        port = self.httpd.server_address[1]
        client = SimpleLoginClient(f"http://127.0.0.1:{port}", "test-api-key")
        resolver = ReverseAliasResolver(self.config, cache=self.cache, client=client)

        reverse_alias = resolver("Alice <alice@example.com>", "shopping@example.com")

        self.assertEqual(reverse_alias, "reply+alice@simplelogin.co")
        self.assertEqual(
            self.cache.find_reverse_alias("123", "alice@example.com"),
            "reply+alice@simplelogin.co",
        )
        self.assertEqual([request[0] for request in self.requests], ["GET", "GET", "POST"])
        self.assertTrue(all(request[2] == "test-api-key" for request in self.requests))
        self.assertEqual(json.loads(self.requests[-1][3]), {"contact": "Alice <alice@example.com>"})


if __name__ == "__main__":
    unittest.main()
