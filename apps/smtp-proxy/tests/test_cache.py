import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

APP_SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, os.path.abspath(APP_SRC))

from sl_smtp_proxy.cache import SQLiteAliasCache


class BulkContactCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.cache = SQLiteAliasCache(os.path.join(self.tmpdir.name, "cache.sqlite3"))

    def test_find_contacts_bulk_reports_hits_and_misses_in_one_query(self):
        self.cache.upsert_contact("1", "alias-1", "Alice", "alice@example.com", "reply+alice@simplelogin.co")

        result = self.cache.find_contacts_bulk(
            "alias-1",
            ["alice@example.com", "bob@example.com"],
            ttl_seconds=3600,
        )

        self.assertIn("alice@example.com", result)
        reverse_alias, block_forward, needs_refresh = result["alice@example.com"]
        self.assertEqual(reverse_alias, "reply+alice@simplelogin.co")
        self.assertFalse(block_forward)
        self.assertFalse(needs_refresh)
        self.assertNotIn("bob@example.com", result)

    def test_find_contacts_bulk_flags_stale_entries_as_needing_refresh(self):
        self.cache.upsert_contact("1", "alias-1", "Alice", "alice@example.com", "reply+old@simplelogin.co")
        stale_time = datetime.now(timezone.utc) - timedelta(seconds=120)
        with self.cache.connect() as conn:
            conn.execute("UPDATE contacts SET updated_at = ? WHERE id = ?", (stale_time.isoformat(), "1"))

        result = self.cache.find_contacts_bulk("alias-1", ["alice@example.com"], ttl_seconds=60)

        self.assertTrue(result["alice@example.com"][2])

    def test_upsert_contacts_bulk_writes_many_rows_in_one_connection(self):
        entries = [
            (str(i), "alias-1", f"Person {i}", f"person{i}@example.com", f"reply+p{i}@simplelogin.co", False)
            for i in range(25)
        ]

        self.cache.upsert_contacts_bulk(entries)

        for i in range(25):
            self.assertEqual(
                self.cache.find_reverse_alias("alias-1", f"person{i}@example.com"),
                f"reply+p{i}@simplelogin.co",
            )

    def test_upsert_contacts_bulk_handles_empty_input(self):
        self.cache.upsert_contacts_bulk([])  # must not raise

    def test_connect_closes_underlying_connection(self):
        with self.cache.connect() as conn:
            conn.execute("SELECT 1")
        # sqlite3 exposes a usable `total_changes` attribute only while the
        # connection is open; after our context manager closes it, any
        # further use must fail with ProgrammingError.
        with self.assertRaises(Exception):
            conn.execute("SELECT 1")


class ForwardedMessageDedupTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.cache = SQLiteAliasCache(os.path.join(self.tmpdir.name, "cache.sqlite3"))

    def test_fingerprint_not_forwarded_until_recorded(self):
        self.assertFalse(self.cache.was_recently_forwarded("fp-1", ttl_seconds=3600))

        self.cache.record_forwarded("fp-1")

        self.assertTrue(self.cache.was_recently_forwarded("fp-1", ttl_seconds=3600))

    def test_was_recently_forwarded_respects_ttl(self):
        self.cache.record_forwarded("fp-1")
        with self.cache.connect() as conn:
            stale = (datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat()
            conn.execute("UPDATE forwarded_messages SET forwarded_at = ? WHERE fingerprint = ?", (stale, "fp-1"))

        self.assertFalse(self.cache.was_recently_forwarded("fp-1", ttl_seconds=60))

    def test_zero_or_negative_ttl_disables_dedup(self):
        self.cache.record_forwarded("fp-1")

        self.assertFalse(self.cache.was_recently_forwarded("fp-1", ttl_seconds=0))

    def test_record_forwarded_prunes_old_entries(self):
        self.cache.record_forwarded("fp-old")
        with self.cache.connect() as conn:
            ancient = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
            conn.execute("UPDATE forwarded_messages SET forwarded_at = ? WHERE fingerprint = ?", (ancient, "fp-old"))

        self.cache.record_forwarded("fp-new", prune_older_than_seconds=30 * 24 * 3600)

        with self.cache.connect() as conn:
            rows = conn.execute("SELECT fingerprint FROM forwarded_messages").fetchall()
        self.assertEqual([row[0] for row in rows], ["fp-new"])


if __name__ == "__main__":
    unittest.main()
