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
    """Covers the duplicate-suppression state machine: no prior submission,
    forwarding pending, completed, failed, abandoned (lease expired after a
    crash), and outcome-unknown (lease still alive, slow but not crashed).
    """

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        self.cache = SQLiteAliasCache(os.path.join(self.tmpdir.name, "cache.sqlite3"))

    def _reserve(self, fingerprint, attempt_id, window=3600, lease=60, grace=300):
        return self.cache.try_reserve_forwarding(fingerprint, attempt_id, window, lease, grace)

    def test_fresh_fingerprint_is_claimed(self):
        result = self._reserve("fp-1", "attempt-1")

        self.assertEqual(result.outcome, "claimed")

    def test_concurrent_submission_while_pending_is_in_flight_not_rejected(self):
        # Two identical concurrent submissions while the first is
        # forwarding: the second must see "in_flight", not a permanent
        # rejection -- the first attempt might still fail.
        first = self._reserve("fp-1", "attempt-1")
        second = self._reserve("fp-1", "attempt-2")

        self.assertEqual(first.outcome, "claimed")
        self.assertEqual(second.outcome, "in_flight")
        self.assertEqual(second.prior_attempt_id, "attempt-1")

    def test_first_succeeds_after_second_observes_pending_state(self):
        self._reserve("fp-1", "attempt-1")
        pending_view = self._reserve("fp-1", "attempt-2")
        self.cache.mark_forwarded("fp-1", "attempt-1", prune_older_than_seconds=3600)

        self.assertEqual(pending_view.outcome, "in_flight")
        # Now that attempt-1 is confirmed complete, a later identical
        # resubmission must be reported as already-delivered, not forwarded
        # again and not permanently rejected as an error.
        after = self._reserve("fp-1", "attempt-3")
        self.assertEqual(after.outcome, "completed")

    def test_first_fails_after_second_observes_pending_state(self):
        self._reserve("fp-1", "attempt-1")
        pending_view = self._reserve("fp-1", "attempt-2")
        self.cache.mark_failed("fp-1", "attempt-1", prune_older_than_seconds=3600)

        self.assertEqual(pending_view.outcome, "in_flight")
        # Nothing was delivered, so a later resubmission must be allowed to
        # actually retry rather than being told it already succeeded or
        # permanently blocked.
        after = self._reserve("fp-1", "attempt-3")
        self.assertEqual(after.outcome, "claimed")

    def test_retry_after_confirmed_success_is_reported_as_already_delivered(self):
        self._reserve("fp-1", "attempt-1")
        self.cache.mark_forwarded("fp-1", "attempt-1", prune_older_than_seconds=3600)

        result = self._reserve("fp-1", "attempt-2")

        self.assertEqual(result.outcome, "completed")
        self.assertEqual(result.prior_attempt_id, "attempt-1")

    def test_retry_after_confirmed_failure_is_allowed_through(self):
        self._reserve("fp-1", "attempt-1")
        self.cache.mark_failed("fp-1", "attempt-1", prune_older_than_seconds=3600)

        result = self._reserve("fp-1", "attempt-2")

        self.assertEqual(result.outcome, "claimed")

    def test_abandoned_reservation_within_grace_defers_without_reclaiming(self):
        # Simulates a crash: the reservation was made but never resolved,
        # and its lease has now expired. Still within the abandoned-
        # reservation grace period, a resubmission must not assume the
        # original was never delivered and must not forward on its behalf.
        self._reserve("fp-1", "attempt-1", lease=5, grace=30)
        self._age_fingerprint("fp-1", seconds=10)

        result = self._reserve("fp-1", "attempt-2", lease=5, grace=30)

        self.assertEqual(result.outcome, "abandoned")
        self.assertEqual(result.prior_attempt_id, "attempt-1")
        self.assertIsNotNone(result.age_seconds)

    def test_abandoned_reservation_beyond_grace_is_reclaimed(self):
        # Recovery: once the proxy has waited lease + grace with no
        # resolution, it gives up waiting and reclaims the fingerprint,
        # accepting the documented residual duplicate-delivery risk rather
        # than blocking retries forever.
        self._reserve("fp-1", "attempt-1", lease=5, grace=10)
        self._age_fingerprint("fp-1", seconds=20)

        result = self._reserve("fp-1", "attempt-2", lease=5, grace=10)

        self.assertEqual(result.outcome, "claimed")

    def test_renewed_lease_keeps_a_slow_forward_in_flight_not_abandoned(self):
        # A forwarding operation that remains in progress beyond the
        # *normal* reservation window must not look abandoned just because
        # it is slow: as long as it keeps renewing its lease, a concurrent
        # retry still sees "in_flight", never "abandoned" or "claimed".
        self._reserve("fp-1", "attempt-1", lease=5, grace=30)
        self._age_fingerprint("fp-1", seconds=4)
        renewed = self.cache.renew_reservation("fp-1", "attempt-1")
        self._age_fingerprint("fp-1", seconds=4)

        result = self._reserve("fp-1", "attempt-2", lease=5, grace=30)

        self.assertTrue(renewed)
        self.assertEqual(result.outcome, "in_flight")

    def test_renew_reservation_reports_false_once_resolved(self):
        self._reserve("fp-1", "attempt-1")
        self.cache.mark_forwarded("fp-1", "attempt-1", prune_older_than_seconds=3600)

        self.assertFalse(self.cache.renew_reservation("fp-1", "attempt-1"))

    def test_renew_reservation_reports_false_for_wrong_attempt(self):
        self._reserve("fp-1", "attempt-1")

        self.assertFalse(self.cache.renew_reservation("fp-1", "attempt-2"))

    def test_zero_or_negative_window_disables_dedup(self):
        result = self.cache.try_reserve_forwarding(
            "fp-1", "attempt-1", suppression_window_seconds=0, lease_seconds=60, abandoned_grace_seconds=300
        )

        self.assertEqual(result.outcome, "claimed")
        with self.cache.connect() as conn:
            rows = conn.execute("SELECT fingerprint FROM forwarded_messages").fetchall()
        self.assertEqual(rows, [])

    def test_completed_entry_older_than_window_is_reclaimed(self):
        self._reserve("fp-1", "attempt-1", window=3600)
        self.cache.mark_forwarded("fp-1", "attempt-1", prune_older_than_seconds=3600)
        self._age_fingerprint("fp-1", seconds=7200)

        result = self._reserve("fp-1", "attempt-2", window=3600)

        self.assertEqual(result.outcome, "claimed")

    def test_mark_forwarded_prunes_using_configured_window_not_a_fixed_default(self):
        # A window configured above 30 days must not have its entries
        # pruned by a hardcoded 30-day default -- pruning must honor the
        # actual configured suppression window so entries remain eligible
        # for suppression for as long as the operator configured.
        window_seconds = 45 * 24 * 3600
        self._reserve("fp-old", "attempt-1", window=window_seconds)
        self.cache.mark_forwarded("fp-old", "attempt-1", prune_older_than_seconds=window_seconds)
        self._age_fingerprint("fp-old", seconds=40 * 24 * 3600)

        self._reserve("fp-new", "attempt-2", window=window_seconds)
        self.cache.mark_forwarded("fp-new", "attempt-2", prune_older_than_seconds=window_seconds)

        with self.cache.connect() as conn:
            rows = {row[0] for row in conn.execute("SELECT fingerprint FROM forwarded_messages").fetchall()}
        self.assertIn("fp-old", rows)

    def _age_fingerprint(self, fingerprint: str, seconds: int) -> None:
        with self.cache.connect() as conn:
            aged = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
            conn.execute(
                "UPDATE forwarded_messages SET forwarded_at = ? WHERE fingerprint = ?",
                (aged, fingerprint),
            )


if __name__ == "__main__":
    unittest.main()
