from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, Iterator, Optional, Tuple


SCHEMA = """
CREATE TABLE IF NOT EXISTS aliases (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
  id TEXT PRIMARY KEY,
  alias_id TEXT NOT NULL,
  contact TEXT NOT NULL,
  contact_email TEXT NOT NULL,
  reverse_alias_address TEXT NOT NULL UNIQUE,
  block_forward INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_contacts_alias_contact_email
ON contacts(alias_id, contact_email);

CREATE TABLE IF NOT EXISTS forwarded_messages (
  fingerprint TEXT PRIMARY KEY,
  forwarded_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'completed'
);

CREATE INDEX IF NOT EXISTS idx_forwarded_messages_forwarded_at
ON forwarded_messages(forwarded_at);
"""


@dataclass(frozen=True)
class ReservationResult:
    """Outcome of attempting to atomically claim a fingerprint.

    outcome is one of:
      - "claimed": no conflicting entry; the caller owns the reservation
        and must forward now.
      - "in_flight": a reservation for the same fingerprint is pending and
        its lease has not expired -- a genuinely concurrent duplicate.
      - "abandoned": a reservation for the same fingerprint is pending but
        its lease has expired and it is within the abandoned-reservation
        grace period -- the prior attempt's outcome is unknown (it may
        have crashed mid-send), so this submission must not be forwarded
        yet, but it is not a confirmed duplicate either.
      - "completed": the fingerprint was already forwarded successfully
        within the suppression window.
      - "partial": the upstream server confirmed-accepted only some of
        the recipients and confirmed-refused the rest. Unlike every
        other outcome, this is never automatically reclaimed by age: an
        identical retry must never be allowed to redeliver to the
        accepted subset, and a standard SMTP client (or an intermediate
        MTA) is entitled to retry a temporary failure indefinitely, so
        there is no time window after which that would become safe. The
        proxy has no way to resend to only the refused subset, so a
        "partial" fingerprint stays blocked until an operator resolves
        it (see cache.py's forwarded_messages and the README's "Partial
        recipient acceptance" section) or the row is manually removed.
    """

    outcome: str
    age_seconds: Optional[float] = None
    prior_attempt_id: Optional[str] = None


def _migrate_schema(conn: sqlite3.Connection) -> None:
    """Add columns introduced after the initial forwarded_messages table.

    forwarded_messages has gone through two shapes in earlier commits of
    this same feature: first with neither status nor attempt_id, then
    with status but not attempt_id. A volume created by either
    intermediate state is missing one or both columns. ALTER TABLE ADD
    COLUMN is additive and safe to run against an already-migrated
    database (the duplicate-column error is swallowed), so this is safe
    to call unconditionally on every connect.
    """
    for statement in (
        "ALTER TABLE forwarded_messages ADD COLUMN status TEXT NOT NULL DEFAULT 'completed'",
        "ALTER TABLE forwarded_messages ADD COLUMN attempt_id TEXT",
    ):
        try:
            conn.execute(statement)
        except sqlite3.OperationalError:
            pass


class SQLiteAliasCache:
    def __init__(self, path: str):
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        try:
            conn.executescript(SCHEMA)
            _migrate_schema(conn)
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def upsert_alias(self, alias_id: str, email: str, name: str = "", enabled: bool = True) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO aliases (id, email, name, enabled, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  email=excluded.email,
                  name=excluded.name,
                  enabled=excluded.enabled,
                  updated_at=excluded.updated_at
                """,
                (alias_id, email, name, 1 if enabled else 0, now),
            )

    def alias_emails(self) -> Iterable[str]:
        with self.connect() as conn:
            for (email,) in conn.execute("SELECT email FROM aliases WHERE enabled = 1"):
                yield email

    def aliases_need_refresh(self, ttl_seconds: int) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*), MAX(updated_at) FROM aliases WHERE enabled = 1"
            ).fetchone()
        count = int(row[0] or 0)
        if count == 0:
            return True
        updated_at = row[1]
        if not updated_at:
            return True
        try:
            last_refresh = datetime.fromisoformat(updated_at)
        except ValueError:
            return True
        if last_refresh.tzinfo is None:
            last_refresh = last_refresh.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last_refresh > timedelta(seconds=ttl_seconds)

    def find_alias_id_by_email(self, email: str) -> Optional[str]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id FROM aliases WHERE lower(email) = lower(?) AND enabled = 1",
                (email,),
            ).fetchone()
        return row[0] if row else None

    def upsert_contact(
        self,
        contact_id: str,
        alias_id: str,
        contact: str,
        contact_email: str,
        reverse_alias_address: str,
        block_forward: bool = False,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO contacts (
                  id, alias_id, contact, contact_email, reverse_alias_address,
                  block_forward, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  alias_id=excluded.alias_id,
                  contact=excluded.contact,
                  contact_email=excluded.contact_email,
                  reverse_alias_address=excluded.reverse_alias_address,
                  block_forward=excluded.block_forward,
                  updated_at=excluded.updated_at
                """,
                (
                    contact_id,
                    alias_id,
                    contact,
                    contact_email.casefold(),
                    reverse_alias_address,
                    1 if block_forward else 0,
                    now,
                ),
            )

    def upsert_contacts_bulk(
        self,
        entries: Iterable[Tuple[str, str, str, str, str, bool]],
    ) -> None:
        """Upsert many contacts in a single connection/transaction.

        Each entry is (contact_id, alias_id, contact, contact_email,
        reverse_alias_address, block_forward). Used by bulk recipient
        resolution so a 40-50 recipient message does a single round trip
        to SQLite instead of one connect+write per recipient.
        """
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                contact_id,
                alias_id,
                contact,
                contact_email.casefold(),
                reverse_alias_address,
                1 if block_forward else 0,
                now,
            )
            for (contact_id, alias_id, contact, contact_email, reverse_alias_address, block_forward) in entries
        ]
        if not rows:
            return
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO contacts (
                  id, alias_id, contact, contact_email, reverse_alias_address,
                  block_forward, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  alias_id=excluded.alias_id,
                  contact=excluded.contact,
                  contact_email=excluded.contact_email,
                  reverse_alias_address=excluded.reverse_alias_address,
                  block_forward=excluded.block_forward,
                  updated_at=excluded.updated_at
                """,
                rows,
            )

    def find_contacts_bulk(
        self,
        alias_id: str,
        contact_emails: Iterable[str],
        ttl_seconds: int,
    ) -> Dict[str, Tuple[str, bool, bool]]:
        """Look up many cached contacts for one alias in a single query.

        Returns a map of casefolded contact_email -> (reverse_alias_address,
        block_forward, needs_refresh).
        """
        emails = sorted({email.casefold() for email in contact_emails if email})
        if not emails:
            return {}

        placeholders = ",".join("?" for _ in emails)
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT contact_email, reverse_alias_address, block_forward, updated_at
                FROM contacts
                WHERE alias_id = ? AND contact_email IN ({placeholders})
                """,
                (alias_id, *emails),
            ).fetchall()

        now = datetime.now(timezone.utc)
        result: Dict[str, Tuple[str, bool, bool]] = {}
        for contact_email, reverse_alias_address, block_forward, updated_at in rows:
            needs_refresh = ttl_seconds <= 0
            if not needs_refresh:
                try:
                    last_refresh = datetime.fromisoformat(updated_at)
                except (TypeError, ValueError):
                    needs_refresh = True
                else:
                    if last_refresh.tzinfo is None:
                        last_refresh = last_refresh.replace(tzinfo=timezone.utc)
                    needs_refresh = now - last_refresh > timedelta(seconds=ttl_seconds)
            result[contact_email] = (reverse_alias_address, bool(block_forward), needs_refresh)
        return result

    def find_contact(
        self,
        alias_id: str,
        contact_email: str,
    ) -> Optional[Tuple[str, bool]]:
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT reverse_alias_address, block_forward
                FROM contacts
                WHERE alias_id = ? AND contact_email = ?
                """,
                (alias_id, contact_email.casefold()),
            ).fetchone()
        if not row:
            return None
        return row[0], bool(row[1])

    def contact_needs_refresh(
        self,
        alias_id: str,
        contact_email: str,
        ttl_seconds: int,
    ) -> bool:
        if ttl_seconds <= 0:
            return True

        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT updated_at
                FROM contacts
                WHERE alias_id = ? AND contact_email = ?
                """,
                (alias_id, contact_email.casefold()),
            ).fetchone()
        if not row or not row[0]:
            return True

        try:
            last_refresh = datetime.fromisoformat(row[0])
        except ValueError:
            return True
        if last_refresh.tzinfo is None:
            last_refresh = last_refresh.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) - last_refresh > timedelta(seconds=ttl_seconds)

    def find_reverse_alias(self, alias_id: str, contact_email: str) -> Optional[str]:
        row = self.find_contact(alias_id, contact_email)
        if not row:
            return None
        reverse_alias_address, block_forward = row
        if block_forward:
            return None
        return reverse_alias_address

    def try_reserve_forwarding(
        self,
        fingerprint: str,
        attempt_id: str,
        suppression_window_seconds: int,
        lease_seconds: int,
        abandoned_grace_seconds: int,
    ) -> ReservationResult:
        """Atomically claim a fingerprint for forwarding, or report why not.

        A single INSERT .. ON CONFLICT DO UPDATE .. WHERE statement either
        claims the fingerprint (writing a fresh 'pending' reservation
        tagged with attempt_id) or, if a conflicting entry blocks the
        claim, leaves the row untouched -- there is no window between
        "check" and "write" for a second, concurrent caller to slip
        through, which is what let two concurrent submissions of the same
        message both reach forwarding before either had recorded success.

        A fingerprint is claimable when there is no existing entry, or the
        existing entry is: a confirmed failure (always safe to retry,
        since nothing was delivered); a completed send older than
        suppression_window_seconds (no longer eligible for suppression);
        or a pending reservation whose lease has expired *and* has sat
        unresolved for longer than lease_seconds + abandoned_grace_seconds
        (abandoned for long enough that the proxy gives up waiting and
        accepts the small residual risk of a duplicate -- see the
        "Delivery-state handling" section of the README for the documented
        trade-off). A "partial" entry is never claimable by age, no matter
        how old: see ReservationResult's "partial" outcome for why.

        suppression_window_seconds <= 0 disables dedup entirely: always
        returns "claimed" without touching the table.
        """
        if suppression_window_seconds <= 0:
            return ReservationResult(outcome="claimed")

        now_dt = datetime.now(timezone.utc)
        now_iso = now_dt.isoformat()
        completed_cutoff = (now_dt - timedelta(seconds=suppression_window_seconds)).isoformat()
        abandoned_cutoff = (
            now_dt - timedelta(seconds=lease_seconds + abandoned_grace_seconds)
        ).isoformat()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO forwarded_messages (fingerprint, forwarded_at, status, attempt_id)
                VALUES (?, ?, 'pending', ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                  forwarded_at = excluded.forwarded_at,
                  status = 'pending',
                  attempt_id = excluded.attempt_id
                WHERE
                  forwarded_messages.status = 'failed'
                  OR (forwarded_messages.status = 'completed' AND forwarded_messages.forwarded_at < ?)
                  OR (forwarded_messages.status = 'pending' AND forwarded_messages.forwarded_at < ?)
                """,
                (
                    fingerprint,
                    now_iso,
                    attempt_id,
                    completed_cutoff,
                    abandoned_cutoff,
                ),
            )
            if cursor.rowcount == 1:
                return ReservationResult(outcome="claimed")

            row = conn.execute(
                "SELECT status, forwarded_at, attempt_id FROM forwarded_messages WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()

        if not row:
            # Something else (e.g. a concurrent prune) removed the row
            # between the failed claim above and this read. Treat it the
            # same as a genuinely in-flight duplicate: defer rather than
            # guess, since we cannot tell whether it was ever forwarded.
            return ReservationResult(outcome="in_flight")

        status, forwarded_at, prior_attempt_id = row
        if status == "completed":
            return ReservationResult(outcome="completed", prior_attempt_id=prior_attempt_id)
        if status == "partial":
            # Deliberately not matched by the WHERE clause above at any
            # age: a "partial" fingerprint is permanently blocked from
            # automatic reclaim (see ReservationResult's docstring).
            return ReservationResult(outcome="partial", prior_attempt_id=prior_attempt_id)

        age_seconds = None
        if forwarded_at:
            try:
                last_update = datetime.fromisoformat(forwarded_at)
            except ValueError:
                last_update = None
            if last_update is not None:
                if last_update.tzinfo is None:
                    last_update = last_update.replace(tzinfo=timezone.utc)
                age_seconds = (now_dt - last_update).total_seconds()

        lease_cutoff = now_dt - timedelta(seconds=lease_seconds)
        if status == "pending" and forwarded_at and forwarded_at < lease_cutoff.isoformat():
            return ReservationResult(
                outcome="abandoned", age_seconds=age_seconds, prior_attempt_id=prior_attempt_id
            )
        return ReservationResult(
            outcome="in_flight", age_seconds=age_seconds, prior_attempt_id=prior_attempt_id
        )

    def renew_reservation(self, fingerprint: str, attempt_id: str) -> bool:
        """Refresh a pending reservation's lease while forwarding is still
        genuinely in progress, so a slow-but-alive forward is never mistaken
        for an abandoned (crashed) one. Returns False if the reservation is
        no longer ours to renew (already resolved or reclaimed elsewhere);
        callers treat that as informational, not an error.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE forwarded_messages
                SET forwarded_at = ?
                WHERE fingerprint = ? AND attempt_id = ? AND status = 'pending'
                """,
                (now_iso, fingerprint, attempt_id),
            )
            return cursor.rowcount == 1

    def mark_forwarded(
        self,
        fingerprint: str,
        attempt_id: str,
        prune_older_than_seconds: int,
    ) -> None:
        """Mark this attempt's reservation as successfully forwarded.

        Only updates the row if attempt_id still matches (i.e. this
        attempt still owns the reservation); opportunistically prunes
        entries older than prune_older_than_seconds so the table does not
        grow without bound. Callers should pass a value at least as large
        as the longest of the suppression window and the abandoned-
        reservation window so pruning never removes a row that is still
        meaningful for either purpose.
        """
        self._resolve_reservation(fingerprint, attempt_id, "completed", prune_older_than_seconds)

    def mark_failed(
        self,
        fingerprint: str,
        attempt_id: str,
        prune_older_than_seconds: int,
    ) -> None:
        """Mark this attempt's reservation as a confirmed forwarding failure.

        A confirmed failure means nothing was delivered, so (unlike a
        completed send) the fingerprint is immediately eligible for a
        legitimate retry to reclaim -- see try_reserve_forwarding.
        """
        self._resolve_reservation(fingerprint, attempt_id, "failed", prune_older_than_seconds)

    def mark_partial(
        self,
        fingerprint: str,
        attempt_id: str,
        prune_older_than_seconds: int,
    ) -> None:
        """Mark this attempt's reservation as a confirmed partial delivery.

        Some recipients were confirmed accepted by the upstream server
        and some were confirmed refused. Unlike every other resolution,
        this is never time-reclaimable and never pruned by age (see
        try_reserve_forwarding and _resolve_reservation): the proxy has
        no way to resend to only the refused subset, and a standard SMTP
        client is entitled to retry a temporary failure indefinitely, so
        no amount of elapsed time makes it safe to let an identical
        retry redeliver to the recipients already accepted.
        """
        self._resolve_reservation(fingerprint, attempt_id, "partial", prune_older_than_seconds)

    def _resolve_reservation(
        self,
        fingerprint: str,
        attempt_id: str,
        status: str,
        prune_older_than_seconds: int,
    ) -> None:
        now_dt = datetime.now(timezone.utc)
        cutoff = (now_dt - timedelta(seconds=prune_older_than_seconds)).isoformat()
        with self.connect() as conn:
            # "partial" rows are excluded here, not just from
            # try_reserve_forwarding's time-based reclaim: pruning one
            # would delete the row outright, which would make the next
            # identical resubmission look like a fresh fingerprint and
            # forward it again, exactly what the "partial" outcome's
            # permanent block exists to prevent.
            conn.execute(
                """
                DELETE FROM forwarded_messages
                WHERE forwarded_at < ? AND fingerprint != ? AND status != 'partial'
                """,
                (cutoff, fingerprint),
            )
            conn.execute(
                """
                UPDATE forwarded_messages
                SET forwarded_at = ?, status = ?
                WHERE fingerprint = ? AND attempt_id = ?
                """,
                (now_dt.isoformat(), status, fingerprint, attempt_id),
            )
