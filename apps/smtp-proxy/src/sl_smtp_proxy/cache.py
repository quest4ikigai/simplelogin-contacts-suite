from __future__ import annotations

import sqlite3
from contextlib import contextmanager
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


class SQLiteAliasCache:
    def __init__(self, path: str):
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        try:
            conn.executescript(SCHEMA)
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

    def try_reserve_forwarding(self, fingerprint: str, ttl_seconds: int) -> bool:
        """Atomically claim a fingerprint for forwarding.

        Returns True if the caller may proceed to forward: either no entry
        exists for this fingerprint, or the existing entry (pending or
        completed) is older than ttl_seconds and therefore no longer
        eligible for suppression. In both cases a 'pending' reservation is
        written in the same statement so a second, concurrent caller with
        the same fingerprint (e.g. a client retry racing the first send)
        sees the reservation and gets False instead of also forwarding.

        Returns False if a reservation or completed send for this
        fingerprint already exists within the window -- this submission is
        a duplicate and must not be forwarded.

        ttl_seconds <= 0 disables dedup entirely: always returns True
        without touching the table.
        """
        if ttl_seconds <= 0:
            return True
        now_dt = datetime.now(timezone.utc)
        cutoff = (now_dt - timedelta(seconds=ttl_seconds)).isoformat()
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO forwarded_messages (fingerprint, forwarded_at, status)
                VALUES (?, ?, 'pending')
                ON CONFLICT(fingerprint) DO UPDATE SET
                  forwarded_at = excluded.forwarded_at,
                  status = 'pending'
                WHERE forwarded_messages.forwarded_at < ?
                """,
                (fingerprint, now_dt.isoformat(), cutoff),
            )
            return cursor.rowcount == 1

    def release_reservation(self, fingerprint: str) -> None:
        """Release a pending reservation after a failed forward attempt.

        Only removes the row if it is still 'pending' (not completed), so
        this never clobbers a dedup record written by another submission
        that reclaimed the same fingerprint after it expired.
        """
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM forwarded_messages WHERE fingerprint = ? AND status = 'pending'",
                (fingerprint,),
            )

    def mark_forwarded(
        self,
        fingerprint: str,
        prune_older_than_seconds: int,
    ) -> None:
        """Mark a reserved fingerprint as successfully forwarded.

        Opportunistically prunes entries older than prune_older_than_seconds
        so the table does not grow without bound; callers should pass the
        configured suppression window here so pruning never removes an
        entry that is still eligible for duplicate suppression.
        """
        now_dt = datetime.now(timezone.utc)
        cutoff = (now_dt - timedelta(seconds=prune_older_than_seconds)).isoformat()
        with self.connect() as conn:
            conn.execute("DELETE FROM forwarded_messages WHERE forwarded_at < ?", (cutoff,))
            conn.execute(
                """
                INSERT INTO forwarded_messages (fingerprint, forwarded_at, status)
                VALUES (?, ?, 'completed')
                ON CONFLICT(fingerprint) DO UPDATE SET
                  forwarded_at = excluded.forwarded_at,
                  status = 'completed'
                """,
                (fingerprint, now_dt.isoformat()),
            )
