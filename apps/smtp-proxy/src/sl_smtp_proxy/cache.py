from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional, Tuple


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
"""


class SQLiteAliasCache:
    def __init__(self, path: str):
        self.path = path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.executescript(SCHEMA)
        return conn

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

    def find_reverse_alias(self, alias_id: str, contact_email: str) -> Optional[str]:
        row = self.find_contact(alias_id, contact_email)
        if not row:
            return None
        reverse_alias_address, block_forward = row
        if block_forward:
            return None
        return reverse_alias_address
