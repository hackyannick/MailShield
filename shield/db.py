"""Zustandsspeicher (SQLite).

Statusmodell eines Absenders:
  * kein Datensatz  -> "unknown"  (noch nie gesehen)
  * status=waiting  -> Challenge gestellt, wartet auf Loesung (Loop-Protection aktiv)
  * status=verified -> auf Allowlist, Mail wird durchgereicht

Quarantaene: rohe Nachrichten liegen als Datei im quarantine_dir, der Datensatz
hier haelt Metadaten + Freigabestatus.
"""
from __future__ import annotations

import os
import sqlite3
import time
from typing import Optional

_conn: Optional[sqlite3.Connection] = None


def connect(path: str) -> sqlite3.Connection:
    global _conn
    os.makedirs(os.path.dirname(path), exist_ok=True)
    _conn = sqlite3.connect(path, timeout=30)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA busy_timeout=30000")
    _init()
    return _conn


def _init() -> None:
    _conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS senders (
            email            TEXT PRIMARY KEY,
            status           TEXT NOT NULL,      -- waiting | verified
            token            TEXT,
            captcha_answer   TEXT,
            challenge_domain TEXT,               -- Mandant/Domain der Challenge
            attempts         INTEGER DEFAULT 0,
            created_at       REAL,
            updated_at       REAL
        );
        CREATE INDEX IF NOT EXISTS idx_senders_token ON senders(token);

        CREATE TABLE IF NOT EXISTS quarantine (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT NOT NULL,
            recipients  TEXT NOT NULL,         -- komma-separiert
            path        TEXT NOT NULL,
            subject     TEXT,
            received_at REAL,
            released    INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_q_email ON quarantine(email, released);
        """
    )
    # Migration bestehender DBs (Spalte ggf. nachziehen)
    cols = {r[1] for r in _conn.execute("PRAGMA table_info(senders)")}
    if "challenge_domain" not in cols:
        _conn.execute("ALTER TABLE senders ADD COLUMN challenge_domain TEXT")
    _conn.commit()


# ---------------------------------------------------------------- senders ----

def get_sender(email: str) -> Optional[sqlite3.Row]:
    return _conn.execute(
        "SELECT * FROM senders WHERE email = ?", (email.lower(),)
    ).fetchone()


def find_by_token(token: str) -> Optional[sqlite3.Row]:
    return _conn.execute(
        "SELECT * FROM senders WHERE token = ?", (token,)
    ).fetchone()


def set_waiting(email: str, token: str, answer: str,
                challenge_domain: str | None = None) -> None:
    """Setzt/erneuert eine Challenge. Status bleibt/wird 'waiting'."""
    email = email.lower()
    now = time.time()
    row = get_sender(email)
    if row is None:
        _conn.execute(
            "INSERT INTO senders(email,status,token,captcha_answer,challenge_domain,"
            "attempts,created_at,updated_at) VALUES (?,?,?,?,?,0,?,?)",
            (email, "waiting", token, answer.upper(), challenge_domain, now, now),
        )
    else:
        _conn.execute(
            "UPDATE senders SET status='waiting', token=?, captcha_answer=?,"
            " challenge_domain=COALESCE(?, challenge_domain), updated_at=? WHERE email=?",
            (token, answer.upper(), challenge_domain, now, email),
        )
    _conn.commit()


def allowlist(email: str) -> None:
    email = email.lower()
    now = time.time()
    _conn.execute(
        "INSERT INTO senders(email,status,token,captcha_answer,created_at,updated_at)"
        " VALUES (?, 'verified', NULL, NULL, ?, ?)"
        " ON CONFLICT(email) DO UPDATE SET status='verified', token=NULL,"
        " captcha_answer=NULL, updated_at=excluded.updated_at",
        (email, now, now),
    )
    _conn.commit()


def reset_sender(email: str) -> None:
    """Zurueck auf 'unknown' -> bei naechster Mail wird neu gechallenget
    (dient auch zum Entsperren eines geblockten Absenders)."""
    _conn.execute("DELETE FROM senders WHERE email = ?", (email.lower(),))
    _conn.commit()


def blocklist(email: str) -> None:
    """Harte Blacklist: Absender wird gesperrt. Die Ablehnungs-Mail wird NICHT
    hier verschickt, sondern einmalig beim naechsten Zustellversuch (Filter)."""
    email = email.lower()
    now = time.time()
    _conn.execute(
        "INSERT INTO senders(email,status,token,captcha_answer,created_at,updated_at)"
        " VALUES (?, 'blocked', NULL, NULL, ?, ?)"
        " ON CONFLICT(email) DO UPDATE SET status='blocked', token=NULL,"
        " captcha_answer=NULL, updated_at=excluded.updated_at",
        (email, now, now),
    )
    _conn.commit()


def mark_block_notified(email: str) -> None:
    """Nach der einmaligen Ablehnung: auf 'blocked_notified' setzen."""
    _conn.execute(
        "UPDATE senders SET status='blocked_notified', updated_at=? WHERE email=?",
        (time.time(), email.lower()),
    )
    _conn.commit()


def bump_attempts(email: str) -> int:
    email = email.lower()
    _conn.execute(
        "UPDATE senders SET attempts = attempts + 1, updated_at=? WHERE email=?",
        (time.time(), email),
    )
    _conn.commit()
    row = get_sender(email)
    return row["attempts"] if row else 0


def challenges_last_hour() -> int:
    since = time.time() - 3600
    return _conn.execute(
        "SELECT COUNT(*) FROM senders WHERE created_at >= ?", (since,)
    ).fetchone()[0]


def list_senders():
    return _conn.execute(
        "SELECT * FROM senders ORDER BY updated_at DESC"
    ).fetchall()


# ------------------------------------------------------------- quarantine ----

def add_quarantine(email: str, recipients, path: str, subject: str) -> int:
    cur = _conn.execute(
        "INSERT INTO quarantine(email,recipients,path,subject,received_at,released)"
        " VALUES (?,?,?,?,?,0)",
        (email.lower(), ",".join(recipients), path, subject or "", time.time()),
    )
    _conn.commit()
    return cur.lastrowid


def pending_for(email: str):
    return _conn.execute(
        "SELECT * FROM quarantine WHERE email=? AND released=0 ORDER BY id",
        (email.lower(),),
    ).fetchall()


def all_pending():
    return _conn.execute(
        "SELECT * FROM quarantine WHERE released=0 ORDER BY received_at"
    ).fetchall()


def mark_released(qid: int) -> None:
    _conn.execute("UPDATE quarantine SET released=1 WHERE id=?", (qid,))
    _conn.commit()


# ---------------------------------------------------------------- cleanup ----

def expired_quarantine(cutoff: float):
    return _conn.execute(
        "SELECT * FROM quarantine WHERE received_at < ?", (cutoff,)
    ).fetchall()


def delete_quarantine(qid: int) -> None:
    _conn.execute("DELETE FROM quarantine WHERE id=?", (qid,))
    _conn.commit()


def stale_waiting(cutoff: float):
    return _conn.execute(
        "SELECT * FROM senders WHERE status='waiting' AND updated_at < ?",
        (cutoff,),
    ).fetchall()

