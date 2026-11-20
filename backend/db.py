"""Shared server-side storage (SQLite).

One file holds users, sessions, applications, assessments, triage state, settings, schedules, tickets and the audit log.
The location is FALCON_DB (default backend/data/falconscan.db). SQLite needs no install; the tables are plain so a move to
another database later only means changing this module.
"""
import os
import pathlib
import sqlite3
import threading
from contextlib import contextmanager

_local = threading.local()
_init_lock = threading.Lock()
_ready: set[str] = set()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_ts REAL NOT NULL,
  last_seen_ts REAL NOT NULL,
  expires_ts REAL NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  working_dir TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT '',
  flows_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS assessments (
  id TEXT PRIMARY KEY,
  app_id TEXT,
  app_name TEXT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT 'upload',
  config TEXT,
  disabled_json TEXT NOT NULL DEFAULT '[]',
  completed INTEGER NOT NULL DEFAULT 0,
  response_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assessments_created ON assessments(created_at);
CREATE TABLE IF NOT EXISTS issues (
  key TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  comment TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS schedules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  interval_minutes INTEGER NOT NULL,
  fail_on TEXT NOT NULL DEFAULT 'High',
  enabled INTEGER NOT NULL DEFAULT 1,
  next_run_ts REAL NOT NULL,
  last_run_ts REAL,
  last_status TEXT NOT NULL DEFAULT '',
  last_assessment_id TEXT,
  created_by TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tickets (
  issue_key TEXT PRIMARY KEY,
  system TEXT NOT NULL,
  external_id TEXT NOT NULL,
  url TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '{}',
  ip TEXT NOT NULL DEFAULT '',
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
"""


def path() -> str:
    return os.environ.get("FALCON_DB") or str(pathlib.Path(__file__).resolve().parent / "data" / "falconscan.db")


def conn() -> sqlite3.Connection:
    """This thread's connection to the current database file (created and migrated on first use)."""
    p = path()
    cache = getattr(_local, "conns", None)
    if cache is None:
        cache = _local.conns = {}
    if p not in cache:
        pathlib.Path(p).parent.mkdir(parents=True, exist_ok=True)
        c = sqlite3.connect(p, timeout=15, isolation_level=None)      # autocommit; transactions are explicit
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        with _init_lock:
            if p not in _ready:
                c.executescript(SCHEMA)
                _ready.add(p)
        cache[p] = c
    return cache[p]


@contextmanager
def tx():
    """A write transaction: BEGIN IMMEDIATE so concurrent writers queue instead of failing half way."""
    c = conn()
    c.execute("BEGIN IMMEDIATE")
    try:
        yield c
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise


def close_all() -> None:
    """Close this thread's connections (used by tests that delete their database file)."""
    for c in getattr(_local, "conns", {}).values():
        c.close()
    _local.conns = {}
    _ready.clear()
