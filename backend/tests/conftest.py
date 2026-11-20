import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

# Existing tests exercise the scanner endpoints directly, so they run in single-user mode.
# Tests of login and roles switch FALCON_AUTH on for themselves. The background scheduler never runs under test.
os.environ["FALCON_AUTH"] = "off"
os.environ["FALCON_SCHEDULER"] = "off"

import pytest


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Every test gets its own empty database file and the real clock."""
    import accounts
    import db
    monkeypatch.setenv("FALCON_DB", str(tmp_path / "falcon-test.db"))
    monkeypatch.setattr(accounts, "_now", __import__("time").time)
    db.close_all()
    yield
    db.close_all()
