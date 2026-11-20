import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

# server.py refuses to start without a built website, so give it a small stand-in before it is imported.
SITE = pathlib.Path(tempfile.mkdtemp(prefix="falcon-site-"))
(SITE / "assets").mkdir()
(SITE / "index.html").write_text("<!doctype html><title>Falcon Scan</title><div id=root></div>", encoding="utf-8")
(SITE / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
os.environ["FALCON_STATIC"] = str(SITE)

import pytest
from fastapi.testclient import TestClient

import accounts
import server

PW = "correct horse battery"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("FALCON_AUTH", "on")
    monkeypatch.setenv("FALCON_SETUP_TOKEN", "setup-secret-token")
    with TestClient(server.app) as c:      # the with-block runs the startup that creates the database
        c.headers["X-Falcon-CSRF"] = "1"
        yield c


def test_the_site_and_its_files_are_served(client):
    assert "Falcon Scan" in client.get("/").text
    assert client.get("/assets/app.js").text == "console.log(1)"


def test_page_addresses_open_the_app_but_a_missing_file_is_a_real_404(client):
    assert "Falcon Scan" in client.get("/workbench").text
    assert "Falcon Scan" in client.get("/login").text
    assert client.get("/assets/missing.js").status_code == 404


def test_the_api_answers_under_slash_api_and_the_public_page_needs_no_sign_in(client):
    r = client.get("/api/account/state")
    assert r.status_code == 200 and r.json()["user"] is None


def test_everything_else_in_the_api_still_needs_sign_in(client):
    assert client.get("/api/data/bootstrap").status_code == 401
    assert client.post("/api/scan/upload", json={"files": []}).status_code == 401
    assert client.get("/api/admin/users").status_code == 401


def test_roles_still_apply_under_slash_api(client):
    accounts.create_user("vera", PW, "viewer", "Vera")
    accounts.create_user("root", PW, "admin", "Root")
    assert client.post("/api/account/login", json={"username": "vera", "password": PW}).status_code == 200
    assert client.get("/api/data/bootstrap").status_code == 200
    assert client.get("/api/admin/users").status_code == 403                      # a viewer is not an administrator
    assert client.post("/api/scan/upload", json={"files": []}).status_code == 403  # nor may a viewer scan


def test_a_write_without_the_csrf_header_is_refused(client):
    accounts.create_user("sam", PW, "assessor", "Sam")
    client.post("/api/account/login", json={"username": "sam", "password": PW})
    del client.headers["X-Falcon-CSRF"]
    assert client.post("/api/scan/upload", json={"files": []}).status_code == 403


def test_security_headers_are_on_every_response(client):
    for path in ("/", "/workbench", "/api/account/state"):
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in h["content-security-policy"] and "script-src 'self'" in h["content-security-policy"]
    assert client.get("/api/account/state").headers["cache-control"] == "no-store"


def test_hsts_is_sent_only_when_the_cookie_is_secure(client, monkeypatch):
    assert "strict-transport-security" not in client.get("/").headers
    monkeypatch.setenv("FALCON_COOKIE_SECURE", "1")
    assert "max-age" in client.get("/").headers["strict-transport-security"]
