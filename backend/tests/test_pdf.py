import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

import main
import pdf

HTML = "<!doctype html><html><body><h1>Security Assessment Report</h1><p>Hello</p><script>document.title='x'</script></body></html>"
needs_browser = pytest.mark.skipif(pdf.find_browser() is None, reason="no Edge or Chrome installed")


@needs_browser
def test_html_becomes_a_pdf():
    data = pdf.html_to_pdf(HTML)
    assert data.startswith(b"%PDF") and len(data) > 1000


@needs_browser
def test_pdf_endpoint_returns_a_pdf_file():
    r = TestClient(main.app).post("/report/pdf", json={"html": HTML})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf" and r.content.startswith(b"%PDF")


def test_missing_browser_is_a_clear_error(monkeypatch):
    monkeypatch.setattr(pdf, "find_browser", lambda: None)
    r = TestClient(main.app).post("/report/pdf", json={"html": HTML})
    assert r.status_code == 501 and "Print > Save as PDF" in r.json()["detail"]


def test_oversized_report_is_refused(monkeypatch):
    monkeypatch.setattr(pdf, "MAX_HTML_BYTES", 10)
    assert TestClient(main.app).post("/report/pdf", json={"html": HTML}).status_code == 413


def test_browser_override_must_exist(monkeypatch):
    monkeypatch.setenv("FALCON_BROWSER", "C:/nope/browser.exe")
    assert pdf.find_browser() is None


def test_page_is_locked_down_before_printing():
    out = pdf.lock_down("<html><head><title>x</title></head><body><script>alert(1)</script></body></html>")
    assert "Content-Security-Policy" in out and "default-src 'none'" in out and out.index("Content-Security-Policy") < out.index("<script>")
    assert "Content-Security-Policy" in pdf.lock_down("<p>no head at all</p>")
