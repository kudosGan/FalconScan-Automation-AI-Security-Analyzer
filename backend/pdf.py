"""Turn a report's HTML into a PDF with the print engine of a browser already installed on this machine.

No Python PDF library is needed. Microsoft Edge ships with Windows; Chrome or Chromium also work. Set FALCON_BROWSER
to the browser's full path to choose one. The report is printed from a temporary copy with scripts and network access blocked by a Content-Security-Policy,
so the page can only show what is inside it (styles and data: images).
"""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

MAX_HTML_BYTES = 15 * 1024 * 1024
TIMEOUT_SECONDS = 90

_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
]
_NAMES = ["msedge", "microsoft-edge", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome"]


def find_browser() -> str | None:
    chosen = os.environ.get("FALCON_BROWSER")
    if chosen:
        return chosen if pathlib.Path(chosen).is_file() else None
    for c in _CANDIDATES:
        if pathlib.Path(c).is_file():
            return c
    return next((p for n in _NAMES if (p := shutil.which(n))), None)


_POLICY = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:"
_CSP = f'<meta http-equiv="Content-Security-Policy" content="{_POLICY}">'


def lock_down(html: str) -> str:
    """Block scripts and network loads in the page being printed. Reports built by Falcon Scan always have a <head>."""
    if re.search(r"<head[^>]*>", html, re.I):
        return re.sub(r"(<head[^>]*>)", lambda m: m.group(1) + _CSP, html, count=1, flags=re.I)
    return f"<!doctype html><html><head>{_CSP}</head><body>{html}</body></html>"


def html_to_pdf(html: str) -> bytes:
    """Return PDF bytes. Raises RuntimeError with a plain message when no browser is available or printing fails."""
    if len(html.encode("utf-8")) > MAX_HTML_BYTES:
        raise ValueError("The report is too large to convert.")
    browser = find_browser()
    if not browser:
        raise RuntimeError("No Edge or Chrome browser was found on the server. Set FALCON_BROWSER to its path, "
                           "or use Open and choose Print > Save as PDF.")
    with tempfile.TemporaryDirectory(prefix="falconpdf-") as tmp:
        root = pathlib.Path(tmp)
        src, out = root / "report.html", root / "report.pdf"
        src.write_text(lock_down(html), encoding="utf-8")
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
               "--no-pdf-header-footer", f"--user-data-dir={root / 'profile'}",
               f"--print-to-pdf={out}", src.as_uri()]
        try:
            subprocess.run(cmd, capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired:
            raise RuntimeError("The browser took too long to produce the PDF.")
        except OSError as e:
            raise RuntimeError(f"Could not start the browser: {e}")
        if not out.is_file() or out.stat().st_size == 0:
            raise RuntimeError("The browser did not produce a PDF.")
        data = out.read_bytes()
    if not data.startswith(b"%PDF"):
        raise RuntimeError("The browser output was not a PDF.")
    return data
