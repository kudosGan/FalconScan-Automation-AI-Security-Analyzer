"""One program that serves both the website and the API, for deployment.

    cd backend
    uvicorn server:app --host 0.0.0.0 --port 8000

The website is the built frontend (run `npm run build` in frontend/ first). The API lives under /api, exactly as the Vite dev
proxy presents it, so the same frontend build works unchanged. For development keep using `uvicorn main:app` plus `npm run dev`.

Environment:
  FALCON_STATIC   folder with the built website (default: ../frontend/dist)
"""
import os
import pathlib

from starlette.applications import Starlette
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import FileResponse
from starlette.routing import Mount
from starlette.staticfiles import StaticFiles

from main import app as api

STATIC = pathlib.Path(os.environ.get("FALCON_STATIC") or pathlib.Path(__file__).resolve().parent.parent / "frontend" / "dist")

# The site loads only its own scripts. Inline styles are needed by the React components; data: and blob: cover the logo and downloads.
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; "
       "connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")


class SinglePageFiles(StaticFiles):
    """Serves the built site. Any page address that is not a file (/workbench, /login) gets index.html so the app's own router takes over.
    A missing file with an extension (a script or image) stays a real 404 instead of being answered with a web page."""

    async def get_response(self, path: str, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as e:
            if e.status_code == 404 and "." not in pathlib.PurePosixPath(path).name:
                return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-cache"})
            raise


class Headers(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        r = await call_next(request)
        r.headers.setdefault("X-Content-Type-Options", "nosniff")
        r.headers.setdefault("X-Frame-Options", "DENY")
        r.headers.setdefault("Referrer-Policy", "no-referrer")
        r.headers.setdefault("Content-Security-Policy", CSP)
        if os.environ.get("FALCON_COOKIE_SECURE", "").lower() in ("1", "true", "yes"):
            r.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        if request.url.path.startswith("/api/"):
            r.headers.setdefault("Cache-Control", "no-store")
        return r


if not (STATIC / "index.html").is_file():
    raise RuntimeError(f"The built website was not found in {STATIC}. Run `npm run build` in frontend/ first, or set FALCON_STATIC.")

# The API app starts the database and the scheduler in its own lifespan, which a mounted app does not run by itself.
app = Starlette(
    routes=[Mount("/api", app=api), Mount("/", app=SinglePageFiles(directory=str(STATIC), html=True))],
    lifespan=lambda _app: api.router.lifespan_context(api),
)
app.add_middleware(Headers)
