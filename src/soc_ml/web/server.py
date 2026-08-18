"""The dashboard's HTTP(S) server — stdlib only.

No web framework, deliberately. NFR-07 says the standalone profile installs and
runs with no infrastructure, and a dashboard is not a good enough reason to put
a server dependency in front of a SOC team's install. ``http.server`` with a
thread pool is more than adequate for a handful of operators polling JSON.

Security posture, because this serves alert data:

* binds ``127.0.0.1`` unless told otherwise, and refuses a non-loopback bind
  without either TLS or an explicit acknowledgement;
* every mutating endpoint (model promotion) requires a bearer token, generated
  at startup and printed once;
* GET endpoints are read-only and serve no path from disk — the one HTML page
  is embedded, so there is no traversal surface.
"""

from __future__ import annotations

import json
import secrets
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from soc_ml.web.state import DashboardState

__all__ = ["serve", "build_server"]

_MAX_BODY = 64 * 1024


def _page() -> str:
    return (Path(__file__).resolve().parent / "dashboard.html").read_text(
        encoding="utf-8")


class _Handler(BaseHTTPRequestHandler):
    server_version = "soc-ml-ui"
    protocol_version = "HTTP/1.1"

    # -- plumbing ------------------------------------------------------ #

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # This page loads nothing remote and is never framed.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'; img-src data:",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload: Any, code: int = 200) -> None:
        self._send(code, json.dumps(payload, default=str).encode(), "application/json")

    def _error(self, code: int, message: str) -> None:
        self._json({"error": message}, code)

    def _authorized(self) -> bool:
        token = self.server.token  # type: ignore[attr-defined]
        if not token:
            return True
        header = self.headers.get("Authorization", "")
        supplied = header[7:] if header.startswith("Bearer ") else ""
        return secrets.compare_digest(supplied, token)

    # -- routing ------------------------------------------------------- #

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        state: DashboardState = self.server.state  # type: ignore[attr-defined]

        try:
            if route == "/":
                self._send(200, _page().encode(), "text/html; charset=utf-8")
            elif route == "/api/overview":
                self._json(state.overview())
            elif route == "/api/catalog":
                self._json({"usecases": state.catalog()})
            elif route == "/api/models":
                self._json(state.models())
            elif route == "/api/timeseries":
                self._json(state.timeseries())
            elif route == "/api/records":
                kind = (query.get("kind") or ["alerts"])[0]
                slug = (query.get("slug") or [""])[0]
                limit = int((query.get("limit") or ["100"])[0])
                if not slug:
                    self._error(400, "slug is required")
                    return
                self._json(state.records(kind, slug, limit))
            elif route == "/api/health":
                self._json({"ok": True, "requires_token": bool(
                    self.server.token)})  # type: ignore[attr-defined]
            else:
                self._error(404, f"no route {route}")
        except KeyError as exc:
            self._error(400, f"unknown kind {exc}")
        except ValueError as exc:
            self._error(400, str(exc))
        except Exception as exc:  # never leak a traceback to a browser
            self._error(500, f"{type(exc).__name__}: {exc}")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        route = urlparse(self.path).path.rstrip("/") or "/"
        state: DashboardState = self.server.state  # type: ignore[attr-defined]

        if not self._authorized():
            self._error(401, "bearer token required for this action")
            return
        if self.server.read_only:  # type: ignore[attr-defined]
            self._error(403, "server started read-only; promotion is disabled")
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > _MAX_BODY:
                self._error(413, "body too large")
                return
            body = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            self._error(400, "body must be JSON")
            return

        slug = (body or {}).get("slug")
        if not slug:
            self._error(400, "slug is required")
            return

        try:
            if route == "/api/models/promote":
                self._json(state.promote(slug, (body or {}).get("version")))
            elif route == "/api/models/rollback":
                self._json(state.rollback(slug))
            else:
                self._error(404, f"no route {route}")
        except ValueError as exc:
            self._error(409, str(exc))
        except Exception as exc:
            self._error(500, f"{type(exc).__name__}: {exc}")


def build_server(
    state: DashboardState,
    host: str = "127.0.0.1",
    port: int = 8888,
    token: str | None = None,
    read_only: bool = False,
    verbose: bool = False,
) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    httpd.daemon_threads = True
    httpd.state = state          # type: ignore[attr-defined]
    httpd.token = token          # type: ignore[attr-defined]
    httpd.read_only = read_only  # type: ignore[attr-defined]
    httpd.verbose = verbose      # type: ignore[attr-defined]
    return httpd


def serve(
    data_root: str | Path,
    host: str = "127.0.0.1",
    port: int = 8888,
    tls_cert: str | None = None,
    tls_key: str | None = None,
    token: str | None = None,
    read_only: bool = False,
    allow_remote: bool = False,
    verbose: bool = False,
    log=None,
) -> int:
    # Unbuffered by default: redirected to a file, Python buffers stdout, and
    # the startup banner carries the bearer token — an operator who cannot see
    # it cannot use the promote button.
    if log is None:
        def log(*a):
            print(*a, flush=True)

    loopback = host in ("127.0.0.1", "::1", "localhost")
    if not loopback and not tls_cert and not allow_remote:
        log(
            f"[ui] REFUSING to bind {host} without TLS.\n"
            "     This serves alert data and can promote models. Either pass\n"
            "     --tls-cert/--tls-key, keep the default 127.0.0.1 and use an\n"
            "     SSH tunnel, or pass --allow-remote to accept the risk."
        )
        return 2

    # A token is generated whenever writes are possible and the socket is not
    # loopback-only — a promote button reachable from the network with no
    # credential is not a defensible default.
    if token is None and not read_only and not loopback:
        token = secrets.token_urlsafe(24)

    state = DashboardState(data_root)
    state.start_sampler()
    httpd = build_server(state, host, port, token, read_only, verbose)

    scheme = "http"
    if tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key or tls_cert)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    shown = "localhost" if loopback else host
    log(f"[ui] dashboard on {scheme}://{shown}:{port}  (data root {state.data_root})")
    log(f"[ui] mode: {'read-only' if read_only else 'promotion enabled'}")
    if token:
        log(f"[ui] bearer token for write actions: {token}")
    if not tls_cert and not loopback:
        log("[ui] WARNING: serving plaintext on a non-loopback address")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        log("\n[ui] stopping")
    finally:
        state.stop_sampler()
        httpd.shutdown()
        httpd.server_close()
    return 0


def serve_in_thread(httpd: ThreadingHTTPServer) -> threading.Thread:
    """Run an already-built server in a daemon thread (used by the tests)."""
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return thread
