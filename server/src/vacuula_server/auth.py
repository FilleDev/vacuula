"""Optional password gate for the web panel and its API.

When VACUULA_PASSWORD is set, /api/* (including the live event streams) requires a
signed cookie. The cookie is handed out by POST /api/login (HTTPS only) and lasts a year. The web
app's static files stay public - it shows its own login screen and holds no data.
Robot traffic (beehive/nucleo/S3) and the endpoints the installer needs are never gated.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import ssl
import time
from http.cookies import SimpleCookie

from vacuula_server.constants import DATA_DIR
from vacuula_server.env import VACUULA_PASSWORD

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from vacuula_server.handlers.router import RouterHandler

COOKIE_NAME = "vacuula_auth"
COOKIE_MAX_AGE_S = 365 * 24 * 60 * 60
WRONG_PASSWORD_DELAY_S = 1.0
SECRET_FILE = DATA_DIR / "auth_secret"

# Installer + health check (server, cert) and the login flow itself stay open
OPEN_API_PATHS = {"/api/server", "/api/cert", "/api/auth", "/api/login"}

logger = logging.getLogger(__name__)


def enabled() -> bool:
    return bool(VACUULA_PASSWORD)


_secret: bytes | None = None

def _get_secret() -> bytes:
    """Random signing key, created once and kept in the data dir so cookies survive restarts."""
    global _secret
    if _secret is None:
        try:
            _secret = bytes.fromhex(SECRET_FILE.read_text().strip())
        except (OSError, ValueError):
            _secret = secrets.token_bytes(32)
            SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
            SECRET_FILE.write_text(_secret.hex())
    return _secret


def _signature(expires: int) -> str:
    # The password is part of the signed message, so changing it logs everyone out
    msg = f"{expires}|{hashlib.sha256(VACUULA_PASSWORD.encode()).hexdigest()}".encode()
    return hmac.new(_get_secret(), msg, hashlib.sha256).hexdigest()


def _make_token() -> str:
    expires = int(time.time()) + COOKIE_MAX_AGE_S
    return f"{expires}.{_signature(expires)}"


def _token_valid(token: str) -> bool:
    try:
        expires_str, sig = token.split(".", 1)
        expires = int(expires_str)
    except ValueError:
        return False
    return expires > time.time() and hmac.compare_digest(sig, _signature(expires))


def is_authenticated(req: RouterHandler) -> bool:
    if not enabled():
        return True
    cookie = SimpleCookie()
    try:
        cookie.load(req.headers.get("Cookie", ""))
    except Exception:
        return False
    morsel = cookie.get(COOKIE_NAME)
    return morsel is not None and _token_valid(morsel.value)


def needs_auth(req: RouterHandler) -> bool:
    """True for API calls the caller isn't logged in for."""
    if not enabled():
        return False
    path = req.path.split("?", 1)[0]
    if not path.startswith("/api/") or path in OPEN_API_PATHS:
        return False
    return not is_authenticated(req)


def _is_https(req: RouterHandler) -> bool:
    """Direct TLS (gen3 port) or a reverse proxy that terminated HTTPS for us."""
    if isinstance(req.connection, ssl.SSLSocket):
        return True
    return req.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower() == "https"


def get_auth(req: RouterHandler) -> None:
    """GET /api/auth - whether a password is set and if this browser is logged in."""
    req.send_response_data({"required": enabled(), "authenticated": is_authenticated(req)}, cache_control="no-store")


def post_login(req: RouterHandler) -> None:
    """POST /api/login {"password": "..."} - check the password and set the 1-year cookie."""
    data = req.read_json()
    if data is None:
        return
    password = str(data.get("password", ""))

    # Only log in over HTTPS, so the password and the cookie never travel in plain text
    if not _is_https(req):
        logger.warning("Refused panel login over plain HTTP from %s", req.client_ip())
        req.send_error_response(400, "HTTPS required")
        return

    if not enabled() or not hmac.compare_digest(password.encode(), VACUULA_PASSWORD.encode()):
        logger.warning("Failed panel login from %s", req.client_ip())
        time.sleep(WRONG_PASSWORD_DELAY_S)  # slows down guessing
        req.send_unauthorized("Wrong password")
        return

    logger.info("Panel login from %s", req.client_ip())
    req.send_response(200)
    req.send_header("Set-Cookie", f"{COOKIE_NAME}={_make_token()}; Max-Age={COOKIE_MAX_AGE_S}; Path=/; HttpOnly; Secure; SameSite=Lax")
    req.send_header("Cache-Control", "no-store")
    req.send_header("Content-Type", "application/json")
    req.send_header("Content-Length", "4")
    req.send_header("Connection", "close")
    req.end_headers()
    req.wfile.write(b'"OK"')
    req.wfile.flush()
