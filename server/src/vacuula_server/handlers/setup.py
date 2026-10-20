from __future__ import annotations
from collections import deque
import logging
from vacuula_server.logger import get_log_files
from zeroconf import NonUniqueNameException, Zeroconf, ServiceInfo
import socket
from pathlib import Path
import os
import re
import subprocess

from typing import TYPE_CHECKING

from vacuula_server.env import VACUULA_HOSTNAME, VACUULA_PORT, get_host_ip
from vacuula_server.constants import APP_VERSION, CERT, CERT_CONFIG, KEY, SSL_DIR, LOG_TAIL_LINES
if TYPE_CHECKING:
    from vacuula_server.handlers.router import RouterHandler


logger = logging.getLogger(__name__)

def ensure_ssl_certificate():
    if CERT.exists() and KEY.exists():
        if VACUULA_HOSTNAME in _certificate_names():
            logger.info("SSL certificate and key already exist, skipping generation.")
            return
        # robots check that the name they connect to is in the certificate
        logger.warning(
            "SSL certificate does not include VACUULA_HOSTNAME %s, generating a new one. "
            "Robots installed before this have to be installed again.",
            VACUULA_HOSTNAME,
        )
    
    logger.info("Generating self-signed SSL certificate and key for %s.", VACUULA_HOSTNAME)

    SSL_DIR.mkdir(parents=True, exist_ok=True)

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey", "rsa:4096",
            "-sha256",
            "-days", "3650",
            "-nodes",
            "-keyout", str(KEY),
            "-out", str(CERT),
            "-config", str(CERT_CONFIG),
        ],
        check=True,
        env={**os.environ, "VACUULA_HOSTNAME": VACUULA_HOSTNAME},
    )

def _certificate_names() -> list[str]:
    """DNS names CERT is valid for"""
    output = subprocess.run(
        ["openssl", "x509", "-in", str(CERT), "-noout", "-ext", "subjectAltName"],
        check=True, capture_output=True, text=True,
    ).stdout
    return re.findall(r"DNS:([^,\s]+)", output)

def get_cert(req: RouterHandler) -> None:
    """GET /cert - download the certificate."""
    try:
        data = CERT.read_bytes()
    except OSError:
        req.send_internal_error("Failed to read certificate")
        return

    req.download_text(data, "vacuula-ca.crt", content_type="application/x-x509-ca-cert")

def get_log(req: RouterHandler) -> None:
    """GET /api/log - send last 500 lines of log."""
    download = '?download=true' in req.path # good enough for now
    lines: deque[bytes] = deque(maxlen=LOG_TAIL_LINES)
    try:
        for path in get_log_files():
            try:
                with open(path, "rb") as f:
                    lines.extend(f)
            except FileNotFoundError:
                continue
    except OSError:
        logger.exception("Failed to read log")
        req.send_internal_error("Failed to read log")
        return

    if download:
        req.download_text(b"".join(lines), "vacuula.log")
    else:
        req.send_text(b"".join(lines))


def get_log_full(req: RouterHandler) -> None:
    """GET /api/log/full - send full log."""
    download = '?download=true' in req.path # good enough for now
    chunks: list[bytes] = []
    try:
        for path in get_log_files():
            try:
                chunks.append(path.read_bytes())
            except FileNotFoundError:
                continue
    except OSError:
        logger.exception("Failed to read log")
        req.send_internal_error("Failed to read log")
        return
    
    if download:
        req.download_text(b"".join(chunks), "vacuula.log")
    else:
        req.send_text(b"".join(chunks))


# mDNS stuff
SERVICE_TYPE = "_vacuula._tcp.local."
SERVICE_NAME = "Vacuula Server._vacuula._tcp.local."
# mDNS only answers for .local names, a domain is found through DNS
MDNS_HOSTNAME = (VACUULA_HOSTNAME if VACUULA_HOSTNAME.endswith(".local") else "vacuula.local") + "."

class MDNSAdvertiser:
    def __init__(self) -> None:
        self._zeroconf = Zeroconf()

        ip = get_host_ip()

        self._info = ServiceInfo(
            SERVICE_TYPE,
            SERVICE_NAME,
            addresses=[socket.inet_aton(ip)],
            server=MDNS_HOSTNAME,
            port=VACUULA_PORT,
            properties={
                "version": APP_VERSION,
                "cert-path": "/api/cert",
                "protocol": "http",
                "url": f"http://{MDNS_HOSTNAME.rstrip('.')}" + (f":{VACUULA_PORT}" if VACUULA_PORT != 80 else ""),
            },
        )

    def start(self) -> None:
        try:
            self._zeroconf.register_service(self._info)
        except (NonUniqueNameException):
            logger.error("mDNS: service name %s is already in use, mDNS advertisement failed", SERVICE_NAME)
            return
        except Exception as e:
            logger.error("mDNS: failed to register service %s: %s", SERVICE_NAME, e)
            return

        logger.info(
            "mDNS: advertising %s at %s:%d",
            SERVICE_NAME,
            self._info.parsed_addresses()[0],
            self._info.port,
        )

    def stop(self) -> None:
        self._zeroconf.unregister_service(self._info)
        self._zeroconf.close()