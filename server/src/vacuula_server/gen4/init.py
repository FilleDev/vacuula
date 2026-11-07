from __future__ import annotations
import logging
from vacuula_server.env import GEN4_PORT, HOST_IP
from vacuula_server.handlers.events import notify_robots_changed
from vacuula_server.tls import CERT, KEY
import threading
import socket, ssl, struct, json
from vacuula_server.generation import Generation
from vacuula_server.conn import RobotConn, Gen4Conn
from vacuula_server.gen4.handlers import handle_login, robot_response, heartbeat_thread, robot_event, roboot_request
from vacuula_server.state import robot_connections

logger = logging.getLogger(__name__)

ROBOT_SOCKET_TIMEOUT_S = 20

def start():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST_IP, GEN4_PORT))
        sock.listen(5)
        logger.info("Gen4 listening on %s:%d", HOST_IP, GEN4_PORT)

        while True:
            client, addr = sock.accept()
            client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 20_000)
            client.settimeout(ROBOT_SOCKET_TIMEOUT_S)

            # Peek at only the start of the stream so a failed TLS handshake can
            # be distinguished from a silent peer or plaintext sent to this port.
            try:
                initial_bytes = client.recv(8, socket.MSG_PEEK)
            except TimeoutError as e:
                logger.warning(
                    "Gen4 TCP peer %s sent no data within %ss, before TLS handshake: %s",
                    addr, ROBOT_SOCKET_TIMEOUT_S, e,
                )
                client.close()
                continue
            except OSError as e:
                logger.warning("Gen4 TCP peer %s failed before TLS handshake: %s", addr, e)
                try:
                    client.close()
                except OSError:
                    pass
                continue

            if not initial_bytes:
                logger.info("Gen4 TCP peer %s closed before TLS handshake", addr)
                client.close()
                continue

            if initial_bytes.startswith(b"\x16"):
                protocol_hint = "TLS record"
            elif initial_bytes.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"PRI ")):
                protocol_hint = "plaintext HTTP"
            else:
                protocol_hint = "unknown protocol"
            logger.info(
                "Gen4 TCP connection from %s; initial bytes=%s (%s)",
                addr, initial_bytes.hex(" "), protocol_hint,
            )

            try:
                tls = ctx.wrap_socket(client, server_side=True)
            except OSError as e:
                # A peer can reset or time out while TLS is negotiating. Keep
                # the initial bytes in the log to help identify wrong protocols.
                logger.warning(
                    "Gen4 TLS handshake failed from %s (initial bytes=%s): %s",
                    addr, initial_bytes.hex(" "), e,
                )
                try:
                    client.close()
                except OSError:
                    pass
                continue

            cipher = tls.cipher()
            logger.info(
                "Gen4 TLS established with %s: version=%s cipher=%s",
                addr, tls.version(), cipher[0] if cipher else "unknown",
            )
            threading.Thread(target=handle_robot, args=(tls, addr), daemon=True).start()



def recv_packet(sock, peer):
    hdr = b""
    header_timeout_logged = False
    while len(hdr) < 4:
        try:
            chunk = sock.recv(4 - len(hdr))
        except TimeoutError:
            if not header_timeout_logged:
                logger.info(
                    "Gen4 peer %s has sent no packet header data for %ss; still waiting (%d/4 bytes)",
                    peer, ROBOT_SOCKET_TIMEOUT_S, len(hdr),
                )
                header_timeout_logged = True
            continue
        if not chunk:
            logger.info(
                "Gen4 peer %s closed while reading packet header (%d/4 bytes)",
                peer, len(hdr),
            )
            return None
        hdr += chunk
    (n,) = struct.unpack(">I", hdr)
    if n == 0:
        return b""
    if n > 10 * 1024 * 1024:
        logger.warning("Gen4 peer %s sent oversized packet length: %d", peer, n)
        return None
    data = b""
    body_timeout_logged = False
    while len(data) < n:
        try:
            chunk = sock.recv(min(65536, n - len(data)))
        except TimeoutError:
            if not body_timeout_logged:
                logger.info(
                    "Gen4 peer %s sent no packet body data for %ss; still waiting (%d/%d bytes)",
                    peer, ROBOT_SOCKET_TIMEOUT_S, len(data), n,
                )
                body_timeout_logged = True
            continue
        if not chunk:
            logger.info(
                "Gen4 peer %s closed during packet body (%d/%d bytes)",
                peer, len(data), n,
            )
            return None
        data += chunk
    return data


def handle_robot(conn, addr):
    rc = RobotConn("<unknown>", Generation.GEN4, Gen4Conn(conn))
    conn.settimeout(ROBOT_SOCKET_TIMEOUT_S)
    heartbeat_seen = False

    try:
        json_count = 0
        while True:

            raw = recv_packet(conn, addr)
            if raw is None:
                break

            if raw == b"\x06":
                if not heartbeat_seen:
                    logger.info("First Gen4 heartbeat from %s", addr)
                    heartbeat_seen = True
                else:
                    logger.debug("heartbeat from %s", rc.serial or addr)
                continue
            if raw == b"\x00":
                logger.info("CLOSE from %s", rc.serial or addr)
                break

            try:
                msg = json.loads(raw)
            except Exception as e:
                logger.warning("non-JSON packet from %s: %s raw=%r", rc.serial or addr, e, raw[:80])
                continue

            json_count += 1 # TODO: verify and remove that a counter does not need to be here, after initial release
            if json_count == 1:
                logger.info(
                    "First Gen4 JSON packet from %s: type=%r serial=%r keys=%s",
                    addr, msg.get("type"), msg.get("serial"), sorted(msg.keys()),
                )
            if json_count == 1 and "signature" in msg:
                threading.Thread(target=handle_login, args=(rc, msg), daemon=True).start()
                hb_t = threading.Thread(target=heartbeat_thread, args=(rc,), daemon=True)
                hb_t.start()
                continue

            msg_id = msg.get("id")
            msg_type = msg.get("type")
            if msg_type == "event":
                robot_event(rc, msg)
            elif msg_type == "response":
                robot_response(rc, msg)
            elif msg_type == "request":
                threading.Thread(target=roboot_request, args=(rc, msg_id, msg), daemon=True).start()
            else:
                logger.warning("unknown msg type %r from %s: %s", msg_type, rc.serial or addr, json.dumps(msg)[:200])

    except (
        BrokenPipeError,
        ConnectionResetError,
        ConnectionAbortedError,
        ssl.SSLEOFError,
        ssl.SSLZeroReturnError,
    ) as e:
        # Robots can close the TLS connection while we're waiting for a packet.
        # Treat that as a normal disconnect; the finally block handles cleanup.
        logger.info(
            "Gen4 connection %s ended during socket I/O: %s",
            rc.serial if rc.serial != "<unknown>" else addr, e,
        )
    except Exception as e:
        logger.error("error handling robot %s: %s", rc.serial or addr, e)
        import traceback
        traceback.print_exc()
    finally:
        rc.stop_event.set()
        if robot_connections.get(rc.serial) is rc:
            del robot_connections[rc.serial]
        logger.info(
            "Robot %s disconnected",
            rc.serial if rc.serial != "<unknown>" else addr,
        )
        notify_robots_changed()
        try:
            conn.close()
        except Exception:
            logger.error("error closing connection for robot %s", rc.serial or addr)
            pass

