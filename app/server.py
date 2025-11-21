import json
import os
import signal
import socket
import ssl
import threading
from pathlib import Path
from urllib.parse import parse_qs

from auth.repositories.session_repository import SessionRepository
from auth.repositories.user_repository import UserRepository
from auth.services.session_cleanup_service import SessionCleanupService
from helpers.env_loader import load_env_file
from helpers.ip_mac import get_mac_for_ip
from infra.firewall import firewall as firewall_module

load_env_file()

HOST = "0.0.0.0"
PORT = int(os.getenv("HTTPS_PORT", "8443"))
REDIRECT_PORT = int(os.getenv("HTTP_REDIRECT_PORT", "8080"))
PORTAL_HOST = os.getenv("PORTAL_HOST", "10.42.0.1")
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "login.html"
CERT_FILE = Path(__file__).resolve().parent / "certs" / "portal.crt"
KEY_FILE = Path(__file__).resolve().parent / "certs" / "portal.key"


user_repository = UserRepository()
session_repository = SessionRepository()
session_cleanup_service = SessionCleanupService(session_repository)
firewall = firewall_module
_shutdown_event = threading.Event()
_server_socket: socket.socket | None = None
_redirect_socket: socket.socket | None = None


def build_response(status_code, body=b"", headers=None):
    reason = "OK"
    status_line = f"HTTP/1.1 {status_code} {reason}\r\n"
    headers = headers or {}
    base_headers = {
        "Content-Length": str(len(body)),
        "Connection": "close",
    }
    base_headers.update(headers)
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in base_headers.items())
    return (status_line + header_lines + "\r\n").encode("utf-8") + body


def send_json(conn, status_code, payload, headers=None):
    body = json.dumps(payload).encode("utf-8")
    headers = headers or {}
    response = build_response(
        status_code,
        body=body,
        headers={"Content-Type": "application/json", **headers},
    )
    conn.sendall(response)


def send_html(conn, status_code, html_text):
    body = html_text.encode("utf-8")
    response = build_response(
        status_code,
        body=body,
        headers={"Content-Type": "text/html; charset=utf-8"},
    )
    conn.sendall(response)


def parse_http_request(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk

    if not data:
        raise ValueError("Petición vacía")

    header_part, rest = data.split(b"\r\n\r\n", 1)
    header_text = header_part.decode("utf-8", errors="replace")
    lines = header_text.split("\r\n")

    request_line = lines[0]
    try:
        method, path, version = request_line.split(" ")
    except ValueError:
        raise ValueError("Línea de petición inválida")

    headers = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    body = rest
    content_length = int(headers.get("content-length", "0") or "0")
    while len(body) < content_length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body += chunk

    return method, path, version, headers, body


def handle_login(headers, body, client_ip):
    content_type = headers.get("content-type", "")
    content_type = content_type.split(";")[0].strip() or "application/json"

    username = None
    password = None

    if content_type == "application/json":
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return 400, {"status": "error", "message": "JSON inválido"}, None
        username = data.get("username")
        password = data.get("password")
    elif content_type == "application/x-www-form-urlencoded":
        parsed = parse_qs(body.decode("utf-8"))
        username = (parsed.get("username") or parsed.get("email") or [None])[0]
        password = (parsed.get("password") or [None])[0]
    else:
        return 415, {"status": "error", "message": "Content-Type no soportado"}, None

    if not username or not password:
        return 400, {
            "status": "error",
            "message": "Faltan campos username o password",
        }, None

    if user_repository.verify_credentials(username, password):
        mac = get_mac_for_ip(client_ip)

        existing_session = session_repository.find_session_by_ip(client_ip)
        if existing_session:
            existing_mac = (existing_session.get("mac") or "").lower()
            current_mac = (mac or "").lower()
            if existing_mac and current_mac and existing_mac != current_mac:
                return 403, {
                    "status": "error",
                    "message": "La IP ya está asociada a otro dispositivo",
                }, None

        session_repository.create_session(username, client_ip, mac)

        try:
            firewall.allow_client_in_firewall(client_ip, mac)
        except Exception as exc:
            print(f"[firewall] No se pudo permitir {client_ip}: {exc}")

        return 200, {
            "status": "ok",
            "message": "Login exitoso",
            "username": username,
        }, None

    return 401, {
        "status": "error",
        "message": "Credenciales inválidas",
    }, None


def handle_logout(client_ip):
    session_key = session_repository.get_session_key_for_ip(client_ip)
    if not session_key:
        return 200, {
            "status": "ok",
            "message": "No había sesión activa",
        }, None

    session = session_repository.get_session(session_key)
    destroyed = session_repository.destroy_session(session_key)

    ip = client_ip
    mac = None
    if destroyed:
        ip, mac = destroyed
    elif session:
        ip = session.get("ip") or client_ip
        mac = session.get("mac")

    if ip:
        try:
            firewall.deny_client_in_firewall(ip, mac)
        except Exception as exc:
            print(f"[firewall] No se pudo bloquear {ip}: {exc}")

    return 200, {
        "status": "ok",
        "message": "Sesión cerrada",
    }, None


def serve_login_page():
    try:
        html = TEMPLATE_PATH.read_text(encoding="utf-8")
        return 200, html
    except OSError:
        return 500, "<h1>Error 500</h1><p>Template no disponible</p>"


def handle_redirect_client(conn, addr):
    redirect_host = PORTAL_HOST
    location = f"https://{redirect_host}:{PORT}/login"
    body = (
        "<html><head><title>Redirigiendo...</title></head>"
        f"<body>Redirigiendo a <a href=\"{location}\">{location}</a></body></html>"
    )
    response = build_response(
        302,
        body=body.encode("utf-8"),
        headers={
            "Content-Type": "text/html; charset=utf-8",
            "Location": location,
        },
    )
    try:
        conn.sendall(response)
    finally:
        conn.close()


def handle_client(conn, addr):
    client_ip, _ = addr
    try:
        method, path, version, headers, body = parse_http_request(conn)
    except ValueError as exc:
        send_json(conn, 400, {"status": "error", "message": str(exc)})
        conn.close()
        return
    except Exception as exc:
        send_json(conn, 500, {"status": "error", "message": f"Error interno: {exc}"})
        conn.close()
        return

    try:
        if method == "GET":
            status_code, html = serve_login_page()
            send_html(conn, status_code, html)
        elif method == "POST" and path == "/login":
            status_code, payload, extra_headers = handle_login(
                headers, body, client_ip
            )
            send_json(conn, status_code, payload, headers=extra_headers)
        elif method == "POST" and path == "/logout":
            status_code, payload, extra_headers = handle_logout(client_ip)
            send_json(conn, status_code, payload, headers=extra_headers)
        else:
            send_json(conn, 404, {"status": "error", "message": "Endpoint no encontrado"})
    except Exception as exc:
        send_json(conn, 500, {"status": "error", "message": f"Error interno: {exc}"})
    finally:
        conn.close()


def shutdown_services():
    if getattr(shutdown_services, "_done", False):
        return
    try:
        clients = session_repository.destroy_all_sessions()
    except Exception as exc:
        print(f"[shutdown] No se pudieron limpiar sesiones: {exc}")
        clients = []

    for ip, mac in clients:
        try:
            firewall.deny_client_in_firewall(ip, mac)
        except Exception as exc:
            print(f"[shutdown] Error bloqueando {ip}: {exc}")

    session_cleanup_service.stop()
    shutdown_services._done = True  


def _handle_termination(signum, _frame):
    print(f"\nRecibida señal {signum}, deteniendo servidor...")
    _shutdown_event.set()
    global _server_socket
    sock = _server_socket
    if sock:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
    redirect_sock = _redirect_socket
    if redirect_sock:
        try:
            redirect_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            redirect_sock.close()
        except OSError:
            pass


def run_server():
    session_repository.init_store()
    session_cleanup_service.start()
    signal.signal(signal.SIGTERM, _handle_termination)
    signal.signal(signal.SIGINT, _handle_termination)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))

    redirect_thread = threading.Thread(
        target=run_http_redirect_server,
        name="HTTPRedirectServer",
        daemon=True,
    )
    redirect_thread.start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        global _server_socket
        _server_socket = server_socket
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(50)
        print(f"Servidor HTTPS simple escuchando en {HOST}:{PORT}")
        try:
            while not _shutdown_event.is_set():
                try:
                    conn, addr = server_socket.accept()
                except OSError:
                    if _shutdown_event.is_set():
                        break
                    raise
                try:
                    tls_conn = context.wrap_socket(conn, server_side=True)
                except ssl.SSLError as exc:
                    print(f"[ssl] Error de handshake con {addr}: {exc}")
                    conn.close()
                    continue
                threading.Thread(
                    target=handle_client, args=(tls_conn, addr), daemon=True
                ).start()
        finally:
            shutdown_services()


def run_http_redirect_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as redirect_socket:
        global _redirect_socket
        _redirect_socket = redirect_socket
        redirect_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        redirect_socket.bind((HOST, REDIRECT_PORT))
        redirect_socket.listen(50)
        print(f"Servidor HTTP de redirección escuchando en {HOST}:{REDIRECT_PORT}")
        while not _shutdown_event.is_set():
            try:
                conn, addr = redirect_socket.accept()
            except OSError:
                if _shutdown_event.is_set():
                    break
                raise
            threading.Thread(
                target=handle_redirect_client, args=(conn, addr), daemon=True
            ).start()


if __name__ == "__main__":
    run_server()
