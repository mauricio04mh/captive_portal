import json
import socket
import threading
from pathlib import Path
from urllib.parse import parse_qs

from auth.repositories.session_repository import SessionRepository
from auth.repositories.user_repository import UserRepository
from auth.services.session_cleanup_service import SessionCleanupService
from helpers.ip_mac import get_mac_for_ip
from infra.firewall import firewall as firewall_module

HOST = "0.0.0.0"
PORT = 8080
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "login.html"

STATUS_REASONS = {
    200: "OK",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    415: "Unsupported Media Type",
    500: "Internal Server Error",
}

user_repository = UserRepository()
session_repository = SessionRepository()
session_cleanup_service = SessionCleanupService(session_repository)
firewall = firewall_module


def build_response(status_code, body=b"", headers=None):
    reason = STATUS_REASONS.get(status_code, "OK")
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


def handle_login(method, headers, body, client_ip):
    if method != "POST":
        return 405, {"status": "error", "message": "Method Not Allowed"}, None

    content_type = headers.get("content-type", "")
    content_type = content_type.split(";")[0].strip() or "application/json"

    username = None
    password = None

    if content_type == "application/json":
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return 400, {"status": "error", "message": "JSON inválido"}, None
        username = data.get("username") or data.get("email")
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
        session_id = session_repository.create_session(username, client_ip, mac)
        cookie = (
            f"session_id={session_id}; Path=/; HttpOnly; "
            f"Max-Age={session_repository.session_duration}"
        )

        try:
            firewall.allow_client_in_firewall(client_ip, mac)
        except Exception as exc:
            print(f"[firewall] No se pudo permitir {client_ip}: {exc}")

        return 200, {
            "status": "ok",
            "message": "Login exitoso",
            "username": username,
        }, {"Set-Cookie": cookie}

    return 401, {
        "status": "error",
        "message": "Credenciales inválidas",
    }, None


def serve_login_page():
    try:
        html = TEMPLATE_PATH.read_text(encoding="utf-8")
        return 200, html
    except OSError:
        return 500, "<h1>Error 500</h1><p>Template no disponible</p>"


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
                method, headers, body, client_ip
            )
            send_json(conn, status_code, payload, headers=extra_headers)
        else:
            send_json(conn, 404, {"status": "error", "message": "Endpoint no encontrado"})
    except Exception as exc:
        send_json(conn, 500, {"status": "error", "message": f"Error interno: {exc}"})
    finally:
        conn.close()


def shutdown_services():
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


def run_server():
    session_repository.init_store()
    session_cleanup_service.start()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(50)
        print(f"Servidor HTTP simple escuchando en {HOST}:{PORT}")
        try:
            while True:
                conn, addr = server_socket.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\nServidor detenido por el usuario.")
        finally:
            shutdown_services()


if __name__ == "__main__":
    run_server()
