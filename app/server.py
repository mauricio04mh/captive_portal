import json
import socket
import threading
from pathlib import Path
from urllib.parse import parse_qs

from auth.repositories.user_repository import UserRepository

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


def send_json(conn, status_code, payload):
    body = json.dumps(payload).encode("utf-8")
    response = build_response(
        status_code,
        body=body,
        headers={"Content-Type": "application/json"},
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


def handle_login(method, path, headers, body, client_ip):
    if method != "POST":
        return 405, {"status": "error", "message": "Method Not Allowed"}

    content_type = headers.get("content-type", "")
    content_type = content_type.split(";")[0].strip() or "application/json"

    username = None
    password = None

    if content_type == "application/json":
        try:
            data = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return 400, {"status": "error", "message": "JSON inválido"}
        username = data.get("username") or data.get("email")
        password = data.get("password")
    elif content_type == "application/x-www-form-urlencoded":
        parsed = parse_qs(body.decode("utf-8"))
        username = (parsed.get("username") or parsed.get("email") or [None])[0]
        password = (parsed.get("password") or [None])[0]
    else:
        return 415, {"status": "error", "message": "Content-Type no soportado"}

    if not username or not password:
        return 400, {
            "status": "error",
            "message": "Faltan campos username o password",
        }

    if user_repository.verify_credentials(username, password):
        # Aquí podrías enganchar tu mecanismo para liberar al cliente en la red.
        return 200, {
            "status": "ok",
            "message": "Login exitoso",
            "username": username,
        }

    return 401, {
        "status": "error",
        "message": "Credenciales inválidas",
    }


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
        if method == "GET" and path in ("/", "/login"):
            status_code, html = serve_login_page()
            send_html(conn, status_code, html)
        elif method == "POST" and path == "/login":
            status_code, payload = handle_login(method, path, headers, body, client_ip)
            send_json(conn, status_code, payload)
        else:
            send_json(conn, 404, {"status": "error", "message": "Endpoint no encontrado"})
    except Exception as exc:
        send_json(conn, 500, {"status": "error", "message": f"Error interno: {exc}"})
    finally:
        conn.close()


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(50)
        print(f"Servidor HTTP simple escuchando en {HOST}:{PORT}")
        while True:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    run_server()
