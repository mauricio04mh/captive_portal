from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
from urllib.parse import parse_qs

from auth.auth import UserRepository

user_repository = UserRepository()


class CaptivePortalHandler(BaseHTTPRequestHandler):

    TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "login.html"

    def _send_json(self, status_code, payload):
        response_bytes = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def _send_html(self, status_code, html_text):
        response_bytes = html_text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def do_GET(self):
        if self.path in ("/", "/login"):
            self.serve_login_page()
        else:
            self._send_json(404, {"status": "error", "message": "Endpoint no encontrado"})

    def serve_login_page(self):
        try:
            html = self.TEMPLATE_PATH.read_text(encoding="utf-8")
        except OSError:
            self._send_json(500, {"status": "error", "message": "Template no disponible"})
            return

        self._send_html(200, html)

    def do_POST(self):
        if self.path == "/login":
            self.handle_login()
        else:
            self._send_json(404, {"status": "error", "message": "Endpoint no encontrado"})

    def handle_login(self):
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"status": "error", "message": "Content-Length inválido"})
            return

        body_bytes = self.rfile.read(content_length)
        content_type = (self.headers.get("Content-Type", "").split(";")[0] or
                        "application/json").strip()

        username = None
        password = None

        if content_type == "application/json":
            try:
                data = json.loads(body_bytes.decode("utf-8"))
            except json.JSONDecodeError:
                self._send_json(400, {"status": "error", "message": "JSON inválido"})
                return
            username = data.get("username") or data.get("email")
            password = data.get("password")
        elif content_type == "application/x-www-form-urlencoded":
            parsed = parse_qs(body_bytes.decode("utf-8"))
            username = (parsed.get("username") or parsed.get("email") or [None])[0]
            password = (parsed.get("password") or [None])[0]
        else:
            self._send_json(415, {"status": "error", "message": "Content-Type no soportado"})
            return

        if not username or not password:
            self._send_json(400, {"status": "error", "message": "Faltan campos username o password"})
            return

        if user_repository.verify_credentials(username, password):
            self._send_json(200, {
                "status": "ok",
                "message": "Login exitoso",
                "username": username
            })
        else:
            self._send_json(401, {
                "status": "error",
                "message": "Credenciales inválidas"
            })
