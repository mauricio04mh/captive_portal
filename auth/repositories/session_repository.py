import json
import time
import secrets
import threading
from pathlib import Path
from http.cookies import SimpleCookie
from typing import Any, Dict, List, Optional, Tuple


class SessionRepository:

    def __init__(
        self,
        sessions_file: Path | None = None,
        session_duration: int = 10 * 60, #10 minutos
    ) -> None:
        base_path = Path(__file__).resolve().parent
        self.sessions_file = sessions_file or (base_path / "data" / "sessions.json")
        self.session_duration = session_duration

        # Estado en memoria (cache)
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._auth_clients: Dict[str, str] = {}
        self._lock = threading.Lock()

    def _ensure_file_exists(self) -> None:
        """Garantiza que exista el archivo de sesiones en disco."""
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.sessions_file.exists():
            self._save_to_disk_locked({"sessions": {}, "auth_clients": {}})

    def _load_from_disk_locked(self) -> None:
        """
        Lee el JSON de disco y actualiza el estado en memoria.
        IMPORTANTE: Solo llamar con _lock adquirido.
        """
        self._ensure_file_exists()
        try:
            with self.sessions_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            data = {"sessions": {}, "auth_clients": {}}

        self._sessions = data.get("sessions", {})
        self._auth_clients = data.get("auth_clients", {})

    def _save_to_disk_locked(self, data: Optional[Dict[str, Any]] = None) -> None:
        """
        Escribe el estado actual a disco.
        IMPORTANTE: Solo llamar con _lock adquirido.
        """
        if data is None:
            data = {"sessions": self._sessions, "auth_clients": self._auth_clients}

        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.sessions_file.with_suffix(".tmp")

        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)

        tmp.replace(self.sessions_file)

    def init_store(self) -> None:
        """
        Debe llamarse una vez al arrancar el servidor.
        Carga el contenido de sessions.json en memoria.
        """
        with self._lock:
            self._load_from_disk_locked()

    def create_session(self, username: str, ip: str, mac: Optional[str] = None) -> str:
        """
        Crea una nueva sesión, la guarda en memoria y en JSON, y devuelve session_id.
        Esta función EScritora: modifica el cache y persiste en disco.
        """
        now = time.time()
        expires_at = now + self.session_duration
        session_id = secrets.token_urlsafe(32)

        with self._lock:
            self._sessions[session_id] = {
                "username": username,
                "ip": ip,
                "mac": mac,
                "login_time": now,
                "last_activity": now,
                "expires_at": expires_at,
            }
            self._auth_clients[ip] = session_id

            self._save_to_disk_locked()

        return session_id

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene una sesión por id desde el cache en memoria (con fallback a disco),
        o None si no existe.
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                return session
            # Reintentamos cargando desde disco si no existe en memoria
            self._load_from_disk_locked()
            return self._sessions.get(session_id)

    def get_session_from_cookie(self, headers) -> Optional[Dict[str, Any]]:
        """
        Extrae session_id de la cabecera Cookie y devuelve la sesión (o None).
        `headers` es self.headers del handler. Hace fallback a disco si no está en RAM.
        """
        cookie_header = headers.get("Cookie")
        if not cookie_header:
            return None

        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get("session_id")
        if not morsel:
            return None

        session_id = morsel.value
        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                return session
            # Reintentamos cargando desde disco si no existe en memoria
            self._load_from_disk_locked()
            return self._sessions.get(session_id)

    def mark_activity(self, session_id: str) -> bool:
        """
        Actualiza last_activity y renueva expires_at para una sesión existente.
        Escritura: actualiza RAM y persiste en JSON.
        """
        now = time.time()
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            session["last_activity"] = now
            session["expires_at"] = now + self.session_duration
            self._save_to_disk_locked()
            return True

    def find_session_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Devuelve la sesión asociada a una IP (si existe), recargando desde disco si hace falta.
        """
        with self._lock:
            sid = self._auth_clients.get(ip)
            if not sid:
                self._load_from_disk_locked()
                sid = self._auth_clients.get(ip)
                if not sid:
                    return None
            session = self._sessions.get(sid)
            if session is not None:
                return session
            # Si había mapeo pero no sesión, recargamos para sincronizar
            self._load_from_disk_locked()
            return self._sessions.get(sid)

    def destroy_session(self, session_id: str) -> Optional[str]:
        """
        Elimina una sesión (y su relación IP) de memoria y JSON.
        Devuelve la IP asociada (o None si no existía sesión).
        Escritura: actualiza RAM y persiste en JSON.
        """
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if not session:
                return None

            ip = session["ip"]
            # borrar mapeo ip -> session_id si coincide
            current_sid = self._auth_clients.get(ip)
            if current_sid == session_id:
                self._auth_clients.pop(ip, None)

            self._save_to_disk_locked()
            return ip

    def destroy_all_sessions(self) -> List[Tuple[str, Optional[str]]]:
        """
        Elimina todas las sesiones activas del cache y JSON.
        Devuelve la lista de (ip, mac) para que el firewall
        pueda limpiar las reglas correspondientes.
        """
        with self._lock:
            clients = [
                (session["ip"], session.get("mac"))
                for session in self._sessions.values()
            ]
            self._sessions.clear()
            self._auth_clients.clear()
            self._save_to_disk_locked()
            return clients

    def cleanup_expired_sessions(self) -> List[Tuple[str, Optional[str]]]:
        """
        Elimina todas las sesiones expiradas del cache y de JSON.
        Devuelve lista de pares (ip, mac) afectados para que el firewall pueda
        eliminar correctamente la regla asociada.
        Escritura: actualiza RAM y persiste si hubo cambios.
        """
        now = time.time()
        expired_clients: List[Tuple[str, Optional[str]]] = []

        with self._lock:
            to_delete: List[Tuple[str, str, Optional[str]]] = []
            for sid, session in self._sessions.items():
                if session.get("expires_at", 0) <= now:
                    to_delete.append((sid, session["ip"], session.get("mac")))

            for sid, ip, mac in to_delete:
                self._sessions.pop(sid, None)
                current_sid = self._auth_clients.get(ip)
                if current_sid == sid:
                    self._auth_clients.pop(ip, None)
                expired_clients.append((ip, mac))

            if to_delete:
                self._save_to_disk_locked()

        return expired_clients

#TODO: QUE la cache funcione bien, con tamanno limite
