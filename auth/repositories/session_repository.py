import heapq
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
        max_cache_size: int | None = 1000,
    ) -> None:
        base_path = Path(__file__).resolve().parent
        self.sessions_file = sessions_file or (base_path / "data" / "sessions.json")
        self.session_duration = session_duration
        self.max_cache_size = max_cache_size

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

        if self._enforce_cache_limit_locked():
            self._save_to_disk_locked()

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

    def _get_session_by_id_locked(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene una sesión intentando primero el cache y recargando desde disco
        si hiciera falta. IMPORTANTE: solo llamar con _lock adquirido.
        """
        session = self._sessions.get(session_id)
        if session is not None:
            return session

        self._load_from_disk_locked()
        return self._sessions.get(session_id)

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
            self._enforce_cache_limit_locked()
            self._save_to_disk_locked()

        return session_id

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene una sesión por id desde el cache en memoria (con fallback a disco),
        o None si no existe.
        """
        with self._lock:
            return self._get_session_by_id_locked(session_id)

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
            return self._get_session_by_id_locked(session_id)

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
            return self._get_session_by_id_locked(sid)

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

    def _evict_session_locked(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if not session:
            return

        ip = session.get("ip")
        if ip and self._auth_clients.get(ip) == session_id:
            self._auth_clients.pop(ip, None)

    def _enforce_cache_limit_locked(self) -> bool:
        """
        Garantiza que el cache no exceda max_cache_size.
        Prioriza limpiar sesiones expiradas y, si sigue sobrando,
        elimina las menos recientes por last_activity/login_time.
        Devuelve True si se evicto algo.
        IMPORTANTE: llamar solo con _lock adquirido.
        """
        limit = self.max_cache_size
        if not limit or limit <= 0:
            return False

        current_size = len(self._sessions)
        if current_size <= limit:
            return False

        now = time.time()
        evicted_any = False

        expired_ids = [
            sid
            for sid, session in self._sessions.items()
            if session.get("expires_at", 0) <= now
        ]

        if expired_ids:
            evicted_any = True
            for sid in expired_ids:
                self._evict_session_locked(sid)

            current_size = len(self._sessions)
            if current_size <= limit:
                return True

        excess = current_size - limit
        if excess <= 0:
            return evicted_any

        candidates = heapq.nsmallest(
            excess,
            self._sessions.items(),
            key=lambda item: item[1].get("last_activity")
            or item[1].get("login_time")
            or 0.0,
        )

        for sid, _ in candidates:
            self._evict_session_locked(sid)

        return True
