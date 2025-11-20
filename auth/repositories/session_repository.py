import json
import time
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class SessionRepository:

    def __init__(
        self,
        sessions_file: Path | None = None,
        session_duration: int = 10 * 60, #10 minutos
    ) -> None:
        base_path = Path(__file__).resolve().parent
        # Guardamos las sesiones en auth/db (fuera de repositories)
        self.sessions_file = sessions_file or (base_path.parent / "db" / "sessions.json")
        self.session_duration = session_duration

        # Estado en memoria (cache)
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _session_key(self, ip: str, mac: Optional[str]) -> str:
        """Genera una clave única para una sesión a partir de IP/MAC."""
        mac_part = mac or ""
        return f"{ip}|{mac_part}"

    def _ensure_file_exists(self) -> None:
        """Garantiza que exista el archivo de sesiones en disco."""
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.sessions_file.exists():
            self._save_to_disk_locked({"sessions": {}})

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
            data = {"sessions": {}}

        self._sessions = data.get("sessions", {})

    def _save_to_disk_locked(self, data: Optional[Dict[str, Any]] = None) -> None:
        """
        Escribe el estado actual a disco.
        IMPORTANTE: Solo llamar con _lock adquirido.
        """
        if data is None:
            data = {"sessions": self._sessions}

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
        Crea una nueva sesión indexada por el par (ip, mac) y devuelve la clave.
        """
        now = time.time()
        expires_at = now + self.session_duration
        session_key = self._session_key(ip, mac)

        with self._lock:
            self._sessions[session_key] = {
                "session_key": session_key,
                "username": username,
                "ip": ip,
                "mac": mac,
                "login_time": now,
                "last_activity": now,
                "expires_at": expires_at,
            }
            self._save_to_disk_locked()

        return session_key

    def get_session(self, session_key: str) -> Optional[Dict[str, Any]]:
        """
        Obtiene una sesión por su clave (ip|mac) desde el cache con fallback a disco.
        """
        with self._lock:
            session = self._sessions.get(session_key)
            if session is not None:
                return session
            self._load_from_disk_locked()
            return self._sessions.get(session_key)

    def mark_activity(self, session_key: str) -> bool:
        """
        Actualiza last_activity y renueva expires_at para una sesión existente.
        """
        now = time.time()
        with self._lock:
            session = self._sessions.get(session_key)
            if not session:
                return False

            session["last_activity"] = now
            session["expires_at"] = now + self.session_duration
            self._save_to_disk_locked()
            return True

    def find_session_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Devuelve la primera sesión asociada a una IP, recargando desde disco si hace falta.
        """
        with self._lock:
            for session in self._sessions.values():
                if session.get("ip") == ip:
                    return session
            self._load_from_disk_locked()
            for session in self._sessions.values():
                if session.get("ip") == ip:
                    return session
            return None

    def get_session_key_for_ip(self, ip: str) -> Optional[str]:
        """
        Devuelve la clave de sesión asociada a una IP, si existe.
        """
        session = self.find_session_by_ip(ip)
        if session:
            return session.get("session_key")
        return None

    def destroy_session(self, session_key: str) -> Optional[Tuple[str, Optional[str]]]:
        """
        Elimina una sesión de memoria y JSON.
        Devuelve el par (ip, mac) asociado o None si no existía.
        """
        with self._lock:
            session = self._sessions.pop(session_key, None)
            if not session:
                return None

            self._save_to_disk_locked()
            return session["ip"], session.get("mac")

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
            for key, session in list(self._sessions.items()):
                if session.get("expires_at", 0) <= now:
                    to_delete.append((key, session["ip"], session.get("mac")))

            for key, ip, mac in to_delete:
                self._sessions.pop(key, None)
                expired_clients.append((ip, mac))

            if to_delete:
                self._save_to_disk_locked()

        return expired_clients

#TODO: QUE la cache funcione bien, con tamanno limite
