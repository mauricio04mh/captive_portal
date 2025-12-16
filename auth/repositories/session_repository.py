import heapq
import json
import time
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SessionRecord = Dict[str, Any]


class SessionRepository:

    def __init__(
        self,
        sessions_file: Path | None = None,
        session_duration: int = 10 * 60,  # 10 minutos
        max_cache_size: int | None = 1000,
    ) -> None:
        base_path = Path(__file__).resolve().parent
        self.sessions_file = sessions_file or (base_path / "db" / "sessions.json")
        self.session_duration = session_duration
        self.max_cache_size = max_cache_size

        # Caché en memoria (acelerador de lectura)
        self._cache: Dict[str, SessionRecord] = {}
        self._lock = threading.Lock()

        # Asegura desde el arranque que el archivo exista y sea válido (o al menos utilizable).
        with self._lock:
            self._ensure_store_initialized_locked()

    @staticmethod
    def _make_session_key(ip: str, mac: Optional[str]) -> str:
        return ip + mac if mac is not None else ip

    @staticmethod
    def _is_expired(session: SessionRecord, now: float) -> bool:
        return float(session.get("expires_at", 0.0)) <= now

    def _ensure_store_initialized_locked(self) -> None:
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.sessions_file.exists():
            self._write_disk_data_locked({"sessions": {}})
            return

    def _read_disk_data_locked(self) -> Dict[str, Any]:
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.sessions_file.exists():
            self._write_disk_data_locked({"sessions": {}})

        try:
            with self.sessions_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            data = {"sessions": {}}

        sessions = data.get("sessions")
        if not isinstance(sessions, dict):
            sessions = {}

        return {"sessions": sessions}

    def _write_disk_data_locked(self, data: Dict[str, Any]) -> None:
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.sessions_file.with_suffix(".tmp")

        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)

        tmp.replace(self.sessions_file)

    def _upsert_session_to_disk_locked(self, session_key: str, session: SessionRecord) -> None:
        data = self._read_disk_data_locked()
        data["sessions"][session_key] = session
        self._write_disk_data_locked(data)

    def _pop_session_from_disk_locked(self, session_key: str) -> Optional[SessionRecord]:
        data = self._read_disk_data_locked()
        sessions: Dict[str, Any] = data["sessions"]
        removed = sessions.pop(session_key, None)
        if removed is not None:
            self._write_disk_data_locked(data)
        return removed

    def _read_session_from_disk_locked(self, session_key: str) -> Optional[SessionRecord]:
        data = self._read_disk_data_locked()
        session = data["sessions"].get(session_key)
        return session if isinstance(session, dict) else None

    def init_store(self) -> None:
        now = time.time()
        with self._lock:
            self._ensure_store_initialized_locked()

            data = self._read_disk_data_locked()
            all_sessions: Dict[str, SessionRecord] = {
                k: v for k, v in data["sessions"].items() if isinstance(v, dict) and not self._is_expired(v, now)
            }

            limit = self.max_cache_size
            if not limit or limit <= 0:
                self._cache.clear()
                return

            if len(all_sessions) <= limit:
                self._cache = dict(all_sessions)
                return

            # Mantener las más recientes por last_activity/login_time
            def score(item: Tuple[str, SessionRecord]) -> float:
                s = item[1]
                return float(s.get("last_activity") or s.get("login_time") or 0.0)

            most_recent = heapq.nlargest(limit, all_sessions.items(), key=score)
            self._cache = dict(most_recent)

    def create_session(self, username: str, ip: str, mac: Optional[str] = None) -> str:
        now = time.time()
        expires_at = now + self.session_duration
        session_key = self._make_session_key(ip, mac)

        session: SessionRecord = {
            "username": username,
            "ip": ip,
            "mac": mac,
            "login_time": now,
            "last_activity": now,
            "expires_at": expires_at,
        }

        with self._lock:
            self._cache[session_key] = session
            self._enforce_cache_limit_locked()
            self._upsert_session_to_disk_locked(session_key, session)

        return session_key

    def get_session(self, ip: str, mac: Optional[str] = None) -> Optional[SessionRecord]:
        session_key = self._make_session_key(ip, mac)
        now = time.time()

        with self._lock:
            cached = self._cache.get(session_key)
            if cached is not None:
                if self._is_expired(cached, now):
                    self._cache.pop(session_key, None)
                    return None
                return dict(cached)

            session = self._read_session_from_disk_locked(session_key)
            if session is None:
                return None

            if self._is_expired(session, now):
                return None

            self._cache[session_key] = session
            self._enforce_cache_limit_locked()
            return dict(session)

    def mark_activity(self, ip: str, mac: Optional[str] = None) -> bool:
        """
        Actualiza last_activity y renueva expires_at para una sesión existente.
        """
        session_key = self._make_session_key(ip, mac)
        now = time.time()

        with self._lock:
            session = self._cache.get(session_key)
            if session is None:
                session = self._read_session_from_disk_locked(session_key)
                if session is None:
                    return False

            if self._is_expired(session, now):
                self._cache.pop(session_key, None)
                return False

            session["last_activity"] = now
            session["expires_at"] = now + self.session_duration

            self._cache[session_key] = session
            self._enforce_cache_limit_locked()
            self._upsert_session_to_disk_locked(session_key, session)
            return True

    def destroy_session(self, ip: str, mac: Optional[str] = None) -> Optional[Tuple[str, Optional[str]]]:
        session_key = self._make_session_key(ip, mac)

        with self._lock:
            self._cache.pop(session_key, None)
            removed = self._pop_session_from_disk_locked(session_key)
            if not removed:
                return None
            return (removed.get("ip", ip), removed.get("mac"))

    def destroy_all_sessions(self) -> List[Tuple[str, Optional[str]]]:
        with self._lock:
            data = self._read_disk_data_locked()
            sessions: Dict[str, SessionRecord] = data["sessions"]

            clients: List[Tuple[str, Optional[str]]] = []
            for s in sessions.values():
                if isinstance(s, dict):
                    clients.append((str(s.get("ip", "")), s.get("mac")))

            data["sessions"] = {}
            self._write_disk_data_locked(data)
            self._cache.clear()
            return clients

    def cleanup_expired_sessions(self) -> List[Tuple[str, Optional[str]]]:
        now = time.time()
        expired_clients: List[Tuple[str, Optional[str]]] = []

        with self._lock:
            data = self._read_disk_data_locked()
            sessions: Dict[str, SessionRecord] = data["sessions"]

            to_delete_keys: List[str] = []
            for key, session in sessions.items():
                if isinstance(session, dict) and self._is_expired(session, now):
                    to_delete_keys.append(key)
                    expired_clients.append((str(session.get("ip", "")), session.get("mac")))

            if to_delete_keys:
                for key in to_delete_keys:
                    sessions.pop(key, None)
                    self._cache.pop(key, None)
                self._write_disk_data_locked(data)

        return expired_clients

    def _enforce_cache_limit_locked(self) -> bool:
        """
        Garantiza que la caché no exceda max_cache_size.

        - Prioriza expulsar sesiones expiradas.
        - Si sigue sobrando, expulsa las menos recientes por last_activity/login_time.
        """
        limit = self.max_cache_size
        if not limit or limit <= 0:
            return False

        current_size = len(self._cache)
        if current_size <= limit:
            return False

        now = time.time()
        evicted_any = False

        # 1) Fuera expiradas (solo caché)
        expired_keys = [k for k, s in self._cache.items() if self._is_expired(s, now)]
        if expired_keys:
            evicted_any = True
            for k in expired_keys:
                self._cache.pop(k, None)
            current_size = len(self._cache)
            if current_size <= limit:
                return True

        # 2) (por last_activity/login_time)
        excess = current_size - limit
        if excess <= 0:
            return evicted_any

        candidates = heapq.nsmallest(
            excess,
            self._cache.items(),
            key=lambda item: float(
                item[1].get("last_activity")
                or item[1].get("login_time")
                or 0.0
            ),
        )

        for key, _ in candidates:
            self._cache.pop(key, None)

        return True
