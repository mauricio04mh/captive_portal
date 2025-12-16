import json
import hashlib
import hmac
import threading
from pathlib import Path
from typing import Any, Dict, Optional


class UserRepository:
    def __init__(
        self,
        users_file: Optional[Path] = None,
        max_cache_size: Optional[int] = 10_000,
    ) -> None:
        base_dir = Path(__file__).resolve().parent
        self.users_file = users_file or (base_dir / "db" / "users.json")
        self.max_cache_size = max_cache_size

        self._lock = threading.Lock()
        self._users_cache: Optional[Dict[str, Any]] = None

        with self._lock:
            self._ensure_store_initialized_locked()

    def _ensure_store_initialized_locked(self) -> None:
        self.users_file.parent.mkdir(parents=True, exist_ok=True)

        if not self.users_file.exists():
            self._write_disk_data_locked({"users": {}})
            return

    def _read_disk_data_locked(self) -> Dict[str, Any]:
        if not self.users_file.exists():
            return {"users": {}}

        try:
            with self.users_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            data = {"users": {}}

        users = data.get("users")
        if not isinstance(users, dict):
            users = {}

        return {"users": users}

    def _write_disk_data_locked(self, data: Dict[str, Any]) -> None:
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.users_file.with_suffix(".tmp")

        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)

        tmp.replace(self.users_file)

    def _enforce_cache_limit_locked(self) -> None:
        limit = self.max_cache_size
        if not limit or limit <= 0:
            return
        if self._users_cache is None:
            return

        users = self._users_cache.get("users")
        if not isinstance(users, dict):
            self._users_cache = {"users": {}}
            return

        if len(users) <= limit:
            return

        kept_keys = sorted(users.keys())[:limit]
        self._users_cache = {"users": {k: users[k] for k in kept_keys}}

    def load_users(self) -> Dict[str, Any]:
        with self._lock:
            if self._users_cache is None:
                self._users_cache = self._read_disk_data_locked()
                self._enforce_cache_limit_locked()
            return self._users_cache

    def reload_users(self) -> Dict[str, Any]:
        with self._lock:
            self._users_cache = self._read_disk_data_locked()
            self._enforce_cache_limit_locked()
            return self._users_cache

    def save_users(self, data: Dict[str, Any]) -> None:
        with self._lock:
            users = data.get("users")
            if not isinstance(users, dict):
                data = {"users": {}}

            self._write_disk_data_locked(data)
            self._users_cache = data
            self._enforce_cache_limit_locked()

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """
        Calcula SHA-256(salt + password) y devuelve el hex digest.
        """
        h = hashlib.sha256()
        h.update((salt + password).encode("utf-8"))
        return h.hexdigest()

    def _get_user_record_locked(self, username: str) -> Optional[Dict[str, Any]]:
        if self._users_cache is None:
            self._users_cache = self._read_disk_data_locked()
            self._enforce_cache_limit_locked()

        users = self._users_cache.get("users", {})
        user = users.get(username)
        if isinstance(user, dict):
            return user

        # Miss: recarga desde disco (por si cambió en otro proceso)
        self._users_cache = self._read_disk_data_locked()
        self._enforce_cache_limit_locked()
        users = self._users_cache.get("users", {})
        user = users.get(username)
        return user if isinstance(user, dict) else None

    def verify_credentials(self, username: str, password: str) -> bool:
        with self._lock:
            user = self._get_user_record_locked(username)
            if not user:
                return False

            salt = user.get("salt")
            expected_hash = user.get("password_hash")
            if not isinstance(salt, str) or not isinstance(expected_hash, str):
                return False

            candidate_hash = self.hash_password(password, salt)
            return hmac.compare_digest(candidate_hash, expected_hash)
