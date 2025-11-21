import json
import hashlib
import threading
from pathlib import Path
from typing import Any, Dict, Optional


class UserRepository:
    """
    Encapsula el acceso al archivo users.json con cache en memoria y las
    operaciones relacionadas con credenciales de usuario.
    """

    def __init__(self, users_file: Optional[Path] = None) -> None:
        base_dir = Path(__file__).resolve().parent
        # Guardamos los usuarios en auth/db (fuera de repositories)
        self.users_file = users_file or (base_dir.parent / "db" / "users.json")
        self._lock = threading.Lock()
        self._users_cache: Optional[Dict[str, Any]] = None

    def _read_from_disk(self) -> Dict[str, Any]:
        if not self.users_file.exists():
            return {"users": {}}
        with self.users_file.open("r", encoding="utf-8") as f:
            return json.load(f)

    def load_users(self) -> Dict[str, Any]:
        with self._lock:
            if self._users_cache is None:
                self._users_cache = self._read_from_disk()
            return self._users_cache

    def reload_users(self) -> Dict[str, Any]:
        with self._lock:
            self._users_cache = self._read_from_disk()
            return self._users_cache

    def save_users(self, data: Dict[str, Any]) -> None:
        self.users_file.parent.mkdir(parents=True, exist_ok=True)
        with self.users_file.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        with self._lock:
            self._users_cache = data

    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        # hash = SHA-256( salt + password )
        h = hashlib.sha256()
        h.update((salt + password).encode("utf-8"))
        return h.hexdigest()

    def verify_credentials(self, username: str, password: str) -> bool:
        data = self.load_users()
        users = data.get("users", {})
        user = users.get(username)
        if not user:
            data = self.reload_users()
            user = data.get("users", {}).get(username)
            if not user:
                return False

        salt = user.get("salt")
        expected_hash = user.get("password_hash")

        if not salt or not expected_hash:
            return False

        candidate_hash = self.hash_password(password, salt)
        return candidate_hash == expected_hash
