import json
import hashlib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "db" / "users.json"


def load_users():
    if not USERS_FILE.exists():
        return {"users": {}}
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(data):
    USERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def hash_password(password: str, salt: str) -> str:
    # hash = SHA-256( salt + password )
    h = hashlib.sha256()
    h.update((salt + password).encode("utf-8"))
    return h.hexdigest()


def verify_credentials(username: str, password: str) -> bool:
    data = load_users()
    users = data.get("users", {})
    user = users.get(username)
    if not user:
        return False

    salt = user.get("salt")
    expected_hash = user.get("password_hash")

    if not salt or not expected_hash:
        return False

    candidate_hash = hash_password(password, salt)
    return candidate_hash == expected_hash
