import os
from pathlib import Path
from threading import Lock

_ENV_LOADED = False
_ENV_LOCK = Lock()


def load_env_file(file_name: str = ".env") -> None:
    """
    Load key=value pairs from .env into os.environ without overriding
    existing values.
    """
    global _ENV_LOADED
    with _ENV_LOCK:
        if _ENV_LOADED:
            return

        project_root = Path(__file__).resolve().parents[1]
        env_path = project_root / file_name
        if env_path.exists():
            for raw_line in env_path.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                os.environ.setdefault(key, value)

        _ENV_LOADED = True
