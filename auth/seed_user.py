"""Herramienta simple para crear/actualizar usuarios de prueba.

Uso típico:
    python -m auth.seed_user --username admin --password secret
"""

import argparse
import getpass
import secrets
import sys

from auth.repositories.user_repository import UserRepository

user_repository = UserRepository()
USERS_FILE = user_repository.users_file


def parse_args():
    parser = argparse.ArgumentParser(description="Genera usuarios en users.json")
    parser.add_argument("--username", required=True, help="Nombre de usuario a crear")
    parser.add_argument(
        "--password",
        help="Contraseña para el usuario (si no se provee se solicitará de forma interactiva)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Sobrescribe al usuario si ya existía",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    password = args.password or getpass.getpass(prompt="Contraseña: ")
    if not password:
        print("[seed] La contraseña no puede estar vacía", file=sys.stderr)
        return 1

    data = user_repository.load_users()
    users = data.setdefault("users", {})

    if args.username in users and not args.force:
        print(
            f"[seed] El usuario '{args.username}' ya existe. Ejecuta con --force para sobrescribir.",
            file=sys.stderr,
        )
        return 1

    salt = secrets.token_hex(16)
    password_hash = UserRepository.hash_password(password, salt)
    users[args.username] = {
        "salt": salt,
        "password_hash": password_hash,
    }

    user_repository.save_users(data)
    print(f"[seed] Usuario '{args.username}' almacenado en {USERS_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
