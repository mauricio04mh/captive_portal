import threading
from typing import Tuple

from auth.repositories.session_repository import SessionRepository
from . import firewall as firewall_module


class SessionCleanupService:
    """
    Ejecuta un hilo daemon que verifica las sesiones expiradas en intervalos
    regulares. Está pensado para iniciarse junto con el servidor HTTP que actúa
    como portal cautivo.
    """

    def __init__(
        self,
        session_repository: SessionRepository,
        interval_seconds: int = 30,
        firewall=firewall_module,
    ) -> None:
        self._session_repository = session_repository
        self._interval_seconds = interval_seconds
        self._firewall = firewall
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """
        Arranca el hilo en background si todavía no está corriendo.
        """
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="SessionCleanupService",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread:
            thread.join()
        self._thread = None

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self._cleanup_expired_sessions()
            # Espera con posibilidad de despertar anticipadamente cuando se llame a stop()
            self._stop_event.wait(self._interval_seconds)

    def _cleanup_expired_sessions(self) -> None:
        try:
            expired_clients = self._session_repository.cleanup_expired_sessions()
        except Exception as exc:  
            print(f"[session-cleanup] Error consultando sesiones: {exc}")
            return

        for client in expired_clients:
            self._deny_client(client)

    def _deny_client(self, client: Tuple[str, str| None]) -> None:
        ip, mac = client
        try:
            self._firewall.deny_client_in_firewall(ip, mac)
            print(f"[session-cleanup] Bloqueada IP {ip} (mac={mac})")
        except Exception as exc: 
            print(f"[session-cleanup] Error bloqueando {ip}: {exc}")

