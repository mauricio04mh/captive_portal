# captive_portal

## Servicio de limpieza de sesiones

El módulo `auth.services.session_cleanup_service` expone `SessionCleanupService`,
un hilo daemon que borra periódicamente las sesiones vencidas y elimina las
reglas del firewall asociadas. Un ejemplo de uso básico:

```python
from auth.repositories.session_repository import SessionRepository
from auth.services.session_cleanup_service import SessionCleanupService

session_repo = SessionRepository()
session_repo.init_store()

cleanup_service = SessionCleanupService(session_repo, interval_seconds=30)
cleanup_service.start()
```

Cuando el servidor finaliza, se puede invocar `cleanup_service.stop()` para
cerrar el hilo limpiamente.
