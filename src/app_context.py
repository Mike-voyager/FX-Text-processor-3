from typing import Optional, Dict, Any
from src.security.crypto.secure_storage import (
    SecureStorage,
    StorageBackend,
    FileEncryptedStorageBackend,
)
from src.security.auth.second_factor import SecondFactorManager

# from src.security.audit.logger import AuditLogger # (если появится/audit)


class AppContext:
    """
    Dependency Injection context (singleton) for FX Text Processor.
    Централизует все core‑, auxiliary‑, audit/SIEM‑, config‑ и future‑services.
    """

    def __init__(
        self,
        storage_backend: Optional[StorageBackend] = None,
        storage_path: str = "second_factors_store.bin",
        audit: Optional[Any] = None,  # тип AuditLogger, если появится
        user_id: Optional[str] = None,
    ) -> None:
        # Backend for SecureStorage (default: FileEncryptedStorageBackend)
        if storage_backend is None:
            storage_backend = FileEncryptedStorageBackend(storage_path)
        self.storage: SecureStorage = SecureStorage(storage_backend)

        # Core service: mfa/second factor manager
        self.mfa_manager: SecondFactorManager = SecondFactorManager(storage=self.storage)

        # Optional audit/logger services
        self.audit = audit  # AuditLogger, SIEM, file, etc.

        # Optional: user/session/config scope
        self.user_id: Optional[str] = user_id

        # Extendable services dictionary for any future needs
        self.services: Dict[str, Any] = {}

    def register_service(self, name: str, service: Any) -> None:
        """Register a service by name (extendable)."""
        self.services[name] = service

    def get_service(self, name: str) -> Any:
        """Retrieve a registered service by name."""
        return self.services[name]

    def reset_storage(
        self, storage_backend: Optional[StorageBackend] = None, storage_path: Optional[str] = None
    ) -> None:
        """Allow dynamic switching of storage backend (for migration/reset/tests)."""
        if storage_backend is None and storage_path is not None:
            storage_backend = FileEncryptedStorageBackend(storage_path)
        elif storage_backend is None:
            raise ValueError("Either storage_backend or storage_path must be provided")
        self.storage = SecureStorage(storage_backend)
        self.mfa_manager = SecondFactorManager(storage=self.storage)


_ctx: Optional[AppContext] = None


def get_app_context(
    storage_backend: Optional[StorageBackend] = None,
    storage_path: str = "second_factors_store.bin",
    audit: Optional[Any] = None,
    user_id: Optional[str] = None,
) -> AppContext:
    """
    Returns global app context (singleton!). Use everywhere for all core services.
    """
    global _ctx
    if _ctx is None:
        _ctx = AppContext(
            storage_backend=storage_backend, storage_path=storage_path, audit=audit, user_id=user_id
        )
    return _ctx
