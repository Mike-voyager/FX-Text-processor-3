"""
Контекст приложения (DI-контейнер, синглтон).

Централизует сервисы приложения: mfa_manager, audit, storage.
Инициализируется при старте; до аутентификации использует in-memory хранилище.
Файловое хранилище (SecureStorage) подключается после получения master_key.

Example:
    >>> ctx = get_app_context()
    >>> ctx.mfa_manager.setup_factor("user1", "totp")
"""

from __future__ import annotations

from pathlib import Path
from threading import RLock
from typing import Any

from src.security.auth.second_factor import SecondFactorManager
from src.security.crypto.core.protocols import KeyStoreProtocol
from src.security.crypto.service.crypto_service import CryptoService
from src.security.crypto.service.profiles import CryptoProfile
from src.security.crypto.utilities.secure_storage import SecureStorage

__all__ = ["AppContext", "get_app_context"]


class _InMemoryStore:
    """
    Простое in-memory хранилище, реализующее KeyStoreProtocol.

    Используется до аутентификации, когда master_key ещё недоступен.
    После аутентификации заменяется на SecureStorage через reset_storage().
    """

    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}

    def save(self, name: str, data: bytes) -> None:
        """Сохраняет элемент по имени."""
        self._data[name] = data

    def load(self, name: str) -> bytes:
        """Загружает элемент по имени. Бросает KeyError если не найден."""
        if name not in self._data:
            raise KeyError(name)
        return self._data[name]

    def delete(self, name: str) -> None:
        """Удаляет элемент по имени. Бросает KeyError если не найден."""
        if name not in self._data:
            raise KeyError(name)
        del self._data[name]


class AppContext:
    """
    DI-контейнер приложения (синглтон).

    Централизует все core-сервисы: MFA-менеджер, аудит, хранилище.

    Attributes:
        storage: Хранилище состояния (in-memory до аутентификации,
            SecureStorage после).
        mfa_manager: Менеджер второго фактора аутентификации.
        audit: Экземпляр ImmutableAuditLog или None.
        user_id: ID текущего пользователя (None = не авторизован).
        services: Реестр дополнительных сервисов.

    Example:
        >>> ctx = AppContext()
        >>> ctx.mfa_manager.setup_factor("uid1", "totp")
    """

    def __init__(
        self,
        storage_backend: str = "memory",
        storage_path: Path | None = None,
        mfa_enabled: bool = True,
        audit_enabled: bool = True,
        user_id: str | None = None,
        crypto_profile: CryptoProfile = CryptoProfile.STANDARD,
    ) -> None:
        """
        Инициализирует контекст приложения.

        Args:
            storage_backend: Тип хранилища: "memory" или "file".
                При "file" требуется storage_path и master_key (подключается
                через reset_storage() после аутентификации).
            storage_path: Путь к файлу хранилища (для "file" бэкенда).
            mfa_enabled: Включить поддержку MFA.
            audit_enabled: Включить аудит-лог.
            user_id: ID пользователя для авторизации.
            crypto_profile: Профиль криптографии (STANDARD, PARANOID, PQC, LEGACY).
        """
        # По умолчанию in-memory; файловый бэкенд подключается после аутентификации
        self.storage: KeyStoreProtocol = _InMemoryStore()

        self.mfa_manager: SecondFactorManager = SecondFactorManager(
            storage=self.storage
        )
        self.audit: Any = None
        self.user_id: str | None = user_id
        self.services: dict[str, Any] = {}

        # Initialize crypto service with selected profile
        self.crypto_service: CryptoService = CryptoService(profile=crypto_profile)

    def register_service(self, name: str, service: Any) -> None:
        """
        Регистрирует сервис по имени.

        Args:
            name: Имя сервиса.
            service: Объект сервиса.
        """
        self.services[name] = service

    def get_service(self, name: str) -> Any:
        """
        Возвращает сервис по имени.

        Args:
            name: Имя сервиса.

        Returns:
            Зарегистрированный сервис.

        Raises:
            KeyError: Если сервис не зарегистрирован.
        """
        return self.services[name]

    def reset_storage(
        self,
        storage_backend: str | None = None,
        storage_path: Path | None = None,
        master_key: bytes | None = None,
    ) -> None:
        """
        Пересоздаёт хранилище (после аутентификации или для тестов).

        Если передан master_key и storage_path — подключает SecureStorage.
        Иначе — in-memory хранилище.

        Args:
            storage_backend: Тип хранилища ("memory" или "file").
            storage_path: Путь к файлу хранилища (для "file").
            master_key: Мастер-ключ (32 байта) для SecureStorage.
        """
        if (
            storage_backend == "file"
            and storage_path is not None
            and master_key is not None
        ):
            self.storage = SecureStorage(storage_path, master_key)
        else:
            self.storage = _InMemoryStore()
        self.mfa_manager = SecondFactorManager(storage=self.storage)


_ctx: AppContext | None = None
_ctx_lock: RLock = RLock()


def get_app_context(
    storage_backend: str = "memory",
    storage_path: Path | None = None,
    mfa_enabled: bool = True,
    audit_enabled: bool = True,
    user_id: str | None = None,
    crypto_profile: CryptoProfile = CryptoProfile.STANDARD,
) -> AppContext:
    """
    Возвращает глобальный AppContext (синглтон).

    При первом вызове создаёт контекст с указанными параметрами.
    Последующие вызовы возвращают существующий экземпляр.

    Args:
        storage_backend: Тип хранилища: "memory" (по умолчанию) или "file".
        storage_path: Путь к файлу хранилища (для "file" бэкенда).
        mfa_enabled: Включить поддержку MFA.
        audit_enabled: Включить аудит-лог.
        user_id: ID пользователя.
        crypto_profile: Профиль криптографии (по умолчанию STANDARD).

    Returns:
        Глобальный экземпляр AppContext.
    """
    global _ctx
    with _ctx_lock:
        if _ctx is None:
            _ctx = AppContext(
                storage_backend=storage_backend,
                storage_path=storage_path,
                mfa_enabled=mfa_enabled,
                audit_enabled=audit_enabled,
                user_id=user_id,
                crypto_profile=crypto_profile,
            )
    return _ctx
