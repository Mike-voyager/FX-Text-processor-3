# src/app_context.py
"""
AppContext: DI-контейнер для хранения глобальных объектов приложения
(например, SecureStorage, SecondFactorManager и других сервисов).
"""

from src.security.crypto.secure_storage import SecureStorage
from src.security.auth.second_factor import SecondFactorManager


class AppContext:
    """
    Dependency Injection context for FX Text Processor:
    - storage: SecureStorage instance
    - mfa_manager: SecondFactorManager (MFA/2FA engine)
    """

    def __init__(self, storage_path: str = "second_factors_store.bin") -> None:
        self.storage = SecureStorage(storage_path)
        self.mfa_manager = SecondFactorManager(storage=self.storage)
        # Здесь можно инициализировать другие сервисы: audit, token, SIEM, API, ...
        # Например:
        # self.some_service = SomeService(dependency=self.storage)


def get_app_context(storage_path: str = "second_factors_store.bin") -> AppContext:
    """
    Returns global app context. Use as singleton in UI/controllers.
    """
    return AppContext(storage_path)


# Пример использования:
# ctx = get_app_context()
# manager = ctx.mfa_manager
# manager.setup_factor(...)
