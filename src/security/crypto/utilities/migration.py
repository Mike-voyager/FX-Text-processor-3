"""
Миграция криптографических алгоритмов (crypto agility).

Перешифрование данных при переходе между алгоритмами.
Поддерживает единичную и массовую миграцию.

Example:
    >>> from src.security.crypto.utilities.migration import CryptoMigrator
    >>> migrator = CryptoMigrator(registry)
    >>> new_data, result = migrator.migrate_document(
    ...     encrypted, old_key, new_key, "aes-128-gcm", "aes-256-gcm"
    ... )
    >>> result.success
    True

Version: 1.0
Date: March 2, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional, Tuple

if TYPE_CHECKING:
    from src.security.crypto.core.registry import AlgorithmRegistry

__all__: list[str] = [
    "MigrationResult",
    "CryptoMigrator",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"

logger = logging.getLogger(__name__)


# ==============================================================================
# DATA CLASSES
# ==============================================================================


@dataclass(frozen=True)
class MigrationResult:
    """
    Результат миграции документа.

    Attributes:
        old_algorithm: Исходный алгоритм.
        new_algorithm: Целевой алгоритм.
        success: Успешна ли миграция.
        error: Сообщение об ошибке (при неудаче).
    """

    old_algorithm: str
    new_algorithm: str
    success: bool
    error: Optional[str] = None


# ==============================================================================
# CRYPTO MIGRATOR
# ==============================================================================


class CryptoMigrator:
    """
    Миграция между криптографическими алгоритмами.

    Расшифровывает данные старым алгоритмом/ключом и перешифровывает
    новым. Обеспечивает crypto agility.

    Example:
        >>> migrator = CryptoMigrator(registry)
        >>> if migrator.can_migrate("aes-128-gcm", "aes-256-gcm"):
        ...     new_data, result = migrator.migrate_document(...)
    """

    def __init__(self, registry: AlgorithmRegistry) -> None:
        """
        Инициализация мигратора.

        Args:
            registry: Экземпляр AlgorithmRegistry.
        """
        self._registry = registry

    def can_migrate(
        self,
        old_algorithm: str,
        new_algorithm: str,
    ) -> bool:
        """
        Проверка возможности миграции между алгоритмами.

        Оба алгоритма должны быть зарегистрированы в registry.

        Args:
            old_algorithm: Исходный алгоритм.
            new_algorithm: Целевой алгоритм.

        Returns:
            True если миграция возможна.
        """
        return (
            self._registry.is_registered(old_algorithm)
            and self._registry.is_registered(new_algorithm)
        )

    def migrate_document(
        self,
        encrypted_data: bytes,
        old_key: bytes,
        new_key: bytes,
        old_algorithm: str,
        new_algorithm: str,
        *,
        old_nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, MigrationResult]:
        """
        Миграция одного документа.

        Расшифровывает данные старым алгоритмом и перешифровывает новым.

        Args:
            encrypted_data: Зашифрованные данные (nonce + ciphertext, если
                           old_nonce не указан).
            old_key: Старый ключ.
            new_key: Новый ключ.
            old_algorithm: Исходный алгоритм.
            new_algorithm: Целевой алгоритм.
            old_nonce: Nonce для расшифровки (если не включён в encrypted_data).

        Returns:
            Tuple (новые зашифрованные данные (nonce + ciphertext),
                   результат миграции).
        """
        try:
            # Расшифровка
            old_cipher = self._registry.create(old_algorithm)

            if old_nonce is not None:
                nonce = old_nonce
                ciphertext = encrypted_data
            else:
                nonce_size = old_cipher.nonce_size
                nonce = encrypted_data[:nonce_size]
                ciphertext = encrypted_data[nonce_size:]

            plaintext = old_cipher.decrypt(old_key, nonce, ciphertext)

            # Перешифровка
            new_cipher = self._registry.create(new_algorithm)
            new_nonce, new_ciphertext = new_cipher.encrypt(new_key, plaintext)

            result = MigrationResult(
                old_algorithm=old_algorithm,
                new_algorithm=new_algorithm,
                success=True,
            )

            logger.info(
                "Document migrated: %s -> %s", old_algorithm, new_algorithm
            )
            return new_nonce + new_ciphertext, result

        except Exception as e:
            result = MigrationResult(
                old_algorithm=old_algorithm,
                new_algorithm=new_algorithm,
                success=False,
                error=str(e),
            )
            logger.error(
                "Migration failed (%s -> %s): %s",
                old_algorithm, new_algorithm, e,
            )
            return encrypted_data, result

    def bulk_migrate(
        self,
        documents: List[bytes],
        old_key: bytes,
        new_key: bytes,
        old_algorithm: str,
        new_algorithm: str,
    ) -> List[MigrationResult]:
        """
        Массовая миграция документов.

        Args:
            documents: Список зашифрованных документов (nonce + ciphertext).
            old_key: Старый ключ.
            new_key: Новый ключ.
            old_algorithm: Исходный алгоритм.
            new_algorithm: Целевой алгоритм.

        Returns:
            Список результатов миграции (по одному на документ).
        """
        results: List[MigrationResult] = []

        for i, doc in enumerate(documents):
            _, result = self.migrate_document(
                doc, old_key, new_key, old_algorithm, new_algorithm,
            )
            results.append(result)

        succeeded = sum(1 for r in results if r.success)
        logger.info(
            "Bulk migration: %d/%d succeeded (%s -> %s)",
            succeeded, len(documents), old_algorithm, new_algorithm,
        )
        return results
