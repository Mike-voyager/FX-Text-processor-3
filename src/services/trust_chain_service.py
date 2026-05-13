"""
Сервис цепочек доверия для шаблонов.

Реализует управление цепочками доверия шаблонов: верификация подписей,
добавление/отзыв ключей, построение и проверка цепочек доверия.

Thread-safe реализация с использованием threading.Lock.
Все операции логируются в аудит через AuditLog.

Example:
    >>> from src.services.trust_chain_service import TrustChainService
    >>> from pathlib import Path
    >>>
    >>> service = TrustChainService(
    ...     keystore_path=Path.home() / ".fxtextprocessor" / "keystore",
    ...     audit_secret_key=b"secret_key_32_bytes_long_for_hmac",
    ... )
    >>>
    >>> # Добавляем корневой ключ
    >>> link = service.add_trusted_key(
    ...     key_id="root-key",
    ...     public_key=b"...",
    ...     algorithm="Ed25519",
    ...     metadata={"name": "Root Authority"}
    ... )

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from src.security.audit.events import AuditEventType
from src.security.audit.logger import AuditLog
from src.security.crypto.algorithms.signing import Ed25519Signer
from src.security.crypto.core.registry import AlgorithmRegistry
from src.services.protocols.template_security import (
    TrustChainLink,
    TrustChainServiceProtocol,
    TrustStatus,
    TrustVerificationResult,
)


class TrustChainError(Exception):
    """Базовая ошибка цепочки доверия."""

    pass


class KeyNotFoundError(TrustChainError):
    """Ключ не найден в реестре."""

    pass


class KeyAlreadyExistsError(TrustChainError):
    """Ключ уже существует в реестре."""

    pass


class InvalidSignatureError(TrustChainError):
    """Неверная подпись."""

    pass


class ChainValidationError(TrustChainError):
    """Ошибка валидации цепочки доверия."""

    pass


@dataclass(frozen=True)
class KeyEntry:
    """
    Запись о ключе в хранилище.

    Расширяет TrustChainLink информацией о статусе отзыва.

    Attributes:
        link: Базовая информация о связи цепочки доверия
        revoked: Отозван ли ключ
        revoked_at: Время отзыва (None если не отозван)
        revoked_by: ID ключа, которым выполнен отзыв
        revoke_reason: Причина отзыва
    """

    link: TrustChainLink
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None
    revoke_reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Сериализует запись в словарь."""
        return {
            "link": self.link.to_dict(),
            "revoked": self.revoked,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_by": self.revoked_by,
            "revoke_reason": self.revoke_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KeyEntry":
        """Десериализует запись из словаря."""
        revoked_at = None
        if data.get("revoked_at"):
            revoked_at = datetime.fromisoformat(data["revoked_at"])

        return cls(
            link=TrustChainLink.from_dict(data["link"]),
            revoked=data.get("revoked", False),
            revoked_at=revoked_at,
            revoked_by=data.get("revoked_by"),
            revoke_reason=data.get("revoke_reason"),
        )


class TrustChainService(TrustChainServiceProtocol):
    """
    Сервис управления цепочками доверия шаблонов.

    Реализует протокол TrustChainServiceProtocol с thread-safe операциями.
    Хранит ключи в JSON файле с полной информацией о цепочке доверия.

    Features:
        - Верификация подписей шаблонов с проверкой цепочки доверия
        - Добавление корневых и подчинённых ключей
        - Отзыв ключей с аудитом
        - Построение полной цепочки от ключа до корня
        - Thread-safe операции через threading.Lock
        - Полный аудит всех операций

    Security:
        - Все операции логируются в AuditLog
        - Отозванные ключи остаются в реестре для проверки старых подписей
        - Цепочка доверия проверяется до корневого ключа
        - Поддержка Ed25519 и других алгоритмов через AlgorithmRegistry

    Example:
        >>> service = TrustChainService(
        ...     keystore_path=Path.home() / ".fxtextprocessor" / "keystore",
        ...     audit_secret_key=audit_key,
        ... )
        >>>
        >>> # Добавление корневого ключа
        >>> root_link = service.add_trusted_key(
        ...     key_id="root-authority",
        ...     public_key=root_public_key,
        ...     algorithm="Ed25519",
        ...     metadata={"name": "Main Root"}
        ... )
        >>>
        >>> # Проверка ключа
        >>> is_trusted = service.is_key_trusted("root-authority")

    Attributes:
        _keystore_path: Путь к директории хранилища ключей
        _keystore_file: Путь к файлу trusted_keys.json
        _audit_log: Журнал аудита для логирования операций
        _lock: Блокировка для thread-safe операций
        _keys: Словарь ключей {key_id: KeyEntry}
        _ed25519: Экземпляр Ed25519Signer для верификации
        _registry: Реестр алгоритмов для создания верификаторов
    """

    def __init__(
        self,
        keystore_path: Path,
        audit_secret_key: bytes,
    ) -> None:
        """
        Инициализация сервиса цепочек доверия.

        Args:
            keystore_path: Путь к директории хранилища ключей.
                          Файл trusted_keys.json будет создан внутри.
            audit_secret_key: Секретный ключ для HMAC аудита (минимум 32 байта).

        Raises:
            ValueError: Если audit_secret_key меньше 32 байт.

        Example:
            >>> service = TrustChainService(
            ...     keystore_path=Path.home() / ".fxtextprocessor" / "keystore",
            ...     audit_secret_key=b"32_bytes_secret_key_for_hmac_auth...",
            ... )
        """
        if len(audit_secret_key) < 32:
            raise ValueError("audit_secret_key должен быть не менее 32 байт")

        self._keystore_path: Path = keystore_path
        self._keystore_file: Path = keystore_path / "trusted_keys.json"
        self._audit_log: AuditLog = AuditLog(
            audit_secret_key=audit_secret_key,
            storage_path=keystore_path / "audit",
        )
        self._lock: threading.Lock = threading.Lock()
        self._keys: dict[str, KeyEntry] = {}
        self._ed25519: Ed25519Signer = Ed25519Signer()
        self._registry: AlgorithmRegistry = AlgorithmRegistry.get_instance()

        # Создаём директории если не существуют
        self._keystore_path.mkdir(parents=True, exist_ok=True)

        # Загружаем существующие ключи
        self._load_keystore()

    def _load_keystore(self) -> None:
        """
        Загружает хранилище ключей из файла.

        Если файл не существует, создаётся пустое хранилище.
        """
        if not self._keystore_file.exists():
            return

        try:
            with open(self._keystore_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            for key_id, entry_data in data.items():
                self._keys[key_id] = KeyEntry.from_dict(entry_data)

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            # Логируем ошибку, но не прерываем работу
            self._audit_log.log_event(
                AuditEventType.KEYSTORE_OPENED,
                details={
                    "keystore_file": str(self._keystore_file),
                    "error": f"Failed to load keystore: {e}",
                    "loaded_keys": 0,
                },
            )
            # Начинаем с пустого хранилища
            self._keys = {}

    def _save_keystore(self) -> None:
        """
        Сохраняет хранилище ключей в файл.

        Thread-safe: должен вызываться внутри self._lock.
        """
        data: dict[str, Any] = {}
        for key_id, entry in self._keys.items():
            data[key_id] = entry.to_dict()

        # Записываем с временной файл + rename для атомарности
        temp_file = self._keystore_file.with_suffix(".tmp")
        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            temp_file.replace(self._keystore_file)
        except (OSError, json.JSONDecodeError) as e:
            # Удаляем временный файл при ошибке
            if temp_file.exists():
                temp_file.unlink()
            raise

    def _compute_key_hash(self, public_key: bytes, algorithm: str) -> str:
        """
        Вычисляет хеш публичного ключа для идентификации.

        Args:
            public_key: Публичный ключ в бинарном формате.
            algorithm: Алгоритм подписи.

        Returns:
            SHA-256 хеш в hex формате (первые 16 байт для краткости).
        """
        data = public_key + algorithm.encode("utf-8")
        full_hash = hashlib.sha256(data).hexdigest()
        return full_hash[:32]  # 16 байт в hex = 32 символа

    def _get_signer(self, algorithm: str) -> Any:
        """
        Получает signer для указанного алгоритма.

        Args:
            algorithm: Название алгоритма ("Ed25519", "ML-DSA-65", etc.).

        Returns:
            Экземпляр signer для верификации.

        Raises:
            ValueError: Если алгоритм не поддерживается.
        """
        # Ed25519 — оптимизированный путь
        if algorithm == "Ed25519":
            return self._ed25519

        # Другие алгоритмы через реестр
        try:
            return self._registry.create(algorithm)
        except (TypeError, ValueError, RuntimeError) as e:
            raise ValueError(f"Алгоритм '{algorithm}' не поддерживается: {e}") from e

    def _verify_signature(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        algorithm: str,
    ) -> bool:
        """
        Верифицирует подпись с помощью указанного алгоритма.

        Args:
            public_key: Публичный ключ в бинарном формате.
            message: Подписанное сообщение.
            signature: Подпись.
            algorithm: Название алгоритма.

        Returns:
            True если подпись валидна.
        """
        try:
            signer = self._get_signer(algorithm)
            result: bool = signer.verify(public_key, message, signature)
            return result
        except (TypeError, ValueError, KeyError) as e:
            logger.debug("Signature verification failed: %s", e)
            return False

    def verify_template(
        self,
        template: Any,
        trusted_keys: Optional[set[str]] = None,
        verify_chain: bool = True,
    ) -> TrustVerificationResult:
        """
        Верифицирует шаблон по цепочке доверия.

        Проверяет подпись шаблона и валидность цепочки доверия
        от подписавшего ключа до корневого.

        Args:
            template: Шаблон для проверки. Должен иметь атрибуты:
                     template_id, signature, signing_key_id,
                     signing_public_key, signing_algorithm.
            trusted_keys: Множество ID доверенных ключей (None = все из реестра).
            verify_chain: Проверять ли полную цепочку или только подпись.

        Returns:
            TrustVerificationResult с полным результатом проверки.

        Raises:
            ValueError: Если шаблон не имеет необходимых атрибутов.
            KeyError: Если ключ не найден в реестре (только при verify_chain=True).

        Example:
            >>> result = service.verify_template(template)
            >>> if result.can_trust:
            ...     print("Шаблон доверенный")
        """
        errors: list[str] = []
        warnings: list[str] = []

        # Извлекаем данные из шаблона
        try:
            template_id: str = getattr(template, "template_id", "")
            signature: Optional[bytes] = getattr(template, "signature", None)
            signing_key_id: Optional[str] = getattr(template, "signing_key_id", None)
            signing_public_key: Optional[bytes] = getattr(template, "signing_public_key", None)
            signing_algorithm: str = getattr(template, "signing_algorithm", "Ed25519")
        except (TypeError, AttributeError, RuntimeError) as e:
            error_msg = f"Шаблон не имеет необходимых атрибутов: {e}"
            self._audit_log.log_event(
                AuditEventType.TEMPLATE_SIGNATURE_INVALID,
                details={"error": error_msg},
            )
            raise ValueError(error_msg) from e

        if not template_id:
            error_msg = "Шаблон не имеет template_id"
            errors.append(error_msg)
            self._audit_log.log_event(
                AuditEventType.TEMPLATE_SIGNATURE_INVALID,
                details={"template_id": "", "error": error_msg},
            )
            return TrustVerificationResult(
                template_id="",
                is_valid=False,
                trust_status=TrustStatus.UNTRUSTED,
                chain_depth=0,
                signing_key_id=signing_key_id or "",
                errors=errors,
                warnings=warnings,
            )

        if not signature:
            error_msg = "Шаблон не имеет подписи"
            errors.append(error_msg)
            self._audit_log.log_event(
                AuditEventType.TEMPLATE_SIGNATURE_INVALID,
                details={"template_id": template_id, "error": error_msg},
            )
            return TrustVerificationResult(
                template_id=template_id,
                is_valid=False,
                trust_status=TrustStatus.UNTRUSTED,
                chain_depth=0,
                signing_key_id=signing_key_id or "",
                errors=errors,
                warnings=warnings,
            )

        # Если не указан signing_key_id, проверяем только криптографическую подпись
        if not signing_key_id:
            if not signing_public_key:
                error_msg = "Не указан ни signing_key_id, ни signing_public_key"
                errors.append(error_msg)
                self._audit_log.log_event(
                    AuditEventType.TEMPLATE_SIGNATURE_INVALID,
                    details={"template_id": template_id, "error": error_msg},
                )
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.UNTRUSTED,
                    chain_depth=0,
                    signing_key_id="",
                    errors=errors,
                    warnings=warnings,
                )

            # Проверяем подпись только криптографически
            is_valid = self._verify_signature(
                signing_public_key,
                template_id.encode("utf-8"),
                signature,
                signing_algorithm,
            )

            if is_valid:
                self._audit_log.log_event(
                    AuditEventType.CRYPTO_VERIFICATION,
                    details={
                        "template_id": template_id,
                        "algorithm": signing_algorithm,
                        "note": "Only cryptographic verification, no trust chain",
                    },
                )
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=True,
                    trust_status=TrustStatus.PENDING,
                    chain_depth=0,
                    signing_key_id="embedded",
                    warnings=["Цепочка доверия не проверена (нет signing_key_id)"],
                )
            else:
                error_msg = "Криптографическая верификация подписи не удалась"
                errors.append(error_msg)
                self._audit_log.log_event(
                    AuditEventType.TEMPLATE_SIGNATURE_INVALID,
                    details={"template_id": template_id, "error": error_msg},
                )
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.UNTRUSTED,
                    chain_depth=0,
                    signing_key_id="embedded",
                    errors=errors,
                    warnings=warnings,
                )

        with self._lock:
            # Получаем цепочку доверия
            try:
                chain = self.get_trust_chain(signing_key_id, include_revoked=True)
            except (TrustChainError, TypeError, ValueError, RuntimeError) as e:
                error_msg = f"Ошибка построения цепочки доверия: {e}"
                errors.append(error_msg)
                self._audit_log.log_event(
                    AuditEventType.TEMPLATE_TRUST_CHAIN_FAILED,
                    details={
                        "template_id": template_id,
                        "signing_key_id": signing_key_id,
                        "error": error_msg,
                    },
                )
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.UNTRUSTED,
                    chain_depth=0,
                    signing_key_id=signing_key_id,
                    errors=errors,
                    warnings=warnings,
                )

            if not chain:
                error_msg = f"Ключ '{signing_key_id}' не найден в реестре доверия"
                errors.append(error_msg)
                self._audit_log.log_event(
                    AuditEventType.TEMPLATE_TRUST_CHAIN_FAILED,
                    details={
                        "template_id": template_id,
                        "signing_key_id": signing_key_id,
                        "error": error_msg,
                    },
                )
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.UNTRUSTED,
                    chain_depth=0,
                    signing_key_id=signing_key_id,
                    errors=errors,
                    warnings=warnings,
                )

            # Проверяем статус ключа
            first_link = chain[0]
            entry = self._keys.get(signing_key_id)

            if entry and entry.revoked:
                error_msg = f"Ключ '{signing_key_id}' отозван: {entry.revoke_reason}"
                errors.append(error_msg)
                self._audit_log.log_event(
                    AuditEventType.TEMPLATE_TRUST_CHAIN_FAILED,
                    details={
                        "template_id": template_id,
                        "signing_key_id": signing_key_id,
                        "error": error_msg,
                        "revoked_at": entry.revoked_at.isoformat() if entry.revoked_at else None,
                    },
                )
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.REVOKED,
                    chain_depth=len(chain),
                    signing_key_id=signing_key_id,
                    errors=errors,
                    warnings=warnings,
                )

            # Проверяем срок действия
            if first_link.is_expired():
                error_msg = f"Срок действия ключа '{signing_key_id}' истёк"
                errors.append(error_msg)
                self._audit_log.log_event(
                    AuditEventType.TEMPLATE_TRUST_CHAIN_FAILED,
                    details={
                        "template_id": template_id,
                        "signing_key_id": signing_key_id,
                        "error": error_msg,
                    },
                )
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.EXPIRED,
                    chain_depth=len(chain),
                    signing_key_id=signing_key_id,
                    errors=errors,
                    warnings=warnings,
                )

            # Проверяем, что ключ в списке доверенных (если указан)
            if trusted_keys is not None and signing_key_id not in trusted_keys:
                error_msg = f"Ключ '{signing_key_id}' не в списке доверенных"
                errors.append(error_msg)
                self._audit_log.log_event(
                    AuditEventType.TEMPLATE_TRUST_CHAIN_FAILED,
                    details={
                        "template_id": template_id,
                        "signing_key_id": signing_key_id,
                        "error": error_msg,
                    },
                )
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.UNTRUSTED,
                    chain_depth=len(chain),
                    signing_key_id=signing_key_id,
                    errors=errors,
                    warnings=warnings,
                )

            # Проверяем цепочку доверия
            if verify_chain:
                try:
                    for i, link in enumerate(chain):
                        if link.is_root():
                            # Корневой ключ должен быть self-signed
                            # В данной реализации считаем корневые ключи доверенными
                            continue

                        # Проверяем, что родительский ключ существует и не отозван
                        parent_entry = self._keys.get(link.parent_key_id) if link.parent_key_id else None
                        if parent_entry and parent_entry.revoked:
                            error_msg = f"Родительский ключ '{link.parent_key_id}' отозван"
                            errors.append(error_msg)
                            self._audit_log.log_event(
                                AuditEventType.TEMPLATE_TRUST_CHAIN_FAILED,
                                details={
                                    "template_id": template_id,
                                    "signing_key_id": signing_key_id,
                                    "parent_key_id": link.parent_key_id,
                                    "error": error_msg,
                                },
                            )
                            return TrustVerificationResult(
                                template_id=template_id,
                                is_valid=False,
                                trust_status=TrustStatus.UNTRUSTED,
                                chain_depth=len(chain),
                                signing_key_id=signing_key_id,
                                errors=errors,
                                warnings=warnings,
                            )

                except (TrustChainError, KeyError, TypeError, ValueError, RuntimeError) as e:
                    error_msg = f"Ошибка валидации цепочки: {e}"
                    errors.append(error_msg)
                    self._audit_log.log_event(
                        AuditEventType.TEMPLATE_TRUST_CHAIN_FAILED,
                        details={
                            "template_id": template_id,
                            "signing_key_id": signing_key_id,
                            "error": error_msg,
                        },
                    )
                    return TrustVerificationResult(
                        template_id=template_id,
                        is_valid=False,
                        trust_status=TrustStatus.UNTRUSTED,
                        chain_depth=len(chain),
                        signing_key_id=signing_key_id,
                        errors=errors,
                        warnings=warnings,
                    )

            # Проверяем криптографическую подпись шаблона
            public_key_for_verify = signing_public_key
            if public_key_for_verify is None:
                # Берём из реестра
                public_key_for_verify = first_link.public_key

            is_valid = self._verify_signature(
                public_key_for_verify,
                template_id.encode("utf-8"),
                signature,
                signing_algorithm,
            )

            if not is_valid:
                error_msg = "Криптографическая верификация подписи не удалась"
                errors.append(error_msg)
                self._audit_log.log_event(
                    AuditEventType.TEMPLATE_SIGNATURE_INVALID,
                    details={
                        "template_id": template_id,
                        "signing_key_id": signing_key_id,
                        "error": error_msg,
                    },
                )
                return TrustVerificationResult(
                    template_id=template_id,
                    is_valid=False,
                    trust_status=TrustStatus.UNTRUSTED,
                    chain_depth=len(chain),
                    signing_key_id=signing_key_id,
                    errors=errors,
                    warnings=warnings,
                )

            # Успех!
            self._audit_log.log_event(
                AuditEventType.CRYPTO_VERIFICATION,
                details={
                    "template_id": template_id,
                    "signing_key_id": signing_key_id,
                    "chain_depth": len(chain),
                    "algorithm": signing_algorithm,
                },
            )

            return TrustVerificationResult(
                template_id=template_id,
                is_valid=True,
                trust_status=TrustStatus.TRUSTED,
                chain_depth=len(chain),
                signing_key_id=signing_key_id,
                warnings=warnings,
            )

    def get_trust_chain(
        self,
        key_id: str,
        include_revoked: bool = False,
    ) -> list[TrustChainLink]:
        """
        Возвращает цепочку доверия для ключа.

        Строит цепочку от указанного ключа до корневого,
        включая все промежуточные звенья.

        Args:
            key_id: ID ключа, для которого строится цепочка.
            include_revoked: Включать ли отозванные ключи в цепочку.

        Returns:
            Список TrustChainLink от ключа к корневому.
            Пустой список если ключ не найден.

        Example:
            >>> chain = service.get_trust_chain("key-456")
            >>> len(chain)
            2
            >>> chain[0].key_id
            'key-456'
            >>> chain[1].is_root()
            True
        """
        with self._lock:
            chain: list[TrustChainLink] = []
            current_key_id: Optional[str] = key_id
            visited: set[str] = set()  # Защита от циклов

            while current_key_id and current_key_id not in visited:
                visited.add(current_key_id)
                entry = self._keys.get(current_key_id)

                if entry is None:
                    break

                # Пропускаем отозванные если не включены
                if entry.revoked and not include_revoked:
                    break

                chain.append(entry.link)

                # Переходим к родительскому ключу
                current_key_id = entry.link.parent_key_id

            return chain

    def add_trusted_key(
        self,
        key_id: str,
        public_key: bytes,
        algorithm: str,
        parent_key_id: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> TrustChainLink:
        """
        Добавляет новый доверенный ключ в цепочку.

        Добавляет публичный ключ в реестр доверенных.
        Если parent_key_id указан — создаёт связь в цепочке.

        Args:
            key_id: Уникальный идентификатор ключа.
            public_key: Публичный ключ в бинарном формате.
            algorithm: Алгоритм подписи ("Ed25519", "ML-DSA-65", etc.).
            parent_key_id: ID родительского ключа (None для корневого).
            expires_at: Срок действия (None для бессрочного).
            metadata: Дополнительные данные (имя, организация).

        Returns:
            Созданный TrustChainLink.

        Raises:
            ValueError: Если key_id уже существует.
            KeyError: Если parent_key_id не найден.

        Example:
            >>> link = service.add_trusted_key(
            ...     key_id="my-key",
            ...     public_key=b"\x01\x02\x03...",
            ...     algorithm="Ed25519",
            ...     metadata={"name": "My Key"}
            ... )
        """
        if metadata is None:
            metadata = {}

        with self._lock:
            # Проверяем уникальность key_id
            if key_id in self._keys:
                error_msg = f"Ключ с ID '{key_id}' уже существует"
                self._audit_log.log_event(
                    AuditEventType.KEYSTORE_OPENED,
                    details={
                        "operation": "add_trusted_key",
                        "key_id": key_id,
                        "error": error_msg,
                    },
                )
                raise KeyAlreadyExistsError(error_msg)

            # Проверяем существование родительского ключа
            if parent_key_id is not None and parent_key_id not in self._keys:
                error_msg = f"Родительский ключ '{parent_key_id}' не найден"
                self._audit_log.log_event(
                    AuditEventType.KEYSTORE_OPENED,
                    details={
                        "operation": "add_trusted_key",
                        "key_id": key_id,
                        "parent_key_id": parent_key_id,
                        "error": error_msg,
                    },
                )
                raise KeyNotFoundError(error_msg)

            # Создаём связь цепочки доверия
            link = TrustChainLink(
                key_id=key_id,
                public_key=public_key,
                algorithm=algorithm,
                added_at=datetime.now(timezone.utc),
                parent_key_id=parent_key_id,
                expires_at=expires_at,
                signature=None,  # Подпись от родительского ключа добавляется отдельно
                metadata=metadata,
            )

            # Создаём запись
            entry = KeyEntry(link=link)
            self._keys[key_id] = entry

            # Сохраняем хранилище
            self._save_keystore()

            # Логируем в аудит
            self._audit_log.log_event(
                AuditEventType.CRYPTO_KEY_GENERATED,
                details={
                    "operation": "add_trusted_key",
                    "key_id": key_id,
                    "algorithm": algorithm,
                    "is_root": parent_key_id is None,
                    "parent_key_id": parent_key_id,
                    "metadata_keys": list(metadata.keys()),
                },
            )

            return link

    def revoke_key(
        self,
        key_id: str,
        reason: str,
        revoked_by: str,
    ) -> bool:
        """
        Отзывает ключ из цепочки доверия.

        Помечает ключ как отозванный. Ключ остаётся в реестре
        для проверки старых подписей, но новые подписи
        считаются недоверенными.

        Args:
            key_id: ID ключа для отзыва.
            reason: Причина отзыва.
            revoked_by: ID ключа, которым выполнен отзыв.

        Returns:
            True если отзыв выполнен успешно.

        Raises:
            KeyError: Если key_id не найден.
            ValueError: Если revoked_by нет прав на отзыв.

        Example:
            >>> success = service.revoke_key(
            ...     key_id="compromised-key",
            ...     reason="Приватный ключ скомпрометирован",
            ...     revoked_by="root-authority"
            ... )
        """
        with self._lock:
            # Проверяем существование ключа
            if key_id not in self._keys:
                error_msg = f"Ключ '{key_id}' не найден"
                self._audit_log.log_event(
                    AuditEventType.KEYSTORE_OPENED,
                    details={
                        "operation": "revoke_key",
                        "key_id": key_id,
                        "error": error_msg,
                    },
                )
                raise KeyNotFoundError(error_msg)

            # Проверяем существование ключа, выполняющего отзыв
            if revoked_by not in self._keys:
                error_msg = f"Ключ '{revoked_by}' не найден (нет прав на отзыв)"
                self._audit_log.log_event(
                    AuditEventType.KEYSTORE_OPENED,
                    details={
                        "operation": "revoke_key",
                        "key_id": key_id,
                        "revoked_by": revoked_by,
                        "error": error_msg,
                    },
                )
                raise KeyNotFoundError(error_msg)

            # Проверяем, что revoked_by является родителем или корневым ключом
            entry_to_revoke = self._keys[key_id]
            revoker_entry = self._keys[revoked_by]

            # Проверяем цепочку: revoked_by должен быть в цепочке выше key_id
            can_revoke = False
            if entry_to_revoke.link.parent_key_id == revoked_by:
                can_revoke = True
            elif revoker_entry.link.is_root():
                # Корневые ключи могут отзывать любые ключи в их поддереве
                chain = self.get_trust_chain(key_id, include_revoked=True)
                for link in chain:
                    if link.key_id == revoked_by:
                        can_revoke = True
                        break

            if not can_revoke:
                error_msg = f"Ключ '{revoked_by}' не имеет прав на отзыв ключа '{key_id}'"
                self._audit_log.log_event(
                    AuditEventType.KEYSTORE_OPENED,
                    details={
                        "operation": "revoke_key",
                        "key_id": key_id,
                        "revoked_by": revoked_by,
                        "error": error_msg,
                    },
                )
                raise ValueError(error_msg)

            # Проверяем, не отозван ли уже ключ
            if self._keys[key_id].revoked:
                # Уже отозван, считаем успехом
                return True

            # Создаём новую запись с отозванным статусом
            old_entry = self._keys[key_id]
            new_entry = KeyEntry(
                link=old_entry.link,
                revoked=True,
                revoked_at=datetime.now(timezone.utc),
                revoked_by=revoked_by,
                revoke_reason=reason,
            )
            self._keys[key_id] = new_entry

            # Сохраняем хранилище
            self._save_keystore()

            # Логируем в аудит
            revoked_at_iso = new_entry.revoked_at.isoformat() if new_entry.revoked_at else None
            self._audit_log.log_event(
                AuditEventType.CRYPTO_KEY_ROTATED,
                details={
                    "key_id": key_id,
                    "revoked_by": revoked_by,
                    "reason": reason,
                    "revoked_at": revoked_at_iso,
                },
            )

            return True

    def is_key_trusted(
        self,
        key_id: str,
        at_time: Optional[datetime] = None,
    ) -> bool:
        """
        Проверяет, является ли ключ доверенным.

        Проверяет статус ключа: не отозван, не истёк,
        цепочка валидна до корневого.

        Args:
            key_id: ID ключа для проверки.
            at_time: Время для проверки (None = текущее).

        Returns:
            True если ключ доверенный и валидный.

        Example:
            >>> if service.is_key_trusted("my-key"):
            ...     print("Ключ доверенный")
        """
        check_time = at_time or datetime.now(timezone.utc)

        with self._lock:
            entry = self._keys.get(key_id)
            if entry is None:
                return False

            # Проверяем отзыв
            if entry.revoked:
                # Ключ отозван - проверяем время отзыва
                if entry.revoked_at and at_time and at_time < entry.revoked_at:
                    # Запрашиваемое время до отзыва
                    pass  # Продолжаем проверку
                else:
                    return False

            # Проверяем срок действия
            if entry.link.expires_at and check_time > entry.link.expires_at:
                return False

            # Проверяем цепочку до корня
            chain = self.get_trust_chain(key_id, include_revoked=False)
            if not chain:
                return False

            # Проверяем, что последний элемент в цепочке - корневой
            if not chain[-1].is_root():
                # Цепочка оборвалась - нет корневого ключа
                return False

            return True

    def get_root_keys(self) -> list[TrustChainLink]:
        """
        Возвращает все корневые (self-signed) ключи.

        Returns:
            Список корневых ключей (где parent_key_id is None).

        Example:
            >>> roots = service.get_root_keys()
            >>> for root in roots:
            ...     print(f"Корневой ключ: {root.key_id}")
        """
        with self._lock:
            return [
                entry.link
                for entry in self._keys.values()
                if entry.link.is_root()
            ]

    def get_key_entry(self, key_id: str) -> Optional[KeyEntry]:
        """
        Возвращает полную запись о ключе.

        Args:
            key_id: ID ключа.

        Returns:
            KeyEntry или None если ключ не найден.
        """
        with self._lock:
            return self._keys.get(key_id)

    def get_key_count(self) -> int:
        """
        Возвращает общее количество ключей в реестре.

        Returns:
            Количество ключей.
        """
        with self._lock:
            return len(self._keys)

    def get_all_key_ids(self) -> list[str]:
        """
        Возвращает список всех ID ключей.

        Returns:
            Список ID ключей.
        """
        with self._lock:
            return list(self._keys.keys())


__all__ = [
    "TrustChainService",
    "TrustChainError",
    "KeyNotFoundError",
    "KeyAlreadyExistsError",
    "InvalidSignatureError",
    "ChainValidationError",
    "KeyEntry",
]
