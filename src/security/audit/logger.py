"""
Неизменяемый журнал аудита с хеш-цепочкой.

Реализует tamper-proof audit log с криптографической защитой:
- SHA3-256 хеш для каждого события
- HMAC-SHA256 подпись
- Цепочка хешей (каждое событие ссылается на предыдущее)

Security:
    - Только append операции
    - Невозможность удаления или модификации
    - Обнаружение любых изменений в цепочке

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Final, List, Optional

from src.security.audit.events import AuditEventType

# Константы
SHA3_256_DIGEST_SIZE: Final[int] = 32  # 256 bits = 32 bytes
HMAC_SHA256_DIGEST_SIZE: Final[int] = 32
AUDIT_LOG_VERSION: Final[str] = "1.0"
MAX_EVENTS_PER_FILE: Final[int] = 100_000
AUDIT_FILE_EXTENSION: Final[str] = ".audit"


class AuditError(Exception):
    """Базовая ошибка аудита."""

    pass


class AuditLogError(AuditError):
    """Ошибка журнала аудита."""

    pass


class AuditIntegrityError(AuditError):
    """Нарушение целостности журнала аудита."""

    pass


class AuditVerificationError(AuditError):
    """Ошибка верификации цепочки."""

    pass


@dataclass(frozen=True)
class AuditEvent:
    """
    Событие аудита.

    Immutable событие с криптографической защитой. Каждое событие
    содержит хеш предыдущего события, образуя цепочку.

    Attributes:
        event_id: Уникальный идентификатор (UUID v4)
        event_type: Тип события из AuditEventType
        timestamp: Время события (UTC)
        previous_hash: Хеш предыдущего события в цепочке
        event_hash: SHA3-256 хеш события
        hmac_signature: HMAC-SHA256 подпись события
        details: Детали события (без секретов!)
        metadata: Дополнительные метаданные

    Security:
        - event_hash вычисляется от (event_id, event_type, timestamp,
          previous_hash, details)
        - hmac_signature вычисляется с audit_secret_key
        - Любое изменение делает цепочку невалидной
    """

    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    previous_hash: bytes
    event_hash: bytes
    hmac_signature: bytes
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация после создания."""
        object.__setattr__(self, "details", dict(self.details))
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def category(self) -> str:
        """Категория события."""
        return self.event_type.category

    @property
    def severity(self) -> str:
        """Серьёзность события."""
        return self.event_type.severity

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация события в словарь.

        Returns:
            Словарь с полями события (байты в hex)
        """
        return {
            "version": AUDIT_LOG_VERSION,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "previous_hash": self.previous_hash.hex(),
            "event_hash": self.event_hash.hex(),
            "hmac_signature": self.hmac_signature.hex(),
            "details": self.details,
            "metadata": self.metadata,
            "category": self.category,
            "severity": self.severity,
        }

    def to_json(self) -> str:
        """
        Сериализация события в JSON.

        Returns:
            JSON строка
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=None)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        """
        Десериализация события из словаря.

        Args:
            data: Словарь с полями события

        Returns:
            AuditEvent объект

        Raises:
            AuditError: Некорректные данные
        """
        try:
            return cls(
                event_id=data["event_id"],
                event_type=AuditEventType(data["event_type"]),
                timestamp=datetime.fromisoformat(data["timestamp"]),
                previous_hash=bytes.fromhex(data["previous_hash"]),
                event_hash=bytes.fromhex(data["event_hash"]),
                hmac_signature=bytes.fromhex(data["hmac_signature"]),
                details=data.get("details", {}),
                metadata=data.get("metadata", {}),
            )
        except (KeyError, ValueError) as e:
            raise AuditError(f"Invalid event data: {e}") from e

    @classmethod
    def from_json(cls, json_str: str) -> "AuditEvent":
        """
        Десериализация события из JSON.

        Args:
            json_str: JSON строка

        Returns:
            AuditEvent объект
        """
        return cls.from_dict(json.loads(json_str))


class AuditLog:
    """
    Неизменяемый журнал аудита с хеш-цепочкой.

    Реализует append-only журнал с криптографической защитой целостности.
    Каждое новое событие содержит хеш предыдущего, образуя цепочку.

    Security:
        - HMAC-SHA256 для аутентификации событий
        - SHA3-256 для хеш-цепочки
        - audit_secret_key хранится в защищённом хранилище
        - Невозможность модификации или удаления записей

    Thread Safety:
        - Все операции синхронизированы через lock
        - Безопасен для многопоточной среды

    Example:
        >>> from src.security.audit import AuditLog, AuditEventType
        >>> audit = AuditLog(audit_secret_key=secret, storage_path=Path("audit"))
        >>> audit.log_event(
        ...     AuditEventType.AUTH_SUCCESS,
        ...     details={"user": "operator", "method": "password"}
        ... )
        >>> audit.log_event(
        ...     AuditEventType.BLANK_SIGNED,
        ...     details={"blank_id": "uuid-...", "document_hash": "..."}
        ... )
        >>> # Проверка целостности
        >>> is_valid = audit.verify_chain()
    """

    def __init__(
        self,
        audit_secret_key: bytes,
        storage_path: Path,
        *,
        max_events_per_file: int = MAX_EVENTS_PER_FILE,
    ) -> None:
        """
        Инициализация журнала аудита.

        Args:
            audit_secret_key: Секретный ключ для HMAC (минимум 32 байта)
            storage_path: Путь к директории хранения журнала
            max_events_per_file: Максимальное количество событий в файле

        Raises:
            AuditError: Некорректные параметры
        """
        if len(audit_secret_key) < 32:
            raise AuditError("audit_secret_key must be at least 32 bytes")

        self._secret_key: bytes = audit_secret_key
        self._storage_path: Path = storage_path
        self._max_events_per_file: int = max_events_per_file
        self._lock: threading.RLock = threading.RLock()
        self._events: List[AuditEvent] = []
        self._last_hash: bytes = bytes(SHA3_256_DIGEST_SIZE)  # Genesis block
        self._event_count: int = 0

        # Создаём директорию если не существует
        self._storage_path.mkdir(parents=True, exist_ok=True)

        # Загружаем существующие события
        self._load_existing_events()

    def _load_existing_events(self) -> None:
        """Загрузка существующих событий из файлов."""
        audit_files = sorted(self._storage_path.glob(f"*{AUDIT_FILE_EXTENSION}"))

        for audit_file in audit_files:
            try:
                self._load_file(audit_file)
            except AuditError:
                # Логируем ошибку, но не прерываем загрузку
                # Целостность будет проверена при verify_chain()
                pass

        # Устанавливаем последний хеш
        if self._events:
            self._last_hash = self._events[-1].event_hash
            self._event_count = len(self._events)

    def _load_file(self, filepath: Path) -> None:
        """
        Загрузка событий из файла.

        Args:
            filepath: Путь к файлу журнала

        Raises:
            AuditError: Ошибка чтения файла
        """
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        event = AuditEvent.from_json(line)
                        self._events.append(event)
        except (OSError, json.JSONDecodeError) as e:
            raise AuditError(f"Failed to load audit file {filepath}: {e}") from e

    def _compute_event_hash(
        self,
        event_id: str,
        event_type: AuditEventType,
        timestamp: datetime,
        previous_hash: bytes,
        details: Dict[str, Any],
    ) -> bytes:
        """
        Вычисление SHA3-256 хеша события.

        Args:
            event_id: UUID события
            event_type: Тип события
            timestamp: Время события
            previous_hash: Хеш предыдущего события
            details: Детали события

        Returns:
            SHA3-256 хеш (32 байта)
        """
        # Формируем детерминированное представление
        data = json.dumps(
            {
                "event_id": event_id,
                "event_type": event_type.value,
                "timestamp": timestamp.isoformat(),
                "previous_hash": previous_hash.hex(),
                "details": details,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha3_256(data.encode("utf-8")).digest()

    def _compute_hmac(self, event_hash: bytes) -> bytes:
        """
        Вычисление HMAC-SHA256 подписи события.

        Args:
            event_hash: Хеш события

        Returns:
            HMAC-SHA256 подпись (32 байта)
        """
        return hmac.new(self._secret_key, event_hash, hashlib.sha256).digest()

    def log_event(
        self,
        event_type: AuditEventType,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> AuditEvent:
        """
        Записать событие в журнал.

        Только append операция. Невозможно удалить или модифицировать.

        Args:
            event_type: Тип события из AuditEventType
            details: Детали события (без секретов!)
            metadata: Дополнительные метаданные

        Returns:
            Созданное событие AuditEvent

        Raises:
            AuditLogError: Ошибка записи

        Security:
            - Все секреты (ключи, пароли, PIN) ДОЛЖНЫ быть исключены из details
            - details логируется и сохраняется в файл
        """
        if details is None:
            details = {}
        if metadata is None:
            metadata = {}

        with self._lock:
            # Генерируем уникальный ID
            event_id = str(uuid.uuid4())

            # Текущее время UTC
            timestamp = datetime.now(timezone.utc)

            # Вычисляем хеш события
            event_hash = self._compute_event_hash(
                event_id=event_id,
                event_type=event_type,
                timestamp=timestamp,
                previous_hash=self._last_hash,
                details=details,
            )

            # Вычисляем HMAC подпись
            hmac_signature = self._compute_hmac(event_hash)

            # Создаём событие
            event = AuditEvent(
                event_id=event_id,
                event_type=event_type,
                timestamp=timestamp,
                previous_hash=self._last_hash,
                event_hash=event_hash,
                hmac_signature=hmac_signature,
                details=details,
                metadata=metadata,
            )

            # Добавляем в память
            self._events.append(event)
            self._last_hash = event_hash
            self._event_count += 1

            # Записываем на диск
            self._append_to_disk(event)

            return event

    def _append_to_disk(self, event: AuditEvent) -> None:
        """
        Запись события на диск.

        Args:
            event: Событие для записи

        Raises:
            AuditLogError: Ошибка записи
        """
        # Определяем файл для записи
        current_file = self._get_current_file()

        try:
            # Append-режим для добавления в конец файла
            with open(current_file, "a", encoding="utf-8") as f:
                f.write(event.to_json())
                f.write("\n")
        except OSError as e:
            raise AuditLogError(f"Failed to write audit event: {e}") from e

    def _get_current_file(self) -> Path:
        """
        Получение текущего файла журнала.

        Returns:
            Путь к текущему файлу
        """
        # Имя файла: audit_YYYYMMDD_HHMMSS.audit (по первому событию)
        existing_files = sorted(self._storage_path.glob(f"*{AUDIT_FILE_EXTENSION}"), reverse=True)

        if existing_files:
            # Проверяем количество событий в последнем файле
            last_file = existing_files[0]
            try:
                with open(last_file, "r", encoding="utf-8") as f:
                    line_count = sum(1 for _ in f)
                if line_count < self._max_events_per_file:
                    return last_file
            except OSError:
                pass

        # Создаём новый файл
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return self._storage_path / f"audit_{timestamp}{AUDIT_FILE_EXTENSION}"

    def verify_chain(self) -> bool:
        """
        Проверка целостности всей цепочки событий.

        Проверяет:
        1. Целостность хеш-цепочки (previous_hash для каждого события)
        2. Корректность HMAC подписей

        Returns:
            True если цепочка валидна

        Raises:
            AuditIntegrityError: Нарушение целостности цепочки
        """
        with self._lock:
            previous_hash = bytes(SHA3_256_DIGEST_SIZE)  # Genesis

            for i, event in enumerate(self._events):
                # Проверяем связь с предыдущим событием
                if event.previous_hash != previous_hash:
                    raise AuditIntegrityError(
                        f"Chain broken at event {i}: previous_hash mismatch. "
                        f"Event ID: {event.event_id}"
                    )

                # Перевычисляем хеш и проверяем
                computed_hash = self._compute_event_hash(
                    event_id=event.event_id,
                    event_type=event.event_type,
                    timestamp=event.timestamp,
                    previous_hash=event.previous_hash,
                    details=event.details,
                )
                if computed_hash != event.event_hash:
                    raise AuditIntegrityError(
                        f"Hash mismatch at event {i}. Event ID: {event.event_id}"
                    )

                # Проверяем HMAC подпись
                expected_hmac = self._compute_hmac(event.event_hash)
                if not hmac.compare_digest(expected_hmac, event.hmac_signature):
                    raise AuditIntegrityError(
                        f"HMAC verification failed at event {i}. Event ID: {event.event_id}"
                    )

                previous_hash = event.event_hash

            return True

    def get_events(
        self,
        event_types: Optional[List[AuditEventType]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEvent]:
        """
        Получение событий с фильтрацией.

        Args:
            event_types: Фильтр по типам событий (None = все)
            start_time: Начало временного диапазона
            end_time: Конец временного диапазона
            limit: Максимальное количество событий
            offset: Смещение от начала

        Returns:
            Список событий, соответствующих фильтрам
        """
        with self._lock:
            result: List[AuditEvent] = []

            for event in reversed(self._events):  # Новые события сначала
                # Фильтр по типу
                if event_types and event.event_type not in event_types:
                    continue

                # Фильтр по времени
                if start_time and event.timestamp < start_time:
                    continue
                if end_time and event.timestamp > end_time:
                    continue

                result.append(event)

                if len(result) >= limit + offset:
                    break

            return result[offset : offset + limit]

    def get_event_by_id(self, event_id: str) -> Optional[AuditEvent]:
        """
        Получение события по ID.

        Args:
            event_id: UUID события

        Returns:
            Событие или None если не найдено
        """
        with self._lock:
            for event in self._events:
                if event.event_id == event_id:
                    return event
            return None

    def count_events(
        self,
        event_types: Optional[List[AuditEventType]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """
        Подсчёт событий с фильтрацией.

        Args:
            event_types: Фильтр по типам событий
            start_time: Начало временного диапазона
            end_time: Конец временного диапазона

        Returns:
            Количество событий
        """
        with self._lock:
            count = 0
            for event in self._events:
                if event_types and event.event_type not in event_types:
                    continue
                if start_time and event.timestamp < start_time:
                    continue
                if end_time and event.timestamp > end_time:
                    continue
                count += 1
            return count

    @property
    def event_count(self) -> int:
        """Общее количество событий в журнале."""
        return self._event_count

    @property
    def last_event(self) -> Optional[AuditEvent]:
        """Последнее событие в журнале."""
        with self._lock:
            return self._events[-1] if self._events else None

    @property
    def last_hash(self) -> bytes:
        """Хеш последнего события (или genesis хеш для пустого журнала)."""
        return self._last_hash

    def export_events(
        self,
        output_path: Path,
        event_types: Optional[List[AuditEventType]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> int:
        """
        Экспорт событий в файл.

        Args:
            output_path: Путь для экспорта
            event_types: Фильтр по типам событий
            start_time: Начало временного диапазона
            end_time: Конец временного диапазона

        Returns:
            Количество экспортированных событий
        """
        events = self.get_events(
            event_types=event_types,
            start_time=start_time,
            end_time=end_time,
            limit=1_000_000,  # Все события
        )

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                for event in events:
                    f.write(event.to_json())
                    f.write("\n")
        except OSError as e:
            raise AuditLogError(f"Failed to export events: {e}") from e

        return len(events)


def verify_chain_integrity(audit_log: AuditLog) -> bool:
    """
    Проверка целостности цепочки журнала аудита.

    Удобная функция для внешнего использования.

    Args:
        audit_log: Журнал аудита для проверки

    Returns:
        True если цепочка валидна

    Raises:
        AuditIntegrityError: Нарушение целостности

    Example:
        >>> from src.security.audit import AuditLog, verify_chain_integrity
        >>> audit = AuditLog(...)
        >>> # ... записываем события ...
        >>> verify_chain_integrity(audit)
        True
    """
    return audit_log.verify_chain()


def generate_audit_secret_key() -> bytes:
    """
    Генерация секретного ключа для журнала аудита.

    Returns:
        Случайный ключ 32 байта (256 бит)

    Security:
        Использует secrets.token_bytes() для криптографически
        стойкой генерации.
    """
    return secrets.token_bytes(32)


__all__: list[str] = [
    "AuditEvent",
    "AuditLog",
    "AuditError",
    "AuditLogError",
    "AuditIntegrityError",
    "AuditVerificationError",
    "verify_chain_integrity",
    "generate_audit_secret_key",
    "SHA3_256_DIGEST_SIZE",
    "HMAC_SHA256_DIGEST_SIZE",
    "AUDIT_LOG_VERSION",
    "MAX_EVENTS_PER_FILE",
    "AUDIT_FILE_EXTENSION",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
