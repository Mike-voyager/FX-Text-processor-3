"""
Модели данных для защищённых бланков.

Определяет структуры данных для бланков:
- BlankStatus: Статусы жизненного цикла
- SigningMode: Режимы подписи
- ProtectedBlank: Защищённый бланк
- VerificationResult: Результат верификации

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Final, List, Optional
from uuid import uuid4


class BlankStatus(Enum):
    """
    Статусы жизненного цикла бланка.

    Lifecycle:
        ISSUED → READY → PRINTED → ARCHIVED
                  ↓
               SPOILED / VOIDED

    Transitions:
        ISSUED → READY: Бланк выпущен и готов к использованию
        ISSUED → SPOILED: Бланк испорчен (физическое повреждение)
        READY → PRINTED: Бланк использован для печати документа
        READY → VOIDED: Бланк аннулирован (превышено количество попыток)
        PRINTED → ARCHIVED: Бланк архивирован (retention: 7 лет)
    """

    ISSUED = "issued"
    """Бланк выпущен, ожидает активации."""

    READY = "ready"
    """Бланк готов к использованию (активирован)."""

    PRINTED = "printed"
    """Бланк использован для печати документа."""

    ARCHIVED = "archived"
    """Бланк архивирован (конец жизненного цикла)."""

    SPOILED = "spoiled"
    """Бланк испорчен (физическое повреждение)."""

    VOIDED = "voided"
    """Бланк аннулирован (превышено количество попыток)."""

    @property
    def is_terminal(self) -> bool:
        """Терминальный статус (нельзя изменить)."""
        return self in (BlankStatus.ARCHIVED, BlankStatus.SPOILED, BlankStatus.VOIDED)

    @property
    def is_usable(self) -> bool:
        """Бланк можно использовать."""
        return self == BlankStatus.READY


class SigningMode(Enum):
    """
    Режим подписи бланка.

    Modes:
        SOFTWARE: Программная подпись (ключ из keystore)
        HARDWARE_PIV: Аппаратная подпись через PIV слот
        HARDWARE_OPENPGP: Аппаратная подпись через OpenPGP слот
    """

    SOFTWARE = "software"
    """Программная подпись (ключ из keystore)."""

    HARDWARE_PIV = "hardware_piv"
    """Аппаратная подпись через PIV слот смарткарты."""

    HARDWARE_OPENPGP = "hardware_openpgp"
    """Аппаратная подпись через OpenPGP слот смарткарты."""

    @property
    def is_hardware(self) -> bool:
        """Аппаратный режим подписи."""
        return self in (SigningMode.HARDWARE_PIV, SigningMode.HARDWARE_OPENPGP)


# Допустимые переходы статусов
VALID_TRANSITIONS: Final[Dict[BlankStatus, List[BlankStatus]]] = {
    BlankStatus.ISSUED: [BlankStatus.READY, BlankStatus.SPOILED],
    BlankStatus.READY: [BlankStatus.PRINTED, BlankStatus.VOIDED],
    BlankStatus.PRINTED: [BlankStatus.ARCHIVED],
    BlankStatus.ARCHIVED: [],  # Терминальный статус
    BlankStatus.SPOILED: [],  # Терминальный статус
    BlankStatus.VOIDED: [],  # Терминальный статус
}


@dataclass(frozen=True)
class ProtectedBlank:
    """
    Защищённый бланк с криптографической идентичностью.

    Attributes:
        blank_id: Уникальный идентификатор (UUID v4)
        series: Серия бланка (буквенно-цифровой код, например "INV-A")
        number: Номер в серии (последовательный)
        blank_type: Тип документа из реестра documents/types
        security_preset: Пресет безопасности ("standard" / "paranoid" / "pqc")
        signing_mode: Режим подписи
        signing_device_id: ID устройства (для аппаратной подписи)
        signature_algorithm: Алгоритм подписи ("Ed25519" / "ML-DSA-65" / ...)
        public_key: Публичный ключ верификации
        certificate_id: ID сертификата X.509 (опционально, для CA mode)
        issued_to: Кому выдан бланк
        status: Текущий статус
        serial_counter: Монотонный счётчик из keystore
        created_at: Время создания
        updated_at: Время последнего обновления
        metadata: Дополнительные метаданные

    Security:
        - public_key хранится вместе с бланком для offline верификации
        - signature_algorithm определяет пресет безопасности
        - serial_counter монотонно возрастает, защита от повторного использования
    """

    blank_id: str
    series: str
    number: int
    blank_type: str
    security_preset: str
    signing_mode: SigningMode
    signature_algorithm: str
    public_key: bytes
    status: BlankStatus
    serial_counter: int
    signing_device_id: Optional[str] = None
    certificate_id: Optional[str] = None
    issued_to: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация после создания."""
        # Frozen dataclass workaround
        object.__setattr__(self, "metadata", dict(self.metadata))

    @classmethod
    def create(
        cls,
        series: str,
        number: int,
        blank_type: str,
        security_preset: str,
        signing_mode: SigningMode,
        signature_algorithm: str,
        public_key: bytes,
        serial_counter: int,
        *,
        signing_device_id: Optional[str] = None,
        certificate_id: Optional[str] = None,
        issued_to: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "ProtectedBlank":
        """
        Фабричный метод для создания нового бланка.

        Args:
            series: Серия бланка
            number: Номер в серии
            blank_type: Тип документа
            security_preset: Пресет безопасности
            signing_mode: Режим подписи
            signature_algorithm: Алгоритм подписи
            public_key: Публичный ключ
            serial_counter: Счётчик из keystore
            signing_device_id: ID устройства (для hardware mode)
            certificate_id: ID сертификата (для CA mode)
            issued_to: Кому выдан
            metadata: Дополнительные метаданные

        Returns:
            Новый бланк в статусе ISSUED
        """
        now = datetime.now(timezone.utc)
        return cls(
            blank_id=str(uuid4()),
            series=series,
            number=number,
            blank_type=blank_type,
            security_preset=security_preset,
            signing_mode=signing_mode,
            signature_algorithm=signature_algorithm,
            public_key=public_key,
            status=BlankStatus.ISSUED,
            serial_counter=serial_counter,
            signing_device_id=signing_device_id,
            certificate_id=certificate_id,
            issued_to=issued_to,
            created_at=now,
            updated_at=now,
            metadata=metadata or {},
        )

    @property
    def display_id(self) -> str:
        """
        Отображаемый идентификатор бланка.

        Returns:
            Формат: SERIES-NUMBER (например, "INV-A-0042")
        """
        return f"{self.series}-{self.number:04d}"

    def can_transition_to(self, new_status: BlankStatus) -> bool:
        """
        Проверка допустимости перехода в новый статус.

        Args:
            new_status: Новый статус

        Returns:
            True если переход допустим
        """
        return new_status in VALID_TRANSITIONS.get(self.status, [])

    def with_status(self, new_status: BlankStatus) -> "ProtectedBlank":
        """
        Создать копию бланка с новым статусом.

        Args:
            new_status: Новый статус

        Returns:
            Новый бланк с обновлённым статусом

        Raises:
            ValueError: Недопустимый переход статуса
        """
        if not self.can_transition_to(new_status):
            raise ValueError(f"Invalid status transition: {self.status.value} → {new_status.value}")

        return ProtectedBlank(
            blank_id=self.blank_id,
            series=self.series,
            number=self.number,
            blank_type=self.blank_type,
            security_preset=self.security_preset,
            signing_mode=self.signing_mode,
            signature_algorithm=self.signature_algorithm,
            public_key=self.public_key,
            status=new_status,
            serial_counter=self.serial_counter,
            signing_device_id=self.signing_device_id,
            certificate_id=self.certificate_id,
            issued_to=self.issued_to,
            created_at=self.created_at,
            updated_at=datetime.now(timezone.utc),
            metadata=self.metadata,
        )

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация бланка в словарь.

        Returns:
            Словарь с полями бланка
        """
        return {
            "blank_id": self.blank_id,
            "series": self.series,
            "number": self.number,
            "blank_type": self.blank_type,
            "security_preset": self.security_preset,
            "signing_mode": self.signing_mode.value,
            "signature_algorithm": self.signature_algorithm,
            "public_key": self.public_key.hex(),
            "status": self.status.value,
            "serial_counter": self.serial_counter,
            "signing_device_id": self.signing_device_id,
            "certificate_id": self.certificate_id,
            "issued_to": self.issued_to,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
            "display_id": self.display_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProtectedBlank":
        """
        Десериализация бланка из словаря.

        Args:
            data: Словарь с полями бланка

        Returns:
            ProtectedBlank объект
        """
        return cls(
            blank_id=data["blank_id"],
            series=data["series"],
            number=data["number"],
            blank_type=data["blank_type"],
            security_preset=data["security_preset"],
            signing_mode=SigningMode(data["signing_mode"]),
            signature_algorithm=data["signature_algorithm"],
            public_key=bytes.fromhex(data["public_key"]),
            status=BlankStatus(data["status"]),
            serial_counter=data["serial_counter"],
            signing_device_id=data.get("signing_device_id"),
            certificate_id=data.get("certificate_id"),
            issued_to=data.get("issued_to", ""),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            metadata=data.get("metadata", {}),
        )


@dataclass(frozen=True)
class QRVerificationData:
    """
    Данные для QR верификации бланка.

    Содержит всю информацию для offline верификации без сети.

    Attributes:
        blank_id: UUID бланка
        series: Серия
        number: Номер в серии
        content_hash_sha3: SHA3-256 хеш содержимого документа
        signature: Цифровая подпись документа
        public_key: Публичный ключ для верификации
        algorithm: Алгоритм подписи
        preset: Пресет безопасности
        printed_at: Время печати
        format_version: Версия формата QR данных
    """

    blank_id: str
    series: str
    number: int
    content_hash_sha3: bytes
    signature: bytes
    public_key: bytes
    algorithm: str
    preset: str
    printed_at: datetime
    format_version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализация в словарь.

        Returns:
            Словарь с полями для JSON
        """
        return {
            "blank_id": self.blank_id,
            "series": self.series,
            "number": self.number,
            "content_hash_sha3": self.content_hash_sha3.hex(),
            "signature": self.signature.hex(),
            "public_key": self.public_key.hex(),
            "algorithm": self.algorithm,
            "preset": self.preset,
            "printed_at": self.printed_at.isoformat(),
            "format_version": self.format_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QRVerificationData":
        """
        Десериализация из словаря.

        Args:
            data: Словарь с полями

        Returns:
            QRVerificationData объект
        """
        return cls(
            blank_id=data["blank_id"],
            series=data["series"],
            number=data["number"],
            content_hash_sha3=bytes.fromhex(data["content_hash_sha3"]),
            signature=bytes.fromhex(data["signature"]),
            public_key=bytes.fromhex(data["public_key"]),
            algorithm=data["algorithm"],
            preset=data["preset"],
            printed_at=datetime.fromisoformat(data["printed_at"]),
            format_version=data.get("format_version", "1.0"),
        )


@dataclass(frozen=True)
class VerificationResult:
    """
    Результат верификации бланка.

    Attributes:
        authentic: True если подпись валидна
        blank_id: ID бланка
        series: Серия бланка
        number: Номер бланка
        algorithm: Алгоритм подписи
        verified_at: Время верификации
        reason: Причина неудачи (если authentic=False)
        warnings: Предупреждения (не блокирующие проблемы)
    """

    authentic: bool
    blank_id: str
    series: str
    number: int
    algorithm: str
    verified_at: datetime
    reason: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Валидация после создания."""
        object.__setattr__(self, "warnings", list(self.warnings))

    @property
    def display_id(self) -> str:
        """Отображаемый идентификатор бланка."""
        return f"{self.series}-{self.number:04d}"


__all__: list[str] = [
    "BlankStatus",
    "SigningMode",
    "VALID_TRANSITIONS",
    "ProtectedBlank",
    "QRVerificationData",
    "VerificationResult",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
