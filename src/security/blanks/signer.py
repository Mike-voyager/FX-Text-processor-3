"""
Модуль подписи защищённых бланков.

Реализует криптографическую подпись бланков в различных режимах:
- SOFTWARE: Программная подпись (ключ из keystore)
- HARDWARE_PIV: Аппаратная подпись через PIV слот
- HARDWARE_OPENPGP: Аппаратная подпись через OpenPGP слот

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional, Protocol, runtime_checkable

from src.security.blanks.models import ProtectedBlank, QRVerificationData, SigningMode

if TYPE_CHECKING:
    from src.security.audit.events import AuditEventType


class SigningError(Exception):
    """Ошибка подписи бланка."""

    pass


class VerificationError(Exception):
    """Ошибка верификации подписи."""

    pass


@runtime_checkable
class AuditLogProtocol(Protocol):
    """Протокол журнала аудита."""

    def log_event(
        self,
        event_type: "AuditEventType",
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Записать событие."""
        ...


@runtime_checkable
class CryptoServiceProtocol(Protocol):
    """Протокол криптографического сервиса для подписи."""

    def sign(
        self,
        algorithm: str,
        private_key: bytes,
        message: bytes,
    ) -> bytes:
        """Подписать сообщение."""
        ...

    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Проверить подпись."""
        ...

    def get_signing_key(self, preset: str) -> tuple[bytes, bytes, str]:
        """Получить ключ подписи для пресета (private_key, public_key, algorithm)."""
        ...


@runtime_checkable
class HardwareManagerProtocol(Protocol):
    """Протокол менеджера аппаратных устройств."""

    def sign_with_device(
        self,
        device_id: str,
        slot: int,
        message: bytes,
        pin: str,
    ) -> bytes:
        """Подписать сообщение на устройстве."""
        ...

    def get_public_key(self, device_id: str, slot: int) -> bytes:
        """Получить публичный ключ с устройства."""
        ...


@runtime_checkable
class KeystoreProtocol(Protocol):
    """Протокол хранилища ключей."""

    def get_signing_keypair(self, preset: str) -> tuple[bytes, bytes, str]:
        """Получить пару ключей для подписи."""
        ...

    def increment_counter(self, counter_name: str) -> int:
        """Увеличить монотонный счётчик."""
        ...


class BlankSigner:
    """
    Подписыватель бланков.

    Поддерживает три режима подписи:
    1. SOFTWARE: Ключ из keystore, подпись в памяти
    2. HARDWARE_PIV: Ключ на смарткарте, PIV слот
    3. HARDWARE_OPENPGP: Ключ на смарткарте, OpenPGP слот

    Example:
        >>> from src.security.blanks import BlankSigner, SigningMode
        >>> signer = BlankSigner(crypto_service=cs, keystore=ks)
        >>> # Программная подпись
        >>> signature = signer.sign_blank(
        ...     blank=blank,
        ...     document_content=b"...",
        ...     mode=SigningMode.SOFTWARE
        ... )
        >>> # Аппаратная подпись
        >>> signature = signer.sign_blank(
        ...     blank=blank,
        ...     document_content=b"...",
        ...     mode=SigningMode.HARDWARE_PIV,
        ...     device_id="yubikey-001",
        ...     pin="123456"
        ... )
    """

    def __init__(
        self,
        crypto_service: CryptoServiceProtocol,
        keystore: KeystoreProtocol,
        hardware_manager: Optional[HardwareManagerProtocol] = None,
        audit_log: Optional["AuditLogProtocol"] = None,
    ) -> None:
        """
        Инициализация подписывателя.

        Args:
            crypto_service: Криптографический сервис
            keystore: Хранилище ключей
            hardware_manager: Менеджер аппаратных устройств (для hardware mode)
            audit_log: Журнал аудита (опционально)
        """
        self._crypto = crypto_service
        self._keystore = keystore
        self._hardware = hardware_manager
        self._audit = audit_log

    def sign_blank(
        self,
        blank: ProtectedBlank,
        document_content: bytes,
        mode: Optional[SigningMode] = None,
        *,
        device_id: Optional[str] = None,
        pin: Optional[str] = None,
    ) -> bytes:
        """
        Подписать документ на бланке.

        Args:
            blank: Защищённый бланк
            document_content: Содержимое документа для подписи
            mode: Режим подписи (по умолчанию из blank.signing_mode)
            device_id: ID устройства (для hardware mode)
            pin: PIN код устройства (для hardware mode)

        Returns:
            Цифровая подпись

        Raises:
            SigningError: Ошибка подписи

        Security:
            - Для SOFTWARE режима: ключ из keystore, PIN не требуется
            - Для HARDWARE режима: ключ на устройстве, PIN обязателен
            - Подписывается хеш SHA3-256 содержимого
        """
        # Используем режим из бланка если не указан
        signing_mode = mode or blank.signing_mode

        # Вычисляем хеш документа
        content_hash = hashlib.sha3_256(document_content).digest()

        # Формируем сообщение для подписи: blank_id + content_hash
        message_to_sign = blank.blank_id.encode("utf-8") + content_hash

        try:
            if signing_mode == SigningMode.SOFTWARE:
                signature = self._sign_software(
                    blank=blank,
                    message=message_to_sign,
                    preset=blank.security_preset,
                )
            elif signing_mode == SigningMode.HARDWARE_PIV:
                if not device_id or not pin:
                    raise SigningError("device_id and pin are required for HARDWARE_PIV mode")
                signature = self._sign_hardware_piv(
                    blank=blank,
                    message=message_to_sign,
                    device_id=device_id,
                    pin=pin,
                )
            elif signing_mode == SigningMode.HARDWARE_OPENPGP:
                if not device_id or not pin:
                    raise SigningError("device_id and pin are required for HARDWARE_OPENPGP mode")
                signature = self._sign_hardware_openpgp(
                    blank=blank,
                    message=message_to_sign,
                    device_id=device_id,
                    pin=pin,
                )
            else:
                raise SigningError(f"Unsupported signing mode: {signing_mode}")

            # Логируем в аудит
            if self._audit:
                self._audit.log_event(
                    event_type=self._get_audit_event_type(signing_mode),
                    details={
                        "blank_id": blank.blank_id,
                        "series": blank.series,
                        "number": blank.number,
                        "signing_mode": signing_mode.value,
                        "algorithm": blank.signature_algorithm,
                        "device_id": device_id,
                    },
                )

            return signature

        except Exception as e:
            # Логируем ошибку
            if self._audit:
                from src.security.audit.events import AuditEventType

                self._audit.log_event(
                    event_type=AuditEventType.BLANK_SIGNING_BLOCKED,
                    details={
                        "blank_id": blank.blank_id,
                        "error": str(e),
                    },
                )
            raise SigningError(f"Failed to sign blank: {e}") from e

    def _sign_software(
        self,
        blank: ProtectedBlank,
        message: bytes,
        preset: str,
    ) -> bytes:
        """
        Программная подпись.

        Args:
            blank: Бланк
            message: Сообщение для подписи
            preset: Пресет безопасности

        Returns:
            Цифровая подпись
        """
        # Получаем ключ из keystore
        private_key, public_key, algorithm = self._keystore.get_signing_keypair(preset)

        # Проверяем что публичный ключ совпадает
        if public_key != blank.public_key:
            raise SigningError("Public key mismatch: keystore key differs from blank")

        # Подписываем
        return self._crypto.sign(algorithm, private_key, message)

    def _sign_hardware_piv(
        self,
        blank: ProtectedBlank,
        message: bytes,
        device_id: str,
        pin: str,
    ) -> bytes:
        """
        Аппаратная подпись через PIV слот.

        Args:
            blank: Бланк
            message: Сообщение для подписи
            device_id: ID устройства
            pin: PIN код

        Returns:
            Цифровая подпись
        """
        if not self._hardware:
            raise SigningError("Hardware manager not available")

        # PIV слот для подписи: 0x9C (Digital Signature)
        PIV_SIGNATURE_SLOT = 0x9C

        # Проверяем публичный ключ
        public_key = self._hardware.get_public_key(device_id, PIV_SIGNATURE_SLOT)
        if public_key != blank.public_key:
            raise SigningError("Public key mismatch: device key differs from blank")

        # Подписываем на устройстве
        return self._hardware.sign_with_device(
            device_id=device_id,
            slot=PIV_SIGNATURE_SLOT,
            message=message,
            pin=pin,
        )

    def _sign_hardware_openpgp(
        self,
        blank: ProtectedBlank,
        message: bytes,
        device_id: str,
        pin: str,
    ) -> bytes:
        """
        Аппаратная подпись через OpenPGP слот.

        Args:
            blank: Бланк
            message: Сообщение для подписи
            device_id: ID устройства
            pin: PIN код

        Returns:
            Цифровая подпись
        """
        if not self._hardware:
            raise SigningError("Hardware manager not available")

        # OpenPGP слот для подписи
        OPENPGP_SIGNATURE_SLOT = 0x01  # Signature key slot

        # Проверяем публичный ключ
        public_key = self._hardware.get_public_key(device_id, OPENPGP_SIGNATURE_SLOT)
        if public_key != blank.public_key:
            raise SigningError("Public key mismatch: device key differs from blank")

        # Подписываем на устройстве
        return self._hardware.sign_with_device(
            device_id=device_id,
            slot=OPENPGP_SIGNATURE_SLOT,
            message=message,
            pin=pin,
        )

    def _get_audit_event_type(self, mode: SigningMode) -> "AuditEventType":
        """Получить тип события аудита для режима подписи."""
        from src.security.audit.events import AuditEventType

        if mode == SigningMode.SOFTWARE:
            return AuditEventType.CRYPTO_SIGNING
        elif mode in (SigningMode.HARDWARE_PIV, SigningMode.HARDWARE_OPENPGP):
            return AuditEventType.DEVICE_OPERATION
        return AuditEventType.CRYPTO_SIGNING


def create_qr_data(
    blank: ProtectedBlank,
    document_content: bytes,
    signature: bytes,
) -> QRVerificationData:
    """
    Создать данные для QR-кода верификации.

    Args:
        blank: Защищённый бланк
        document_content: Содержимое документа
        signature: Цифровая подпись

    Returns:
        QRVerificationData для кодирования в QR
    """
    content_hash = hashlib.sha3_256(document_content).digest()

    return QRVerificationData(
        blank_id=blank.blank_id,
        series=blank.series,
        number=blank.number,
        content_hash_sha3=content_hash,
        signature=signature,
        public_key=blank.public_key,
        algorithm=blank.signature_algorithm,
        preset=blank.security_preset,
        printed_at=datetime.now(timezone.utc),
    )


__all__: list[str] = [
    "BlankSigner",
    "SigningError",
    "VerificationError",
    "CryptoServiceProtocol",
    "HardwareManagerProtocol",
    "KeystoreProtocol",
    "create_qr_data",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
