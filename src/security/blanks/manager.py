"""
Менеджер жизненного цикла защищённых бланков.

Реализует управление бланками:
- Создание (issue)
- Активация (activate)
- Подпись (sign)
- Аннулирование (void/spoil)
- Архивирование (archive)

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol, runtime_checkable

from src.security.blanks.models import (
    BlankStatus,
    ProtectedBlank,
    QRVerificationData,
    SigningMode,
)
from src.security.blanks.signer import (
    BlankSigner,
    CryptoServiceProtocol,
    HardwareManagerProtocol,
    KeystoreProtocol,
)

if TYPE_CHECKING:
    from src.security.audit import AuditEventType


class BlankManagerError(Exception):
    """Базовая ошибка менеджера бланков."""

    pass


class BlankNotFoundError(BlankManagerError):
    """Бланк не найден."""

    pass


class BlankStatusError(BlankManagerError):
    """Недопустимый статус бланка."""

    pass


class BlankValidationError(BlankManagerError):
    """Ошибка валидации бланка."""

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
class BlankStorageProtocol(Protocol):
    """Протокол хранилища бланков."""

    def save(self, blank: ProtectedBlank) -> None:
        """Сохранить бланк."""
        ...

    def load(self, blank_id: str) -> Optional[ProtectedBlank]:
        """Загрузить бланк по ID."""
        ...

    def load_by_series_number(self, series: str, number: int) -> Optional[ProtectedBlank]:
        """Загрузить бланк по серии и номеру."""
        ...

    def list_by_status(self, status: BlankStatus) -> List[ProtectedBlank]:
        """Список бланков по статусу."""
        ...

    def delete(self, blank_id: str) -> bool:
        """Удалить бланк. Returns True if deleted."""
        ...


class BlankManager:
    """
    Менеджер жизненного цикла защищённых бланков.

    Управляет полным жизненным циклом бланков:
    - Issue: Создание нового бланка
    - Activate: Активация для использования
    - Sign: Подпись документа на бланке
    - Void/Spoil: Аннулирование
    - Archive: Архивирование

    Thread Safety:
        Все операции синхронизированы через lock.

    Example:
        >>> from src.security.blanks import BlankManager, BlankStatus
        >>> manager = BlankManager(
        ...     crypto_service=cs,
        ...     keystore=ks,
        ...     storage=storage,
        ...     audit_log=audit
        ... )
        >>> # Создание бланка
        >>> blank = manager.issue_blank(
        ...     series="INV-A",
        ...     number=42,
        ...     blank_type="invoice",
        ...     security_preset="standard"
        ... )
        >>> # Активация
        >>> blank = manager.activate_blank(blank.blank_id)
        >>> # Подпись
        >>> signature = manager.sign_blank(
        ...     blank_id=blank.blank_id,
        ...     document_content=b"...",
        ...     mode=SigningMode.SOFTWARE
        ... )
    """

    def __init__(
        self,
        crypto_service: CryptoServiceProtocol,
        keystore: KeystoreProtocol,
        storage: BlankStorageProtocol,
        audit_log: Optional[AuditLogProtocol] = None,
        hardware_manager: Optional[HardwareManagerProtocol] = None,
    ) -> None:
        """
        Инициализация менеджера.

        Args:
            crypto_service: Криптографический сервис
            keystore: Хранилище ключей
            storage: Хранилище бланков
            audit_log: Журнал аудита (опционально)
            hardware_manager: Менеджер аппаратных устройств (опционально)
        """
        self._crypto = crypto_service
        self._keystore = keystore
        self._storage = storage
        self._audit = audit_log
        self._hardware = hardware_manager
        self._signer = BlankSigner(
            crypto_service=crypto_service,
            keystore=keystore,
            hardware_manager=hardware_manager,
            audit_log=audit_log,
        )

    def issue_blank(
        self,
        series: str,
        number: int,
        blank_type: str,
        security_preset: str,
        *,
        signing_mode: SigningMode = SigningMode.SOFTWARE,
        signing_device_id: Optional[str] = None,
        certificate_id: Optional[str] = None,
        issued_to: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ProtectedBlank:
        """
        Создать новый бланк.

        Args:
            series: Серия бланка (например, "INV-A")
            number: Номер в серии
            blank_type: Тип документа из реестра
            security_preset: Пресет безопасности ("standard" / "paranoid" / "pqc")
            signing_mode: Режим подписи
            signing_device_id: ID устройства (для hardware mode)
            certificate_id: ID сертификата X.509 (для CA mode)
            issued_to: Кому выдан
            metadata: Дополнительные метаданные

        Returns:
            Созданный бланк в статусе ISSUED

        Raises:
            BlankManagerError: Ошибка создания бланка
        """
        # Получаем монотонный счётчик
        counter_name = f"blank_series_{series}"
        serial_counter = self._keystore.increment_counter(counter_name)

        # Получаем ключ подписи
        private_key, public_key, algorithm = self._keystore.get_signing_keypair(security_preset)

        # Создаём бланк
        blank = ProtectedBlank.create(
            series=series,
            number=number,
            blank_type=blank_type,
            security_preset=security_preset,
            signing_mode=signing_mode,
            signature_algorithm=algorithm,
            public_key=public_key,
            serial_counter=serial_counter,
            signing_device_id=signing_device_id,
            certificate_id=certificate_id,
            issued_to=issued_to,
            metadata=metadata,
        )

        # Сохраняем
        self._storage.save(blank)

        # Логируем в аудит
        if self._audit:
            from src.security.audit.events import AuditEventType

            self._audit.log_event(
                event_type=AuditEventType.BLANK_ISSUED,
                details={
                    "blank_id": blank.blank_id,
                    "series": series,
                    "number": number,
                    "blank_type": blank_type,
                    "security_preset": security_preset,
                    "signing_mode": signing_mode.value,
                },
            )

        return blank

    def activate_blank(self, blank_id: str) -> ProtectedBlank:
        """
        Активировать бланк (перевести в статус READY).

        Args:
            blank_id: UUID бланка

        Returns:
            Активированный бланк

        Raises:
            BlankNotFoundError: Бланк не найден
            BlankStatusError: Недопустимый статус
        """
        blank = self._storage.load(blank_id)
        if not blank:
            raise BlankNotFoundError(f"Blank not found: {blank_id}")

        if blank.status != BlankStatus.ISSUED:
            raise BlankStatusError(f"Cannot activate blank in status {blank.status.value}")

        # Переводим в статус READY
        activated = blank.with_status(BlankStatus.READY)
        self._storage.save(activated)

        return activated

    def sign_blank(
        self,
        blank_id: str,
        document_content: bytes,
        *,
        mode: Optional[SigningMode] = None,
        device_id: Optional[str] = None,
        pin: Optional[str] = None,
    ) -> tuple[ProtectedBlank, bytes, QRVerificationData]:
        """
        Подписать документ на бланке.

        Args:
            blank_id: UUID бланка
            document_content: Содержимое документа
            mode: Режим подписи (опционально, использует blank.signing_mode)
            device_id: ID устройства (для hardware mode)
            pin: PIN код устройства (для hardware mode)

        Returns:
            Кортеж (подписанный бланк, подпись, QR данные)

        Raises:
            BlankNotFoundError: Бланк не найден
            BlankStatusError: Недопустимый статус
            SigningError: Ошибка подписи
        """
        blank = self._storage.load(blank_id)
        if not blank:
            raise BlankNotFoundError(f"Blank not found: {blank_id}")

        if blank.status != BlankStatus.READY:
            raise BlankStatusError(f"Cannot sign blank in status {blank.status.value}")

        # Подписываем
        signing_mode = mode or blank.signing_mode
        signature = self._signer.sign_blank(
            blank=blank,
            document_content=document_content,
            mode=signing_mode,
            device_id=device_id,
            pin=pin,
        )

        # Переводим в статус PRINTED
        signed_blank = blank.with_status(BlankStatus.PRINTED)
        self._storage.save(signed_blank)

        # Создаём QR данные
        from src.security.blanks.signer import create_qr_data

        qr_data = create_qr_data(
            blank=signed_blank,
            document_content=document_content,
            signature=signature,
        )

        # Логируем
        if self._audit:
            from src.security.audit.events import AuditEventType

            self._audit.log_event(
                event_type=AuditEventType.BLANK_SIGNED,
                details={
                    "blank_id": blank_id,
                    "series": blank.series,
                    "number": blank.number,
                    "signing_mode": signing_mode.value,
                },
            )

        return signed_blank, signature, qr_data

    def void_blank(
        self,
        blank_id: str,
        reason: str,
    ) -> ProtectedBlank:
        """
        Аннулировать бланк.

        Args:
            blank_id: UUID бланка
            reason: Причина аннулирования

        Returns:
            Аннулированный бланк

        Raises:
            BlankNotFoundError: Бланк не найден
            BlankStatusError: Недопустимый статус
        """
        blank = self._storage.load(blank_id)
        if not blank:
            raise BlankNotFoundError(f"Blank not found: {blank_id}")

        if blank.status != BlankStatus.READY:
            raise BlankStatusError(f"Cannot void blank in status {blank.status.value}")

        # Переводим в статус VOIDED
        voided = blank.with_status(BlankStatus.VOIDED)
        voided_data = voided.to_dict()
        voided_data["metadata"] = {**voided.metadata, "void_reason": reason}
        voided_with_reason = ProtectedBlank.from_dict(voided_data)
        self._storage.save(voided_with_reason)

        # Логируем
        if self._audit:
            from src.security.audit.events import AuditEventType

            self._audit.log_event(
                event_type=AuditEventType.BLANK_VOIDED,
                details={
                    "blank_id": blank_id,
                    "series": blank.series,
                    "number": blank.number,
                    "reason": reason,
                },
            )

        return voided_with_reason

    def spoil_blank(
        self,
        blank_id: str,
        reason: str,
    ) -> ProtectedBlank:
        """
        Пометить бланк как испорченный.

        Args:
            blank_id: UUID бланка
            reason: Причина

        Returns:
            Испорченный бланк

        Raises:
            BlankNotFoundError: Бланк не найден
            BlankStatusError: Недопустимый статус
        """
        blank = self._storage.load(blank_id)
        if not blank:
            raise BlankNotFoundError(f"Blank not found: {blank_id}")

        if blank.status != BlankStatus.ISSUED:
            raise BlankStatusError(f"Cannot spoil blank in status {blank.status.value}")

        # Переводим в статус SPOILED
        spoiled = blank.with_status(BlankStatus.SPOILED)
        spoiled_data = spoiled.to_dict()
        spoiled_data["metadata"] = {**spoiled.metadata, "spoil_reason": reason}
        spoiled_with_reason = ProtectedBlank.from_dict(spoiled_data)
        self._storage.save(spoiled_with_reason)

        # Логируем
        if self._audit:
            from src.security.audit.events import AuditEventType

            self._audit.log_event(
                event_type=AuditEventType.BLANK_SPOILED,
                details={
                    "blank_id": blank_id,
                    "series": blank.series,
                    "number": blank.number,
                    "reason": reason,
                },
            )

        return spoiled_with_reason

    def archive_blank(self, blank_id: str) -> ProtectedBlank:
        """
        Архивировать бланк.

        Args:
            blank_id: UUID бланка

        Returns:
            Архивированный бланк

        Raises:
            BlankNotFoundError: Бланк не найден
            BlankStatusError: Недопустимый статус
        """
        blank = self._storage.load(blank_id)
        if not blank:
            raise BlankNotFoundError(f"Blank not found: {blank_id}")

        if blank.status != BlankStatus.PRINTED:
            raise BlankStatusError(f"Cannot archive blank in status {blank.status.value}")

        # Переводим в статус ARCHIVED
        archived = blank.with_status(BlankStatus.ARCHIVED)
        self._storage.save(archived)

        # Логируем
        if self._audit:
            from src.security.audit.events import AuditEventType

            self._audit.log_event(
                event_type=AuditEventType.BLANK_ARCHIVED,
                details={
                    "blank_id": blank_id,
                    "series": blank.series,
                    "number": blank.number,
                },
            )

        return archived

    def get_blank(self, blank_id: str) -> Optional[ProtectedBlank]:
        """
        Получить бланк по ID.

        Args:
            blank_id: UUID бланка

        Returns:
            Бланк или None если не найден
        """
        return self._storage.load(blank_id)

    def get_blank_by_series_number(self, series: str, number: int) -> Optional[ProtectedBlank]:
        """
        Получить бланк по серии и номеру.

        Args:
            series: Серия бланка
            number: Номер в серии

        Returns:
            Бланк или None если не найден
        """
        return self._storage.load_by_series_number(series, number)

    def list_blanks_by_status(self, status: BlankStatus) -> List[ProtectedBlank]:
        """
        Получить список бланков по статусу.

        Args:
            status: Статус бланков

        Returns:
            Список бланков
        """
        return self._storage.list_by_status(status)


__all__: list[str] = [
    "BlankManager",
    "BlankManagerError",
    "BlankNotFoundError",
    "BlankStatusError",
    "BlankValidationError",
    "BlankStorageProtocol",
    "AuditLogProtocol",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
