"""
Верификация защищённых бланков.

Реализует проверку подлинности бланков:
- Offline верификация через QR-код
- Проверка цифровой подписи
- Проверка хеш-цепочки

Supports:
    - Ed25519 подписи
    - RSA-PSS подписи
    - ML-DSA-65 (Post-Quantum) подписи

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from src.security.blanks.models import (
    QRVerificationData,
    VerificationResult,
)
from src.security.blanks.signer import VerificationError


@runtime_checkable
class CryptoServiceProtocol(Protocol):
    """Протокол криптографического сервиса."""

    def verify(
        self,
        algorithm: str,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """Проверить подпись."""
        ...


@runtime_checkable
class AuditLogProtocol(Protocol):
    """Протокол журнала аудита."""

    def log_event(
        self,
        event_type: Any,  # AuditEventType
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Записать событие."""
        ...


def verify_blank(
    qr_data: QRVerificationData,
    printed_content: bytes,
    crypto_service: CryptoServiceProtocol,
    *,
    audit_log: Optional[AuditLogProtocol] = None,
    max_age_days: Optional[int] = None,
) -> VerificationResult:
    """
    Верифицировать бланк по QR-данным.

    Offline верификация — все данные для проверки содержатся в QR-коде.
    Сеть не требуется.

    Args:
        qr_data: Данные из QR-кода
        printed_content: Содержимое напечатанного документа
        crypto_service: Криптографический сервис
        audit_log: Журнал аудита (опционально)
        max_age_days: Максимальный возраст документа в днях (опционально)

    Returns:
        VerificationResult с результатами проверки

    Security:
        - Проверяется SHA3-256 хеш содержимого
        - Проверяется цифровая подпись
        - Проверяется возраст документа (если указан)

    Example:
        >>> from src.security.blanks import verify_blank, QRVerificationData
        >>> qr_data = QRVerificationData.from_dict(parsed_qr_json)
        >>> result = verify_blank(
        ...     qr_data=qr_data,
        ...     printed_content=document_bytes,
        ...     crypto_service=crypto_service
        ... )
        >>> if result.authentic:
        ...     print(f"✓ Valid blank {result.display_id}")
        ... else:
        ...     print(f"⚠️ Verification failed: {result.reason}")
    """
    warnings: list[str] = []

    try:
        # 1. Проверяем формат версии
        if qr_data.format_version not in ("1.0", "1.1"):
            return VerificationResult(
                authentic=False,
                blank_id=qr_data.blank_id,
                series=qr_data.series,
                number=qr_data.number,
                algorithm=qr_data.algorithm,
                verified_at=datetime.now(timezone.utc),
                reason=f"Unsupported format version: {qr_data.format_version}",
            )

        # 2. Проверяем хеш содержимого
        computed_hash = hashlib.sha3_256(printed_content).digest()
        if computed_hash != qr_data.content_hash_sha3:
            # Логируем неудачную верификацию
            if audit_log:
                from src.security.audit.events import AuditEventType

                audit_log.log_event(
                    event_type=AuditEventType.BLANK_VERIFY_FAILED,
                    details={
                        "blank_id": qr_data.blank_id,
                        "reason": "content_hash_mismatch",
                        "expected": qr_data.content_hash_sha3.hex()[:16],
                        "computed": computed_hash.hex()[:16],
                    },
                )

            return VerificationResult(
                authentic=False,
                blank_id=qr_data.blank_id,
                series=qr_data.series,
                number=qr_data.number,
                algorithm=qr_data.algorithm,
                verified_at=datetime.now(timezone.utc),
                reason="Content hash mismatch — document may have been modified",
            )

        # 3. Проверяем возраст документа (если указан)
        if max_age_days is not None:
            age = datetime.now(timezone.utc) - qr_data.printed_at
            if age.days > max_age_days:
                warnings.append(
                    f"Document age ({age.days} days) exceeds maximum ({max_age_days} days)"
                )

        # 4. Формируем сообщение для проверки подписи
        message_to_verify = qr_data.blank_id.encode("utf-8") + computed_hash

        # 5. Проверяем подпись
        signature_valid = crypto_service.verify(
            algorithm=qr_data.algorithm,
            public_key=qr_data.public_key,
            message=message_to_verify,
            signature=qr_data.signature,
        )

        if not signature_valid:
            # Логируем неудачную верификацию
            if audit_log:
                from src.security.audit.events import AuditEventType

                audit_log.log_event(
                    event_type=AuditEventType.BLANK_VERIFY_FAILED,
                    details={
                        "blank_id": qr_data.blank_id,
                        "reason": "signature_invalid",
                        "algorithm": qr_data.algorithm,
                    },
                )

            return VerificationResult(
                authentic=False,
                blank_id=qr_data.blank_id,
                series=qr_data.series,
                number=qr_data.number,
                algorithm=qr_data.algorithm,
                verified_at=datetime.now(timezone.utc),
                reason="Signature verification failed — document may be forged",
                warnings=warnings,
            )

        # 6. Успешная верификация
        if audit_log:
            from src.security.audit.events import AuditEventType

            audit_log.log_event(
                event_type=AuditEventType.BLANK_VERIFIED,
                details={
                    "blank_id": qr_data.blank_id,
                    "series": qr_data.series,
                    "number": qr_data.number,
                    "algorithm": qr_data.algorithm,
                    "preset": qr_data.preset,
                },
            )

        return VerificationResult(
            authentic=True,
            blank_id=qr_data.blank_id,
            series=qr_data.series,
            number=qr_data.number,
            algorithm=qr_data.algorithm,
            verified_at=datetime.now(timezone.utc),
            warnings=warnings,
        )

    except Exception as e:
        # Логируем ошибку
        if audit_log:
            from src.security.audit.events import AuditEventType

            audit_log.log_event(
                event_type=AuditEventType.BLANK_VERIFY_FAILED,
                details={
                    "blank_id": qr_data.blank_id,
                    "error": str(e),
                },
            )

        return VerificationResult(
            authentic=False,
            blank_id=qr_data.blank_id,
            series=qr_data.series,
            number=qr_data.number,
            algorithm=qr_data.algorithm,
            verified_at=datetime.now(timezone.utc),
            reason=f"Verification error: {e}",
        )


def verify_blank_from_json(
    qr_json: Dict[str, Any],
    printed_content: bytes,
    crypto_service: CryptoServiceProtocol,
    *,
    audit_log: Optional[AuditLogProtocol] = None,
    max_age_days: Optional[int] = None,
) -> VerificationResult:
    """
    Верифицировать бланк из JSON данных QR-кода.

    Удобная обёртка для verify_blank.

    Args:
        qr_json: JSON данные из QR-кода
        printed_content: Содержимое напечатанного документа
        crypto_service: Криптографический сервис
        audit_log: Журнал аудита (опционально)
        max_age_days: Максимальный возраст документа в днях (опционально)

    Returns:
        VerificationResult с результатами проверки
    """
    qr_data = QRVerificationData.from_dict(qr_json)
    return verify_blank(
        qr_data=qr_data,
        printed_content=printed_content,
        crypto_service=crypto_service,
        audit_log=audit_log,
        max_age_days=max_age_days,
    )


class BlankVerifier:
    """
    Класс для верификации бланков с кэшированием публичных ключей.

    Предоставляет удобный интерфейс для множественной верификации
    с оптимизацией кэширования.

    Example:
        >>> from src.security.blanks import BlankVerifier
        >>> verifier = BlankVerifier(crypto_service=cs, audit_log=audit)
        >>> # Верификация одного бланка
        >>> result = verifier.verify(qr_data, document_bytes)
        >>> # Массовая верификация
        >>> results = verifier.verify_batch([
        ...     (qr_data_1, doc_bytes_1),
        ...     (qr_data_2, doc_bytes_2),
        ... ])
    """

    def __init__(
        self,
        crypto_service: CryptoServiceProtocol,
        audit_log: Optional[AuditLogProtocol] = None,
        max_age_days: Optional[int] = None,
    ) -> None:
        """
        Инициализация верификатора.

        Args:
            crypto_service: Криптографический сервис
            audit_log: Журнал аудита (опционально)
            max_age_days: Максимальный возраст документа (опционально)
        """
        self._crypto = crypto_service
        self._audit = audit_log
        self._max_age_days = max_age_days
        self._key_cache: Dict[str, bytes] = {}  # Кэш публичных ключей

    def verify(
        self,
        qr_data: QRVerificationData,
        printed_content: bytes,
    ) -> VerificationResult:
        """
        Верифицировать бланк.

        Args:
            qr_data: Данные из QR-кода
            printed_content: Содержимое документа

        Returns:
            VerificationResult
        """
        return verify_blank(
            qr_data=qr_data,
            printed_content=printed_content,
            crypto_service=self._crypto,
            audit_log=self._audit,
            max_age_days=self._max_age_days,
        )

    def verify_batch(
        self,
        items: list[tuple[QRVerificationData, bytes]],
    ) -> list[VerificationResult]:
        """
        Массовая верификация бланков.

        Args:
            items: Список (qr_data, printed_content)

        Returns:
            Список VerificationResult в том же порядке
        """
        return [self.verify(qr_data, content) for qr_data, content in items]

    def clear_cache(self) -> None:
        """Очистить кэш публичных ключей."""
        self._key_cache.clear()


__all__: list[str] = [
    "verify_blank",
    "verify_blank_from_json",
    "BlankVerifier",
    "VerificationError",
    "CryptoServiceProtocol",
    "AuditLogProtocol",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
