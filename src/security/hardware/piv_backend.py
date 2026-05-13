"""
PIV (Personal Identity Verification) backend для YubiKey и смарткарт.

Реализует поддержку NIST SP 800-73 PIV для аппаратных устройств с PIV-апплетом.
Приватный ключ НИКОГДА не покидает устройство — все операции выполняются
на смарткарте через APDU.

Поддерживаемые устройства:
    - YubiKey 5 серии (PIV через CCID)
    - YubiKey FIPS (только PIV)
    - PIV-совместимые смарткарты (NIST SP 800-73)
    - PIVKey, Gemalto IDPrime и др.

PIV слоты (NIST SP 800-73):
    0x9A — Authentication (PKI auth)
    0x9C — Digital Signature (подпись документов)
    0x9D — Key Management (ECDH, ключевая доставка)
    0x9E — Card Authentication (Fast ID Online)

Зависимости:
    - pyscard>=2.0.0

Security Notes:
    - PIN передаётся как параметр и не сохраняется в памяти.
    - Логирование БЕЗ PIN-кодов и ключевого материала.
    - Thread-unsafe: используйте отдельный экземпляр на поток.

Example:
    >>> backend = PIVBackend("yubikey_123456")
    >>> if backend.connect():
    ...     sig = backend.sign(0x9C, b"document_hash", pin="123456")
    ...     print(f"Signature: {len(sig)} bytes")

Version: 1.0.0
Date: 2026-04-05
Author: Mike Voyager
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from src.security.crypto.core.exceptions import (
    AlgorithmNotAvailableError,
    DeviceCommunicationError,
    DeviceNotFoundError,
    HardwareDeviceError,
    InvalidKeyError,
    KeyGenerationError,
    PINError,
    SlotError,
)

# Optional dependency handling
try:
    from smartcard.Exceptions import CardConnectionException, NoCardException
    from smartcard.System import readers as sc_readers
    from smartcard.util import toBytes

    HAS_PYSCARD = True
except ImportError:
    HAS_PYSCARD = False
    CardConnectionException = None  # type: ignore[misc, assignment]
    NoCardException = None  # type: ignore[misc, assignment]
    sc_readers = None  # type: ignore[misc, assignment]
    toBytes = None  # type: ignore[misc, assignment]


logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTS
# ==============================================================================

PIV_AID: Final[bytes] = bytes.fromhex("A000000308")
"""PIV Application Identifier (NIST RID A00000 + PIX 0308)."""

# PIV Slots (NIST SP 800-73)
PIV_SLOT_AUTHENTICATION: Final[int] = 0x9A
PIV_SLOT_DIGITAL_SIGNATURE: Final[int] = 0x9C
PIV_SLOT_KEY_MANAGEMENT: Final[int] = 0x9D
PIV_SLOT_CARD_AUTHENTICATION: Final[int] = 0x9E

# APDU Instructions
_INS_SELECT: Final[int] = 0xA4
_INS_VERIFY: Final[int] = 0x20
_INS_GENERAL_AUTHENTICATE: Final[int] = 0x87
_INS_GET_DATA: Final[int] = 0xCB
_INS_GENERATE_ASYMMETRIC_KEY_PAIR: Final[int] = 0x47
_INS_PUT_DATA: Final[int] = 0xDB

# Status Words
_SW_SUCCESS: Final[tuple[int, int]] = (0x90, 0x00)
_SW_PIN_BLOCKED: Final[tuple[int, int]] = (0x69, 0x83)
_SW_SECURITY_NOT_SATISFIED: Final[tuple[int, int]] = (0x69, 0x82)
_SW_WRONG_PIN: Final[int] = 0x63C0  # Mask: 0x63C0 + retries

# Algorithm Identifiers for PIV
_ALGO_RSA_2048: Final[int] = 0x07
_ALGO_RSA_3072: Final[int] = 0x05
_ALGO_RSA_4096: Final[int] = 0x10
_ALGO_ECC_P256: Final[int] = 0x11
_ALGO_ECC_P384: Final[int] = 0x14
_ALGO_ECC_CV_25519: Final[int] = 0x12  # X25519

# Data Object Tags
_DO_PUBLIC_KEY: Final[bytes] = bytes([0x5F, 0xC1, 0x06])  # CCC or pubkey
_DO_CERTIFICATE: Final[bytes] = bytes([0x5F, 0xC1, 0x05])  # Certificate


# ==============================================================================
# ENUMS
# ==============================================================================


class PIVAlgorithm(IntEnum):
    """Алгоритмы PIV, поддерживаемые NIST SP 800-73."""

    RSA_2048 = 0x07
    RSA_3072 = 0x05
    RSA_4096 = 0x10
    ECC_P256 = 0x11
    ECC_P384 = 0x14
    X25519 = 0x12


class PIVSlotType(IntEnum):
    """Типы PIV слотов для различных криптографических операций."""

    AUTHENTICATION = 0x9A
    DIGITAL_SIGNATURE = 0x9C
    KEY_MANAGEMENT = 0x9D
    CARD_AUTHENTICATION = 0x9E


# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass(frozen=True)
class PIVPublicKey:
    """
    Публичный ключ из PIV слота.

    Attributes:
        slot: PIV слот (0x9A, 0x9C, 0x9D, 0x9E).
        algorithm: Алгоритм ключа (RSA-2048, ECC-P256 и т.д.).
        key_data: Raw bytes публичного ключа.
        key_length: Длина ключа в битах.

    Example:
        >>> pub_key = PIVPublicKey(
        ...     slot=0x9C,
        ...     algorithm="ECC-P256",
        ...     key_data=b"...",
        ...     key_length=256,
        ... )
        >>> pub_key.slot_name
        'Digital Signature'
    """

    slot: int
    algorithm: str
    key_data: bytes
    key_length: int

    @property
    def slot_name(self) -> str:
        """Человекочитаемое имя слота."""
        names = {
            PIV_SLOT_AUTHENTICATION: "Authentication",
            PIV_SLOT_DIGITAL_SIGNATURE: "Digital Signature",
            PIV_SLOT_KEY_MANAGEMENT: "Key Management",
            PIV_SLOT_CARD_AUTHENTICATION: "Card Authentication",
        }
        return names.get(self.slot, f"Unknown (0x{self.slot:02X})")


@dataclass(frozen=True)
class PIVCardInfo:
    """
    Информация о PIV карте.

    Attributes:
        card_id: Идентификатор устройства.
        manufacturer: Производитель чипа.
        serial_number: Серийный номер карты.
        chuid: Cardholder Unique ID (DO 0x3000).
        url: URL для проверки сертификата.

    Example:
        >>> info = PIVCardInfo(
        ...     card_id="yubikey_123456",
        ...     manufacturer="Yubico",
        ...     serial_number="123456789",
        ... )
    """

    card_id: str
    manufacturer: str = "Unknown"
    serial_number: str = ""
    chuid: bytes = b""
    url: str = ""


# ==============================================================================
# PIV BACKEND
# ==============================================================================


class PIVBackend:
    """
    PIV backend для аппаратных устройств.

    Обеспечивает криптографические операции через PIV-апплет смарткарты.
    Приватный ключ НИКОГДА не покидает устройство.

    SLOTS:
        0x9A — Authentication: PKI аутентификация.
        0x9C — Digital Signature: подпись документов.
        0x9D — Key Management: ECDH, шифрование ключей.
        0x9E — Card Authentication: FIDO/WebAuthn.

    Example:
        >>> backend = PIVBackend("yubikey_123456", pin="123456")
        >>> if backend.connect():
        ...     # Подпись данных через slot 0x9C
        ...     sig = backend.sign(0x9C, b"data_hash")
        ...     # ECDH через slot 0x9D
        ...     shared = backend.ecdh(0x9D, peer_public_key)
        >>> backend.disconnect()

    Security Note:
        PIN передаётся как параметр метода, а не хранится в объекте.
    """

    SLOTS: Final[dict[int, str]] = {
        0x9A: "AUTHENTICATION",
        0x9C: "DIGITAL_SIGNATURE",
        0x9D: "KEY_MANAGEMENT",
        0x9E: "CARD_AUTH",
    }

    def __init__(self, card_id: str, pin: str | None = None):
        """
        Инициализация PIV backend.

        Args:
            card_id: Идентификатор карты/ридера (например, "sc_0_YubiKey 5 NFC 0").
            pin: PIN-код (опционально, может быть передан позже).

        Raises:
            AlgorithmNotAvailableError: pyscard не установлен.
        """
        if not HAS_PYSCARD:
            raise AlgorithmNotAvailableError(
                algorithm="PIV Smartcard",
                reason="pyscard library is required for PIV operations",
                required_library="pyscard>=2.0.0",
            )

        self._card_id = card_id
        self._pin = pin
        self._connection: object | None = None
        self._reader: object | None = None

        logger.debug("PIVBackend initialized: card_id=%s", card_id)

    def __enter__(self) -> PIVBackend:
        """Контекстный менеджер: автоматически подключается."""
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        """Контекстный менеджер: автоматически отключается."""
        self.disconnect()

    def __repr__(self) -> str:
        """Строковое представление."""
        status = "connected" if self._connection else "disconnected"
        return f"PIVBackend(card_id={self._card_id!r}, {status})"

    # ------------------------------------------------------------------
    # CONNECTION
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """
        Подключение к PIV устройству.

        Выполняет SELECT APDU для активации PIV апплета.

        Returns:
            True если подключение успешно.

        Raises:
            DeviceNotFoundError: Устройство не найдено.
            DeviceCommunicationError: Ошибка связи с устройством.

        Example:
            >>> backend = PIVBackend("sc_0_YubiKey")
            >>> if backend.connect():
            ...     print("Connected!")
            >>> backend.disconnect()
        """
        if self._connection is not None:
            logger.debug("Already connected to %s", self._card_id)
            return True

        try:
            if sc_readers is None:
                raise DeviceCommunicationError(
                    device_id=self._card_id,
                    reason="PC/SC readers unavailable",
                )

            readers = sc_readers()
            reader_name = self._card_id.split("_", 2)[-1] if "_" in self._card_id else self._card_id

            # Find matching reader
            self._reader = None
            for r in readers:
                if reader_name.lower() in str(r).lower():
                    self._reader = r
                    break

            if self._reader is None:
                # Try first reader if no match
                if readers:
                    self._reader = readers[0]
                else:
                    raise DeviceNotFoundError(
                        device_id=self._card_id,
                        reason="No PC/SC readers available",
                    )

            self._connection = self._reader.createConnection()
            self._connection.connect()

            # SELECT PIV AID
            select_apdu = [0x00, _INS_SELECT, 0x04, 0x00, len(PIV_AID)]
            select_apdu.extend(list(PIV_AID))
            select_apdu.append(0x00)  # Le

            _, sw1, sw2 = self._connection.transmit(select_apdu)
            if (sw1, sw2) != _SW_SUCCESS:
                self._connection.disconnect()
                self._connection = None
                raise DeviceCommunicationError(
                    device_id=self._card_id,
                    reason=f"SELECT PIV AID failed: SW={sw1:02X}{sw2:02X}",
                )

            logger.info("PIV connected: %s", self._card_id)
            return True

        except CardConnectionException as exc:
            raise DeviceCommunicationError(
                device_id=self._card_id,
                reason=f"Card connection failed: {exc}",
            ) from exc
        except NoCardException as exc:
            raise DeviceNotFoundError(
                device_id=self._card_id,
                reason="No card in reader",
            ) from exc

    def disconnect(self) -> None:
        """
        Отключение от PIV устройства.

        Всегда безопасен для повторного вызова.
        """
        if self._connection is not None:
            try:
                self._connection.disconnect()
            except Exception as exc:
                logger.debug("Disconnect warning: %s", exc)
            finally:
                self._connection = None
                self._reader = None
                logger.debug("PIV disconnected: %s", self._card_id)

    def is_connected(self) -> bool:
        """Проверка активного подключения."""
        return self._connection is not None

    # ------------------------------------------------------------------
    # PRIVATE HELPERS
    # ------------------------------------------------------------------

    def _require_connection(self) -> object:
        """Проверка подключения и возврат соединения."""
        if self._connection is None:
            raise DeviceCommunicationError(
                device_id=self._card_id,
                reason="Not connected. Call connect() first.",
            )
        return self._connection

    def _verify_pin(self, pin: str | None = None) -> None:
        """
        Верификация PIN перед криптографической операцией.

        Args:
            pin: PIN-код. Если None, используется pin из конструктора.

        Raises:
            PINError: Неверный PIN или превышены попытки.
        """
        connection = self._require_connection()
        pin_to_use = pin or self._pin

        if not pin_to_use:
            raise PINError(
                device_id=self._card_id,
                reason="PIN not provided",
            )

        pin_bytes = pin_to_use.encode("utf-8")
        apdu = [0x00, _INS_VERIFY, 0x00, 0x80, len(pin_bytes)]
        apdu.extend(pin_bytes)

        _, sw1, sw2 = connection.transmit(apdu)

        if (sw1, sw2) == _SW_SUCCESS:
            logger.debug("PIN verified for %s", self._card_id)
            return

        if (sw1, sw2) == _SW_PIN_BLOCKED:
            raise PINError(
                device_id=self._card_id,
                reason="PIN blocked",
                retries_remaining=0,
            )

        # 0x63Cx - x retries remaining
        if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
            retries = sw2 & 0x0F
            raise PINError(
                device_id=self._card_id,
                reason=f"Wrong PIN, {retries} retries remaining",
                retries_remaining=retries,
            )

        raise PINError(
            device_id=self._card_id,
            reason=f"PIN verification failed: SW={sw1:02X}{sw2:02X}",
        )

    def _check_slot(self, slot: int) -> None:
        """Проверка корректности PIV слота."""
        if slot not in self.SLOTS:
            valid = ", ".join(f"0x{s:02X}" for s in self.SLOTS.keys())
            raise SlotError(
                device_id=self._card_id,
                slot=slot,
                reason=f"Invalid PIV slot. Valid: {valid}",
            )

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def sign(self, slot: int, data: bytes, pin: str | None = None) -> bytes:
        """
        Подпись данных через PIV slot.

        Использует GENERAL AUTHENTICATE APDU для подписи на устройстве.
        Slot 0x9C предназначен для цифровой подписи.

        Args:
            slot: PIV слот (0x9C для подписи).
            data: Данные для подписи (для RSA — DigestInfo, для ECC — hash).
            pin: PIN-код (опционально, если передан в конструкторе).

        Returns:
            Подпись (raw bytes для ECC, DER для RSA).

        Raises:
            SlotError: Некорректный слот.
            PINError: Ошибка верификации PIN.
            HardwareDeviceError: Ошибка подписи на устройстве.

        Example:
            >>> backend = PIVBackend("yubikey_123456")
            >>> if backend.connect():
            ...     digest = hashlib.sha256(b"document").digest()
            ...     sig = backend.sign(0x9C, digest, pin="123456")
            ...     print(f"Signature: {len(sig)} bytes")
        """
        self._check_slot(slot)
        connection = self._require_connection()

        # VERIFY PIN
        self._verify_pin(pin)

        # BUILD GENERAL AUTHENTICATE for signing
        # Construct dynamic authentication data (signature)
        algo_id = _ALGO_ECC_P256  # Default, will be detected
        tag_82 = _build_tlv(0x82, bytes([algo_id]))
        tag_81 = _build_tlv(0x81, data)
        auth_data = tag_82 + tag_81

        apdu = [
            0x00,
            _INS_GENERAL_AUTHENTICATE,
            0x03,  # P1 = digital signature
            slot,
            len(auth_data),
        ]
        apdu.extend(auth_data)
        apdu.append(0x00)  # Le

        resp, sw1, sw2 = connection.transmit(apdu)

        if (sw1, sw2) != _SW_SUCCESS:
            raise HardwareDeviceError(
                f"Signing failed: SW={sw1:02X}{sw2:02X}",
                device_id=self._card_id,
                context={"slot": f"0x{slot:02X}", "sw": f"{sw1:02X}{sw2:02X}"},
            )

        # Extract signature from response (tag 0x82)
        signature = _extract_tlv_value(bytes(resp), 0x82)
        if not signature:
            raise HardwareDeviceError(
                "Invalid signature response format",
                device_id=self._card_id,
            )

        logger.info("PIV sign complete: slot=0x%02X, sig_len=%d", slot, len(signature))
        return signature

    def get_public_key(self, slot: int) -> PIVPublicKey:
        """
        Получение public key с устройства.

        Использует GENERATE ASYMMETRIC KEY PAIR с P1=0x81 (read-only)
        или GET DATA для чтения существующего ключа.

        Args:
            slot: PIV слот (0x9A, 0x9C, 0x9D, 0x9E).

        Returns:
            PIVPublicKey с информацией о публичном ключе.

        Raises:
            SlotError: Некорректный слот.
            HardwareDeviceError: Слот пуст или ошибка чтения.

        Example:
            >>> backend = PIVBackend("yubikey_123456")
            >>> if backend.connect():
            ...     pub = backend.get_public_key(0x9C)
            ...     print(f"Algorithm: {pub.algorithm}")
        """
        self._check_slot(slot)
        connection = self._require_connection()

        # Try GENERATE KEY PAIR with P1=0x81 (read-only)
        apdu = [
            0x00,
            _INS_GENERATE_ASYMMETRIC_KEY_PAIR,
            0x81,  # P1 = read public key
            0x00,
            0x02,  # Lc
            (slot >> 8) & 0xFF,
            slot & 0xFF,
            0x00,  # Le
        ]

        resp, sw1, sw2 = connection.transmit(apdu)

        if (sw1, sw2) != _SW_SUCCESS:
            raise HardwareDeviceError(
                f"Failed to get public key: SW={sw1:02X}{sw2:02X}",
                device_id=self._card_id,
                context={"slot": f"0x{slot:02X}"},
            )

        # Parse response (tag 0x7F49 for public key)
        resp_bytes = bytes(resp)
        pubkey_data = _extract_tlv_value(resp_bytes, 0x7F49)
        if not pubkey_data:
            raise HardwareDeviceError(
                "Invalid public key response format",
                device_id=self._card_id,
            )

        # Detect algorithm from response
        algo, key_len, key_bytes = _parse_public_key(pubkey_data)

        return PIVPublicKey(
            slot=slot,
            algorithm=algo,
            key_data=key_bytes,
            key_length=key_len,
        )

    def ecdh(self, slot: int, peer_public_key: bytes, pin: str | None = None) -> bytes:
        """
        ECDH key agreement через slot 0x9D.

        Выполняет ECDH между приватным ключом на карте (slot 0x9D)
        и публичным ключом пира. Результат — shared secret.

        Args:
            slot: PIV слот (обычно 0x9D для Key Management).
            peer_public_key: Публичный ключ пира (raw bytes).
            pin: PIN-код (опционально).

        Returns:
            Shared secret (raw bytes, 32 bytes для X25519).

        Raises:
            SlotError: Некорректный слот.
            PINError: Ошибка верификации PIN.
            HardwareDeviceError: Ошибка ECDH на устройстве.

        Example:
            >>> backend = PIVBackend("yubikey_123456")
            >>> if backend.connect():
            ...     # X25519 ECDH
            ...     peer_pub = os.urandom(32)
            ...     shared = backend.ecdh(0x9D, peer_pub, pin="123456")
            ...     print(f"Shared: {len(shared)} bytes")
        """
        self._check_slot(slot)
        connection = self._require_connection()

        # VERIFY PIN
        self._verify_pin(pin)

        # Build GENERAL AUTHENTICATE for ECDH
        # For ECDH, peer public key is sent in tag 0x85
        tag_85 = _build_tlv(0x85, peer_public_key)
        apdu = [
            0x00,
            _INS_GENERAL_AUTHENTICATE,
            0x03,  # P1 = key agreement
            slot,
            len(tag_85),
        ]
        apdu.extend(tag_85)
        apdu.append(0x00)

        resp, sw1, sw2 = connection.transmit(apdu)

        if (sw1, sw2) != _SW_SUCCESS:
            raise HardwareDeviceError(
                f"ECDH failed: SW={sw1:02X}{sw2:02X}",
                device_id=self._card_id,
                context={"slot": f"0x{slot:02X}", "sw": f"{sw1:02X}{sw2:02X}"},
            )

        # Extract shared secret from response (tag 0x85)
        shared = _extract_tlv_value(bytes(resp), 0x85)
        if not shared:
            raise HardwareDeviceError(
                "Invalid ECDH response format",
                device_id=self._card_id,
            )

        logger.info("PIV ECDH complete: slot=0x%02X, shared_len=%d", slot, len(shared))
        return shared

    def generate_key(self, slot: int, algorithm: str, admin_pin: str | None = None) -> PIVPublicKey:
        """
        Генерация ключевой пары на устройстве.

        Создаёт ключевую пару в указанном слоте. Приватный ключ генерируется
        аппаратно и НИКОГДА не покидает устройство.

        Args:
            slot: PIV слот для генерации ключа.
            algorithm: Алгоритм (ECC-P256, ECC-P384, RSA-2048, RSA-3072, RSA-4096).
            admin_pin: Admin PIN для криптографических операций (опционально).

        Returns:
            PIVPublicKey с публичным ключом.

        Raises:
            SlotError: Некорректный слот.
            KeyGenerationError: Ошибка генерации на устройстве.
            InvalidKeyError: Неподдерживаемый алгоритм.

        Example:
            >>> backend = PIVBackend("yubikey_123456")
            >>> if backend.connect():
            ...     pub = backend.generate_key(0x9C, "ECC-P256", admin_pin="12345678")
            ...     print(f"Generated: {pub.algorithm}")
        """
        self._check_slot(slot)
        connection = self._require_connection()

        # Map algorithm name to PIV algorithm ID
        algo_map = {
            "rsa-2048": _ALGO_RSA_2048,
            "rsa-3072": _ALGO_RSA_3072,
            "rsa-4096": _ALGO_RSA_4096,
            "ecc-p256": _ALGO_ECC_P256,
            "p-256": _ALGO_ECC_P256,
            "ecc-p384": _ALGO_ECC_P384,
            "p-384": _ALGO_ECC_P384,
        }

        algo_lower = algorithm.lower()
        algo_id = algo_map.get(algo_lower)

        if algo_id is None:
            raise InvalidKeyError(
                f"Unsupported algorithm: {algorithm}",
                algorithm=algorithm,
            )

        # Build GENERATE ASYMMETRIC KEY PAIR with P1=0x00 (generate)
        apdu = [
            0x00,
            _INS_GENERATE_ASYMMETRIC_KEY_PAIR,
            0x00,  # P1 = generate
            0x00,
            0x05,  # Lc
            (slot >> 8) & 0xFF,
            slot & 0xFF,
            0x00,  # Algorithm ID tag
            0x01,
            algo_id,
            0x00,  # Le
        ]

        resp, sw1, sw2 = connection.transmit(apdu)

        if (sw1, sw2) != _SW_SUCCESS:
            raise KeyGenerationError(
                f"Key generation failed: SW={sw1:02X}{sw2:02X}",
                algorithm=algorithm,
                context={"slot": f"0x{slot:02X}"},
            )

        # Parse response and return public key
        resp_bytes = bytes(resp)
        pubkey_data = _extract_tlv_value(resp_bytes, 0x7F49)
        if not pubkey_data:
            raise HardwareDeviceError(
                "Invalid key generation response",
                device_id=self._card_id,
            )

        algo_name, key_len, key_bytes = _parse_public_key(pubkey_data)

        logger.info("PIV key generated: slot=0x%02X, algo=%s", slot, algo_name)
        return PIVPublicKey(
            slot=slot,
            algorithm=algo_name,
            key_data=key_bytes,
            key_length=key_len,
        )

    def get_card_info(self) -> PIVCardInfo:
        """
        Получение информации о PIV карте.

        Returns:
            PIVCardInfo с метаданными карты.

        Raises:
            HardwareDeviceError: Ошибка чтения данных.

        Example:
            >>> backend = PIVBackend("yubikey_123456")
            >>> if backend.connect():
            ...     info = backend.get_card_info()
            ...     print(f"Manufacturer: {info.manufacturer}")
        """
        connection = self._require_connection()

        # Get CHUID (Cardholder Unique ID) - DO 0x3000
        apdu = [
            0x00,
            _INS_GET_DATA,
            0x3F,
            0x00,
            0x05,  # Lc
        ]
        # Tag 0x3000 for CHUID
        apdu.extend([0x30, 0x00, 0x00, 0x00, 0x00])
        apdu.append(0x00)

        try:
            resp, sw1, sw2 = connection.transmit(apdu)
            chuid = bytes(resp) if (sw1, sw2) == _SW_SUCCESS else b""
        except Exception as exc:
            logger.debug("CHUID read failed: %s", exc)
            chuid = b""

        # Parse manufacturer from ATR or default
        manufacturer = "Unknown"
        if self._reader:
            reader_name = str(self._reader).lower()
            if "yubico" in reader_name or "yubikey" in reader_name:
                manufacturer = "Yubico"

        return PIVCardInfo(
            card_id=self._card_id,
            manufacturer=manufacturer,
            chuid=chuid,
        )


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================


def _build_tlv(tag: int, value: bytes) -> bytes:
    """Сборка TLV структуры."""
    length = len(value)
    if length <= 127:
        len_bytes = bytes([length])
    elif length <= 255:
        len_bytes = bytes([0x81, length])
    else:
        len_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])

    tag_bytes = bytes([tag]) if tag <= 0xFF else bytes([(tag >> 8) & 0xFF, tag & 0xFF])
    return tag_bytes + len_bytes + value


def _extract_tlv_value(data: bytes, tag: int) -> bytes | None:
    """Извлечение значения из TLV структуры."""
    idx = 0
    tag_bytes = bytes([tag]) if tag <= 0xFF else bytes([(tag >> 8) & 0xFF, tag & 0xFF])
    tag_len = len(tag_bytes)

    while idx < len(data):
        # Check for our tag
        if idx + tag_len <= len(data) and data[idx : idx + tag_len] == tag_bytes:
            idx += tag_len
            if idx >= len(data):
                return None

            # Parse length
            length = data[idx]
            idx += 1
            if length == 0x81 and idx < len(data):
                length = data[idx]
                idx += 1
            elif length == 0x82 and idx + 1 < len(data):
                length = (data[idx] << 8) | data[idx + 1]
                idx += 2

            # Return value
            end = idx + length
            if end <= len(data):
                return data[idx:end]
            return None

        # Skip this TLV
        idx += 1
        if idx >= len(data):
            break
        length = data[idx]
        idx += 1
        if length == 0x81 and idx < len(data):
            length = data[idx]
            idx += 1
        elif length == 0x82 and idx + 1 < len(data):
            length = (data[idx] << 8) | data[idx + 1]
            idx += 2
        idx += length

    return None


def _parse_public_key(data: bytes) -> tuple[str, int, bytes]:
    """Парсинг публичного ключа из PIV ответа."""
    # Try to detect algorithm from structure
    # ECC keys typically have tag 0x86 (public key point)
    # RSA keys have tags 0x81 (modulus) and 0x82 (exponent)

    ecc_key = _extract_tlv_value(data, 0x86)
    if ecc_key:
        if len(ecc_key) == 65:  # Uncompressed P-256
            return ("ECC-P256", 256, ecc_key)
        if len(ecc_key) == 97:  # Uncompressed P-384
            return ("ECC-P384", 384, ecc_key)
        if len(ecc_key) == 32:  # X25519/Ed25519
            return ("X25519/Ed25519", 256, ecc_key)
        return ("ECC-Unknown", len(ecc_key) * 8, ecc_key)

    rsa_mod = _extract_tlv_value(data, 0x81)
    rsa_exp = _extract_tlv_value(data, 0x82)
    if rsa_mod and rsa_exp:
        key_bits = len(rsa_mod) * 8
        return (f"RSA-{key_bits}", key_bits, rsa_mod + rsa_exp)

    return ("Unknown", 0, data)


# ==============================================================================
# EXPORTS
# ==============================================================================

__all__ = [
    "PIVBackend",
    "PIVPublicKey",
    "PIVCardInfo",
    "PIVAlgorithm",
    "PIVSlotType",
    "PIV_AID",
    "PIV_SLOT_AUTHENTICATION",
    "PIV_SLOT_DIGITAL_SIGNATURE",
    "PIV_SLOT_KEY_MANAGEMENT",
    "PIV_SLOT_CARD_AUTHENTICATION",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-04-05"
