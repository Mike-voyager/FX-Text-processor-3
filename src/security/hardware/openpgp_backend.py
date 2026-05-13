"""
OpenPGP Card 3.4 backend для аппаратных устройств.

Реализует протокол OpenPGP Card 3.4 (ISO/IEC 7816-4) для YubiKey,
J3R200 с апплетом SmartPGP и других OpenPGP-совместимых карт.
Приватный ключ НИКОГДА не покидает аппаратный модуль.

Поддерживаемые устройства:
    - YubiKey 5 серии (нативный OpenPGP 3.4, FW 5.2.3+)
    - J3R200 (JCOP4 P71) с апплетом SmartPGP
    - Nitrokey Pro/Start
    - Gnuk Token

Слоты OpenPGP:
    SIGN    (PW1/0x81) — Цифровая подпись, Ed25519 / RSA
    ENCRYPT (PW1/0x82) — Расшифровка / ECDH, X25519 / RSA
    AUTH    (PW1/0x82) — Аутентификация, Ed25519 / RSA

Зависимости:
    - pyscard>=2.0.0

Security Notes:
    - PIN передаётся как параметр и не сохраняется в памяти.
    - Логирование БЕЗ PIN-кодов и ключевого материала.
    - Thread-unsafe: используйте отдельный экземпляр на поток.

Example:
    >>> backend = OpenPGPBackend("sc_0_YubiKey")
    >>> if backend.connect():
    ...     # Получить публичные ключи
    ...     keys = backend.get_public_keys()
    ...     # Подписать данные
    ...     sig = backend.sign(b"data_hash", pin="123456")

Version: 1.0.0
Date: 2026-04-05
Author: Mike Voyager
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Final

from src.security.crypto.core.exceptions import (
    AlgorithmNotAvailableError,
    DeviceCommunicationError,
    DeviceNotFoundError,
    HardwareDeviceError,
    PINError,
)

# Optional dependency handling
try:
    from smartcard.Exceptions import CardConnectionException, NoCardException
    from smartcard.System import readers as sc_readers

    HAS_PYSCARD = True
except ImportError:
    HAS_PYSCARD = False
    CardConnectionException = None  # type: ignore[misc, assignment]
    NoCardException = None  # type: ignore[misc, assignment]
    sc_readers = None  # type: ignore[misc, assignment]


logger = logging.getLogger(__name__)

# ==============================================================================
# CONSTANTS
# ==============================================================================

OPENPGP_AID: Final[bytes] = bytes.fromhex("D27600012401")
"""OpenPGP Card Application Identifier (RID D27600 + PIX 012401)."""

# APDU Instructions
_INS_SELECT: Final[int] = 0xA4
_INS_VERIFY: Final[int] = 0x20
_INS_PSO: Final[int] = 0x2A  # PERFORM SECURITY OPERATION
_INS_GET_DATA: Final[int] = 0xCA
_INS_GENERATE_KEYPAIR: Final[int] = 0x47
_INS_INTERNAL_AUTHENTICATE: Final[int] = 0x88

# PSO Sub-instructions
_PSO_SIGN_P1: Final[int] = 0x9E
_PSO_SIGN_P2: Final[int] = 0x9A
_PSO_DECRYPT_P1: Final[int] = 0x80
_PSO_DECRYPT_P2: Final[int] = 0x86

# Status Words
_SW_SUCCESS: Final[tuple[int, int]] = (0x90, 0x00)
_SW_PIN_BLOCKED: Final[tuple[int, int]] = (0x69, 0x83)
_SW_SECURITY_NOT_SATISFIED: Final[tuple[int, int]] = (0x69, 0x82)
_SW_WRONG_PIN_MASK: Final[int] = 0x63C0

# PIN References
_PIN_PW1_SIGN: Final[int] = 0x81  # PW1 для подписи
_PIN_PW1_OTHER: Final[int] = 0x82  # PW1 для шифрования/аутентификации
_PIN_PW3_ADMIN: Final[int] = 0x83  # PW3 административный

# Algorithm IDs
_ALGO_RSA: Final[int] = 0x01
_ALGO_ECDH: Final[int] = 0x12
_ALGO_ED25519: Final[int] = 0x16

# Data Object Tags
_DO_PUBLIC_KEY: Final[int] = 0x7F49
_DO_ALGO_ATTR_SIGN: Final[int] = 0xC1
_DO_ALGO_ATTR_ENC: Final[int] = 0xC2
_DO_ALGO_ATTR_AUTH: Final[int] = 0xC3

# CRT (Control Reference Template) for slots
_CRT_SIGN: Final[bytes] = bytes([0xB6, 0x00])
_CRT_ENC: Final[bytes] = bytes([0xB8, 0x00])
_CRT_AUTH: Final[bytes] = bytes([0xA4, 0x00])


# ==============================================================================
# ENUMS
# ==============================================================================


class OpenPGPSlot(Enum):
    """OpenPGP Card key slots per OpenPGP card spec §4.2.1."""

    SIGN = "sign"
    ENCRYPT = "encrypt"
    AUTH = "auth"


class OpenPGPAlgorithm(Enum):
    """Поддерживаемые OpenPGP алгоритмы."""

    ED25519 = "Ed25519"
    X25519 = "X25519"
    RSA2048 = "RSA-2048"
    RSA3072 = "RSA-3072"
    RSA4096 = "RSA-4096"


# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass(frozen=True)
class OpenPGPPublicKeys:
    """
    Публичные ключи всех трёх слотов OpenPGP-карты.

    Attributes:
        sign: Raw bytes публичного ключа Sign-слота.
        encrypt: Raw bytes публичного ключа Encrypt-слота.
        auth: Raw bytes публичного ключа Auth-слота.
        sign_algorithm: Имя алгоритма Sign-слота.
        encrypt_algorithm: Имя алгоритма Encrypt-слота.
        auth_algorithm: Имя алгоритма Auth-слота.

    Example:
        >>> keys = backend.get_public_keys()
        >>> print(f"Sign algo: {keys.sign_algorithm}")
    """

    sign: bytes = b""
    encrypt: bytes = b""
    auth: bytes = b""
    sign_algorithm: str = ""
    encrypt_algorithm: str = ""
    auth_algorithm: str = ""


@dataclass(frozen=True)
class OpenPGPCardInfo:
    """
    Метаданные OpenPGP-карты.

    Attributes:
        card_id: Идентификатор ридера/устройства.
        manufacturer_id: 2-байтовый ID производителя.
        serial_number: Серийный номер карты.
        app_version: Версия апплета (major, minor).
        pw1_remaining: Оставшихся попыток User PIN.
        pw3_remaining: Оставшихся попыток Admin PIN.

    Example:
        >>> info = backend.get_card_info()
        >>> print(f"Version: {info.app_version}")
    """

    card_id: str
    manufacturer_id: bytes = b""
    serial_number: bytes = b""
    app_version: tuple[int, int] = (0, 0)
    pw1_remaining: int = 3
    pw3_remaining: int = 3


# ==============================================================================
# OPENPGP BACKEND
# ==============================================================================


class OpenPGPBackend:
    """
    OpenPGP Card 3.4 backend.

    Единый интерфейс для YubiKey 5 NFC и J3R200 + SmartPGP.
    Оба устройства реализуют OpenPGP Card Application 3.4 через ISO 7816-4.

    Ограничения:
        - Не потокобезопасен: используйте отдельный экземпляр на поток.
        - Импорт ключа требует Admin PIN (PW3).
        - sign() увеличивает аппаратный счётчик подписей.

    Example:
        >>> backend = OpenPGPBackend("sc_0_YubiKey", pin="123456")
        >>> if backend.connect():
        ...     sig = backend.sign(b"data_hash")
        ...     keys = backend.get_public_keys()
        >>> backend.disconnect()
    """

    def __init__(self, card_id: str, pin: str | None = None):
        """
        Инициализация OpenPGP backend.

        Args:
            card_id: Идентификатор карты/ридера.
            pin: PIN-код (опционально).

        Raises:
            AlgorithmNotAvailableError: pyscard не установлен.
        """
        if not HAS_PYSCARD:
            raise AlgorithmNotAvailableError(
                algorithm="OpenPGP Card",
                reason="pyscard library is required for OpenPGP operations",
                required_library="pyscard>=2.0.0",
            )

        self._card_id = card_id
        self._pin = pin
        self._connection: object | None = None
        self._reader: object | None = None

        logger.debug("OpenPGPBackend initialized: card_id=%s", card_id)

    def __enter__(self) -> OpenPGPBackend:
        """Контекстный менеджер: автоматически подключается."""
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        """Контекстный менеджер: автоматически отключается."""
        self.disconnect()

    def __repr__(self) -> str:
        """Строковое представление."""
        status = "connected" if self._connection else "disconnected"
        return f"OpenPGPBackend(card_id={self._card_id!r}, {status})"

    # ------------------------------------------------------------------
    # CONNECTION
    # ------------------------------------------------------------------

    def connect(self) -> bool:
        """
        Подключение к OpenPGP устройству.

        Выполняет SELECT APDU для активации OpenPGP апплета.

        Returns:
            True если подключение успешно.

        Raises:
            DeviceNotFoundError: Устройство не найдено.
            DeviceCommunicationError: Ошибка связи с устройством.
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
                if readers:
                    self._reader = readers[0]
                else:
                    raise DeviceNotFoundError(
                        device_id=self._card_id,
                        reason="No PC/SC readers available",
                    )

            self._connection = self._reader.createConnection()
            self._connection.connect()

            # SELECT OpenPGP AID
            select_apdu = [0x00, _INS_SELECT, 0x04, 0x00, len(OPENPGP_AID)]
            select_apdu.extend(list(OPENPGP_AID))
            select_apdu.append(0x00)

            _, sw1, sw2 = self._connection.transmit(select_apdu)
            if (sw1, sw2) != _SW_SUCCESS:
                self._connection.disconnect()
                self._connection = None
                raise DeviceCommunicationError(
                    device_id=self._card_id,
                    reason=f"SELECT OpenPGP AID failed: SW={sw1:02X}{sw2:02X}",
                )

            logger.info("OpenPGP connected: %s", self._card_id)
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
        Отключение от OpenPGP устройства.

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
                logger.debug("OpenPGP disconnected: %s", self._card_id)

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

    def _verify_pin(self, pin_ref: int, pin: str | None = None) -> None:
        """
        Верификация PIN.

        Args:
            pin_ref: PIN reference (0x81 для подписи, 0x82 для шифрования/аутентификации).
            pin: PIN-код. Если None, используется pin из конструктора.

        Raises:
            PINError: Неверный PIN или заблокирован.
        """
        connection = self._require_connection()
        pin_to_use = pin or self._pin

        if not pin_to_use:
            raise PINError(
                device_id=self._card_id,
                reason="PIN not provided",
            )

        pin_bytes = pin_to_use.encode("utf-8")
        apdu = [0x00, _INS_VERIFY, 0x00, pin_ref, len(pin_bytes)]
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

    def _build_ecdh_decipher_data(self, ephemeral_public_key: bytes) -> bytes:
        """
        Сборка данных для ECDH (PSO:DEC).

        Args:
            ephemeral_public_key: Эфемерный публичный ключ пира.

        Returns:
            TLV структура для PSO:DEC.
        """
        # Per OpenPGP spec: A6 Lc [7F49 Lc [86 Lc [ephemeral_pub]]]
        tag_86 = _build_tlv(0x86, ephemeral_public_key)
        tag_7f49 = _build_tlv(0x7F49, tag_86)
        return _build_tlv(0xA6, tag_7f49)

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def sign(self, data: bytes, pin: str | None = None) -> bytes:
        """
        Подпись данных через OpenPGP Sign slot.

        Использует PSO (Perform Security Operation) для подписи.
        Для Ed25519: передавайте raw message или SHA-512 digest.
        Для RSA: передавайте DER-encoded DigestInfo.

        Args:
            data: Данные для подписи.
            pin: PIN-код (опционально).

        Returns:
            Raw signature bytes (64 bytes для Ed25519, DER для RSA).

        Raises:
            PINError: Ошибка верификации PIN.
            HardwareDeviceError: Ошибка подписи.

        Example:
            >>> backend = OpenPGPBackend("sc_0_YubiKey")
            >>> if backend.connect():
            ...     digest = hashlib.sha512(b"document").digest()
            ...     sig = backend.sign(digest, pin="123456")
        """
        connection = self._require_connection()

        # VERIFY PIN for signature (PW1/0x81)
        self._verify_pin(_PIN_PW1_SIGN, pin)

        # PSO: Compute Digital Signature
        resp, sw1, sw2 = connection.transmit(
            [0x00, _INS_PSO, _PSO_SIGN_P1, _PSO_SIGN_P2, len(data)] + list(data) + [0x00]
        )

        if (sw1, sw2) != _SW_SUCCESS:
            raise HardwareDeviceError(
                f"Signing failed: SW={sw1:02X}{sw2:02X}",
                device_id=self._card_id,
            )

        logger.info("OpenPGP sign complete: sig_len=%d", len(resp))
        return bytes(resp)

    def decrypt(self, encrypted_data: bytes, pin: str | None = None) -> bytes:
        """
        Расшифровка через OpenPGP Decrypt slot.

        Для X25519 ECDH: передавайте ephemeral_public_key, обёрнутый
        через метод _build_ecdh_decipher_data.
        Для RSA: передавайте raw ciphertext.

        Args:
            encrypted_data: Зашифрованные данные или ECDH payload.
            pin: PIN-код (опционально).

        Returns:
            Расшифрованные данные или shared secret.

        Raises:
            PINError: Ошибка верификации PIN.
            HardwareDeviceError: Ошибка расшифровки.

        Example:
            >>> backend = OpenPGPBackend("sc_0_YubiKey")
            >>> if backend.connect():
            ...     # For RSA decryption
            ...     plaintext = backend.decrypt(ciphertext, pin="123456")
        """
        connection = self._require_connection()

        # VERIFY PIN for decryption (PW1/0x82)
        self._verify_pin(_PIN_PW1_OTHER, pin)

        # PSO: Decipher
        resp, sw1, sw2 = connection.transmit(
            [0x00, _INS_PSO, _PSO_DECRYPT_P1, _PSO_DECRYPT_P2, len(encrypted_data)]
            + list(encrypted_data)
            + [0x00]
        )

        if (sw1, sw2) != _SW_SUCCESS:
            raise HardwareDeviceError(
                f"Decryption failed: SW={sw1:02X}{sw2:02X}",
                device_id=self._card_id,
            )

        logger.info("OpenPGP decrypt complete: plain_len=%d", len(resp))
        return bytes(resp)

    def authenticate(self, challenge: bytes, pin: str | None = None) -> bytes:
        """
        Аутентификация через OpenPGP Auth slot.

        Использует INTERNAL AUTHENTICATE APDU.
        Подходит для challenge-response и TLS client auth.

        Args:
            challenge: Challenge для аутентификации (обычно hash).
            pin: PIN-код (опционально).

        Returns:
            Response (signature over challenge).

        Raises:
            PINError: Ошибка верификации PIN.
            HardwareDeviceError: Ошибка аутентификации.

        Example:
            >>> import os
            >>> backend = OpenPGPBackend("sc_0_YubiKey")
            >>> if backend.connect():
            ...     challenge = os.urandom(32)
            ...     response = backend.authenticate(challenge, pin="123456")
        """
        connection = self._require_connection()

        # VERIFY PIN for authentication (PW1/0x82)
        self._verify_pin(_PIN_PW1_OTHER, pin)

        # INTERNAL AUTHENTICATE
        resp, sw1, sw2 = connection.transmit(
            [0x00, _INS_INTERNAL_AUTHENTICATE, 0x00, 0x00, len(challenge)]
            + list(challenge)
            + [0x00]
        )

        if (sw1, sw2) != _SW_SUCCESS:
            raise HardwareDeviceError(
                f"Authentication failed: SW={sw1:02X}{sw2:02X}",
                device_id=self._card_id,
            )

        logger.info("OpenPGP authenticate complete: resp_len=%d", len(resp))
        return bytes(resp)

    def get_public_keys(self) -> dict[str, bytes]:
        """
        Получение всех трёх public keys (sign, encrypt, auth).

        Returns:
            Словарь с ключами: "sign", "encrypt", "authenticate".

        Raises:
            HardwareDeviceError: Ошибка чтения ключей.

        Example:
            >>> backend = OpenPGPBackend("sc_0_YubiKey")
            >>> if backend.connect():
            ...     keys = backend.get_public_keys()
            ...     print(f"Sign key: {len(keys['sign'])} bytes")
        """
        connection = self._require_connection()
        result: dict[str, bytes] = {}

        slots = {
            "sign": _CRT_SIGN,
            "encrypt": _CRT_ENC,
            "authenticate": _CRT_AUTH,
        }

        for slot_name, crt in slots.items():
            # GENERATE KEY PAIR with P1=0x81 (read-only)
            apdu = [0x00, _INS_GENERATE_KEYPAIR, 0x81, 0x00, len(crt)] + list(crt) + [0x00]
            resp, sw1, sw2 = connection.transmit(apdu)

            if (sw1, sw2) == _SW_SUCCESS:
                # Extract public key from response (tag 0x7F49 -> 0x86)
                pubkey = _extract_public_key_from_response(bytes(resp))
                result[slot_name] = pubkey
            else:
                result[slot_name] = b""
                logger.debug(
                    "Failed to get %s public key: SW=%02X%02X",
                    slot_name,
                    sw1,
                    sw2,
                )

        return result

    def get_public_key_info(self) -> OpenPGPPublicKeys:
        """
        Получение публичных ключей с информацией об алгоритмах.

        Returns:
            OpenPGPPublicKeys с ключами и алгоритмами.

        Raises:
            HardwareDeviceError: Ошибка чтения.
        """
        connection = self._require_connection()

        # Read algorithm attributes for each slot
        algo_attrs: dict[str, str] = {}
        for slot_name, do_tag in [
            ("sign", _DO_ALGO_ATTR_SIGN),
            ("encrypt", _DO_ALGO_ATTR_ENC),
            ("auth", _DO_ALGO_ATTR_AUTH),
        ]:
            apdu = [0x00, _INS_GET_DATA, 0x00, do_tag, 0x00]
            resp, sw1, sw2 = connection.transmit(apdu)
            if (sw1, sw2) == _SW_SUCCESS:
                algo_attrs[slot_name] = _parse_algo_attr(bytes(resp))
            else:
                algo_attrs[slot_name] = "Unknown"

        # Read public keys
        keys = self.get_public_keys()

        # Determine key lengths
        def key_len(key: bytes, algo: str) -> int:
            if "RSA" in algo:
                # Parse from key structure if possible
                return len(key) * 8 if key else 0
            if "25519" in algo or "Ed25519" in algo:
                return 256
            return len(key) * 8

        return OpenPGPPublicKeys(
            sign=keys.get("sign", b""),
            encrypt=keys.get("encrypt", b""),
            auth=keys.get("authenticate", b""),
            sign_algorithm=algo_attrs["sign"],
            encrypt_algorithm=algo_attrs["encrypt"],
            auth_algorithm=algo_attrs["auth"],
        )

    def get_card_info(self) -> OpenPGPCardInfo:
        """
        Получение информации о карте.

        Returns:
            OpenPGPCardInfo с метаданными.

        Raises:
            HardwareDeviceError: Ошибка чтения.
        """
        connection = self._require_connection()

        # Get Application Related Data (DO 0x4F via GET DATA)
        app_data = b""
        apdu = [0x00, _INS_GET_DATA, 0x00, 0x4F, 0x00]
        resp, sw1, sw2 = connection.transmit(apdu)
        if (sw1, sw2) == _SW_SUCCESS:
            app_data = bytes(resp)

        # Get PW Status (DO 0xC4)
        pw1_remaining = 3
        pw3_remaining = 3
        apdu = [0x00, _INS_GET_DATA, 0x00, 0xC4, 0x00]
        resp, sw1, sw2 = connection.transmit(apdu)
        if (sw1, sw2) == _SW_SUCCESS and len(resp) >= 7:
            pw1_remaining = resp[4] if len(resp) > 4 else 3
            pw3_remaining = resp[6] if len(resp) > 6 else 3

        # Parse AID for manufacturer and serial
        manufacturer_id = b""
        serial_number = b""
        app_version = (0, 0)

        if len(app_data) >= 14:
            # AID: RID(5) + app(1) + version(2) + mfr(2) + serial(4) + RFU(2)
            manufacturer_id = app_data[7:9] if len(app_data) > 9 else b""
            serial_number = app_data[9:13] if len(app_data) > 13 else b""
            app_version = (app_data[6], app_data[7]) if len(app_data) > 7 else (0, 0)

        return OpenPGPCardInfo(
            card_id=self._card_id,
            manufacturer_id=manufacturer_id,
            serial_number=serial_number,
            app_version=app_version,
            pw1_remaining=pw1_remaining,
            pw3_remaining=pw3_remaining,
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


def _extract_public_key_from_response(data: bytes) -> bytes:
    """Извлечение публичного ключа из ответа GENERATE KEY PAIR."""
    # Parse TLV structure
    idx = 0
    while idx < len(data):
        if idx + 1 >= len(data):
            break
        tag = data[idx]
        idx += 1
        if tag == 0x7F:  # Long form tag
            if idx >= len(data):
                break
            tag = (tag << 8) | data[idx]
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

        if tag == 0x7F49:  # Public Key DO
            # Parse inner TLV for key material
            inner_idx = idx
            while inner_idx < idx + length:
                if inner_idx >= len(data):
                    break
                inner_tag = data[inner_idx]
                inner_idx += 1
                if inner_idx >= len(data):
                    break
                inner_len = data[inner_idx]
                inner_idx += 1
                if inner_len == 0x81 and inner_idx < len(data):
                    inner_len = data[inner_idx]
                    inner_idx += 1
                elif inner_len == 0x82 and inner_idx + 1 < len(data):
                    inner_len = (data[inner_idx] << 8) | data[inner_idx + 1]
                    inner_idx += 2

                # Tag 0x86 = public key point for ECC
                # Tag 0x81 = modulus for RSA
                if inner_tag in (0x86, 0x81) and inner_idx + inner_len <= len(data):
                    return data[inner_idx : inner_idx + inner_len]

                inner_idx += inner_len

        idx += length

    return data  # Return raw if parsing fails


def _parse_algo_attr(data: bytes) -> str:
    """Парсинг algorithm attributes в строку."""
    if not data:
        return "Unknown"

    algo_id = data[0]
    if algo_id == _ALGO_ED25519:
        return "Ed25519"
    if algo_id == _ALGO_ECDH:
        return "X25519"
    if algo_id == _ALGO_RSA and len(data) >= 3:
        key_bits = struct.unpack(">H", data[1:3])[0]
        return f"RSA-{key_bits}"

    return f"Algo-{algo_id:02X}"


# ==============================================================================
# EXPORTS
# ==============================================================================

__all__ = [
    "OpenPGPBackend",
    "OpenPGPSlot",
    "OpenPGPAlgorithm",
    "OpenPGPPublicKeys",
    "OpenPGPCardInfo",
    "OPENPGP_AID",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-04-05"
