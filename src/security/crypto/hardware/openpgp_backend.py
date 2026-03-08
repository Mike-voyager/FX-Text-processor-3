"""
OpenPGP Card 3.4 бэкенд для аппаратных криптографических устройств.

Реализует протокол OpenPGP Card 3.4 (ISO/IEC 7816-4) для YubiKey 5 NFC
и J3R200 с апплетом SmartPGP через raw APDU (pyscard). Единый интерфейс
для обоих устройств — приватный ключ НИКОГДА не покидает аппаратный модуль.

Поддерживаемые устройства:
- YubiKey 5 NFC (нативный OpenPGP 3.4, FW 5.2.3+)
- J3R200 (JCOP4 P71) с апплетом SmartPGP

Слоты OpenPGP:
- SIGN    (PW1/0x81) — Цифровая подпись, Ed25519 / RSA
- ENCRYPT (PW1/0x82) — Расшифровка / ECDH, X25519 / RSA
- AUTH    (PW1/0x82) — Аутентификация, Ed25519 / RSA

Зависимости: только pyscard>=2.0.0 (уже в проекте).

Security Notes:
- PIN передаётся как параметр и не сохраняется в памяти дольше одного вызова.
- Логирование без PIN-кодов и ключевого материала.
- Не потокобезопасен по умолчанию — используйте отдельный экземпляр на поток.

Example:
    >>> backend = OpenPGPBackend()
    >>> keys = backend.get_public_keys("sc_0_YubiKey 5 NFC 0")
    >>> import hashlib
    >>> digest = hashlib.sha512(b"document").digest()
    >>> sig = backend.sign("sc_0_YubiKey 5 NFC 0", digest, pin="123456")
    >>> len(sig)
    64

Version: 1.0.0
Date: 2026-03-02
Author: Mike Voyager
Priority: Phase 2 (Hardware Crypto Roadmap v1.0)
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
    HardwareDeviceError,
    InvalidKeyError,
    KeyGenerationError,
    PINError,
)
from src.security.crypto.hardware.apdu_transport import ApduTransport

logger = logging.getLogger(__name__)

# ==============================================================================
# AID
# ==============================================================================

OPENPGP_AID: Final[bytes] = bytes.fromhex("D276000124")
"""OpenPGP Card Application Identifier (RID D27600 + PIX 0124)."""

# ==============================================================================
# DATA OBJECT TAGS (OpenPGP card spec §4.4)
# ==============================================================================

_DO_ALGO_ATTR_SIGN: Final[int] = 0xC1
_DO_ALGO_ATTR_ENC: Final[int] = 0xC2
_DO_ALGO_ATTR_AUTH: Final[int] = 0xC3

# ==============================================================================
# CONTROL REFERENCE TEMPLATES (CRT) FOR KEY SLOTS
# ==============================================================================

_CRT_SIGN: Final[bytes] = bytes([0xB6, 0x00])
_CRT_ENC: Final[bytes] = bytes([0xB8, 0x00])
_CRT_AUTH: Final[bytes] = bytes([0xA4, 0x00])

# ==============================================================================
# APDU INSTRUCTION BYTES
# ==============================================================================

_INS_VERIFY: Final[int] = 0x20
_INS_PSO: Final[int] = 0x2A          # PERFORM SECURITY OPERATION
_INS_INT_AUTH: Final[int] = 0x88     # INTERNAL AUTHENTICATE
_INS_GEN_KEYPAIR: Final[int] = 0x47  # GENERATE ASYMMETRIC KEY PAIR
_INS_PUT_DATA_EVEN: Final[int] = 0xDA  # PUT DATA (even INS, for DOs ≤ 0xFF)
_INS_PUT_DATA_ODD: Final[int] = 0xDB   # PUT DATA (odd INS, for private keys / 4D)
_INS_GET_DATA: Final[int] = 0xCA    # GET DATA

# PSO P1/P2 combinations
_PSO_SIGN_P1: Final[int] = 0x9E
_PSO_SIGN_P2: Final[int] = 0x9A
_PSO_DEC_P1: Final[int] = 0x80
_PSO_DEC_P2: Final[int] = 0x86

# ==============================================================================
# STATUS WORDS
# ==============================================================================

_SW_SUCCESS: Final[int] = 0x9000
_SW_PIN_WRONG_MASK: Final[int] = 0x63C0   # 0x63Cx → x retries left
_SW_PIN_BLOCKED: Final[int] = 0x6983
_SW_SECURITY_NOT_SATISFIED: Final[int] = 0x6982
_SW_INCORRECT_DATA: Final[int] = 0x6A80

# ==============================================================================
# PIN REFERENCES
# ==============================================================================

_PIN_USER_SIGN: Final[int] = 0x81    # PW1 — unlocks Sign slot only
_PIN_USER_OTHER: Final[int] = 0x82   # PW1 mode 2 — unlocks Enc/Auth slots
_PIN_ADMIN: Final[int] = 0x83        # PW3 — administrative operations

# ==============================================================================
# ALGORITHM IDS (OpenPGP card spec §4.3.3.6)
# ==============================================================================

_ALGO_RSA: Final[int] = 0x01
_ALGO_ECDH: Final[int] = 0x12   # X25519 / ECDH
_ALGO_ED25519: Final[int] = 0x16

# Algorithm OIDs (DER-encoded OID body as per OpenPGP spec)
_OID_ED25519: Final[bytes] = bytes.fromhex("2B06010401DA470F01")
_OID_X25519: Final[bytes] = bytes.fromhex("2B060104019755010501")

# ==============================================================================
# ENUMS
# ==============================================================================


class OpenPGPSlot(Enum):
    """OpenPGP card key slots per the OpenPGP card spec §4.2.1."""

    SIGN = "sign"
    ENCRYPT = "encrypt"
    AUTH = "auth"


class OpenPGPAlgorithm(Enum):
    """Supported on-card algorithms for OpenPGP key operations."""

    ED25519 = "Ed25519"
    X25519 = "X25519"
    RSA2048 = "RSA-2048"
    RSA3072 = "RSA-3072"
    RSA4096 = "RSA-4096"


_SLOT_CRT: dict[OpenPGPSlot, bytes] = {
    OpenPGPSlot.SIGN: _CRT_SIGN,
    OpenPGPSlot.ENCRYPT: _CRT_ENC,
    OpenPGPSlot.AUTH: _CRT_AUTH,
}

_SLOT_PIN_REF: dict[OpenPGPSlot, int] = {
    OpenPGPSlot.SIGN: _PIN_USER_SIGN,
    OpenPGPSlot.ENCRYPT: _PIN_USER_OTHER,
    OpenPGPSlot.AUTH: _PIN_USER_OTHER,
}

_SLOT_ALGO_DO: dict[OpenPGPSlot, int] = {
    OpenPGPSlot.SIGN: _DO_ALGO_ATTR_SIGN,
    OpenPGPSlot.ENCRYPT: _DO_ALGO_ATTR_ENC,
    OpenPGPSlot.AUTH: _DO_ALGO_ATTR_AUTH,
}

# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass(frozen=True)
class OpenPGPPublicKeys:
    """
    Публичные ключи всех трёх слотов OpenPGP-карты.

    Attributes:
        sign: Raw bytes публичного ключа Sign-слота (32 байта для Ed25519).
        encrypt: Raw bytes публичного ключа Encrypt-слота.
        auth: Raw bytes публичного ключа Auth-слота.
        sign_algorithm: Имя алгоритма Sign-слота (напр. "Ed25519").
        encrypt_algorithm: Имя алгоритма Encrypt-слота.
        auth_algorithm: Имя алгоритма Auth-слота.

    Example:
        >>> keys = backend.get_public_keys("sc_0_YubiKey")
        >>> keys.sign_algorithm
        'Ed25519'
        >>> len(keys.sign)
        32
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
    Метаданные OpenPGP-карты из Application Related Data (DO 0x6E).

    Attributes:
        card_id: Идентификатор ридера/устройства.
        manufacturer_id: 2-байтовый ID производителя (из AID).
        serial_number: Серийный номер карты (4 байта).
        app_version: Версия апплета (major, minor).
        pw1_remaining: Оставшихся попыток User PIN.
        pw3_remaining: Оставшихся попыток Admin PIN.

    Example:
        >>> info = backend.get_card_info("sc_0_YubiKey")
        >>> info.app_version
        (3, 4)
    """

    card_id: str
    manufacturer_id: bytes = b""
    serial_number: bytes = b""
    app_version: tuple[int, int] = (0, 0)
    pw1_remaining: int = 3
    pw3_remaining: int = 3


# ==============================================================================
# INTERNAL TLV UTILITIES
# ==============================================================================


def _build_tlv(tag: int, value: bytes) -> bytes:
    """
    Encode a single BER-TLV element with 1- or 2-byte tag.

    Length encoding: definite short (≤127), 0x81 (128–255), 0x82 (256–65535).

    Args:
        tag: Tag integer (up to 16-bit).
        value: Value bytes.

    Returns:
        Encoded TLV bytes.

    Example:
        >>> _build_tlv(0x86, b"\\x00" * 3)
        b'\\x86\\x03\\x00\\x00\\x00'
    """
    length = len(value)
    tag_bytes = bytes([(tag >> 8) & 0xFF, tag & 0xFF]) if tag > 0xFF else bytes([tag])

    if length <= 127:
        len_bytes = bytes([length])
    elif length <= 255:
        len_bytes = bytes([0x81, length])
    else:
        len_bytes = bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])

    return tag_bytes + len_bytes + value


def _parse_tlv(data: bytes) -> dict[int, bytes]:
    """
    Parse flat BER-TLV sequence (1- and 2-byte tags, definite length).

    Minimal parser for OpenPGP DOs — not a full ASN.1 decoder.
    Ignores 0x00 padding bytes.

    Args:
        data: Raw TLV-encoded bytes.

    Returns:
        Mapping {tag: value}. Duplicate tags: last wins.

    Example:
        >>> _parse_tlv(bytes.fromhex("C103010000"))
        {193: b'\\x01\\x00\\x00'}
    """
    result: dict[int, bytes] = {}
    idx = 0
    while idx < len(data):
        # Skip 0x00 padding
        if data[idx] == 0x00:
            idx += 1
            continue
        # Tag byte(s)
        tag: int = data[idx]
        idx += 1
        if (tag & 0x1F) == 0x1F:  # Long-form first byte
            if idx >= len(data):
                break
            tag = (tag << 8) | data[idx]
            idx += 1
        # Length
        if idx >= len(data):
            break
        length = data[idx]
        idx += 1
        if length == 0x81:
            if idx >= len(data):
                break
            length = data[idx]
            idx += 1
        elif length == 0x82:
            if idx + 1 >= len(data):
                break
            length = (data[idx] << 8) | data[idx + 1]
            idx += 2
        # Value
        result[tag] = data[idx: idx + length]
        idx += length
    return result


def _build_algo_attr_ed25519() -> bytes:
    """Build algorithm attributes DO value for Ed25519 (algo_id=0x16 + OID)."""
    return bytes([_ALGO_ED25519]) + _OID_ED25519


def _build_algo_attr_x25519() -> bytes:
    """Build algorithm attributes DO value for X25519 (algo_id=0x12 + OID)."""
    return bytes([_ALGO_ECDH]) + _OID_X25519


def _build_algo_attr_rsa(key_size: int) -> bytes:
    """
    Build RSA algorithm attributes DO value.

    Format: algo_id(1B) + modulus_bits(2B) + exponent_bits(2B) + import_format(1B).

    Args:
        key_size: RSA key size in bits (2048, 3072, or 4096).

    Returns:
        6-byte algorithm attributes.

    Raises:
        InvalidKeyError: Unsupported key size.
    """
    if key_size not in (2048, 3072, 4096):
        raise InvalidKeyError(
            f"Неподдерживаемый размер RSA-ключа: {key_size}. "
            "Допустимые: 2048, 3072, 4096.",
            algorithm=f"RSA-{key_size}",
        )
    # exponent_bits=17 means 65537 (standard); import_format=0x00 (standard)
    return struct.pack(">BHHB", _ALGO_RSA, key_size, 17, 0x00)


def _algo_name_from_attr(attr_bytes: bytes) -> str:
    """
    Decode algorithm name string from a raw algorithm attributes DO value.

    Args:
        attr_bytes: Raw DO value bytes (from C1/C2/C3).

    Returns:
        Human-readable algorithm name (e.g. "Ed25519", "RSA-2048", "X25519").
    """
    if not attr_bytes:
        return "Unknown"
    algo_id = attr_bytes[0]
    if algo_id == _ALGO_ED25519:
        return OpenPGPAlgorithm.ED25519.value
    if algo_id == _ALGO_ECDH:
        oid = attr_bytes[1:]
        if oid.startswith(_OID_X25519):
            return OpenPGPAlgorithm.X25519.value
        return f"ECDH-{oid.hex().upper()}"
    if algo_id == _ALGO_RSA and len(attr_bytes) >= 3:
        key_size = struct.unpack(">H", attr_bytes[1:3])[0]
        return f"RSA-{key_size}"
    return f"AlgoID-0x{algo_id:02X}"


def _extract_public_key_from_response(
    response: bytes, slot: OpenPGPSlot
) -> bytes:
    """
    Extract raw public key material from a GENERATE KEY PAIR (0x47) response.

    The response is structured as:
    ``7F49 [86 Lc [key_point]]``  for ECC/Ed25519
    ``7F49 [81 Lc [modulus] 82 Lc [exponent]]``  for RSA.

    Args:
        response: Raw response bytes.
        slot: Key slot (used only for log/error context).

    Returns:
        Raw public key bytes (32 bytes for Ed25519, 65 for P-256,
        DER modulus for RSA).

    Raises:
        DeviceCommunicationError: If the expected TLV structure is absent.
    """
    outer = _parse_tlv(response)
    pub_key_do = outer.get(0x7F49)  # 7F49 = Public Key DO
    inner_data = pub_key_do if pub_key_do is not None else response
    inner = _parse_tlv(inner_data)

    # ECC uses tag 0x86 (public key point); RSA uses tag 0x81 (modulus)
    material = inner.get(0x86) or inner.get(0x81)
    if not material:
        raise DeviceCommunicationError(
            device_id="openpgp",
            reason=(
                f"Не удалось разобрать публичный ключ из ответа устройства "
                f"(слот {slot.value}). Ожидались TLV-теги 7F49→86 или 81."
            ),
        )
    return material


def _check_sw(sw: int, operation: str, card_id: str) -> None:
    """
    Validate APDU status word; raise typed exception on failure.

    Args:
        sw: Combined status word (sw1 << 8 | sw2).
        operation: Human-readable operation description for error messages.
        card_id: Device identifier for error messages.

    Raises:
        PINError: SW indicates wrong or blocked PIN.
        HardwareDeviceError: Any other non-9000 status word.
    """
    if sw == _SW_SUCCESS:
        return
    if sw == _SW_PIN_BLOCKED:
        raise PINError(
            card_id,
            f"PIN заблокирован (операция: {operation}). "
            "Используйте Admin PIN для разблокировки (UNBLOCK PIN).",
        )
    if (sw & 0xFFF0) == _SW_PIN_WRONG_MASK:
        retries = sw & 0x0F
        raise PINError(
            card_id,
            f"Неверный PIN (операция: {operation}). "
            f"Осталось попыток: {retries}.",
            retries_remaining=retries,
        )
    if sw == _SW_SECURITY_NOT_SATISFIED:
        raise PINError(
            card_id,
            f"Для операции '{operation}' необходима верификация PIN.",
        )
    raise HardwareDeviceError(
        f"Операция '{operation}' на устройстве '{card_id}' "
        f"завершилась ошибкой: SW=0x{sw:04X}.",
        device_id=card_id,
        context={"sw": f"0x{sw:04X}", "operation": operation},
    )


# ==============================================================================
# OPENPGP BACKEND
# ==============================================================================


class OpenPGPBackend:
    """
    OpenPGP Card 3.4 бэкенд через raw APDU (pyscard + ApduTransport).

    Единый интерфейс для YubiKey 5 NFC и J3R200 + SmartPGP. Оба устройства
    реализуют одинаковый OpenPGP Card Application 3.4 через ISO 7816-4.

    Ограничения:
    - Не потокобезопасен: используйте отдельный экземпляр на поток.
    - Импорт ключа требует Admin PIN (PW3), не User PIN.
    - sign() увеличивает аппаратный счётчик подписей на устройстве.
    - Для X25519 ECDH передавайте данные через ``build_ecdh_decipher_data()``.

    Example:
        >>> backend = OpenPGPBackend()
        >>> info = backend.get_card_info("sc_0_YubiKey 5 NFC 0")
        >>> info.app_version
        (3, 4)
    """

    def __init__(self) -> None:
        """Initialize the backend. Card connections are lazy (per-call)."""
        logger.info("OpenPGPBackend initialized")

    # ------------------------------------------------------------------
    # SIGN
    # ------------------------------------------------------------------

    def sign(self, card_id: str, data: bytes, pin: str) -> bytes:
        """
        Sign data using the OpenPGP Sign slot (PSO: Compute Digital Signature).

        For Ed25519: pass the raw message or SHA-512 digest (≤512 bytes).
        For RSA: pass a DER-encoded DigestInfo structure.
        The card applies the appropriate padding/signature scheme automatically.

        Args:
            card_id: Reader/device identifier (e.g. ``"sc_0_YubiKey 5 NFC 0"``).
            data: Data or digest to sign.
            pin: User PIN (PW1, unlocks Sign slot; reference 0x81).

        Returns:
            Raw signature bytes (64 bytes for Ed25519; DER for RSA).

        Raises:
            PINError: Incorrect or blocked PIN.
            HardwareDeviceError: Card returned non-success SW.
            DeviceCommunicationError: Transport-level failure.

        Example:
            >>> import hashlib
            >>> digest = hashlib.sha512(b"invoice #001").digest()
            >>> sig = backend.sign("sc_0_YubiKey 5 NFC 0", digest, pin="123456")
            >>> len(sig)
            64
        """
        logger.info(
            "OpenPGP sign: card=%s, data_len=%d",
            card_id,
            len(data),
        )
        with ApduTransport(card_id) as transport:
            transport.select_applet(OPENPGP_AID)
            _verify_pin(transport, _PIN_USER_SIGN, pin, card_id)
            resp = transport.send_apdu(
                cla=0x00,
                ins=_INS_PSO,
                p1=_PSO_SIGN_P1,
                p2=_PSO_SIGN_P2,
                data=data,
                le=0,
            )
            _check_sw(resp.sw, "PSO:CDS", card_id)
        logger.info(
            "OpenPGP sign complete: card=%s, sig_len=%d",
            card_id,
            len(resp.data),
        )
        return resp.data

    # ------------------------------------------------------------------
    # DECRYPT / ECDH
    # ------------------------------------------------------------------

    def decrypt(self, card_id: str, ciphertext: bytes, pin: str) -> bytes:
        """
        Decrypt ciphertext or perform ECDH using the OpenPGP Encrypt slot.

        For X25519 ECDH: wrap the ephemeral public key with
        ``OpenPGPBackend.build_ecdh_decipher_data()`` before passing here.
        The card returns the raw shared secret (32 bytes for X25519).

        For RSA: pass the raw RSA-encrypted session key bytes.

        Args:
            card_id: Reader/device identifier.
            ciphertext: ECDH-wrapped ephemeral key or RSA ciphertext.
            pin: User PIN (PW1 mode 2, reference 0x82).

        Returns:
            Decrypted plaintext or ECDH shared secret.

        Raises:
            PINError: Incorrect or blocked PIN.
            HardwareDeviceError: Card returned non-success SW.

        Example:
            >>> ecdh_payload = OpenPGPBackend.build_ecdh_decipher_data(ephem_pub)
            >>> shared = backend.decrypt("sc_0_J3R200", ecdh_payload, pin="123456")
            >>> len(shared)
            32
        """
        logger.info(
            "OpenPGP decrypt: card=%s, data_len=%d",
            card_id,
            len(ciphertext),
        )
        with ApduTransport(card_id) as transport:
            transport.select_applet(OPENPGP_AID)
            _verify_pin(transport, _PIN_USER_OTHER, pin, card_id)
            resp = transport.send_apdu(
                cla=0x00,
                ins=_INS_PSO,
                p1=_PSO_DEC_P1,
                p2=_PSO_DEC_P2,
                data=ciphertext,
                le=0,
            )
            _check_sw(resp.sw, "PSO:DEC", card_id)
        logger.info(
            "OpenPGP decrypt complete: card=%s, result_len=%d",
            card_id,
            len(resp.data),
        )
        return resp.data

    # ------------------------------------------------------------------
    # AUTHENTICATE
    # ------------------------------------------------------------------

    def authenticate(self, card_id: str, challenge: bytes, pin: str) -> bytes:
        """
        Authenticate using the OpenPGP Auth slot (INTERNAL AUTHENTICATE).

        Suitable for challenge-response and TLS client authentication.

        Args:
            card_id: Reader/device identifier.
            challenge: Challenge to authenticate over (typically a hash).
            pin: User PIN (PW1 mode 2, reference 0x82).

        Returns:
            Authentication response bytes (signature over challenge).

        Raises:
            PINError: Incorrect or blocked PIN.
            HardwareDeviceError: Card returned non-success SW.

        Example:
            >>> import os
            >>> resp = backend.authenticate("sc_0_YubiKey 5 NFC 0",
            ...                             os.urandom(32), pin="123456")
        """
        logger.info(
            "OpenPGP authenticate: card=%s, challenge_len=%d",
            card_id,
            len(challenge),
        )
        with ApduTransport(card_id) as transport:
            transport.select_applet(OPENPGP_AID)
            _verify_pin(transport, _PIN_USER_OTHER, pin, card_id)
            resp = transport.send_apdu(
                cla=0x00,
                ins=_INS_INT_AUTH,
                p1=0x00,
                p2=0x00,
                data=challenge,
                le=0,
            )
            _check_sw(resp.sw, "INTERNAL AUTHENTICATE", card_id)
        logger.info(
            "OpenPGP authenticate complete: card=%s, resp_len=%d",
            card_id,
            len(resp.data),
        )
        return resp.data

    # ------------------------------------------------------------------
    # GET PUBLIC KEYS
    # ------------------------------------------------------------------

    def get_public_keys(self, card_id: str) -> OpenPGPPublicKeys:
        """
        Read all three public keys from the OpenPGP card without regenerating.

        Sends GENERATE KEY PAIR with P1=0x81 (read-only) for each slot.
        Returns empty bytes for unpopulated slots.

        Args:
            card_id: Reader/device identifier.

        Returns:
            ``OpenPGPPublicKeys`` with raw public key material and algorithm
            names for each slot.

        Raises:
            HardwareDeviceError: Communication failure.

        Example:
            >>> keys = backend.get_public_keys("sc_0_YubiKey 5 NFC 0")
            >>> keys.sign_algorithm
            'Ed25519'
        """
        logger.info("OpenPGP get_public_keys: card=%s", card_id)
        with ApduTransport(card_id) as transport:
            transport.select_applet(OPENPGP_AID)
            sign_algo = _read_algo_attr(transport, _DO_ALGO_ATTR_SIGN, card_id)
            enc_algo = _read_algo_attr(transport, _DO_ALGO_ATTR_ENC, card_id)
            auth_algo = _read_algo_attr(transport, _DO_ALGO_ATTR_AUTH, card_id)
            sign_key = _read_existing_public_key(transport, OpenPGPSlot.SIGN, card_id)
            enc_key = _read_existing_public_key(transport, OpenPGPSlot.ENCRYPT, card_id)
            auth_key = _read_existing_public_key(transport, OpenPGPSlot.AUTH, card_id)

        return OpenPGPPublicKeys(
            sign=sign_key,
            encrypt=enc_key,
            auth=auth_key,
            sign_algorithm=sign_algo,
            encrypt_algorithm=enc_algo,
            auth_algorithm=auth_algo,
        )

    # ------------------------------------------------------------------
    # GET CARD INFO
    # ------------------------------------------------------------------

    def get_card_info(self, card_id: str) -> OpenPGPCardInfo:
        """
        Read OpenPGP card metadata from Application Related Data (DO 0x6E).

        Also reads PW Status Bytes (DO 0xC4) for remaining PIN retry counts.

        Args:
            card_id: Reader/device identifier.

        Returns:
            ``OpenPGPCardInfo`` with manufacturer, serial, version, PIN retries.

        Raises:
            HardwareDeviceError: Communication failure.

        Example:
            >>> info = backend.get_card_info("sc_0_YubiKey 5 NFC 0")
            >>> info.pw1_remaining
            3
        """
        logger.debug("OpenPGP get_card_info: card=%s", card_id)
        with ApduTransport(card_id) as transport:
            transport.select_applet(OPENPGP_AID)

            # Application Related Data (DO 0x6E)
            app_result = transport.send_apdu(
                cla=0x00, ins=_INS_GET_DATA, p1=0x00, p2=0x6E, data=b"", le=0
            )
            _check_sw(app_result.sw, "GET DATA 0x6E", card_id)
            app_data = _parse_tlv(app_result.data)

            # PW Status Bytes (DO 0xC4) — best-effort
            pw_result = transport.send_apdu(
                cla=0x00, ins=_INS_GET_DATA, p1=0x00, p2=0xC4, data=b"", le=0
            )
            pw_status = pw_result.data if pw_result.sw == _SW_SUCCESS else b""

        # AID value layout (14 bytes): RID(5)+app(1)+version(2)+mfr(2)+serial(4)+RFU(2)
        aid_val = app_data.get(0x4F, b"")
        manufacturer_id = aid_val[7:9] if len(aid_val) >= 9 else b""
        serial_number = aid_val[9:13] if len(aid_val) >= 13 else b""
        app_version: tuple[int, int] = (
            (aid_val[6], aid_val[7]) if len(aid_val) >= 8 else (0, 0)
        )

        # pw_status[4] = PW1 retries; pw_status[6] = PW3 retries
        pw1_remaining = pw_status[4] if len(pw_status) > 4 else 3
        pw3_remaining = pw_status[6] if len(pw_status) > 6 else 3

        return OpenPGPCardInfo(
            card_id=card_id,
            manufacturer_id=manufacturer_id,
            serial_number=serial_number,
            app_version=app_version,
            pw1_remaining=pw1_remaining,
            pw3_remaining=pw3_remaining,
        )

    # ------------------------------------------------------------------
    # IMPORT KEY
    # ------------------------------------------------------------------

    def import_key(
        self,
        card_id: str,
        slot: OpenPGPSlot,
        key_data: bytes,
        admin_pin: str,
    ) -> None:
        """
        Import a private key into the specified OpenPGP slot.

        Requires Admin PIN (PW3). Build ``key_data`` with the appropriate
        static helper:
        - Ed25519: ``OpenPGPBackend.build_ed25519_private_key_tl(seed, slot)``
        - RSA: construct Extended Header List per OpenPGP spec §4.3.3.7.

        Args:
            card_id: Reader/device identifier.
            slot: Target OpenPGP slot.
            key_data: Private key material TLV (inner body, without 4D wrapper).
            admin_pin: Admin PIN (PW3).

        Raises:
            PINError: Incorrect or blocked Admin PIN.
            HardwareDeviceError: PUT DATA failure.

        Example:
            >>> tl = OpenPGPBackend.build_ed25519_private_key_tl(seed, OpenPGPSlot.SIGN)
            >>> backend.import_key("sc_0_YubiKey", OpenPGPSlot.SIGN, tl, "12345678")
        """
        logger.info(
            "OpenPGP import_key: card=%s, slot=%s",
            card_id,
            slot.value,
        )
        with ApduTransport(card_id) as transport:
            transport.select_applet(OPENPGP_AID)
            _verify_pin(transport, _PIN_ADMIN, admin_pin, card_id)
            crt = _SLOT_CRT[slot]
            # Extended Header List: tag 0x4D wraps CRT + private key TLV
            ehl = _build_tlv(0x4D, crt + key_data)
            resp = transport.send_apdu(
                cla=0x00,
                ins=_INS_PUT_DATA_ODD,
                p1=0x3F,
                p2=0xFF,
                data=ehl,
                le=0,
            )
            _check_sw(resp.sw, f"PUT DATA 4D (import, slot={slot.value})", card_id)
        logger.info(
            "OpenPGP import_key complete: card=%s, slot=%s",
            card_id,
            slot.value,
        )

    # ------------------------------------------------------------------
    # GENERATE KEY ONBOARD
    # ------------------------------------------------------------------

    def generate_key_onboard(
        self,
        card_id: str,
        slot: OpenPGPSlot,
        algorithm: OpenPGPAlgorithm,
        admin_pin: str,
    ) -> bytes:
        """
        Generate a key pair on the device; return the public key.

        Sequence:
        1. PUT DATA Cx: set algorithm attributes for the slot.
        2. GENERATE ASYMMETRIC KEY PAIR (P1=0x80): generate on-device.

        The private key is created by the card's hardware RNG and never
        leaves the device.

        Args:
            card_id: Reader/device identifier.
            slot: Target OpenPGP slot.
            algorithm: Algorithm for the new key pair.
            admin_pin: Admin PIN (PW3).

        Returns:
            Raw public key bytes (32 bytes for Ed25519).

        Raises:
            PINError: Incorrect or blocked Admin PIN.
            KeyGenerationError: Device-side key generation failure.
            AlgorithmNotAvailableError: Algorithm not supported.
            HardwareDeviceError: Communication failure.

        Example:
            >>> pub = backend.generate_key_onboard(
            ...     "sc_0_YubiKey 5 NFC 0",
            ...     OpenPGPSlot.SIGN,
            ...     OpenPGPAlgorithm.ED25519,
            ...     admin_pin="12345678",
            ... )
            >>> len(pub)
            32
        """
        logger.info(
            "OpenPGP generate_key_onboard: card=%s, slot=%s, algo=%s",
            card_id,
            slot.value,
            algorithm.value,
        )
        algo_attr = _build_algo_attr_for(algorithm)
        attr_do = _SLOT_ALGO_DO[slot]

        with ApduTransport(card_id) as transport:
            transport.select_applet(OPENPGP_AID)
            _verify_pin(transport, _PIN_ADMIN, admin_pin, card_id)

            # Step 1: set algorithm attributes
            attr_resp = transport.send_apdu(
                cla=0x00,
                ins=_INS_PUT_DATA_EVEN,
                p1=0x00,
                p2=attr_do & 0xFF,
                data=algo_attr,
                le=0,
            )
            _check_sw(attr_resp.sw, f"PUT DATA algo attr (slot={slot.value})", card_id)

            # Step 2: generate key pair (P1=0x80)
            crt = _SLOT_CRT[slot]
            try:
                gen_resp = transport.send_apdu(
                    cla=0x00,
                    ins=_INS_GEN_KEYPAIR,
                    p1=0x80,
                    p2=0x00,
                    data=crt,
                    le=0,
                )
                _check_sw(gen_resp.sw, f"GENERATE KEY PAIR (slot={slot.value})", card_id)
            except HardwareDeviceError as exc:
                raise KeyGenerationError(
                    f"Генерация ключа на устройстве '{card_id}' "
                    f"(слот {slot.value}, алгоритм {algorithm.value}) не удалась: {exc}",
                    algorithm=algorithm.value,
                    context={"card_id": card_id, "slot": slot.value},
                ) from exc

        pub_key = _extract_public_key_from_response(gen_resp.data, slot)
        logger.info(
            "OpenPGP generate_key_onboard complete: card=%s, slot=%s, pub_len=%d",
            card_id,
            slot.value,
            len(pub_key),
        )
        return pub_key

    # ------------------------------------------------------------------
    # STATIC HELPERS (public API for callers)
    # ------------------------------------------------------------------

    @staticmethod
    def build_ecdh_decipher_data(ephemeral_public_key: bytes) -> bytes:
        """
        Wrap an ephemeral X25519 public key into the PSO:DEC input format.

        Per OpenPGP card spec §7.2.11: the decipher data for ECDH is
        ``A6 Lc [7F49 Lc [86 Lc [0x04 || ephemeral_pub]]]``.

        For X25519 the 0x04 prefix is NOT used — key is raw 32 bytes.
        For NIST P-256/P-384 use the uncompressed point ``04 || x || y``.

        Args:
            ephemeral_public_key: Raw ephemeral public key bytes.
                32 bytes for X25519; 65 bytes (04||x||y) for NIST curves.

        Returns:
            APDU data field for PSO:DEC ECDH operation.

        Example:
            >>> import os
            >>> eph = os.urandom(32)  # mock X25519 ephemeral key
            >>> payload = OpenPGPBackend.build_ecdh_decipher_data(eph)
            >>> payload[0]
            166  # 0xA6
        """
        inner_86 = _build_tlv(0x86, ephemeral_public_key)
        inner_7f49 = _build_tlv(0x7F49, inner_86)
        return _build_tlv(0xA6, inner_7f49)

    @staticmethod
    def build_ed25519_private_key_tl(
        seed: bytes,
        slot: OpenPGPSlot,
    ) -> bytes:
        """
        Build the inner TLV for importing an Ed25519 private key (seed).

        Produces the inner body for Extended Header List (without 0x4D wrapper):
        ``CRT || 92 20 [seed]``

        Per OpenPGP card spec §4.3.3.7, tag 0x92 is the private key DO
        for the Sign slot.

        Args:
            seed: 32-byte Ed25519 private key seed.
            slot: Target slot (used to select CRT).

        Returns:
            TLV bytes: CRT_bytes + private_key_tlv.

        Raises:
            InvalidKeyError: seed is not exactly 32 bytes.

        Example:
            >>> import os
            >>> seed = os.urandom(32)
            >>> tl = OpenPGPBackend.build_ed25519_private_key_tl(
            ...     seed, OpenPGPSlot.SIGN
            ... )
            >>> tl[0:2]
            b'\\xb6\\x00'
        """
        if len(seed) != 32:
            raise InvalidKeyError(
                f"Ed25519 seed должен быть ровно 32 байта, получено {len(seed)}.",
                algorithm="Ed25519",
            )
        crt = _SLOT_CRT[slot]
        priv_tlv = _build_tlv(0x92, seed)
        return crt + priv_tlv


# ==============================================================================
# PRIVATE MODULE-LEVEL HELPERS
# ==============================================================================


def _verify_pin(
    transport: ApduTransport,
    pin_ref: int,
    pin: str,
    card_id: str,
) -> None:
    """
    Send VERIFY PIN (INS=0x20) APDU and raise PINError on failure.

    Args:
        transport: Active ApduTransport (applet already selected).
        pin_ref: PIN reference byte (0x81, 0x82, or 0x83).
        pin: PIN string; encoded as UTF-8 bytes.
        card_id: Device id for error messages.

    Raises:
        PINError: Wrong PIN, blocked, or security precondition not met.
        HardwareDeviceError: Unexpected status word.
    """
    pin_bytes = pin.encode("utf-8")
    resp = transport.send_apdu(
        cla=0x00,
        ins=_INS_VERIFY,
        p1=0x00,
        p2=pin_ref,
        data=pin_bytes,
        le=0,
    )
    _check_sw(resp.sw, f"VERIFY PIN (ref=0x{pin_ref:02X})", card_id)
    logger.debug("PIN verified: card=%s, ref=0x%02X", card_id, pin_ref)


def _read_algo_attr(
    transport: ApduTransport,
    do_tag: int,
    card_id: str,
) -> str:
    """
    Read a single algorithm attribute DO (C1/C2/C3) and return algorithm name.

    Args:
        transport: Active ApduTransport (applet already selected).
        do_tag: DO tag (0xC1, 0xC2, or 0xC3).
        card_id: Device id for error messages.

    Returns:
        Algorithm name string. Returns "Unknown" on read failure.
    """
    result = transport.send_apdu(
        cla=0x00,
        ins=_INS_GET_DATA,
        p1=0x00,
        p2=do_tag & 0xFF,
        data=b"",
        le=0,
    )
    if result.sw != _SW_SUCCESS:
        logger.debug(
            "GET DATA 0x%02X returned SW=0x%04X on '%s', skipping",
            do_tag, result.sw, card_id,
        )
        return "Unknown"
    return _algo_name_from_attr(result.data)


def _read_existing_public_key(
    transport: ApduTransport,
    slot: OpenPGPSlot,
    card_id: str,
) -> bytes:
    """
    Read an existing public key using GENERATE KEY PAIR with P1=0x81 (read-only).

    Returns empty bytes if the slot is not populated or the APDU fails.

    Args:
        transport: Active ApduTransport (applet already selected).
        slot: OpenPGP key slot.
        card_id: Device id for error messages.

    Returns:
        Raw public key bytes, or empty bytes if slot is empty.
    """
    crt = _SLOT_CRT[slot]
    result = transport.send_apdu(
        cla=0x00,
        ins=_INS_GEN_KEYPAIR,
        p1=0x81,  # read-only — does NOT generate a new key
        p2=0x00,
        data=crt,
        le=0,
    )
    if result.sw != _SW_SUCCESS:
        logger.debug(
            "Public key read for slot '%s' on '%s': SW=0x%04X (slot may be empty)",
            slot.value, card_id, result.sw,
        )
        return b""
    try:
        return _extract_public_key_from_response(result.data, slot)
    except DeviceCommunicationError as exc:
        logger.debug("Public key parse failed for slot '%s': %s", slot.value, exc)
        return b""


def _build_algo_attr_for(algorithm: OpenPGPAlgorithm) -> bytes:
    """
    Build algorithm attributes DO value for a given OpenPGPAlgorithm.

    Args:
        algorithm: Target algorithm.

    Returns:
        Raw algorithm attributes bytes.

    Raises:
        AlgorithmNotAvailableError: Algorithm not supported.
    """
    match algorithm:
        case OpenPGPAlgorithm.ED25519:
            return _build_algo_attr_ed25519()
        case OpenPGPAlgorithm.X25519:
            return _build_algo_attr_x25519()
        case OpenPGPAlgorithm.RSA2048:
            return _build_algo_attr_rsa(2048)
        case OpenPGPAlgorithm.RSA3072:
            return _build_algo_attr_rsa(3072)
        case OpenPGPAlgorithm.RSA4096:
            return _build_algo_attr_rsa(4096)
        case _:
            raise AlgorithmNotAvailableError(
                algorithm=algorithm.value,
                reason=f"Алгоритм '{algorithm.value}' не поддерживается OpenPGP-бэкендом.",
                required_library="N/A",
            )


# ==============================================================================
# MODULE METADATA
# ==============================================================================

__all__: list[str] = [
    "OPENPGP_AID",
    "OpenPGPSlot",
    "OpenPGPAlgorithm",
    "OpenPGPPublicKeys",
    "OpenPGPCardInfo",
    "OpenPGPBackend",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"
