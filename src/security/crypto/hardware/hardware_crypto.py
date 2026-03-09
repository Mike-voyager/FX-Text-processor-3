"""
Менеджер аппаратных криптографических устройств.

Обеспечивает взаимодействие со смарткартами (PIV, OpenPGP) и YubiKey
для выполнения криптографических операций на устройстве. Приватный ключ
НИКОГДА не покидает аппаратный модуль.

Поддерживаемые устройства:
    - YubiKey 5 серии (PIV + HMAC-SHA1 + OpenPGP + OATH + FIDO2)
    - PIV-совместимые смарткарты (NIST SP 800-73)
    - OpenPGP-совместимые смарткарты (ISO/IEC 7816)

Ограничения YubiKey по прошивке (PIV):
    FW < 5.7:  RSA-2048, ECC P-256, ECC P-384
    FW 5.7+:   + RSA-3072, RSA-4096, Ed25519, X25519
    OpenPGP:   Ed25519, X25519, RSA до 4096 (с FW 5.2.3+)

PIV слоты:
    0x9A — Authentication
    0x9C — Digital Signature
    0x9D — Key Management
    0x9E — Card Authentication

Опциональные зависимости:
    - pyscard>=2.0.0
    - yubikey-manager>=5.0.0

Security Notes:
    - ExternalKeypair: contextmanager + wipe() + __del__ для автообнуления.
    - Thread-safe: dict[str, RLock] — отдельный лок на устройство;
      _global_lock только для enumeration и cache.
    - Enumeration cache (TTL=3 с): list_devices() не делает USB-опрос
      при каждом вызове.
    - Логирование БЕЗ секретных данных.

Example:
    >>> manager = HardwareCryptoManager()
    >>> devices = manager.list_devices()
    >>> with manager.generate_keypair_external("ECC-P256") as kp:
    ...     manager.import_key_to_device(
    ...         devices[0].card_id, 0x9C, bytes(kp.private_key_der), pin="123456"
    ...     )
    # private_key_der обнулён автоматически

Version: 1.3.0
Date: 2026-03-02
Author: Mike Voyager
Priority: Phase 9 (CRYPTO_MASTER_PLAN v2.3)
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import (
    TYPE_CHECKING,
    Any,
    Literal,
    Union,
)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_private_key,
)

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

if TYPE_CHECKING:
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import KEY_TYPE as _YKKeyType
    from yubikit.piv import SLOT as _YKSlot

# Определяются ОДИН РАЗ — здесь, до optional-импортов
logger = logging.getLogger(__name__)
_PrivateKeyType = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]


# ==============================================================================
# OPTIONAL DEPENDENCY DETECTION
# ==============================================================================

try:
    from smartcard.Exceptions import CardConnectionException, NoCardException
    from smartcard.System import readers as sc_readers

    has_pyscard = True
    logger.debug("pyscard detected, smartcard operations available")
except ImportError:
    sc_readers = None
    CardConnectionException = None
    NoCardException = None
    has_pyscard = False
    logger.debug("pyscard not installed. Install: pip install pyscard>=2.0.0")

try:
    from ykman.device import list_all_devices as yk_list_all
    from yubikit.core import TRANSPORT as YK_TRANSPORT
    from yubikit.management import CAPABILITY as YK_CAPABILITY
    from yubikit.piv import (
        KEY_TYPE as YK_KEY_TYPE,
    )
    from yubikit.piv import (
        SLOT as YK_SLOT,
    )
    from yubikit.piv import (
        PivSession,
    )

    has_ykman = True
    logger.debug("yubikey-manager detected, YubiKey operations available")
except ImportError:
    yk_list_all = None  # type: ignore[assignment]
    PivSession = None  # type: ignore[misc, assignment]
    YK_SLOT = None  # type: ignore[misc, assignment]
    YK_KEY_TYPE = None  # type: ignore[misc, assignment]
    YK_CAPABILITY = None  # type: ignore[misc, assignment]
    YK_TRANSPORT = None  # type: ignore[misc, assignment]
    has_ykman = False
    logger.debug("yubikey-manager not installed. Install: pip install yubikey-manager>=5.0.0")


# ==============================================================================
# TYPE ALIASES
# ==============================================================================

SmartcardType = Literal["piv", "openpgp", "yubikey_piv"]
KeyGenerationCapability = Literal["onboard", "external"]


# ==============================================================================
# PIV SLOT CONSTANTS
# ==============================================================================

PIV_SLOT_AUTHENTICATION: int = 0x9A
PIV_SLOT_DIGITAL_SIGNATURE: int = 0x9C
PIV_SLOT_KEY_MANAGEMENT: int = 0x9D
PIV_SLOT_CARD_AUTHENTICATION: int = 0x9E

PIV_VALID_SLOTS: frozenset[int] = frozenset(
    {
        PIV_SLOT_AUTHENTICATION,
        PIV_SLOT_DIGITAL_SIGNATURE,
        PIV_SLOT_KEY_MANAGEMENT,
        PIV_SLOT_CARD_AUTHENTICATION,
    }
)

PIV_SLOT_NAMES: dict[int, str] = {
    PIV_SLOT_AUTHENTICATION: "PIV Authentication (9A)",
    PIV_SLOT_DIGITAL_SIGNATURE: "Digital Signature (9C)",
    PIV_SLOT_KEY_MANAGEMENT: "Key Management (9D)",
    PIV_SLOT_CARD_AUTHENTICATION: "Card Authentication (9E)",
}

_PIV_FW57_ALGORITHMS: frozenset[str] = frozenset(
    {
        "RSA-3072",
        "RSA3072",
        "RSA-4096",
        "RSA4096",
        "ED25519",
        "X25519",
    }
)

# ==============================================================================
# DEVICE CAPABILITIES  [DC — новый dataclass]
# ==============================================================================


@dataclass(frozen=True)
class DeviceCapabilities:
    """
    Структурированные криптографические возможности устройства.

    Заменяет плоский ``algorithms_supported`` детальной моделью с разделением
    по протоколам (PIV vs OpenPGP) и отражает реальные аппаратные ограничения.

    Attributes:
        rsa_key_sizes:      Размеры RSA-ключей в битах (пустой tuple = нет RSA).
        ecc_curves:         ECC-кривые ("P-256", "P-384").
        ed25519_piv:        Ed25519 через PIV (только FW 5.7.0+).
        ed25519_openpgp:    Ed25519 через OpenPGP (FW 5.2.3+).
        x25519_piv:         X25519 через PIV (только FW 5.7.0+).
        x25519_openpgp:     X25519 через OpenPGP (FW 5.2.3+).
        can_generate_onboard: Аппаратная генерация ключей на устройстве.
        aes_modes:          AES-режимы (например, для J3R200 кастомных апплетов).
        hmac_sha1:          HMAC-SHA1 Challenge-Response (YubiKey OTP-слот).
        has_openpgp:        Устройство поддерживает OpenPGP-протокол.
        has_oath:           OATH TOTP/HOTP на устройстве.
        has_fido2:          FIDO2/WebAuthn.

    Properties:
        piv_algorithms:  Tuple алгоритмов, доступных через PIV.
        all_algorithms:  Все алгоритмы через все протоколы (дедупликация).

    Example:
        >>> caps = DeviceCapabilities(
        ...     rsa_key_sizes=(2048,),
        ...     ecc_curves=("P-256", "P-384"),
        ...     ed25519_openpgp=True,
        ...     has_openpgp=True,
        ... )
        >>> "Ed25519" in caps.all_algorithms
        True
        >>> "ECC-P256" in caps.piv_algorithms
        True
    """

    rsa_key_sizes: tuple[int, ...] = ()
    ecc_curves: tuple[str, ...] = ()
    ed25519_piv: bool = False
    ed25519_openpgp: bool = False
    x25519_piv: bool = False
    x25519_openpgp: bool = False
    can_generate_onboard: bool = False
    aes_modes: tuple[str, ...] = ()
    hmac_sha1: bool = False
    has_openpgp: bool = False
    has_oath: bool = False
    has_fido2: bool = False

    @property
    def piv_algorithms(self) -> tuple[str, ...]:
        """Алгоритмы, доступные через PIV."""
        algos: list[str] = [f"RSA-{s}" for s in self.rsa_key_sizes]
        algos += [f"ECC-{c}" for c in self.ecc_curves]
        if self.ed25519_piv:
            algos.append("Ed25519")
        if self.x25519_piv:
            algos.append("X25519")
        return tuple(algos)

    @property
    def all_algorithms(self) -> tuple[str, ...]:
        """Все алгоритмы через все протоколы (без дубликатов, сортировка)."""
        algos: set[str] = set(self.piv_algorithms)
        if self.ed25519_openpgp:
            algos.add("Ed25519")
        if self.x25519_openpgp:
            algos.add("X25519")
        return tuple(sorted(algos))


# ==============================================================================
# CAPABILITY FACTORIES
# ==============================================================================


def _make_yubikey_capabilities(fw: tuple[int, int, int]) -> DeviceCapabilities:
    """
    Построить ``DeviceCapabilities`` для YubiKey по версии прошивки.

    Данные основаны на официальной документации Yubico
    (docs.yubico.com/hardware/yubikey/yk-tech-manual):

    - PIV Ed25519/X25519/RSA-3072/4096: только FW 5.7.0+
    - OpenPGP Ed25519/X25519: с FW 5.2.3+
    - OATH: до 32 credentials (< 5.7), до 64 (5.7+)
    - FIDO2: до 25 discoverable credentials (< 5.7), до 100 (5.7+)

    Args:
        fw: Версия прошивки (major, minor, patch).

    Returns:
        ``DeviceCapabilities`` для данной версии прошивки.

    Example:
        >>> caps = _make_yubikey_capabilities((5, 2, 4))
        >>> caps.ed25519_openpgp
        True
        >>> caps.ed25519_piv
        False
        >>> caps = _make_yubikey_capabilities((5, 7, 2))
        >>> caps.ed25519_piv
        True
    """
    is_57plus = fw >= (5, 7, 0)
    is_523plus = fw >= (5, 2, 3)  # OpenPGP 3.4 с Ed25519/X25519

    return DeviceCapabilities(
        rsa_key_sizes=(2048, 3072, 4096) if is_57plus else (2048,),
        ecc_curves=("P256", "P384"),  # ← f"ECC-{c}" → "ECC-P256", "ECC-P384"
        ed25519_piv=is_57plus,
        ed25519_openpgp=is_523plus,
        x25519_piv=is_57plus,
        x25519_openpgp=is_523plus,
        can_generate_onboard=True,
        hmac_sha1=True,
        has_openpgp=True,
        has_oath=True,
        has_fido2=True,
    )


# ==============================================================================
# AID CONSTANTS (ISO/IEC 7816-4 / NIST SP 800-73)
# ==============================================================================

_PIV_AID: bytes = bytes.fromhex("A000000308")
_OPENPGP_AID: bytes = bytes.fromhex("D276000124")

# SELECT AID APDU: CLA=0x00 INS=0xA4 P1=0x04 P2=0x00 Lc=len(AID) AID Le=0x00
_SW_SUCCESS: tuple[int, int] = (0x90, 0x00)


# ==============================================================================
# CARD PROFILE
# ==============================================================================


@dataclass(frozen=True)
class CardProfile:
    """
    Профиль смарткарты, определённый через ATR или SELECT AID.

    Используется внутри ``_detect_card_profile()`` и преобразуется
    в ``SmartcardInfo`` в ``_list_smartcards()``.

    Attributes:
        card_type:    Основной протокол.
        manufacturer: Производитель чипа.
        chip:         Наименование чипа (например, "JCOP4 P71").
        capabilities: Криптографические возможности.
        detected_via: Метод обнаружения:
                      ``"atr"``           — точное совпадение в базе ATR;
                      ``"aid_openpgp"``   — SELECT OpenPGP AID = SW 9000;
                      ``"aid_piv"``       — SELECT PIV AID = SW 9000;
                      ``"name_fallback"`` — подстрока в имени ридера
                                           (ненадёжно, только как крайний случай).

    Example:
        >>> profile = CardProfile(
        ...     card_type="piv",
        ...     manufacturer="NXP",
        ...     chip="JCOP4 P71",
        ...     capabilities=_J3R200_CAPABILITIES,
        ...     detected_via="atr",
        ... )
    """

    card_type: SmartcardType
    manufacturer: str = "Unknown"
    chip: str = "Unknown"
    capabilities: DeviceCapabilities = field(default_factory=DeviceCapabilities)
    detected_via: str = "name_fallback"


# ==============================================================================
# CAPABILITY PRESETS
# ==============================================================================

# J3R200 (JCOP4 P71) — AlgTest-verified:
# RSA 2048/3072/4096 keygen: YES | ECC P-256/P-384: NO | AES-128 only
# Источник: github.com/crocs-muni/JCAlgTest результаты для NXP JCOP4 P71
_J3R200_CAPABILITIES: DeviceCapabilities = DeviceCapabilities(
    rsa_key_sizes=(2048, 3072, 4096),  # on-card keygen подтверждён
    ecc_curves=(),  # AlgTest: все EC-операции → "no"
    can_generate_onboard=True,
    aes_modes=("CBC", "ECB", "CTR"),  # AES-128; 192/256 — только блок, без GCM
    hmac_sha1=False,
    has_openpgp=False,
    has_oath=False,
    has_fido2=False,
)

# Консервативный PIV — только RSA-2048 гарантирован без ATR/AlgTest
_CONSERVATIVE_PIV_CAPABILITIES: DeviceCapabilities = DeviceCapabilities(
    rsa_key_sizes=(2048,),
    can_generate_onboard=False,
)

# Консервативный OpenPGP — стандартные возможности без проверки чипа
_CONSERVATIVE_OPENPGP_CAPABILITIES: DeviceCapabilities = DeviceCapabilities(
    rsa_key_sizes=(2048, 3072, 4096),
    ecc_curves=("P256", "P384"),
    ed25519_openpgp=True,
    x25519_openpgp=True,
    can_generate_onboard=False,
    has_openpgp=True,
)


# ==============================================================================
# ATR DATABASE
# ==============================================================================
# Источники:
#   - PC/SC Workgroup ATR Database v3.3.0 (pcscworkgroup.com)
#   - NXP JCOP4 P71 Datasheet (NXP документация)
#   - JCAlgTest results (github.com/crocs-muni/JCAlgTest)
#   - OpenPGP card spec 3.4 (gnupg.org/ftp/specs/OpenPGP-smart-card-application-3.4.pdf)
#
# Добавление нового ATR:
#   1. Получить ATR через pcsc_scan или opensc-tool --atr
#   2. Проверить возможности через JCAlgTest или AlgTest
#   3. Добавить строку в словарь ниже

_ATR_DATABASE: dict[bytes, CardProfile] = {
    # ── NXP JCOP4 P71 (используется в J3R200 / ThinkTrust) ──────────────────
    # ATR: 3B FA 13 00 00 91 01 31 FE 45 00 31 C1 73 C8 40 00 00 90 00 68
    # Verified: RSA-2048/3072/4096 YES; ECC: NO (AlgTest JCOP4)
    bytes.fromhex("3BFA130000910131FE450031C173C8400000900068"): CardProfile(
        card_type="piv",
        manufacturer="NXP",
        chip="JCOP4 P71",
        capabilities=_J3R200_CAPABILITIES,
        detected_via="atr",
    ),
    # JCOP4 P71 — вариант с другими историческими байтами
    bytes.fromhex("3BFA130000910131FE450031807300C0400090006B"): CardProfile(
        card_type="piv",
        manufacturer="NXP",
        chip="JCOP4 P71 (variant B)",
        capabilities=_J3R200_CAPABILITIES,
        detected_via="atr",
    ),
    # ── NXP JCOP3 P60 ────────────────────────────────────────────────────────
    # Используется в ряде PIV-смарткарт. RSA-2048 + ECC P-256/P-384.
    bytes.fromhex("3BF81300008131FE454A434F503331B0"): CardProfile(
        card_type="piv",
        manufacturer="NXP",
        chip="JCOP3 P60",
        capabilities=DeviceCapabilities(
            rsa_key_sizes=(2048,),
            ecc_curves=("P256", "P384"),
            can_generate_onboard=True,
        ),
        detected_via="atr",
    ),
    # ── Infineon SLE97144 (PIV) ───────────────────────────────────────────────
    bytes.fromhex("3B7D960080318065B0831102E183009000"): CardProfile(
        card_type="piv",
        manufacturer="Infineon",
        chip="SLE97144",
        capabilities=DeviceCapabilities(
            rsa_key_sizes=(2048,),
            ecc_curves=("P256", "P384"),
            can_generate_onboard=True,
        ),
        detected_via="atr",
    ),
    # ── Gnuk Token (STM32F103, FSF Japan) — OpenPGP ──────────────────────────
    # Ed25519 + X25519 + RSA-2048 (через SmartPGP расширение)
    bytes.fromhex("3BDA18FF81B1FE751F03004139004E00"): CardProfile(
        card_type="openpgp",
        manufacturer="FSF Japan",
        chip="Gnuk (STM32)",
        capabilities=_CONSERVATIVE_OPENPGP_CAPABILITIES,
        detected_via="atr",
    ),
    # ── Fidesmo / Generic ISO 7816 OpenPGP ───────────────────────────────────
    bytes.fromhex("3B80800101"): CardProfile(
        card_type="openpgp",
        manufacturer="Generic",
        chip="OpenPGP (ISO 7816)",
        capabilities=_CONSERVATIVE_OPENPGP_CAPABILITIES,
        detected_via="atr",
    ),
}

# ==============================================================================
# ATR / AID DETECTION HELPERS
# ==============================================================================


def _select_aid(connection: Any, aid: bytes) -> bool:
    """
    Отправить SELECT AID APDU и вернуть True при SW=9000.

    APDU: CLA=0x00 INS=0xA4 P1=0x04 P2=0x00 Lc=len(aid) AID Le=0x00

    Args:
        connection: Активное ``CardConnection`` (pyscard).
        aid:        AID для SELECT.

    Returns:
        ``True`` если карта ответила SW1=0x90 SW2=0x00.

    Example:
        >>> _select_aid(conn, _OPENPGP_AID)
        True   # OpenPGP-карта
        >>> _select_aid(conn, _PIV_AID)
        False  # PIV-апплет не найден
    """
    apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid) + [0x00]  # Le
    try:
        _, sw1, sw2 = connection.transmit(apdu)
        return (sw1, sw2) == _SW_SUCCESS
    except Exception as exc:
        logger.debug("SELECT AID %s failed: %s", aid.hex().upper(), exc)
        return False


def _detect_card_profile(reader: Any, reader_name: str) -> CardProfile:
    """
    Определить профиль смарткарты через ATR и/или SELECT AID.

    Алгоритм:
    1. Подключиться к ридеру и получить ATR.
    2. Точный поиск в ``_ATR_DATABASE``.
    3. Если не найден — SELECT OpenPGP AID (D276000124).
    4. Если не найден — SELECT PIV AID (A000000308).
    5. Fallback: имя ридера как подстрока (ненадёжно, логируется с WARNING).

    Соединение всегда закрывается в ``finally`` — без утечек дескрипторов.

    Args:
        reader:      Объект ридера из ``sc_readers()``.
        reader_name: Строковое имя ридера (для логов).

    Returns:
        ``CardProfile`` с определёнными типом и возможностями.
        Никогда не выбрасывает исключений — все ошибки перехватываются
        и возвращается консервативный ``CardProfile``.

    Example:
        >>> profile = _detect_card_profile(reader, "HID Global OMNIKEY 3121 0")
        >>> profile.detected_via
        'atr'
        >>> profile.chip
        'JCOP4 P71'
    """
    connection = None
    try:
        connection = reader.createConnection()
        connection.connect()

        # 1. ATR — точный поиск в базе
        atr_raw: list[int] = connection.getATR()
        atr_bytes = bytes(atr_raw)
        logger.debug(
            "Reader '%s' ATR: %s",
            reader_name,
            atr_bytes.hex().upper(),
        )

        profile = _ATR_DATABASE.get(atr_bytes)
        if profile is not None:
            logger.debug(
                "Reader '%s': ATR match → chip=%s, type=%s",
                reader_name,
                profile.chip,
                profile.card_type,
            )
            return profile

        logger.debug(
            "Reader '%s': ATR %s not in database, trying AID SELECT",
            reader_name,
            atr_bytes.hex().upper(),
        )

        # 2. SELECT OpenPGP AID
        if _select_aid(connection, _OPENPGP_AID):
            logger.debug(
                "Reader '%s': OpenPGP AID confirmed (SW=9000)",
                reader_name,
            )
            return CardProfile(
                card_type="openpgp",
                capabilities=_CONSERVATIVE_OPENPGP_CAPABILITIES,
                detected_via="aid_openpgp",
            )

        # 3. SELECT PIV AID
        if _select_aid(connection, _PIV_AID):
            logger.debug(
                "Reader '%s': PIV AID confirmed (SW=9000)",
                reader_name,
            )
            return CardProfile(
                card_type="piv",
                capabilities=_CONSERVATIVE_PIV_CAPABILITIES,
                detected_via="aid_piv",
            )

        # 4. Fallback — имя ридера (ненадёжно)
        logger.warning(
            "Reader '%s': ATR=%s unknown, AID SELECT failed. "
            "Using name-based fallback (unreliable). "
            "Consider adding ATR to _ATR_DATABASE.",
            reader_name,
            atr_bytes.hex().upper(),
        )
        card_type: SmartcardType = "openpgp" if "openpgp" in reader_name.lower() else "piv"
        return CardProfile(
            card_type=card_type,
            capabilities=_make_smartcard_capabilities(card_type),
            detected_via="name_fallback",
        )

    except Exception as exc:
        _card_exc = tuple(e for e in (CardConnectionException, NoCardException) if e is not None)
        _is_no_card = bool(_card_exc) and isinstance(exc, _card_exc)
        if _is_no_card:
            # Ридер присутствует, карта не вставлена — не ошибка
            logger.debug("No card in reader '%s': %s", reader_name, exc)
            return CardProfile(
                card_type="piv",
                capabilities=_CONSERVATIVE_PIV_CAPABILITIES,
                detected_via="name_fallback",
            )
        logger.warning(
            "ATR/AID detection failed for reader '%s': %s. "
            "Falling back to conservative PIV capabilities.",
            reader_name,
            exc,
        )
        card_type = "openpgp" if "openpgp" in reader_name.lower() else "piv"
        return CardProfile(
            card_type=card_type,
            capabilities=_make_smartcard_capabilities(card_type),
            detected_via="name_fallback",
        )
    finally:
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:
                logger.debug("Failed to disconnect smartcard connection during cleanup")


def _make_smartcard_capabilities(card_type: SmartcardType) -> DeviceCapabilities:
    """
    Консервативные возможности для смарткарты без ATR-detection.

    RSA-2048 — единственный алгоритм, гарантированный спецификацией
    NIST SP 800-73 без проверки конкретного чипа через AlgTest/ATR.

    ВАЖНО: J3R200 (JCOP4 P71) не поддерживает ECC вообще — все EC-операции
    по AlgTest возвращают «no». При наличии ATR-based detection
    этот фолбэк заменяется реальными данными чипа.

    Args:
        card_type: Тип смарткарты.

    Returns:
        Консервативные ``DeviceCapabilities``.
    """
    if card_type == "openpgp":
        return DeviceCapabilities(
            rsa_key_sizes=(2048, 3072, 4096),
            ecc_curves=("P256", "P384"),  # ← исправлено
            ed25519_openpgp=True,
            x25519_openpgp=True,
            can_generate_onboard=False,
            has_openpgp=True,
        )
    return DeviceCapabilities(
        rsa_key_sizes=(2048,),
        can_generate_onboard=False,
    )


def _piv_algorithms_for_fw(fw: tuple[int, int, int] | None) -> tuple[str, ...]:
    """
    PIV-алгоритмы по версии прошивки YubiKey (устаревший хелпер).

    Для новых вызовов предпочтите ``_make_yubikey_capabilities(fw).piv_algorithms``.
    Оставлен для обратной совместимости внутри модуля.

    Example:
        >>> _piv_algorithms_for_fw((5, 2, 4))
        ('RSA-2048', 'ECC-P256', 'ECC-P384')
        >>> _piv_algorithms_for_fw((5, 7, 2))
        ('RSA-2048', 'ECC-P256', 'ECC-P384', 'RSA-3072', 'RSA-4096', 'Ed25519', 'X25519')
    """
    if fw is None:
        return ("RSA-2048", "ECC-P256", "ECC-P384")
    return _make_yubikey_capabilities(fw).piv_algorithms


_ = _piv_algorithms_for_fw  # retain: backward-compat helper, suppress unused warning


# ==============================================================================
# INTERNAL: ENUMERATION CACHE  [EC — новый dataclass]
# ==============================================================================


@dataclass
class _EnumerationCache:
    """
    Кеш результатов перечисления устройств с TTL.

    Снижает USB-опросы при повторных вызовах list_devices().
    """

    devices: list[SmartcardInfo]
    errors: list[Exception]
    timestamp: float
    ttl: float = 3.0  # секунды

    @property
    def is_fresh(self) -> bool:
        """Кеш актуален, если не истёк TTL."""
        return (time.monotonic() - self.timestamp) < self.ttl


# ==============================================================================
# EXTERNAL KEYPAIR  [E1]
# ==============================================================================


class ExternalKeypair:
    """
    Ключевая пара, сгенерированная вне аппаратного устройства.

    Хранит приватный ключ как mutable ``bytearray``. Реализует контекстный
    менеджер и ``__del__`` для автоматического обнуления::

        with manager.generate_keypair_external("ECC-P256") as kp:
            manager.import_key_to_device(card_id, slot, bytes(kp.private_key_der), pin)
        # private_key_der обнулён автоматически

    Attributes:
        private_key_der: Приватный ключ DER/PKCS#8 (mutable bytearray).
        public_key_der:  Публичный ключ DER/SubjectPublicKeyInfo (bytes).

    Raises:
        TypeError: Если ``private_key_der`` не является ``bytearray``.
    """

    __slots__ = ("private_key_der", "public_key_der", "_wiped")

    def __init__(self, private_key_der: bytearray, public_key_der: bytes) -> None:
        if not isinstance(private_key_der, bytearray):
            raise TypeError(
                f"private_key_der must be bytearray, got {type(private_key_der).__name__}"
            )
        self.private_key_der: bytearray = private_key_der
        self.public_key_der: bytes = public_key_der
        self._wiped: bool = False

    def wipe(self) -> None:
        """
        Обнулить приватный ключ в памяти. Идемпотентен.

        После вызова ``private_key_der`` заполнен нулевыми байтами.
        """
        if not self._wiped and self.private_key_der:
            self.private_key_der[:] = bytes(len(self.private_key_der))
            self._wiped = True

    def __enter__(self) -> ExternalKeypair:
        return self

    def __exit__(self, *_: object) -> None:
        self.wipe()

    def __del__(self) -> None:
        """Страховка: обнуляет ключ при сборке мусора если wipe() не вызван."""
        self.wipe()

    def __repr__(self) -> str:
        status = "wiped" if self._wiped else f"{len(self.private_key_der)}B"
        return (
            f"ExternalKeypair("
            f"private_key_der=<{status}>, "
            f"public_key_der={len(self.public_key_der)}B)"
        )


# ==============================================================================
# SMARTCARD INFO DATACLASS
# ==============================================================================


@dataclass(frozen=True)
class SmartcardInfo:
    """
    Информация об аппаратном криптографическом устройстве.

    Frozen dataclass — неизменяемый после создания. Все коллекции хранятся
    как ``tuple`` или ``frozenset`` для полной иммутабельности.

    Attributes:
        card_id:              Уникальный идентификатор (1–128 символов).
        card_type:            Основной протокол ("piv", "openpgp", "yubikey_piv").
        key_generation:       Способ генерации ключей.
        available_slots:      PIV-слоты в детерминированном порядке.
        algorithms_supported: Все доступные алгоритмы через все протоколы.
                              Для YubiKey включает OpenPGP-алгоритмы.
        protocols:            Все включённые протоколы устройства.
                              YubiKey: {"piv", "openpgp", "fido2", "oath", "otp"}.
        capabilities:         Структурированные возможности (``DeviceCapabilities``).
                              ``None`` для устройств без ATR-detection.
        requires_pin:         Требуется ли PIN.
        manufacturer:         Производитель.
        serial_number:        Серийный номер (если доступен).
        firmware_version:     Версия прошивки (если доступна).

    Raises:
        ValueError: Если card_id пустой или длиннее 128 символов.

    Example:
        >>> info = SmartcardInfo(
        ...     card_id="yubikey_10620473",
        ...     card_type="yubikey_piv",
        ...     key_generation="onboard",
        ... )
        >>> "yubikey_10620473".startswith("yubikey_")
        True
    """

    card_id: str
    card_type: SmartcardType
    key_generation: KeyGenerationCapability
    available_slots: tuple[int, ...] = field(default_factory=tuple)
    algorithms_supported: tuple[str, ...] = field(default_factory=tuple)
    protocols: frozenset[str] = field(default_factory=frozenset)  # [MP]
    capabilities: DeviceCapabilities | None = None  # [DC]
    requires_pin: bool = True
    manufacturer: str = "Unknown"
    serial_number: str | None = None
    firmware_version: str | None = None

    def __post_init__(self) -> None:
        """
        Raises:
            ValueError: Если card_id пустой или превышает 128 символов.
        """
        if not self.card_id or not self.card_id.strip():
            raise ValueError("SmartcardInfo.card_id не может быть пустым")
        if len(self.card_id) > 128:
            raise ValueError(
                f"SmartcardInfo.card_id слишком длинный: {len(self.card_id)} > 128 символов"
            )


# ==============================================================================
# HARDWARE CRYPTO MANAGER
# ==============================================================================


class HardwareCryptoManager:
    """
    Менеджер аппаратных криптографических устройств.

    Единый интерфейс для PIV-смарткарт и YubiKey. Все операции выполняются
    на устройстве — приватный ключ никогда не покидает аппаратный модуль.

    Thread Safety:
        ``dict[str, RLock]`` — отдельный лок на каждое устройство.
        Два потока, работающих с разными устройствами, не блокируют друг друга.
        ``_global_lock`` — только для enumeration cache и регистрации локов.

    Enumeration Cache:
        ``list_devices()`` кеширует результаты USB-опроса (TTL=3 с).
        Повторные вызовы не инициируют физическое перечисление.
        Для принудительного обновления: ``list_devices(force_refresh=True)``
        или ``invalidate_cache()``.

    Example:
        >>> manager = HardwareCryptoManager()
        >>> print(manager)
        HardwareCryptoManager(pyscard=✓, ykman=✓, tracked_devices=0, cache=stale)
        >>> devices = manager.list_devices()
    """

    def __init__(self) -> None:
        """Инициализация менеджера. Зависимости проверяются лениво."""
        self._global_lock = threading.RLock()
        self._device_locks: dict[str, threading.RLock] = {}
        self._enum_cache: _EnumerationCache | None = None  # [EC]
        logger.info("HardwareCryptoManager initialized")

    # ------------------------------------------------------------------
    # REPR  [R1]
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        pyscard = "✓" if has_pyscard else "✗"
        ykman = "✓" if has_ykman else "✗"
        with self._global_lock:
            tracked = len(self._device_locks)
            cache_state = (
                "fresh" if self._enum_cache is not None and self._enum_cache.is_fresh else "stale"
            )
        return (
            f"HardwareCryptoManager("
            f"pyscard={pyscard}, ykman={ykman}, "
            f"tracked_devices={tracked}, cache={cache_state})"
        )

    # ------------------------------------------------------------------
    # PER-DEVICE LOCKING  [L1]
    # ------------------------------------------------------------------

    def _get_device_lock(self, card_id: str) -> threading.RLock:
        """Получить или создать RLock для конкретного устройства."""
        with self._global_lock:
            if card_id not in self._device_locks:
                self._device_locks[card_id] = threading.RLock()
            return self._device_locks[card_id]

    # ------------------------------------------------------------------
    # DEPENDENCY CHECKS
    # ------------------------------------------------------------------

    @staticmethod
    def _ensure_pyscard() -> None:
        """Raises: AlgorithmNotAvailableError если pyscard не установлен."""
        if not has_pyscard:
            raise AlgorithmNotAvailableError(
                algorithm="Smartcard (PIV/OpenPGP)",
                reason=(
                    "pyscard library is required for smartcard operations. "
                    "Install: pip install pyscard>=2.0.0"
                ),
                required_library="pyscard>=2.0.0",
            )

    @staticmethod
    def _ensure_ykman() -> None:
        """Raises: AlgorithmNotAvailableError если yubikey-manager не установлен."""
        if not has_ykman:
            raise AlgorithmNotAvailableError(
                algorithm="YubiKey (PIV)",
                reason=(
                    "yubikey-manager library is required for YubiKey operations. "
                    "Install: pip install yubikey-manager>=5.0.0"
                ),
                required_library="yubikey-manager>=5.0.0",
            )

    # ------------------------------------------------------------------
    # SLOT VALIDATION
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_piv_slot(slot: int) -> None:
        """Raises: SlotError для недопустимого номера слота."""
        if slot not in PIV_VALID_SLOTS:
            valid = ", ".join(f"0x{s:02X}" for s in sorted(PIV_VALID_SLOTS))
            raise SlotError(
                device_id="(validation)",
                slot=slot,
                reason=f"Invalid PIV slot. Valid slots: {valid}",
            )

    # ------------------------------------------------------------------
    # DEVICE ENUMERATION  [EC, SM]
    # ------------------------------------------------------------------

    def list_devices(
        self, *, strict: bool = False, force_refresh: bool = False
    ) -> list[SmartcardInfo]:
        """
        Получить список подключённых аппаратных устройств.

        Результаты кешируются (TTL=3 с). Повторные вызовы не выполняют
        USB-перечисление до истечения кеша или явного сброса.

        Args:
            strict:        Если ``True`` — выбрасывает
                           ``DeviceCommunicationError`` при любой ошибке
                           перечисления. Если ``False`` (по умолчанию) —
                           ошибки логируются с ``WARNING``, устройства
                           из успешных источников возвращаются.
            force_refresh: Принудительно обновить кеш, игнорируя TTL.

        Returns:
            Список ``SmartcardInfo``.

        Raises:
            DeviceCommunicationError: Только при ``strict=True`` и ошибках.

        Example:
            >>> devices = manager.list_devices()
            >>> devices = manager.list_devices(strict=True)   # ошибки — исключение
            >>> devices = manager.list_devices(force_refresh=True)
        """
        # Быстрая проверка кеша под локом (только чтение)
        with self._global_lock:
            if not force_refresh and self._enum_cache is not None and self._enum_cache.is_fresh:
                if strict and self._enum_cache.errors:
                    raise DeviceCommunicationError(
                        device_id="(enumeration)",
                        reason=(
                            f"{len(self._enum_cache.errors)} error(s) during "
                            f"last enumeration: {self._enum_cache.errors[0]}"
                        ),
                    )
                return list(self._enum_cache.devices)

        # USB-опрос БЕЗ лока — не блокирует операции с устройствами
        all_devices: list[SmartcardInfo] = []
        all_errors: list[Exception] = []

        sc_devices, sc_errors = self._list_smartcards()
        all_devices.extend(sc_devices)
        all_errors.extend(sc_errors)

        yk_devices, yk_errors = self._list_yubikeys()
        all_devices.extend(yk_devices)
        all_errors.extend(yk_errors)

        # Запись кеша под локом с повторной проверкой (другой поток мог успеть)
        with self._global_lock:
            if self._enum_cache is None or not self._enum_cache.is_fresh or force_refresh:
                self._enum_cache = _EnumerationCache(
                    devices=all_devices,
                    errors=all_errors,
                    timestamp=time.monotonic(),
                )
            else:
                # Другой поток уже обновил кеш — возвращаем его результат
                if strict and self._enum_cache.errors:
                    raise DeviceCommunicationError(
                        device_id="(enumeration)",
                        reason=(
                            f"{len(self._enum_cache.errors)} error(s) during "
                            f"last enumeration: {self._enum_cache.errors[0]}"
                        ),
                    )
                return list(self._enum_cache.devices)

        if all_errors:
            logger.warning(
                "Enumeration completed with %d error(s): %s",
                len(all_errors),
                all_errors,
            )

        if strict and all_errors:
            raise DeviceCommunicationError(
                device_id="(enumeration)",
                reason=(f"{len(all_errors)} error(s) during enumeration: {all_errors[0]}"),
            )

        logger.info("Found %d hardware device(s)", len(all_devices))
        return list(all_devices)

    def invalidate_cache(self) -> None:
        """
        Принудительно инвалидировать кеш enumeration.

        Следующий вызов ``list_devices()`` выполнит полное USB-перечисление.
        Используйте при подключении или отключении устройств.
        """
        with self._global_lock:
            self._enum_cache = None
        logger.debug("Enumeration cache invalidated")

    def _list_smartcards(
        self,
    ) -> tuple[list[SmartcardInfo], list[Exception]]:
        """
        Перечислить смарткарты через PC/SC с ATR-based detection.

        Для каждого ридера вызывает ``_detect_card_profile()`` — ATR → AID → fallback.
        Ошибки отдельных ридеров не прерывают перечисление остальных.

        Returns:
            ``(devices, errors)`` — частичный результат при ошибках.
        """
        if not has_pyscard or sc_readers is None:
            return [], []

        result: list[SmartcardInfo] = []
        errors: list[Exception] = []
        detected_via_counts: dict[str, int] = {
            "atr": 0,
            "aid_openpgp": 0,
            "aid_piv": 0,
            "name_fallback": 0,
        }

        try:
            available_readers: list[Any] = sc_readers()
        except Exception as exc:
            logger.warning("PC/SC enumeration failed: %s", exc)
            return [], [exc]

        for idx, reader in enumerate(available_readers):
            reader_name = str(reader)

            try:
                profile = _detect_card_profile(reader, reader_name)
            except Exception as exc:
                logger.warning(
                    "Unexpected error detecting reader '%s': %s",
                    reader_name,
                    exc,
                )
                errors.append(exc)
                continue

            detected_via_counts[profile.detected_via] = (
                detected_via_counts.get(profile.detected_via, 0) + 1
            )

            card_id = f"sc_{idx}_{reader_name[:20]}"
            protocols: frozenset[str] = (
                frozenset({"openpgp"}) if profile.card_type == "openpgp" else frozenset({"piv"})
            )

            info = SmartcardInfo(
                card_id=card_id,
                card_type=profile.card_type,
                key_generation=(
                    "onboard" if profile.capabilities.can_generate_onboard else "external"
                ),
                available_slots=(
                    tuple(sorted(PIV_VALID_SLOTS)) if profile.card_type == "piv" else ()
                ),
                algorithms_supported=profile.capabilities.all_algorithms,
                protocols=protocols,
                capabilities=profile.capabilities,
                requires_pin=True,
                manufacturer=profile.manufacturer,
            )
            result.append(info)

        logger.debug(
            "Found %d smartcard reader(s) "
            "[ATR: %d, AID-OpenPGP: %d, AID-PIV: %d, name-fallback: %d]",
            len(result),
            detected_via_counts["atr"],
            detected_via_counts["aid_openpgp"],
            detected_via_counts["aid_piv"],
            detected_via_counts["name_fallback"],
        )
        return result, errors

    @staticmethod
    def _get_yubikey_protocols(dev_info: Any) -> frozenset[str]:
        """
        Определить активные протоколы YubiKey из ``dev_info.config.enabled_capabilities``.

        Объединяет USB + NFC bitmask (оба транспорта), маппит биты
        ``CAPABILITY`` → строковые имена протоколов.

        Fallback ``{"piv", "openpgp", "fido2", "oath", "otp"}`` при:
        - yubikit.management недоступен (``YK_CAPABILITY is None``);
        - ``dev_info.config is None``;
        - ``enabled_capabilities`` пустой;
        - неожиданное исключение.

        Args:
            dev_info: Объект ``DeviceInfo`` из ``yk_list_all()``.

        Returns:
            ``frozenset[str]`` активных протоколов.

        Example:
            >>> # YubiKey 5 NFC SN 10620473 FW 5.2.4 — все протоколы включены:
            >>> HardwareCryptoManager._get_yubikey_protocols(dev_info)
            frozenset({'fido2', 'oath', 'openpgp', 'otp', 'piv'})
            >>> # YubiKey FIPS (PIV only):
            >>> HardwareCryptoManager._get_yubikey_protocols(dev_info_fips)
            frozenset({'piv'})
        """
        _FALLBACK: frozenset[str] = frozenset({"piv", "openpgp", "fido2", "oath", "otp"})

        if YK_CAPABILITY is None or YK_TRANSPORT is None:
            logger.debug(
                "_get_yubikey_protocols: yubikit.management недоступен, используется fallback"
            )
            return _FALLBACK

        try:
            config = dev_info.config
            if config is None:
                logger.debug("_get_yubikey_protocols: dev_info.config=None, fallback")
                return _FALLBACK

            enabled: dict[Any, int] = config.enabled_capabilities
            if not enabled:
                logger.debug("_get_yubikey_protocols: enabled_capabilities пустой, fallback")
                return _FALLBACK

            # Объединяем USB + NFC: устройство поддерживает протокол если он
            # включён хотя бы на одном транспорте
            combined_caps: int = 0
            for transport_caps in enabled.values():
                combined_caps |= int(transport_caps)

            # Маппинг CAPABILITY бит → имя протокола
            # yubikit.management.CAPABILITY — IntFlag, значения:
            # OTP=0x001, U2F=0x002, OPENPGP=0x008, PIV=0x010,
            # OATH=0x020, FIDO2=0x200, HSMAUTH=0x100
            cap_map: dict[str, int] = {
                "piv": int(YK_CAPABILITY.PIV),
                "openpgp": int(YK_CAPABILITY.OPENPGP),
                "fido2": int(YK_CAPABILITY.FIDO2),
                "oath": int(YK_CAPABILITY.OATH),
                "otp": int(YK_CAPABILITY.OTP),
            }

            protocols: set[str] = {name for name, bit in cap_map.items() if combined_caps & bit}

            if not protocols:
                # Есть capabilities, но ни один из известных битов не установлен
                # (например, будущий YubiKey с новыми протоколами)
                logger.warning(
                    "_get_yubikey_protocols: нет известных протоколов "
                    "в enabled_capabilities=0x%04X, fallback",
                    combined_caps,
                )
                return _FALLBACK

            logger.debug(
                "_get_yubikey_protocols: %s (caps=0x%04X)",
                sorted(protocols),
                combined_caps,
            )
            return frozenset(protocols)

        except AttributeError as exc:
            # Старые версии yubikit без .config.enabled_capabilities
            logger.debug("_get_yubikey_protocols: AttributeError (%s), fallback", exc)
            return _FALLBACK
        except Exception as exc:
            logger.warning("_get_yubikey_protocols: неожиданная ошибка (%s), fallback", exc)
            return _FALLBACK

    def _list_yubikeys(
        self,
    ) -> tuple[list[SmartcardInfo], list[Exception]]:
        """
        Перечислить YubiKey через ykman с FW-aware возможностями и
        точным определением протоколов через ``enabled_capabilities``.

        Returns:
            ``(devices, errors)`` — частичный результат при ошибках.
        """
        if not has_ykman or yk_list_all is None:
            return [], []

        result: list[SmartcardInfo] = []
        errors: list[Exception] = []

        try:
            for _device, dev_info in yk_list_all():
                serial = str(dev_info.serial) if dev_info.serial else None
                fw = self._parse_fw_version(dev_info)
                fw_str = ".".join(map(str, fw)) if fw != (0, 0, 0) else None

                caps = _make_yubikey_capabilities(fw)

                protocols = self._get_yubikey_protocols(dev_info)

                info = SmartcardInfo(
                    card_id=f"yubikey_{serial or 'unknown'}",
                    card_type="yubikey_piv",
                    key_generation="onboard",
                    available_slots=tuple(sorted(PIV_VALID_SLOTS)),
                    algorithms_supported=caps.all_algorithms,
                    protocols=protocols,
                    capabilities=caps,
                    requires_pin=True,
                    manufacturer="Yubico",
                    serial_number=serial,
                    firmware_version=fw_str,
                )
                result.append(info)

            logger.debug("Found %d YubiKey(s)", len(result))

        except Exception as exc:
            logger.warning("Error listing YubiKeys: %s", exc)
            errors.append(exc)

        return result, errors

    # ------------------------------------------------------------------
    # KEY GENERATION — EXTERNAL
    # ------------------------------------------------------------------

    def generate_keypair_external(
        self,
        algorithm: str,
        key_size: int | None = None,
    ) -> ExternalKeypair:
        """
        Генерация ключевой пары ВНЕ устройства.

        Args:
            algorithm: Алгоритм ("RSA-2048", "RSA-3072", "RSA-4096",
                       "ECC-P256", "ECC-P384").
            key_size:  Размер RSA-ключа (если не задан суффиксом algorithm).
                       Для ECC игнорируется с предупреждением.

        Returns:
            ``ExternalKeypair`` — используйте как контекстный менеджер.

        Raises:
            KeyGenerationError: Ошибка генерации.
            InvalidKeyError:    Неподдерживаемый алгоритм.

        Example:
            >>> with manager.generate_keypair_external("ECC-P256") as kp:
            ...     manager.import_key_to_device(card_id, 0x9C, bytes(kp.private_key_der), pin)
        """
        return self._generate_keypair_external(algorithm, key_size)

    def _generate_keypair_external(
        self,
        algorithm: str,
        key_size: int | None,
    ) -> ExternalKeypair:
        algo_upper = algorithm.upper()
        logger.info(
            "Generating external keypair: algorithm=%s, key_size=%s",
            algorithm,
            key_size,
        )

        try:
            private_key: _PrivateKeyType

            if algo_upper.startswith("RSA"):
                parts = algo_upper.split("-")
                if len(parts) >= 2 and parts[-1].isdigit():
                    key_size = int(parts[-1])
                elif key_size is None:
                    key_size = 2048

                if key_size not in (2048, 3072, 4096):
                    raise InvalidKeyError(
                        f"Unsupported RSA key size: {key_size}. Supported: 2048, 3072, 4096",
                        algorithm=algorithm,
                    )
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                )

            elif algo_upper in ("ECC-P256", "ECC-P-256", "P-256", "P256"):
                if key_size is not None:
                    logger.warning(
                        "key_size=%d ignored for ECC algorithm %s "
                        "(curve size is fixed by algorithm name)",
                        key_size,
                        algorithm,
                    )
                private_key = ec.generate_private_key(ec.SECP256R1())

            elif algo_upper in ("ECC-P384", "ECC-P-384", "P-384", "P384"):
                if key_size is not None:
                    logger.warning(
                        "key_size=%d ignored for ECC algorithm %s "
                        "(curve size is fixed by algorithm name)",
                        key_size,
                        algorithm,
                    )
                private_key = ec.generate_private_key(ec.SECP384R1())

            else:
                raise InvalidKeyError(
                    f"Unsupported algorithm: {algorithm}. "
                    "Supported: RSA-2048, RSA-3072, RSA-4096, ECC-P256, ECC-P384",
                    algorithm=algorithm,
                )

            private_der = bytearray(
                private_key.private_bytes(
                    encoding=Encoding.DER,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption(),
                )
            )
            public_der = private_key.public_key().public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo,
            )

            logger.info("External keypair generated: algorithm=%s", algorithm)
            return ExternalKeypair(
                private_key_der=private_der,
                public_key_der=public_der,
            )

        except (InvalidKeyError, AlgorithmNotAvailableError):
            raise
        except Exception as exc:
            logger.error("Key generation failed: %s", exc)
            raise KeyGenerationError(
                f"Failed to generate keypair for {algorithm}: {exc}",
                algorithm=algorithm,
            ) from exc

    # ------------------------------------------------------------------
    # KEY GENERATION — ONBOARD
    # ------------------------------------------------------------------

    def generate_keypair_onboard(
        self,
        card_id: str,
        slot: int,
        algorithm: str,
        pin: str,
    ) -> bytes:
        """
        Генерация ключевой пары ВНУТРИ устройства (YubiKey).

        Приватный ключ генерируется аппаратным RNG и остаётся на устройстве.

        Ограничения прошивки (PIV):
            - FW < 5.7: только RSA-2048, ECC-P256, ECC-P384
            - FW 5.7+: + RSA-3072, RSA-4096, Ed25519, X25519
            - Ed25519 на FW 5.2.x: только через OpenPGP (Phase 1 roadmap)

        Args:
            card_id:   Идентификатор YubiKey ("yubikey_10620473").
            slot:      PIV-слот (0x9A, 0x9C, 0x9D, 0x9E).
            algorithm: Алгоритм ("RSA-2048", "ECC-P256", "ECC-P384").
            pin:       PIN-код (не сохраняется).

        Returns:
            Публичный ключ DER/SubjectPublicKeyInfo.

        Raises:
            AlgorithmNotAvailableError: yubikey-manager не установлен или
                                        алгоритм недоступен для данного FW.
            DeviceNotFoundError:        YubiKey не найден.
            PINError:                   Неверный PIN.
            SlotError:                  Недопустимый слот.
            KeyGenerationError:         Ошибка генерации.
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)
        with self._get_device_lock(card_id):
            return self._generate_keypair_onboard(card_id, slot, algorithm, pin)

    def _generate_keypair_onboard(
        self,
        card_id: str,
        slot: int,
        algorithm: str,
        pin: str,
    ) -> bytes:
        logger.info(
            "Generating onboard keypair: card=%s, slot=0x%02X, algorithm=%s",
            card_id,
            slot,
            algorithm,
        )

        with self._open_yubikey(card_id) as (yk_device, yk_info):
            fw = self._parse_fw_version(yk_info)
            if algorithm.upper() in _PIV_FW57_ALGORITHMS and fw < (5, 7, 0):
                fw_str = ".".join(map(str, fw))
                raise AlgorithmNotAvailableError(
                    algorithm=algorithm,
                    reason=(
                        f"Algorithm '{algorithm}' requires YubiKey firmware 5.7.0+ "
                        f"in PIV mode. Device '{card_id}' has firmware {fw_str}. "
                        f"For Ed25519 on FW 5.2.x — use OpenPGP slot "
                        f"(planned: Phase 1 roadmap)."
                    ),
                    required_library=(f"YubiKey firmware 5.7.0+ (current: {fw_str})"),
                )

            try:
                assert PivSession is not None  # guarded by has_ykman
                piv_session = PivSession(yk_device)
                piv_session.verify_pin(pin)

                key_type = self._resolve_yk_key_type(algorithm)
                piv_slot = self._resolve_yk_slot(slot)

                public_key = piv_session.generate_key(
                    slot=piv_slot,
                    key_type=key_type,
                )

                public_der: bytes = public_key.public_bytes(
                    encoding=Encoding.DER,
                    format=PublicFormat.SubjectPublicKeyInfo,
                )

                logger.info(
                    "Onboard keypair generated: card=%s, slot=0x%02X",
                    card_id,
                    slot,
                )
                return public_der

            except (PINError, AlgorithmNotAvailableError):
                raise
            except Exception as exc:
                logger.error(
                    "Onboard key generation failed: card=%s, error=%s",
                    card_id,
                    exc,
                )
                raise KeyGenerationError(
                    f"Failed to generate keypair on device '{card_id}': {exc}",
                    algorithm=algorithm,
                    context={"card_id": card_id, "slot": f"0x{slot:02X}"},
                ) from exc

    # ------------------------------------------------------------------
    # KEY IMPORT
    # ------------------------------------------------------------------

    def import_key_to_device(
        self,
        card_id: str,
        slot: int,
        private_key: bytes,
        pin: str,
    ) -> None:
        """
        Импортировать приватный ключ на устройство.

        Args:
            card_id:     Идентификатор устройства.
            slot:        PIV-слот (0x9A, 0x9C, 0x9D, 0x9E).
            private_key: Приватный ключ DER/PKCS#8.
            pin:         PIN-код (не сохраняется).

        Raises:
            AlgorithmNotAvailableError: yubikey-manager не установлен.
            DeviceNotFoundError:        Устройство не найдено.
            PINError:                   Неверный PIN.
            SlotError:                  Недопустимый слот.
            InvalidKeyError:            Некорректный формат ключа.
            HardwareDeviceError:        Ошибка импорта.

        Example:
            >>> with manager.generate_keypair_external("ECC-P256") as kp:
            ...     manager.import_key_to_device(
            ...         "yubikey_10620473", 0x9C, bytes(kp.private_key_der), "123456"
            ...     )
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)
        with self._get_device_lock(card_id):
            self._import_key_to_device(card_id, slot, private_key, pin)

    def _import_key_to_device(
        self,
        card_id: str,
        slot: int,
        private_key: bytes,
        pin: str,
    ) -> None:
        logger.info(
            "Importing key to device: card=%s, slot=0x%02X",
            card_id,
            slot,
        )

        with self._open_yubikey(card_id) as (yk_device, _):
            try:
                key_obj = load_der_private_key(private_key, password=None)

                if not isinstance(
                    key_obj,
                    (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey),
                ):
                    raise InvalidKeyError(
                        f"Unsupported key type for PIV import: "
                        f"{type(key_obj).__name__}. Supported: RSA, ECC (P-256, P-384)",
                        algorithm="PIV",
                    )

                assert PivSession is not None  # guarded by has_ykman
                piv_session = PivSession(yk_device)
                piv_session.verify_pin(pin)

                piv_slot = self._resolve_yk_slot(slot)
                piv_session.put_key(slot=piv_slot, private_key=key_obj)

                logger.info("Key imported: card=%s, slot=0x%02X", card_id, slot)

            except (PINError, InvalidKeyError):
                raise
            except ValueError as exc:
                raise InvalidKeyError(
                    f"Invalid private key format: {exc}",
                    algorithm="DER/PKCS#8",
                ) from exc
            except Exception as exc:
                logger.error("Key import failed: card=%s, error=%s", card_id, exc)
                raise HardwareDeviceError(
                    f"Failed to import key to device '{card_id}': {exc}",
                    device_id=card_id,
                    context={"slot": f"0x{slot:02X}"},
                ) from exc

    # ------------------------------------------------------------------
    # SIGNING ON DEVICE
    # ------------------------------------------------------------------

    def sign_with_device(
        self,
        card_id: str,
        slot: int,
        message: bytes,
        pin: str,
    ) -> bytes:
        """
        Подписать данные на аппаратном устройстве.

        Хеш выбирается автоматически по ключу в слоте:
        P-384 → SHA-384, остальные → SHA-256 (NIST SP 800-57).

        Args:
            card_id: Идентификатор устройства.
            slot:    PIV-слот с подписывающим ключом.
            message: Данные для подписи.
            pin:     PIN-код (не сохраняется).

        Returns:
            DER-подпись.

        Raises:
            AlgorithmNotAvailableError: yubikey-manager не установлен.
            DeviceNotFoundError:        Устройство не найдено.
            PINError:                   Неверный PIN.
            SlotError:                  Слот пуст или недопустим.
            HardwareDeviceError:        Ошибка подписи.

        Example:
            >>> sig = manager.sign_with_device("yubikey_10620473", 0x9C, b"data", "123456")
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)
        with self._get_device_lock(card_id):
            return self._sign_with_device(card_id, slot, message, pin)

    def _sign_with_device(
        self,
        card_id: str,
        slot: int,
        message: bytes,
        pin: str,
    ) -> bytes:
        logger.info(
            "Signing on device: card=%s, slot=0x%02X, message_len=%d",
            card_id,
            slot,
            len(message),
        )

        with self._open_yubikey(card_id) as (yk_device, _):
            try:
                assert PivSession is not None  # guarded by has_ykman
                piv_session = PivSession(yk_device)
                piv_session.verify_pin(pin)

                piv_slot = self._resolve_yk_slot(slot)
                slot_metadata = piv_session.get_slot_metadata(piv_slot)
                pub_key = slot_metadata.public_key
                if not isinstance(pub_key, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
                    raise InvalidKeyError(
                        f"Unsupported key type for signing: {type(pub_key).__name__}"
                    )
                hash_alg = self._get_hash_for_key_type(pub_key)

                signature: bytes = piv_session.sign(
                    slot=piv_slot,
                    key_type=slot_metadata.key_type,
                    message=message,
                    hash_algorithm=hash_alg,
                )

                logger.info(
                    "Signed on device: card=%s, slot=0x%02X, sig_len=%d",
                    card_id,
                    slot,
                    len(signature),
                )
                return signature

            except PINError:
                raise
            except Exception as exc:
                logger.error(
                    "Signing failed: card=%s, slot=0x%02X, error=%s",
                    card_id,
                    slot,
                    exc,
                )
                raise HardwareDeviceError(
                    f"Signing failed on device '{card_id}', slot 0x{slot:02X}: {exc}",
                    device_id=card_id,
                    context={"slot": f"0x{slot:02X}", "operation": "sign"},
                ) from exc

    # ------------------------------------------------------------------
    # DECRYPTION ON DEVICE
    # ------------------------------------------------------------------

    def decrypt_with_device(
        self,
        card_id: str,
        slot: int,
        ciphertext: bytes,
        pin: str,
    ) -> bytes:
        """
        Расшифровать данные на аппаратном устройстве (RSA-OAEP-SHA256).

        ECC-ключи не поддерживают прямую расшифровку. Используйте
        ``ecdh_with_device()`` (планируется: Phase 5 roadmap).

        Args:
            card_id:    Идентификатор устройства.
            slot:       PIV-слот с RSA-ключом (обычно 0x9D).
            ciphertext: Данные, зашифрованные RSA-OAEP(SHA-256).
            pin:        PIN-код (не сохраняется).

        Returns:
            Расшифрованные данные.

        Raises:
            InvalidKeyError:     Слот содержит ECC-ключ.
            HardwareDeviceError: Ошибка расшифровки.
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)
        with self._get_device_lock(card_id):
            return self._decrypt_with_device(card_id, slot, ciphertext, pin)

    def _decrypt_with_device(
        self,
        card_id: str,
        slot: int,
        ciphertext: bytes,
        pin: str,
    ) -> bytes:
        logger.info(
            "Decrypting on device: card=%s, slot=0x%02X, ct_len=%d",
            card_id,
            slot,
            len(ciphertext),
        )

        with self._open_yubikey(card_id) as (yk_device, _):
            try:
                assert PivSession is not None  # guarded by has_ykman
                piv_session = PivSession(yk_device)
                piv_session.verify_pin(pin)

                piv_slot = self._resolve_yk_slot(slot)
                slot_metadata = piv_session.get_slot_metadata(piv_slot)

                if isinstance(slot_metadata.public_key, ec.EllipticCurvePublicKey):
                    raise InvalidKeyError(
                        "ECC keys do not support direct decryption. "
                        "Use ECDH key agreement instead "
                        "(planned: ecdh_with_device(), Phase 5 roadmap).",
                        algorithm="ECC",
                    )

                plaintext: bytes = piv_session.decrypt(
                    slot=piv_slot,
                    cipher_text=ciphertext,
                    padding=asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                logger.info(
                    "Decrypted on device: card=%s, slot=0x%02X",
                    card_id,
                    slot,
                )
                return plaintext

            except (PINError, InvalidKeyError):
                raise
            except Exception as exc:
                logger.error(
                    "Decryption failed: card=%s, slot=0x%02X, error=%s",
                    card_id,
                    slot,
                    exc,
                )
                raise HardwareDeviceError(
                    f"Decryption failed on device '{card_id}', slot 0x{slot:02X}: {exc}",
                    device_id=card_id,
                    context={"slot": f"0x{slot:02X}", "operation": "decrypt"},
                ) from exc

    # ------------------------------------------------------------------
    # PUBLIC KEY RETRIEVAL
    # ------------------------------------------------------------------

    def get_public_key(
        self,
        card_id: str,
        slot: int,
    ) -> bytes:
        """
        Получить публичный ключ из слота. PIN не требуется.

        Args:
            card_id: Идентификатор устройства.
            slot:    PIV-слот (0x9A, 0x9C, 0x9D, 0x9E).

        Returns:
            Публичный ключ DER/SubjectPublicKeyInfo.

        Raises:
            SlotError: Слот пуст или не содержит ключ.

        Example:
            >>> pub = manager.get_public_key("yubikey_10620473", 0x9C)
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)
        with self._get_device_lock(card_id):
            return self._get_public_key(card_id, slot)

    def _get_public_key(self, card_id: str, slot: int) -> bytes:
        logger.info("Getting public key: card=%s, slot=0x%02X", card_id, slot)

        with self._open_yubikey(card_id) as (yk_device, _):
            try:
                assert PivSession is not None  # guarded by has_ykman
                piv_session = PivSession(yk_device)
                piv_slot = self._resolve_yk_slot(slot)
                slot_metadata = piv_session.get_slot_metadata(piv_slot)

                public_der: bytes = slot_metadata.public_key.public_bytes(
                    encoding=Encoding.DER,
                    format=PublicFormat.SubjectPublicKeyInfo,
                )

                logger.info(
                    "Public key retrieved: card=%s, slot=0x%02X, key_len=%d",
                    card_id,
                    slot,
                    len(public_der),
                )
                return public_der

            except Exception as exc:
                logger.error(
                    "Failed to get public key: card=%s, slot=0x%02X, error=%s",
                    card_id,
                    slot,
                    exc,
                )
                raise SlotError(
                    device_id=card_id,
                    slot=slot,
                    reason=f"Cannot read public key: {exc}",
                ) from exc

    # ------------------------------------------------------------------
    # YUBIKEY HMAC-SHA1 KDF
    # ------------------------------------------------------------------

    def derive_key_from_device(
        self,
        card_id: str,
        challenge: bytes,
        pin: str,
        *,
        hmac_slot: int = 2,
    ) -> bytes:
        """
        Вывести ключ через YubiKey HMAC-SHA1 Challenge-Response.

        Args:
            card_id:   Идентификатор YubiKey.
            challenge: Challenge-данные (1–64 байт).
            pin:       Параметр для совместимости с ``HardwareSigningProtocol``.
                       HMAC-SHA1 PIN не требует — непустое значение логируется
                       с ``WARNING`` и игнорируется.
            hmac_slot: OTP-слот YubiKey (1 или 2; по умолчанию 2).

        Returns:
            20 байт HMAC-SHA1 response.

        Raises:
            ValueError:          challenge пустой, > 64 байт или
                                 hmac_slot ∉ {1, 2}.
            HardwareDeviceError: Ошибка операции.

        Example:
            >>> km = manager.derive_key_from_device(
            ...     "yubikey_10620473", b"unique_32_byte_challenge________", ""
            ... )
            >>> len(km)
            20
        """
        self._ensure_ykman()
        with self._get_device_lock(card_id):
            return self._derive_key_from_device(card_id, challenge, pin, hmac_slot)

    def _derive_key_from_device(
        self,
        card_id: str,
        challenge: bytes,
        pin: str,
        hmac_slot: int,
    ) -> bytes:
        if not challenge:
            raise ValueError("challenge не может быть пустым")
        if len(challenge) > 64:
            raise ValueError(f"challenge слишком длинный: {len(challenge)} > 64 байт")
        if hmac_slot not in (1, 2):
            raise ValueError(f"hmac_slot должен быть 1 или 2, получено: {hmac_slot}")
        if pin:
            logger.warning(
                "derive_key_from_device: параметр 'pin' получен, но "
                "HMAC-SHA1 Challenge-Response не использует PIN. Игнорируется."
            )

        logger.info(
            "Deriving key from device: card=%s, challenge_len=%d, hmac_slot=%d",
            card_id,
            len(challenge),
            hmac_slot,
        )

        with self._open_yubikey(card_id) as (yk_device, _):
            try:
                from yubikit.yubiotp import (
                    SLOT as OTP_SLOT,
                )  # noqa: PLC0415
                from yubikit.yubiotp import (
                    YubiOtpSession,
                )

                otp_session = YubiOtpSession(yk_device)
                otp_slot = OTP_SLOT.ONE if hmac_slot == 1 else OTP_SLOT.TWO

                response: bytes = otp_session.calculate_hmac_sha1(
                    slot=otp_slot,
                    challenge=challenge,
                )

                logger.info("Key derived from device: card=%s", card_id)
                return response

            except Exception as exc:
                logger.error(
                    "HMAC-SHA1 KDF failed: card=%s, error=%s",
                    card_id,
                    exc,
                )
                raise HardwareDeviceError(
                    f"HMAC-SHA1 key derivation failed on '{card_id}': {exc}",
                    device_id=card_id,
                    context={"operation": "hmac_sha1_kdf"},
                ) from exc

    # ------------------------------------------------------------------
    # DEVICE INFO
    # ------------------------------------------------------------------

    def get_device_info(self, card_id: str) -> SmartcardInfo:
        """
        Получить информацию об устройстве по card_id.

        Использует кеш enumeration — USB-опрос только при
        истёкшем TTL или первом обращении. Не захватывает
        _global_lock поверх list_devices(), исключая deadlock
        при реентерабельном вызове.  [FIX #3]

        Args:
            card_id: Идентификатор устройства.

        Returns:
            ``SmartcardInfo`` с полной информацией.

        Raises:
            DeviceNotFoundError: Устройство не найдено.

        Example:
            >>> info = manager.get_device_info("yubikey_10620473")
            >>> print(f"FW: {info.firmware_version}")
            FW: 5.2.4
            >>> print(f"Protocols: {info.protocols}")
            Protocols: frozenset({'piv', 'openpgp', 'fido2', 'oath', 'otp'})
            >>> print(info.capabilities.ed25519_openpgp)
            True
        """
        # Вызываем list_devices() без _global_lock — он захватывается
        # внутри list_devices() самостоятельно.  [FIX #3]
        devices = self.list_devices()
        for device in devices:
            if device.card_id == card_id:
                return device
        raise DeviceNotFoundError(card_id)

    # ------------------------------------------------------------------
    # INTERNAL: YubiKey context manager  [C1, S3, C5]
    # ------------------------------------------------------------------

    @contextmanager
    def _open_yubikey(
        self,
        card_id: str,
    ) -> Generator[tuple[SmartCardConnection, Any], None, None]:
        """
        Контекстный менеджер подключения к YubiKey.

        Гарантирует ``close()`` при любом выходе из блока. Паттерн::

            with self._open_yubikey(card_id) as (conn, info):
                fw = self._parse_fw_version(info)

        Важно: каждый вызов выполняет ``yk_list_all()`` (USB-опрос).
        Кеш enumeration из ``list_devices()`` здесь намеренно НЕ
        используется — при открытии соединения нужен «живой» дескриптор
        устройства, а не снимок из кеша.

        Args:
            card_id: Идентификатор вида ``"yubikey_<serial>"``.

        Yields:
            ``(SmartCardConnection, DeviceInfo)`` — соединение
            и метаданные устройства.

        Raises:
            DeviceNotFoundError:      YubiKey с данным card_id не найден.
            DeviceCommunicationError: Ошибка подключения (не-YubiKey exc).
            PINError, InvalidKeyError, SlotError,
            AlgorithmNotAvailableError, KeyGenerationError:
                Пробрасываются без оборачивания.  [S3]
        """
        if yk_list_all is None:
            raise DeviceNotFoundError(card_id)

        connection = None
        dev_info: Any = None

        try:
            for device, dev_info in yk_list_all():
                serial = str(dev_info.serial) if dev_info.serial else "unknown"
                if card_id == f"yubikey_{serial}":
                    from yubikit.core.smartcard import (
                        SmartCardConnection,
                    )  # noqa: PLC0415

                    connection = device.open_connection(SmartCardConnection)
                    break

            if connection is None:
                raise DeviceNotFoundError(card_id)

            yield connection, dev_info

        except (
            DeviceNotFoundError,
            PINError,
            InvalidKeyError,
            SlotError,
            AlgorithmNotAvailableError,
            KeyGenerationError,
        ):
            raise  # [S3] passthrough всех кастомных исключений
        except Exception as exc:
            raise DeviceCommunicationError(
                device_id=card_id,
                reason=f"Failed to connect to '{card_id}': {exc}",
            ) from exc
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    logger.debug("Failed to close YubiKey connection during cleanup")

    # ------------------------------------------------------------------
    # INTERNAL: hash selection  [C4]
    # ------------------------------------------------------------------

    @staticmethod
    def _get_hash_for_key_type(
        public_key: ec.EllipticCurvePublicKey | rsa.RSAPublicKey,
    ) -> hashes.HashAlgorithm:
        """
        SHA-384 для P-384, SHA-256 для всех остальных.

        Соответствует рекомендациям NIST SP 800-57, часть 1,
        таблица 2 (symmetric strength matching).

        Example:
            >>> key = ec.generate_private_key(ec.SECP384R1()).public_key()
            >>> isinstance(
            ...     HardwareCryptoManager._get_hash_for_key_type(key),
            ...     hashes.SHA384,
            ... )
            True
        """
        if isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(
            public_key.curve, ec.SECP384R1
        ):
            return hashes.SHA384()
        return hashes.SHA256()

    # ------------------------------------------------------------------
    # INTERNAL: firmware version parser  [S4, S5]
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_fw_version(dev_info: Any) -> tuple[int, int, int]:
        """
        Извлечь версию прошивки из объекта DeviceInfo ykman.

        Поддерживает две формы возвращаемого значения из разных версий
        yubikit: ``tuple`` (legacy) и объект ``Version`` с атрибутами
        ``.major``, ``.minor``, ``.patch``.

        Args:
            dev_info: Объект DeviceInfo из ``yk_list_all()``.

        Returns:
            ``(major, minor, patch)``. ``(0, 0, 0)`` если недоступно
            или произошла ошибка парсинга.

        Example:
            >>> # YubiKey 5 NFC SN 10620473 → FW 5.2.4
            >>> HardwareCryptoManager._parse_fw_version(dev_info)
            (5, 2, 4)
        """
        try:
            v = dev_info.version
            if v is None:
                return (0, 0, 0)
            if isinstance(v, tuple):
                if len(v) >= 3:
                    return (int(v[0]), int(v[1]), int(v[2]))
                return (0, 0, 0)
            # yubikit.core.Version: .major, .minor, .patch
            return (int(v.major), int(v.minor), int(v.patch))
        except Exception:
            return (0, 0, 0)

    # ------------------------------------------------------------------
    # INTERNAL: YubiKey slot / key-type resolution  [M1, M7]
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_yk_slot(slot: int) -> _YKSlot:
        """
        Числовой PIV-слот → объект yubikit ``SLOT``.

        Raises:
            SlotError: Неизвестный слот или yubikey-manager недоступен.
        """
        if YK_SLOT is None:
            raise SlotError(
                device_id="(ykman)",
                slot=slot,
                reason="yubikey-manager not available",
            )

        slot_map: dict[int, object] = {
            PIV_SLOT_AUTHENTICATION: YK_SLOT.AUTHENTICATION,
            PIV_SLOT_DIGITAL_SIGNATURE: YK_SLOT.SIGNATURE,
            PIV_SLOT_KEY_MANAGEMENT: YK_SLOT.KEY_MANAGEMENT,
            PIV_SLOT_CARD_AUTHENTICATION: YK_SLOT.CARD_AUTH,
        }

        resolved = slot_map.get(slot)
        if resolved is None:
            raise SlotError(
                device_id="(ykman)",
                slot=slot,
                reason="Cannot map to YubiKey PIV slot",
            )
        return resolved  # type: ignore[return-value]

    @staticmethod
    def _resolve_yk_key_type(algorithm: str) -> _YKKeyType:
        """
        Строковый алгоритм → объект yubikit ``KEY_TYPE``.

        RSA-3072/4096 включены намеренно: FW guard в
        ``_generate_keypair_onboard`` проверяет версию до вызова
        этого метода, поэтому здесь дублировать проверку не нужно.

        Raises:
            InvalidKeyError: Неподдерживаемый алгоритм или
                             yubikey-manager недоступен.
        """
        if YK_KEY_TYPE is None:
            raise InvalidKeyError(
                "yubikey-manager not available for key type resolution",
                algorithm=algorithm,
            )

        algo_upper = algorithm.upper()
        key_type_map: dict[str, object] = {
            "RSA-2048": YK_KEY_TYPE.RSA2048,
            "RSA2048": YK_KEY_TYPE.RSA2048,
            "RSA-3072": YK_KEY_TYPE.RSA3072,  # FW 5.7+
            "RSA3072": YK_KEY_TYPE.RSA3072,  # FW 5.7+
            "RSA-4096": YK_KEY_TYPE.RSA4096,  # FW 5.7+
            "RSA4096": YK_KEY_TYPE.RSA4096,  # FW 5.7+
            "ECC-P256": YK_KEY_TYPE.ECCP256,
            "ECCP256": YK_KEY_TYPE.ECCP256,
            "P-256": YK_KEY_TYPE.ECCP256,
            "P256": YK_KEY_TYPE.ECCP256,
            "ECC-P384": YK_KEY_TYPE.ECCP384,
            "ECCP384": YK_KEY_TYPE.ECCP384,
            "P-384": YK_KEY_TYPE.ECCP384,
            "P384": YK_KEY_TYPE.ECCP384,
        }

        key_type = key_type_map.get(algo_upper)
        if key_type is None:
            supported = [
                "RSA-2048",
                "RSA-3072 (FW 5.7+)",
                "RSA-4096 (FW 5.7+)",
                "ECC-P256",
                "ECC-P384",
            ]
            raise InvalidKeyError(
                f"Unsupported YubiKey PIV algorithm: {algorithm}. "
                f"Supported: {', '.join(supported)}",
                algorithm=algorithm,
            )
        return key_type  # type: ignore[return-value]


# ==============================================================================
# MODULE METADATA
# ==============================================================================

__all__: list[str] = [
    # Типы
    "SmartcardType",
    "KeyGenerationCapability",
    # Публичные классы
    "DeviceCapabilities",
    "ExternalKeypair",
    "SmartcardInfo",
    # PIV-константы
    "PIV_SLOT_AUTHENTICATION",
    "PIV_SLOT_DIGITAL_SIGNATURE",
    "PIV_SLOT_KEY_MANAGEMENT",
    "PIV_SLOT_CARD_AUTHENTICATION",
    "PIV_VALID_SLOTS",
    "PIV_SLOT_NAMES",
    # Менеджер
    "HardwareCryptoManager",
    # Флаги доступности
    "has_pyscard",
    "has_ykman",
]

__version__ = "1.3.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"
