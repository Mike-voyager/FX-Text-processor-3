"""
Менеджер аппаратных криптографических устройств.

Обеспечивает взаимодействие со смарткартами (PIV, OpenPGP) и YubiKey
для выполнения криптографических операций на устройстве. Приватный ключ
НИКОГДА не покидает аппаратный модуль.

Поддерживаемые устройства:
    - PIV-совместимые смарткарты (NIST SP 800-73)
    - OpenPGP-совместимые смарткарты (ISO/IEC 7816)
    - YubiKey 5 серии (PIV-режим + HMAC-SHA1 KDF)

PIV слоты:
    - 0x9A: Authentication (PIV Authentication)
    - 0x9C: Digital Signature (подпись документов)
    - 0x9D: Key Management (расшифровка, обмен ключами)
    - 0x9E: Card Authentication (бесконтактная аутентификация)

Опциональные зависимости:
    - pyscard>=2.0.0: ISO 7816 APDU для смарткарт
    - yubikey-manager>=5.0.0: YubiKey CLI/API

Security Notes:
    - PIN передаётся как параметр и НИКОГДА не сохраняется в памяти дольше
      одной операции
    - Все ключи в DER формате (PKCS#8 для приватных, SubjectPublicKeyInfo
      для публичных)
    - Thread-safe: RLock для всех операций с устройствами
    - Логирование операций БЕЗ секретных данных (PIN, ключи)

Example:
    >>> from src.security.crypto.hardware import HardwareCryptoManager
    >>> manager = HardwareCryptoManager()
    >>> devices = manager.list_devices()
    >>> if devices:
    ...     sig = manager.sign_with_device(
    ...         devices[0].card_id, 0x9C, b"data", pin="123456"
    ...     )

Version: 1.0
Date: February 22, 2026
Author: Mike Voyager
Priority: Phase 9 (CRYPTO_MASTER_PLAN v2.3)
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import (
    Any,
    Dict,
    List,
    Literal,
    Optional,
    Tuple,
    Union,
)

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
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

logger = logging.getLogger(__name__)

# Тип для приватных ключей, генерируемых generate_keypair_external
_PrivateKeyType = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]


# ==============================================================================
# TYPE ALIASES
# ==============================================================================

SmartcardType = Literal["piv", "openpgp", "yubikey_piv"]
"""Тип смарткарты: PIV, OpenPGP или YubiKey в PIV-режиме."""

KeyGenerationCapability = Literal["onboard", "external"]
"""Способ генерации ключей: на устройстве или вне его."""


# ==============================================================================
# PIV SLOT CONSTANTS
# ==============================================================================

PIV_SLOT_AUTHENTICATION: int = 0x9A
"""Слот PIV Authentication — для аутентификации владельца карты."""

PIV_SLOT_DIGITAL_SIGNATURE: int = 0x9C
"""Слот Digital Signature — для подписи документов."""

PIV_SLOT_KEY_MANAGEMENT: int = 0x9D
"""Слот Key Management — для расшифровки и обмена ключами."""

PIV_SLOT_CARD_AUTHENTICATION: int = 0x9E
"""Слот Card Authentication — для бесконтактной аутентификации."""

PIV_VALID_SLOTS: frozenset[int] = frozenset({
    PIV_SLOT_AUTHENTICATION,
    PIV_SLOT_DIGITAL_SIGNATURE,
    PIV_SLOT_KEY_MANAGEMENT,
    PIV_SLOT_CARD_AUTHENTICATION,
})
"""Допустимые номера PIV-слотов."""

PIV_SLOT_NAMES: Dict[int, str] = {
    PIV_SLOT_AUTHENTICATION: "PIV Authentication (9A)",
    PIV_SLOT_DIGITAL_SIGNATURE: "Digital Signature (9C)",
    PIV_SLOT_KEY_MANAGEMENT: "Key Management (9D)",
    PIV_SLOT_CARD_AUTHENTICATION: "Card Authentication (9E)",
}
"""Человекочитаемые имена PIV-слотов."""


# ==============================================================================
# SMARTCARD INFO DATACLASS
# ==============================================================================


@dataclass(frozen=True)
class SmartcardInfo:
    """
    Информация об аппаратном криптографическом устройстве.

    Frozen dataclass — неизменяемый после создания. Содержит все необходимые
    метаданные для идентификации устройства и определения его возможностей.

    Attributes:
        card_id: Уникальный идентификатор устройства
        card_type: Тип устройства ("piv", "openpgp", "yubikey_piv")
        key_generation: Способ генерации ключей ("onboard" или "external")
        available_slots: Список доступных слотов для криптоопераций
        algorithms_supported: Поддерживаемые алгоритмы (например, ["RSA-2048", "ECC-P256"])
        requires_pin: Требуется ли PIN для операций
        manufacturer: Производитель устройства
        serial_number: Серийный номер (если доступен)
        firmware_version: Версия прошивки (если доступна)

    Example:
        >>> info = SmartcardInfo(
        ...     card_id="yubikey_12345678",
        ...     card_type="yubikey_piv",
        ...     key_generation="onboard",
        ...     available_slots=[0x9A, 0x9C, 0x9D, 0x9E],
        ...     algorithms_supported=["RSA-2048", "ECC-P256", "ECC-P384"],
        ...     requires_pin=True,
        ...     manufacturer="Yubico",
        ...     serial_number="12345678",
        ...     firmware_version="5.4.3",
        ... )
        >>> info.card_type
        'yubikey_piv'
    """

    card_id: str
    card_type: SmartcardType
    key_generation: KeyGenerationCapability
    available_slots: List[int] = field(default_factory=list)
    algorithms_supported: List[str] = field(default_factory=list)
    requires_pin: bool = True
    manufacturer: str = "Unknown"
    serial_number: Optional[str] = None
    firmware_version: Optional[str] = None


# ==============================================================================
# OPTIONAL DEPENDENCY DETECTION
# ==============================================================================

try:
    from smartcard.System import readers as sc_readers
    from smartcard.CardConnection import CardConnection as _CardConnection

    HAS_PYSCARD = True
    logger.info("pyscard detected, smartcard operations available")
except ImportError:
    sc_readers = None  # type: ignore[assignment]
    _CardConnection = None  # type: ignore[assignment,misc]
    HAS_PYSCARD = False
    logger.debug(
        "pyscard not installed, smartcard operations unavailable. "
        "Install: pip install pyscard>=2.0.0"
    )

try:
    from ykman.device import list_all_devices as yk_list_all
    from yubikit.piv import (
        PivSession,
        SLOT as YK_SLOT,
        KEY_TYPE as YK_KEY_TYPE,
    )

    HAS_YKMAN = True
    logger.info("yubikey-manager detected, YubiKey operations available")
except ImportError:
    yk_list_all = None  # type: ignore[assignment]
    PivSession = None  # type: ignore[assignment,misc]
    YK_SLOT = None  # type: ignore[assignment,misc]
    YK_KEY_TYPE = None  # type: ignore[assignment,misc]
    HAS_YKMAN = False
    logger.debug(
        "yubikey-manager not installed, YubiKey operations unavailable. "
        "Install: pip install yubikey-manager>=5.0.0"
    )


# ==============================================================================
# HARDWARE CRYPTO MANAGER
# ==============================================================================


class HardwareCryptoManager:
    """
    Менеджер аппаратных криптографических устройств.

    Предоставляет единый интерфейс для работы со смарткартами (PIV, OpenPGP)
    и YubiKey. Все криптографические операции выполняются на устройстве —
    приватный ключ никогда не покидает аппаратный модуль.

    Реализует ``HardwareSigningProtocol`` из ``core.protocols``.

    Опциональные зависимости:
        - pyscard>=2.0.0: взаимодействие со смарткартами через PC/SC
        - yubikey-manager>=5.0.0: управление YubiKey

    Thread Safety:
        Все публичные методы защищены RLock. Безопасно использовать
        из нескольких потоков.

    Example:
        >>> manager = HardwareCryptoManager()
        >>> devices = manager.list_devices()
        >>> for dev in devices:
        ...     print(f"{dev.card_id}: {dev.card_type}")
    """

    def __init__(self) -> None:
        """
        Инициализация менеджера аппаратных устройств.

        Зависимости (pyscard, ykman) проверяются лениво —
        при первом вызове метода, требующего библиотеку.
        """
        self._lock = threading.RLock()
        logger.info("HardwareCryptoManager initialized")

    # ------------------------------------------------------------------
    # DEPENDENCY CHECKS
    # ------------------------------------------------------------------

    @staticmethod
    def _ensure_pyscard() -> None:
        """
        Проверка доступности pyscard.

        Raises:
            AlgorithmNotAvailableError: pyscard не установлен
        """
        if not HAS_PYSCARD:
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
        """
        Проверка доступности yubikey-manager.

        Raises:
            AlgorithmNotAvailableError: yubikey-manager не установлен
        """
        if not HAS_YKMAN:
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
        """
        Валидация номера PIV-слота.

        Args:
            slot: Номер слота

        Raises:
            SlotError: Недопустимый номер слота
        """
        if slot not in PIV_VALID_SLOTS:
            valid = ", ".join(f"0x{s:02X}" for s in sorted(PIV_VALID_SLOTS))
            raise SlotError(
                device_id="(validation)",
                slot=slot,
                reason=f"Invalid PIV slot. Valid slots: {valid}",
            )

    # ------------------------------------------------------------------
    # DEVICE ENUMERATION
    # ------------------------------------------------------------------

    def list_devices(self) -> List[SmartcardInfo]:
        """
        Получить список подключённых аппаратных устройств.

        Перечисляет все доступные смарткарты (через pyscard) и YubiKey
        (через ykman). Если ни одна библиотека не установлена,
        возвращает пустой список.

        Returns:
            Список ``SmartcardInfo`` для каждого обнаруженного устройства

        Example:
            >>> manager = HardwareCryptoManager()
            >>> devices = manager.list_devices()
            >>> for dev in devices:
            ...     print(f"{dev.card_id}: {dev.manufacturer}")
        """
        devices: List[SmartcardInfo] = []

        with self._lock:
            devices.extend(self._list_smartcards())
            devices.extend(self._list_yubikeys())

        logger.info("Found %d hardware device(s)", len(devices))
        return devices

    def _list_smartcards(self) -> List[SmartcardInfo]:
        """
        Перечислить подключённые смарткарты через PC/SC.

        Returns:
            Список SmartcardInfo для смарткарт
        """
        if not HAS_PYSCARD or sc_readers is None:
            return []

        result: List[SmartcardInfo] = []
        try:
            available_readers = sc_readers()
            for idx, reader in enumerate(available_readers):
                reader_name = str(reader)
                card_type: SmartcardType = "piv"

                if "openpgp" in reader_name.lower():
                    card_type = "openpgp"

                info = SmartcardInfo(
                    card_id=f"sc_{idx}_{reader_name[:20]}",
                    card_type=card_type,
                    key_generation="external",
                    available_slots=list(PIV_VALID_SLOTS) if card_type == "piv" else [],
                    algorithms_supported=["RSA-2048", "ECC-P256", "ECC-P384"],
                    requires_pin=True,
                    manufacturer=reader_name.split(" ")[0] if reader_name else "Unknown",
                )
                result.append(info)

            logger.debug("Found %d smartcard reader(s)", len(result))
        except Exception as exc:
            logger.warning("Error listing smartcard readers: %s", exc)

        return result

    def _list_yubikeys(self) -> List[SmartcardInfo]:
        """
        Перечислить подключённые YubiKey через ykman.

        Returns:
            Список SmartcardInfo для YubiKey
        """
        if not HAS_YKMAN or yk_list_all is None:
            return []

        result: List[SmartcardInfo] = []
        try:
            for device, dev_info in yk_list_all():
                serial = str(dev_info.serial) if dev_info.serial else None
                fw = str(dev_info.version) if dev_info.version else None

                info = SmartcardInfo(
                    card_id=f"yubikey_{serial or 'unknown'}",
                    card_type="yubikey_piv",
                    key_generation="onboard",
                    available_slots=list(PIV_VALID_SLOTS),
                    algorithms_supported=[
                        "RSA-2048",
                        "ECC-P256",
                        "ECC-P384",
                    ],
                    requires_pin=True,
                    manufacturer="Yubico",
                    serial_number=serial,
                    firmware_version=fw,
                )
                result.append(info)

            logger.debug("Found %d YubiKey(s)", len(result))
        except Exception as exc:
            logger.warning("Error listing YubiKeys: %s", exc)

        return result

    # ------------------------------------------------------------------
    # KEY GENERATION — EXTERNAL (вне устройства)
    # ------------------------------------------------------------------

    def generate_keypair_external(
        self,
        algorithm: str,
        key_size: int = 2048,
    ) -> Tuple[bytes, bytes]:
        """
        Генерация ключевой пары ВНЕ устройства.

        Ключи генерируются программно (на хосте), после чего приватный ключ
        может быть импортирован на смарткарту через ``import_key_to_device()``.
        Используется для PIV и OpenPGP смарткарт, не поддерживающих генерацию
        ключей на борту.

        Args:
            algorithm: Алгоритм ("RSA-2048", "RSA-3072", "RSA-4096",
                       "ECC-P256", "ECC-P384")
            key_size: Размер ключа в битах (для RSA, по умолчанию 2048)

        Returns:
            Tuple[private_key_der, public_key_der]:
                - private_key_der: Приватный ключ в DER формате (PKCS#8)
                - public_key_der: Публичный ключ в DER формате (SubjectPublicKeyInfo)

        Raises:
            KeyGenerationError: Ошибка генерации ключей
            InvalidKeyError: Неподдерживаемый алгоритм или размер ключа

        Security Note:
            После импорта ключа на карту приватный ключ на хосте следует
            безопасно удалить (обнулить в памяти).

        Example:
            >>> priv_der, pub_der = manager.generate_keypair_external("ECC-P256")
            >>> manager.import_key_to_device("card_001", 0x9C, priv_der, "123456")
        """
        with self._lock:
            return self._generate_keypair_external(algorithm, key_size)

    def _generate_keypair_external(
        self,
        algorithm: str,
        key_size: int,
    ) -> Tuple[bytes, bytes]:
        """Внутренняя реализация генерации ключей."""
        algo_upper = algorithm.upper()
        logger.info(
            "Generating external keypair: algorithm=%s, key_size=%d",
            algorithm,
            key_size,
        )

        try:
            private_key: _PrivateKeyType

            if algo_upper.startswith("RSA"):
                # Извлечь размер из алгоритма, если указан (RSA-2048 → 2048)
                parts = algo_upper.split("-")
                if len(parts) >= 2 and parts[-1].isdigit():
                    key_size = int(parts[-1])

                if key_size not in (2048, 3072, 4096):
                    raise InvalidKeyError(
                        f"Unsupported RSA key size: {key_size}. "
                        "Supported: 2048, 3072, 4096",
                        algorithm=algorithm,
                    )

                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=key_size,
                )

            elif algo_upper in ("ECC-P256", "ECC-P-256", "P-256", "P256"):
                private_key = ec.generate_private_key(ec.SECP256R1())

            elif algo_upper in ("ECC-P384", "ECC-P-384", "P-384", "P384"):
                private_key = ec.generate_private_key(ec.SECP384R1())

            else:
                raise InvalidKeyError(
                    f"Unsupported algorithm: {algorithm}. "
                    "Supported: RSA-2048, RSA-3072, RSA-4096, ECC-P256, ECC-P384",
                    algorithm=algorithm,
                )

            private_der = private_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
            public_der = private_key.public_key().public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo,
            )

            logger.info("External keypair generated: algorithm=%s", algorithm)
            return private_der, public_der

        except (InvalidKeyError, AlgorithmNotAvailableError):
            raise
        except Exception as exc:
            logger.error("Key generation failed: %s", exc)
            raise KeyGenerationError(
                f"Failed to generate keypair for {algorithm}: {exc}",
                algorithm=algorithm,
            ) from exc

    # ------------------------------------------------------------------
    # KEY GENERATION — ONBOARD (на устройстве)
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

        Приватный ключ генерируется и остаётся на устройстве. Метод
        возвращает только публичный ключ. Поддерживается только YubiKey.

        Args:
            card_id: Идентификатор YubiKey
            slot: PIV-слот для генерации (0x9A, 0x9C, 0x9D, 0x9E)
            algorithm: Алгоритм ("RSA-2048", "ECC-P256", "ECC-P384")
            pin: PIN-код для аутентификации (НЕ сохраняется)

        Returns:
            Публичный ключ в DER формате (SubjectPublicKeyInfo)

        Raises:
            AlgorithmNotAvailableError: yubikey-manager не установлен
            DeviceNotFoundError: YubiKey не найден
            PINError: Неверный PIN
            SlotError: Недопустимый слот
            KeyGenerationError: Ошибка генерации

        Security Note:
            Приватный ключ генерируется аппаратным RNG устройства и
            НИКОГДА не покидает YubiKey.

        Example:
            >>> pub_key = manager.generate_keypair_onboard(
            ...     "yubikey_12345678", 0x9C, "ECC-P256", "123456"
            ... )
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)

        with self._lock:
            return self._generate_keypair_onboard(card_id, slot, algorithm, pin)

    def _generate_keypair_onboard(
        self,
        card_id: str,
        slot: int,
        algorithm: str,
        pin: str,
    ) -> bytes:
        """Внутренняя реализация генерации ключей на устройстве."""
        logger.info(
            "Generating onboard keypair: card=%s, slot=0x%02X, algorithm=%s",
            card_id,
            slot,
            algorithm,
        )

        yk_device = self._connect_yubikey(card_id)
        try:
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

        except PINError:
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

        Загружает приватный ключ (DER/PKCS#8) в указанный слот устройства.
        После успешного импорта приватный ключ на хосте следует безопасно
        удалить.

        Args:
            card_id: Идентификатор устройства
            slot: PIV-слот для импорта (0x9A, 0x9C, 0x9D, 0x9E)
            private_key: Приватный ключ в DER формате (PKCS#8)
            pin: PIN-код для аутентификации (НЕ сохраняется)

        Raises:
            AlgorithmNotAvailableError: yubikey-manager не установлен
            DeviceNotFoundError: Устройство не найдено
            PINError: Неверный PIN
            SlotError: Недопустимый слот
            InvalidKeyError: Некорректный формат ключа
            HardwareDeviceError: Ошибка импорта

        Security Note:
            После импорта ОБЯЗАТЕЛЬНО обнулите приватный ключ на хосте:
            ``secure_zero(bytearray(private_key))``

        Example:
            >>> priv, pub = manager.generate_keypair_external("ECC-P256")
            >>> manager.import_key_to_device("yubikey_123", 0x9C, priv, "123456")
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)

        with self._lock:
            self._import_key_to_device(card_id, slot, private_key, pin)

    def _import_key_to_device(
        self,
        card_id: str,
        slot: int,
        private_key: bytes,
        pin: str,
    ) -> None:
        """Внутренняя реализация импорта ключа."""
        logger.info(
            "Importing key to device: card=%s, slot=0x%02X",
            card_id,
            slot,
        )

        yk_device = self._connect_yubikey(card_id)
        try:
            from cryptography.hazmat.primitives.serialization import (
                load_der_private_key,
            )

            key_obj = load_der_private_key(private_key, password=None)
            piv_session = PivSession(yk_device)
            piv_session.verify_pin(pin)

            piv_slot = self._resolve_yk_slot(slot)

            piv_session.put_key(
                slot=piv_slot,
                private_key=key_obj,
            )

            logger.info(
                "Key imported: card=%s, slot=0x%02X",
                card_id,
                slot,
            )

        except (PINError, InvalidKeyError):
            raise
        except ValueError as exc:
            raise InvalidKeyError(
                f"Invalid private key format: {exc}",
                algorithm="DER/PKCS#8",
            ) from exc
        except Exception as exc:
            logger.error(
                "Key import failed: card=%s, error=%s",
                card_id,
                exc,
            )
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

        Подпись выполняется приватным ключом, хранящимся в указанном слоте
        устройства. Приватный ключ НЕ покидает устройство.

        Args:
            card_id: Идентификатор устройства
            slot: PIV-слот с приватным ключом (0x9A, 0x9C, 0x9D, 0x9E)
            message: Данные для подписи (произвольная длина)
            pin: PIN-код для аутентификации (НЕ сохраняется)

        Returns:
            Цифровая подпись в DER формате

        Raises:
            AlgorithmNotAvailableError: Нет нужной библиотеки
            DeviceNotFoundError: Устройство не найдено
            PINError: Неверный PIN
            SlotError: Слот пуст или не содержит подписывающий ключ
            HardwareDeviceError: Ошибка подписи

        Example:
            >>> signature = manager.sign_with_device(
            ...     "yubikey_123", 0x9C, b"Document data", "123456"
            ... )
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)

        with self._lock:
            return self._sign_with_device(card_id, slot, message, pin)

    def _sign_with_device(
        self,
        card_id: str,
        slot: int,
        message: bytes,
        pin: str,
    ) -> bytes:
        """Внутренняя реализация подписи на устройстве."""
        logger.info(
            "Signing on device: card=%s, slot=0x%02X, message_len=%d",
            card_id,
            slot,
            len(message),
        )

        yk_device = self._connect_yubikey(card_id)
        try:
            from cryptography.hazmat.primitives import hashes

            piv_session = PivSession(yk_device)
            piv_session.verify_pin(pin)

            piv_slot = self._resolve_yk_slot(slot)

            signature: bytes = piv_session.sign(
                slot=piv_slot,
                key_type=piv_session.get_slot_metadata(piv_slot).key_type,
                message=message,
                hash_algorithm=hashes.SHA256(),
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
        Расшифровать данные на аппаратном устройстве.

        Расшифровка выполняется приватным ключом, хранящимся на устройстве.
        Обычно используется слот Key Management (0x9D).

        Args:
            card_id: Идентификатор устройства
            slot: PIV-слот с приватным ключом (обычно 0x9D)
            ciphertext: Зашифрованные данные
            pin: PIN-код для аутентификации (НЕ сохраняется)

        Returns:
            Расшифрованные данные

        Raises:
            AlgorithmNotAvailableError: Нет нужной библиотеки
            DeviceNotFoundError: Устройство не найдено
            PINError: Неверный PIN
            SlotError: Слот не содержит ключ расшифровки
            HardwareDeviceError: Ошибка расшифровки

        Example:
            >>> plaintext = manager.decrypt_with_device(
            ...     "yubikey_123", 0x9D, ciphertext, "123456"
            ... )
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)

        with self._lock:
            return self._decrypt_with_device(card_id, slot, ciphertext, pin)

    def _decrypt_with_device(
        self,
        card_id: str,
        slot: int,
        ciphertext: bytes,
        pin: str,
    ) -> bytes:
        """Внутренняя реализация расшифровки на устройстве."""
        logger.info(
            "Decrypting on device: card=%s, slot=0x%02X, ct_len=%d",
            card_id,
            slot,
            len(ciphertext),
        )

        yk_device = self._connect_yubikey(card_id)
        try:
            from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

            piv_session = PivSession(yk_device)
            piv_session.verify_pin(pin)

            piv_slot = self._resolve_yk_slot(slot)

            plaintext: bytes = piv_session.decrypt(
                slot=piv_slot,
                cipher_text=ciphertext,
                padding=asym_padding.PKCS1v15(),
            )

            logger.info(
                "Decrypted on device: card=%s, slot=0x%02X",
                card_id,
                slot,
            )
            return plaintext

        except PINError:
            raise
        except Exception as exc:
            logger.error(
                "Decryption failed: card=%s, slot=0x%02X, error=%s",
                card_id,
                slot,
                exc,
            )
            raise HardwareDeviceError(
                f"Decryption failed on device '{card_id}', "
                f"slot 0x{slot:02X}: {exc}",
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
        Получить публичный ключ из слота устройства.

        Читает публичный ключ из указанного PIV-слота устройства.
        Не требует PIN для чтения публичного ключа.

        Args:
            card_id: Идентификатор устройства
            slot: PIV-слот (0x9A, 0x9C, 0x9D, 0x9E)

        Returns:
            Публичный ключ в DER формате (SubjectPublicKeyInfo)

        Raises:
            AlgorithmNotAvailableError: Нет нужной библиотеки
            DeviceNotFoundError: Устройство не найдено
            SlotError: Слот пуст или не содержит ключ

        Example:
            >>> pub_key = manager.get_public_key("yubikey_123", 0x9C)
        """
        self._ensure_ykman()
        self._validate_piv_slot(slot)

        with self._lock:
            return self._get_public_key(card_id, slot)

    def _get_public_key(
        self,
        card_id: str,
        slot: int,
    ) -> bytes:
        """Внутренняя реализация получения публичного ключа."""
        logger.info(
            "Getting public key: card=%s, slot=0x%02X",
            card_id,
            slot,
        )

        yk_device = self._connect_yubikey(card_id)
        try:
            piv_session = PivSession(yk_device)
            piv_slot = self._resolve_yk_slot(slot)

            slot_metadata = piv_session.get_slot_metadata(piv_slot)
            public_key = slot_metadata.public_key

            public_der: bytes = public_key.public_bytes(
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
    ) -> bytes:
        """
        Вывести ключ через YubiKey HMAC-SHA1 Challenge-Response.

        Использует HMAC-SHA1 Challenge-Response slot YubiKey для вывода
        20-байтного ключа из challenge. Полезно как аппаратный KDF.

        Args:
            card_id: Идентификатор YubiKey
            challenge: Challenge-данные (до 64 байт)
            pin: PIN-код (для совместимости интерфейса; HMAC-SHA1
                 слот YubiKey обычно не требует PIN)

        Returns:
            20 байт HMAC-SHA1 response (ключевой материал)

        Raises:
            AlgorithmNotAvailableError: yubikey-manager не установлен
            DeviceNotFoundError: YubiKey не найден
            HardwareDeviceError: Ошибка HMAC-SHA1 операции

        Example:
            >>> key_material = manager.derive_key_from_device(
            ...     "yubikey_123", b"unique_challenge", ""
            ... )
            >>> len(key_material)
            20
        """
        self._ensure_ykman()

        with self._lock:
            return self._derive_key_from_device(card_id, challenge, pin)

    def _derive_key_from_device(
        self,
        card_id: str,
        challenge: bytes,
        pin: str,
    ) -> bytes:
        """Внутренняя реализация HMAC-SHA1 KDF."""
        logger.info(
            "Deriving key from device: card=%s, challenge_len=%d",
            card_id,
            len(challenge),
        )

        yk_device = self._connect_yubikey(card_id)
        try:
            from yubikit.yubiotp import YubiOtpSession
            from yubikit.yubiotp import SLOT as OTP_SLOT

            otp_session = YubiOtpSession(yk_device)
            response: bytes = otp_session.calculate_hmac_sha1(
                slot=OTP_SLOT.TWO,
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
        Получить детальную информацию об устройстве.

        Args:
            card_id: Идентификатор устройства

        Returns:
            ``SmartcardInfo`` с полной информацией об устройстве

        Raises:
            DeviceNotFoundError: Устройство не найдено

        Example:
            >>> info = manager.get_device_info("yubikey_12345678")
            >>> print(f"FW: {info.firmware_version}")
        """
        with self._lock:
            devices = self.list_devices()

        for device in devices:
            if device.card_id == card_id:
                return device

        raise DeviceNotFoundError(card_id)

    # ------------------------------------------------------------------
    # INTERNAL HELPERS: YubiKey connection
    # ------------------------------------------------------------------

    def _connect_yubikey(self, card_id: str) -> Any:
        """
        Подключиться к YubiKey по идентификатору.

        Args:
            card_id: Идентификатор вида "yubikey_<serial>"

        Returns:
            Объект соединения YubiKey (SmartCardConnection)

        Raises:
            DeviceNotFoundError: YubiKey не найден
            DeviceCommunicationError: Ошибка подключения
        """
        if yk_list_all is None:
            raise DeviceNotFoundError(card_id)

        try:
            for device, dev_info in yk_list_all():
                serial = str(dev_info.serial) if dev_info.serial else "unknown"
                if card_id == f"yubikey_{serial}":
                    from yubikit.core.smartcard import SmartCardConnection

                    connection = device.open_connection(SmartCardConnection)
                    return connection

        except DeviceNotFoundError:
            raise
        except Exception as exc:
            raise DeviceCommunicationError(
                device_id=card_id,
                reason=f"Failed to connect: {exc}",
            ) from exc

        raise DeviceNotFoundError(card_id)

    # ------------------------------------------------------------------
    # INTERNAL HELPERS: YubiKey type resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_yk_slot(slot: int) -> Any:
        """
        Преобразовать числовой PIV-слот в объект yubikit SLOT.

        Args:
            slot: Числовой PIV-слот (0x9A, 0x9C, 0x9D, 0x9E)

        Returns:
            Объект ``yubikit.piv.SLOT``

        Raises:
            SlotError: Неизвестный слот
        """
        if YK_SLOT is None:
            raise SlotError(
                device_id="(ykman)",
                slot=slot,
                reason="yubikey-manager not available",
            )

        slot_map: Dict[int, Any] = {
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

        return resolved

    @staticmethod
    def _resolve_yk_key_type(algorithm: str) -> Any:
        """
        Преобразовать строковый алгоритм в объект yubikit KEY_TYPE.

        Args:
            algorithm: Алгоритм ("RSA-2048", "ECC-P256", "ECC-P384")

        Returns:
            Объект ``yubikit.piv.KEY_TYPE``

        Raises:
            InvalidKeyError: Неподдерживаемый алгоритм
        """
        if YK_KEY_TYPE is None:
            raise InvalidKeyError(
                "yubikey-manager not available for key type resolution",
                algorithm=algorithm,
            )

        algo_upper = algorithm.upper()
        key_type_map: Dict[str, Any] = {
            "RSA-2048": YK_KEY_TYPE.RSA2048,
            "RSA2048": YK_KEY_TYPE.RSA2048,
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
            supported = ["RSA-2048", "ECC-P256", "ECC-P384"]
            raise InvalidKeyError(
                f"Unsupported YubiKey algorithm: {algorithm}. "
                f"Supported: {', '.join(supported)}",
                algorithm=algorithm,
            )

        return key_type


# ==============================================================================
# MODULE METADATA
# ==============================================================================

__all__: list[str] = [
    # Types
    "SmartcardType",
    "KeyGenerationCapability",
    # Dataclass
    "SmartcardInfo",
    # Constants
    "PIV_SLOT_AUTHENTICATION",
    "PIV_SLOT_DIGITAL_SIGNATURE",
    "PIV_SLOT_KEY_MANAGEMENT",
    "PIV_SLOT_CARD_AUTHENTICATION",
    "PIV_VALID_SLOTS",
    "PIV_SLOT_NAMES",
    # Manager
    "HardwareCryptoManager",
    # Availability flags
    "HAS_PYSCARD",
    "HAS_YKMAN",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-22"
