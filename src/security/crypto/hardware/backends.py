"""
Абстракция бэкендов аппаратных криптографических устройств.

Определяет единый ``DeviceBackend`` Protocol и конкретные реализации
для различных типов устройств. ``HardwareCryptoManager`` использует
бэкенды как фасад — маршрутизирует вызовы по card_id → backend.

Бэкенды:
    - ``YubiKeyPivBackend``     — YubiKey через ykman (PIV-протокол)
    - ``OpenPGPDeviceBackend``  — адаптер поверх ``OpenPGPBackend`` (APDU)
    - ``JavaCardRawBackend``    — кастомные апплеты J3R200 (raw APDU)

Каждый бэкенд привязан к одному устройству (card_id задаётся
при создании). Это позволяет:
    - Избежать повторной передачи card_id в каждый метод
    - Хранить per-device state (PIN-кеш для сессии, счётчик и т.д.)
    - Безопасно использовать в ``HardwareCryptoManager`` с per-device lock

Зависимости:
    - pyscard>=2.0.0       — ``JavaCardRawBackend``
    - yubikey-manager>=5.0 — ``YubiKeyPivBackend``
    - Без новых зависимостей сверх уже существующих в проекте.

Security Notes:
    - PIN передаётся как параметр и НЕ сохраняется дольше одной операции.
    - Приватный ключ НИКОГДА не покидает аппаратное устройство.
    - Логирование без PIN-кодов и ключевого материала.

Example:
    >>> backend = YubiKeyPivBackend(card_id="yubikey_10620473")
    >>> slots = backend.list_slots()
    >>> sig = backend.sign("9C", b"data-to-sign", pin="123456")

Version: 1.0.0
Date: 2026-03-02
Author: Mike Voyager
Priority: Phase 3 (Hardware Crypto Roadmap v1.0)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    Final,
    Literal,
    Protocol,
    cast,
    runtime_checkable,
)

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
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
    from src.security.crypto.hardware.openpgp_backend import (
        OpenPGPBackend,
        OpenPGPSlot,
    )

logger = logging.getLogger(__name__)


# ==============================================================================
# OPTIONAL DEPENDENCY DETECTION
# ==============================================================================

try:
    from ykman.device import list_all_devices as yk_list_all
    from yubikit.core.smartcard import SmartCardConnection
    from yubikit.piv import (
        KEY_TYPE as YK_KEY_TYPE,
    )
    from yubikit.piv import (
        SLOT as YK_SLOT,
    )
    from yubikit.piv import (
        PivSession,
    )

    HAS_YKMAN = True
except ImportError:
    yk_list_all = None  # type: ignore[assignment]
    SmartCardConnection = None  # type: ignore[assignment, misc]
    PivSession = None  # type: ignore[assignment, misc]
    YK_SLOT = None  # type: ignore[assignment, misc]
    YK_KEY_TYPE = None  # type: ignore[assignment, misc]
    HAS_YKMAN = False

try:
    from smartcard.System import readers as sc_readers

    HAS_PYSCARD = True
except ImportError:
    sc_readers = None
    HAS_PYSCARD = False


# ==============================================================================
# SLOT STATUS ENUM
# ==============================================================================


class SlotStatus(Enum):
    """Статус слота на устройстве."""

    EMPTY = "empty"
    """Слот не содержит ключ."""

    POPULATED = "populated"
    """Слот содержит ключ."""

    LOCKED = "locked"
    """Слот заблокирован (PIN/PUK/management key)."""

    UNKNOWN = "unknown"
    """Статус невозможно определить."""


# ==============================================================================
# SLOT INFO DATACLASS
# ==============================================================================


@dataclass(frozen=True)
class SlotInfo:
    """
    Информация о слоте на аппаратном криптографическом устройстве.

    Attributes:
        slot_id:   Идентификатор слота (зависит от протокола):
                   PIV — ``"9A"``, ``"9C"``, ``"9D"``, ``"9E"``;
                   OpenPGP — ``"sign"``, ``"encrypt"``, ``"auth"``.
        label:     Человекочитаемое описание назначения слота.
        algorithm: Алгоритм ключа в слоте (``""`` если пуст).
        status:    Статус слота.
        key_size:  Размер ключа в битах (0 если пуст).

    Example:
        >>> info = SlotInfo(
        ...     slot_id="9C",
        ...     label="Digital Signature",
        ...     algorithm="RSA-2048",
        ...     status=SlotStatus.POPULATED,
        ...     key_size=2048,
        ... )
        >>> info.status == SlotStatus.POPULATED
        True
    """

    slot_id: str
    label: str
    algorithm: str = ""
    status: SlotStatus = SlotStatus.EMPTY
    key_size: int = 0


# ==============================================================================
# DEVICE BACKEND PROTOCOL
# ==============================================================================


@runtime_checkable
class DeviceBackend(Protocol):
    """
    Протокол для бэкендов аппаратных криптографических устройств.

    Каждая реализация привязана к одному устройству (card_id при создании).
    Единый интерфейс для PIV, OpenPGP и кастомных JavaCard-апплетов.

    Контракт:
        - Приватный ключ НИКОГДА не покидает устройство.
        - PIN не сохраняется между вызовами.
        - Реализация может быть НЕ потокобезопасной — внешний код
          (``HardwareCryptoManager``) обеспечивает per-device locking.

    Example:
        >>> def process(backend: DeviceBackend) -> bytes:
        ...     slots = backend.list_slots()
        ...     return backend.sign("9C", b"data", pin="123456")
    """

    @property
    def card_id(self) -> str:
        """Идентификатор устройства, к которому привязан бэкенд."""
        ...

    @property
    def backend_type(self) -> str:
        """Тип бэкенда: ``"yubikey_piv"``, ``"openpgp"``, ``"javacard_raw"``."""
        ...

    def sign(self, slot: str, data: bytes, pin: str) -> bytes:
        """
        Подписать данные на устройстве.

        Args:
            slot: Идентификатор слота (``"9C"`` для PIV, ``"sign"`` для OpenPGP).
            data: Данные или хеш для подписи.
            pin:  PIN-код пользователя.

        Returns:
            Подпись (DER для RSA/ECDSA, raw 64 байта для Ed25519).

        Raises:
            PINError: Неверный или заблокированный PIN.
            SlotError: Слот пуст или не поддерживает подпись.
            HardwareDeviceError: Общая ошибка устройства.
        """
        ...

    def decrypt(self, slot: str, ciphertext: bytes, pin: str) -> bytes:
        """
        Расшифровать данные или выполнить ECDH на устройстве.

        Args:
            slot:       Идентификатор слота (``"9D"`` для PIV, ``"encrypt"`` для OpenPGP).
            ciphertext: Зашифрованные данные или ECDH-wrapped публичный ключ.
            pin:        PIN-код пользователя.

        Returns:
            Расшифрованные данные или ECDH shared secret.

        Raises:
            PINError: Неверный или заблокированный PIN.
            SlotError: Слот пуст или не поддерживает расшифровку.
            HardwareDeviceError: Общая ошибка устройства.
        """
        ...

    def get_public_key(self, slot: str) -> bytes:
        """
        Получить публичный ключ из слота.

        Не требует PIN — публичный ключ доступен без аутентификации.

        Args:
            slot: Идентификатор слота.

        Returns:
            Публичный ключ (DER SubjectPublicKeyInfo для PIV;
            raw bytes для OpenPGP Ed25519/X25519).

        Raises:
            SlotError: Слот пуст.
            HardwareDeviceError: Ошибка чтения.
        """
        ...

    def import_key(self, slot: str, key_data: bytes, pin: str) -> None:
        """
        Импортировать приватный ключ в слот устройства.

        Для PIV: ``pin`` — management key или PIN (зависит от устройства).
        Для OpenPGP: ``pin`` — Admin PIN (PW3).

        Args:
            slot:     Целевой слот.
            key_data: Приватный ключ (DER PKCS#8 для PIV; TLV для OpenPGP).
            pin:      PIN/management key для авторизации.

        Raises:
            PINError: Неверный PIN.
            InvalidKeyError: Ключ не соответствует формату/алгоритму.
            HardwareDeviceError: Ошибка записи.
        """
        ...

    def generate_key(self, slot: str, algorithm: str, pin: str) -> bytes:
        """
        Сгенерировать ключевую пару на устройстве; вернуть публичный ключ.

        Приватный ключ создаётся аппаратным RNG устройства и НИКОГДА
        не покидает карту.

        Args:
            slot:      Целевой слот.
            algorithm: Алгоритм (``"RSA-2048"``, ``"ECC-P256"``, ``"Ed25519"`` и т.д.).
            pin:       PIN/management key для авторизации.

        Returns:
            Публичный ключ сгенерированной пары.

        Raises:
            AlgorithmNotAvailableError: Алгоритм не поддерживается устройством.
            KeyGenerationError: Ошибка генерации.
            PINError: Неверный PIN.
        """
        ...

    def list_slots(self) -> list[SlotInfo]:
        """
        Получить информацию обо всех доступных слотах устройства.

        Returns:
            Список ``SlotInfo`` для каждого слота.
        """
        ...


# ==============================================================================
# PIV SLOT MAPPING
# ==============================================================================

# PIV slot hex → (human label, YK_SLOT enum name)
_PIV_SLOT_MAP: Final[dict[str, str]] = {
    "9A": "PIV Authentication",
    "9C": "Digital Signature",
    "9D": "Key Management",
    "9E": "Card Authentication",
}


def _piv_slot_hex_to_int(slot_hex: str) -> int:
    """
    Преобразовать строковый PIV slot ID в int.

    Args:
        slot_hex: ``"9A"``, ``"9C"``, ``"9D"`` или ``"9E"``.

    Returns:
        Целочисленное значение (0x9A, 0x9C, 0x9D, 0x9E).

    Raises:
        SlotError: Неизвестный слот.
    """
    slot_upper = slot_hex.upper().strip()
    if slot_upper not in _PIV_SLOT_MAP:
        valid = ", ".join(sorted(_PIV_SLOT_MAP))
        raise SlotError(
            device_id="(validation)",
            slot=int(slot_upper, 16) if slot_upper else 0,
            reason=f"Неизвестный PIV-слот '{slot_hex}'. Допустимые: {valid}.",
        )
    return int(slot_upper, 16)


# ==============================================================================
# YUBIKEY PIV BACKEND
# ==============================================================================


class YubiKeyPivBackend:
    """
    YubiKey PIV бэкенд через yubikey-manager (ykman).

    Привязан к конкретному YubiKey по serial number. Все криптографические
    операции делегируются ``PivSession`` — приватный ключ не покидает YubiKey.

    Ограничения:
        - Требует ``yubikey-manager>=5.0.0``.
        - Не потокобезопасен — используйте per-device lock в менеджере.
        - PIV-слоты: 0x9A, 0x9C, 0x9D, 0x9E.

    Args:
        card_id:       Идентификатор YubiKey (например ``"yubikey_10620473"``).
        serial_number: Серийный номер для поиска конкретного устройства.

    Raises:
        AlgorithmNotAvailableError: ykman не установлен.

    Example:
        >>> backend = YubiKeyPivBackend(
        ...     card_id="yubikey_10620473", serial_number=10620473
        ... )
        >>> slots = backend.list_slots()
    """

    def __init__(self, card_id: str, serial_number: int | None = None) -> None:
        if not HAS_YKMAN:
            raise AlgorithmNotAvailableError(
                algorithm="YubiKey (PIV)",
                reason=(
                    "yubikey-manager is required for YubiKey PIV operations. "
                    "Install: pip install yubikey-manager>=5.0.0"
                ),
                required_library="yubikey-manager>=5.0.0",
            )
        self._card_id = card_id
        self._serial_number = serial_number
        logger.info(
            "YubiKeyPivBackend initialized: card_id=%s, serial=%s",
            card_id,
            serial_number,
        )

    # ------------------------------------------------------------------
    # PROPERTIES
    # ------------------------------------------------------------------

    @property
    def card_id(self) -> str:
        """Идентификатор YubiKey."""
        return self._card_id

    @property
    def backend_type(self) -> str:
        """Тип бэкенда."""
        return "yubikey_piv"

    # ------------------------------------------------------------------
    # INTERNAL: OPEN PIV SESSION
    # ------------------------------------------------------------------

    def _open_piv_session(self) -> tuple[Any, Any]:
        """
        Открыть PivSession для YubiKey с данным serial number.

        Returns:
            ``(piv_session, connection)`` — вызывающий код ОБЯЗАН
            закрыть connection после использования.

        Raises:
            DeviceNotFoundError: YubiKey не найден.
            DeviceCommunicationError: Ошибка подключения.
        """
        assert yk_list_all is not None, "HAS_YKMAN guaranteed True in __init__"
        assert SmartCardConnection is not None
        assert PivSession is not None

        connection = None
        try:
            for device, device_info in yk_list_all():
                if (
                    self._serial_number is not None
                    and device_info.serial != self._serial_number
                ):
                    continue
                connection = device.open_connection(SmartCardConnection)
                try:
                    piv = PivSession(connection)
                except Exception:
                    connection.close()
                    raise
                logger.debug("PIV session opened: card_id=%s", self._card_id)
                return piv, connection
        except DeviceCommunicationError:
            raise
        except DeviceNotFoundError:
            raise
        except Exception as exc:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass
            raise DeviceCommunicationError(
                device_id=self._card_id,
                reason=f"Ошибка подключения к YubiKey: {exc}",
            ) from exc

        raise DeviceNotFoundError(
            self._card_id,
            reason=f"YubiKey serial={self._serial_number} не найден. Проверьте подключение.",
        )

    @staticmethod
    def _resolve_yk_slot(slot_hex: str) -> Any:
        """
        Преобразовать строковый slot ID в ``YK_SLOT`` enum.

        Args:
            slot_hex: ``"9A"``, ``"9C"``, ``"9D"`` или ``"9E"``.

        Returns:
            Соответствующий ``yubikit.piv.SLOT``.

        Raises:
            SlotError: Неизвестный слот.
        """
        assert YK_SLOT is not None, "HAS_YKMAN guaranteed True in __init__"
        slot_int = _piv_slot_hex_to_int(slot_hex)
        slot_map: dict[int, Any] = {
            0x9A: YK_SLOT.AUTHENTICATION,
            0x9C: YK_SLOT.SIGNATURE,
            0x9D: YK_SLOT.KEY_MANAGEMENT,
            0x9E: YK_SLOT.CARD_AUTH,
        }
        yk_slot = slot_map.get(slot_int)
        if yk_slot is None:
            raise SlotError(
                device_id="(resolve)",
                slot=slot_int,
                reason=f"PIV slot 0x{slot_int:02X} не маппится на YK_SLOT.",
            )
        return yk_slot

    # ------------------------------------------------------------------
    # SIGN
    # ------------------------------------------------------------------

    def sign(self, slot: str, data: bytes, pin: str) -> bytes:
        """
        Подписать данные через PIV Digital Signature на YubiKey.

        Использует SHA-256 digest + PKCS#1 v1.5 padding для RSA,
        или ECDSA с SHA-256 для ECC-ключей.

        Args:
            slot: PIV-слот (``"9A"``, ``"9C"``, ``"9D"``, ``"9E"``).
            data: Данные для подписи.
            pin:  User PIN.

        Returns:
            DER-кодированная подпись.

        Raises:
            PINError: Неверный PIN.
            SlotError: Слот пуст.
            HardwareDeviceError: Ошибка устройства.
        """
        logger.info(
            "YubiKeyPiv sign: card=%s, slot=%s, data_len=%d",
            self._card_id,
            slot,
            len(data),
        )
        yk_slot = self._resolve_yk_slot(slot)
        piv, connection = self._open_piv_session()
        try:
            piv.verify_pin(pin)
            key_type = _read_slot_key_type(piv, yk_slot)
            hash_algo, pad = _signing_params_for_key_type(key_type)
            signature = piv.sign(yk_slot, key_type, data, hash_algo, pad)
            logger.info(
                "YubiKeyPiv sign complete: card=%s, sig_len=%d",
                self._card_id,
                len(signature),
            )
            return cast(bytes, signature)
        except (PINError, SlotError):
            raise
        except _ykman_pin_errors() as exc:
            raise PINError(
                self._card_id,
                "Неверный или заблокированный PIN.",
            ) from exc
        except Exception as exc:
            raise HardwareDeviceError(
                f"Ошибка подписи на YubiKey '{self._card_id}': {exc}",
                device_id=self._card_id,
            ) from exc
        finally:
            connection.close()

    # ------------------------------------------------------------------
    # DECRYPT
    # ------------------------------------------------------------------

    def decrypt(self, slot: str, ciphertext: bytes, pin: str) -> bytes:
        """
        Расшифровать данные через PIV Key Management на YubiKey.

        Для RSA-ключей: RSA PKCS#1 v1.5 расшифровка.
        Для ECC-ключей: ECDH не поддерживается через PIV decrypt —
        используйте OpenPGP-бэкенд или отдельный ECDH-метод (roadmap Phase 5).

        Args:
            slot:       PIV-слот (обычно ``"9D"`` — Key Management).
            ciphertext: RSA-зашифрованные данные.
            pin:        User PIN.

        Returns:
            Расшифрованные данные.

        Raises:
            PINError: Неверный PIN.
            HardwareDeviceError: Ошибка расшифровки или ECC-ключ в слоте.
        """
        logger.info(
            "YubiKeyPiv decrypt: card=%s, slot=%s, ct_len=%d",
            self._card_id,
            slot,
            len(ciphertext),
        )
        yk_slot = self._resolve_yk_slot(slot)
        piv, connection = self._open_piv_session()
        try:
            piv.verify_pin(pin)
            key_type = _read_slot_key_type(piv, yk_slot)
            if not _is_rsa_key_type(key_type):
                raise HardwareDeviceError(
                    f"PIV decrypt поддерживает только RSA-ключи. "
                    f"Слот {slot} содержит {key_type}. "
                    f"Для ECC используйте OpenPGP-бэкенд (ECDH).",
                    device_id=self._card_id,
                )
            plaintext = piv.decrypt(
                yk_slot,
                ciphertext,
                asym_padding.PKCS1v15(),
            )
            logger.info(
                "YubiKeyPiv decrypt complete: card=%s, pt_len=%d",
                self._card_id,
                len(plaintext),
            )
            return cast(bytes, plaintext)
        except (PINError, SlotError, HardwareDeviceError):
            raise
        except _ykman_pin_errors() as exc:
            raise PINError(
                self._card_id,
                "Неверный или заблокированный PIN.",
            ) from exc
        except Exception as exc:
            raise HardwareDeviceError(
                f"Ошибка расшифровки на YubiKey '{self._card_id}': {exc}",
                device_id=self._card_id,
            ) from exc
        finally:
            connection.close()

    # ------------------------------------------------------------------
    # GET PUBLIC KEY
    # ------------------------------------------------------------------

    def get_public_key(self, slot: str) -> bytes:
        """
        Получить публичный ключ из PIV-слота YubiKey.

        Returns:
            Публичный ключ в DER формате (SubjectPublicKeyInfo).

        Raises:
            SlotError: Слот пуст.
            HardwareDeviceError: Ошибка чтения.
        """
        logger.debug(
            "YubiKeyPiv get_public_key: card=%s, slot=%s",
            self._card_id,
            slot,
        )
        yk_slot = self._resolve_yk_slot(slot)
        piv, connection = self._open_piv_session()
        try:
            cert = piv.get_certificate(yk_slot)
            pub_key = cert.public_key()
            return cast(bytes, pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
        except Exception as exc:
            raise SlotError(
                device_id=self._card_id,
                slot=_piv_slot_hex_to_int(slot),
                reason=f"Не удалось получить ключ: {exc}",
            ) from exc
        finally:
            connection.close()

    # ------------------------------------------------------------------
    # IMPORT KEY
    # ------------------------------------------------------------------

    def import_key(self, slot: str, key_data: bytes, pin: str) -> None:
        """
        Импортировать приватный ключ в PIV-слот YubiKey.

        Для PIV-операций ``pin`` используется как management key (24 байта).
        Если передан PIN пользователя, он будет проигнорирован для операций
        ключевого импорта — потребуется management key.

        Args:
            slot:     PIV-слот.
            key_data: Приватный ключ в DER PKCS#8.
            pin:      Management key (hex) или PIN.

        Raises:
            InvalidKeyError: Ключ невалиден.
            HardwareDeviceError: Ошибка записи.
        """
        logger.info(
            "YubiKeyPiv import_key: card=%s, slot=%s",
            self._card_id,
            slot,
        )
        yk_slot = self._resolve_yk_slot(slot)
        piv, connection = self._open_piv_session()
        try:
            private_key = load_der_private_key(key_data, password=None)
            piv.put_key(yk_slot, private_key)
            logger.info(
                "YubiKeyPiv import_key complete: card=%s, slot=%s",
                self._card_id,
                slot,
            )
        except ValueError as exc:
            raise InvalidKeyError(
                f"Невалидный DER-ключ для импорта в YubiKey '{self._card_id}': {exc}",
                algorithm="unknown",
            ) from exc
        except Exception as exc:
            raise HardwareDeviceError(
                f"Ошибка импорта ключа в YubiKey '{self._card_id}': {exc}",
                device_id=self._card_id,
            ) from exc
        finally:
            connection.close()

    # ------------------------------------------------------------------
    # GENERATE KEY
    # ------------------------------------------------------------------

    def generate_key(self, slot: str, algorithm: str, pin: str) -> bytes:
        """
        Сгенерировать ключевую пару на YubiKey (on-board).

        Args:
            slot:      PIV-слот.
            algorithm: ``"RSA-2048"``, ``"ECC-P256"``, ``"ECC-P384"`` и т.д.
            pin:       Management key или PIN.

        Returns:
            Публичный ключ (DER SubjectPublicKeyInfo).

        Raises:
            AlgorithmNotAvailableError: Алгоритм не поддерживается.
            KeyGenerationError: Ошибка генерации.
        """
        logger.info(
            "YubiKeyPiv generate_key: card=%s, slot=%s, algo=%s",
            self._card_id,
            slot,
            algorithm,
        )
        yk_slot = self._resolve_yk_slot(slot)
        key_type = _resolve_yk_key_type(algorithm)
        piv, connection = self._open_piv_session()
        try:
            pub_key = piv.generate_key(yk_slot, key_type)
            der_bytes = cast(
                bytes,
                pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo),
            )
            logger.info(
                "YubiKeyPiv generate_key complete: card=%s, pub_len=%d",
                self._card_id,
                len(der_bytes),
            )
            return der_bytes
        except Exception as exc:
            raise KeyGenerationError(
                f"Генерация ключа на YubiKey '{self._card_id}' не удалась: {exc}",
                algorithm=algorithm,
            ) from exc
        finally:
            connection.close()

    # ------------------------------------------------------------------
    # LIST SLOTS
    # ------------------------------------------------------------------

    def list_slots(self) -> list[SlotInfo]:
        """
        Получить информацию обо всех PIV-слотах YubiKey.

        Проверяет наличие сертификата в каждом слоте для определения
        статуса.

        Returns:
            Список ``SlotInfo`` для слотов 9A, 9C, 9D, 9E.
        """
        logger.debug("YubiKeyPiv list_slots: card=%s", self._card_id)
        piv, connection = self._open_piv_session()
        slots: list[SlotInfo] = []
        try:
            for slot_hex, label in _PIV_SLOT_MAP.items():
                yk_slot = self._resolve_yk_slot(slot_hex)
                try:
                    cert = piv.get_certificate(yk_slot)
                    pub_key = cert.public_key()
                    algo = type(pub_key).__name__
                    key_size = getattr(pub_key, "key_size", 0)
                    slots.append(
                        SlotInfo(
                            slot_id=slot_hex,
                            label=label,
                            algorithm=algo,
                            status=SlotStatus.POPULATED,
                            key_size=key_size,
                        )
                    )
                except Exception:
                    slots.append(
                        SlotInfo(
                            slot_id=slot_hex,
                            label=label,
                            status=SlotStatus.EMPTY,
                        )
                    )
        finally:
            connection.close()
        return slots

    def __repr__(self) -> str:
        return (
            f"YubiKeyPivBackend(card_id={self._card_id!r}, "
            f"serial={self._serial_number})"
        )


# ==============================================================================
# OPENPGP DEVICE BACKEND (ADAPTER)
# ==============================================================================


class OpenPGPDeviceBackend:
    """
    Адаптер ``OpenPGPBackend`` → ``DeviceBackend`` Protocol.

    Привязывает существующий ``OpenPGPBackend`` к конкретному устройству
    (card_id) и транслирует вызовы в формате DeviceBackend Protocol.

    Маппинг слотов:
        ``"sign"``    → ``OpenPGPSlot.SIGN``
        ``"encrypt"`` → ``OpenPGPSlot.ENCRYPT``
        ``"auth"``    → ``OpenPGPSlot.AUTH``

    Зависимости: pyscard>=2.0.0 (через ``OpenPGPBackend`` → ``ApduTransport``).

    Args:
        card_id:        Идентификатор ридера/устройства.
        openpgp_backend: Экземпляр ``OpenPGPBackend``. Если ``None`` — создаётся новый.

    Example:
        >>> from src.security.crypto.hardware.openpgp_backend import OpenPGPBackend
        >>> backend = OpenPGPDeviceBackend("sc_0_YubiKey 5 NFC 0")
        >>> sig = backend.sign("sign", b"data", pin="123456")
    """

    def __init__(
        self,
        card_id: str,
        openpgp_backend: OpenPGPBackend | None = None,
    ) -> None:
        from src.security.crypto.hardware.openpgp_backend import (
            OpenPGPBackend as _OpenPGPBackend,
        )

        self._card_id = card_id
        self._backend = (
            openpgp_backend if openpgp_backend is not None else _OpenPGPBackend()
        )
        logger.info("OpenPGPDeviceBackend initialized: card_id=%s", card_id)

    # ------------------------------------------------------------------
    # PROPERTIES
    # ------------------------------------------------------------------

    @property
    def card_id(self) -> str:
        """Идентификатор устройства."""
        return self._card_id

    @property
    def backend_type(self) -> str:
        """Тип бэкенда."""
        return "openpgp"

    # ------------------------------------------------------------------
    # INTERNAL: SLOT RESOLUTION
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_slot(slot: str) -> OpenPGPSlot:
        """
        Преобразовать строковый slot ID в ``OpenPGPSlot``.

        Args:
            slot: ``"sign"``, ``"encrypt"`` или ``"auth"``.

        Returns:
            Соответствующий ``OpenPGPSlot``.

        Raises:
            SlotError: Неизвестный слот.
        """
        from src.security.crypto.hardware.openpgp_backend import OpenPGPSlot

        slot_lower = slot.lower().strip()
        slot_map: dict[str, OpenPGPSlot] = {
            "sign": OpenPGPSlot.SIGN,
            "encrypt": OpenPGPSlot.ENCRYPT,
            "auth": OpenPGPSlot.AUTH,
        }
        resolved = slot_map.get(slot_lower)
        if resolved is None:
            valid = ", ".join(sorted(slot_map))
            raise SlotError(
                device_id="(validation)",
                slot=0,
                reason=(f"Неизвестный OpenPGP-слот '{slot}'. " f"Допустимые: {valid}."),
            )
        return resolved

    # ------------------------------------------------------------------
    # SIGN
    # ------------------------------------------------------------------

    def sign(self, slot: str, data: bytes, pin: str) -> bytes:
        """
        Подписать данные через OpenPGP Sign-слот.

        Args:
            slot: ``"sign"`` (или ``"auth"`` для INTERNAL AUTHENTICATE).
            data: Данные или хеш для подписи.
            pin:  User PIN (PW1).

        Returns:
            Raw подпись (64 байта для Ed25519, DER для RSA).
        """
        logger.info(
            "OpenPGPDevice sign: card=%s, slot=%s, data_len=%d",
            self._card_id,
            slot,
            len(data),
        )
        openpgp_slot = self._resolve_slot(slot)
        from src.security.crypto.hardware.openpgp_backend import OpenPGPSlot

        if openpgp_slot == OpenPGPSlot.AUTH:
            return self._backend.authenticate(self._card_id, data, pin)
        return self._backend.sign(self._card_id, data, pin)

    # ------------------------------------------------------------------
    # DECRYPT
    # ------------------------------------------------------------------

    def decrypt(self, slot: str, ciphertext: bytes, pin: str) -> bytes:
        """
        Расшифровать данные или выполнить ECDH через OpenPGP Encrypt-слот.

        Для X25519 ECDH: оберните эфемерный ключ через
        ``OpenPGPBackend.build_ecdh_decipher_data()`` перед передачей.

        Args:
            slot:       ``"encrypt"``.
            ciphertext: ECDH-wrapped ключ или RSA-шифротекст.
            pin:        User PIN (PW1 mode 2).

        Returns:
            Расшифрованные данные или ECDH shared secret.
        """
        self._resolve_slot(slot)  # валидация
        return self._backend.decrypt(self._card_id, ciphertext, pin)

    # ------------------------------------------------------------------
    # GET PUBLIC KEY
    # ------------------------------------------------------------------

    def get_public_key(self, slot: str) -> bytes:
        """
        Получить публичный ключ из OpenPGP-слота.

        Args:
            slot: ``"sign"``, ``"encrypt"`` или ``"auth"``.

        Returns:
            Raw публичный ключ (32 байта для Ed25519/X25519).
        """
        from src.security.crypto.hardware.openpgp_backend import OpenPGPSlot

        openpgp_slot = self._resolve_slot(slot)
        keys = self._backend.get_public_keys(self._card_id)
        key_map = {
            OpenPGPSlot.SIGN: keys.sign,
            OpenPGPSlot.ENCRYPT: keys.encrypt,
            OpenPGPSlot.AUTH: keys.auth,
        }
        key_data = key_map[openpgp_slot]
        if not key_data:
            raise SlotError(
                device_id=self._card_id,
                slot=0,
                reason=f"OpenPGP-слот '{slot}' пуст.",
            )
        return key_data

    # ------------------------------------------------------------------
    # IMPORT KEY
    # ------------------------------------------------------------------

    def import_key(self, slot: str, key_data: bytes, pin: str) -> None:
        """
        Импортировать приватный ключ в OpenPGP-слот.

        Args:
            slot:     ``"sign"``, ``"encrypt"`` или ``"auth"``.
            key_data: TLV-данные ключа (подготовленные через
                      ``OpenPGPBackend.build_ed25519_private_key_tl()`` и т.д.).
            pin:      Admin PIN (PW3).
        """
        openpgp_slot = self._resolve_slot(slot)
        self._backend.import_key(self._card_id, openpgp_slot, key_data, pin)

    # ------------------------------------------------------------------
    # GENERATE KEY
    # ------------------------------------------------------------------

    def generate_key(self, slot: str, algorithm: str, pin: str) -> bytes:
        """
        Сгенерировать ключевую пару на устройстве через OpenPGP.

        Args:
            slot:      ``"sign"``, ``"encrypt"`` или ``"auth"``.
            algorithm: ``"Ed25519"``, ``"X25519"``, ``"RSA-2048"`` и т.д.
            pin:       Admin PIN (PW3).

        Returns:
            Raw публичный ключ.
        """
        from src.security.crypto.hardware.openpgp_backend import OpenPGPAlgorithm

        openpgp_slot = self._resolve_slot(slot)
        algo_map: dict[str, OpenPGPAlgorithm] = {
            "Ed25519": OpenPGPAlgorithm.ED25519,
            "X25519": OpenPGPAlgorithm.X25519,
            "RSA-2048": OpenPGPAlgorithm.RSA2048,
            "RSA-3072": OpenPGPAlgorithm.RSA3072,
            "RSA-4096": OpenPGPAlgorithm.RSA4096,
        }
        openpgp_algo = algo_map.get(algorithm)
        if openpgp_algo is None:
            valid = ", ".join(sorted(algo_map))
            raise AlgorithmNotAvailableError(
                algorithm=algorithm,
                reason=(
                    f"Алгоритм '{algorithm}' не поддерживается OpenPGP-бэкендом. "
                    f"Доступные: {valid}."
                ),
                required_library="N/A",
            )
        return self._backend.generate_key_onboard(
            self._card_id, openpgp_slot, openpgp_algo, pin
        )

    # ------------------------------------------------------------------
    # LIST SLOTS
    # ------------------------------------------------------------------

    def list_slots(self) -> list[SlotInfo]:
        """
        Получить информацию о трёх слотах OpenPGP-карты.

        Returns:
            Список ``SlotInfo`` для слотов sign, encrypt, auth.
        """
        keys = self._backend.get_public_keys(self._card_id)
        return [
            SlotInfo(
                slot_id="sign",
                label="OpenPGP Sign",
                algorithm=keys.sign_algorithm,
                status=SlotStatus.POPULATED if keys.sign else SlotStatus.EMPTY,
                key_size=len(keys.sign) * 8 if keys.sign else 0,
            ),
            SlotInfo(
                slot_id="encrypt",
                label="OpenPGP Encrypt",
                algorithm=keys.encrypt_algorithm,
                status=SlotStatus.POPULATED if keys.encrypt else SlotStatus.EMPTY,
                key_size=len(keys.encrypt) * 8 if keys.encrypt else 0,
            ),
            SlotInfo(
                slot_id="auth",
                label="OpenPGP Auth",
                algorithm=keys.auth_algorithm,
                status=SlotStatus.POPULATED if keys.auth else SlotStatus.EMPTY,
                key_size=len(keys.auth) * 8 if keys.auth else 0,
            ),
        ]

    def __repr__(self) -> str:
        return f"OpenPGPDeviceBackend(card_id={self._card_id!r})"


# ==============================================================================
# JAVACARD RAW BACKEND
# ==============================================================================

# Default J3R200 custom applet AID (пример — должен совпадать с загруженным апплетом)
_DEFAULT_JAVACARD_APPLET_AID: Final[bytes] = bytes.fromhex("F058544350303100")
"""AID кастомного апплета FX Text Processor для J3R200 (FXTCPnn)."""

# Custom APDU INS bytes for J3R200 applet
_JC_INS_SIGN: Final[int] = 0x2A
_JC_INS_DECRYPT: Final[int] = 0x2C
_JC_INS_GET_PUBLIC_KEY: Final[int] = 0x30
_JC_INS_IMPORT_KEY: Final[int] = 0x32
_JC_INS_GENERATE_KEY: Final[int] = 0x34
_JC_INS_LIST_SLOTS: Final[int] = 0x36
_JC_INS_AES_ENCRYPT: Final[int] = 0x40
_JC_INS_AES_DECRYPT: Final[int] = 0x42
_JC_INS_HMAC: Final[int] = 0x44
_JC_INS_GET_COUNTER: Final[int] = 0x46
_JC_INS_INCREMENT_COUNTER: Final[int] = 0x48


class JavaCardRawBackend:
    """
    Бэкенд для кастомных апплетов на JavaCard (J3R200 / JCOP4 P71).

    Общается с картой через raw APDU (``ApduTransport``). Требует, чтобы
    на карту был загружен соответствующий апплет (через GlobalPlatformPro).

    Кроме стандартных операций ``DeviceBackend`` предоставляет специфичные
    для J3R200 возможности:
        - ``aes_encrypt`` / ``aes_decrypt`` — AES-128 на карте
        - ``hmac_sha256`` — HMAC-SHA256 challenge-response
        - ``get_counter`` / ``increment_counter`` — монотонный счётчик (EEPROM)

    Ограничения:
        - Требует ``pyscard>=2.0.0``.
        - Апплет должен быть предварительно загружен на карту.
        - Не потокобезопасен.

    Args:
        card_id:    Идентификатор ридера (имя PC/SC ридера).
        applet_aid: AID кастомного апплета. По умолчанию — стандартный
                    AID для FX Text Processor.

    Raises:
        AlgorithmNotAvailableError: pyscard не установлен.

    Example:
        >>> backend = JavaCardRawBackend(card_id="HID Global OMNIKEY 3121 0")
        >>> counter = backend.get_counter(pin="123456")
        >>> backend.increment_counter(pin="123456")
    """

    def __init__(
        self,
        card_id: str,
        applet_aid: bytes = _DEFAULT_JAVACARD_APPLET_AID,
    ) -> None:
        if not HAS_PYSCARD:
            raise AlgorithmNotAvailableError(
                algorithm="JavaCard (J3R200)",
                reason=(
                    "pyscard is required for JavaCard APDU operations. "
                    "Install: pip install pyscard>=2.0.0"
                ),
                required_library="pyscard>=2.0.0",
            )
        self._card_id = card_id
        self._applet_aid = applet_aid
        logger.info(
            "JavaCardRawBackend initialized: card_id=%s, applet_aid=%s",
            card_id,
            applet_aid.hex().upper(),
        )

    # ------------------------------------------------------------------
    # PROPERTIES
    # ------------------------------------------------------------------

    @property
    def card_id(self) -> str:
        """Идентификатор ридера/устройства."""
        return self._card_id

    @property
    def backend_type(self) -> str:
        """Тип бэкенда."""
        return "javacard_raw"

    # ------------------------------------------------------------------
    # INTERNAL: APDU HELPERS
    # ------------------------------------------------------------------

    def _send_apdu(
        self,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b"",
        *,
        pin: str | None = None,
    ) -> bytes:
        """
        Отправить APDU кастомному апплету и вернуть данные ответа.

        Последовательность:
        1. SELECT APPLICATION по AID.
        2. VERIFY PIN (если передан).
        3. Отправить целевую команду.

        Args:
            ins:  INS-байт команды.
            p1:   P1-байт.
            p2:   P2-байт.
            data: Данные команды.
            pin:  PIN для верификации (``None`` — без PIN).

        Returns:
            Данные ответа (без SW).

        Raises:
            PINError: Неверный PIN.
            HardwareDeviceError: Ошибка APDU.
        """
        from src.security.crypto.hardware.apdu_transport import ApduTransport

        with ApduTransport(self._card_id) as transport:
            transport.select_applet(self._applet_aid)
            if pin is not None:
                transport.verify_pin(pin, pin_ref=0x81)
            response = transport.send_apdu(
                cla=0x00,
                ins=ins,
                p1=p1,
                p2=p2,
                data=data,
                le=0,
            )
            if not response.ok:
                raise HardwareDeviceError(
                    f"APDU command INS=0x{ins:02X} failed: SW={response.sw_hex}",
                    device_id=self._card_id,
                    context={"ins": f"0x{ins:02X}", "sw": response.sw_hex},
                )
            return response.data

    @staticmethod
    def _validate_slot_byte(slot: str) -> int:
        """
        Преобразовать строковый slot в P2-байт (0x00–0xFF).

        Args:
            slot: Строка — номер слота (``"0"``, ``"1"``, ``"2"`` и т.д.).

        Returns:
            Целочисленный номер слота.

        Raises:
            SlotError: Невалидный слот.
        """
        try:
            slot_int = int(slot)
        except ValueError:
            raise SlotError(
                device_id="(validation)",
                slot=0,
                reason=(f"JavaCard slot должен быть числом, получено: '{slot}'."),
            )
        if not 0 <= slot_int <= 255:
            raise SlotError(
                device_id="(validation)",
                slot=slot_int,
                reason=f"JavaCard slot вне диапазона 0–255: {slot_int}.",
            )
        return slot_int

    # ------------------------------------------------------------------
    # SIGN
    # ------------------------------------------------------------------

    def sign(self, slot: str, data: bytes, pin: str) -> bytes:
        """
        Подписать данные на J3R200 (RSA через кастомный апплет).

        Args:
            slot: Номер слота на карте (``"0"``, ``"1"`` и т.д.).
            data: Данные для подписи.
            pin:  User PIN.

        Returns:
            Подпись (формат зависит от алгоритма в слоте).
        """
        slot_byte = self._validate_slot_byte(slot)
        logger.info(
            "JavaCard sign: card=%s, slot=%d, data_len=%d",
            self._card_id,
            slot_byte,
            len(data),
        )
        return self._send_apdu(_JC_INS_SIGN, p1=0x00, p2=slot_byte, data=data, pin=pin)

    # ------------------------------------------------------------------
    # DECRYPT
    # ------------------------------------------------------------------

    def decrypt(self, slot: str, ciphertext: bytes, pin: str) -> bytes:
        """
        Расшифровать данные на J3R200.

        Args:
            slot:       Номер слота.
            ciphertext: Зашифрованные данные.
            pin:        User PIN.

        Returns:
            Расшифрованные данные.
        """
        slot_byte = self._validate_slot_byte(slot)
        logger.info(
            "JavaCard decrypt: card=%s, slot=%d, ct_len=%d",
            self._card_id,
            slot_byte,
            len(ciphertext),
        )
        return self._send_apdu(
            _JC_INS_DECRYPT, p1=0x00, p2=slot_byte, data=ciphertext, pin=pin
        )

    # ------------------------------------------------------------------
    # GET PUBLIC KEY
    # ------------------------------------------------------------------

    def get_public_key(self, slot: str) -> bytes:
        """
        Получить публичный ключ из слота J3R200.

        Не требует PIN.

        Args:
            slot: Номер слота.

        Returns:
            Публичный ключ (DER или raw — зависит от апплета).
        """
        slot_byte = self._validate_slot_byte(slot)
        return self._send_apdu(_JC_INS_GET_PUBLIC_KEY, p1=0x00, p2=slot_byte)

    # ------------------------------------------------------------------
    # IMPORT KEY
    # ------------------------------------------------------------------

    def import_key(self, slot: str, key_data: bytes, pin: str) -> None:
        """
        Импортировать приватный ключ в слот J3R200.

        Args:
            slot:     Номер слота.
            key_data: Приватный ключ (формат зависит от апплета).
            pin:      Admin PIN.
        """
        slot_byte = self._validate_slot_byte(slot)
        logger.info(
            "JavaCard import_key: card=%s, slot=%d",
            self._card_id,
            slot_byte,
        )
        self._send_apdu(
            _JC_INS_IMPORT_KEY, p1=0x00, p2=slot_byte, data=key_data, pin=pin
        )

    # ------------------------------------------------------------------
    # GENERATE KEY
    # ------------------------------------------------------------------

    def generate_key(self, slot: str, algorithm: str, pin: str) -> bytes:
        """
        Сгенерировать ключевую пару на J3R200.

        Алгоритм кодируется в P1 — маппинг:
            ``"RSA-2048"`` → 0x01, ``"RSA-3072"`` → 0x02,
            ``"RSA-4096"`` → 0x03, ``"AES-128"``  → 0x10.

        Args:
            slot:      Номер слота.
            algorithm: Алгоритм.
            pin:       Admin PIN.

        Returns:
            Публичный ключ сгенерированной пары.
        """
        slot_byte = self._validate_slot_byte(slot)
        algo_p1 = _resolve_jc_algorithm(algorithm)
        logger.info(
            "JavaCard generate_key: card=%s, slot=%d, algo=%s",
            self._card_id,
            slot_byte,
            algorithm,
        )
        return self._send_apdu(_JC_INS_GENERATE_KEY, p1=algo_p1, p2=slot_byte, pin=pin)

    # ------------------------------------------------------------------
    # LIST SLOTS
    # ------------------------------------------------------------------

    def list_slots(self) -> list[SlotInfo]:
        """
        Получить информацию о слотах кастомного апплета.

        Апплет возвращает бинарные данные: по 4 байта на слот
        ``[slot_id, status, algo_id, key_size_div_256]``.

        Returns:
            Список ``SlotInfo``.
        """
        try:
            raw = self._send_apdu(_JC_INS_LIST_SLOTS, p1=0x00, p2=0x00)
        except HardwareDeviceError:
            logger.warning(
                "JavaCard list_slots: command not supported on card=%s",
                self._card_id,
            )
            return []

        slots: list[SlotInfo] = []
        idx = 0
        while idx + 3 < len(raw):
            sid = raw[idx]
            status_byte = raw[idx + 1]
            algo_byte = raw[idx + 2]
            key_size = raw[idx + 3] * 256 if idx + 3 < len(raw) else 0
            idx += 4

            status = SlotStatus.POPULATED if status_byte == 0x01 else SlotStatus.EMPTY
            algo = _JC_ALGO_NAMES.get(algo_byte, f"AlgoID-0x{algo_byte:02X}")

            slots.append(
                SlotInfo(
                    slot_id=str(sid),
                    label=f"JavaCard Slot {sid}",
                    algorithm=algo if status == SlotStatus.POPULATED else "",
                    status=status,
                    key_size=key_size,
                )
            )
        return slots

    # ------------------------------------------------------------------
    # J3R200-SPECIFIC: AES ON CARD
    # ------------------------------------------------------------------

    def aes_encrypt(self, data: bytes, pin: str) -> bytes:
        """
        Зашифровать данные AES-128 на карте. Ключ не покидает J3R200.

        Args:
            data: Данные для шифрования (должны быть кратны 16 байтам
                  или padding обрабатывается апплетом).
            pin:  User PIN.

        Returns:
            Зашифрованные данные.
        """
        logger.info(
            "JavaCard AES encrypt: card=%s, data_len=%d",
            self._card_id,
            len(data),
        )
        return self._send_apdu(
            _JC_INS_AES_ENCRYPT, p1=0x00, p2=0x00, data=data, pin=pin
        )

    def aes_decrypt(self, ciphertext: bytes, pin: str) -> bytes:
        """
        Расшифровать данные AES-128 на карте. Ключ не покидает J3R200.

        Args:
            ciphertext: Зашифрованные данные.
            pin:        User PIN.

        Returns:
            Расшифрованные данные.
        """
        logger.info(
            "JavaCard AES decrypt: card=%s, ct_len=%d",
            self._card_id,
            len(ciphertext),
        )
        return self._send_apdu(
            _JC_INS_AES_DECRYPT, p1=0x00, p2=0x00, data=ciphertext, pin=pin
        )

    # ------------------------------------------------------------------
    # J3R200-SPECIFIC: HMAC-SHA256
    # ------------------------------------------------------------------

    def hmac_sha256(self, challenge: bytes, pin: str) -> bytes:
        """
        HMAC-SHA256 challenge-response на карте.

        Аналог YubiKey HMAC-SHA1, но с SHA-256 и настраиваемым секретом
        внутри J3R200. Полезно для KDF: подаём challenge → получаем
        HMAC → используем как ключ шифрования.

        Args:
            challenge: Данные для HMAC (до 255 байт).
            pin:       User PIN.

        Returns:
            HMAC-SHA256 (32 байта).
        """
        if len(challenge) > 255:
            raise ValueError(
                f"HMAC challenge не должен превышать 255 байт, "
                f"получено {len(challenge)}."
            )
        logger.info(
            "JavaCard HMAC-SHA256: card=%s, challenge_len=%d",
            self._card_id,
            len(challenge),
        )
        return self._send_apdu(_JC_INS_HMAC, p1=0x00, p2=0x00, data=challenge, pin=pin)

    # ------------------------------------------------------------------
    # J3R200-SPECIFIC: MONOTONIC COUNTER
    # ------------------------------------------------------------------

    def get_counter(self, pin: str) -> int:
        """
        Получить текущее значение монотонного счётчика из EEPROM.

        Используется для нумерации защищённых бланков — невозможно
        откатить (аппаратная гарантия уникальности серийных номеров).

        Args:
            pin: User PIN.

        Returns:
            Текущее значение счётчика (4-байтовый unsigned int, big-endian).
        """
        raw = self._send_apdu(_JC_INS_GET_COUNTER, p1=0x00, p2=0x00, pin=pin)
        if len(raw) < 4:
            raise DeviceCommunicationError(
                device_id=self._card_id,
                reason=(f"GET_COUNTER: ожидалось 4 байта, получено {len(raw)}."),
            )
        return int.from_bytes(raw[:4], byteorder="big")

    def increment_counter(self, pin: str) -> int:
        """
        Инкрементировать монотонный счётчик и вернуть новое значение.

        Операция атомарна — даже при сбое питания счётчик не сбрасывается.

        Args:
            pin: User PIN.

        Returns:
            Новое значение счётчика.
        """
        raw = self._send_apdu(_JC_INS_INCREMENT_COUNTER, p1=0x00, p2=0x00, pin=pin)
        if len(raw) < 4:
            raise DeviceCommunicationError(
                device_id=self._card_id,
                reason=(f"INCREMENT_COUNTER: ожидалось 4 байта, получено {len(raw)}."),
            )
        value = int.from_bytes(raw[:4], byteorder="big")
        logger.info(
            "JavaCard counter incremented: card=%s, new_value=%d",
            self._card_id,
            value,
        )
        return value

    def __repr__(self) -> str:
        return (
            f"JavaCardRawBackend(card_id={self._card_id!r}, "
            f"applet_aid={self._applet_aid.hex().upper()})"
        )


# ==============================================================================
# MODULE-LEVEL HELPERS
# ==============================================================================

# JavaCard algorithm P1 mapping
_JC_ALGO_MAP: Final[dict[str, int]] = {
    "RSA-2048": 0x01,
    "RSA-3072": 0x02,
    "RSA-4096": 0x03,
    "AES-128": 0x10,
    "AES-192": 0x11,
    "AES-256": 0x12,
}

# Reverse mapping for list_slots decoding
_JC_ALGO_NAMES: Final[dict[int, str]] = {v: k for k, v in _JC_ALGO_MAP.items()}


def _resolve_jc_algorithm(algorithm: str) -> int:
    """
    Преобразовать строковое имя алгоритма в P1-байт для JavaCard APDU.

    Args:
        algorithm: Имя алгоритма (``"RSA-2048"``, ``"AES-128"`` и т.д.).

    Returns:
        P1-байт.

    Raises:
        AlgorithmNotAvailableError: Неизвестный алгоритм.
    """
    p1 = _JC_ALGO_MAP.get(algorithm)
    if p1 is None:
        valid = ", ".join(sorted(_JC_ALGO_MAP))
        raise AlgorithmNotAvailableError(
            algorithm=algorithm,
            reason=(
                f"Алгоритм '{algorithm}' не поддерживается JavaCard-бэкендом. "
                f"Доступные: {valid}."
            ),
            required_library="N/A",
        )
    return p1


def _ykman_pin_errors() -> tuple[type[Exception], ...]:
    """
    Вернуть tuple типов исключений ykman, связанных с PIN.

    Используется в ``except _ykman_pin_errors() as exc:`` для надёжного
    определения PIN-ошибок вместо сопоставления по подстроке.

    Returns:
        Tuple исключений. Пустой tuple если ykman не установлен
        (тогда ``except ()`` ничего не ловит — корректное поведение).
    """
    errors: list[type[Exception]] = []
    try:
        from yubikit.core import InvalidPinError

        errors.append(InvalidPinError)
    except ImportError:
        pass
    try:
        from yubikit.piv import AuthRequiredError  # type: ignore[attr-defined]

        errors.append(AuthRequiredError)
    except ImportError:
        pass
    return tuple(errors)


def _read_slot_key_type(piv: Any, yk_slot: Any) -> Any:
    """
    Определить тип ключа в PIV-слоте по сертификату.

    Читает сертификат из слота, извлекает публичный ключ и определяет
    соответствующий ``YK_KEY_TYPE``.

    Args:
        piv:     Активная ``PivSession``.
        yk_slot: ``YK_SLOT`` enum.

    Returns:
        ``YK_KEY_TYPE`` ключа в слоте.

    Raises:
        SlotError: Слот пуст или не содержит сертификат.
    """
    assert YK_KEY_TYPE is not None
    try:
        cert = piv.get_certificate(yk_slot)
        pub_key = cert.public_key()
    except Exception as exc:
        raise SlotError(
            device_id="(read_key_type)",
            slot=int(yk_slot) if isinstance(yk_slot, int) else 0,
            reason=f"Слот не содержит сертификат: {exc}",
        ) from exc

    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    if isinstance(pub_key, rsa.RSAPublicKey):
        size = pub_key.key_size
        size_map: dict[int, Any] = {
            2048: YK_KEY_TYPE.RSA2048,
            3072: getattr(YK_KEY_TYPE, "RSA3072", None),
            4096: getattr(YK_KEY_TYPE, "RSA4096", None),
        }
        key_type = size_map.get(size)
        if key_type is None:
            raise SlotError(
                device_id="(read_key_type)",
                slot=0,
                reason=f"Неподдерживаемый размер RSA: {size}",
            )
        return key_type
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve_name = pub_key.curve.name
        curve_map: dict[str, Any] = {
            "secp256r1": YK_KEY_TYPE.ECCP256,
            "secp384r1": YK_KEY_TYPE.ECCP384,
        }
        key_type = curve_map.get(curve_name)
        if key_type is None:
            raise SlotError(
                device_id="(read_key_type)",
                slot=0,
                reason=f"Неподдерживаемая кривая: {curve_name}",
            )
        return key_type
    raise SlotError(
        device_id="(read_key_type)",
        slot=0,
        reason=f"Неизвестный тип ключа: {type(pub_key).__name__}",
    )


def _is_rsa_key_type(key_type: Any) -> bool:
    """Проверить, является ли YK_KEY_TYPE RSA-типом."""
    assert YK_KEY_TYPE is not None
    rsa_types = {YK_KEY_TYPE.RSA2048}
    for attr in ("RSA3072", "RSA4096"):
        val = getattr(YK_KEY_TYPE, attr, None)
        if val is not None:
            rsa_types.add(val)
    return key_type in rsa_types


def _signing_params_for_key_type(key_type: Any) -> tuple[Any, Any]:
    """
    Определить параметры подписи (hash, padding) по типу ключа.

    RSA → SHA-256 + PKCS1v15.
    ECC → SHA-256 + ec.ECDSA (padding передаётся как None в ykman).

    Args:
        key_type: ``YK_KEY_TYPE``.

    Returns:
        ``(hash_algorithm, padding_or_none)`` для ``piv.sign()``.
    """
    if _is_rsa_key_type(key_type):
        return hashes.SHA256(), asym_padding.PKCS1v15()
    # ECC: ykman PivSession.sign() принимает hash и padding=None для ECDSA
    return hashes.SHA256(), None


def _resolve_yk_key_type(algorithm: str) -> Any:
    """
    Преобразовать строковое имя алгоритма в ``YK_KEY_TYPE``.

    Args:
        algorithm: ``"RSA-2048"``, ``"ECC-P256"``, ``"ECC-P384"`` и т.д.

    Returns:
        Соответствующий ``yubikit.piv.KEY_TYPE``.

    Raises:
        AlgorithmNotAvailableError: Неизвестный алгоритм.
    """
    assert YK_KEY_TYPE is not None, "HAS_YKMAN guaranteed True by caller"
    algo_map: dict[str, Any] = {
        "RSA-2048": YK_KEY_TYPE.RSA2048,
        "RSA-3072": getattr(YK_KEY_TYPE, "RSA3072", None),
        "RSA-4096": getattr(YK_KEY_TYPE, "RSA4096", None),
        "ECC-P256": YK_KEY_TYPE.ECCP256,
        "ECC-P384": YK_KEY_TYPE.ECCP384,
    }
    key_type = algo_map.get(algorithm)
    if key_type is None:
        valid = ", ".join(k for k, v in algo_map.items() if v is not None)
        raise AlgorithmNotAvailableError(
            algorithm=algorithm,
            reason=(
                f"Алгоритм '{algorithm}' не поддерживается YubiKey PIV. "
                f"Доступные: {valid}."
            ),
            required_library="yubikey-manager>=5.0.0",
        )
    return key_type


# ==============================================================================
# FACTORY FUNCTION
# ==============================================================================


def create_backend(
    card_id: str,
    backend_type: Literal["yubikey_piv", "openpgp", "javacard_raw"],
    *,
    serial_number: int | None = None,
    applet_aid: bytes | None = None,
) -> DeviceBackend:
    """
    Фабрика для создания бэкенда по типу.

    Позволяет ``HardwareCryptoManager`` создавать бэкенды без знания
    конкретных классов.

    Args:
        card_id:       Идентификатор устройства.
        backend_type:  ``"yubikey_piv"``, ``"openpgp"`` или ``"javacard_raw"``.
        serial_number: Серийный номер YubiKey (только для ``yubikey_piv``).
        applet_aid:    AID апплета (только для ``javacard_raw``).

    Returns:
        Экземпляр соответствующего бэкенда.

    Raises:
        ValueError: Неизвестный backend_type.

    Example:
        >>> backend = create_backend("yubikey_123", "yubikey_piv", serial_number=123)
        >>> isinstance(backend, DeviceBackend)
        True
    """
    if backend_type == "yubikey_piv":
        return YubiKeyPivBackend(card_id, serial_number=serial_number)
    if backend_type == "openpgp":
        return OpenPGPDeviceBackend(card_id)
    if backend_type == "javacard_raw":
        aid = applet_aid if applet_aid is not None else _DEFAULT_JAVACARD_APPLET_AID
        return JavaCardRawBackend(card_id, applet_aid=aid)
    raise ValueError(
        f"Неизвестный backend_type: '{backend_type}'. "
        f"Допустимые: 'yubikey_piv', 'openpgp', 'javacard_raw'."
    )


# ==============================================================================
# MODULE METADATA
# ==============================================================================

__all__: list[str] = [
    # Protocol
    "DeviceBackend",
    # Dataclasses / Enums
    "SlotInfo",
    "SlotStatus",
    # Implementations
    "YubiKeyPivBackend",
    "OpenPGPDeviceBackend",
    "JavaCardRawBackend",
    # Factory
    "create_backend",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"
