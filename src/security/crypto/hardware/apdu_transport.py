"""
Низкоуровневый APDU-транспорт для смарткарт (ISO/IEC 7816-4).

Единственный слой, который знает о pyscard. Поверх строятся
протокольные бэкенды: ``openpgp_backend.py``, ``piv_backend.py``,
``JavaCardRawBackend`` для кастомных апплетов J3R200.

Поддерживаемые операции:
    - SELECT APPLICATION по AID
    - Передача произвольных APDU (short + extended)
    - Автоматический GET RESPONSE при SW=61xx (response chaining)
    - Автоматическое разбиение данных > 255 байт (command chaining)
    - VERIFY PIN с разбором SW=63Cx (оставшиеся попытки)
    - GET DATA / PUT DATA для Data Objects
    - GET CHALLENGE

Структура APDU (ISO/IEC 7816-4):
    Short:    CLA INS P1 P2 [Lc Data] [Le]
    Extended: CLA INS P1 P2 [00 LcH LcL Data] [LeH LeL]

Ключевые SW-коды:
    90 00 — Success
    61 xx — More data (GET RESPONSE с Le=xx)
    63 Cx — VERIFY failed, x retries remaining
    69 83 — Authentication method blocked (PIN locked)
    6A 82 — File/application not found

Зависимости:
    pyscard >= 2.0.0  (единственная — без ykman, без cryptography)

Пример использования::

    from src.security.crypto.hardware.apdu_transport import ApduTransport

    with ApduTransport("HID Global OMNIKEY 3121 0") as t:
        t.select_applet(bytes.fromhex("D276000124"))   # OpenPGP
        t.verify_pin("123456", pin_ref=0x81)
        data = t.get_data(0x006E)                      # Application Related Data

Version: 1.0.0
Date: 2026-03-02
Author: Mike Voyager
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from src.security.crypto.core.exceptions import (
    DeviceCommunicationError,
    DeviceNotFoundError,
    HardwareDeviceError,
    PINError,
)

if TYPE_CHECKING:
    pass  # Будущие type-only импорты

logger = logging.getLogger(__name__)


# ==============================================================================
# OPTIONAL DEPENDENCY
# ==============================================================================

try:
    from smartcard.CardConnection import CardConnection as _CardConnection
    from smartcard.Exceptions import (
        CardConnectionException,
        NoCardException,
        NoReadersException,
    )
    from smartcard.System import readers as sc_readers

    HAS_PYSCARD = True
    logger.debug("pyscard available for APDU transport")
except ImportError:
    _CardConnection = None  # type: ignore[assignment, misc]
    CardConnectionException = Exception  # type: ignore[assignment, misc]
    NoCardException = Exception  # type: ignore[assignment, misc]
    NoReadersException = Exception  # type: ignore[assignment, misc]
    sc_readers = None  # type: ignore[assignment]
    HAS_PYSCARD = False
    logger.debug("pyscard not installed. Install: pip install pyscard>=2.0.0")


# ==============================================================================
# SW STATUS WORD CONSTANTS
# ==============================================================================

# Success
SW_SUCCESS: int = 0x9000

# Response chaining
SW_MORE_DATA_SW1: int = 0x61  # SW1=0x61, SW2=N → GET RESPONSE(Le=N)

# Authentication
SW_SECURITY_NOT_SATISFIED: int = 0x6982
SW_AUTH_METHOD_BLOCKED: int = 0x6983  # PIN locked (PUK needed)
SW_VERIFY_FAIL_BASE: int = 0x63C0  # 0x63C0 | retries_left
SW_VERIFY_FAIL_MASK: int = 0xFFF0
SW_VERIFY_NO_INFO: int = 0x6300  # Wrong PIN, retries unknown

# Data / applet errors
SW_WRONG_LENGTH: int = 0x6700
SW_WRONG_DATA: int = 0x6A80
SW_FILE_NOT_FOUND: int = 0x6A82
SW_INCORRECT_P1_P2: int = 0x6A86
SW_REF_DATA_NOT_FOUND: int = 0x6A88
SW_INS_NOT_SUPPORTED: int = 0x6D00
SW_CLA_NOT_SUPPORTED: int = 0x6E00
SW_UNKNOWN: int = 0x6F00

# INS bytes used in transport layer
INS_SELECT: int = 0xA4
INS_GET_RESPONSE: int = 0xC0
INS_VERIFY: int = 0x20
INS_CHANGE_REFERENCE_DATA: int = 0x24
INS_GET_DATA: int = 0xCA
INS_PUT_DATA: int = 0xDA
INS_GET_CHALLENGE: int = 0x84

# CLA bytes
CLA_ISO: int = 0x00
CLA_CHAIN: int = 0x10  # ISO 7816-4 command chaining flag (bit 4)

# SELECT P1/P2
P1_SELECT_BY_AID: int = 0x04
P2_SELECT_FIRST_OR_ONLY: int = 0x00

# APDU size limits (short APDU)
MAX_SHORT_LC: int = 255
MAX_SHORT_LE: int = 256  # Le=0x00 encodes 256 in short APDU

# Well-known AIDs
AID_PIV: bytes = bytes.fromhex("A000000308")
AID_OPENPGP: bytes = bytes.fromhex("D276000124")
AID_OATH: bytes = bytes.fromhex("A0000005272101")


# ==============================================================================
# APDU RESPONSE DATACLASS
# ==============================================================================


@dataclass(frozen=True)
class ApduResponse:
    """
    Ответ на APDU-команду.

    Attributes:
        data: Данные ответа (без SW байт). Может быть пустым.
        sw1:  Первый байт статуса (SW1).
        sw2:  Второй байт статуса (SW2).

    Properties:
        sw:           16-битный статус (sw1 << 8 | sw2).
        ok:           True если SW == 9000.
        sw_hex:       Hex-строка статуса (``"9000"``, ``"6A82"`` и т.д.).
        has_more_data: True если SW1 == 0x61 (response chaining нужен).
        remaining_len: Количество оставшихся байт при SW1=0x61.
                       0 в SW2 означает 256 байт.

    Example::

        resp = transport.send_apdu(0x00, 0xCA, 0x00, 0x6E, le=256)
        if resp.ok:
            process(resp.data)
    """

    data: bytes
    sw1: int
    sw2: int

    @property
    def sw(self) -> int:
        """16-битный статус SW1SW2."""
        return (self.sw1 << 8) | self.sw2

    @property
    def ok(self) -> bool:
        """True если SW == 9000."""
        return self.sw == SW_SUCCESS

    @property
    def sw_hex(self) -> str:
        """Статус в виде 4-символьного hex (``"9000"``)."""
        return f"{self.sw:04X}"

    @property
    def has_more_data(self) -> bool:
        """SW1 == 0x61: карта сигнализирует о дополнительных данных."""
        return self.sw1 == SW_MORE_DATA_SW1

    @property
    def remaining_len(self) -> int:
        """
        Количество оставшихся байт (SW2 при SW1=0x61).

        Значение 0x00 в SW2 кодирует 256 байт (максимум short Le).
        """
        if not self.has_more_data:
            return 0
        return self.sw2 if self.sw2 != 0 else 256

    def __repr__(self) -> str:
        return f"ApduResponse(sw={self.sw_hex}, data_len={len(self.data)})"


# ==============================================================================
# APDU TRANSPORT
# ==============================================================================


class ApduTransport:
    """
    Низкоуровневый APDU-транспорт для одной смарткарты в одном ридере.

    Управляет жизненным циклом соединения (connect / disconnect).
    Является контекстным менеджером — соединение открывается в ``__enter__``
    и гарантированно закрывается в ``__exit__``.

    Автоматически обрабатывает:

    - **Response chaining** (SW=61xx): после каждого ответа с SW1=0x61
      отправляет GET RESPONSE и накапливает данные до финального SW=9000.
    - **Command chaining** (данные > 255 байт): разбивает команду
      на блоки с CLA |= 0x10 (бит командной цепочки ISO 7816-4).
    - **Extended APDU** (опционально): Lc/Le > 255 в одной команде;
      включается через ``use_extended_apdu=True``. Требует поддержки ридером.

    Thread Safety:
        **НЕ** thread-safe. Каждое устройство должно использовать свой
        экземпляр. В ``HardwareCryptoManager`` каждое устройство защищено
        своим ``RLock``.

    Args:
        reader_name:       Точное имя PC/SC-ридера (из ``list_readers()``).
        protocol:          Транспортный протокол: ``"T0"``, ``"T1"`` или
                           ``"ANY"`` (попробовать T1 затем T0).
                           Значение по умолчанию — ``"T1"`` (предпочтительно
                           для ISO 7816-4 блочных протоколов).
        use_extended_apdu: Использовать extended APDU для данных > 255 байт
                           вместо command chaining. По умолчанию ``False``
                           (command chaining универсальнее).

    Raises:
        DeviceCommunicationError: pyscard не установлен.

    Example::

        with ApduTransport("HID Global OMNIKEY 3121 0") as t:
            t.select_applet(AID_OPENPGP)
            t.verify_pin("123456", pin_ref=0x81)
            atr = t.get_atr()
            data = t.get_data(0x006E)
    """

    def __init__(
        self,
        reader_name: str,
        *,
        protocol: str = "T1",
        use_extended_apdu: bool = False,
    ) -> None:
        if not HAS_PYSCARD:
            raise DeviceCommunicationError(
                device_id=reader_name,
                reason=(
                    "pyscard is required for raw APDU transport. "
                    "Install: pip install pyscard>=2.0.0"
                ),
            )
        self._reader_name = reader_name
        self._protocol = protocol
        self._use_extended = use_extended_apdu
        self._connection: Any = None
        self._connected: bool = False
        self._selected_aid: bytes | None = None

    # ------------------------------------------------------------------
    # CONTEXT MANAGER
    # ------------------------------------------------------------------

    def __enter__(self) -> ApduTransport:
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.disconnect()

    def __repr__(self) -> str:
        state = "connected" if self._connected else "disconnected"
        aid_str = (
            f", aid={self._selected_aid.hex().upper()}" if self._selected_aid else ""
        )
        return f"ApduTransport(reader={self._reader_name!r}, " f"{state}{aid_str})"

    # ------------------------------------------------------------------
    # CONNECT / DISCONNECT
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """
        Открыть соединение с картой в ридере.

        Идемпотентен: повторный вызов при открытом соединении — no-op.

        Raises:
            DeviceNotFoundError:      Ридер не найден среди доступных.
            DeviceCommunicationError: Нет карты в ридере или ошибка PC/SC.
        """
        if self._connected:
            return

        reader_obj = self._find_reader()
        try:
            conn = reader_obj.createConnection()
            proto = self._resolve_protocol()
            conn.connect(proto)
            self._connection = conn
            self._connected = True
            logger.debug(
                "ApduTransport: connected to '%s' (protocol=%s)",
                self._reader_name,
                self._protocol,
            )
        except NoCardException as exc:
            raise DeviceCommunicationError(
                device_id=self._reader_name,
                reason=f"No card in reader: {exc}",
            ) from exc
        except CardConnectionException as exc:
            raise DeviceCommunicationError(
                device_id=self._reader_name,
                reason=f"Card connection failed: {exc}",
            ) from exc

    def disconnect(self) -> None:
        """
        Закрыть соединение. Идемпотентен — никогда не выбрасывает исключений.
        """
        if not self._connected or self._connection is None:
            return
        try:
            self._connection.disconnect()
        except Exception as exc:
            logger.debug("ApduTransport: disconnect error (ignored): %s", exc)
        finally:
            self._connection = None
            self._connected = False
            self._selected_aid = None
            logger.debug("ApduTransport: disconnected from '%s'", self._reader_name)

    # ------------------------------------------------------------------
    # ATR
    # ------------------------------------------------------------------

    def get_atr(self) -> bytes:
        """
        Получить ATR (Answer-to-Reset) карты.

        Returns:
            ATR как bytes.

        Raises:
            DeviceCommunicationError: Нет активного соединения или ошибка.
        """
        self._ensure_connected()
        try:
            atr_list: list[int] = self._connection.getATR()
            return bytes(atr_list)
        except Exception as exc:
            raise DeviceCommunicationError(
                device_id=self._reader_name,
                reason=f"Failed to get ATR: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # CORE: SEND APDU
    # ------------------------------------------------------------------

    def send_apdu(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes = b"",
        le: int = 0,
        *,
        chain: bool = True,
    ) -> ApduResponse:
        """
        Отправить APDU и получить полный ответ.

        Автоматически обрабатывает SW=61xx — собирает все данные через
        GET RESPONSE до финального SW=9000.

        При ``chain=True`` и ``len(data) > 255``: разбивает на несколько
        команд с CLA |= 0x10 (command chaining, ISO 7816-4 §5.1.1.1).

        Args:
            cla:   CLA-байт (0x00 — ISO, 0x10 — chained block).
            ins:   INS-байт.
            p1:    P1-байт.
            p2:    P2-байт.
            data:  Данные команды (Lc-поле). Может быть пустым.
            le:    Ожидаемая длина ответа. 0 = Le-поле не добавляется.
                   256 (или 0x00 в short APDU) = запрос всех доступных.
            chain: Если True и len(data) > 255, использовать command chaining.

        Returns:
            ``ApduResponse`` с накопленными данными и финальным SW.

        Raises:
            DeviceCommunicationError: Ошибка PC/SC при передаче.
        """
        self._ensure_connected()

        if self._use_extended and (len(data) > MAX_SHORT_LC or le > MAX_SHORT_LE):
            return self._send_extended(cla, ins, p1, p2, data, le)

        if chain and len(data) > MAX_SHORT_LC:
            return self._send_chained(cla, ins, p1, p2, data, le)

        apdu = _build_short_apdu(cla, ins, p1, p2, data, le)
        response = self._transmit(apdu)

        if response.has_more_data:
            response = self._collect_responses(response)

        return response

    def send_raw(self, apdu_bytes: bytes) -> ApduResponse:
        """
        Отправить сырой APDU (байты напрямую) без автоматической обработки.

        Используется для нестандартных команд, отладки или когда вызывающий
        код управляет chaining самостоятельно.

        Args:
            apdu_bytes: Полный APDU как bytes.

        Returns:
            ``ApduResponse`` — SW без автоматического GET RESPONSE.

        Raises:
            DeviceCommunicationError: Ошибка PC/SC.
        """
        self._ensure_connected()
        return self._transmit(list(apdu_bytes))

    # ------------------------------------------------------------------
    # HIGH-LEVEL COMMANDS
    # ------------------------------------------------------------------

    def select_applet(self, aid: bytes) -> bytes:
        """
        SELECT APPLICATION по AID (CLA=00 INS=A4 P1=04 P2=00).

        Работает для любого апплета: OpenPGP (D276000124), PIV (A000000308),
        OATH (A0000005272101) или кастомного J3R200.

        Args:
            aid: Application Identifier (4–16 байт).

        Returns:
            FCI (File Control Information) из ответа. Может быть пустым —
            некоторые карты не возвращают FCI при успешном SELECT.

        Raises:
            ValueError:          AID вне допустимой длины (4–16 байт).
            HardwareDeviceError: Апплет не найден (SW=6A82) или иная ошибка.
            DeviceCommunicationError: Ошибка PC/SC.

        Example::

            fci = transport.select_applet(AID_OPENPGP)
        """
        if not 4 <= len(aid) <= 16:
            raise ValueError(f"AID must be 4–16 bytes, got {len(aid)}")
        response = self.send_apdu(
            CLA_ISO,
            INS_SELECT,
            P1_SELECT_BY_AID,
            P2_SELECT_FIRST_OR_ONLY,
            data=aid,
            le=256,
        )
        if response.sw == SW_FILE_NOT_FOUND:
            raise HardwareDeviceError(
                f"Applet not found (AID={aid.hex().upper()}). "
                f"Device may not have this applet installed.",
                device_id=self._reader_name,
                context={"aid": aid.hex().upper(), "sw": response.sw_hex},
            )
        if not response.ok:
            raise HardwareDeviceError(
                f"SELECT AID={aid.hex().upper()} failed: SW={response.sw_hex}",
                device_id=self._reader_name,
                context={"aid": aid.hex().upper(), "sw": response.sw_hex},
            )
        self._selected_aid = aid
        logger.debug(
            "ApduTransport: selected AID=%s, fci_len=%d",
            aid.hex().upper(),
            len(response.data),
        )
        return response.data

    def verify_pin(
        self,
        pin: str,
        pin_ref: int = 0x81,
        *,
        encoding: str = "utf-8",
    ) -> None:
        """
        VERIFY PIN (CLA=00 INS=20 P1=00 P2=pin_ref).

        PIN reference (P2):

        +----------+-----------------------------------------------------------+
        | Значение | Назначение                                                |
        +==========+===========================================================+
        | 0x81     | OpenPGP PW1 — User PIN (decrypt, auth)                    |
        | 0x82     | OpenPGP PW1 — User PIN только для подписи (если CFB3=1)   |
        | 0x83     | OpenPGP PW3 — Admin PIN (изменение ключей/метаданных)     |
        | 0x80     | PIV Global PIN                                             |
        | 0x81     | PIV Application PIN (чаще всего используемый)             |
        +----------+-----------------------------------------------------------+

        Args:
            pin:      PIN-код в виде строки.
            pin_ref:  PIN reference byte (P2). По умолчанию 0x81.
            encoding: Кодировка PIN. Большинство карт — UTF-8.
                      Некоторые старые PIV-карты требуют ISO-8859-1.

        Raises:
            PINError:            Неверный PIN. Содержит число оставшихся попыток.
            HardwareDeviceError: PIN заблокирован (SW=6983) или иная ошибка.
            DeviceCommunicationError: Ошибка PC/SC.
        """
        pin_bytes = pin.encode(encoding)
        response = self.send_apdu(
            CLA_ISO,
            INS_VERIFY,
            0x00,
            pin_ref,
            data=pin_bytes,
        )
        if response.ok:
            logger.debug("ApduTransport: PIN verified (ref=0x%02X)", pin_ref)
            return

        if response.sw == SW_AUTH_METHOD_BLOCKED:
            raise HardwareDeviceError(
                f"PIN blocked (ref=0x{pin_ref:02X}). "
                f"Use PUK or Admin PIN to unblock.",
                device_id=self._reader_name,
                context={"pin_ref": f"0x{pin_ref:02X}", "sw": response.sw_hex},
            )
        if (response.sw & SW_VERIFY_FAIL_MASK) == SW_VERIFY_FAIL_BASE:
            retries = response.sw & 0x000F
            raise PINError(
                reason=f"Wrong PIN (ref=0x{pin_ref:02X}). "
                f"{retries} {'retry' if retries == 1 else 'retries'} remaining.",
                device_id=self._reader_name,
                retries_remaining=retries,
            )
        if response.sw == SW_VERIFY_NO_INFO:
            raise PINError(
                reason=f"Wrong PIN (ref=0x{pin_ref:02X}).",
                device_id=self._reader_name,
                retries_remaining=-1,
            )
        raise HardwareDeviceError(
            f"VERIFY PIN failed: SW={response.sw_hex}",
            device_id=self._reader_name,
            context={"pin_ref": f"0x{pin_ref:02X}", "sw": response.sw_hex},
        )

    def get_pin_retries(self, pin_ref: int = 0x81) -> int:
        """
        Получить число оставшихся попыток PIN **без** его проверки.

        Отправляет VERIFY с пустыми данными (Lc=0). Карта возвращает
        SW=63Cx не изменяя счётчик попыток.

        Args:
            pin_ref: PIN reference (аналогично ``verify_pin()``).

        Returns:
            Число оставшихся попыток (0–N). -1 если карта не поддерживает.

        Example::

            if transport.get_pin_retries(0x81) == 0:
                raise RuntimeError("PIN is blocked")
        """
        response = self.send_apdu(
            CLA_ISO,
            INS_VERIFY,
            0x00,
            pin_ref,
            data=b"",
        )
        if response.ok:
            return -1  # карта приняла пустой VERIFY — PIN не требуется
        if response.sw == SW_AUTH_METHOD_BLOCKED:
            return 0
        if (response.sw & SW_VERIFY_FAIL_MASK) == SW_VERIFY_FAIL_BASE:
            return response.sw & 0x000F
        return -1

    def get_data(self, tag: int, *, le: int = 256) -> bytes:
        """
        GET DATA — получить Data Object по тегу (CLA=00 INS=CA P1P2=tag).

        Стандартные теги OpenPGP:

        +---------+---------------------------------------------+
        | Тег     | Описание                                    |
        +=========+=============================================+
        | 0x006E  | Application Related Data                    |
        | 0x007A  | Security Support Template                   |
        | 0x00C4  | PW Status Bytes                             |
        | 0x00B6  | Public Key DO — Sign slot                   |
        | 0x00B8  | Public Key DO — Decrypt slot                |
        | 0x00A4  | Public Key DO — Auth slot                   |
        | 0x004F  | Application Identifier (AID)                |
        | 0x0065  | Cardholder Related Data                     |
        +---------+---------------------------------------------+

        Args:
            tag: 1- или 2-байтовый тег (P1=tag>>8, P2=tag&0xFF).
            le:  Ожидаемый размер ответа. По умолчанию 256.

        Returns:
            Данные Data Object.

        Raises:
            HardwareDeviceError: Объект не найден (SW=6A82/6A88) или ошибка.
        """
        p1 = (tag >> 8) & 0xFF
        p2 = tag & 0xFF
        response = self.send_apdu(CLA_ISO, INS_GET_DATA, p1, p2, le=le)

        if response.sw in (SW_FILE_NOT_FOUND, SW_REF_DATA_NOT_FOUND):
            raise HardwareDeviceError(
                f"Data object not found: tag=0x{tag:04X}",
                device_id=self._reader_name,
                context={"tag": f"0x{tag:04X}", "sw": response.sw_hex},
            )
        if not response.ok:
            raise HardwareDeviceError(
                f"GET DATA failed: tag=0x{tag:04X}, SW={response.sw_hex}",
                device_id=self._reader_name,
                context={"tag": f"0x{tag:04X}", "sw": response.sw_hex},
            )
        return response.data

    def put_data(self, tag: int, data: bytes) -> None:
        """
        PUT DATA — записать Data Object по тегу (CLA=00 INS=DA P1P2=tag).

        Большинство операций требует предварительного ``verify_pin()``.

        Args:
            tag:  1- или 2-байтовый тег.
            data: Данные для записи.

        Raises:
            HardwareDeviceError: Недостаточно прав (SW=6982) или ошибка записи.
        """
        p1 = (tag >> 8) & 0xFF
        p2 = tag & 0xFF
        response = self.send_apdu(CLA_ISO, INS_PUT_DATA, p1, p2, data=data)

        if response.sw == SW_SECURITY_NOT_SATISFIED:
            raise HardwareDeviceError(
                f"PUT DATA denied: tag=0x{tag:04X}. " f"Verify PIN (Admin/PW3) first.",
                device_id=self._reader_name,
                context={"tag": f"0x{tag:04X}", "sw": response.sw_hex},
            )
        if not response.ok:
            raise HardwareDeviceError(
                f"PUT DATA failed: tag=0x{tag:04X}, SW={response.sw_hex}",
                device_id=self._reader_name,
                context={"tag": f"0x{tag:04X}", "sw": response.sw_hex},
            )

    def get_challenge(self, length: int = 16) -> bytes:
        """
        GET CHALLENGE — запросить случайные байты от карты (INS=84).

        Используется для:
        - Проверки живости карты
        - Дополнительного источника энтропии
        - Внешней аутентификации (EXTERNAL AUTHENTICATE)

        Args:
            length: Количество запрашиваемых байт (1–255).

        Returns:
            Случайные байты от аппаратного RNG карты.

        Raises:
            ValueError:          length вне диапазона 1–255.
            HardwareDeviceError: Команда не поддерживается или ошибка.
        """
        if not 1 <= length <= 255:
            raise ValueError(f"Challenge length must be 1–255, got {length}")
        response = self.send_apdu(
            CLA_ISO,
            INS_GET_CHALLENGE,
            0x00,
            0x00,
            le=length,
        )
        if response.sw == SW_INS_NOT_SUPPORTED:
            raise HardwareDeviceError(
                "GET CHALLENGE not supported by this applet.",
                device_id=self._reader_name,
                context={"sw": response.sw_hex},
            )
        if not response.ok:
            raise HardwareDeviceError(
                f"GET CHALLENGE failed: SW={response.sw_hex}",
                device_id=self._reader_name,
                context={"sw": response.sw_hex},
            )
        return response.data

    # ------------------------------------------------------------------
    # PRIVATE: APDU BUILDING & CHAINING
    # ------------------------------------------------------------------

    def _send_extended(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes,
        le: int,
    ) -> ApduResponse:
        """
        Extended APDU (ISO 7816-4): Lc/Le кодируются как 3/2 байта.

        Формат: CLA INS P1 P2 [00 LcH LcL Data] [LeH LeL]

        Предупреждение: не все PC/SC-ридеры поддерживают extended APDU
        на уровне драйвера — драйвер может усекать данные молча.
        Используйте только если убедились в поддержке ридером.
        """
        apdu: list[int] = [cla, ins, p1, p2]

        if data:
            apdu += [0x00, (len(data) >> 8) & 0xFF, len(data) & 0xFF]
            apdu.extend(data)
            if le > 0:
                apdu += [(le >> 8) & 0xFF, le & 0xFF]
        elif le > 0:
            apdu += [0x00, (le >> 8) & 0xFF, le & 0xFF]

        response = self._transmit(apdu)
        if response.has_more_data:
            response = self._collect_responses(response)
        return response

    def _send_chained(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2: int,
        data: bytes,
        le: int,
    ) -> ApduResponse:
        """
        Command chaining (ISO 7816-4 §5.1.1.1): разбить данные > 255 байт
        на блоки по 255. Каждый блок кроме последнего — CLA |= 0x10.
        """
        chunks = [data[i : i + MAX_SHORT_LC] for i in range(0, len(data), MAX_SHORT_LC)]
        # Все блоки кроме последнего — без Le, с флагом chaining
        for chunk in chunks[:-1]:
            apdu = _build_short_apdu(cla | CLA_CHAIN, ins, p1, p2, chunk, le=0)
            resp = self._transmit(apdu)
            if not resp.ok:
                raise HardwareDeviceError(
                    f"Command chaining failed at intermediate block: "
                    f"SW={resp.sw_hex}",
                    device_id=self._reader_name,
                    context={"sw": resp.sw_hex, "operation": "command_chain"},
                )

        # Последний блок — с оригинальным CLA и Le
        last_apdu = _build_short_apdu(cla, ins, p1, p2, chunks[-1], le)
        response = self._transmit(last_apdu)
        if response.has_more_data:
            response = self._collect_responses(response)
        return response

    def _collect_responses(self, first: ApduResponse) -> ApduResponse:
        """
        Собрать полный ответ через серию GET RESPONSE (SW1=0x61).

        Карта возвращает SW1=0x61, SW2=N → нужно отправить
        GET RESPONSE с Le=N. Повторяется до SW=9000 или ошибки.
        """
        accumulated = bytearray(first.data)
        current = first

        while current.has_more_data:
            le = current.remaining_len
            apdu = _build_short_apdu(
                CLA_ISO,
                INS_GET_RESPONSE,
                0x00,
                0x00,
                data=b"",
                le=le,
            )
            current = self._transmit(apdu)
            accumulated.extend(current.data)

        return ApduResponse(
            data=bytes(accumulated),
            sw1=current.sw1,
            sw2=current.sw2,
        )

    # ------------------------------------------------------------------
    # PRIVATE: TRANSMIT
    # ------------------------------------------------------------------

    def _transmit(self, apdu: list[int]) -> ApduResponse:
        """
        Передать APDU через pyscard CardConnection.transmit().

        Raises:
            DeviceCommunicationError: Ошибка CardConnection или неожиданное
                                       исключение.
        """
        try:
            response_data, sw1, sw2 = self._connection.transmit(apdu)
            result = ApduResponse(
                data=bytes(response_data),
                sw1=sw1,
                sw2=sw2,
            )
            logger.debug(
                "APDU tx [%s] → SW=%s len=%d",
                bytes(apdu[:4]).hex().upper(),
                result.sw_hex,
                len(result.data),
            )
            return result
        except CardConnectionException as exc:
            raise DeviceCommunicationError(
                device_id=self._reader_name,
                reason=f"Card communication error: {exc}",
            ) from exc
        except Exception as exc:
            raise DeviceCommunicationError(
                device_id=self._reader_name,
                reason=f"Unexpected transmit error: {exc}",
            ) from exc

    # ------------------------------------------------------------------
    # PRIVATE: HELPERS
    # ------------------------------------------------------------------

    def _ensure_connected(self) -> None:
        """
        Raises:
            DeviceCommunicationError: Нет активного соединения.
        """
        if not self._connected or self._connection is None:
            raise DeviceCommunicationError(
                device_id=self._reader_name,
                reason=(
                    "Not connected. Use 'with ApduTransport(...) as t:' "
                    "or call connect() explicitly."
                ),
            )

    def _find_reader(self) -> Any:
        """
        Найти объект ридера по точному имени среди доступных PC/SC-ридеров.

        Raises:
            DeviceNotFoundError:      Ридер не найден.
            DeviceCommunicationError: PC/SC менеджер недоступен.
        """
        if sc_readers is None:
            raise DeviceCommunicationError(
                device_id=self._reader_name,
                reason="pyscard not available",
            )
        try:
            available = sc_readers()
        except NoReadersException as exc:
            raise DeviceCommunicationError(
                device_id=self._reader_name,
                reason=f"No PC/SC readers available: {exc}",
            ) from exc
        except Exception as exc:
            raise DeviceCommunicationError(
                device_id=self._reader_name,
                reason=f"PC/SC manager error: {exc}",
            ) from exc

        for reader in available:
            if str(reader) == self._reader_name:
                return reader

        available_names = [str(r) for r in available]
        raise DeviceNotFoundError(
            device_id=self._reader_name,
            reason=(f"Reader not found. " f"Available: {available_names}"),
        )

    def _resolve_protocol(self) -> int:
        """
        Разрешить строковое имя протокола в константу pyscard.

        Возвращает T1 (2) если CardConnection недоступен или протокол
        не распознан — pyscard сам выберет при connect().
        """
        if _CardConnection is None:
            return 2  # fallback T1
        proto_map: dict[str, int] = {
            "T0": _CardConnection.T0_protocol,
            "T1": _CardConnection.T1_protocol,
            "ANY": _CardConnection.T0_protocol | _CardConnection.T1_protocol,
        }
        return proto_map.get(self._protocol.upper(), _CardConnection.T1_protocol)


# ==============================================================================
# MODULE-LEVEL HELPERS (pure functions, без pyscard)
# ==============================================================================


def _build_short_apdu(
    cla: int,
    ins: int,
    p1: int,
    p2: int,
    data: bytes,
    le: int,
) -> list[int]:
    """
    Собрать short APDU по ISO 7816-4 Case 1/2/3/4.

    Case 1: CLA INS P1 P2               — нет данных, нет Le
    Case 2: CLA INS P1 P2 Le            — нет данных, есть Le
    Case 3: CLA INS P1 P2 Lc Data       — данные, нет Le
    Case 4: CLA INS P1 P2 Lc Data Le    — данные и Le

    Le=256 кодируется как 0x00 в short APDU.
    """
    apdu: list[int] = [cla & 0xFF, ins & 0xFF, p1 & 0xFF, p2 & 0xFF]
    if data:
        apdu.append(len(data) & 0xFF)  # Lc
        apdu.extend(data)
    if le > 0:
        apdu.append(le & 0xFF)  # Le (256 → 0x00)
    return apdu


# ==============================================================================
# PUBLIC FACTORY FUNCTIONS
# ==============================================================================


def open_transport(
    reader_name: str,
    *,
    protocol: str = "T1",
    use_extended_apdu: bool = False,
) -> ApduTransport:
    """
    Создать ``ApduTransport`` без автоматического подключения.

    Используйте как контекстный менеджер::

        with open_transport("HID Global OMNIKEY 3121 0") as t:
            t.select_applet(AID_OPENPGP)
            t.verify_pin("123456")

    Args:
        reader_name:       Имя PC/SC-ридера (из ``list_readers()``).
        protocol:          ``"T0"``, ``"T1"`` или ``"ANY"``.
        use_extended_apdu: Использовать extended APDU (не для всех ридеров).

    Returns:
        Неподключённый ``ApduTransport``.
    """
    return ApduTransport(
        reader_name,
        protocol=protocol,
        use_extended_apdu=use_extended_apdu,
    )


def list_readers() -> list[str]:
    """
    Получить список имён всех доступных PC/SC-ридеров.

    Returns:
        Список строк. Пустой если pyscard недоступен или ридеры не найдены.

    Example::

        for name in list_readers():
            print(name)
        # "HID Global OMNIKEY 3121 0"
        # "Yubico YubiKey OTP+FIDO+CCID 0"
    """
    if not HAS_PYSCARD or sc_readers is None:
        return []
    try:
        return [str(r) for r in sc_readers()]
    except Exception:
        return []
