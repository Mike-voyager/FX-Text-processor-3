"""
Тесты для низкоуровневого APDU-транспорта.

Обеспечивает 100% покрытие строк и ветвей логики сборки APDU,
обработки command/response цепочек и обработки кодов SW
с полным мокированием pyscard.
"""

import sys
import importlib
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

from src.security.crypto.core.exceptions import (
    DeviceCommunicationError,
    DeviceNotFoundError,
    HardwareDeviceError,
    PINError,
)
from src.security.crypto.hardware.apdu_transport import (
    ApduResponse,
    ApduTransport,
    _build_short_apdu,
    list_readers,
    open_transport,
)


class MockCardConnectionException(Exception):
    """Имитация исключения pyscard CardConnectionException."""


class MockNoCardException(Exception):
    """Имитация исключения pyscard NoCardException."""


class MockNoReadersException(Exception):
    """Имитация исключения pyscard NoReadersException."""


@pytest.fixture
def mock_reader_env() -> Generator[tuple[MagicMock, MagicMock], None, None]:
    """Создает изолированное окружение с моками для pyscard."""
    with (
        patch("src.security.crypto.hardware.apdu_transport.HAS_PYSCARD", True),
        patch("src.security.crypto.hardware.apdu_transport.sc_readers") as mock_readers,
        patch(
            "src.security.crypto.hardware.apdu_transport._CardConnection"
        ) as mock_card_conn,
        patch(
            "src.security.crypto.hardware.apdu_transport.CardConnectionException",
            MockCardConnectionException,
        ),
        patch(
            "src.security.crypto.hardware.apdu_transport.NoCardException",
            MockNoCardException,
        ),
        patch(
            "src.security.crypto.hardware.apdu_transport.NoReadersException",
            MockNoReadersException,
        ),
    ):

        reader = MagicMock()
        reader.__str__.return_value = "Test Reader 0"

        conn = MagicMock()
        reader.createConnection.return_value = conn

        mock_readers.return_value = [reader]

        mock_card_conn.T0_protocol = 1
        mock_card_conn.T1_protocol = 2

        yield reader, conn


class TestApduResponse:
    """Тестирование структуры ответа APDU."""

    def test_properties_success(self) -> None:
        """Базовые свойства успешного ответа."""
        resp = ApduResponse(b"data", 0x90, 0x00)
        assert resp.sw == 0x9000
        assert resp.ok is True
        assert resp.sw_hex == "9000"
        assert resp.has_more_data is False
        assert resp.remaining_len == 0

    def test_properties_more_data(self) -> None:
        """Ответ требует GET RESPONSE (61xx)."""
        resp = ApduResponse(b"", 0x61, 0x14)
        assert resp.sw == 0x6114
        assert resp.ok is False
        assert resp.sw_hex == "6114"
        assert resp.has_more_data is True
        assert resp.remaining_len == 20

    def test_properties_more_data_256(self) -> None:
        """GET RESPONSE с 256 байтами (кодируется как 0x00)."""
        resp = ApduResponse(b"", 0x61, 0x00)
        assert resp.has_more_data is True
        assert resp.remaining_len == 256


class TestApduTransportConnection:
    """Тестирование жизненного цикла соединения."""

    def test_pyscard_not_installed(self) -> None:
        """Ошибка инициализации при отсутствии pyscard."""
        with patch("src.security.crypto.hardware.apdu_transport.HAS_PYSCARD", False):
            with pytest.raises(DeviceCommunicationError, match="pyscard is required"):
                ApduTransport("Test Reader 0")

    def test_connect_success(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Успешное подключение к ридеру."""
        reader, conn = mock_reader_env
        transport = ApduTransport("Test Reader 0")

        assert not transport._connected
        transport.connect()
        assert transport._connected

        reader.createConnection.assert_called_once()
        conn.connect.assert_called_once_with(2)

        # Повторный вызов безопасен
        transport.connect()
        assert reader.createConnection.call_count == 1

    def test_connect_reader_not_found(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Ридер не найден среди доступных."""
        transport = ApduTransport("Nonexistent Reader")
        with pytest.raises(DeviceNotFoundError, match="Reader not found"):
            transport.connect()

    def test_connect_no_card(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Ридер найден, но смарткарта отсутствует."""
        _, conn = mock_reader_env
        conn.connect.side_effect = MockNoCardException("No card")
        transport = ApduTransport("Test Reader 0")

        with pytest.raises(DeviceCommunicationError, match="No card in reader"):
            transport.connect()

    def test_connect_card_connection_exception(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Ошибка соединения с картой на уровне PC/SC."""
        _, conn = mock_reader_env
        conn.connect.side_effect = MockCardConnectionException("Connect failed")
        transport = ApduTransport("Test Reader 0")

        with pytest.raises(DeviceCommunicationError, match="Card connection failed"):
            transport.connect()

    def test_disconnect(self, mock_reader_env: tuple[MagicMock, MagicMock]) -> None:
        """Успешное отключение."""
        _, conn = mock_reader_env
        transport = ApduTransport("Test Reader 0")
        transport.connect()

        transport.disconnect()
        assert not transport._connected
        conn.disconnect.assert_called_once()

        # Повторный вызов безопасен
        transport.disconnect()
        assert conn.disconnect.call_count == 1

    def test_disconnect_exception_ignored(
        self,
        mock_reader_env: tuple[MagicMock, MagicMock],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Исключение при отключении глушится и логируется."""
        _, conn = mock_reader_env
        conn.disconnect.side_effect = Exception("Disconnect error")
        transport = ApduTransport("Test Reader 0")
        transport.connect()

        transport.disconnect()
        assert not transport._connected
        assert "disconnect error (ignored)" in caplog.text

    def test_ensure_connected_raises(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Операции требуют активного соединения."""
        transport = ApduTransport("Test Reader 0")
        with pytest.raises(DeviceCommunicationError, match="Not connected"):
            transport.get_atr()

    def test_get_atr(self, mock_reader_env: tuple[MagicMock, MagicMock]) -> None:
        """Получение ATR."""
        _, conn = mock_reader_env
        conn.getATR.return_value = [0x3B, 0x8C, 0x80, 0x01]

        with ApduTransport("Test Reader 0") as t:
            atr = t.get_atr()
            assert atr == b"\x3b\x8c\x80\x01"

    def test_get_atr_exception(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Ошибка при получении ATR оборачивается в DeviceCommunicationError."""
        _, conn = mock_reader_env
        conn.getATR.side_effect = Exception("ATR read failed")

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(DeviceCommunicationError, match="Failed to get ATR"):
                t.get_atr()


class TestApduTransportCommands:
    """Тестирование протокола отправки и цепочек APDU."""

    def test_send_raw(self, mock_reader_env: tuple[MagicMock, MagicMock]) -> None:
        """Отправка сырых байт без обертки."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x90, 0x00)

        with ApduTransport("Test Reader 0") as t:
            resp = t.send_raw(b"\x00\xa4\x04\x00")
            assert resp.ok
            conn.transmit.assert_called_once_with([0x00, 0xA4, 0x04, 0x00])

    def test_transmit_unexpected_error(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Неизвестная ошибка CardConnection оборачивается."""
        _, conn = mock_reader_env
        conn.transmit.side_effect = Exception("Surprise!")

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(
                DeviceCommunicationError, match="Unexpected transmit error"
            ):
                t.send_raw(b"\x00")

    def test_transmit_card_error(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Ошибки протокола оборачиваются."""
        _, conn = mock_reader_env
        conn.transmit.side_effect = MockCardConnectionException("Card err")

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(
                DeviceCommunicationError, match="Card communication error"
            ):
                t.send_raw(b"\x00")

    def test_send_chained_success(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Разбиение команды на фрагменты (Command Chaining)."""
        _, conn = mock_reader_env
        conn.transmit.side_effect = [
            ([0x90, 0x00], 0x90, 0x00),  # Первая часть (255)
            ([0x01, 0x02], 0x90, 0x00),  # Вторая часть (45)
        ]

        with ApduTransport("Test Reader 0") as t:
            data = bytes([0xAA] * 300)
            resp = t.send_apdu(0x00, 0xDA, 0x01, 0x02, data, le=16, chain=True)

            assert resp.ok
            assert resp.data == b"\x01\x02"
            assert conn.transmit.call_count == 2

            call1 = conn.transmit.call_args_list
            assert call1[:5] == [0x10, 0xDA, 0x01, 0x02, 255]

            call2 = conn.transmit.call_args_list[1]
            assert call2[:5] == [0x00, 0xDA, 0x01, 0x02, 45]
            assert call2[-1] == 16

    def test_send_chained_intermediate_fail(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Падение промежуточного чанка при command chaining."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x69, 0x82)

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(
                HardwareDeviceError,
                match="Command chaining failed at intermediate block",
            ):
                t.send_apdu(0x00, 0xDA, 0x00, 0x00, b"\x01" * 300, chain=True)

    def test_send_chained_more_data(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Конечный ответ цепочки возвращает SW=61xx."""
        _, conn = mock_reader_env
        conn.transmit.side_effect = [
            ([], 0x90, 0x00),  # chunk 1
            ([], 0x61, 0x02),  # chunk 2 has response!
            ([0xAA, 0xBB], 0x90, 0x00),  # GET RESPONSE payload
        ]

        with ApduTransport("Test Reader 0") as t:
            resp = t.send_apdu(0x00, 0xDA, 0x00, 0x00, b"\x01" * 300, chain=True)
            assert resp.data == b"\xaa\xbb"

    def test_send_extended_branches(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Проверка всех 4х ветвлений сборки Extended APDU."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x90, 0x00)

        with ApduTransport("Test Reader 0", use_extended_apdu=True) as t:
            # 1. data=True, le=0
            t._send_extended(0x00, 0xDA, 0x00, 0x00, b"\x01" * 300, 0)
            call1 = conn.transmit.call_args
            assert call1[-2:] != [0x00, 0x00]  # No Le appended

            # 2. data=True, le>0
            t._send_extended(0x00, 0xDA, 0x00, 0x00, b"\x01" * 300, 500)
            call2 = conn.transmit.call_args
            assert call2[-2:] == [0x01, 0xF4]  # Le=500

            # 3. data=False, le>0
            t._send_extended(0x00, 0xDA, 0x00, 0x00, b"", 300)
            call3 = conn.transmit.call_args
            assert call3[-3:] == [0x00, 0x01, 0x2C]

            # 4. data=False, le=0
            t._send_extended(0x00, 0xDA, 0x00, 0x00, b"", 0)
            call4 = conn.transmit.call_args
            assert call4 == [0x00, 0xDA, 0x00, 0x00]

    def test_send_extended_more_data(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Extended APDU возвращает SW=61xx."""
        _, conn = mock_reader_env
        conn.transmit.side_effect = [([], 0x61, 0x01), ([0xFF], 0x90, 0x00)]
        with ApduTransport("Test Reader 0", use_extended_apdu=True) as t:
            resp = t._send_extended(0x00, 0xDA, 0x00, 0x00, b"", 300)
            assert resp.data == b"\xff"


class TestApduTransportHighLevel:
    """Тестирование прикладных методов смарткарты."""

    def test_select_applet_success(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Успешный выбор апплета."""
        _, conn = mock_reader_env
        conn.transmit.return_value = (list(b"FCI"), 0x90, 0x00)

        with ApduTransport("Test Reader 0") as t:
            aid = bytes.fromhex("D276000124")
            fci = t.select_applet(aid)
            assert fci == b"FCI"
            assert t._selected_aid == aid

    def test_select_applet_invalid_length(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Валидация длины AID."""
        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(ValueError, match="AID must be 4–16 bytes"):
                t.select_applet(b"\x00" * 3)
            with pytest.raises(ValueError, match="AID must be 4–16 bytes"):
                t.select_applet(b"\x00" * 17)

    def test_select_applet_not_found(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Апплет не установлен (6A82)."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x6A, 0x82)

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(HardwareDeviceError, match="Applet not found"):
                t.select_applet(b"\x00" * 8)

    def test_select_applet_other_error(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Неизвестная ошибка выбора апплета."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x69, 0x99)

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(HardwareDeviceError, match="SELECT AID.*failed"):
                t.select_applet(b"\x00" * 8)

    def test_verify_pin_success(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Успешный VERIFY PIN."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x90, 0x00)

        with ApduTransport("Test Reader 0") as t:
            t.verify_pin("123456", 0x81)
            call_args = conn.transmit.call_args
            assert call_args == [0x00, 0x20, 0x00, 0x81, 0x06] + list(b"123456")

    def test_verify_pin_wrong_retries(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Неверный PIN с указанием попыток (63Cx)."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x63, 0xC2)

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(PINError) as exc:
                t.verify_pin("wrong")
            assert exc.value.retries_remaining == 2

    def test_verify_pin_no_info(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Неверный PIN без числа попыток (6300)."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x63, 0x00)

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(PINError) as exc:
                t.verify_pin("wrong")
            assert exc.value.retries_remaining == -1

    def test_verify_pin_blocked(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """PIN заблокирован (6983)."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x69, 0x83)

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(HardwareDeviceError, match="blocked"):
                t.verify_pin("123456")

    def test_verify_pin_other_error(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Иная ошибка проверки PIN."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x69, 0x99)

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(HardwareDeviceError, match="VERIFY PIN failed"):
                t.verify_pin("123456")

    def test_get_pin_retries_ok(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Карта приняла пустой VERIFY (9000)."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x90, 0x00)

        with ApduTransport("Test Reader 0") as t:
            assert t.get_pin_retries() == -1

    def test_get_pin_retries_blocked(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Заблокировано (6983) при проверке попыток."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x69, 0x83)

        with ApduTransport("Test Reader 0") as t:
            assert t.get_pin_retries() == 0

    def test_get_pin_retries_unknown(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Неизвестная ошибка при пустом VERIFY (fallback)."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x6F, 0x00)

        with ApduTransport("Test Reader 0") as t:
            assert t.get_pin_retries() == -1

    def test_get_pin_retries_with_value(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Запрос попыток возвращает 63C3."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x63, 0xC3)

        with ApduTransport("Test Reader 0") as t:
            assert t.get_pin_retries(0x81) == 3

            # пустой VERIFY не имеет Lc=0 или Le=0 в конце списка APDU!
            call_args = conn.transmit.call_args
            assert call_args == [0x00, 0x20, 0x00, 0x81]

    def test_get_data_success(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """GET DATA по тегу."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([0xAB, 0xCD], 0x90, 0x00)

        with ApduTransport("Test Reader 0") as t:
            assert t.get_data(0x006E) == b"\xab\xcd"
            call_args = conn.transmit.call_args
            assert call_args == [0x00, 0xCA, 0x00, 0x6E, 0x00]

    def test_get_data_not_found(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Объект не найден."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x6A, 0x82)
        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(HardwareDeviceError, match="Data object not found"):
                t.get_data(0x006E)

    def test_get_data_other_error(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Иная ошибка GET DATA."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x69, 0x99)
        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(HardwareDeviceError, match="GET DATA failed"):
                t.get_data(0x006E)

    def test_put_data_denied(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """PUT DATA без прав (6982)."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x69, 0x82)

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(HardwareDeviceError, match="PUT DATA denied"):
                t.put_data(0x006E, b"\x01")

    def test_put_data_other_error(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Иная ошибка при PUT DATA."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x69, 0x99)

        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(HardwareDeviceError, match="PUT DATA failed"):
                t.put_data(0x006E, b"\x01")

    def test_get_challenge_success(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Запрос случайных байт с RNG карты."""
        _, conn = mock_reader_env
        conn.transmit.return_value = (list(b"random1234567890"), 0x90, 0x00)

        with ApduTransport("Test Reader 0") as t:
            assert t.get_challenge(16) == b"random1234567890"

    def test_get_challenge_invalid_length(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Челлендж неверной длины."""
        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(ValueError):
                t.get_challenge(300)

    def test_get_challenge_not_supported(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """GET CHALLENGE не поддерживается."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x6D, 0x00)
        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(
                HardwareDeviceError, match="GET CHALLENGE not supported"
            ):
                t.get_challenge()

    def test_get_challenge_other_error(
        self, mock_reader_env: tuple[MagicMock, MagicMock]
    ) -> None:
        """Иная ошибка GET CHALLENGE."""
        _, conn = mock_reader_env
        conn.transmit.return_value = ([], 0x69, 0x99)
        with ApduTransport("Test Reader 0") as t:
            with pytest.raises(HardwareDeviceError, match="GET CHALLENGE failed"):
                t.get_challenge()


class TestModuleFunctions:
    """Тестирование утилит и фабрик модуля."""

    def test_build_short_apdu(self) -> None:
        """Проверка сборки Case 1, 2, 3, 4."""
        # Case 1
        assert _build_short_apdu(0x00, 0xA4, 0x04, 0x00, b"", 0) == [
            0x00,
            0xA4,
            0x04,
            0x00,
        ]
        # Case 2
        assert _build_short_apdu(0x00, 0xA4, 0x04, 0x00, b"", 256) == [
            0x00,
            0xA4,
            0x04,
            0x00,
            0x00,
        ]
        # Case 3
        assert _build_short_apdu(0x00, 0xA4, 0x04, 0x00, b"\x01", 0) == [
            0x00,
            0xA4,
            0x04,
            0x00,
            0x01,
            0x01,
        ]
        # Case 4
        assert _build_short_apdu(0x00, 0xA4, 0x04, 0x00, b"\x01", 16) == [
            0x00,
            0xA4,
            0x04,
            0x00,
            0x01,
            0x01,
            0x10,
        ]

    def test_list_readers(self, mock_reader_env: tuple[MagicMock, MagicMock]) -> None:
        """Список доступных ридеров PC/SC."""
        readers = list_readers()
        assert readers == ["Test Reader 0"]

    def test_list_readers_no_pyscard(self) -> None:
        """Безопасный пустой возврат без pyscard."""
        with patch("src.security.crypto.hardware.apdu_transport.HAS_PYSCARD", False):
            assert list_readers() == []

    def test_list_readers_exception(self) -> None:
        """Безопасный пустой возврат при исключении PCSC."""
        with patch(
            "src.security.crypto.hardware.apdu_transport.sc_readers",
            side_effect=Exception,
        ):
            assert list_readers() == []

    def test_find_reader_no_readers_exception(self) -> None:
        """Нет доступных ридеров (NoReadersException)."""
        with patch(
            "src.security.crypto.hardware.apdu_transport.sc_readers",
            side_effect=MockNoReadersException("No readers"),
        ):
            transport = ApduTransport("Test Reader 0")
            with pytest.raises(
                DeviceCommunicationError, match="No PC/SC readers available"
            ):
                transport.connect()

    def test_find_reader_pcsc_error(self) -> None:
        """Ошибка менеджера PC/SC при поиске ридера."""
        with patch(
            "src.security.crypto.hardware.apdu_transport.sc_readers",
            side_effect=Exception("Crash"),
        ):
            transport = ApduTransport("Test Reader 0")
            with pytest.raises(DeviceCommunicationError, match="PC/SC manager error"):
                transport.connect()

    def test_resolve_protocol_fallback(self) -> None:
        """Fallback протокола (T1=2), если pyscard (CardConnection) недоступен."""
        with patch("src.security.crypto.hardware.apdu_transport._CardConnection", None):
            transport = ApduTransport("Test Reader 0")
            assert transport._resolve_protocol() == 2

    def test_open_transport(self) -> None:
        """Фабрика неподключенного транспорта."""
        with patch("src.security.crypto.hardware.apdu_transport.HAS_PYSCARD", True):
            transport = open_transport("Test", protocol="T0", use_extended_apdu=True)
            assert not transport._connected
            assert transport._protocol == "T0"
            assert transport._use_extended is True

    def test_import_without_pyscard(self) -> None:
        """Имитация отсутствия пакета pyscard для покрытия блока except ImportError."""
        import sys
        import importlib
        import src.security.crypto.hardware.apdu_transport as apdu_transport

        # Мокаем отсутствие модуля smartcard в sys.modules
        with patch.dict(
            sys.modules,
            {
                "smartcard": None,
                "smartcard.CardConnection": None,
                "smartcard.Exceptions": None,
                "smartcard.System": None,
            },
        ):
            importlib.reload(apdu_transport)
            assert apdu_transport.HAS_PYSCARD is False
            assert apdu_transport._CardConnection is None

        # Восстанавливаем оригинальное состояние
        importlib.reload(apdu_transport)
        assert apdu_transport.HAS_PYSCARD is True
