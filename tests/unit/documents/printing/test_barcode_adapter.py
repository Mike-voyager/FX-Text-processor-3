"""Тесты для barcode_adapter.

Покрытие:
- Конвертация BarcodeType -> ESCPBarcodeType
- Проверка is_hardware_supported
- Обработка неподдерживаемых типов
"""

from __future__ import annotations

import pytest

from src.documents.printing.barcode_adapter import (
    is_hardware_supported,
    to_escp_type,
)
from src.escp.commands.barcode import ESCPBarcodeType
from src.model.enums import BarcodeType


class TestToESCPType:
    """Тесты конвертации BarcodeType -> ESCPBarcodeType."""

    @pytest.mark.parametrize(
        "software_type,expected_escp",
        [
            (BarcodeType.EAN13, ESCPBarcodeType.EAN13),
            (BarcodeType.EAN8, ESCPBarcodeType.EAN8),
            (BarcodeType.UPCA, ESCPBarcodeType.UPCA),
            (BarcodeType.UPCE, ESCPBarcodeType.UPCE),
            (BarcodeType.CODE39, ESCPBarcodeType.CODE39),
            (BarcodeType.CODE128, ESCPBarcodeType.CODE128),
            (BarcodeType.ITF, ESCPBarcodeType.INTERLEAVED_2OF5),
            (BarcodeType.CODABAR, ESCPBarcodeType.CODABAR),
            (BarcodeType.POSTNET, ESCPBarcodeType.POSTNET),
        ],
    )
    def test_supported_types(
        self, software_type: BarcodeType, expected_escp: ESCPBarcodeType
    ) -> None:
        """Поддерживаемые типы конвертируются в ESCPBarcodeType."""
        result = to_escp_type(software_type)
        assert result == expected_escp

    @pytest.mark.parametrize(
        "software_type",
        [
            BarcodeType.EAN14,
            BarcodeType.CODE93,
            BarcodeType.MSI,
            BarcodeType.PHARMACODE,
            BarcodeType.CODE11,
            BarcodeType.STANDARD2OF5,
            BarcodeType.GS1128,
            BarcodeType.PLESSEY,
            BarcodeType.TELEPEN,
            BarcodeType.TRIOPTIC,
        ],
    )
    def test_unsupported_types_return_none(self, software_type: BarcodeType) -> None:
        """Неподдерживаемые типы возвращают None."""
        result = to_escp_type(software_type)
        assert result is None


class TestIsHardwareSupported:
    """Тесты проверки hardware поддержки."""

    @pytest.mark.parametrize(
        "software_type",
        [
            BarcodeType.EAN13,
            BarcodeType.EAN8,
            BarcodeType.UPCA,
            BarcodeType.UPCE,
            BarcodeType.CODE39,
            BarcodeType.CODE128,
            BarcodeType.ITF,
            BarcodeType.CODABAR,
            BarcodeType.POSTNET,
        ],
    )
    def test_supported_returns_true(self, software_type: BarcodeType) -> None:
        """Поддерживаемые типы возвращают True."""
        assert is_hardware_supported(software_type) is True

    @pytest.mark.parametrize(
        "software_type",
        [
            BarcodeType.EAN14,
            BarcodeType.CODE93,
            BarcodeType.MSI,
            BarcodeType.PHARMACODE,
            BarcodeType.CODE11,
            BarcodeType.STANDARD2OF5,
            BarcodeType.GS1128,
            BarcodeType.PLESSEY,
            BarcodeType.TELEPEN,
            BarcodeType.TRIOPTIC,
        ],
    )
    def test_unsupported_returns_false(self, software_type: BarcodeType) -> None:
        """Неподдерживаемые типы возвращают False."""
        assert is_hardware_supported(software_type) is False


class TestIntegration:
    """Интеграционные тесты."""

    def test_escp_type_can_create_barcode_command(self) -> None:
        """ESCPBarcodeType можно использовать для создания команды."""
        from src.escp.commands.barcode import print_barcode

        escp_type = to_escp_type(BarcodeType.EAN13)
        assert escp_type is not None

        # Должно работать без ошибок
        cmd = print_barcode(escp_type, "978014300723", height=50, width=2)
        assert isinstance(cmd, bytes)
        assert len(cmd) > 0

    def test_all_hardware_types_match_escp(self) -> None:
        """Все hardware-поддерживаемые типы имеют соответствующий ESCPBarcodeType."""
        from src.model.enums import validate_barcode

        for bt in BarcodeType:
            if validate_barcode(bt):
                result = to_escp_type(bt)
                assert result is not None, f"{bt} should have ESCP mapping"