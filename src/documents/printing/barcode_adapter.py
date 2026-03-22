"""
Адаптер для конвертации software barcode types в hardware ESC/P types.

Предоставляет функцию to_escp_type() для конвертации BarcodeType -> ESCPBarcodeType.
Используется для печати штрихкодов, которые поддерживаются hardware FX-890.

Не все BarcodeType имеют аппаратную поддержку. Для неподдерживаемых типов
необходимо использовать software rendering (barcodegen модуль).
"""

from typing import Optional

from src.escp.commands.barcode import ESCPBarcodeType
from src.model.enums import BarcodeType


def to_escp_type(software_type: BarcodeType) -> Optional[ESCPBarcodeType]:
    """
    Конвертирует software barcode type в hardware ESC/P type.

    Args:
        software_type: Тип штрихкода из model.BarcodeType

    Returns:
        ESCPBarcodeType если тип поддерживается hardware, иначе None.

    Example:
        >>> from src.documents.printing.barcode_adapter import to_escp_type
        >>> from src.model.enums import BarcodeType
        >>> escp_type = to_escp_type(BarcodeType.EAN13)
        >>> escp_type
        <ESCPBarcodeType.EAN13: 67>

        >>> to_escp_type(BarcodeType.QR)  # QR не поддерживается hardware
        None
    """
    mapping: dict[BarcodeType, ESCPBarcodeType] = {
        BarcodeType.EAN13: ESCPBarcodeType.EAN13,
        BarcodeType.EAN8: ESCPBarcodeType.EAN8,
        BarcodeType.UPCA: ESCPBarcodeType.UPCA,
        BarcodeType.UPCE: ESCPBarcodeType.UPCE,
        BarcodeType.CODE39: ESCPBarcodeType.CODE39,
        BarcodeType.CODE128: ESCPBarcodeType.CODE128,
        BarcodeType.ITF: ESCPBarcodeType.INTERLEAVED_2OF5,
        BarcodeType.CODABAR: ESCPBarcodeType.CODABAR,
        BarcodeType.POSTNET: ESCPBarcodeType.POSTNET,
    }
    return mapping.get(software_type)


def is_hardware_supported(software_type: BarcodeType) -> bool:
    """
    Проверяет, поддерживается ли тип штрихкода hardware FX-890.

    Args:
        software_type: Тип штрихкода из model.BarcodeType

    Returns:
        True если тип поддерживается для ESC/P печати, иначе False.

    Example:
        >>> from src.documents.printing.barcode_adapter import is_hardware_supported
        >>> from src.model.enums import BarcodeType
        >>> is_hardware_supported(BarcodeType.EAN13)
        True
        >>> is_hardware_supported(BarcodeType.QR)
        False
    """
    return to_escp_type(software_type) is not None


__all__ = [
    "to_escp_type",
    "is_hardware_supported",
]