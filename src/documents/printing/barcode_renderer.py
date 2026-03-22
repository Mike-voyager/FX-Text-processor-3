"""Рендерер штрихкодов в ESC/P байты.

Предоставляет:
- BarcodeRenderer: Barcode → ESC/P bytes (ESC ( B command)

Example:
    >>> from src.documents.printing import BarcodeRenderer
    >>> renderer = BarcodeRenderer()
    >>> escp_data = renderer.render("123456789012", BarcodeType.EAN13)
"""

from __future__ import annotations

import logging
from typing import Final

from src.escp.commands.barcode import (
    BarcodeHRI,
    BarcodeType,
)
from src.escp.commands.barcode import (
    print_barcode as build_barcode_command,
)

logger: Final = logging.getLogger(__name__)


class BarcodeRenderer:
    """Рендерер штрихкодов.

    Преобразует данные штрихкода в ESC/P команды.
    Использует команду ESC ( B для печати штрихкодов.

    Supported types: EAN-13, EAN-8, UPC-A, UPC-E, CODE39,
    CODE128, Interleaved 2 of 5, Codabar, CODE93.

    Example:
        >>> renderer = BarcodeRenderer()
        >>> data = renderer.render("123456789012", BarcodeType.EAN13)
    """

    def __init__(self) -> None:
        """Инициализирует рендерер штрихкодов."""
        self._logger = logging.getLogger(__name__)

    def render(
        self,
        barcode_data: str,
        barcode_type: BarcodeType,
        module_width: int = 2,
        height: int = 50,
        hri: BarcodeHRI = BarcodeHRI.BELOW,
    ) -> bytes:
        """Рендерит штрихкод в ESC/P байты.

        Args:
            barcode_data: Данные штрихкода (цифры/символы в зависимости от типа)
            barcode_type: Тип штрихкода (protocol-level)
            module_width: Ширина модуля (1-6 точек)
            height: Высота штрихкода в точках (1-255)
            hri: Позиция HRI текста

        Returns:
            ESC/P команды для печати штрихкода

        Raises:
            ValueError: При невалидных параметрах

        Example:
            >>> data = renderer.render("123456789012", BarcodeType.EAN13)
            >>> len(data) > 0
            True
        """
        if not barcode_data:
            self._logger.warning("Empty barcode data provided")
            return b""

        # Валидация параметров
        if not 1 <= module_width <= 6:
            raise ValueError(f"Module width must be 1-6, got {module_width}")

        if not 1 <= height <= 255:
            raise ValueError(f"Height must be 1-255, got {height}")

        self._logger.debug(
            f"Rendering barcode: type={barcode_type.name}, "
            f"data={barcode_data[:10]}..., height={height}"
        )

        return build_barcode_command(
            barcode_type=barcode_type,
            data=barcode_data,
            height=height,
            width=module_width,
            hri=hri,
        )

    def render_ean13(
        self,
        data: str,
        module_width: int = 3,
        height: int = 162,
        hri: BarcodeHRI = BarcodeHRI.BELOW,
    ) -> bytes:
        """Рендерит EAN-13 штрихкод.

        Args:
            data: 13 цифр (или 12 для автоматического расчёта контрольной суммы)
            module_width: Ширина модуля (1-6)
            height: Высота (1-255)
            hri: Позиция текста

        Returns:
            ESC/P байты
        """
        return self.render(data, BarcodeType.EAN13, module_width, height, hri)

    def render_code128(
        self,
        data: str,
        module_width: int = 3,
        height: int = 162,
        hri: BarcodeHRI = BarcodeHRI.BELOW,
    ) -> bytes:
        """Рендерит Code 128 штрихкод.

        Args:
            data: ASCII символы (0-127)
            module_width: Ширина модуля (1-6)
            height: Высота (1-255)
            hri: Позиция текста

        Returns:
            ESC/P байты
        """
        return self.render(data, BarcodeType.CODE128, module_width, height, hri)

    def render_code39(
        self,
        data: str,
        module_width: int = 3,
        height: int = 162,
        hri: BarcodeHRI = BarcodeHRI.BELOW,
    ) -> bytes:
        """Рендерит Code 39 штрихкод.

        Args:
            data: Цифры, буквы, дефис, точка, пробел, $, /, +, %
            module_width: Ширина модуля (1-6)
            height: Высота (1-255)
            hri: Позиция текста

        Returns:
            ESC/P байты
        """
        return self.render(data, BarcodeType.CODE39, module_width, height, hri)


__all__ = ["BarcodeRenderer"]
