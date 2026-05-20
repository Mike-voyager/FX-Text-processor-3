"""Рендерер штрих-кодов для canvas.

Предоставляет классы для отображения штрих-кодов в DocumentView canvas:
- BarcodeCanvasRenderer: базовый рендерер
- HardwareBarcodeRenderer: рендеринг для ESC/P (текстовое представление)
- SoftwareBarcodeRenderer: рендеринг через PIL Image
- PlaceholderBarcodeRenderer: упрощённый placeholder

Example:
    >>> from src.gui.renderers.barcode_canvas_renderer import SoftwareBarcodeRenderer
    >>> renderer = SoftwareBarcodeRenderer(canvas)
    >>> image = renderer.render_barcode("CODE128", "12345", width=200, height=100)
    >>> canvas.create_image(x, y, image=image)

Module: src/gui.renderers.barcode_canvas_renderer.py
Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from abc import ABC, abstractmethod
from enum import Enum, auto
from io import BytesIO
from typing import Any, Final, Optional, Protocol

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

PLACEHOLDER_BG: Final[str] = "#e9ecef"
PLACEHOLDER_FG: Final[str] = "#6c757d"
PLACEHOLDER_BORDER: Final[str] = "#adb5bd"
HARDWARE_BG: Final[str] = "#fff3cd"
HARDWARE_FG: Final[str] = "#856404"
HARDWARE_BORDER: Final[str] = "#ffc107"

# Canvas item tags
BARCODE_TAG: Final[str] = "barcode_item"
PLACEHOLDER_TAG: Final[str] = "barcode_placeholder"


# =============================================================================
# ENUMS
# =============================================================================


class BarcodeRenderMode(Enum):
    """Режим рендеринга штрих-кода на canvas.

    Attributes:
        REAL: Реальное изображение штрих-кода (PIL → PhotoImage).
        PLACEHOLDER: Упрощённый прямоугольник с текстом.
    """

    REAL = auto()
    PLACEHOLDER = auto()


# =============================================================================
# PROTOCOL
# =============================================================================


class BarcodeRendererProtocol(Protocol):
    """Протокол для рендереров штрих-кодов."""

    def render(
        self,
        barcode_type: str,
        data: str,
        x: int,
        y: int,
        width: int,
        height: int,
        **kwargs: Any,
    ) -> int:
        """Рендерит штрих-код на canvas.

        Args:
            barcode_type: Тип штрих-кода (CODE128, EAN13, etc).
            data: Данные для кодирования.
            x: X координата.
            y: Y координата.
            width: Ширина в пикселях.
            height: Высота в пикселях.
            **kwargs: Дополнительные параметры.

        Returns:
            ID созданного элемента canvas.
        """
        ...

    def clear(self, item_id: Optional[int] = None) -> None:
        """Очищает рендерер."""
        ...


# =============================================================================
# BASE CLASS
# =============================================================================


class BarcodeCanvasRenderer(ABC):
    """Базовый класс для рендереров штрих-кодов на canvas.

    Attributes:
        _canvas: Canvas для рендеринга.
        _render_mode: Режим рендеринга.
        _item_refs: Список созданных элементов (для очистки).

    Example:
        >>> renderer = ConcreteRenderer(canvas)
        >>> item_id = renderer.render("CODE128", "123", 0, 0, 200, 100)
    """

    def __init__(
        self,
        canvas: tk.Canvas,
        render_mode: BarcodeRenderMode = BarcodeRenderMode.REAL,
    ) -> None:
        """Инициализация рендерера.

        Args:
            canvas: Canvas для рендеринга.
            render_mode: Режим рендеринга (REAL или PLACEHOLDER).
        """
        self._canvas: tk.Canvas = canvas
        self._render_mode: BarcodeRenderMode = render_mode
        self._item_refs: list[int] = []
        self._photo_images: list[tk.PhotoImage] = []  # Keep references

    @property
    def render_mode(self) -> BarcodeRenderMode:
        """Возвращает текущий режим рендеринга."""
        return self._render_mode

    @render_mode.setter
    def render_mode(self, mode: BarcodeRenderMode) -> None:
        """Устанавливает режим рендеринга."""
        self._render_mode = mode

    def clear(self, item_id: Optional[int] = None) -> None:
        """Очищает элементы canvas.

        Args:
            item_id: ID конкретного элемента или None для очистки всех.
        """
        if item_id is not None:
            try:
                self._canvas.delete(item_id)
                if item_id in self._item_refs:
                    self._item_refs.remove(item_id)
            except tk.TclError:
                pass
        else:
            for item in self._item_refs[:]:
                try:
                    self._canvas.delete(item)
                except tk.TclError:
                    pass
            self._item_refs.clear()
            self._photo_images.clear()

    def _store_item(self, item_id: int) -> int:
        """Сохраняет ссылку на элемент canvas.

        Args:
            item_id: ID элемента.

        Returns:
            ID элемента.
        """
        self._item_refs.append(item_id)
        return item_id

    def _store_photo(self, photo: tk.PhotoImage) -> tk.PhotoImage:
        """Сохраняет ссылку на PhotoImage (предотвращает GC).

        Args:
            photo: PhotoImage для сохранения.

        Returns:
            PhotoImage.
        """
        self._photo_images.append(photo)
        return photo

    @abstractmethod
    def render(
        self,
        barcode_type: str,
        data: str,
        x: int,
        y: int,
        width: int,
        height: int,
        **kwargs: Any,
    ) -> int:
        """Рендерит штрих-код.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные для кодирования.
            x: X координата.
            y: Y координата.
            width: Ширина.
            height: Высота.
            **kwargs: Дополнительные параметры.

        Returns:
            ID элемента canvas.
        """
        raise NotImplementedError


# =============================================================================
# CONCRETE RENDERERS
# =============================================================================


class SoftwareBarcodeRenderer(BarcodeCanvasRenderer):
    """Рендерер штрих-кодов через software (PIL).

    Использует python-barcode для генерации изображения,
    конвертирует в PhotoImage и отображает на canvas.

    Example:
        >>> renderer = SoftwareBarcodeRenderer(canvas)
        >>> item = renderer.render("CODE128", "12345", 10, 10, 200, 100)
    """

    def __init__(
        self,
        canvas: tk.Canvas,
        render_mode: BarcodeRenderMode = BarcodeRenderMode.REAL,
        dpi: int = 300,
    ) -> None:
        """Инициализация software рендерера.

        Args:
            canvas: Canvas для рендеринга.
            render_mode: Режим рендеринга.
            dpi: Разрешение для генерации.
        """
        super().__init__(canvas, render_mode)
        self._dpi: int = dpi

    def render(
        self,
        barcode_type: str,
        data: str,
        x: int,
        y: int,
        width: int,
        height: int,
        show_text: bool = True,
        **kwargs: Any,
    ) -> int:
        """Рендерит штрих-код через PIL.

        Args:
            barcode_type: Тип штрих-кода (CODE128, EAN13, etc).
            data: Данные для кодирования.
            x: X координата.
            y: Y координата.
            width: Ширина.
            height: Высота.
            show_text: Показывать ли текст под штрих-кодом.
            **kwargs: Дополнительные параметры.

        Returns:
            ID элемента canvas.
        """
        if self._render_mode == BarcodeRenderMode.PLACEHOLDER:
            return self._render_placeholder(barcode_type, data, x, y, width, height)

        try:
            # Generate barcode image
            image = self._generate_barcode_image(barcode_type, data, width, height, show_text)

            if image is None:
                return self._render_placeholder(
                    barcode_type, data, x, y, width, height, error="Generation failed"
                )

            # Convert to PhotoImage
            try:
                from PIL import ImageTk

                photo = ImageTk.PhotoImage(image)
            except ImportError:
                logger.warning("ImageTk не доступен, предпросмотр штрих-кода отключен")
                return self._render_placeholder(
                    barcode_type, data, x, y, width, height, error="ImageTk не доступен"
                )

            self._store_photo(photo)

            # Create image on canvas
            item_id = self._canvas.create_image(
                x + width // 2,
                y + height // 2,
                image=photo,
                anchor=tk.CENTER,
                tags=(BARCODE_TAG,),
            )

            return self._store_item(item_id)

        except ImportError as e:
            logger.warning("Barcode library not available: %s", e)
            return self._render_placeholder(
                barcode_type, data, x, y, width, height, error="Library not available"
            )
        except Exception as e:
            logger.error("Barcode render error: %s", e)
            return self._render_placeholder(barcode_type, data, x, y, width, height, error=str(e))

    def _generate_barcode_image(
        self,
        barcode_type: str,
        data: str,
        width: int,
        height: int,
        show_text: bool,
    ) -> Optional[Any]:
        """Генерирует изображение штрих-кода через python-barcode.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные для кодирования.
            width: Ширина изображения.
            height: Высота изображения.
            show_text: Показывать ли текст.

        Returns:
            PIL Image или None.
        """
        try:
            from barcode import CODABAR, EAN8, EAN13, ITF, UPCA, Code39, Code128
            from barcode.writer import ImageWriter
            from PIL import Image

            # Map type to class
            type_map = {
                "CODE128": Code128,
                "CODE39": Code39,
                "EAN13": EAN13,
                "EAN8": EAN8,
                "UPC": UPCA,
                "ITF": ITF,
                "CODABAR": CODABAR,
            }

            barcode_class = type_map.get(barcode_type)
            if barcode_class is None:
                logger.warning("Unsupported barcode type: %s", barcode_type)
                return None

            # Generate barcode
            writer = ImageWriter()
            writer.set_options(
                {
                    "write_text": show_text,
                    "module_height": height * 0.7,  # 70% of height for bars
                    "font_size": 10,
                    "text_distance": 5,
                    "quiet_zone": 3,
                }
            )

            barcode_instance = barcode_class(data, writer=writer)

            # Render to buffer
            buffer = BytesIO()
            barcode_instance.write(buffer, options={"dpi": self._dpi})
            buffer.seek(0)

            # Open and resize
            img = Image.open(buffer)

            # Resize to target dimensions
            if img.width != width or img.height != height:
                img = img.resize((width, height), Image.LANCZOS)  # type: ignore[attr-defined,assignment]

            return img

        except Exception as e:
            logger.error("Barcode generation error: %s", e)
            return None

    def _render_placeholder(
        self,
        barcode_type: str,
        data: str,
        x: int,
        y: int,
        width: int,
        height: int,
        error: Optional[str] = None,
    ) -> int:
        """Рендерит placeholder при ошибке.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные.
            x: X координата.
            y: Y координата.
            width: Ширина.
            height: Высота.
            error: Сообщение об ошибке.

        Returns:
            ID элемента canvas.
        """
        # Background rectangle
        rect_id = self._canvas.create_rectangle(
            x,
            y,
            x + width,
            y + height,
            fill=PLACEHOLDER_BG,
            outline=PLACEHOLDER_BORDER,
            width=2,
            tags=(BARCODE_TAG, PLACEHOLDER_TAG),
        )

        # Label
        label_text = f"[BAR] {barcode_type}"
        if error:
            label_text += f"\n[!] {error[:30]}"
        else:
            label_text += f"\n{data[:20]}{'...' if len(data) > 20 else ''}"

        text_id = self._canvas.create_text(
            x + width // 2,
            y + height // 2,
            text=label_text,
            fill=PLACEHOLDER_FG,
            font=("Helvetica", 9),
            justify=tk.CENTER,
            tags=(BARCODE_TAG, PLACEHOLDER_TAG),
        )

        self._item_refs.extend([rect_id, text_id])
        return rect_id


class HardwareBarcodeRenderer(BarcodeCanvasRenderer):
    """Рендерер для hardware-режима (ESC/P).

    Показывает текстовое представление ESC/P команды
    или placeholder с информацией о hardware-режиме.

    Example:
        >>> renderer = HardwareBarcodeRenderer(canvas)
        >>> item = renderer.render("EAN13", "123456789012", 10, 10, 200, 100)
    """

    def render(
        self,
        barcode_type: str,
        data: str,
        x: int,
        y: int,
        width: int,
        height: int,
        **kwargs: Any,
    ) -> int:
        """Рендерит hardware-представление штрих-кода.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные для кодирования.
            x: X координата.
            y: Y координата.
            width: Ширина.
            height: Высота.
            **kwargs: Дополнительные параметры.

        Returns:
            ID группы элементов canvas.
        """
        if self._render_mode == BarcodeRenderMode.PLACEHOLDER:
            return self._render_placeholder(barcode_type, data, x, y, width, height)

        # Render ESC/P representation
        return self._render_hardware_repr(barcode_type, data, x, y, width, height)

    def _render_hardware_repr(
        self,
        barcode_type: str,
        data: str,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> int:
        """Рендерит текстовое представление ESC/P команды.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные.
            x: X координата.
            y: Y координата.
            width: Ширина.
            height: Высота.

        Returns:
            ID группы элементов.
        """
        # Background
        rect_id = self._canvas.create_rectangle(
            x,
            y,
            x + width,
            y + height,
            fill=HARDWARE_BG,
            outline=HARDWARE_BORDER,
            width=2,
            tags=(BARCODE_TAG,),
        )

        # Header
        header_id = self._canvas.create_text(
            x + width // 2,
            y + 20,
            text=f"[HW] Hardware Mode: {barcode_type}",
            fill=HARDWARE_FG,
            font=("Helvetica", 10, "bold"),
            anchor=tk.CENTER,
            tags=(BARCODE_TAG,),
        )

        # ESC/P command representation
        escp_cmd = self._format_escp_command(barcode_type, data)
        cmd_id = self._canvas.create_text(
            x + width // 2,
            y + height // 2,
            text=escp_cmd,
            fill=HARDWARE_FG,
            font=("Courier", 8),
            anchor=tk.CENTER,
            justify=tk.CENTER,
            tags=(BARCODE_TAG,),
        )

        # Data preview
        data_preview = data[:25] + ("..." if len(data) > 25 else "")
        data_id = self._canvas.create_text(
            x + width // 2,
            y + height - 20,
            text=f"Data: {data_preview}",
            fill=HARDWARE_FG,
            font=("Helvetica", 8),
            anchor=tk.CENTER,
            tags=(BARCODE_TAG,),
        )

        self._item_refs.extend([rect_id, header_id, cmd_id, data_id])
        return rect_id

    def _render_placeholder(
        self,
        barcode_type: str,
        data: str,
        x: int,
        y: int,
        width: int,
        height: int,
    ) -> int:
        """Рендерит placeholder для hardware-режима.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные.
            x: X координата.
            y: Y координата.
            width: Ширина.
            height: Высота.

        Returns:
            ID элемента canvas.
        """
        # Background
        rect_id = self._canvas.create_rectangle(
            x,
            y,
            x + width,
            y + height,
            fill=HARDWARE_BG,
            outline=HARDWARE_BORDER,
            width=2,
            tags=(BARCODE_TAG, PLACEHOLDER_TAG),
        )

        # Content
        content = f"[HW] {barcode_type}\nHardware Mode\nESC/P"
        text_id = self._canvas.create_text(
            x + width // 2,
            y + height // 2,
            text=content,
            fill=HARDWARE_FG,
            font=("Helvetica", 9),
            justify=tk.CENTER,
            tags=(BARCODE_TAG, PLACEHOLDER_TAG),
        )

        self._item_refs.extend([rect_id, text_id])
        return rect_id

    def _format_escp_command(self, barcode_type: str, data: str) -> str:
        """Форматирует ESC/P команду для отображения.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные.

        Returns:
            Отформатированная команда.
        """
        # ESC/P command format
        escp_type_map = {
            "EAN13": "65",
            "EAN8": "64",
            "CODE39": "69",
            "CODE128": "73",
            "UPC": "65",
        }
        escp_type = escp_type_map.get(barcode_type, "??")

        return f"ESC GS k {escp_type} {len(data)}\n{data[:20]}"


class PlaceholderBarcodeRenderer(BarcodeCanvasRenderer):
    """Рендерер placeholder для штрих-кодов.

    Всегда показывает упрощённое представление без генерации.
    Используется для производительности с большими документами.

    Example:
        >>> renderer = PlaceholderBarcodeRenderer(canvas)
        >>> item = renderer.render("CODE128", "12345", 10, 10, 200, 100)
    """

    def render(
        self,
        barcode_type: str,
        data: str,
        x: int,
        y: int,
        width: int,
        height: int,
        **kwargs: Any,
    ) -> int:
        """Рендерит placeholder штрих-кода.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные для кодирования.
            x: X координата.
            y: Y координата.
            width: Ширина.
            height: Высота.
            **kwargs: Дополнительные параметры.

        Returns:
            ID группы элементов canvas.
        """
        # Background rectangle
        rect_id = self._canvas.create_rectangle(
            x,
            y,
            x + width,
            y + height,
            fill=PLACEHOLDER_BG,
            outline=PLACEHOLDER_BORDER,
            width=2,
            tags=(BARCODE_TAG, PLACEHOLDER_TAG),
        )

        # Barcode icon (simulated with lines)
        icon_x = x + width // 2
        icon_y = y + height // 3
        icon_items = []

        # Draw barcode-like lines
        line_start = icon_x - 40
        for i in range(10):
            line_width = 3 + (i % 3) * 2
            line_id = self._canvas.create_line(
                [
                    line_start + i * 8,
                    icon_y - 15,
                    line_start + i * 8 + line_width,
                    icon_y - 15,
                    line_start + i * 8 + line_width,
                    icon_y + 15,
                    line_start + i * 8,
                    icon_y + 15,
                ],
                fill="#333333",
                width=1,
                tags=(BARCODE_TAG, PLACEHOLDER_TAG),
            )
            icon_items.append(line_id)

        # Type label
        label_id = self._canvas.create_text(
            icon_x,
            y + height - 30,
            text=f"[BAR] {barcode_type}",
            fill=PLACEHOLDER_FG,
            font=("Helvetica", 10, "bold"),
            anchor=tk.CENTER,
            tags=(BARCODE_TAG, PLACEHOLDER_TAG),
        )

        # Data preview (truncated)
        data_preview = data[:15] + ("..." if len(data) > 15 else "")
        data_id = self._canvas.create_text(
            icon_x,
            y + height - 12,
            text=data_preview,
            fill=PLACEHOLDER_FG,
            font=("Helvetica", 8),
            anchor=tk.CENTER,
            tags=(BARCODE_TAG, PLACEHOLDER_TAG),
        )

        self._item_refs.extend([rect_id, label_id, data_id] + icon_items)
        return rect_id


# =============================================================================
# FACTORY
# =============================================================================


def create_barcode_renderer(
    canvas: tk.Canvas,
    mode: str = "software",
    render_mode: BarcodeRenderMode = BarcodeRenderMode.REAL,
    **kwargs: Any,
) -> BarcodeCanvasRenderer:
    """Фабричная функция для создания рендерера.

    Args:
        canvas: Canvas для рендеринга.
        mode: Режим работы ("software", "hardware", "placeholder").
        render_mode: Режим рендеринга (REAL или PLACEHOLDER).
        **kwargs: Дополнительные параметры.

    Returns:
        Экземпляр рендерера.

    Example:
        >>> renderer = create_barcode_renderer(
        ...     canvas,
        ...     mode="software",
        ...     render_mode=BarcodeRenderMode.REAL,
        ...     dpi=300,
        ... )
    """
    if mode == "placeholder":
        return PlaceholderBarcodeRenderer(canvas, render_mode)
    elif mode == "hardware":
        return HardwareBarcodeRenderer(canvas, render_mode)
    else:
        return SoftwareBarcodeRenderer(canvas, render_mode, **kwargs)
