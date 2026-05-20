"""Рендерер QR-кодов для canvas.

Предоставляет классы для отображения QR-кодов в DocumentView canvas:
- QRCanvasRenderer: базовый рендерер
- SoftwareQRRenderer: рендеринг через qrcode library
- PlaceholderQRRenderer: упрощённый placeholder

Example:
    >>> from src.gui.renderers.qr_canvas_renderer import SoftwareQRRenderer
    >>> renderer = SoftwareQRRenderer(canvas)
    >>> item = renderer.render_qr("https://example.com", x=10, y=10, size=200)

Module: src/gui/renderers/qr_canvas_renderer.py
Version: 1.0
"""

from __future__ import annotations

import hashlib
import logging
import tkinter as tk
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Any, Final, Optional, Protocol

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

PLACEHOLDER_BG: Final[str] = "#e9ecef"
PLACEHOLDER_FG: Final[str] = "#6c757d"
PLACEHOLDER_BORDER: Final[str] = "#adb5bd"
QR_BG: Final[str] = "#ffffff"
QR_FG: Final[str] = "#000000"

# Canvas item tags
QR_TAG: Final[str] = "qr_item"
PLACEHOLDER_TAG: Final[str] = "qr_placeholder"


# =============================================================================
# ENUMS
# =============================================================================


class QRRenderMode(Enum):
    """Режим рендеринга QR-кода на canvas.

    Attributes:
        REAL: Реальное изображение QR-кода (PIL → PhotoImage).
        PLACEHOLDER: Упрощённый прямоугольник с текстом.
    """

    REAL = auto()
    PLACEHOLDER = auto()


# =============================================================================
# PROTOCOL
# =============================================================================


class QRRendererProtocol(Protocol):
    """Протокол для рендереров QR-кодов."""

    def render_qr(
        self,
        data: str,
        x: int,
        y: int,
        size: int,
        **kwargs: Any,
    ) -> int:
        """Рендерит QR-код на canvas.

        Args:
            data: Данные для кодирования.
            x: X координата.
            y: Y координата.
            size: Размер стороны QR-кода.
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


class QRCanvasRenderer(ABC):
    """Базовый класс для рендереров QR-кодов на canvas.

    Attributes:
        _canvas: Canvas для рендеринга.
        _render_mode: Режим рендеринга.
        _item_refs: Список созданных элементов.

    Example:
        >>> renderer = ConcreteRenderer(canvas)
        >>> item_id = renderer.render_qr("data", 0, 0, 200)
    """

    def __init__(
        self,
        canvas: tk.Canvas,
        render_mode: QRRenderMode = QRRenderMode.REAL,
    ) -> None:
        """Инициализация рендерера.

        Args:
            canvas: Canvas для рендеринга.
            render_mode: Режим рендеринга (REAL или PLACEHOLDER).
        """
        self._canvas: tk.Canvas = canvas
        self._render_mode: QRRenderMode = render_mode
        self._item_refs: list[int] = []
        self._photo_images: list[tk.PhotoImage] = []

    @property
    def render_mode(self) -> QRRenderMode:
        """Возвращает текущий режим рендеринга."""
        return self._render_mode

    @render_mode.setter
    def render_mode(self, mode: QRRenderMode) -> None:
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
        """Сохраняет ссылку на PhotoImage.

        Args:
            photo: PhotoImage для сохранения.

        Returns:
            PhotoImage.
        """
        self._photo_images.append(photo)
        return photo

    @abstractmethod
    def render_qr(
        self,
        data: str,
        x: int,
        y: int,
        size: int,
        **kwargs: Any,
    ) -> int:
        """Рендерит QR-код.

        Args:
            data: Данные для кодирования.
            x: X координата.
            y: Y координата.
            size: Размер стороны.
            **kwargs: Дополнительные параметры.

        Returns:
            ID элемента canvas.
        """
        raise NotImplementedError


# =============================================================================
# CONCRETE RENDERERS
# =============================================================================


class SoftwareQRRenderer(QRCanvasRenderer):
    """Рендерер QR-кодов через software (PIL).

    Использует qrcode library для генерации изображения,
    конвертирует в PhotoImage и отображает на canvas.

    Attributes:
        _error_correction: Уровень коррекции ошибок.
        _box_size: Размер модуля.
        _border: Ширина границы.
        _version: Версия QR-кода.

    Example:
        >>> renderer = SoftwareQRRenderer(canvas)
        >>> item = renderer.render_qr("data", 10, 10, 200)
    """

    def __init__(
        self,
        canvas: tk.Canvas,
        render_mode: QRRenderMode = QRRenderMode.REAL,
        error_correction: str = "M",
        box_size: int = 4,
        border: int = 4,
        version: Optional[int] = None,
    ) -> None:
        """Инициализация software рендерера.

        Args:
            canvas: Canvas для рендеринга.
            render_mode: Режим рендеринга.
            error_correction: Уровень коррекции (L, M, Q, H).
            box_size: Размер модуля в пикселях.
            border: Ширина границы в модулях.
            version: Версия QR (None для авто).
        """
        super().__init__(canvas, render_mode)
        self._error_correction: str = error_correction
        self._box_size: int = box_size
        self._border: int = border
        self._version: Optional[int] = version

    def render_qr(
        self,
        data: str,
        x: int,
        y: int,
        size: int,
        error_correction: Optional[str] = None,
        box_size: Optional[int] = None,
        border: Optional[int] = None,
        version: Optional[int] = None,
        **kwargs: Any,
    ) -> int:
        """Рендерит QR-код через qrcode library.

        Args:
            data: Данные для кодирования.
            x: X координата.
            y: Y координата.
            size: Размер стороны.
            error_correction: Уровень коррекции ошибок.
            box_size: Размер модуля.
            border: Ширина границы.
            version: Версия QR-кода.
            **kwargs: Дополнительные параметры.

        Returns:
            ID элемента canvas.
        """
        if self._render_mode == QRRenderMode.PLACEHOLDER:
            return self._render_placeholder(data, x, y, size)

        try:
            # Use provided or default parameters
            ec = error_correction or self._error_correction
            bs = box_size or self._box_size
            br = border or self._border
            ver = version if version is not None else self._version

            # Generate QR image
            image = self._generate_qr_image(data, ec, bs, br, ver, size)

            if image is None:
                return self._render_placeholder(data, x, y, size, error="Generation failed")

            # Convert to PhotoImage
            try:
                from PIL import ImageTk

                photo = ImageTk.PhotoImage(image)
            except ImportError:
                logger.warning("ImageTk не доступен, предпросмотр QR отключен")
                return self._render_placeholder(data, x, y, size, error="ImageTk не доступен")

            self._store_photo(photo)

            # Create image on canvas
            item_id = self._canvas.create_image(
                x + size // 2,
                y + size // 2,
                image=photo,
                anchor=tk.CENTER,
                tags=(QR_TAG,),
            )

            return self._store_item(item_id)

        except ImportError as e:
            logger.warning("qrcode library not available: %s", e)
            return self._render_placeholder(data, x, y, size, error="Library not available")
        except Exception as e:
            logger.error("QR render error: %s", e)
            return self._render_placeholder(data, x, y, size, error=str(e)[:50])

    def _generate_qr_image(
        self,
        data: str,
        error_correction: str,
        box_size: int,
        border: int,
        version: Optional[int],
        target_size: int,
    ) -> Optional[Any]:
        """Генерирует изображение QR-кода.

        Args:
            data: Данные для кодирования.
            error_correction: Уровень коррекции.
            box_size: Размер модуля.
            border: Ширина границы.
            version: Версия QR.
            target_size: Целевой размер в пикселях.

        Returns:
            PIL Image или None.
        """
        try:
            from PIL import Image
            from qrcode import QRCode
            from qrcode.constants import (
                ERROR_CORRECT_H,
                ERROR_CORRECT_L,
                ERROR_CORRECT_M,
                ERROR_CORRECT_Q,
            )

            # Map error correction string to constant
            ec_map = {
                "L": ERROR_CORRECT_L,
                "M": ERROR_CORRECT_M,
                "Q": ERROR_CORRECT_Q,
                "H": ERROR_CORRECT_H,
            }
            ec_constant = ec_map.get(error_correction, ERROR_CORRECT_M)

            # Create QR code
            qr = QRCode(
                version=version,
                error_correction=ec_constant,
                box_size=box_size,
                border=border,
            )
            qr.add_data(data)
            qr.make(fit=True)

            # Generate image
            img = qr.make_image(fill_color="black", back_color="white")

            # Resize to target size
            if img.width != target_size or img.height != target_size:
                img = img.resize((target_size, target_size), Image.LANCZOS)  # type: ignore[attr-defined]

            return img

        except Exception as e:
            logger.error("QR generation error: %s", e)
            return None

    def _render_placeholder(
        self,
        data: str,
        x: int,
        y: int,
        size: int,
        error: Optional[str] = None,
    ) -> int:
        """Рендерит placeholder при ошибке.

        Args:
            data: Данные.
            x: X координата.
            y: Y координата.
            size: Размер стороны.
            error: Сообщение об ошибке.

        Returns:
            ID элемента canvas.
        """
        # Background rectangle
        rect_id = self._canvas.create_rectangle(
            x,
            y,
            x + size,
            y + size,
            fill=PLACEHOLDER_BG,
            outline=PLACEHOLDER_BORDER,
            width=2,
            tags=(QR_TAG, PLACEHOLDER_TAG),
        )

        # QR icon (simulated with simple squares)
        icon_items = []
        icon_size = size // 3
        icon_x = x + size // 2 - icon_size // 2
        icon_y = y + size // 3 - icon_size // 2

        # Three position detection patterns
        for dx, dy in [(0, 0), (icon_size - 15, 0), (0, icon_size - 15)]:
            pattern = self._canvas.create_rectangle(
                icon_x + dx,
                icon_y + dy,
                icon_x + dx + 15,
                icon_y + dy + 15,
                fill=PLACEHOLDER_FG,
                outline="",
                tags=(QR_TAG, PLACEHOLDER_TAG),
            )
            icon_items.append(pattern)

        # Label
        label_text = "[QR] QR Code"
        if error:
            label_text += f"\n[!] {error[:25]}"
        else:
            preview = data[:12] + ("..." if len(data) > 12 else "")
            label_text += f"\n{preview}"

        text_id = self._canvas.create_text(
            x + size // 2,
            y + size - 30,
            text=label_text,
            fill=PLACEHOLDER_FG,
            font=("Helvetica", 9),
            justify=tk.CENTER,
            tags=(QR_TAG, PLACEHOLDER_TAG),
        )

        self._item_refs.extend([rect_id, text_id] + icon_items)
        return rect_id


class PlaceholderQRRenderer(QRCanvasRenderer):
    """Рендерер placeholder для QR-кодов.

    Всегда показывает упрощённое представление без генерации.
    Используется для производительности с большими документами.

    Example:
        >>> renderer = PlaceholderQRRenderer(canvas)
        >>> item = renderer.render_qr("data", 10, 10, 200)
    """

    def render_qr(
        self,
        data: str,
        x: int,
        y: int,
        size: int,
        **kwargs: Any,
    ) -> int:
        """Рендерит placeholder QR-кода.

        Args:
            data: Данные для кодирования.
            x: X координата.
            y: Y координата.
            size: Размер стороны.
            **kwargs: Дополнительные параметры.

        Returns:
            ID группы элементов canvas.
        """
        # Background rectangle
        rect_id = self._canvas.create_rectangle(
            x,
            y,
            x + size,
            y + size,
            fill=PLACEHOLDER_BG,
            outline=PLACEHOLDER_BORDER,
            width=2,
            tags=(QR_TAG, PLACEHOLDER_TAG),
        )

        # QR pattern (simplified)
        pattern_items = []
        pattern_size = min(size * 0.5, 100)
        cell_size = pattern_size / 21  # Version 1 QR is 21x21
        pattern_x = x + (size - pattern_size) // 2
        pattern_y = y + (size - pattern_size) // 2 - 10

        # Draw position detection patterns (corners)
        corners = [
            (0, 0, 7, 7),  # Top-left
            (14, 0, 21, 7),  # Top-right
            (0, 14, 7, 21),  # Bottom-left
        ]

        for cx1, cy1, cx2, cy2 in corners:
            for row in range(cy1, cy2):
                for col in range(cx1, cx2):
                    # Simplified: fill entire corner
                    if row == cy1 or row == cy2 - 1 or col == cx1 or col == cx2 - 1:
                        pass  # Border
                    elif row == cy1 + 1 or row == cy2 - 2 or col == cx1 + 1 or col == cx2 - 2:
                        pass  # Inner border
                    else:
                        # Center
                        px = pattern_x + col * cell_size
                        py = pattern_y + row * cell_size
                        cell = self._canvas.create_rectangle(
                            px,
                            py,
                            px + cell_size,
                            py + cell_size,
                            fill=PLACEHOLDER_FG,
                            outline="",
                            tags=(QR_TAG, PLACEHOLDER_TAG),
                        )
                        pattern_items.append(cell)

        # Deterministic data pattern using hash (prevents weak-random lint)
        digest = hashlib.sha256(data.encode()).digest()
        for i in range(50):
            idx = (i * 4) % len(digest)
            chunk = digest[idx : idx + 4]
            row_val = int.from_bytes(chunk[:2], "big")
            col_val = int.from_bytes(chunk[2:], "big")
            row = 8 + (row_val % 6)
            col = 8 + (col_val % 6)
            px = pattern_x + col * cell_size
            py = pattern_y + row * cell_size
            cell = self._canvas.create_rectangle(
                px,
                py,
                px + cell_size,
                py + cell_size,
                fill=PLACEHOLDER_FG,
                outline="",
                tags=(QR_TAG, PLACEHOLDER_TAG),
            )
            pattern_items.append(cell)

        # Label
        label_id = self._canvas.create_text(
            x + size // 2,
            y + size - 25,
            text="[QR] QR Code",
            fill=PLACEHOLDER_FG,
            font=("Helvetica", 10, "bold"),
            anchor=tk.CENTER,
            tags=(QR_TAG, PLACEHOLDER_TAG),
        )

        # Data preview
        preview = data[:15] + ("..." if len(data) > 15 else "")
        data_id = self._canvas.create_text(
            x + size // 2,
            y + size - 10,
            text=preview,
            fill=PLACEHOLDER_FG,
            font=("Helvetica", 8),
            anchor=tk.CENTER,
            tags=(QR_TAG, PLACEHOLDER_TAG),
        )

        self._item_refs.extend([rect_id, label_id, data_id] + pattern_items)
        return rect_id


# =============================================================================
# FACTORY
# =============================================================================


def create_qr_renderer(
    canvas: tk.Canvas,
    mode: str = "software",
    render_mode: QRRenderMode = QRRenderMode.REAL,
    **kwargs: Any,
) -> QRCanvasRenderer:
    """Фабричная функция для создания рендерера QR.

    Args:
        canvas: Canvas для рендеринга.
        mode: Режим работы ("software", "placeholder").
        render_mode: Режим рендеринга (REAL или PLACEHOLDER).
        **kwargs: Дополнительные параметры.

    Returns:
        Экземпляр рендерера.

    Example:
        >>> renderer = create_qr_renderer(
        ...     canvas,
        ...     mode="software",
        ...     render_mode=QRRenderMode.REAL,
        ...     error_correction="H",
        ...     box_size=6,
        ... )
    """
    if mode == "placeholder":
        return PlaceholderQRRenderer(canvas, render_mode)
    else:
        return SoftwareQRRenderer(canvas, render_mode, **kwargs)
