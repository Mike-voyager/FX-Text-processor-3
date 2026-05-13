"""Визуализация бумаги и статус Codepage для DocumentView.

Модуль предоставляет компоненты для визуализации:
- Линии перфорации (perforation lines)
- Границы листа (paper borders)
- Оверлей конверта (envelope overlay)
- Индикаторы double-height строк (gutter indicators)
- Статус валидации Codepage

Example:
    >>> viz = PaperVisualizationWidget(widget_id="paper_viz")
    >>> viz.mount(parent_frame)
    >>> viz.set_paper_size(width_px=595, height_px=842)
    >>> viz.set_line_properties([LineProperties(is_double_height=True)])
    >>> viz.set_envelope_type("DL")

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from typing import Callable, Final, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol

# =============================================================================
# CONSTANTS
# =============================================================================

PERFORATION_COLOR: Final[str] = "#cccccc"
PERFORATION_DASH: Final[tuple[int, ...]] = (5, 5)

PAPER_BORDER_COLOR: Final[str] = "#999999"
PAPER_BORDER_WIDTH: Final[int] = 1

ENVELOPE_COLOR: Final[str] = "#E6E6FA"
ENVELOPE_BORDER_COLOR: Final[str] = "#9370DB"
ENVELOPE_BORDER_WIDTH: Final[int] = 2

DOUBLE_HEIGHT_COLOR: Final[str] = "#e0e0e0"

GUTTER_WIDTH_PX: Final[int] = 20

VALID_STATUS_COLOR: Final[str] = "#90EE90"
WARN_STATUS_COLOR: Final[str] = "#FFD700"
ERROR_STATUS_COLOR: Final[str] = "#FF6B6B"

MM_TO_PX: Final[float] = 3.78


# =============================================================================
# LINE PROPERTIES
# =============================================================================


@dataclass(frozen=True)
class LineProperties:
    """Свойства строки для визуализации.

    Attributes:
        is_double_height: Строка с двойной высотой (double-height row).
        is_condensed: Строка с уплотнённым шрифтом (condensed).
        is_bold: Строка с жирным шрифтом.
        is_italic: Строка с курсивом.

    Example:
        >>> props = LineProperties(is_double_height=True)
        >>> props.is_double_height
        True
    """

    is_double_height: bool = False
    is_condensed: bool = False
    is_bold: bool = False
    is_italic: bool = False


# =============================================================================
# PAPER VISUALIZATION WIDGET
# =============================================================================


class PaperVisualizationWidget(BaseWidget):
    """Виджет визуализации элементов бумаги.

    Отрисовывает поверх текстового виджета:
    - Пунктирные линии перфорации на -10 мм от края
    - Сплошные границы листа
    - Полупрозрачный оверлей для конвертов
    - Серые индикаторы в gutter для double-height строк

    Layout:
        Canvas positioned behind text, overlays paper visualization.

    Example:
        >>> viz = PaperVisualizationWidget(widget_id="paper_viz")
        >>> viz.mount(text_frame)
        >>> viz.set_paper_size(width_px=595, height_px=842)
        >>> viz.update()
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация виджета визуализации.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(widget_id=widget_id, controller=controller)

        self._canvas: Optional[tk.Canvas] = None

        self._paper_width_px: int = 595
        self._paper_height_px: int = 842
        self._line_properties: list[LineProperties] = []
        self._envelope_type: Optional[str] = None
        self._show_perforation: bool = True
        self._show_borders: bool = True
        self._show_envelope: bool = False
        self._show_gutter: bool = True

        self._char_width_px: int = 9
        self._char_height_px: int = 15
        self._total_lines: int = 66
        self._total_cols: int = 80

    def set_paper_size(self, width_px: int, height_px: int) -> None:
        """Устанавливает размер бумаги в пикселях.

        Args:
            width_px: Ширина в пикселях.
            height_px: Высота в пикселях.
        """
        self._paper_width_px = width_px
        self._paper_height_px = height_px
        self._update_visualization()

    def set_character_size(self, width_px: int, height_px: int) -> None:
        """Устанавливает размер символа для расчёта gutter.

        Args:
            width_px: Ширина символа в пикселях.
            height_px: Высота символа в пикселях.
        """
        self._char_width_px = width_px
        self._char_height_px = height_px

    def set_document_size(self, lines: int, cols: int) -> None:
        """Устанавливает размер документа в строках/колонках.

        Args:
            lines: Количество строк.
            cols: Количество колонок.
        """
        self._total_lines = lines
        self._total_cols = cols

    def set_line_properties(self, properties: list[LineProperties]) -> None:
        """Устанавливает свойства строк для индикации.

        Args:
            properties: Список LineProperties для каждой строки.
        """
        self._line_properties = list(properties)
        self._update_visualization()

    def set_envelope_type(self, envelope_type: Optional[str]) -> None:
        """Устанавливает тип конверта для оверлея.

        Args:
            envelope_type: Тип конверта ("DL", "C5", "C4") или None.
        """
        self._envelope_type = envelope_type
        self._show_envelope = envelope_type is not None
        self._update_visualization()

    def set_show_perforation(self, show: bool) -> None:
        """Устанавливает видимость линий перфорации.

        Args:
            show: True для показа линий перфорации.
        """
        self._show_perforation = show
        self._update_visualization()

    def set_show_borders(self, show: bool) -> None:
        """Устанавливает видимость границ листа.

        Args:
            show: True для показа границ.
        """
        self._show_borders = show
        self._update_visualization()

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Canvas для визуализации.

        Args:
            parent: Родительский виджет.

        Returns:
            Canvas виджет.
        """
        self._canvas = tk.Canvas(
            parent,
            bg="white",
            highlightthickness=0,
            borderwidth=0,
        )
        return self._canvas

    def _update_visualization(self) -> None:
        """Обновляет визуализацию на canvas."""
        if self._canvas is None or not self._is_mounted:
            return

        self._canvas.delete("all")

        if self._show_perforation:
            self._draw_perforation_lines()

        if self._show_borders:
            self._draw_paper_border()

        if self._show_envelope and self._envelope_type is not None:
            self._draw_envelope_overlay()

        if self._show_gutter:
            self._draw_gutter_indicators()

    def _draw_perforation_lines(self) -> None:
        """Отрисовывает пунктирные линии перфорации."""
        if self._canvas is None:
            return

        offset_px = int(10 * MM_TO_PX)

        self._canvas.create_line(
            offset_px,
            0,
            offset_px,
            self._paper_height_px,
            fill=PERFORATION_COLOR,
            dash=PERFORATION_DASH,
            tags="perforation_left",
        )

        self._canvas.create_line(
            self._paper_width_px - offset_px,
            0,
            self._paper_width_px - offset_px,
            self._paper_height_px,
            fill=PERFORATION_COLOR,
            dash=PERFORATION_DASH,
            tags="perforation_right",
        )

        self._canvas.create_line(
            0,
            offset_px,
            self._paper_width_px,
            offset_px,
            fill=PERFORATION_COLOR,
            dash=PERFORATION_DASH,
            tags="perforation_top",
        )

        self._canvas.create_line(
            0,
            self._paper_height_px - offset_px,
            self._paper_width_px,
            self._paper_height_px - offset_px,
            fill=PERFORATION_COLOR,
            dash=PERFORATION_DASH,
            tags="perforation_bottom",
        )

    def _draw_paper_border(self) -> None:
        """Отрисовывает границы листа."""
        if self._canvas is None:
            return

        self._canvas.create_rectangle(
            0,
            0,
            self._paper_width_px,
            self._paper_height_px,
            outline=PAPER_BORDER_COLOR,
            width=PAPER_BORDER_WIDTH,
            tags="paper_border",
        )

    def _draw_envelope_overlay(self) -> None:
        """Отрисовывает полупрозрачный оверлей конверта."""
        if self._canvas is None or self._envelope_type is None:
            return

        envelope_sizes: dict[str, tuple[int, int]] = {
            "DL": (114, 229),
            "C5": (162, 229),
            "C4": (229, 324),
        }

        dims = envelope_sizes.get(self._envelope_type, (114, 229))
        env_width, env_height = dims
        env_width_px = int(env_width * MM_TO_PX)
        env_height_px = int(env_height * MM_TO_PX)

        x_offset = (self._paper_width_px - env_width_px) // 2
        y_offset = (self._paper_height_px - env_height_px) // 2

        self._canvas.create_rectangle(
            x_offset,
            y_offset,
            x_offset + env_width_px,
            y_offset + env_height_px,
            fill=ENVELOPE_COLOR,
            outline=ENVELOPE_BORDER_COLOR,
            width=ENVELOPE_BORDER_WIDTH,
            stipple="gray25",
            tags="envelope_overlay",
        )

    def _draw_gutter_indicators(self) -> None:
        """Отрисовывает индикаторы double-height строк в gutter."""
        if self._canvas is None:
            return

        for i, props in enumerate(self._line_properties):
            if props.is_double_height:
                y_top = i * self._char_height_px
                y_bottom = y_top + self._char_height_px * 2

                self._canvas.create_rectangle(
                    0,
                    y_top,
                    GUTTER_WIDTH_PX,
                    y_bottom,
                    fill=DOUBLE_HEIGHT_COLOR,
                    outline="",
                    tags=f"gutter_indicator_{i}",
                )

    def update(self) -> None:
        """Принудительное обновление визуализации."""
        self._update_visualization()

    def _setup_bindings(self) -> None:
        """Настраивает event bindings."""
        pass

    def _cleanup(self) -> None:
        """Очищает ресурсы."""
        self._canvas = None
        self._line_properties = []
        self._envelope_type = None


# =============================================================================
# CODEPAGE STATUS WIDGET
# =============================================================================


class CodepageStatusWidget(BaseWidget):
    """Виджет статуса валидации Codepage.

    Отображает количество невалидных символов в тексте
    с цветовой индикацией:
    - Green: все символы валидны
    - Yellow: есть символы с заменой
    - Red: есть невалидные символы без замены

    Attributes:
        widget_id: Уникальный идентификатор.
        on_validate: Callback с текстом для валидации.

    Example:
        >>> status = CodepageStatusWidget(widget_id="cp_status")
        >>> status.mount(parent_frame)
        >>> status.validate_text("Hello world")
        >>> # Показывает: ✓ 0
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        on_validate: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Инициализация виджета статуса Codepage.

        Args:
            widget_id: Уникальный идентификатор.
            controller: Опциональная ссылка на контроллер.
            on_validate: Callback для передачи текста на валидацию.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._on_validate = on_validate

        self._frame: Optional[tk.Frame] = None
        self._icon_label: Optional[tk.Label] = None
        self._count_label: Optional[tk.Label] = None

        self._valid_count: int = 0
        self._invalid_count: int = 0
        self._status: str = "ok"

    def validate_text(self, text: str) -> None:
        """Валидирует текст и обновляет статус.

        Args:
            text: Текст для валидации.
        """
        from src.gui.components.codepage_validator import CodepageValidator

        validator = CodepageValidator()
        results = validator.validate(text)

        self._invalid_count = len(results)
        self._valid_count = len(text) - self._invalid_count

        if self._invalid_count == 0:
            self._status = "ok"
            self._update_display("ok")
        elif all(r.replacement is not None for r in results):
            self._status = "warning"
            self._update_display("warning")
        else:
            self._status = "error"
            self._update_display("error")

    def get_status(self) -> str:
        """Возвращает текущий статус.

        Returns:
            Статус: "ok", "warning" или "error".
        """
        return self._status

    def get_counts(self) -> tuple[int, int]:
        """Возвращает количество символов.

        Returns:
            Кортеж (valid_count, invalid_count).
        """
        return (self._valid_count, self._invalid_count)

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Frame со статус-индикатором.

        Args:
            parent: Родительский виджет.

        Returns:
            Frame виджет.
        """
        self._frame = tk.Frame(parent, bg="#f0f0f0", height=24)

        self._icon_label = tk.Label(
            self._frame,
            text="✓",
            font=("Arial", 12, "bold"),
            bg="#f0f0f0",
            fg="green",
            width=3,
        )
        self._icon_label.pack(side=tk.LEFT, padx=(4, 0), pady=2)

        self._count_label = tk.Label(
            self._frame,
            text="PC866: OK",
            font=("Arial", 9),
            bg="#f0f0f0",
            fg="#333333",
        )
        self._count_label.pack(side=tk.LEFT, padx=(0, 4), pady=2)

        return self._frame

    def _update_display(self, status: str) -> None:
        """Обновляет отображение статуса.

        Args:
            status: Статус для отображения.
        """
        if self._icon_label is None or self._count_label is None:
            return

        if status == "ok":
            self._icon_label.config(text="✓", fg="green")
            self._count_label.config(
                text=f"PC866: OK ({self._valid_count})",
                fg="#333333",
            )
            self._frame.config(bg="#f0f0f0") if self._frame else None
            self._icon_label.config(bg="#f0f0f0")
            self._count_label.config(bg="#f0f0f0")
        elif status == "warning":
            self._icon_label.config(text="⚠", fg="#B8860B")
            self._count_label.config(
                text=f"PC866: {self._invalid_count} замен",
                fg="#B8860B",
            )
            if self._frame:
                self._frame.config(bg="#FFFACD")
                self._icon_label.config(bg="#FFFACD")
                self._count_label.config(bg="#FFFACD")
        else:
            self._icon_label.config(text="✗", fg="red")
            self._count_label.config(
                text=f"PC866: {self._invalid_count} ошибок",
                fg="red",
            )
            if self._frame:
                self._frame.config(bg="#FFE4E1")
                self._icon_label.config(bg="#FFE4E1")
                self._count_label.config(bg="#FFE4E1")

    def _setup_bindings(self) -> None:
        """Настраивает event bindings."""
        pass

    def _cleanup(self) -> None:
        """Очищает ресурсы."""
        self._frame = None
        self._icon_label = None
        self._count_label = None
        self._on_validate = None


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "LineProperties",
    "PaperVisualizationWidget",
    "CodepageStatusWidget",
    "PERFORATION_COLOR",
    "PAPER_BORDER_COLOR",
    "ENVELOPE_COLOR",
    "DOUBLE_HEIGHT_COLOR",
    "VALID_STATUS_COLOR",
    "WARN_STATUS_COLOR",
    "ERROR_STATUS_COLOR",
    "GUTTER_WIDTH_PX",
]
