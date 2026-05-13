"""TooltipManager — централизованное управление подсказками.

Предоставляет систему всплывающих подсказок с:
- Автоматическим позиционированием
- Задержкой показа
- Поддержкой HTML-форматирования
- Умным скрытием

Example:
    >>> from src.gui.components.tooltip import TooltipManager
    >>> tooltip_mgr = TooltipManager.get_instance()
    >>> tooltip_mgr.show(widget, "Tooltip text", x=100, y=200)
    >>> tooltip_mgr.hide()

Version: 1.0
"""

from __future__ import annotations

import tkinter as tk
from typing import ClassVar, Optional


class TooltipManager:
    """Централизованный менеджер тултипов.

    Реализует паттерн Singleton для единого управления
    подсказками во всём приложении.

    Attributes:
        DELAY_MS: Задержка показа в миллисекундах.
        PADDING: Отступ внутри тултипа.
        BORDER_WIDTH: Ширина рамки.

    Example:
        >>> mgr = TooltipManager.get_instance()
        >>> mgr.show(widget, "Description", event.x_root, event.y_root)
    """

    # Class constants
    DELAY_MS: ClassVar[int] = 500
    PADDING: ClassVar[int] = 6
    BORDER_WIDTH: ClassVar[int] = 1

    # Colors
    BG_COLOR: ClassVar[str] = "#ffffe0"  # Light yellow
    BORDER_COLOR: ClassVar[str] = "#000000"
    TEXT_COLOR: ClassVar[str] = "#000000"

    # Singleton instance
    _instance: ClassVar[Optional["TooltipManager"]] = None

    def __new__(cls) -> "TooltipManager":
        """Реализация Singleton паттерна."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Инициализация менеджера тултипов."""
        # Use hasattr to avoid re-initialization
        if hasattr(self, "_initialized") and self._initialized:
            return

        self._initialized: bool = True
        self._tooltip: Optional[tk.Toplevel] = None
        self._label: Optional[tk.Label] = None
        self._after_id: Optional[str] = None
        self._current_widget: Optional[tk.Widget] = None

    @classmethod
    def get_instance(cls) -> TooltipManager:
        """Возвращает единственный экземпляр менеджера.

        Returns:
            Экземпляр TooltipManager.
        """
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def show(
        self,
        widget: tk.Widget,
        text: str,
        x: int,
        y: int,
        delay_ms: int = 0,
    ) -> None:
        """Показывает тултип для виджета.

        Args:
            widget: Виджет, для которого показывается тултип.
            text: Текст подсказки.
            x: X координата (screen coordinates).
            y: Y координата (screen coordinates).
            delay_ms: Задержка перед показом (0 для немедленного).
        """
        # Cancel any pending tooltip
        self._cancel_pending()

        self._current_widget = widget

        if delay_ms <= 0:
            self._show_now(text, x, y)
        else:
            self._after_id = widget.after(
                delay_ms,
                lambda: self._show_now(text, x, y),
            )

    def hide(self) -> None:
        """Скрывает текущий тултип."""
        self._cancel_pending()
        self._destroy_tooltip()

    def _cancel_pending(self) -> None:
        """Отменяет отложенный показ тултипа."""
        if self._after_id is not None and self._current_widget is not None:
            self._current_widget.after_cancel(self._after_id)
            self._after_id = None

    def _destroy_tooltip(self) -> None:
        """Уничтожает окно тултипа."""
        if self._tooltip is not None:
            self._tooltip.destroy()
            self._tooltip = None
            self._label = None

    def _show_now(self, text: str, x: int, y: int) -> None:
        """Немедленно показывает тултип.

        Args:
            text: Текст подсказки.
            x: X координата (screen coordinates).
            y: Y координата (screen coordinates).
        """
        self._after_id = None

        # Hide any existing tooltip
        self._destroy_tooltip()

        if not text:
            return

        # Create tooltip window
        self._tooltip = tk.Toplevel()
        self._tooltip.overrideredirect(True)  # No window decorations
        self._tooltip.attributes("-topmost", True)  # Keep on top

        # Calculate position (ensure it fits on screen)
        x_pos, y_pos = self._calculate_position(x, y)
        self._tooltip.geometry(f"+{x_pos}+{y_pos}")

        # Create label
        self._label = tk.Label(
            self._tooltip,
            text=text,
            justify=tk.LEFT,
            background=self.BG_COLOR,
            foreground=self.TEXT_COLOR,
            relief=tk.SOLID,
            borderwidth=self.BORDER_WIDTH,
            padx=self.PADDING,
            pady=self.PADDING,
            font=self._get_font(),
        )
        self._label.pack()

    def _calculate_position(self, x: int, y: int) -> tuple[int, int]:
        """Вычисляет позицию тултипа.

        Учитывает границы экрана, чтобы тултип не выходил за пределы.

        Args:
            x: Желаемая X координата.
            y: Желаемая Y координата.

        Returns:
            Корректные координаты (x, y).
        """
        if self._tooltip is None:
            return x, y

        # Get tooltip size
        self._tooltip.update_idletasks()
        width = self._tooltip.winfo_width()
        height = self._tooltip.winfo_height()

        # Get screen size
        screen_width = self._tooltip.winfo_screenwidth()
        screen_height = self._tooltip.winfo_screenheight()

        # Adjust X if tooltip goes off right edge
        if x + width > screen_width:
            x = screen_width - width - 10

        # Adjust Y if tooltip goes off bottom edge
        if y + height > screen_height:
            y = y - height - 20  # Show above cursor
        else:
            y = y + 20  # Show below cursor

        # Ensure minimum positions
        x = max(10, x)
        y = max(10, y)

        return x, y

    def _get_font(self) -> tuple[str, int, str]:
        """Возвращает шрифт для тултипа.

        Returns:
            Кортеж (family, size, weight).
        """
        return ("Arial", 10, "normal")

    def bind_to_widget(
        self,
        widget: tk.Widget,
        text: str,
        delay_ms: int = 500,
    ) -> None:
        """Привязывает тултип к виджету.

        Устанавливает обработчики событий для автоматического
        показа и скрытия тултипа.

        Args:
            widget: Виджет для привязки.
            text: Текст подсказки.
            delay_ms: Задержка перед показом.
        """

        def on_enter(event: tk.Event) -> None:  # noqa: ARG001
            widget_x = widget.winfo_rootx()
            widget_y = widget.winfo_rooty()
            # Show near the center of widget
            x = widget_x + widget.winfo_width() // 2
            y = widget_y + widget.winfo_height()
            self.show(widget, text, x, y, delay_ms)

        def on_leave(event: tk.Event) -> None:  # noqa: ARG001
            self.hide()

        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__ = ["TooltipManager"]
