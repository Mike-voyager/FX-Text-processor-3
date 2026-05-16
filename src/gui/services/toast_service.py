"""Toast Notification Service для FX Text Processor 3.

Реализует уведомления в стиле toast с поддержкой нескольких уровней важности,
автоматическим закрытием и ограничением очереди для предотвращения перегрузки UI.

Security:
    - Валидация длины сообщения (MAX_MESSAGE_LENGTH) для предотвращения DoS.
    - Нет eval/exec для динамического контента.
    - Строгая типизация всех параметров.
"""

from __future__ import annotations

import time
import tkinter as tk
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Final

from src.gui.layout.layout_constants import (
    PADDING_NORMAL,
    PADDING_SMALL,
)
from src.gui.views import ToastLevel, ToastMessage

# Security constraints
MAX_MESSAGE_LENGTH: Final[int] = 500
MAX_QUEUE_SIZE: Final[int] = 6
AUTO_CLOSE_MS: Final[int] = 30000

# Toast window geometry
TOAST_WIDTH: Final[int] = 300
TOAST_HEIGHT: Final[int] = 50
TOAST_SPACING: Final[int] = 60
TOAST_OFFSET_X: Final[int] = 310
TOAST_OFFSET_Y: Final[int] = 100


class ToastColor(Enum):
    """Colorа для разных уровней toast уведомлений."""

    INFO_BG = "#1a73e8"  # Синий
    INFO_FG = "#ffffff"
    SUCCESS_BG = "#34a853"  # Зелёный
    SUCCESS_FG = "#ffffff"
    WARNING_BG = "#f9ab00"  # Жёлтый
    WARNING_FG = "#000000"
    ERROR_BG = "#ea4335"  # Красный
    ERROR_FG = "#ffffff"
    PROGRESS_BG = "#3b82f6"  # Синий для прогресса
    PROGRESS_FG = "#ffffff"


@dataclass
class ToastConfig:
    """Конфигурация внешнего вида toast окна."""

    bg_color: str
    fg_color: str
    icon_text: str
    auto_close_ms: int = 30000


class ToastWindow:
    """Окно отдельного toast уведомления.

    Создаётся как отдельное Toplevel окно без рамки, позиционируется
    в правом нижнем углу экрана с учётом индекса в очереди.
    """

    _COLOR_MAP: Final[dict[ToastLevel, ToastConfig]] = {
        ToastLevel.INFO: ToastConfig(
            bg_color=ToastColor.INFO_BG.value,
            fg_color=ToastColor.INFO_FG.value,
            icon_text="ⓘ",
            auto_close_ms=30000,
        ),
        ToastLevel.SUCCESS: ToastConfig(
            bg_color=ToastColor.SUCCESS_BG.value,
            fg_color=ToastColor.SUCCESS_FG.value,
            icon_text="✓",
            auto_close_ms=30000,
        ),
        ToastLevel.WARNING: ToastConfig(
            bg_color=ToastColor.WARNING_BG.value,
            fg_color=ToastColor.WARNING_FG.value,
            icon_text="⚠",
            auto_close_ms=30000,
        ),
        ToastLevel.ERROR: ToastConfig(
            bg_color=ToastColor.ERROR_BG.value,
            fg_color=ToastColor.ERROR_FG.value,
            icon_text="✕",
            auto_close_ms=30000,
        ),
        ToastLevel.PROGRESS: ToastConfig(
            bg_color=ToastColor.PROGRESS_BG.value,
            fg_color=ToastColor.PROGRESS_FG.value,
            icon_text="⟳",
            auto_close_ms=60000,
        ),
    }

    def __init__(
        self,
        parent: tk.Tk,
        toast_id: str,
        message: str,
        level: ToastLevel,
        position_index: int,
        on_close: Callable[[str], None],
        auto_close: bool = True,
    ) -> None:
        """Инициализирует окно toast уведомления.

        Args:
            parent: Родительское окно (главное окно приложения).
            toast_id: Уникальный идентификатор уведомления.
            message: Текст сообщения.
            level: Уровень важности (INFO, SUCCESS, WARNING, ERROR).
            position_index: Индекс для расчёта вертикальной позиции.
            on_close: Callback при закрытии окна.
            auto_close: Автоматически закрыть через AUTO_CLOSE_MS.
        """
        self._toast_id = toast_id
        self._on_close = on_close
        self._level = level
        self._auto_close = auto_close
        self._after_id: str | None = None
        self._is_closing = False

        # Создаём Toplevel окно
        self._window = tk.Toplevel(parent)
        self._window.overrideredirect(True)  # Убираем рамку и заголовок
        self._window.attributes("-topmost", True)  # Всегда поверх других окон

        # Получаем цвета для уровня
        config = self._COLOR_MAP[level]

        # Устанавливаем размер и позицию
        self._window.geometry(f"{TOAST_WIDTH}x{TOAST_HEIGHT}")
        self._position_window(parent, position_index)

        # Создаём UI
        self._create_ui(config, message)

        # Отменяем after при уничтожении окна, чтобы избежать
        # TclError "invalid command name" на уже удалённом виджете
        self._window.bind("<Destroy>", lambda _e: self._on_destroyed(), add=True)

        # Запускаем таймер авто-закрытия
        if auto_close:
            self._after_id = self._window.after(config.auto_close_ms, self._close)

    def _position_window(self, parent: tk.Tk, index: int) -> None:
        """Позиционирует окно в правом нижнем углу экрана.

        Args:
            parent: Главное окно для определения размера экрана.
            index: Индекс уведомления для расчёта вертикальной позиции.
        """
        parent.update_idletasks()
        screen_width = parent.winfo_screenwidth()
        screen_height = parent.winfo_screenheight()

        x = screen_width - TOAST_OFFSET_X
        y = screen_height - TOAST_OFFSET_Y - (index * TOAST_SPACING)

        self._window.geometry(f"+{x}+{y}")

    def _create_ui(self, config: ToastConfig, message: str) -> None:
        """Создаёт UI компоненты toast окна.

        Args:
            config: Конфигурация цветов и иконки.
            message: Текст сообщения для отображения.
        """
        # Фрейм с фоном
        frame = tk.Frame(
            self._window,
            bg=config.bg_color,
            padx=PADDING_NORMAL,
            pady=PADDING_SMALL,
        )
        frame.pack(fill=tk.BOTH, expand=True)

        # Иконка (левая сторона)
        icon_label = tk.Label(
            frame,
            text=config.icon_text,
            font=("Arial", 14, "bold"),
            bg=config.bg_color,
            fg=config.fg_color,
        )
        icon_label.pack(side=tk.LEFT, padx=(0, PADDING_NORMAL))

        # Текст сообщения (центр)
        message_label = tk.Label(
            frame,
            text=message,
            font=("Arial", 10),
            bg=config.bg_color,
            fg=config.fg_color,
            wraplength=TOAST_WIDTH - 60,
            justify=tk.LEFT,
        )
        message_label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Кнопка закрытия (правая сторона)
        close_label = tk.Label(
            frame,
            text="×",
            font=("Arial", 16, "bold"),
            bg=config.bg_color,
            fg=config.fg_color,
            cursor="hand2",
            padx=PADDING_SMALL,
        )
        close_label.pack(side=tk.RIGHT)
        close_label.bind("<Button-1>", lambda _: self._close())

        # Закрытие по клику на сообщение
        message_label.bind("<Button-1>", lambda _: self._close())
        icon_label.bind("<Button-1>", lambda _: self._close())
        frame.bind("<Button-1>", lambda _: self._close())

    def _on_destroyed(self) -> None:
        """Обработчик уничтожения окна — отменяет pending after и notify сервис."""
        if self._is_closing:
            return
        self._is_closing = True
        if self._after_id is not None:
            try:
                self._window.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None
        self._on_close(self._toast_id)

    def _close(self) -> None:
        """Закрывает окно и вызывает callback."""
        if self._is_closing:
            return
        self._is_closing = True
        if self._after_id is not None:
            try:
                self._window.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None

        try:
            self._window.destroy()
        except tk.TclError:
            pass
        self._on_close(self._toast_id)

    def close(self) -> None:
        """Публичный метод для закрытия окна."""
        if self._is_closing:
            return
        try:
            self._close()
        except tk.TclError:
            pass

    def pin(self) -> None:
        """Отменяет авто-закрытие окна (Pin)."""
        if self._is_closing:
            return
        if self._after_id is not None:
            self._window.after_cancel(self._after_id)
            self._after_id = None
        self._auto_close = False

    def update_position(self, parent: tk.Tk, new_index: int) -> None:
        """Обновляет позицию окна при изменении индекса.

        Args:
            parent: Главное окно для определения размера экрана.
            new_index: Новый индекс в очереди.
        """
        self._position_window(parent, new_index)


class ToastService:
    """Сервис для управления toast уведомлениями.

    Реализует ToastServiceProtocol. Отвечает ТОЛЬКО за визуальные popup:
    очередь, позиционирование, auto-close. История и badge управляются
    NotificationService (data layer).

    Security:
        - Проверка длины сообщения (MAX_MESSAGE_LENGTH).
        - Ограничение размера очереди (MAX_QUEUE_SIZE) для защиты от DoS.
    """

    def __init__(self, root: tk.Tk) -> None:
        """Инициализирует сервис уведомлений.

        Args:
            root: Главное окно приложения для позиционирования.
        """
        self._root = root
        self._toasts: dict[str, ToastWindow] = {}
        self._created_at: dict[str, float] = {}
        self._messages: dict[str, ToastMessage] = {}

    def _validate_message(self, message: str) -> None:
        """Валидирует длину сообщения.

        Args:
            message: Сообщение для проверки.

        Raises:
            ValueError: Если длина сообщения превышает MAX_MESSAGE_LENGTH.
        """
        if len(message) > MAX_MESSAGE_LENGTH:
            raise ValueError(
                f"Message exceeds maximum length ({MAX_MESSAGE_LENGTH} chars): {len(message)}"
            )

    def _cleanup_old_toasts(self) -> None:
        """Удаляет старые уведомления при превышении размера очереди."""
        while len(self._toasts) >= MAX_QUEUE_SIZE:
            oldest_id = min(
                self._created_at.keys(),
                key=lambda tid: self._created_at[tid],
            )
            self.close_toast(oldest_id)

    def _on_toast_closed(self, toast_id: str) -> None:
        """Callback при закрытии окна уведомления.

        Args:
            toast_id: Идентификатор закрытого уведомления.
        """
        self._toasts.pop(toast_id, None)
        self._created_at.pop(toast_id, None)
        self._messages.pop(toast_id, None)
        self._reposition_toasts()

    def _reposition_toasts(self) -> None:
        """Пересчитывает позиции всех открытых уведомлений."""
        sorted_ids = sorted(
            self._created_at.keys(),
            key=lambda tid: self._created_at[tid],
        )
        for index, toast_id in enumerate(sorted_ids):
            if toast_id in self._toasts:
                self._toasts[toast_id].update_position(self._root, index)

    def show(
        self,
        message: str,
        level: ToastLevel = ToastLevel.INFO,
        auto_close: bool = True,
    ) -> str:
        """Показывает toast уведомление.

        Args:
            message: Текст сообщения (макс. MAX_MESSAGE_LENGTH символов).
            level: Уровень важности (INFO, SUCCESS, WARNING, ERROR).
            auto_close: Автоматически закрыть через AUTO_CLOSE_MS.

        Returns:
            Идентификатор созданного уведомления.

        Raises:
            ValueError: Если длина сообщения превышает MAX_MESSAGE_LENGTH.
        """
        self._validate_message(message)
        self._cleanup_old_toasts()

        try:
            if self._root is None or not self._root.winfo_exists():
                return ""
        except tk.TclError:
            return ""

        toast_id = str(uuid.uuid4())
        self._created_at[toast_id] = time.time()

        position_index = len(self._toasts)

        toast_window = ToastWindow(
            parent=self._root,
            toast_id=toast_id,
            message=message,
            level=level,
            position_index=position_index,
            on_close=self._on_toast_closed,
            auto_close=auto_close,
        )
        self._toasts[toast_id] = toast_window
        self._messages[toast_id] = ToastMessage(
            toast_id=toast_id,
            message=message,
            level=level,
            created_at=self._created_at[toast_id],
        )

        return toast_id

    def close_toast(self, toast_id: str) -> None:
        """Закрывает конкретное уведомление.

        Args:
            toast_id: Идентификатор уведомления для закрытия.
        """
        if toast_id in self._toasts:
            self._toasts[toast_id].close()

    def close_all(self) -> None:
        """Закрывает все уведомления."""
        for toast_id in list(self._toasts.keys()):
            try:
                self.close_toast(toast_id)
            except tk.TclError:
                pass
        self._toasts.clear()
        self._created_at.clear()
        self._messages.clear()

    def pin_all(self) -> None:
        """Отменяет авто-закрытие для всех видимых уведомлений."""
        for toast_window in self._toasts.values():
            toast_window.pin()
