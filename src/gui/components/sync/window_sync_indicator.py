"""Индикаторы синхронизации для вкладок и окон FX Text Processor 3.

Реализует три основных компонента:
- WindowSyncIndicator: виджет-индикатор статуса (BaseWidget) с анимацией и tooltip.
- TabSyncIndicator: обёртка для встраивания индикатора во вкладку CardFileTabBar.
- TitleBarSyncDecorator: утилитарный класс для обновления заголовка окна.

Статусы:
    synced   — зелёный ●
    syncing  — синий ⟳ (анимация)
    conflict — оранжевый ⚠
    offline  — серый ✗

Thread Safety:
    Все методы обновления UI thread-safe через ``widget.after()``.

Example:
    >>> indicator = WindowSyncIndicator(widget_id="sync_1")
    >>> indicator.mount(tab_frame)
    >>> indicator.set_status(SyncStatus.SYNCING)
    >>> indicator.start_animation()

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import re
import threading
import tkinter as tk
from enum import Enum
from typing import Any, Final, Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.services.sync_service import SyncMessage, SyncService

# =============================================================================
# CONSTANTS
# =============================================================================


class SyncStatus(str, Enum):
    """Статусы синхронизации."""

    SYNCED = "synced"
    SYNCING = "syncing"
    CONFLICT = "conflict"
    OFFLINE = "offline"


SYNC_STATUS_COLORS: Final[dict[str, str]] = {
    SyncStatus.SYNCED: "#4CAF50",
    SyncStatus.SYNCING: "#2196F3",
    SyncStatus.CONFLICT: "#FF9800",
    SyncStatus.OFFLINE: "#9E9E9E",
}

SYNC_STATUS_ICONS: Final[dict[str, str]] = {
    SyncStatus.SYNCED: "●",
    SyncStatus.SYNCING: "⟳",
    SyncStatus.CONFLICT: "⚠",
    SyncStatus.OFFLINE: "✗",
}

SYNC_STATUS_LABELS: Final[dict[str, str]] = {
    SyncStatus.SYNCED: "Synced",
    SyncStatus.SYNCING: "Syncing...",
    SyncStatus.CONFLICT: "Conflict",
    SyncStatus.OFFLINE: "Offline",
}

_ANIMATION_INTERVAL_MS: Final[int] = 200
"""Интервал анимации для статуса SYNCING (мс)."""

_ANIMATION_ICONS: Final[tuple[str, str]] = ("⟳", "⟲")
"""Иконки, чередующиеся при анимации."""

_TOOLTIP_BG: Final[str] = "#333333"
_TOOLTIP_FG: Final[str] = "#FFFFFF"
_TOOLTIP_FONT: Final[tuple[str, int]] = ("Helvetica", 9)

_DATA_SYNC_STATUS: Final[str] = "sync_status"
"""data_type для сообщений SyncService об изменении статуса."""


# Regex для удаления суффикса индикатора из заголовка окна
_TITLE_SUFFIX_RE: Final[re.Pattern[str]] = re.compile(r"\s*\[[●⟳⚠✗]\].*$")


# =============================================================================
# WINDOW SYNC INDICATOR
# =============================================================================


class WindowSyncIndicator(BaseWidget):
    """Визуальный индикатор статуса синхронизации.

    Отображает маленькую иконку с цветом, соответствующим статусу.
    Для ``SYNCING`` поддерживает анимацию через ``after()``.
    При наведении показывает tooltip с дополнительной информацией.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Опциональная ссылка на контроллер.

    Example:
        >>> ind = WindowSyncIndicator(widget_id="sync_doc_1")
        >>> ind.mount(parent_frame)
        >>> ind.set_status(SyncStatus.CONFLICT)
        >>> ind.set_tooltip("3 конфликта\nПоследняя синхронизация: 12:34")
    """

    def __init__(
        self,
        widget_id: str = "window_sync_indicator",
        controller: Optional[Any] = None,
        status: str = SyncStatus.OFFLINE,
    ) -> None:
        """Инициализирует индикатор.

        Args:
            widget_id: Уникальный идентификатор.
            controller: Опциональный контроллер.
            status: Начальный статус (по умолчанию OFFLINE).
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._status: str = status
        self._tooltip_text: str = ""
        self._after_id: Optional[str] = None
        self._animation_frame: int = 0
        self._tk_label: Optional[tk.Label] = None
        self._tk_tooltip: Optional[tk.Toplevel] = None
        self._pending_status: Optional[str] = None

    @property
    def status(self) -> str:
        """Текущий статус индикатора."""
        return self._status

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter Label для отображения иконки."""
        color = SYNC_STATUS_COLORS.get(self._status, SYNC_STATUS_COLORS[SyncStatus.OFFLINE])
        icon = SYNC_STATUS_ICONS.get(self._status, SYNC_STATUS_ICONS[SyncStatus.OFFLINE])
        bg_color = ""
        if hasattr(parent, "cget"):
            try:
                bg_color = parent.cget("bg")
            except tk.TclError:
                bg_color = ""
        self._tk_label = tk.Label(
            parent,
            text=icon,
            fg=color,
            bg=bg_color,
            font=("Segoe UI Emoji", 9),
            padx=2,
        )
        # Применяем отложенный статус, если он был установлен до mount
        if self._pending_status is not None:
            self._apply_status(self._pending_status)
            self._pending_status = None
        return self._tk_label

    def _setup_bindings(self) -> None:
        """Настраивает tooltip bindings."""
        if self._tk_label is not None:
            self._tk_label.bind("<Enter>", self._on_enter)
            self._tk_label.bind("<Leave>", self._on_leave)
            self._tk_label.bind("<Destroy>", lambda _e: self.stop_animation(), add=True)

    def _cleanup(self) -> None:
        """Останавливает анимацию и уничтожает tooltip."""
        self.stop_animation()
        self._destroy_tooltip()
        self._tk_label = None

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def set_status(self, status: str) -> None:
        """Устанавливает статус синхронизации (thread-safe).

        Если метод вызывается не из главного потока, обновление
        откладывается через ``widget.after(0, ...)``.

        Args:
            status: Новый статус (значение из :class:`SyncStatus`).

        Raises:
            ValueError: Если передан неизвестный статус.
        """
        if status not in SYNC_STATUS_COLORS:
            raise ValueError(f"Unknown sync status: '{status}'")

        if threading.current_thread() is not threading.main_thread():
            # Thread-safe defer через after
            try:
                if self._tk_label is not None and self._tk_label.winfo_exists():

                    def _apply_pending(s: str = status) -> None:
                        self._set_status(s)

                    self._tk_label.after(0, _apply_pending)
                    return
            except RuntimeError:
                # Tcl недоступен из стороннего потока
                pass
            self._pending_status = status
            return

        self._set_status(status)
        if not self.is_mounted():
            self._pending_status = status

    def set_tooltip(self, text: str) -> None:
        """Устанавливает текст tooltip.

        Args:
            text: Текст подсказки (может быть многострочным).
        """
        self._tooltip_text = text

    def start_animation(self) -> None:
        """Запускает анимацию для статуса SYNCING.

        Безопасно вызывать многократно — старая анимация отменяется.
        """
        self.stop_animation()
        if self._status != SyncStatus.SYNCING:
            return
        self._animation_frame = 0
        self._animation_step()

    def stop_animation(self) -> None:
        """Останавливает анимацию и сбрасывает иконку."""
        if self._after_id is not None and self._tk_label is not None:
            try:
                self._tk_label.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None
        self._animation_frame = 0
        if self._tk_label is not None and self._tk_label.winfo_exists():
            self._tk_label.config(
                text=SYNC_STATUS_ICONS.get(self._status, SYNC_STATUS_ICONS[SyncStatus.OFFLINE])
            )

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _set_status(self, status: str) -> None:
        """Внутренний синхронный setter статуса (должен вызываться из main thread)."""
        self._status = status
        self._apply_status(status)
        if status == SyncStatus.SYNCING:
            self.start_animation()
        else:
            self.stop_animation()

    def _apply_status(self, status: str) -> None:
        """Применяет визуальное отображение статуса."""
        color = SYNC_STATUS_COLORS.get(status, SYNC_STATUS_COLORS[SyncStatus.OFFLINE])
        icon = SYNC_STATUS_ICONS.get(status, SYNC_STATUS_ICONS[SyncStatus.OFFLINE])
        if self._tk_label is not None and self._tk_label.winfo_exists():
            self._tk_label.config(text=icon, fg=color)

    def _animation_step(self) -> None:
        """Один шаг анимации (чередование иконок)."""
        if not self._is_mounted or self._status != SyncStatus.SYNCING:
            return
        if self._tk_label is None or not self._tk_label.winfo_exists():
            return
        icon = _ANIMATION_ICONS[self._animation_frame % len(_ANIMATION_ICONS)]
        self._tk_label.config(text=icon)
        self._animation_frame += 1
        self._after_id = str(self._tk_label.after(_ANIMATION_INTERVAL_MS, self._animation_step))

    def _on_enter(self, event: Optional[tk.Event] = None) -> None:
        """Показывает tooltip при наведении."""
        if not self._tooltip_text or self._tk_label is None:
            return
        self._destroy_tooltip()
        x = self._tk_label.winfo_rootx()
        y = self._tk_label.winfo_rooty() - 24
        self._tk_tooltip = tk.Toplevel(self._tk_label)
        self._tk_tooltip.wm_overrideredirect(True)
        self._tk_tooltip.wm_geometry(f"+{x}+{y}")
        self._tk_tooltip.attributes("-topmost", True)
        label = tk.Label(
            self._tk_tooltip,
            text=self._tooltip_text,
            bg=_TOOLTIP_BG,
            fg=_TOOLTIP_FG,
            font=_TOOLTIP_FONT,
            relief="solid",
            bd=1,
            padx=6,
            pady=3,
        )
        label.pack()

    def _on_leave(self, event: Optional[tk.Event] = None) -> None:
        """Скрывает tooltip при уходе курсора."""
        self._destroy_tooltip()

    def _destroy_tooltip(self) -> None:
        """Уничтожает окно tooltip."""
        if self._tk_tooltip is not None:
            try:
                self._tk_tooltip.destroy()
            except tk.TclError:
                pass
            self._tk_tooltip = None


# =============================================================================
# TAB SYNC INDICATOR
# =============================================================================


class TabSyncIndicator:
    """Индикатор синхронизации, встраиваемый во вкладку CardFileTabBar.

    Размещается справа от заголовка вкладки (перед кнопкой закрытия).
    Опционально подписывается на :class:`SyncService` для автоматического
    обновления статуса.

    Attributes:
        document_id: Идентификатор документа, связанного с вкладкой.
        indicator: Экземпляр :class:`WindowSyncIndicator`.

    Example:
        >>> tsi = TabSyncIndicator(tab_frame, document_id="doc_1")
        >>> tsi.mount(before_widget=close_btn)
        >>> tsi.set_status(SyncStatus.SYNCED)
    """

    def __init__(
        self,
        tab_frame: tk.Frame,
        document_id: str,
        sync_service: Optional[SyncService] = None,
        status: str = SyncStatus.OFFLINE,
    ) -> None:
        """Инициализация TabSyncIndicator.

        Args:
            tab_frame: Frame вкладки из CardFileTabBar.
            document_id: Идентификатор документа.
            sync_service: Опциональный SyncService для подписки.
            status: Начальный статус.
        """
        self._document_id: str = document_id
        self._tab_frame: tk.Frame = tab_frame
        self._sync_service: Optional[SyncService] = sync_service
        self._handler_id: Optional[str] = None
        self._indicator: WindowSyncIndicator = WindowSyncIndicator(
            widget_id=f"tab_sync_indicator_{document_id}",
            status=status,
        )

    @property
    def document_id(self) -> str:
        """ID документа."""
        return self._document_id

    @property
    def indicator(self) -> WindowSyncIndicator:
        """Внутренний :class:`WindowSyncIndicator`."""
        return self._indicator

    def mount(
        self,
        before_widget: Optional[tk.Widget] = None,
        side: str = "right",
        padx: int = 2,
    ) -> tk.Widget:
        """Монтирует индикатор во вкладку и регистрирует SyncService handler.

        Args:
            before_widget: Виджет, перед которым нужно разместить индикатор
                (например, кнопка закрытия).
            side: Сторона packing (по умолчанию 'right').
            padx: Горизонтальный отступ.

        Returns:
            Созданный Tkinter виджет индикатора.
        """
        widget = self._indicator.mount(self._tab_frame)
        pack_kwargs: dict[str, Any] = {"side": side, "padx": padx}
        if before_widget is not None:
            pack_kwargs["before"] = before_widget
        widget.pack(**pack_kwargs)

        # Подписка на SyncService
        if self._sync_service is not None:
            # Используем document_id как уникальный window_id в рамках сервиса
            self._handler_id = self._sync_service.register_handler(
                _DATA_SYNC_STATUS,
                f"tab_{self._document_id}",
                self._on_sync_message,
            )
        return widget

    def set_status(self, status: str) -> None:
        """Пробрасывает установку статуса во внутренний индикатор."""
        self._indicator.set_status(status)

    def set_tooltip(self, text: str) -> None:
        """Пробрасывает tooltip во внутренний индикатор."""
        self._indicator.set_tooltip(text)

    def unmount(self) -> None:
        """Демонтирует индикатор и отписывается от SyncService."""
        if self._sync_service is not None and self._handler_id is not None:
            try:
                self._sync_service.unregister_handler(self._handler_id)
            except KeyError:
                pass
            self._handler_id = None
        self._indicator.unmount()

    def _on_sync_message(self, message: SyncMessage) -> None:
        """Обработчик входящих сообщений SyncService.

        Args:
            message: Сообщение синхронизации.
        """
        data = message.data if isinstance(message.data, dict) else {}
        status = data.get("status", SyncStatus.OFFLINE)
        if status in SYNC_STATUS_COLORS:
            self.set_status(status)
            tooltip_parts: list[str] = []
            last_sync = data.get("last_sync_time")
            if last_sync is not None:
                tooltip_parts.append(f"Last sync: {last_sync}")
            conflicts = data.get("conflict_count")
            if conflicts is not None:
                tooltip_parts.append(f"Conflicts: {conflicts}")
            conn_status = data.get("connection_status")
            if conn_status is not None:
                tooltip_parts.append(f"Connection status: {conn_status}")
            if tooltip_parts:
                self.set_tooltip("\n".join(tooltip_parts))


# =============================================================================
# TITLE BAR SYNC DECORATOR
# =============================================================================


class TitleBarSyncDecorator:
    """Утилитарный класс для добавления/удаления суффикса статуса
    в заголовок окна Tkinter.

    Example:
        >>> TitleBarSyncDecorator.update_title(root, SyncStatus.SYNCING)
        >>> # title == "Document.fxsd - FX Text Processor 3 [⟳] Syncing..."
        >>> TitleBarSyncDecorator.clear_title(root)
        >>> # title == "Document.fxsd - FX Text Processor 3"
    """

    @staticmethod
    def update_title(
        window: tk.Tk | tk.Toplevel,
        status: str,
    ) -> None:
        """Добавляет суффикс статуса к заголовку окна.

        Args:
            window: Tk или Toplevel окно.
            status: Статус синхронизации.

        Raises:
            ValueError: При неизвестном статусе.
        """
        if status not in SYNC_STATUS_ICONS:
            raise ValueError(f"Unknown status: '{status}'")
        current = window.title()
        cleaned = _TITLE_SUFFIX_RE.sub("", current)
        icon = SYNC_STATUS_ICONS[status]
        label = SYNC_STATUS_LABELS.get(status, "")
        window.title(f"{cleaned} [{icon}] {label}")

    @staticmethod
    def clear_title(window: tk.Tk | tk.Toplevel) -> None:
        """Удаляет все суффиксы статуса из заголовка окна.

        Args:
            window: Tk или Toplevel окно.
        """
        current = window.title()
        cleaned = _TITLE_SUFFIX_RE.sub("", current)
        window.title(cleaned)

    @staticmethod
    def get_status_suffix(status: str) -> str:
        """Возвращает строковый суффикс для указанного статуса.

        Args:
            status: Статус синхронизации.

        Returns:
            Строка вида ``" [●] Synced"`` или пустая строка при неизвестном статусе.
        """
        icon = SYNC_STATUS_ICONS.get(status, "")
        label = SYNC_STATUS_LABELS.get(status, "")
        return f" [{icon}] {label}" if icon else ""


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "SyncStatus",
    "SYNC_STATUS_COLORS",
    "SYNC_STATUS_ICONS",
    "SYNC_STATUS_LABELS",
    "WindowSyncIndicator",
    "TabSyncIndicator",
    "TitleBarSyncDecorator",
]

__version__ = "1.0.0"
__author__ = "FX Text Processor Team"
__date__ = "May 2026"
