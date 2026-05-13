"""Protocol для GUI Views.

Определяет интерфейсы для всех View-компонентов.
"""

from __future__ import annotations

import importlib
import tkinter as tk
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Protocol, runtime_checkable


class SideBarMode(Enum):
    """Режимы отображения SideBar."""

    SECTIONS = auto()
    TREE = auto()


class DocumentMode(Enum):
    """Режимы документа."""

    FREE_FORM = auto()
    STRUCTURED_FORM = auto()


class ToastLevel(Enum):
    """Уровни важности toast уведомлений."""

    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    PROGRESS = "progress"


@runtime_checkable
class ViewProtocol(Protocol):
    """Базовый протокол для всех View-компонентов."""

    @property
    def widget(self) -> tk.Widget:
        """Возвращает tkinter widget для размещения."""
        ...

    def show(self) -> None:
        """Показывает компонент."""
        ...

    def hide(self) -> None:
        """Скрывает компонент."""
        ...

    def is_visible(self) -> bool:
        """Проверяет видимость компонента."""
        ...


@runtime_checkable
class SideBarViewProtocol(ViewProtocol, Protocol):
    """Протокол для SideBar."""

    def set_mode(self, mode: SideBarMode) -> None:
        """Устанавливает режим отображения."""
        ...

    def set_collapsed(self, collapsed: bool) -> None:
        """Устанавливает состояние свёрнутости."""
        ...

    def filter_items(self, query: str) -> None:
        """Фильтрует элементы по запросу."""
        ...


@runtime_checkable
class StatusBarViewProtocol(ViewProtocol, Protocol):
    """Протокол для StatusBar."""

    def set_cursor_position(self, line: int, column: int) -> None:
        """Устанавливает позицию курсора."""
        ...

    def set_modified(self, modified: bool) -> None:
        """Устанавливает индикатор изменений."""
        ...

    def set_security_preset(self, preset_name: str) -> None:
        """Устанавливает индикатор пресета безопасности."""
        ...

    def set_page_info(self, current: int, total: int) -> None:
        """Устанавливает информацию о странице."""
        ...


@runtime_checkable
class CardFileTabBarProtocol(ViewProtocol, Protocol):
    """Протокол для CardFileTabBar."""

    def add_tab(
        self,
        document_id: str,
        title: str,
        mode: DocumentMode,
        modified: bool = False,
    ) -> None:
        """Добавляет вкладку."""
        ...

    def close_tab(self, document_id: str) -> bool:
        """Закрывает вкладку. Возвращает True если успешно."""
        ...

    def set_active_tab(self, document_id: str) -> None:
        """Устанавливает активную вкладку."""
        ...

    def set_tab_modified(self, document_id: str, modified: bool) -> None:
        """Устанавливает индикатор изменений для вкладки."""
        ...


@runtime_checkable
class ToastServiceProtocol(Protocol):
    """Протокол для Toast Service."""

    def show(
        self,
        message: str,
        level: ToastLevel = ToastLevel.INFO,
        auto_close: bool = True,
    ) -> str:
        """Показывает toast уведомление. Возвращает toast_id."""
        ...

    def close_toast(self, toast_id: str) -> None:
        """Закрывает конкретное уведомление."""
        ...

    def close_all(self) -> None:
        """Закрывает все уведомления."""
        ...

    def pin_all(self) -> None:
        """Отменяет авто-закрытие для всех видимых уведомлений."""
        ...


@dataclass(frozen=True)
class ToastMessage:
    """Структура toast сообщения."""

    toast_id: str
    message: str
    level: ToastLevel
    created_at: float


@runtime_checkable
class DocumentViewProtocol(ViewProtocol, Protocol):
    """Протокол для DocumentView."""

    def show_placeholder(self, message: str = "No document open") -> None:
        """Показывает placeholder."""
        ...

    def set_document(self, document_id: str) -> None:
        """Устанавливает текущий документ."""
        ...

    def clear_document(self) -> None:
        """Очищает текущий документ."""
        ...


@runtime_checkable
class MainWindowProtocol(Protocol):
    """Протокол для MainWindow."""

    def initialize(self) -> None:
        """Инициализирует окно."""
        ...

    def run(self) -> None:
        """Запускает главный цикл."""
        ...

    def destroy(self) -> None:
        """Корректно закрывает окно."""
        ...

    def set_title(self, title: str) -> None:
        """Устанавливает заголовок окна."""
        ...

    def get_toast_service(self) -> ToastServiceProtocol:
        """Возвращает сервис уведомлений."""
        ...


# Concrete view classes (imported lazily via __getattr__ to avoid circular imports)
_VIEW_IMPORTS: dict[str, tuple[str, str]] = {
    "AuthOverlay": ("src.gui.views.auth_overlay", "AuthOverlay"),
    "CardFileTabBar": ("src.gui.views.card_file_tab_bar", "CardFileTabBar"),
    "DocumentView": ("src.gui.views.document_view", "DocumentView"),
    "MainWindow": ("src.gui.views.main_window", "MainWindow"),
    "SideBar": ("src.gui.views.side_bar", "SideBar"),
    "StatusBar": ("src.gui.views.status_bar", "StatusBar"),
}


def __getattr__(name: str) -> Any:
    """Lazily import concrete view classes to avoid circular imports."""
    if name in _VIEW_IMPORTS:
        module_path, class_name = _VIEW_IMPORTS[name]
        module = importlib.import_module(module_path)
        return getattr(module, class_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AuthOverlay",
    "CardFileTabBar",
    "CardFileTabBarProtocol",
    "DocumentMode",
    "DocumentView",
    "DocumentViewProtocol",
    "MainWindow",
    "MainWindowProtocol",
    "SideBar",
    "SideBarMode",
    "SideBarViewProtocol",
    "StatusBar",
    "StatusBarViewProtocol",
    "ToastLevel",
    "ToastMessage",
    "ToastServiceProtocol",
    "ViewProtocol",
]
