"""MainLayout — координатор основного layout приложения.

Управляет размещением основных компонентов GUI:
- SideBar (слева, collapsible)
- Content (основная область с document/tabs)
- StatusBar (внизу)

Использует PanedLayout для side|content разделения.

Example:
    >>> layout = MainLayout(
    ...     widget_id="main_layout",
    ...     controller=controller,
    ...     root=root_window,
    ... )
    >>> layout.mount(root_frame)
    >>> layout.set_sidebar(sidebar_widget)
    >>> layout.set_content(content_widget)
    >>> layout.set_statusbar(statusbar_widget)
    >>> layout.collapse_sidebar()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Final, Optional, Protocol, runtime_checkable

__author__ = "FX Text Processor Team"
__date__ = "April 2026"
__version__ = "1.0"

from src.gui.components.base.widget import BaseWidget
from src.gui.core.events import BaseEvent
from src.gui.core.exceptions import GUIError, LifecycleError
from src.gui.core.protocols import ControllerProtocol
from src.gui.layout.layout_constants import (
    PANEL_RATIO_DEFAULT,
    SIDEBAR_COLLAPSED_WIDTH,
    SIDEBAR_WIDTH,
    STATUSBAR_HEIGHT,
)
from src.gui.layout.paned_layout import PanedLayout

# =============================================================================
# PROTOCOLS
# =============================================================================


@runtime_checkable
class SidebarToggleCallback(Protocol):
    """Callback для переключения sidebar."""

    def __call__(self, visible: bool) -> None:
        """Вызывается при изменении видимости sidebar.

        Args:
            visible: True если sidebar видим (развёрнут).
        """
        ...


# =============================================================================
# MAIN LAYOUT
# =============================================================================


class MainLayout(BaseWidget):
    """Координатор основного layout приложения FX Text Processor 3.

    Структура layout:
    ```
    +---------------------------+
    | SideBar | Content         |
    |         |                 |
    |         |                 |
    |         |                 |
    +---------------------------+
    | StatusBar                 |
    +---------------------------+
    ```

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        sidebar_ratio: Текущее соотношение sidebar (0.0 - 1.0).
        sidebar_collapsed: Состояние свёрнутости sidebar.

    Example:
        >>> layout = MainLayout(widget_id="main_layout", root=root)
        >>> layout.mount(parent_frame)
        >>> layout.set_sidebar(sidebar_view.widget)
        >>> layout.set_content(document_view.widget)
        >>> layout.set_statusbar(statusbar_view.widget)
    """

    # Константы layout
    _DEFAULT_SIDEBAR_RATIO: Final[float] = PANEL_RATIO_DEFAULT
    _MIN_SIDEBAR_WIDTH: Final[int] = SIDEBAR_COLLAPSED_WIDTH
    _DEFAULT_SIDEBAR_WIDTH: Final[int] = SIDEBAR_WIDTH
    _STATUSBAR_HEIGHT: Final[int] = STATUSBAR_HEIGHT

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        root: Optional[tk.Tk] = None,
        sidebar_toggle_callback: Optional[SidebarToggleCallback] = None,
    ) -> None:
        """Инициализация MainLayout.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональный контроллер для callbacks.
            root: Корневое окно Tkinter (для получения размеров).
            sidebar_toggle_callback: Callback при переключении sidebar.
        """
        super().__init__(widget_id=widget_id, controller=controller)

        self._root: Optional[tk.Tk] = root
        self._sidebar_toggle_callback: Optional[SidebarToggleCallback] = sidebar_toggle_callback

        # Внутренние виджеты
        self._main_container: Optional[tk.Frame] = None
        self._content_frame: Optional[tk.Frame] = None
        self._statusbar_frame: Optional[tk.Frame] = None

        # PanedLayout для side|content
        self._paned_layout: Optional[PanedLayout] = None

        # Дочерние виджеты (устанавливаются через set_* методы)
        self._sidebar_widget: Optional[tk.Widget] = None
        self._content_widget: Optional[tk.Widget] = None
        self._statusbar_widget: Optional[tk.Widget] = None

        # Состояние
        self._sidebar_ratio: float = self._DEFAULT_SIDEBAR_RATIO
        self._sidebar_collapsed: bool = False

    @property
    def sidebar_ratio(self) -> float:
        """Текущее соотношение sidebar.

        Returns:
            Ratio от 0.0 до 1.0 (sidebar / общая ширина).
        """
        return self._sidebar_ratio

    @property
    def sidebar_collapsed(self) -> bool:
        """Состояние свёрнутости sidebar.

        Returns:
            True если sidebar свёрнут.
        """
        return self._sidebar_collapsed

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт основной контейнер layout.

        Args:
            parent: Родительский виджет.

        Returns:
            Созданный Frame контейнер.
        """
        # Главный контейнер с вертикальным размещением
        self._main_container = tk.Frame(parent)
        self._main_container.rowconfigure(0, weight=1)  # Content растягивается
        self._main_container.rowconfigure(1, weight=0)  # StatusBar фиксирован
        self._main_container.columnconfigure(0, weight=1)

        # Фрейм для контента (paned side|content)
        self._content_frame = tk.Frame(self._main_container)
        self._content_frame.grid(row=0, column=0, sticky="nsew")
        self._content_frame.rowconfigure(0, weight=1)
        self._content_frame.columnconfigure(0, weight=1)

        # Фрейм для statusbar
        self._statusbar_frame = tk.Frame(
            self._main_container,
            height=self._STATUSBAR_HEIGHT,
        )
        self._statusbar_frame.grid(row=1, column=0, sticky="ew")
        self._statusbar_frame.grid_propagate(False)

        # Создаём PanedLayout для side|content
        self._paned_layout = PanedLayout(
            widget_id=f"{self._widget_id}_paned",
            controller=self._controller,
            orientation="horizontal",
            sash_callback=self._on_sash_changed,
            collapse_callback=self._on_collapse_changed,
        )
        paned_widget = self._paned_layout.mount(self._content_frame)
        paned_widget.grid(row=0, column=0, sticky="nsew")

        return self._main_container

    def _setup_bindings(self) -> None:
        """Настраивает event bindings."""
        # Bind на изменение размера окна
        if self._main_container is not None:
            self._main_container.bind("<Configure>", self._on_container_configure)

    def _cleanup(self) -> None:
        """Очистка ресурсов перед демонтированием."""
        # Отмонтируем дочерние виджеты
        if self._paned_layout is not None:
            self._paned_layout.unmount()
            self._paned_layout = None

        self._sidebar_widget = None
        self._content_widget = None
        self._statusbar_widget = None
        self._main_container = None
        self._content_frame = None
        self._statusbar_frame = None

    def set_sidebar(self, widget: tk.Widget) -> None:
        """Устанавливает боковую панель (sidebar).

        Args:
            widget: Виджет для размещения в sidebar.

        Raises:
            LifecycleError: Если layout не смонтирован.
            LayoutError: Если sidebar уже установлен.
        """
        self._ensure_mounted()
        if self._sidebar_widget is not None:
            raise GUIError("Sidebar already set")
        if self._paned_layout is None:
            raise GUIError("PanedLayout not initialized")

        self._sidebar_widget = widget
        self._paned_layout.add_left_panel(widget)

        # Dispatch event
        if self._controller is not None:
            event = BaseEvent(
                widget_id=self._widget_id,
            )
            self._controller.dispatch("sidebar_set", event=event)

    def set_content(self, widget: tk.Widget) -> None:
        """Устанавливает основной контент.

        Args:
            widget: Виджет для размещения в основной области.

        Raises:
            LifecycleError: Если layout не смонтирован.
            LayoutError: Если контент уже установлен.
        """
        self._ensure_mounted()
        if self._content_widget is not None:
            raise GUIError("Content already set")
        if self._paned_layout is None:
            raise GUIError("PanedLayout not initialized")

        self._content_widget = widget
        self._paned_layout.add_right_panel(widget)

        # Dispatch event
        if self._controller is not None:
            event = BaseEvent(
                widget_id=self._widget_id,
            )
            self._controller.dispatch("content_set", event=event)

    def set_statusbar(self, widget: tk.Widget) -> None:
        """Устанавливает статусную строку.

        Args:
            widget: Виджет для размещения в statusbar.

        Raises:
            LifecycleError: Если layout не смонтирован.
            LayoutError: Если statusbar уже установлен.
        """
        self._ensure_mounted()
        if self._statusbar_widget is not None:
            raise GUIError("StatusBar already set")
        if self._statusbar_frame is None:
            raise GUIError("StatusBar frame not initialized")

        self._statusbar_widget = widget
        self._statusbar_frame.rowconfigure(0, weight=1)
        self._statusbar_frame.columnconfigure(0, weight=1)
        widget.grid(in_=self._statusbar_frame, row=0, column=0, sticky="nsew")

        # Dispatch event
        if self._controller is not None:
            event = BaseEvent(
                widget_id=self._widget_id,
            )
            self._controller.dispatch("statusbar_set", event=event)

    def collapse_sidebar(self) -> None:
        """Сворачивает боковую панель.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        if self._paned_layout is None:
            return

        self._sidebar_collapsed = True
        self._paned_layout.collapse_left()

    def expand_sidebar(self) -> None:
        """Разворачивает боковую панель.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        if self._paned_layout is None:
            return

        self._sidebar_collapsed = False
        self._paned_layout.expand_left()

    def toggle_sidebar(self) -> None:
        """Переключает состояние боковой панели.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        if self._sidebar_collapsed:
            self.expand_sidebar()
        else:
            self.collapse_sidebar()

    def get_sidebar_width(self) -> int:
        """Возвращает текущую ширину sidebar в пикселях.

        Returns:
            Ширина sidebar или 0 если не установлен.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        if self._paned_layout is None:
            return 0

        if self._sidebar_collapsed:
            return SIDEBAR_COLLAPSED_WIDTH

        return self._paned_layout.get_sash_pixels()

    def set_sidebar_width(self, width: int) -> None:
        """Устанавливает ширину sidebar в пикселях.

        Args:
            width: Желаемая ширина в пикселях.

        Raises:
            LifecycleError: Если layout не смонтирован.
            ValueError: Если width отрицательный.
        """
        self._ensure_mounted()
        if width < 0:
            raise ValueError(f"Width must be non-negative, got {width}")
        if self._paned_layout is None:
            return

        # Вычисляем ratio из width
        container_width = self._get_container_width()
        if container_width > 0:
            ratio = width / container_width
            self._paned_layout.set_sash_position(ratio)
            self._sidebar_ratio = ratio
            self._sidebar_collapsed = False

    def get_content_area(self) -> tuple[int, int]:
        """Возвращает размеры области контента.

        Returns:
            Кортеж (width, height) контентной области.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        if self._content_frame is None:
            return (0, 0)

        return (self._content_frame.winfo_width(), self._content_frame.winfo_height())

    def is_sidebar_visible(self) -> bool:
        """Проверяет, видима ли боковая панель.

        Returns:
            True если sidebar развёрнут (не collapsed).
        """
        return not self._sidebar_collapsed

    def save_sidebar_state(self) -> dict[str, object]:
        """Сохраняет состояние sidebar для восстановления.

        Returns:
            Словарь с состоянием sidebar.
        """
        return {
            "ratio": self._sidebar_ratio,
            "collapsed": self._sidebar_collapsed,
            "width": self.get_sidebar_width() if self._is_mounted else 0,
        }

    def restore_sidebar_state(self, state: dict[str, object]) -> None:
        """Восстанавливает состояние sidebar.

        Args:
            state: Словарь с сохранённым состоянием.
        """
        self._ensure_mounted()

        ratio_value = state.get("ratio", self._DEFAULT_SIDEBAR_RATIO)
        if isinstance(ratio_value, (int, float, str)):
            ratio = float(ratio_value)
        else:
            ratio = self._DEFAULT_SIDEBAR_RATIO
        collapsed = bool(state.get("collapsed", False))

        if self._paned_layout is not None:
            self._paned_layout.set_sash_position(ratio)

        if collapsed:
            self.collapse_sidebar()
        else:
            self.expand_sidebar()

    def _ensure_mounted(self) -> None:
        """Проверяет, что layout смонтирован.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="layout_operation",
                message="MainLayout not mounted",
            )

    def _get_container_width(self) -> int:
        """Возвращает ширину контейнера.

        Returns:
            Ширина в пикселях.
        """
        if self._content_frame is not None:
            return self._content_frame.winfo_width()
        if self._root is not None:
            return self._root.winfo_width()
        return 0

    def _on_sash_changed(self, ratio: float) -> None:
        """Callback при изменении позиции sash.

        Args:
            ratio: Новое соотношение.
        """
        self._sidebar_ratio = ratio

        # Dispatch event через controller
        if self._controller is not None:
            event = BaseEvent(
                widget_id=self._widget_id,
            )
            self._controller.dispatch("sidebar_resized", event=event, ratio=ratio)

    def _on_collapse_changed(self, collapsed: bool) -> None:
        """Callback при изменении состояния collapse.

        Args:
            collapsed: True если панель свёрнута.
        """
        self._sidebar_collapsed = collapsed

        if self._sidebar_toggle_callback is not None:
            self._sidebar_toggle_callback(not collapsed)

        # Dispatch event через controller
        if self._controller is not None:
            event_type = "sidebar_collapsed" if collapsed else "sidebar_expanded"
            event = BaseEvent(
                widget_id=self._widget_id,
            )
            self._controller.dispatch(event_type, event=event)

    def _on_container_configure(self, event: tk.Event) -> None:
        """Обработчик изменения размера контейнера.

        Note:
            PanedLayout самостоятельно обрабатывает <Configure>
            и обновляет позицию sash. Данный метод — точка расширения
            для будущих обработчиков (например, перерасчёт статуса).
        """
        # PanedLayout обрабатывает resize самостоятельно через _on_configure


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "MainLayout",
    "SidebarToggleCallback",
]
