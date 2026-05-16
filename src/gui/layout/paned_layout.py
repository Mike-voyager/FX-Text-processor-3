"""PanedLayout — wrapper вокруг tk.PanedWindow.

Предоставляет типизированную обёртку для Tkinter PanedWindow с:
- Управлением позицией sash через ratio
- Сохранением/восстановлением позиции
- Collapse/expand левой панели
- Throttled resize handling

Example:
    >>> layout = PanedLayout(
    ...     widget_id="main_paned",
    ...     controller=controller,
    ...     orientation="horizontal",
    ... )
    >>> paned = layout.mount(parent_frame)
    >>> layout.set_sash_position(0.25)  # 25% для левой панели
    >>> layout.collapse_left()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
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
    PANEL_RATIO_MAX,
    PANEL_RATIO_MIN,
    SASH_WIDTH,
    SIDEBAR_COLLAPSED_WIDTH,
)

# =============================================================================
# PROTOCOLS
# =============================================================================


@runtime_checkable
class SashChangeCallback(Protocol):
    """Callback для изменения позиции sash."""

    def __call__(self, ratio: float) -> None:
        """Вызывается при изменении позиции sash.

        Args:
            ratio: Новое значение ratio (0.0 - 1.0).
        """
        ...


@runtime_checkable
class CollapseStateCallback(Protocol):
    """Callback для изменения состояния collapse."""

    def __call__(self, collapsed: bool) -> None:
        """Вызывается при изменении состояния свёрнутости.

        Args:
            collapsed: True если панель свёрнута.
        """
        ...


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass(frozen=True)
class PanedLayoutState:
    """Состояние PanedLayout для сохранения/восстановления.

    Attributes:
        ratio: Текущее соотношение панелей (0.0 - 1.0).
        collapsed: Состояние свёрнутости левой панели.
        width: Ширина контейнера при сохранении.
        height: Высота контейнера при сохранении.
    """

    ratio: float
    collapsed: bool
    width: int
    height: int


# =============================================================================
# PANED LAYOUT
# =============================================================================


class PanedLayout(BaseWidget):
    """Wrapper вокруг tk.PanedWindow с типизированным API.

    Управляет разделителем между двумя панелями с сохранением
    пропорциональной позиции при resize окна.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        orientation: Ориентация разделителя ('horizontal' | 'vertical').
        sash_callback: Callback при изменении позиции sash.
        collapse_callback: Callback при изменении состояния collapse.

    Example:
        >>> layout = PanedLayout(
        ...     widget_id="main_paned",
        ...     orientation="horizontal",
        ... )
        >>> layout.mount(parent)
        >>> layout.add_left_panel(sidebar_widget)
        >>> layout.add_right_panel(content_widget)
        >>> layout.set_sash_position(0.3)
    """

    # Throttle delay для resize events (миллисекунды)
    _RESIZE_THROTTLE_MS: Final[int] = 100

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        orientation: str = "horizontal",
        sash_callback: Optional[SashChangeCallback] = None,
        collapse_callback: Optional[CollapseStateCallback] = None,
    ) -> None:
        """Инициализация PanedLayout.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональный контроллер для callbacks.
            orientation: Ориентация разделителя ('horizontal' | 'vertical').
            sash_callback: Callback при изменении позиции sash.
            collapse_callback: Callback при изменении состояния collapse.

        Raises:
            ValueError: Если orientation невалиден.
        """
        super().__init__(widget_id=widget_id, controller=controller)

        if orientation not in ("horizontal", "vertical"):
            raise ValueError(f"Invalid orientation: {orientation}")

        self._orientation: str = orientation
        self._sash_callback: Optional[SashChangeCallback] = sash_callback
        self._collapse_callback: Optional[CollapseStateCallback] = collapse_callback

        # Tkinter PanedWindow (создаётся в mount)
        self._paned: Optional[tk.PanedWindow] = None

        # Дочерние виджеты
        self._left_widget: Optional[tk.Widget] = None
        self._right_widget: Optional[tk.Widget] = None

        # Состояние
        self._current_ratio: float = PANEL_RATIO_DEFAULT
        self._is_collapsed: bool = False
        self._saved_ratio_before_collapse: float = PANEL_RATIO_DEFAULT
        self._container_width: int = 0
        self._container_height: int = 0

        # Throttle state
        self._resize_after_id: Optional[str] = None
        self._is_animating: bool = False

    @property
    def orientation(self) -> str:
        """Возвращает ориентацию разделителя.

        Returns:
            'horizontal' или 'vertical'.
        """
        return self._orientation

    @property
    def is_collapsed(self) -> bool:
        """Проверяет, свёрнута ли левая панель.

        Returns:
            True если левая панель свёрнута.
        """
        return self._is_collapsed

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter PanedWindow.

        Args:
            parent: Родительский виджет.

        Returns:
            Созданный PanedWindow.
        """
        self._paned = tk.PanedWindow(
            parent,
            orient=tk.HORIZONTAL if self._orientation == "horizontal" else tk.VERTICAL,
            sashwidth=SASH_WIDTH,
            sashrelief=tk.FLAT,
            showhandle=False,
        )
        return self._paned

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для PanedWindow."""
        if self._paned is None:
            return

        # Bind на изменение позиции sash
        self._paned.bind("<B1-Motion>", self._on_sash_drag)
        self._paned.bind("<ButtonRelease-1>", self._on_sash_release)
        self._paned.bind("<Destroy>", lambda _e: self._cancel_resize(), add=True)

        # Bind на resize с throttle
        self._paned.bind("<Configure>", self._on_configure)

    def _cleanup(self) -> None:
        """Очистка ресурсов перед демонтированием."""
        # Отменяем pending resize callback
        if self._resize_after_id is not None and self._paned is not None:
            try:
                self._paned.after_cancel(self._resize_after_id)
            except tk.TclError:
                pass
            self._resize_after_id = None

        # Сохраняем ссылки для возможного восстановления
        self._left_widget = None
        self._right_widget = None
        self._paned = None

    def add_left_panel(self, widget: tk.Widget) -> None:
        """Добавляет левую (или верхнюю) панель.

        Args:
            widget: Виджет для добавления в левую панель.

        Raises:
            LifecycleError: Если layout не смонтирован.
            LayoutError: Если левая панель уже добавлена.
        """
        self._ensure_mounted()
        if self._left_widget is not None:
            raise GUIError("Left panel already added")
        if self._paned is None:
            raise GUIError("PanedWindow not initialized")

        self._left_widget = widget
        self._paned.add(widget, minsize=SIDEBAR_COLLAPSED_WIDTH)

        # Применяем текущее состояние
        self._apply_sash_position()

    def add_right_panel(self, widget: tk.Widget) -> None:
        """Добавляет правую (или нижнюю) панель.

        Args:
            widget: Виджет для добавления в правую панель.

        Raises:
            LifecycleError: Если layout не смонтирован.
            LayoutError: Если правая панель уже добавлена.
        """
        self._ensure_mounted()
        if self._right_widget is not None:
            raise GUIError("Right panel already added")
        if self._paned is None:
            raise GUIError("PanedWindow not initialized")

        self._right_widget = widget
        self._paned.add(widget)

        # Применяем текущее состояние
        self._apply_sash_position()

    def set_sash_position(self, ratio: float) -> None:
        """Устанавливает позицию sash через ratio.

        Args:
            ratio: Соотношение от 0.0 до 1.0 (левая панель / общая).
                   Автоматически ограничивается PANEL_RATIO_MIN/MAX.

        Raises:
            LifecycleError: Если layout не смонтирован.

        Example:
            >>> layout.set_sash_position(0.25)  # 25% для левой панели
        """
        self._ensure_mounted()

        # Ограничиваем ratio допустимыми значениями
        clamped_ratio = max(PANEL_RATIO_MIN, min(PANEL_RATIO_MAX, ratio))
        self._current_ratio = clamped_ratio
        self._is_collapsed = False

        self._apply_sash_position()

        # Notify callback
        if self._sash_callback is not None:
            self._sash_callback(clamped_ratio)

    def get_sash_position(self) -> float:
        """Возвращает текущее соотношение панелей.

        Returns:
            Текущий ratio (0.0 - 1.0).

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        return self._current_ratio

    def get_sash_pixels(self) -> int:
        """Возвращает текущую позицию sash в пикселях.

        Returns:
            Позиция sash от левого/верхнего края.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        if self._paned is None:
            return 0

        try:
            if hasattr(self._paned, "sash_coord"):
                coord: tuple[int, int] = self._paned.sash_coord(0)  # type: ignore[no-untyped-call]
                return int(coord[0]) if self._orientation == "horizontal" else int(coord[1])
        except tk.TclError:
            pass
        if self._orientation == "horizontal":
            return int(self._container_width * self._current_ratio)
        else:
            return int(self._container_height * self._current_ratio)

    def collapse_left(self) -> None:
        """Сворачивает левую панель до минимального размера.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        if self._is_collapsed:
            return

        self._saved_ratio_before_collapse = self._current_ratio
        self._is_collapsed = True

        self._apply_sash_position()

        # Notify callback
        if self._collapse_callback is not None:
            self._collapse_callback(True)

        # Dispatch event через controller
        if self._controller is not None:
            event = BaseEvent(
                widget_id=self._widget_id,
            )
            self._controller.dispatch("panel_collapsed", event=event)

    def expand_left(self) -> None:
        """Разворачивает левую панель до прежнего размера.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        if not self._is_collapsed:
            return

        self._is_collapsed = False
        self._current_ratio = self._saved_ratio_before_collapse

        self._apply_sash_position()

        # Notify callback
        if self._collapse_callback is not None:
            self._collapse_callback(False)

        # Dispatch event через controller
        if self._controller is not None:
            event = BaseEvent(
                widget_id=self._widget_id,
            )
            self._controller.dispatch("panel_expanded", event=event)

    def toggle_left(self) -> None:
        """Переключает состояние свёрнутости левой панели.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        if self._is_collapsed:
            self.expand_left()
        else:
            self.collapse_left()

    def save_state(self) -> PanedLayoutState:
        """Сохраняет текущее состояние layout.

        Returns:
            PanedLayoutState с текущими параметрами.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        return PanedLayoutState(
            ratio=self._current_ratio,
            collapsed=self._is_collapsed,
            width=self._container_width,
            height=self._container_height,
        )

    def restore_state(self, state: PanedLayoutState) -> None:
        """Восстанавливает состояние layout.

        Args:
            state: Сохранённое состояние для восстановления.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        self._ensure_mounted()
        self._current_ratio = max(PANEL_RATIO_MIN, min(PANEL_RATIO_MAX, state.ratio))
        self._is_collapsed = state.collapsed

        if self._is_collapsed:
            self._saved_ratio_before_collapse = self._current_ratio

        self._apply_sash_position()

    def _ensure_mounted(self) -> None:
        """Проверяет, что layout смонтирован.

        Raises:
            LifecycleError: Если layout не смонтирован.
        """
        if not self._is_mounted or self._paned is None:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="paned_operation",
                message="PanedLayout not mounted",
            )

    def _apply_sash_position(self) -> None:
        """Применяет текущую позицию sash к PanedWindow."""
        if self._paned is None:
            return

        if self._is_collapsed:
            # Сворачиваем до минимальной ширины
            sash_pos = SIDEBAR_COLLAPSED_WIDTH
        else:
            # Вычисляем позицию из ratio
            if self._orientation == "horizontal":
                sash_pos = int(self._container_width * self._current_ratio)
            else:
                sash_pos = int(self._container_height * self._current_ratio)

        # Применяем позицию sash через sash_place
        try:
            # Используем sash_place для установки позиции sash
            if hasattr(self._paned, "sash_place"):
                if self._orientation == "horizontal":
                    self._paned.sash_place(0, sash_pos, 0)  # type: ignore[no-untyped-call]
                else:
                    self._paned.sash_place(0, 0, sash_pos)  # type: ignore[no-untyped-call]
        except tk.TclError:
            # Sash ещё не создан или панели не добавлены
            pass

    def _on_sash_drag(self, event: tk.Event) -> None:
        """Обработчик перетаскивания sash."""
        # Вычисляем новый ratio из текущей позиции
        if self._paned is None or self._container_width == 0:
            return

        try:
            # Получаем координаты sash
            if hasattr(self._paned, "sash_coord"):
                coord: tuple[int, int] = self._paned.sash_coord(0)  # type: ignore[no-untyped-call]
                sash_x = coord[0] if self._orientation == "horizontal" else coord[1]
                if self._orientation == "horizontal":
                    container_size = self._container_width
                else:
                    container_size = self._container_height

                if container_size > 0:
                    new_ratio = sash_x / container_size
                    self._current_ratio = max(PANEL_RATIO_MIN, min(PANEL_RATIO_MAX, new_ratio))
                    self._is_collapsed = False  # Drag всегда разворачивает
        except tk.TclError:
            pass

    def _on_sash_release(self, event: tk.Event) -> None:
        """Обработчик отпускания sash."""
        if self._sash_callback is not None:
            self._sash_callback(self._current_ratio)

    def _on_configure(self, event: tk.Event) -> None:
        """Обработчик resize с throttle."""
        if self._paned is None:
            return

        # Обновляем размеры контейнера
        self._container_width = event.width
        self._container_height = event.height

        # Cancel pending resize
        if self._resize_after_id is not None:
            try:
                self._paned.after_cancel(self._resize_after_id)
            except tk.TclError:
                pass

        # Schedule new resize callback
        self._resize_after_id = self._paned.after(
            self._RESIZE_THROTTLE_MS,
            self._on_throttled_resize,
        )

    def _cancel_resize(self) -> None:
        """Отменяет pending after() для resize."""
        if self._resize_after_id is not None and self._paned is not None:
            try:
                self._paned.after_cancel(self._resize_after_id)
            except tk.TclError:
                pass
            self._resize_after_id = None

    def _on_throttled_resize(self) -> None:
        """Обработчик throttled resize."""
        self._resize_after_id = None
        self._apply_sash_position()


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "PanedLayout",
    "PanedLayoutState",
    "SashChangeCallback",
    "CollapseStateCallback",
]
