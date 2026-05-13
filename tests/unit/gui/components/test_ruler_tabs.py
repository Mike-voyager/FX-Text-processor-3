"""Unit-тесты для функциональности табуляторов Ruler.

Проверяет:
- Интеграцию с TabStopManager
- Добавление табуляторов через двойной клик
- Drag-and-drop перемещение табуляторов
- Контекстное меню (удаление, смена типа)
- Визуальное отображение маркеров
- Callback при изменении табуляторов

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.components.ruler import (
    RULER_HEIGHT,
    TAB_MARKER_ACTIVE_COLOR,
    TAB_MARKER_COLOR,
    TAB_MARKER_HOVER_COLOR,
    Ruler,
)
from src.model.tab_stop import TabStop, TabStopType
from src.model.tab_stop_manager import TabStopManager


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def tab_manager() -> TabStopManager:
    """Fixture для TabStopManager."""
    return TabStopManager()


@pytest.fixture
def ruler_with_tabs(
    tk_root: tk.Tk, tab_manager: TabStopManager
) -> Generator[Ruler, None, None]:
    """Fixture для Ruler с TabStopManager."""
    r = Ruler(
        widget_id="test_ruler",
        tab_stop_manager=tab_manager,
        initial_cpi=10,
        initial_width_chars=80,
    )
    r.mount(tk_root)
    yield r


# =============================================================================
# TEST: TabStopManager Integration
# =============================================================================


class TestTabStopManagerIntegration:
    """Тесты интеграции с TabStopManager."""

    def test_init_with_tab_manager(self, tk_root: tk.Tk) -> None:
        """Инициализация Ruler с TabStopManager."""
        manager = TabStopManager()
        manager.add_tab(10, TabStopType.LEFT)
        manager.add_tab(20, TabStopType.RIGHT)

        ruler = Ruler(
            widget_id="test_ruler",
            tab_stop_manager=manager,
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        assert ruler.get_tab_stop_manager() is manager

    def test_set_tab_stop_manager(self, ruler_with_tabs: Ruler) -> None:
        """set_tab_stop_manager() устанавливает новый менеджер."""
        new_manager = TabStopManager()
        new_manager.add_tab(15, TabStopType.CENTER)

        ruler_with_tabs.set_tab_stop_manager(new_manager)

        assert ruler_with_tabs.get_tab_stop_manager() is new_manager

    def test_set_tab_stop_manager_none(self, ruler_with_tabs: Ruler) -> None:
        """set_tab_stop_manager(None) сбрасывает менеджер."""
        ruler_with_tabs.set_tab_stop_manager(None)

        assert ruler_with_tabs.get_tab_stop_manager() is None

    def test_refresh_tabs(self, ruler_with_tabs: Ruler, tab_manager: TabStopManager) -> None:
        """refresh_tabs() перерисовывает табуляторы."""
        # Добавляем табулятор в менеджер
        tab_manager.add_tab(10, TabStopType.LEFT)

        # Вызываем refresh
        ruler_with_tabs.refresh_tabs()

        # Табулятор должен быть отображен
        tabs = tab_manager.get_tabs()
        assert len(tabs) == 1
        assert tabs[0].position == 10


# =============================================================================
# TEST: Adding Tabs via Double Click
# =============================================================================


class TestAddTabDoubleClick:
    """Тесты добавления табуляторов через двойной клик."""

    def test_double_click_adds_tab(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Двойной клик добавляет табулятор."""
        event = MagicMock()
        event.x = 96  # 10 символов при CPI=10 (9.6 px/char)

        ruler_with_tabs._on_ruler_double_click(event)

        assert tab_manager.has_tab_at(10)
        tab = tab_manager.get_tab_at(10)
        assert tab is not None
        assert tab.tab_type == TabStopType.LEFT

    def test_double_click_position_clamped_to_min(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Позиция ограничена минимумом 1."""
        event = MagicMock()
        event.x = 0  # Позиция 0

        ruler_with_tabs._on_ruler_double_click(event)

        assert not tab_manager.has_tab_at(0)
        assert tab_manager.has_tab_at(1)

    def test_double_click_position_clamped_to_max(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Позиция ограничена максимальной шириной."""
        event = MagicMock()
        event.x = 10000  # За пределами

        ruler_with_tabs._on_ruler_double_click(event)

        assert tab_manager.has_tab_at(80)  # width_chars

    def test_double_click_duplicate_ignored(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Дубликат позиции игнорируется."""
        tab_manager.add_tab(10, TabStopType.LEFT)

        event = MagicMock()
        event.x = 96  # Позиция 10

        ruler_with_tabs._on_ruler_double_click(event)

        # Всё ещё только один табулятор
        assert tab_manager.count() == 1

    def test_double_click_without_manager(self, tk_root: tk.Tk) -> None:
        """Двойной клик без менеджера не вызывает ошибки."""
        ruler = Ruler(
            widget_id="test_ruler",
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        event = MagicMock()
        event.x = 96

        # Не должно вызывать исключение
        ruler._on_ruler_double_click(event)


# =============================================================================
# TEST: Delete Tab
# =============================================================================


class TestDeleteTab:
    """Тесты удаления табуляторов."""

    def test_delete_tab_success(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Успешное удаление табулятора."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        ruler_with_tabs._delete_tab(tab)

        assert not tab_manager.has_tab_at(10)

    def test_delete_tab_not_exists(self, ruler_with_tabs: Ruler) -> None:
        """Удаление несуществующего табулятора не вызывает ошибку."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)

        # Не должно вызывать исключение
        ruler_with_tabs._delete_tab(tab)

    def test_delete_without_manager(
        self, tk_root: tk.Tk, tab_manager: TabStopManager
    ) -> None:
        """Удаление без менеджера не вызывает ошибку."""
        ruler = Ruler(
            widget_id="test_ruler",
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        tab = TabStop(position=10, tab_type=TabStopType.LEFT)

        # Не должно вызывать исключение
        ruler._delete_tab(tab)


# =============================================================================
# TEST: Change Tab Type
# =============================================================================


class TestChangeTabType:
    """Тесты изменения типа табулятора."""

    def test_change_tab_type_success(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Успешное изменение типа табулятора."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        ruler_with_tabs._change_tab_type(tab, TabStopType.RIGHT)

        new_tab = tab_manager.get_tab_at(10)
        assert new_tab is not None
        assert new_tab.tab_type == TabStopType.RIGHT

    def test_change_tab_type_same_type_noop(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Изменение на тот же тип ничего не делает."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        ruler_with_tabs._change_tab_type(tab, TabStopType.LEFT)

        new_tab = tab_manager.get_tab_at(10)
        assert new_tab is not None
        assert new_tab.tab_type == TabStopType.LEFT

    def test_change_tab_type_without_manager(
        self, tk_root: tk.Tk
    ) -> None:
        """Изменение типа без менеджера не вызывает ошибку."""
        ruler = Ruler(
            widget_id="test_ruler",
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        tab = TabStop(position=10, tab_type=TabStopType.LEFT)

        # Не должно вызывать исключение
        ruler._change_tab_type(tab, TabStopType.RIGHT)


# =============================================================================
# TEST: Tab Type Labels
# =============================================================================


class TestTabTypeLabels:
    """Тесты меток типов табуляторов."""

    def test_left_label(self, ruler_with_tabs: Ruler) -> None:
        """Метка LEFT табулятора."""
        label = ruler_with_tabs._get_tab_type_label(TabStopType.LEFT)
        assert "Левый" in label

    def test_right_label(self, ruler_with_tabs: Ruler) -> None:
        """Метка RIGHT табулятора."""
        label = ruler_with_tabs._get_tab_type_label(TabStopType.RIGHT)
        assert "Правый" in label

    def test_center_label(self, ruler_with_tabs: Ruler) -> None:
        """Метка CENTER табулятора."""
        label = ruler_with_tabs._get_tab_type_label(TabStopType.CENTER)
        assert "Центральный" in label

    def test_decimal_label(self, ruler_with_tabs: Ruler) -> None:
        """Метка DECIMAL табулятора."""
        label = ruler_with_tabs._get_tab_type_label(TabStopType.DECIMAL)
        assert "Десятичный" in label


# =============================================================================
# TEST: Drag Operations
# =============================================================================


class TestDragOperations:
    """Тесты drag-and-drop операций."""

    def test_start_drag_sets_state(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Начало drag устанавливает состояние."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        event = MagicMock()
        event.num = 1
        event.x = 96

        ruler_with_tabs._start_tab_drag(event, tab)

        assert ruler_with_tabs._drag_tab_stop is tab
        assert ruler_with_tabs._drag_start_x == 96

    def test_start_drag_ignores_right_click(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Правый клик не начинает drag."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        event = MagicMock()
        event.num = 3  # Правый клик
        event.x = 96

        ruler_with_tabs._start_tab_drag(event, tab)

        assert ruler_with_tabs._drag_tab_stop is None

    def test_end_drag_moves_tab(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Завершение drag перемещает табулятор."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        # Имитируем начало drag
        ruler_with_tabs._drag_tab_stop = tab
        ruler_with_tabs._drag_start_x = 96  # Позиция 10

        event = MagicMock()
        event.x = 192  # Позиция 20

        ruler_with_tabs._end_tab_drag(event)

        assert not tab_manager.has_tab_at(10)
        assert tab_manager.has_tab_at(20)

    def test_end_drag_same_position_noop(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Drag на ту же позицию ничего не делает."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        # Имитируем начало drag
        ruler_with_tabs._drag_tab_stop = tab
        ruler_with_tabs._drag_start_x = 96

        event = MagicMock()
        event.x = 100  # Всё ещё позиция 10

        ruler_with_tabs._end_tab_drag(event)

        # Табулятор остался на месте
        assert tab_manager.has_tab_at(10)

    def test_end_drag_occupied_position_cancelled(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Drag на занятую позицию отменяется."""
        tab1 = tab_manager.add_tab(10, TabStopType.LEFT)
        tab_manager.add_tab(20, TabStopType.RIGHT)
        assert tab1 is not None

        # Имитируем начало drag
        ruler_with_tabs._drag_tab_stop = tab1
        ruler_with_tabs._drag_start_x = 96

        event = MagicMock()
        event.x = 192  # Позиция 20 (занята)

        ruler_with_tabs._end_tab_drag(event)

        # Табулятор остался на исходной позиции
        assert tab_manager.has_tab_at(10)
        assert tab_manager.has_tab_at(20)

    def test_reset_drag_state(self, ruler_with_tabs: Ruler, tab_manager: TabStopManager) -> None:
        """reset_drag_state() сбрасывает состояние."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        ruler_with_tabs._drag_tab_stop = tab
        ruler_with_tabs._drag_start_x = 96
        ruler_with_tabs._drag_current_x = 100

        ruler_with_tabs._reset_drag_state()

        assert ruler_with_tabs._drag_tab_stop is None
        assert ruler_with_tabs._drag_start_x == 0
        assert ruler_with_tabs._drag_current_x == 0


# =============================================================================
# TEST: Visual Markers
# =============================================================================


class TestVisualMarkers:
    """Тесты визуальных маркеров табуляторов."""

    def test_draw_tab_markers_creates_items(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """draw_tab_markers() создаёт canvas items."""
        tab_manager.add_tab(10, TabStopType.LEFT)
        tab_manager.add_tab(20, TabStopType.RIGHT)

        ruler_with_tabs._draw_tab_markers()

        # Проверяем, что маркеры созданы
        assert len(ruler_with_tabs._tab_markers) == 2

    def test_create_left_marker(
        self, ruler_with_tabs: Ruler
    ) -> None:
        """Создание LEFT маркера."""
        tab = TabStop(position=10, tab_type=TabStopType.LEFT)

        item_id = ruler_with_tabs._create_tab_marker(tab)

        assert item_id != -1
        assert 10 in ruler_with_tabs._tab_markers

    def test_create_right_marker(
        self, ruler_with_tabs: Ruler
    ) -> None:
        """Создание RIGHT маркера."""
        tab = TabStop(position=10, tab_type=TabStopType.RIGHT)

        item_id = ruler_with_tabs._create_tab_marker(tab)

        assert item_id != -1

    def test_create_center_marker(
        self, ruler_with_tabs: Ruler
    ) -> None:
        """Создание CENTER маркера."""
        tab = TabStop(position=10, tab_type=TabStopType.CENTER)

        item_id = ruler_with_tabs._create_tab_marker(tab)

        assert item_id != -1

    def test_create_decimal_marker(
        self, ruler_with_tabs: Ruler
    ) -> None:
        """Создание DECIMAL маркера."""
        tab = TabStop(position=10, tab_type=TabStopType.DECIMAL)

        item_id = ruler_with_tabs._create_tab_marker(tab)

        assert item_id != -1

    def test_tab_hover_enter_changes_color(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Hover enter меняет цвет маркера."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        ruler_with_tabs._draw_tab_markers()
        item_id, _ = ruler_with_tabs._tab_markers[10]

        ruler_with_tabs._on_tab_hover_enter(item_id)

        # Проверяем, что цвет изменился
        assert ruler_with_tabs._canvas is not None
        fill = ruler_with_tabs._canvas.itemcget(item_id, "fill")  # type: ignore[no-untyped-call]
        assert fill == TAB_MARKER_HOVER_COLOR

    def test_tab_hover_leave_restores_color(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Hover leave возвращает исходный цвет."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        ruler_with_tabs._draw_tab_markers()
        item_id, _ = ruler_with_tabs._tab_markers[10]

        ruler_with_tabs._on_tab_hover_enter(item_id)
        ruler_with_tabs._on_tab_hover_leave(item_id)

        # Проверяем, что цвет вернулся
        assert ruler_with_tabs._canvas is not None
        fill = ruler_with_tabs._canvas.itemcget(item_id, "fill")  # type: ignore[no-untyped-call]
        assert fill == TAB_MARKER_COLOR


# =============================================================================
# TEST: Callbacks
# =============================================================================


class TestCallbacks:
    """Тесты callback-функций."""

    def test_on_tabs_changed_called_on_add(
        self, tk_root: tk.Tk, tab_manager: TabStopManager
    ) -> None:
        """Callback вызывается при добавлении табулятора."""
        callback = MagicMock()
        ruler = Ruler(
            widget_id="test_ruler",
            tab_stop_manager=tab_manager,
            on_tabs_changed=callback,
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        event = MagicMock()
        event.x = 96
        ruler._on_ruler_double_click(event)

        callback.assert_called_once()
        args = callback.call_args[0][0]
        assert len(args) == 1
        assert args[0].position == 10

    def test_on_tabs_changed_called_on_delete(
        self, tk_root: tk.Tk, tab_manager: TabStopManager
    ) -> None:
        """Callback вызывается при удалении табулятора."""
        callback = MagicMock()
        ruler = Ruler(
            widget_id="test_ruler",
            tab_stop_manager=tab_manager,
            on_tabs_changed=callback,
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        callback.reset_mock()
        ruler._delete_tab(tab)

        callback.assert_called_once()
        args = callback.call_args[0][0]
        assert len(args) == 0

    def test_on_tabs_changed_called_on_type_change(
        self, tk_root: tk.Tk, tab_manager: TabStopManager
    ) -> None:
        """Callback вызывается при изменении типа табулятора."""
        callback = MagicMock()
        ruler = Ruler(
            widget_id="test_ruler",
            tab_stop_manager=tab_manager,
            on_tabs_changed=callback,
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        callback.reset_mock()
        ruler._change_tab_type(tab, TabStopType.RIGHT)

        callback.assert_called_once()

    def test_on_tabs_changed_exception_handled(
        self, tk_root: tk.Tk, tab_manager: TabStopManager
    ) -> None:
        """Исключение в callback обрабатывается gracefully."""
        callback = MagicMock(side_effect=Exception("Test error"))
        ruler = Ruler(
            widget_id="test_ruler",
            tab_stop_manager=tab_manager,
            on_tabs_changed=callback,
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        event = MagicMock()
        event.x = 96

        # Не должно вызывать исключение
        ruler._on_ruler_double_click(event)


# =============================================================================
# TEST: Edge Cases
# =============================================================================


class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_drag_without_tab_stop_manager(
        self, tk_root: tk.Tk
    ) -> None:
        """Drag без менеджера не вызывает ошибку."""
        ruler = Ruler(
            widget_id="test_ruler",
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        ruler._drag_tab_stop = tab

        event = MagicMock()
        event.x = 192

        # Не должно вызывать исключение
        ruler._end_tab_drag(event)

    def test_draw_markers_without_manager(
        self, ruler_with_tabs: Ruler
    ) -> None:
        """draw_tab_markers() без менеджера не вызывает ошибку."""
        ruler_with_tabs.set_tab_stop_manager(None)

        # Не должно вызывать исключение
        ruler_with_tabs._draw_tab_markers()

        assert len(ruler_with_tabs._tab_markers) == 0

    def test_operations_on_unmounted_ruler(
        self, tk_root: tk.Tk, tab_manager: TabStopManager
    ) -> None:
        """Операции на несмонтированном ruler не вызывают ошибок."""
        ruler = Ruler(
            widget_id="test_ruler",
            tab_stop_manager=tab_manager,
            initial_cpi=10,
            initial_width_chars=80,
        )
        # Не вызываем mount()

        # Эти операции не должны вызывать исключений
        ruler.set_tab_stop_manager(tab_manager)
        ruler.refresh_tabs()

    def test_cpi_change_redraws_tabs(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Изменение CPI перерисовывает табуляторы."""
        tab_manager.add_tab(10, TabStopType.LEFT)
        ruler_with_tabs._draw_tab_markers()

        original_markers = len(ruler_with_tabs._tab_markers)

        ruler_with_tabs.set_cpi(12)

        # Табуляторы должны быть перерисованы
        assert len(ruler_with_tabs._tab_markers) == original_markers

    def test_width_change_redraws_tabs(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """Изменение ширины перерисовывает табуляторы."""
        tab_manager.add_tab(10, TabStopType.LEFT)
        ruler_with_tabs._draw_tab_markers()

        original_markers = len(ruler_with_tabs._tab_markers)

        ruler_with_tabs.set_width_chars(132)

        # Табуляторы должны быть перерисованы
        assert len(ruler_with_tabs._tab_markers) == original_markers


# =============================================================================
# TEST: Context Menu
# =============================================================================


class TestContextMenu:
    """Тесты контекстного меню."""

    def test_show_context_menu(
        self, ruler_with_tabs: Ruler, tab_manager: TabStopManager
    ) -> None:
        """show_context_menu() создаёт меню."""
        tab = tab_manager.add_tab(10, TabStopType.LEFT)
        assert tab is not None

        event = MagicMock()
        event.x_root = 100
        event.y_root = 100

        # Не должно вызывать исключение
        ruler_with_tabs._show_tab_context_menu(event, tab)

        assert ruler_with_tabs._context_menu is not None

    def test_hide_context_menu(
        self, ruler_with_tabs: Ruler
    ) -> None:
        """hide_context_menu() скрывает меню."""
        # Не должно вызывать исключение
        ruler_with_tabs._hide_context_menu()

    def test_show_context_menu_without_canvas(
        self, tk_root: tk.Tk, tab_manager: TabStopManager
    ) -> None:
        """show_context_menu() без canvas не вызывает ошибку."""
        ruler = Ruler(
            widget_id="test_ruler",
            tab_stop_manager=tab_manager,
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)
        ruler._canvas = None

        tab = TabStop(position=10, tab_type=TabStopType.LEFT)
        event = MagicMock()

        # Не должно вызывать исключение
        ruler._show_tab_context_menu(event, tab)


# =============================================================================
# TEST: Constructor Parameters
# =============================================================================


class TestConstructorParameters:
    """Тесты параметров конструктора."""

    def test_init_with_on_tabs_changed(self, tk_root: tk.Tk) -> None:
        """Инициализация с on_tabs_changed callback."""
        callback = MagicMock()
        ruler = Ruler(
            widget_id="test_ruler",
            on_tabs_changed=callback,
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler.mount(tk_root)

        assert ruler._on_tabs_changed is callback

    def test_init_with_all_parameters(
        self, tk_root: tk.Tk, tab_manager: TabStopManager
    ) -> None:
        """Инициализация со всеми параметрами."""
        on_click = MagicMock()
        on_tabs_changed = MagicMock()
        controller = MagicMock()

        ruler = Ruler(
            widget_id="test_ruler",
            controller=controller,
            on_click=on_click,
            on_tabs_changed=on_tabs_changed,
            tab_stop_manager=tab_manager,
            initial_cpi=12,
            initial_width_chars=100,
        )
        ruler.mount(tk_root)

        assert ruler.widget_id == "test_ruler"
        assert ruler._controller is controller
        assert ruler._on_click is on_click
        assert ruler._on_tabs_changed is on_tabs_changed
        assert ruler.get_tab_stop_manager() is tab_manager
        assert ruler.get_cpi() == 12
        assert ruler.get_width_chars() == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.components.ruler"])
