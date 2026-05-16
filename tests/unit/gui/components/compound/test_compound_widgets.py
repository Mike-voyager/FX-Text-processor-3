"""Unit-тесты для compound виджетов.

Все тесты GUI выполняются через виртуальный фреймбуфер.

Example:
    xvfb-run -a python -m pytest tests/unit/gui/components/compound/test_compound_widgets.py -v
"""

from __future__ import annotations

import tkinter as tk
from unittest.mock import MagicMock

import pytest
from src.gui.components.compound.expandable_panel import ExpandablePanel
from src.gui.components.compound.icon_button import IconButton
from src.gui.components.compound.input_group import InputGroup
from src.gui.components.compound.list_tile import ListTile
from src.gui.components.compound.progress_indicator import ProgressIndicator
from src.gui.components.compound.search_box import SearchBox
from src.gui.components.compound.status_badge import StatusBadge
from src.gui.core.protocols import ControllerProtocol


@pytest.fixture
def tk_root() -> tk.Tk:
    """Создаёт Tk root для GUI тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_controller() -> MagicMock:
    """Mock контроллер."""
    controller = MagicMock(spec=ControllerProtocol)
    controller.dispatch = MagicMock(return_value=None)
    return controller


# =============================================================================
# InputGroup
# =============================================================================


class TestInputGroup:
    """Тесты InputGroup."""

    def test_init(self) -> None:
        """Конструктор сохраняет параметры."""
        group = InputGroup(widget_id="ig", label="Email")
        assert group.widget_id == "ig"
        assert group._label_text == "Email"
        assert group.get_value() == ""

    def test_init_with_validator(self) -> None:
        """Валидатор сохраняется."""
        v = lambda t: "err" if "@" not in t else None  # noqa: E731
        group = InputGroup(widget_id="ig", label="Email", validator=v)
        assert group._validator is v

    def test_set_and_get_value(self, tk_root: tk.Tk) -> None:
        """set_value и get_value синхронизированы."""
        group = InputGroup(widget_id="ig", label="Name")
        group.mount(tk_root)
        group.set_value("Alice")
        assert group.get_value() == "Alice"

    def test_validate_pass(self, tk_root: tk.Tk) -> None:
        """Валидация проходит."""
        group = InputGroup(widget_id="ig", label="Name", validator=lambda t: None)
        group.mount(tk_root)
        group.set_value("ok")
        assert group.validate() is True
        assert group._error_message is None

    def test_validate_fail(self, tk_root: tk.Tk) -> None:
        """Валидация не проходит — устанавливается ошибка."""
        group = InputGroup(widget_id="ig", label="Name", validator=lambda t: "bad")
        group.mount(tk_root)
        group.set_value("x")
        assert group.validate() is False
        assert group._error_message == "bad"

    def test_set_error_and_clear(self, tk_root: tk.Tk) -> None:
        """Ошибка устанавливается и очищается."""
        group = InputGroup(widget_id="ig", label="Name")
        group.mount(tk_root)
        group.set_error("msg")
        assert group._error_message == "msg"
        group.clear_error()
        assert group._error_message is None

    def test_mount_creates_widget(self, tk_root: tk.Tk) -> None:
        """mount возвращает Frame."""
        group = InputGroup(widget_id="ig", label="Name")
        w = group.mount(tk_root)
        assert isinstance(w, tk.Frame)
        assert group.is_mounted() is True

    def test_unmount_cleanup(self, tk_root: tk.Tk) -> None:
        """unmount освобождает ресурсы."""
        group = InputGroup(widget_id="ig", label="Name")
        group.mount(tk_root)
        group.unmount()
        assert group.is_mounted() is False
        assert group._entry_widget is None

    def test_focus_out_validates(self, tk_root: tk.Tk) -> None:
        """Потеря фокуса запускает валидацию."""
        validator = lambda t: "err" if not t else None  # noqa: E731
        group = InputGroup(widget_id="ig", label="Name", validator=validator)
        group.mount(tk_root)
        group._on_focus_out()
        assert group._error_message == "err"

    def test_key_release_clears_error(self, tk_root: tk.Tk) -> None:
        """Ввод очищает ошибку."""
        group = InputGroup(widget_id="ig", label="Name")
        group.mount(tk_root)
        group.set_error("err")
        group._on_key_release()
        assert group._error_message is None


# =============================================================================
# SearchBox
# =============================================================================


class TestSearchBox:
    """Тесты SearchBox."""

    def test_init(self) -> None:
        """Конструктор сохраняет параметры."""
        sb = SearchBox(widget_id="sb")
        assert sb.widget_id == "sb"
        assert sb._placeholder == "Search..."
        assert sb._debounce_ms == 300

    def test_get_text_empty(self, tk_root: tk.Tk) -> None:
        """Пустое поле возвращает пустую строку."""
        sb = SearchBox(widget_id="sb")
        sb.mount(tk_root)
        assert sb.get_text() == ""

    def test_clear(self, tk_root: tk.Tk) -> None:
        """clear очищает текст и вызывает on_search с пустой строкой."""
        cb = MagicMock()
        sb = SearchBox(widget_id="sb", on_search=cb)
        sb.mount(tk_root)
        sb.set_text("x")
        sb.clear()
        assert sb.get_text() == ""
        cb.assert_called_with("")

    def test_focus(self, tk_root: tk.Tk) -> None:
        """focus устанавливает фокус на entry (без ошибок)."""
        sb = SearchBox(widget_id="sb")
        sb.mount(tk_root)
        # focus() не выбрасывает ошибок
        sb.focus()
        assert sb._entry is not None

    def test_debounce_search(self, tk_root: tk.Tk) -> None:
        """Ввод текста запускает debounce поиск."""
        cb = MagicMock()
        sb = SearchBox(widget_id="sb", on_search=cb, debounce_ms=50)
        sb.mount(tk_root)
        sb._placeholder_active = False
        sb._entry.delete(0, tk.END)
        sb._entry.insert(0, "hello")
        sb._on_key_release()
        assert sb._after_id is not None

    def test_return_triggers_search(self, tk_root: tk.Tk) -> None:
        """Enter запускает поиск немедленно."""
        cb = MagicMock()
        sb = SearchBox(widget_id="sb", on_search=cb)
        sb.mount(tk_root)
        sb._placeholder_active = False
        sb._entry.delete(0, tk.END)
        sb._entry.insert(0, "test")
        sb._on_return()
        cb.assert_called_with("test")

    def test_unmount_cancels_after(self, tk_root: tk.Tk) -> None:
        """unmount отменяет запланированный after."""
        sb = SearchBox(widget_id="sb")
        sb.mount(tk_root)
        sb._after_id = sb._entry.after(1000, lambda: None)
        sb.unmount()
        assert sb._entry is None

    def test_set_text_not_mounted(self) -> None:
        """set_value для не смонтированного ничего не делает."""
        sb = SearchBox(widget_id="sb")
        # Просто проверяем что не выбрасывает
        sb.clear()


# =============================================================================
# StatusBadge
# =============================================================================


class TestStatusBadge:
    """Тесты StatusBadge."""

    def test_init(self) -> None:
        """Конструктор сохраняет параметры."""
        badge = StatusBadge(widget_id="sb", text="OK", variant="success")
        assert badge._text == "OK"
        assert badge._variant == "success"

    def test_init_bad_variant(self) -> None:
        """Неизвестный variant вызывает ValueError."""
        with pytest.raises(ValueError, match="Unknown variant"):
            StatusBadge(widget_id="sb", text="OK", variant="unknown")

    def test_set_text(self, tk_root: tk.Tk) -> None:
        """set_text обновляет текст."""
        badge = StatusBadge(widget_id="sb", text="OK")
        badge.mount(tk_root)
        badge.set_text("Done")
        assert badge._text == "Done"
        assert badge._label is not None
        assert str(badge._label.cget("text")) == "Done"

    def test_set_variant(self, tk_root: tk.Tk) -> None:
        """set_variant меняет цвета."""
        badge = StatusBadge(widget_id="sb", text="OK", variant="default")
        badge.mount(tk_root)
        badge.set_variant("error")
        assert badge._variant == "error"
        # Проверяем что цвет изменился
        assert str(badge._tk_widget.cget("bg")) == "#F44336"

    def test_set_variant_bad(self, tk_root: tk.Tk) -> None:
        """set_variant с неизвестным variant вызывает ValueError."""
        badge = StatusBadge(widget_id="sb", text="OK")
        badge.mount(tk_root)
        with pytest.raises(ValueError, match="Unknown variant"):
            badge.set_variant("bad")

    def test_unmount(self, tk_root: tk.Tk) -> None:
        """unmount очищает ссылки."""
        badge = StatusBadge(widget_id="sb", text="OK")
        badge.mount(tk_root)
        badge.unmount()
        assert badge._label is None


# =============================================================================
# ListTile
# =============================================================================


class TestListTile:
    """Тесты ListTile."""

    def test_init(self) -> None:
        """Конструктор сохраняет параметры."""
        tile = ListTile(widget_id="lt", title="Item")
        assert tile._title == "Item"
        assert tile._subtitle == ""
        assert tile._icon == ""
        assert tile._selected is False

    def test_set_title(self, tk_root: tk.Tk) -> None:
        """set_title обновляет текст."""
        tile = ListTile(widget_id="lt", title="Old")
        tile.mount(tk_root)
        tile.set_title("New")
        assert tile._title == "New"
        assert str(tile._title_label.cget("text")) == "New"

    def test_set_subtitle(self, tk_root: tk.Tk) -> None:
        """set_subtitle обновляет текст."""
        tile = ListTile(widget_id="lt", title="Item", subtitle="sub")
        tile.mount(tk_root)
        tile.set_subtitle("new sub")
        assert tile._subtitle_label is not None
        assert str(tile._subtitle_label.cget("text")) == "new sub"

    def test_set_icon(self, tk_root: tk.Tk) -> None:
        """set_icon обновляет иконку."""
        tile = ListTile(widget_id="lt", title="Item", icon="⭐")
        tile.mount(tk_root)
        tile.set_icon("⭐")
        assert str(tile._icon_label.cget("text")) == "⭐"

    def test_set_selected(self, tk_root: tk.Tk) -> None:
        """set_selected перекрашивает фон."""
        tile = ListTile(widget_id="lt", title="Item")
        tile.mount(tk_root)
        tile.set_selected(True)
        assert tile._selected is True
        assert str(tile._frame.cget("bg")) == "#E3F2FD"
        tile.set_selected(False)
        assert str(tile._frame.cget("bg")) == "#FFFFFF"

    def test_on_click(self, tk_root: tk.Tk) -> None:
        """Клик вызывает on_click callback."""
        cb = MagicMock()
        tile = ListTile(widget_id="lt", title="Item", on_click=cb)
        tile.mount(tk_root)
        tile._on_click_event()
        cb.assert_called_once()

    def test_hover_effects(self, tk_root: tk.Tk) -> None:
        """Hover меняет цвет фона когда не selected."""
        tile = ListTile(widget_id="lt", title="Item")
        tile.mount(tk_root)
        tile._on_enter()
        assert str(tile._frame.cget("bg")) == "#F5F5F5"
        tile._on_leave()
        assert str(tile._frame.cget("bg")) == "#FFFFFF"

    def test_unmount(self, tk_root: tk.Tk) -> None:
        """unmount очищает ссылки."""
        tile = ListTile(widget_id="lt", title="Item")
        tile.mount(tk_root)
        tile.unmount()
        assert tile._frame is None


# =============================================================================
# ExpandablePanel
# =============================================================================


class TestExpandablePanel:
    """Тесты ExpandablePanel."""

    def test_init(self) -> None:
        """Конструктор сохраняет параметры."""
        panel = ExpandablePanel(widget_id="ep", title="Panel", expanded=True)
        assert panel._title == "Panel"
        assert panel.is_expanded is True

    def test_mount_returns_frame(self, tk_root: tk.Tk) -> None:
        """mount возвращает Frame."""
        panel = ExpandablePanel(widget_id="ep", title="Panel")
        w = panel.mount(tk_root)
        assert isinstance(w, tk.Frame)

    def test_toggle(self, tk_root: tk.Tk) -> None:
        """toggle переключает состояние."""
        panel = ExpandablePanel(widget_id="ep", title="Panel", expanded=False)
        panel.mount(tk_root)
        panel.toggle()
        assert panel.is_expanded is True
        panel.toggle()
        assert panel.is_expanded is False

    def test_expand_and_collapse(self, tk_root: tk.Tk) -> None:
        """expand и collapse меняют состояние."""
        panel = ExpandablePanel(widget_id="ep", title="Panel", expanded=False)
        panel.mount(tk_root)
        panel.expand()
        assert panel.is_expanded is True
        panel.collapse()
        assert panel.is_expanded is False

    def test_set_content(self, tk_root: tk.Tk) -> None:
        """set_content устанавливает виджет в контент-фрейм."""
        panel = ExpandablePanel(widget_id="ep", title="Panel")
        panel.mount(tk_root)
        inner = tk.Label(tk_root, text="inner")
        panel.set_content(inner)
        assert panel._content is inner

    def test_unmount(self, tk_root: tk.Tk) -> None:
        """unmount очищает ссылки."""
        panel = ExpandablePanel(widget_id="ep", title="Panel")
        panel.mount(tk_root)
        panel.unmount()
        assert panel._content_frame is None


# =============================================================================
# IconButton
# =============================================================================


class TestIconButton:
    """Тесты IconButton."""

    def test_init(self) -> None:
        """Конструктор сохраняет параметры."""
        btn = IconButton(widget_id="ib", icon="⭐", tooltip="hint", size=20)
        assert btn._icon == "⭐"
        assert btn._tooltip_text == "hint"
        assert btn._size == 20

    def test_set_icon(self, tk_root: tk.Tk) -> None:
        """set_icon обновляет текст кнопки."""
        btn = IconButton(widget_id="ib", icon="⭐")
        btn.mount(tk_root)
        btn.set_icon("🌟")
        assert str(btn._button.cget("text")) == "🌟"

    def test_set_tooltip(self, tk_root: tk.Tk) -> None:
        """set_tooltip устанавливает новый текст подсказки."""
        btn = IconButton(widget_id="ib", icon="⭐")
        btn.mount(tk_root)
        btn.set_tooltip("new hint")
        assert btn._tooltip_text == "new hint"

    def test_command_executed(self, tk_root: tk.Tk) -> None:
        """Нажатие вызывает command callback."""
        cb = MagicMock()
        btn = IconButton(widget_id="ib", icon="⭐", command=cb)
        btn.mount(tk_root)
        btn._on_click()
        cb.assert_called_once()

    def test_no_command_ok(self, tk_root: tk.Tk) -> None:
        """Нажатие без команды не вызывает ошибок."""
        btn = IconButton(widget_id="ib", icon="⭐")
        btn.mount(tk_root)
        btn._on_click()  # no error

    def test_tooltip_show_hide(self, tk_root: tk.Tk) -> None:
        """show_tooltip и hide_tooltip управляют Toplevel."""
        btn = IconButton(widget_id="ib", icon="⭐", tooltip="hint")
        btn.mount(tk_root)
        btn._show_tooltip()
        assert btn._tooltip_window is not None
        btn._hide_tooltip()
        assert btn._tooltip_window is None

    def test_unmount_hides_tooltip(self, tk_root: tk.Tk) -> None:
        """unmount закрывает tooltip и очищает ссылки."""
        btn = IconButton(widget_id="ib", icon="⭐", tooltip="hint")
        btn.mount(tk_root)
        btn._show_tooltip()
        btn.unmount()
        assert btn._button is None


# =============================================================================
# ProgressIndicator
# =============================================================================


class TestProgressIndicator:
    """Тесты ProgressIndicator."""

    def test_init(self) -> None:
        """Конструктор сохраняет параметры."""
        pi = ProgressIndicator(widget_id="pi", show_text=True, determinate=True)
        assert pi._show_text is True
        assert pi._determinate is True

    def test_mount_returns_frame(self, tk_root: tk.Tk) -> None:
        """mount возвращает Frame."""
        pi = ProgressIndicator(widget_id="pi")
        w = pi.mount(tk_root)
        assert isinstance(w, tk.Frame)

    def test_set_progress(self, tk_root: tk.Tk) -> None:
        """set_progress обновляет значение."""
        pi = ProgressIndicator(widget_id="pi")
        pi.mount(tk_root)
        pi.set_progress(0.75, "Loading...")
        assert pi._progress == 0.75
        assert pi._status_text == "Loading..."

    def test_set_progress_clamps(self, tk_root: tk.Tk) -> None:
        """set_progress ограничивает значение 0–1."""
        pi = ProgressIndicator(widget_id="pi")
        pi.mount(tk_root)
        pi.set_progress(-0.5)
        assert pi._progress == 0.0
        pi.set_progress(1.5)
        assert pi._progress == 1.0

    def test_set_text(self, tk_root: tk.Tk) -> None:
        """set_text обновляет текст статуса."""
        pi = ProgressIndicator(widget_id="pi", show_text=True)
        pi.mount(tk_root)
        pi.set_text("Done")
        assert str(pi._label.cget("text")) == "Done"

    def test_set_indeterminate(self, tk_root: tk.Tk) -> None:
        """Индетерминированный режим запускается и останавливается."""
        pi = ProgressIndicator(widget_id="pi")
        pi.mount(tk_root)
        pi.set_indeterminate(True)
        assert pi._indeterminate_running is True
        pi.set_indeterminate(False)
        assert pi._indeterminate_running is False
        assert pi._after_id is None

    def test_unmount(self, tk_root: tk.Tk) -> None:
        """unmount останавляет анимацию и очищает ссылки."""
        pi = ProgressIndicator(widget_id="pi")
        pi.mount(tk_root)
        pi.set_indeterminate(True)
        pi.unmount()
        assert pi._canvas is None
        assert pi._indeterminate_running is False


# =============================================================================
# Module exports
# =============================================================================

__all__ = [
    "TestInputGroup",
    "TestSearchBox",
    "TestStatusBadge",
    "TestListTile",
    "TestExpandablePanel",
    "TestIconButton",
    "TestProgressIndicator",
]
