"""Тесты для ToolbarSection.

Модуль содержит тесты для компонента секции панели инструментов,
используемого для группировки связанных элементов управления.
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.components.toolbar_section import ToolbarSection
from src.gui.core.exceptions import LifecycleError


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestToolbarSection:
    """Тестовый набор для ToolbarSection."""

    def test_section_initialization(self) -> None:
        """Тест инициализации секции."""
        section = ToolbarSection(widget_id="test_section", title="Файл")
        assert section.widget_id == "test_section"
        assert section._title == "Файл"
        assert not section.is_mounted()
        assert section.get_button_count() == 0

    def test_section_title(self, tk_root: tk.Tk) -> None:
        """Тест заголовка секции."""
        section = ToolbarSection(widget_id="test_section", title="Редактирование")
        section.mount(tk_root)
        try:
            assert section._title_label is not None
            label_text = section._title_label.cget("text")
            assert label_text == "Редактирование"
        finally:
            section.unmount()

    def test_add_widget_to_section(self) -> None:
        """Тест добавления кнопки в секцию."""
        section = ToolbarSection(widget_id="test_section")
        handler = MagicMock()
        section.add_button("save", "💾", "Сохранить", handler)
        assert section.get_button_count() == 1
        assert "save" in section._buttons

    def test_section_visibility(self, tk_root: tk.Tk) -> None:
        """Тест сворачивания и разворачивания секции."""
        section = ToolbarSection(
            widget_id="test_section", title="Секция", collapsible=True
        )
        section.mount(tk_root)
        try:
            assert not section.is_collapsed()
            section.set_collapsed(True)
            assert section.is_collapsed()
            section.set_collapsed(False)
            assert not section.is_collapsed()
        finally:
            section.unmount()

    def test_add_duplicate_button_raises(self) -> None:
        """Дублирующая кнопка вызывает ValueError."""
        section = ToolbarSection(widget_id="test_section")
        section.add_button("save", "💾", "Сохранить", lambda: None)
        with pytest.raises(ValueError, match="уже существует"):
            section.add_button("save", "💾", "Сохранить", lambda: None)

    def test_add_button_non_callable_raises(self) -> None:
        """Некорректный command вызывает TypeError."""
        section = ToolbarSection(widget_id="test_section")
        with pytest.raises(TypeError, match="callable"):
            section.add_button("save", "💾", "Сохранить", "not_callable")  # type: ignore[arg-type]

    def test_remove_button(self) -> None:
        """Тест удаления кнопки."""
        section = ToolbarSection(widget_id="test_section")
        section.add_button("save", "💾", "Сохранить", lambda: None)
        section.remove_button("save")
        assert section.get_button_count() == 0

    def test_remove_unknown_button_raises(self) -> None:
        """Удаление несуществующей кнопки вызывает ValueError."""
        section = ToolbarSection(widget_id="test_section")
        with pytest.raises(ValueError, match="не найдена"):
            section.remove_button("missing")

    def test_set_button_enabled(self, tk_root: tk.Tk) -> None:
        """Тест включения/отключения кнопки."""
        section = ToolbarSection(widget_id="test_section")
        section.add_button("save", "💾", "Сохранить", lambda: None)
        section.mount(tk_root)
        try:
            section.set_button_enabled("save", False)
            button = section._buttons["save"][0]
            assert button is not None
            state = button.cget("state")
            assert state == "disabled"
            section.set_button_enabled("save", True)
            state = button.cget("state")
            assert state == "normal"
        finally:
            section.unmount()

    def test_set_button_text(self, tk_root: tk.Tk) -> None:
        """Тест изменения текста кнопки."""
        section = ToolbarSection(widget_id="test_section")
        section.add_button("save", "💾", "Сохранить", lambda: None)
        section.mount(tk_root)
        try:
            section.set_button_text("save", "Сохранить *")
            button = section._buttons["save"][0]
            assert button is not None
            assert "Сохранить *" in button.cget("text")
        finally:
            section.unmount()

    def test_clear_buttons(self, tk_root: tk.Tk) -> None:
        """Тест очистки всех кнопок и разделителей."""
        section = ToolbarSection(widget_id="test_section")
        section.add_button("a", "A", "A", lambda: None)
        section.add_separator()
        section.add_button("b", "B", "B", lambda: None)
        section.mount(tk_root)
        try:
            assert section.get_button_count() == 2
            assert len(section._separators) == 1
            section.clear()
            assert section.get_button_count() == 0
            assert len(section._separators) == 0
        finally:
            section.unmount()


class TestToolbarSectionStyling:
    """Тесты стилизации секции панели."""

    def test_separator_style(self, tk_root: tk.Tk) -> None:
        """Тест добавления разделителя."""
        section = ToolbarSection(widget_id="test_section")
        section.add_separator()
        section.mount(tk_root)
        try:
            assert len(section._separators) == 1
            sep = section._separators[0]
            assert sep is not None
            assert isinstance(sep, tk.Frame)
        finally:
            section.unmount()

    def test_collapsible_state(self, tk_root: tk.Tk) -> None:
        """Тест сворачивания/разворачивания."""
        section = ToolbarSection(
            widget_id="test_section", title="Collapsible", collapsible=True
        )
        section.mount(tk_root)
        try:
            assert not section.is_collapsed()
            section.set_collapsed(True)
            assert section.is_collapsed()
            section._toggle_collapse()
            assert not section.is_collapsed()
            section._toggle_collapse()
            assert section.is_collapsed()
        finally:
            section.unmount()

    def test_collapsible_without_title_is_ignored(self, tk_root: tk.Tk) -> None:
        """Сворачивание без заголовка игнорируется."""
        section = ToolbarSection(
            widget_id="test_section", title="", collapsible=True
        )
        section.mount(tk_root)
        try:
            assert not section._collapsible
            section.set_collapsed(True)
            assert not section.is_collapsed()
        finally:
            section.unmount()

    def test_icon_size_consistency(self, tk_root: tk.Tk) -> None:
        """Тест консистентности текста кнопок."""
        section = ToolbarSection(widget_id="test_section")
        section.add_button("a", "A", "Alpha", lambda: None)
        section.add_button("b", "B", "Beta", lambda: None)
        section.mount(tk_root)
        try:
            for name, (btn, icon, text, _cmd) in section._buttons.items():
                assert btn is not None
                full_text = btn.cget("text")
                assert icon in full_text
                assert text in full_text
        finally:
            section.unmount()


class TestToolbarSectionIntegration:
    """Тесты интеграции секции панели."""

    def test_section_in_main_toolbar(self, tk_root: tk.Tk) -> None:
        """Тест размещения в главной панели."""
        toolbar = tk.Frame(tk_root)
        section = ToolbarSection(widget_id="file_section", title="Файл")
        section.add_button("open", "📂", "Открыть", lambda: None)
        section.add_separator()
        section.add_button("save", "💾", "Сохранить", lambda: None)
        widget = section.mount(toolbar)
        try:
            assert widget is not None
            assert widget.winfo_exists()
            assert section.get_button_count() == 2
        finally:
            section.unmount()

    def test_section_event_propagation(self, tk_root: tk.Tk) -> None:
        """Тест распространения событий к контроллеру."""
        controller = MagicMock()
        controller.dispatch = MagicMock()
        section = ToolbarSection(
            widget_id="test_section", title="События", controller=controller
        )
        section.mount(tk_root)
        try:
            calls = controller.dispatch.call_args_list
            actions = [call.args[0] for call in calls]
            assert "widget_mounted" in actions
        finally:
            section.unmount()

    def test_dynamic_widget_addition(self, tk_root: tk.Tk) -> None:
        """Тест динамического добавления кнопок после монтирования."""
        section = ToolbarSection(widget_id="test_section")
        section.add_button("pre", "P", "Pre", lambda: None)
        section.mount(tk_root)
        try:
            assert section.get_button_count() == 1
            section.add_button("post", "P", "Post", lambda: None)
            assert section.get_button_count() == 2
            widget = section._buttons["post"][0]
            assert widget is not None
            assert widget.winfo_exists()
        finally:
            section.unmount()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.components.toolbar_section"])
