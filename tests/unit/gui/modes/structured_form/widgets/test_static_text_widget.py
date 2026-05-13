"""Тесты для StaticTextWidget.

Author: AI Agent
Date: 2026-05-04
"""

from __future__ import annotations

import tkinter as tk

import pytest
from src.documents.types.type_schema import CharSize, FieldDefinition, FieldType
from src.gui.modes.structured_form.widgets.static_text_widget import StaticTextWidget


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


class TestStaticTextWidget:
    """Тесты для StaticTextWidget."""

    @pytest.fixture
    def field_def(self) -> FieldDefinition:
        """Создаёт тестовое определение статического текста."""
        return FieldDefinition(
            field_id="static_header",
            field_type=FieldType.STATIC_TEXT,
            label="Заголовок",
            default_value="Платёжное поручение",
            required=False,
            readonly=True,
        )

    @pytest.fixture
    def widget(self, root: tk.Tk, field_def: FieldDefinition) -> StaticTextWidget:
        """Создаёт виджет для тестирования."""
        widget = StaticTextWidget(
            parent=root,
            field_def=field_def,
        )
        widget.mount(root)
        root.update_idletasks()
        return widget

    def test_widget_creation(self, widget: StaticTextWidget) -> None:
        """Тест создания виджета и отображения текста."""
        assert widget._label is not None
        assert widget.field_id == "static_header"
        assert widget.field_type == FieldType.STATIC_TEXT
        assert widget.get_value() == "Платёжное поручение"

    def test_default_value_as_text(self, root: tk.Tk) -> None:
        """Тест использования default_value как текста для отображения."""
        field_def = FieldDefinition(
            field_id="static_note",
            field_type=FieldType.STATIC_TEXT,
            label="Примечание",
            default_value="Текст примечания",
        )
        widget = StaticTextWidget(parent=root, field_def=field_def)
        widget.mount(root)
        assert widget.get_value() == "Текст примечания"
        assert widget._label is not None
        assert widget._label.cget("text") == "Текст примечания"

    def test_set_value_no_on_change(self, root: tk.Tk, field_def: FieldDefinition) -> None:
        """Тест что set_value не генерирует on_change."""
        calls: list[tuple[str, str]] = []

        def on_change(field_id: str, value: object) -> None:
            calls.append((field_id, str(value)))

        widget = StaticTextWidget(
            parent=root,
            field_def=field_def,
            on_change=on_change,
        )
        widget.mount(root)
        widget.set_value("Новый текст")
        assert widget.get_value() == "Новый текст"
        assert len(calls) == 0

    def test_charsize_double_height(self, root: tk.Tk) -> None:
        """Тест поддержки CharSize.DOUBLE_HEIGHT."""
        field_def = FieldDefinition(
            field_id="big_title",
            field_type=FieldType.STATIC_TEXT,
            label="Большой заголовок",
            default_value="ВНИМАНИЕ",
            char_size=CharSize.DOUBLE_HEIGHT,
        )
        widget = StaticTextWidget(parent=root, field_def=field_def)
        widget.mount(root)
        assert widget._label is not None
        font = widget._label.cget("font")
        if isinstance(font, str):
            parts = font.split()
            assert len(parts) >= 3
            assert parts[1] == "16"
        else:
            assert isinstance(font, tuple)
            assert font[1] == 16  # размер для DOUBLE_HEIGHT

    def test_charsize_double_width(self, root: tk.Tk) -> None:
        """Тест поддержки CharSize.DOUBLE_WIDTH."""
        field_def = FieldDefinition(
            field_id="wide_title",
            field_type=FieldType.STATIC_TEXT,
            label="Широкий заголовок",
            default_value="ВАЖНО",
            char_size=CharSize.DOUBLE_WIDTH,
        )
        widget = StaticTextWidget(parent=root, field_def=field_def)
        widget.mount(root)
        assert widget._label is not None
        font = widget._label.cget("font")
        if isinstance(font, str):
            parts = font.split()
            assert len(parts) >= 3
            assert parts[1] == "14"
            assert parts[2] == "bold"
        else:
            assert isinstance(font, tuple)
            assert font[1] == 14  # размер для DOUBLE_WIDTH
            assert font[2] == "bold"

    def test_charsize_normal(self, root: tk.Tk) -> None:
        """Тест CharSize.NORMAL — стандартный размер."""
        field_def = FieldDefinition(
            field_id="normal_text",
            field_type=FieldType.STATIC_TEXT,
            label="Обычный текст",
            default_value="Обычный",
            char_size=CharSize.NORMAL,
        )
        widget = StaticTextWidget(parent=root, field_def=field_def)
        widget.mount(root)
        assert widget._label is not None
        font = widget._label.cget("font")
        # Tkinter может возвращать строку в headless режиме
        if isinstance(font, str):
            parts = font.split()
            assert len(parts) >= 3
            assert parts[1] == "11"
            assert parts[2] == "normal"
        else:
            assert isinstance(font, tuple)
            assert font[1] == 11
            assert font[2] == "normal"

    def test_validate_always_true(self, widget: StaticTextWidget) -> None:
        """Статическое поле всегда валидно."""
        assert widget.validate() is True

    def test_wipe_sensitive_data(self, widget: StaticTextWidget) -> None:
        """Очистка чувствительных данных."""
        widget.set_value("Секретные данные")
        assert widget.get_value() == "Секретные данные"

        widget.wipe_sensitive_data()
        assert widget.get_value() == ""
        assert widget._label is not None
        assert widget._label.cget("text") == ""

    def test_fallback_label_when_no_default(self, root: tk.Tk) -> None:
        """Если default_value отсутствует — используется label."""
        field_def = FieldDefinition(
            field_id="no_default",
            field_type=FieldType.STATIC_TEXT,
            label="Текст по умолчанию",
        )
        widget = StaticTextWidget(parent=root, field_def=field_def)
        widget.mount(root)
        assert widget.get_value() == "Текст по умолчанию"
