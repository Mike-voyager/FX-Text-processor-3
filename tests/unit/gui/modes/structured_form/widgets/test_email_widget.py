"""Тесты для EmailWidget.

Author: Mike Voyager
Date: 2026-05-04
"""

from __future__ import annotations

import tkinter as tk
from typing import Any

import pytest

from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.modes.structured_form.widgets.email_widget import EmailWidget


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


class TestEmailWidget:
    """Тесты для EmailWidget."""

    @pytest.fixture
    def field_def(self) -> FieldDefinition:
        """Создаёт тестовое определение поля."""
        return FieldDefinition(
            field_id="email_test",
            field_type=FieldType.EMAIL,
            label="Email Field",
        )

    @pytest.fixture
    def widget(self, root: tk.Tk, field_def: FieldDefinition) -> EmailWidget:
        """Создаёт виджет для тестирования."""
        widget = EmailWidget(parent=root, field_def=field_def)
        widget.mount(root)
        root.update_idletasks()
        return widget

    def test_widget_creation(self, widget: EmailWidget) -> None:
        """Тест создания виджета."""
        assert widget._entry is not None
        assert widget.field_id == "email_test"
        assert widget.field_type == FieldType.EMAIL

    def test_get_set_value(self, widget: EmailWidget) -> None:
        """Тест получения/установки значения."""
        widget.set_value("user@example.com")
        assert widget.get_value() == "user@example.com"

        widget.set_value("")
        assert widget.get_value() == ""

    def test_validate_ok(self, widget: EmailWidget) -> None:
        """Тест валидации корректного email."""
        widget.set_value("user@example.com")
        assert widget.validate() is True

    def test_validate_invalid(self, widget: EmailWidget) -> None:
        """Тест валидации неверного email."""
        widget.set_value("not-an-email")
        assert widget.validate() is False

    def test_invalid_highlight(self, widget: EmailWidget) -> None:
        """Тест подсветки при невалидном email."""
        widget.set_value("bad-email")
        hb = widget._entry.cget("highlightbackground")
        assert "red" in str(hb)

    def test_valid_no_highlight(self, widget: EmailWidget) -> None:
        """Тест отсутствия подсветки при валидном email."""
        widget.set_value("good@domain.org")
        hb = widget._entry.cget("highlightbackground")
        assert "red" not in str(hb)

    def test_on_change_callback(self, root: tk.Tk, field_def: FieldDefinition) -> None:
        """Тест callback при изменении."""
        calls: list[tuple[str, Any]] = []

        def on_change(field_id: str, value: str) -> None:
            calls.append((field_id, value))

        widget = EmailWidget(
            parent=root,
            field_def=field_def,
            on_change=on_change,
        )
        widget.mount(root)
        widget.set_value("test@mail.ru")

        assert any(cid == "email_test" and val == "test@mail.ru" for cid, val in calls)

    def test_wipe_sensitive_data(self, widget: EmailWidget) -> None:
        """Тест очистки sensitive данных."""
        widget.set_value("secret@example.com")
        widget.wipe_sensitive_data()
        assert widget.get_value() == ""
        assert widget._value is None

    def test_required_empty(self, root: tk.Tk) -> None:
        """Тест валидации обязательного пустого поля."""
        field_def = FieldDefinition(
            field_id="email_req",
            field_type=FieldType.EMAIL,
            label="Required Email",
            required=True,
        )
        widget = EmailWidget(parent=root, field_def=field_def)
        widget.mount(root)
        assert widget.validate() is False

    def test_readonly_state(self, root: tk.Tk) -> None:
        """Тест readonly состояния."""
        field_def = FieldDefinition(
            field_id="email_ro",
            field_type=FieldType.EMAIL,
            label="Email",
            readonly=True,
        )
        widget = EmailWidget(parent=root, field_def=field_def)
        widget.mount(root)
        assert str(widget._entry.cget("state")) == "readonly"

    def test_focus(self, widget: EmailWidget) -> None:
        """Тест установки фокуса."""
        widget.focus()
        assert widget._entry is not None
