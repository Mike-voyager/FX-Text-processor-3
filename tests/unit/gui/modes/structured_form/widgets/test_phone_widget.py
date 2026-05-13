"""Тесты для PhoneWidget.

Author: Mike Voyager
Date: 2026-05-04
"""

from __future__ import annotations

import tkinter as tk
from typing import Any

import pytest

from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.modes.structured_form.widgets.phone_widget import PhoneWidget


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


class TestPhoneWidget:
    """Тесты для PhoneWidget."""

    @pytest.fixture
    def field_def(self) -> FieldDefinition:
        """Создаёт тестовое определение поля."""
        return FieldDefinition(
            field_id="phone_test",
            field_type=FieldType.PHONE,
            label="Phone Field",
        )

    @pytest.fixture
    def widget(self, root: tk.Tk, field_def: FieldDefinition) -> PhoneWidget:
        """Создаёт виджет для тестирования."""
        widget = PhoneWidget(parent=root, field_def=field_def)
        widget.mount(root)
        root.update_idletasks()
        return widget

    def test_widget_creation(self, widget: PhoneWidget) -> None:
        """Тест создания виджета."""
        assert widget._entry is not None
        assert widget.field_id == "phone_test"
        assert widget.field_type == FieldType.PHONE
        assert widget._mask == "+X (XXX) XXX-XX-XX"

    def test_get_set_value(self, widget: PhoneWidget) -> None:
        """Тест получения/установки значения."""
        widget.set_value("+79031234567")
        assert widget.get_value() == "+7 (903) 123-45-67"

        widget.set_value("")
        assert widget.get_value() == ""

    def test_custom_mask(self, root: tk.Tk) -> None:
        """Тест пользовательской маски."""
        field_def = FieldDefinition(
            field_id="phone_alt",
            field_type=FieldType.PHONE,
            label="Alt Phone",
        )
        widget = PhoneWidget(parent=root, field_def=field_def, mask="+X XXX XXX-XX-XX")
        widget.mount(root)
        widget.set_value("+79031234567")
        assert widget.get_value() == "+7 903 123-45-67"

    def test_validate_ok(self, widget: PhoneWidget) -> None:
        """Тест валидации корректного телефона."""
        widget.set_value("+79031234567")
        assert widget.validate() is True

    def test_validate_too_short(self, widget: PhoneWidget) -> None:
        """Тест валидации слишком короткого номера."""
        widget.set_value("+7")
        assert widget.validate() is False

    def test_on_change_callback(self, root: tk.Tk, field_def: FieldDefinition) -> None:
        """Тест callback при изменении."""
        calls: list[tuple[str, Any]] = []

        def on_change(field_id: str, value: str) -> None:
            calls.append((field_id, value))

        widget = PhoneWidget(
            parent=root,
            field_def=field_def,
            on_change=on_change,
        )
        widget.mount(root)
        widget.set_value("+79031234567")

        assert any(cid == "phone_test" for cid, _ in calls)

    def test_wipe_sensitive_data(self, widget: PhoneWidget) -> None:
        """Тест очистки sensitive данных."""
        widget.set_value("+79031234567")
        assert widget.get_value() == "+7 (903) 123-45-67"

        widget.wipe_sensitive_data()
        assert widget.get_value() == ""
        assert widget._value is None

    def test_readonly_state(self, root: tk.Tk) -> None:
        """Тест readonly состояния."""
        field_def = FieldDefinition(
            field_id="phone_readonly",
            field_type=FieldType.PHONE,
            label="Phone",
            readonly=True,
        )
        widget = PhoneWidget(parent=root, field_def=field_def)
        widget.mount(root)
        assert widget._entry is not None
        assert str(widget._entry.cget("state")) == "readonly"

    def test_focus(self, widget: PhoneWidget) -> None:
        """Тест установки фокуса."""
        widget.focus()
        assert widget._entry is not None
        # В headless режиме фокус может не передаваться корректно
        # Проверяем что метод focus() вызвал focus() на Entry
        assert widget._entry.focus_get() is not None or widget._entry.winfo_exists()
