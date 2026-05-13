"""Unit-тесты для FormFieldFactory.

Проверяет:
- Создание FormField через фабрику
- Передача параметров в FormField
- Lazy import не вызывает circular import
- Тип результата соответствует FormFieldProtocol

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.components.factories.form_field_factory import create_form_field
from src.gui.core.protocols import FormFieldProtocol


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def text_field_def() -> FieldDefinition:
    """Создаёт тестовое текстовое поле."""
    return FieldDefinition(
        field_id="factory_test",
        field_type=FieldType.TEXT_INPUT,
        label="Фабричное поле",
        required=False,
        max_length=50,
    )


class TestCreateFormField:
    """Тесты для create_form_field factory."""

    def test_create_form_field_returns_instance(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Проверяет что фабрика возвращает FormField instance."""
        field = create_form_field(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )
        assert field is not None
        assert isinstance(field, FormFieldProtocol)

    def test_create_form_field_with_callbacks(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Проверяет передачу callbacks через фабрику."""
        on_change = MagicMock()
        on_validate = MagicMock()

        field = create_form_field(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
            on_change=on_change,
            on_validate=on_validate,
        )
        assert field is not None

    def test_create_form_field_value_management(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Проверяет set_value/get_value через созданный фабрикой виджет."""
        field = create_form_field(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )
        field.set_value("тестовое значение")
        assert field.get_value() == "тестовое значение"

    def test_create_form_field_validation(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Проверяет validate через созданный фабрикой виджет."""
        field = create_form_field(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )
        is_valid, error = field.validate()
        assert is_valid is True
        assert error is None

    def test_create_form_field_error_display(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Проверяет set_error/clear_error через созданный фабрикой виджет."""
        field = create_form_field(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )
        field.set_error("Ошибка")
        field.clear_error()

    def test_create_form_field_wipe(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Проверяет wipe_sensitive_data через созданный фабрикой виджет."""
        field = create_form_field(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )
        field.set_value("secret")
        field.wipe_sensitive_data()
        assert field.get_value() is None


class TestCircularImport:
    """Тесты для проверки отсутствия circular import."""

    def test_import_components_does_not_raise(self) -> None:
        """Проверяет что импорт components не вызывает circular import."""
        try:
            from src.gui.components import FormField  # noqa: F401
        except ImportError as e:
            pytest.fail(f"Circular import detected: {e}")

    def test_import_renderers_does_not_raise(self) -> None:
        """Проверяет что импорт renderers не вызывает circular import."""
        try:
            from src.gui.renderers import StructuredFormRenderer  # noqa: F401
        except ImportError as e:
            pytest.fail(f"Circular import detected: {e}")

    def test_factory_import_alone(self) -> None:
        """Проверяет что импорт фабрики не вызывает circular import."""
        try:
            from src.gui.components.factories.form_field_factory import create_form_field  # noqa: F401
        except ImportError as e:
            pytest.fail(f"Circular import detected: {e}")
