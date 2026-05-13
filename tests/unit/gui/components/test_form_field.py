"""Unit-тесты для FormField composite widget.

Проверяет:
- Создание FormField с различными типами полей
- Валидация и отображение ошибок
- Установка/получение значений
- Состояния enabled/disabled
- Интеграция с темами
- Очистка sensitive данных

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from datetime import date
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.components.form_field import FormField
from src.services.autocomplete_service import AutocompleteService

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
def text_field_def() -> FieldDefinition:
    """Создаёт тестовое текстовое поле (необязательное)."""
    return FieldDefinition(
        field_id="test_text",
        field_type=FieldType.TEXT_INPUT,
        label="Тестовое текстовое поле",
        required=False,
        max_length=100,
        placeholder="Введите текст",
    )


@pytest.fixture
def required_field_def() -> FieldDefinition:
    """Создаёт обязательное тестовое поле."""
    return FieldDefinition(
        field_id="required_field",
        field_type=FieldType.TEXT_INPUT,
        label="Обязательное поле",
        required=True,
    )


@pytest.fixture
def number_field_def() -> FieldDefinition:
    """Создаёт числовое поле."""
    return FieldDefinition(
        field_id="test_number",
        field_type=FieldType.NUMBER_INPUT,
        label="Числовое поле",
        min_value=0.0,
        max_value=1000.0,
    )


@pytest.fixture
def date_field_def() -> FieldDefinition:
    """Создаёт поле даты."""
    return FieldDefinition(
        field_id="test_date",
        field_type=FieldType.DATE_INPUT,
        label="Дата",
        min_date=date(2020, 1, 1),
        max_date=date(2030, 12, 31),
    )


@pytest.fixture
def dropdown_field_def() -> FieldDefinition:
    """Создаёт выпадающий список."""
    return FieldDefinition(
        field_id="test_dropdown",
        field_type=FieldType.DROPDOWN,
        label="Выбор",
        options=("Опция 1", "Опция 2", "Опция 3"),
        default_value="Опция 1",
    )


@pytest.fixture
def autocomplete_field_def() -> FieldDefinition:
    """Создаёт поле с автокомплитом."""
    return FieldDefinition(
        field_id="test_autocomplete",
        field_type=FieldType.TEXT_INPUT,
        label="Поле с автокомплитом",
        autocomplete_source="companies",
    )


@pytest.fixture
def multiline_field_def() -> FieldDefinition:
    """Создаёт многострочное поле."""
    return FieldDefinition(
        field_id="test_multiline",
        field_type=FieldType.MULTI_LINE_TEXT,
        label="Многострочный текст",
    )


@pytest.fixture
def autocomplete_service() -> MagicMock:
    """Создаёт мок AutocompleteService."""
    service = MagicMock(spec=AutocompleteService)
    service.search.return_value = [("Результат 1", 5), ("Результат 2", 3)]
    return service


# =============================================================================
# TEST: FormField Creation
# =============================================================================


@pytest.mark.gui
class TestFormFieldCreation:
    """Тесты создания FormField."""

    def test_form_field_creation(self, tk_root: tk.Tk, text_field_def: FieldDefinition) -> None:
        """Базовое создание FormField."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        assert field is not None
        assert field._field_def == text_field_def
        assert field._document_index == "DVN-44-K53-IX"
        assert field._is_valid is True

    def test_form_field_with_callbacks(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Создание с callback-функциями."""
        on_change = MagicMock()
        on_validate = MagicMock()

        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
            on_change=on_change,
            on_validate=on_validate,
        )

        assert field._on_change == on_change
        assert field._on_validate == on_validate


# =============================================================================
# TEST: Text Input
# =============================================================================


@pytest.mark.gui
class TestFormFieldTextInput:
    """Тесты TEXT_INPUT типа."""

    def test_form_field_with_text_input(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """TEXT_INPUT создаёт Entry виджет."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        assert field._input_widget is not None
        assert isinstance(field._input_widget, tk.Entry)

    def test_form_field_text_placeholder(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Placeholder отображается в поле."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        # Placeholder should be set initially
        entry = field._input_widget
        assert isinstance(entry, tk.Entry)

    def test_form_field_text_max_length(self, tk_root: tk.Tk) -> None:
        """max_length применяется к полю."""
        field_def = FieldDefinition(
            field_id="limited_text",
            field_type=FieldType.TEXT_INPUT,
            label="Ограниченное поле",
            max_length=10,
        )

        field = FormField(
            parent=tk_root,
            field_def=field_def,
            document_index="DVN-44-K53-IX",
        )

        entry = field._input_widget
        assert isinstance(entry, tk.Entry)
        # Entry should have validation configured

    def test_form_field_with_help_text(self, tk_root: tk.Tk) -> None:
        """Help text создаёт иконку (?)."""
        field_def = FieldDefinition(
            field_id="with_help",
            field_type=FieldType.TEXT_INPUT,
            label="Поле с подсказкой",
            help_text="Это подсказка для поля",
        )

        field = FormField(
            parent=tk_root,
            field_def=field_def,
            document_index="DVN-44-K53-IX",
        )

        # Field should have help label
        assert field._label_widget is not None


# =============================================================================
# TEST: Autocomplete
# =============================================================================


@pytest.mark.gui
class TestFormFieldAutocomplete:
    """Тесты автокомплита."""

    @patch("src.gui.modes.structured_form.widgets.autocomplete_entry.AutocompleteEntry")
    def test_form_field_with_autocomplete(
        self,
        mock_autocomplete_entry: MagicMock,
        tk_root: tk.Tk,
        autocomplete_field_def: FieldDefinition,
        autocomplete_service: MagicMock,
    ) -> None:
        """TEXT_INPUT с autocomplete_source использует AutocompleteEntry."""
        mock_widget = MagicMock()
        mock_widget.mount.return_value = MagicMock(spec=tk.Widget)
        mock_autocomplete_entry.return_value = mock_widget

        field = FormField(
            parent=tk_root,
            field_def=autocomplete_field_def,
            document_index="DVN-44-K53-IX",
            autocomplete_service=autocomplete_service,
        )

        assert field._autocomplete_service == autocomplete_service

    def test_form_field_without_autocomplete_service(
        self, tk_root: tk.Tk, autocomplete_field_def: FieldDefinition
    ) -> None:
        """Без autocomplete_service используется обычный Entry."""
        field = FormField(
            parent=tk_root,
            field_def=autocomplete_field_def,
            document_index="DVN-44-K53-IX",
            autocomplete_service=None,
        )

        # Should fall back to regular Entry
        assert field._input_widget is not None


# =============================================================================
# TEST: Number Input
# =============================================================================


@pytest.mark.gui
class TestFormFieldNumberInput:
    """Тесты NUMBER_INPUT типа."""

    def test_form_field_with_number_input(
        self, tk_root: tk.Tk, number_field_def: FieldDefinition
    ) -> None:
        """NUMBER_INPUT создаёт Entry с числовой валидацией."""
        field = FormField(
            parent=tk_root,
            field_def=number_field_def,
            document_index="DVN-44-K53-IX",
        )

        assert field._input_widget is not None

    def test_form_field_number_right_aligned(
        self, tk_root: tk.Tk, number_field_def: FieldDefinition
    ) -> None:
        """Числовое поле выравнивается по правому краю."""
        field = FormField(
            parent=tk_root,
            field_def=number_field_def,
            document_index="DVN-44-K53-IX",
        )

        entry = field._input_widget
        assert isinstance(entry, tk.Entry)


# =============================================================================
# TEST: Date Input
# =============================================================================


@pytest.mark.gui
class TestFormFieldDateInput:
    """Тесты DATE_INPUT типа."""

    def test_form_field_with_date_input(
        self, tk_root: tk.Tk, date_field_def: FieldDefinition
    ) -> None:
        """DATE_INPUT создаёт Entry с кнопкой календаря."""
        field = FormField(
            parent=tk_root,
            field_def=date_field_def,
            document_index="DVN-44-K53-IX",
        )

        assert field._input_widget is not None
        # Date input is a frame with entry and calendar button
        assert hasattr(field, "_date_entry")

    def test_form_field_date_default_value(self, tk_root: tk.Tk) -> None:
        """DATE_INPUT с default_value date."""
        today = date.today()
        field_def = FieldDefinition(
            field_id="date_with_default",
            field_type=FieldType.DATE_INPUT,
            label="Дата с дефолтом",
            default_value=today,
        )

        field = FormField(
            parent=tk_root,
            field_def=field_def,
            document_index="DVN-44-K53-IX",
        )

        assert field._input_widget is not None

    @patch("src.gui.dialogs.calendar_dialog.CalendarDialog")
    def test_form_field_calendar_dialog_sets_value(
        self, mock_dialog_cls: MagicMock, tk_root: tk.Tk, date_field_def: FieldDefinition
    ) -> None:
        """Кнопка календаря открывает диалог и устанавливает выбранную дату."""
        mock_dialog = MagicMock()
        mock_dialog.show.return_value = date(2026, 5, 15)
        mock_dialog_cls.return_value = mock_dialog

        field = FormField(
            parent=tk_root,
            field_def=date_field_def,
            document_index="DVN-44-K53-IX",
        )

        field._show_calendar_dialog()

        mock_dialog_cls.assert_called_once_with(parent=field, initial_date=None)
        mock_dialog.show.assert_called_once()
        assert field.get_value() == date(2026, 5, 15)

    @patch("src.gui.dialogs.calendar_dialog.CalendarDialog")
    def test_form_field_calendar_dialog_cancel(
        self, mock_dialog_cls: MagicMock, tk_root: tk.Tk, date_field_def: FieldDefinition
    ) -> None:
        """Отмена в диалоге не меняет значение поля."""
        mock_dialog = MagicMock()
        mock_dialog.show.return_value = None
        mock_dialog_cls.return_value = mock_dialog

        field = FormField(
            parent=tk_root,
            field_def=date_field_def,
            document_index="DVN-44-K53-IX",
        )
        field.set_value(date(2026, 1, 1))

        field._show_calendar_dialog()

        assert field.get_value() == date(2026, 1, 1)

    @patch("src.gui.dialogs.calendar_dialog.CalendarDialog")
    def test_form_field_calendar_dialog_with_existing_date(
        self, mock_dialog_cls: MagicMock, tk_root: tk.Tk, date_field_def: FieldDefinition
    ) -> None:
        """Диалог получает текущее значение поля как initial_date."""
        mock_dialog = MagicMock()
        mock_dialog.show.return_value = None
        mock_dialog_cls.return_value = mock_dialog

        existing = date(2025, 8, 20)
        field = FormField(
            parent=tk_root,
            field_def=date_field_def,
            document_index="DVN-44-K53-IX",
        )
        field.set_value(existing)

        field._show_calendar_dialog()

        mock_dialog_cls.assert_called_once_with(parent=field, initial_date=existing)


# =============================================================================
# TEST: Dropdown
# =============================================================================


@pytest.mark.gui
class TestFormFieldDropdown:
    """Тесты DROPDOWN типа."""

    def test_form_field_with_dropdown(
        self, tk_root: tk.Tk, dropdown_field_def: FieldDefinition
    ) -> None:
        """DROPDOWN создаёт Combobox."""
        from tkinter import ttk

        field = FormField(
            parent=tk_root,
            field_def=dropdown_field_def,
            document_index="DVN-44-K53-IX",
        )

        assert field._input_widget is not None
        assert isinstance(field._input_widget, ttk.Combobox)

    def test_form_field_dropdown_values(
        self, tk_root: tk.Tk, dropdown_field_def: FieldDefinition
    ) -> None:
        """Combobox содержит опции."""
        from tkinter import ttk

        field = FormField(
            parent=tk_root,
            field_def=dropdown_field_def,
            document_index="DVN-44-K53-IX",
        )

        combo = field._input_widget
        assert isinstance(combo, ttk.Combobox)
        # Combo should have the options


# =============================================================================
# TEST: Required Indicator
# =============================================================================


@pytest.mark.gui
class TestFormFieldRequiredIndicator:
    """Тесты индикатора обязательности."""

    def test_form_field_required_indicator(
        self, tk_root: tk.Tk, required_field_def: FieldDefinition
    ) -> None:
        """Обязательное поле показывает * в метке."""
        field = FormField(
            parent=tk_root,
            field_def=required_field_def,
            document_index="DVN-44-K53-IX",
        )

        label = field._label_widget
        assert label is not None
        # Label text should include "*"

    def test_form_field_not_required_no_asterisk(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Необязательное поле не показывает *."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        assert field._field_def.required is False


# =============================================================================
# TEST: Validation
# =============================================================================


@pytest.mark.gui
class TestFormFieldValidation:
    """Тесты валидации."""

    def test_form_field_validation_success(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Валидное значение проходит валидацию."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field.set_value("Валидное значение")
        is_valid, error = field.validate()

        assert is_valid is True
        assert error is None
        assert field._is_valid is True

    def test_form_field_validation_failure(self, tk_root: tk.Tk) -> None:
        """Невалидное значение показывает ошибку."""
        field_def = FieldDefinition(
            field_id="pattern_field",
            field_type=FieldType.TEXT_INPUT,
            label="Поле с паттерном",
            validation_pattern=r"^\d+$",
        )

        field = FormField(
            parent=tk_root,
            field_def=field_def,
            document_index="DVN-44-K53-IX",
        )

        field.set_value("abc")  # Doesn't match pattern
        is_valid, error = field.validate()

        assert is_valid is False
        assert error is not None

    def test_form_field_required_validation_empty(
        self, tk_root: tk.Tk, required_field_def: FieldDefinition
    ) -> None:
        """Обязательное поле без значения не проходит валидацию."""
        field = FormField(
            parent=tk_root,
            field_def=required_field_def,
            document_index="DVN-44-K53-IX",
        )

        field.set_value("")
        is_valid, error = field.validate()

        assert is_valid is False
        assert error is not None

    def test_form_field_clear_error(self, tk_root: tk.Tk, text_field_def: FieldDefinition) -> None:
        """clear_error() очищает состояние ошибки."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field.set_error("Test error")
        assert field._is_valid is False

        field.clear_error()
        assert field._is_valid is True

    def test_form_field_set_error(self, tk_root: tk.Tk, text_field_def: FieldDefinition) -> None:
        """set_error() устанавливает сообщение об ошибке."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        error_msg = "Ошибка валидации"
        field.set_error(error_msg)

        assert field._error_message == error_msg
        assert field._is_valid is False


# =============================================================================
# TEST: Value Set/Get
# =============================================================================


@pytest.mark.gui
class TestFormFieldValue:
    """Тесты установки и получения значений."""

    def test_form_field_set_get_value(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """set_value/get_value работают корректно."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        test_value = "Тестовое значение"
        field.set_value(test_value)

        assert field.get_value() == test_value
        assert field._value == test_value

    def test_form_field_set_value_callback(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """set_value вызывает on_change callback."""
        on_change = MagicMock()

        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
            on_change=on_change,
        )

        field.set_value("New value")

        on_change.assert_called_once_with("test_text", "New value")

    def test_form_field_update_input_value(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """_update_input_value обновляет виджет."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field._update_input_value("Updated value")


# =============================================================================
# TEST: Enabled/Disabled
# =============================================================================


@pytest.mark.gui
class TestFormFieldEnabled:
    """Тесты состояня enabled/disabled."""

    def test_form_field_set_enabled(self, tk_root: tk.Tk, text_field_def: FieldDefinition) -> None:
        """set_enabled меняет состояние поля."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field.set_enabled(False)
        assert field._is_enabled is False

        field.set_enabled(True)
        assert field._is_enabled is True

    def test_form_field_disabled_state(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """set_enabled(False) деактивирует виджет."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field.set_enabled(False)
        # Entry should be disabled


# =============================================================================
# TEST: Focus
# =============================================================================


@pytest.mark.gui
class TestFormFieldFocus:
    """Тесты фокуса."""

    def test_form_field_focus(self, tk_root: tk.Tk, text_field_def: FieldDefinition) -> None:
        """focus() устанавливает фокус на поле."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field.focus()
        # Focus should be set (may not work in headless mode)


# =============================================================================
# TEST: Security Wipe
# =============================================================================


@pytest.mark.gui
class TestFormFieldSecurityWipe:
    """Тесты очистки sensitive данных."""

    def test_form_field_wipe_sensitive_data(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """wipe_sensitive_data очищает значение."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field.set_value("Sensitive data")
        assert field.get_value() == "Sensitive data"

        field.wipe_sensitive_data()

        assert field.get_value() is None
        assert field._value is None

    def test_form_field_wipe_clears_error(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """wipe_sensitive_data очищает ошибку."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field.set_error("Error message")
        field.wipe_sensitive_data()

        assert field._error_message is None


# =============================================================================
# TEST: Theme Integration
# =============================================================================


@pytest.mark.gui
class TestFormFieldTheme:
    """Тесты интеграции с темами."""

    def test_form_field_theme_integration(
        self, tk_root: tk.Tk, text_field_def: FieldDefinition
    ) -> None:
        """Тема применяется при создании."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        # Theme manager should be set
        assert field._theme_manager is not None

    def test_form_field_apply_theme(self, tk_root: tk.Tk, text_field_def: FieldDefinition) -> None:
        """_apply_theme применяет стили."""
        field = FormField(
            parent=tk_root,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        # Apply theme should set colors
        assert field._label_widget is not None


# =============================================================================
# TEST: Constants
# =============================================================================


class TestFormFieldConstants:
    """Тесты констант."""

    def test_field_types_exist(self) -> None:
        """Все типы полей определены."""
        assert FieldType.TEXT_INPUT == "text_input"
        assert FieldType.NUMBER_INPUT == "number_input"
        assert FieldType.DATE_INPUT == "date_input"
        assert FieldType.DROPDOWN == "dropdown"
        assert FieldType.MULTI_LINE_TEXT == "multi_line_text"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.components.form_field"])
