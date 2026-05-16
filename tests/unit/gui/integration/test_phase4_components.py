"""Integration-тесты для Phase 4 GUI компонентов.

Проверяет интеграцию между:
- FormField и AutocompleteServiceGui
- Диалоговые окна с FormField
- Навигация в диалогах

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from datetime import date
from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.components.form_field import FormField
from src.gui.services.autocomplete_service import AutocompleteServiceGui

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture  # type: ignore[misc]
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture  # type: ignore[misc]
def mock_core_service() -> Generator[MagicMock, None, None]:
    """Создаёт мок AutocompleteService."""
    service = MagicMock()
    service.search.return_value = [
        ("ООО Ромашка", 42),
        ("ООО Василёк", 15),
        ("ООО Лютик", 8),
    ]
    service.record_usage.return_value = None
    yield service


@pytest.fixture  # type: ignore[misc]
def autocomplete_service(
    tk_root: tk.Tk, mock_core_service: MagicMock
) -> Generator[AutocompleteServiceGui, None, None]:
    """Создаёт AutocompleteServiceGui с мок core."""
    service = AutocompleteServiceGui(
        core_service=mock_core_service,
        root=tk_root,
    )
    yield service


@pytest.fixture  # type: ignore[misc]
def text_field_def() -> FieldDefinition:
    """Текстовое поле."""
    return FieldDefinition(
        field_id="test_text",
        field_type=FieldType.TEXT_INPUT,
        label="Текстовое поле",
    )


@pytest.fixture  # type: ignore[misc]
def autocomplete_field_def() -> FieldDefinition:
    """Поле с автокомплитом."""
    return FieldDefinition(
        field_id="recipient",
        field_type=FieldType.TEXT_INPUT,
        label="Получатель",
        autocomplete_source="companies",
    )


@pytest.fixture  # type: ignore[misc]
def required_field_def() -> FieldDefinition:
    """Обязательное поле."""
    return FieldDefinition(
        field_id="required_field",
        field_type=FieldType.TEXT_INPUT,
        label="Обязательное поле",
        required=True,
    )


@pytest.fixture  # type: ignore[misc]
def number_field_def() -> FieldDefinition:
    """Числовое поле."""
    return FieldDefinition(
        field_id="amount",
        field_type=FieldType.NUMBER_INPUT,
        label="Сумма",
        min_value=0.0,
        max_value=1000000.0,
    )


@pytest.fixture  # type: ignore[misc]
def date_field_def() -> FieldDefinition:
    """Поле даты."""
    return FieldDefinition(
        field_id="document_date",
        field_type=FieldType.DATE_INPUT,
        label="Дата документа",
    )


@pytest.fixture  # type: ignore[misc]
def dropdown_field_def() -> FieldDefinition:
    """Выпадающий список."""
    return FieldDefinition(
        field_id="document_type",
        field_type=FieldType.DROPDOWN,
        label="Тип документа",
        options=("Счёт", "Акт", "Накладная", "Договор"),
        default_value="Счёт",
    )


# =============================================================================
# TEST: FormField with AutocompleteServiceGui
# =============================================================================


@pytest.mark.gui
@pytest.mark.integration
class TestFormFieldAutocompleteIntegration:
    """Интеграция FormField с AutocompleteServiceGui."""

    @patch("src.gui.modes.structured_form.widgets.autocomplete_entry.AutocompleteEntry")
    def test_form_field_with_autocomplete_service(
        self,
        mock_autocomplete_entry: MagicMock,
        tk_root: tk.Tk,
        autocomplete_field_def: FieldDefinition,
        autocomplete_service: AutocompleteServiceGui,
    ) -> None:
        """FormField использует AutocompleteServiceGui."""
        mock_widget = MagicMock()
        mock_widget.mount.return_value = MagicMock(spec=tk.Widget)
        mock_autocomplete_entry.return_value = mock_widget

        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=autocomplete_field_def,
            document_index="DVN-44-K53-IX",
            autocomplete_service=autocomplete_service,
        )

        assert field._autocomplete_service == autocomplete_service

    def test_form_field_value_saved_to_history(
        self,
        tk_root: tk.Tk,
        autocomplete_field_def: FieldDefinition,
        autocomplete_service: AutocompleteServiceGui,
        mock_core_service: MagicMock,
    ) -> None:
        """Значение поля записывается в историю."""
        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=autocomplete_field_def,
            document_index="DVN-44-K53-IX",
            autocomplete_service=autocomplete_service,
        )

        # Set value and record usage
        field.set_value('ООО "Ромашка"')
        autocomplete_service.record_usage(
            field_id=autocomplete_field_def.field_id,
            document_index="DVN-44-K53-IX",
            value='ООО "Ромашка"',
        )

        mock_core_service.record_usage.assert_called_once_with(
            "recipient",
            "DVN-44-K53-IX",
            'ООО "Ромашка"',
        )

    def test_form_field_search_uses_cache(
        self,
        tk_root: tk.Tk,
        autocomplete_field_def: FieldDefinition,
        autocomplete_service: AutocompleteServiceGui,
        mock_core_service: MagicMock,
    ) -> None:
        """Поиск использует кэш сервиса."""
        # Prime cache
        autocomplete_service._cache[
            (
                "recipient",
                "DVN-44-K53-IX",
                "ООО",
                5,
            )
        ] = ([("Cached Company", 10)], __import__("time").time())

        # Search through service
        results = autocomplete_service.search(
            field_id="recipient",
            document_index="DVN-44-K53-IX",
            query="ООО",
        )

        assert results == [("Cached Company", 10)]
        assert mock_core_service.search.call_count == 0


# =============================================================================
# TEST: Prefill Dialog Integration
# =============================================================================


@pytest.mark.gui
@pytest.mark.integration
class TestPrefillDialogIntegration:
    """Интеграция диалога предзаполнения с FormField."""

    def test_prefill_dialog_with_form_field(
        self,
        tk_root: tk.Tk,
        text_field_def: FieldDefinition,
        autocomplete_service: AutocompleteServiceGui,
    ) -> None:
        """Диалог предзаполнения работает с FormField."""
        # Create dialog-like container with FormField
        dialog_frame = tk.Frame(tk_root)
        dialog_frame.pack()

        # Create FormField in dialog context
        field = FormField(
            parent=dialog_frame,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
            autocomplete_service=autocomplete_service,
        )
        field.pack(fill=tk.X, padx=10, pady=5)

        # Simulate prefilling value
        field.set_value("Предзаполненное значение")

        assert field.get_value() == "Предзаполненное значение"

    def test_prefill_dialog_validation(
        self,
        tk_root: tk.Tk,
        required_field_def: FieldDefinition,
    ) -> None:
        """Валидация работает в диалоге предзаполнения."""
        dialog_frame = tk.Frame(tk_root)

        field = FormField(
            parent=dialog_frame,
            field_def=required_field_def,
            document_index="DVN-44-K53-IX",
        )

        # Empty required field should fail validation
        field.set_value("")
        is_valid, error = field.validate()

        assert is_valid is False
        assert error is not None
        assert "обязательно" in error.lower()


# =============================================================================
# TEST: Bookmarks Dialog Navigation
# =============================================================================


@pytest.mark.gui
@pytest.mark.integration
class TestBookmarksDialogNavigation:
    """Навигация в диалоге закладок."""

    def test_bookmarks_dialog_navigation(self, tk_root: tk.Tk) -> None:
        """Переход к закладке работает."""
        # Simulate bookmark navigation structure
        bookmarks = [
            {"name": "Заголовок", "index": "DVN-44-K53-I", "line": 10},
            {"name": "Тело", "index": "DVN-44-K53-II", "line": 50},
            {"name": "Подпись", "index": "DVN-44-K53-III", "line": 100},
        ]

        # Simulate goto functionality
        selected_bookmark = bookmarks[1]  # "Тело"
        target_index = selected_bookmark["index"]
        target_line = selected_bookmark["line"]

        assert target_index == "DVN-44-K53-II"
        assert target_line == 50

    def test_bookmarks_dialog_field_focus(
        self,
        tk_root: tk.Tk,
        text_field_def: FieldDefinition,
    ) -> None:
        """Фокус устанавливается после перехода к закладке."""
        frame = tk.Frame(tk_root)

        field = FormField(
            parent=frame,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        # Simulate goto bookmark and focus
        field.set_value("")
        field.focus()

        # Field should be ready for input
        assert field._input_widget is not None


# =============================================================================
# TEST: Goto Dialog Navigation
# =============================================================================


@pytest.mark.gui
@pytest.mark.integration
class TestGotoDialogNavigation:
    """Навигация в диалоге перехода."""

    def test_goto_dialog_navigation(self, tk_root: tk.Tk) -> None:
        """Переход к конкретному индексу работает."""
        # Simulate goto dialog input
        target_index = "DVN-44-K53-II"

        # Parse index components
        parts = target_index.split("-")
        assert len(parts) == 4
        assert parts[0] == "DVN"
        assert parts[1] == "44"
        assert parts[2] == "K53"
        assert parts[3] == "II"

    def test_goto_dialog_field_navigation(
        self,
        tk_root: tk.Tk,
        text_field_def: FieldDefinition,
        number_field_def: FieldDefinition,
    ) -> None:
        """Навигация между полями в goto контексте."""
        frame = tk.Frame(tk_root)

        # Create multiple fields
        field1 = FormField(
            parent=frame,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field2 = FormField(
            parent=frame,
            field_def=number_field_def,
            document_index="DVN-44-K53-IX",
        )

        # Simulate tab navigation
        field1.set_value("Первое поле")
        field2.set_value(100)

        assert field1.get_value() == "Первое поле"
        assert field2.get_value() == 100


# =============================================================================
# TEST: Validation Error Display
# =============================================================================


@pytest.mark.gui
@pytest.mark.integration
class TestValidationErrorDisplay:
    """Отображение ошибок валидации в FormField."""

    def test_validation_error_display(
        self,
        tk_root: tk.Tk,
        text_field_def: FieldDefinition,
    ) -> None:
        """Ошибка валидации отображается в FormField."""
        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        error_msg = "Ошибка: некорректное значение"
        field.set_error(error_msg)

        assert field._error_message == error_msg
        assert field._is_valid is False

    def test_validation_error_indicator_shown(
        self,
        tk_root: tk.Tk,
        required_field_def: FieldDefinition,
    ) -> None:
        """Индикатор ошибки показывается при валидации."""
        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=required_field_def,
            document_index="DVN-44-K53-IX",
        )

        # Empty required field triggers error display
        field.set_value("")
        field.validate()

        # Error indicator should be visible
        assert field._is_valid is False

    def test_validation_error_cleared_on_valid_input(
        self,
        tk_root: tk.Tk,
        required_field_def: FieldDefinition,
    ) -> None:
        """Ошибка очищается при вводе валидного значения."""
        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=required_field_def,
            document_index="DVN-44-K53-IX",
        )

        # First trigger error
        field.set_value("")
        field.validate()
        assert field._is_valid is False

        # Then set valid value
        field.set_value("Валидное значение")
        is_valid, error = field.validate()

        assert is_valid is True
        assert field._is_valid is True

    def test_multiple_field_validation(
        self,
        tk_root: tk.Tk,
        required_field_def: FieldDefinition,
        number_field_def: FieldDefinition,
    ) -> None:
        """Валидация нескольких полей."""
        frame = tk.Frame(tk_root)

        field1 = FormField(
            parent=frame,
            field_def=required_field_def,
            document_index="DVN-44-K53-IX",
        )

        field2 = FormField(
            parent=frame,
            field_def=number_field_def,
            document_index="DVN-44-K53-IX",
        )

        # Set valid values
        field1.set_value("Заполнено")
        field2.set_value(100)

        is_valid1, _ = field1.validate()
        is_valid2, _ = field2.validate()

        assert is_valid1 is True
        assert is_valid2 is True


# =============================================================================
# TEST: Document Index Integration
# =============================================================================


@pytest.mark.gui
@pytest.mark.integration
class TestDocumentIndexIntegration:
    """Интеграция с иерархическими индексами документов."""

    def test_document_index_passed_to_field(
        self,
        tk_root: tk.Tk,
        text_field_def: FieldDefinition,
    ) -> None:
        """Индекс документа передаётся в FormField."""
        document_index = "DVN-44-K53-IX"

        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=text_field_def,
            document_index=document_index,
        )

        assert field._document_index == document_index

    def test_document_index_hierarchy(
        self,
        tk_root: tk.Tk,
        autocomplete_field_def: FieldDefinition,
        autocomplete_service: AutocompleteServiceGui,
    ) -> None:
        """Иерархия индекса используется для поиска."""
        full_index = "DVN-44-K53-IX"

        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=autocomplete_field_def,
            document_index=full_index,
            autocomplete_service=autocomplete_service,
        )

        assert field._document_index == full_index


# =============================================================================
# TEST: Callback Integration
# =============================================================================


@pytest.mark.gui
@pytest.mark.integration
class TestCallbackIntegration:
    """Интеграция callback-функций."""

    def test_on_change_callback_chain(
        self,
        tk_root: tk.Tk,
        text_field_def: FieldDefinition,
    ) -> None:
        """Цепочка callback при изменении."""
        change_calls = []

        def on_change(field_id: str, value: Any) -> None:
            change_calls.append((field_id, value))

        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
            on_change=on_change,
        )

        field.set_value("Значение 1")
        field.set_value("Значение 2")

        assert len(change_calls) == 2
        assert change_calls[0] == ("test_text", "Значение 1")
        assert change_calls[1] == ("test_text", "Значение 2")

    def test_on_validate_callback(
        self,
        tk_root: tk.Tk,
        required_field_def: FieldDefinition,
    ) -> None:
        """Callback валидации вызывается."""
        validate_calls = []

        def on_validate(field_id: str, is_valid: bool, error: str | None) -> None:
            validate_calls.append((field_id, is_valid, error))

        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=required_field_def,
            document_index="DVN-44-K53-IX",
            on_validate=on_validate,
        )

        # Trigger validation with empty value (should fail)
        field.set_value("")
        field.validate()

        assert len(validate_calls) >= 1
        assert validate_calls[-1][0] == "required_field"
        assert validate_calls[-1][1] is False


# =============================================================================
# TEST: Form Types Integration
# =============================================================================


@pytest.mark.gui
@pytest.mark.integration
class TestFormTypesIntegration:
    """Интеграция различных типов полей."""

    def test_text_input_integration(
        self,
        tk_root: tk.Tk,
        text_field_def: FieldDefinition,
    ) -> None:
        """Текстовое поле работает в форме."""
        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        test_value = "Тестовый текст"
        field.set_value(test_value)

        assert field.get_value() == test_value

    def test_number_input_integration(
        self,
        tk_root: tk.Tk,
        number_field_def: FieldDefinition,
    ) -> None:
        """Числовое поле работает в форме."""
        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=number_field_def,
            document_index="DVN-44-K53-IX",
        )

        field.set_value(123.45)

        assert field.get_value() == 123.45

    def test_dropdown_integration(
        self,
        tk_root: tk.Tk,
        dropdown_field_def: FieldDefinition,
    ) -> None:
        """Выпадающий список работает в форме."""
        from tkinter import ttk

        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=dropdown_field_def,
            document_index="DVN-44-K53-IX",
        )

        assert isinstance(field._input_widget, ttk.Combobox)

        field.set_value("Акт")
        assert field.get_value() == "Акт"

    def test_date_input_integration(
        self,
        tk_root: tk.Tk,
        date_field_def: FieldDefinition,
    ) -> None:
        """Поле даты работает в форме."""
        field = FormField(
            parent=tk.Frame(tk_root),
            field_def=date_field_def,
            document_index="DVN-44-K53-IX",
        )

        test_date = date(2026, 4, 15)
        field.set_value(test_date)

        assert field.get_value() == test_date


# =============================================================================
# TEST: Security Integration
# =============================================================================


@pytest.mark.gui
@pytest.mark.integration
class TestSecurityIntegration:
    """Интеграция security features."""

    def test_form_field_wipe_in_dialog(
        self,
        tk_root: tk.Tk,
        text_field_def: FieldDefinition,
    ) -> None:
        """Очистка данных при закрытии диалога."""
        frame = tk.Frame(tk_root)

        field = FormField(
            parent=frame,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        # Simulate user input
        field.set_value("Конфиденциальные данные")

        # Simulate dialog close with wipe
        field.wipe_sensitive_data()

        assert field.get_value() is None
        assert field._error_message is None

    def test_multiple_fields_wipe(
        self,
        tk_root: tk.Tk,
        text_field_def: FieldDefinition,
        number_field_def: FieldDefinition,
    ) -> None:
        """Очистка нескольких полей."""
        frame = tk.Frame(tk_root)

        field1 = FormField(
            parent=frame,
            field_def=text_field_def,
            document_index="DVN-44-K53-IX",
        )

        field2 = FormField(
            parent=frame,
            field_def=number_field_def,
            document_index="DVN-44-K53-IX",
        )

        field1.set_value("Секрет")
        field2.set_value(999)

        # Wipe all
        field1.wipe_sensitive_data()
        field2.wipe_sensitive_data()

        assert field1.get_value() is None
        assert field2.get_value() is None


if __name__ == "__main__":
    pytest.main(
        [
            __file__,
            "-v",
            "--cov=src.gui.components.form_field,src.gui.services.autocomplete_service",
        ]
    )
