"""Tests for OptionsEditorDialog.

Tests FieldOption dataclass, CRUD operations, reordering,
validation, and dialog modal behavior.

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
from unittest.mock import patch

import pytest
from src.gui.form_designer.dialogs.options_editor_dialog import (
    FieldOption,
    OptionsEditorDialog,
)

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def root():
    """Создает Tk root window для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def sample_options():
    """Создает список тестовых опций."""
    return [
        FieldOption("yes", "Да", "Yes"),
        FieldOption("no", "Нет", "No"),
        FieldOption("maybe", "Возможно", "Maybe"),
    ]


@pytest.fixture
def dialog(root):
    """Создает диалог без опций."""
    dialog = OptionsEditorDialog(parent=root, current_options=[])
    yield dialog
    if dialog.winfo_exists():
        dialog.destroy()


@pytest.fixture
def dialog_with_options(root, sample_options):
    """Создает диалог с тестовыми опциями."""
    dialog = OptionsEditorDialog(
        parent=root,
        current_options=sample_options,
        field_id="test_field",
    )
    yield dialog
    if dialog.winfo_exists():
        dialog.destroy()


# =============================================================================
# TEST: FieldOption Dataclass
# =============================================================================


class TestFieldOption:
    """Test suite for FieldOption dataclass."""

    def test_field_option_creation(self):
        """Тест создания FieldOption с полными данными."""
        option = FieldOption("yes", "Да", "Yes")
        assert option.value == "yes"
        assert option.label_ru == "Да"
        assert option.label_en == "Yes"

    def test_field_option_creation_without_en(self):
        """Тест создания FieldOption без label_en (default='')."""
        option = FieldOption("yes", "Да")
        assert option.value == "yes"
        assert option.label_ru == "Да"
        assert option.label_en == ""

    def test_field_option_equality_same(self):
        """Тест равенства FieldOption с одинаковыми значениями."""
        opt1 = FieldOption("yes", "Да", "Yes")
        opt2 = FieldOption("yes", "Да", "Yes")
        assert opt1 == opt2

    def test_field_option_equality_different(self):
        """Тест неравенства FieldOption с разными значениями."""
        opt1 = FieldOption("yes", "Да", "Yes")
        opt2 = FieldOption("no", "Нет", "No")
        assert opt1 != opt2

    def test_field_option_equality_different_type(self):
        """Тест сравнения FieldOption с другим типом."""
        opt = FieldOption("yes", "Да", "Yes")
        assert opt != "yes"
        assert opt != {"value": "yes", "label_ru": "Да"}

    def test_field_option_repr(self):
        """Тест строкового представления FieldOption."""
        option = FieldOption("yes", "Да", "Yes")
        repr_str = repr(option)
        assert "FieldOption" in repr_str
        assert "yes" in repr_str
        assert "Да" in repr_str

    def test_field_option_immutable(self):
        """Тест immutability (frozen-like) через dataclass."""
        # FieldOption не frozen, но проверим атрибуты
        option = FieldOption("yes", "Да", "Yes")
        option.value = "no"  # Можно изменить
        assert option.value == "no"


# =============================================================================
# TEST: Dialog Initialization
# =============================================================================


class TestDialogInitialization:
    """Test suite for dialog initialization."""

    @pytest.mark.gui
    def test_dialog_creation_empty(self, root):
        """Тест создания диалога с пустыми опциями."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        assert dialog._options == []
        assert dialog._field_id == ""
        dialog.destroy()

    @pytest.mark.gui
    def test_dialog_creation_with_options(self, root, sample_options):
        """Тест создания диалога с существующими опциями."""
        dialog = OptionsEditorDialog(
            parent=root,
            current_options=sample_options,
        )
        assert len(dialog._options) == 3
        assert dialog._options[0].value == "yes"
        dialog.destroy()

    @pytest.mark.gui
    def test_dialog_creation_with_field_id(self, root):
        """Тест создания диалога с field_id."""
        dialog = OptionsEditorDialog(
            parent=root,
            current_options=[],
            field_id="test_field_123",
        )
        assert dialog._field_id == "test_field_123"
        assert "test_field_123" in dialog.title()
        dialog.destroy()

    @pytest.mark.gui
    def test_dialog_creation_without_field_id(self, root):
        """Тест создания диалога без field_id."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        assert dialog.title() == "Options Editor"
        dialog.destroy()

    @pytest.mark.gui
    def test_dialog_creation_none_options(self, root):
        """Тест создания диалога с None вместо списка опций."""
        dialog = OptionsEditorDialog(parent=root, current_options=None)
        assert dialog._options == []
        dialog.destroy()

    @pytest.mark.gui
    def test_dialog_initial_options_copied(self, root, sample_options):
        """Тест что опции копируются при создании."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._options.append(FieldOption("new", "Новый", "New"))
        assert len(sample_options) == 3  # Оригинал не изменился
        dialog.destroy()


# =============================================================================
# TEST: Get/Set Editor Values
# =============================================================================


class TestEditorValues:
    """Test suite for editor value operations."""

    @pytest.mark.gui
    def test_get_editor_values_empty(self, root):
        """Тест получения пустых значений из редактора."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        value, label_ru, label_en = dialog._get_editor_values()
        assert value == ""
        assert label_ru == ""
        assert label_en == ""
        dialog.destroy()

    @pytest.mark.gui
    def test_get_editor_values_with_data(self, root):
        """Тест получения значений из заполненного редактора."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        dialog._value_entry.insert(0, "test_value")
        dialog._label_ru_entry.insert(0, "Тестовое значение")
        dialog._label_en_entry.insert(0, "Test Value")

        value, label_ru, label_en = dialog._get_editor_values()
        assert value == "test_value"
        assert label_ru == "Тестовое значение"
        assert label_en == "Test Value"
        dialog.destroy()

    @pytest.mark.gui
    def test_get_editor_values_strips_whitespace(self, root):
        """Тест что _get_editor_values обрезает пробелы."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        dialog._value_entry.insert(0, "  test_value  ")
        dialog._label_ru_entry.insert(0, "  Значение  ")

        value, label_ru, _ = dialog._get_editor_values()
        assert value == "test_value"
        assert label_ru == "Значение"
        dialog.destroy()

    @pytest.mark.gui
    def test_set_editor_values(self, root):
        """Тест установки значений в редактор."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        option = FieldOption("opt1", "Опция 1", "Option 1")

        dialog._set_editor_values(option)

        assert dialog._value_entry.get() == "opt1"
        assert dialog._label_ru_entry.get() == "Опция 1"
        assert dialog._label_en_entry.get() == "Option 1"
        dialog.destroy()

    @pytest.mark.gui
    def test_clear_editor(self, root):
        """Тест очистки полей редактора."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        dialog._value_entry.insert(0, "test")
        dialog._label_ru_entry.insert(0, "тест")

        dialog._clear_editor()

        assert dialog._value_entry.get() == ""
        assert dialog._label_ru_entry.get() == ""
        assert dialog._label_en_entry.get() == ""
        dialog.destroy()


# =============================================================================
# TEST: Validation
# =============================================================================


class TestValidation:
    """Test suite for validation logic."""

    @pytest.mark.gui
    def test_validate_empty_value(self, root, sample_options):
        """Тест валидации пустого значения."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        is_valid, error = dialog._validate_option("", "Метка")
        assert is_valid is False
        assert "Value" in error
        dialog.destroy()

    @pytest.mark.gui
    def test_validate_empty_label_ru(self, root, sample_options):
        """Тест валидации пустой русской метки."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        is_valid, error = dialog._validate_option("value", "")
        assert is_valid is False
        assert "Label (RU)" in error
        dialog.destroy()

    @pytest.mark.gui
    def test_validate_valid_option(self, root, sample_options):
        """Тест валидации валидной опции."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        is_valid, error = dialog._validate_option("new_value", "Новая метка")
        assert is_valid is True
        assert error == ""
        dialog.destroy()

    @pytest.mark.gui
    def test_validate_duplicate_value(self, root, sample_options):
        """Тест валидации дубликата значения."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        is_valid, error = dialog._validate_option("yes", "Да Да")
        assert is_valid is False
        assert "already exists" in error
        dialog.destroy()

    @pytest.mark.gui
    def test_validate_with_exclude_index(self, root, sample_options):
        """Тест валидации с исключением индекса (update scenario)."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        # "yes" существует на индексе 0, но мы исключаем его из проверки
        is_valid, error = dialog._validate_option(
            "yes",
            "Обновленная метка",
            exclude_index=0,
        )
        assert is_valid is True
        assert error == ""
        dialog.destroy()

    @pytest.mark.gui
    def test_validate_duplicate_different_index(self, root, sample_options):
        """Тест что дубликат найден на другом индексе."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        # "yes" на индексе 0, проверяем на индексе 1
        is_valid, error = dialog._validate_option(
            "yes",
            "Метка",
            exclude_index=1,
        )
        assert is_valid is False
        assert "already exists" in error
        dialog.destroy()

    @pytest.mark.gui
    def test_validate_empty_options_list(self, root):
        """Тест валидации с пустым списком опций."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        is_valid, error = dialog._validate_option("value", "Метка")
        assert is_valid is True
        assert error == ""
        dialog.destroy()


# =============================================================================
# TEST: Add Operation
# =============================================================================


class TestAddOperation:
    """Test suite for _on_add operation."""

    @pytest.mark.gui
    def test_add_valid_option(self, root):
        """Тест добавления валидной опции."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        dialog._value_entry.insert(0, "new_opt")
        dialog._label_ru_entry.insert(0, "Новая опция")
        dialog._label_en_entry.insert(0, "New Option")

        dialog._on_add()

        assert len(dialog._options) == 1
        assert dialog._options[0].value == "new_opt"
        assert dialog._options[0].label_ru == "Новая опция"
        assert dialog._options[0].label_en == "New Option"
        dialog.destroy()

    @pytest.mark.gui
    def test_add_clears_editor(self, root):
        """Тест что добавление очищает редактор."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        dialog._value_entry.insert(0, "new_opt")
        dialog._label_ru_entry.insert(0, "Новая опция")

        dialog._on_add()

        assert dialog._value_entry.get() == ""
        assert dialog._label_ru_entry.get() == ""
        dialog.destroy()

    @pytest.mark.gui
    def test_add_invalid_shows_error(self, root, sample_options):
        """Тест что невалидная опция не добавляется."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._value_entry.insert(0, "yes")  # Дубликат
        dialog._label_ru_entry.insert(0, "Дубликат")

        dialog._on_add()

        assert len(dialog._options) == 3  # Не изменилось
        assert "already exists" in dialog._status_label.cget("text")
        dialog.destroy()

    @pytest.mark.gui
    def test_add_empty_value_shows_error(self, root):
        """Тест что пустое значение не добавляется."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        dialog._value_entry.insert(0, "")
        dialog._label_ru_entry.insert(0, "Метка")

        dialog._on_add()

        assert len(dialog._options) == 0
        assert "Value" in dialog._status_label.cget("text")
        dialog.destroy()

    @pytest.mark.gui
    def test_add_empty_label_shows_error(self, root):
        """Тест что пустая метка не добавляется."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        dialog._value_entry.insert(0, "value")
        dialog._label_ru_entry.insert(0, "")

        dialog._on_add()

        assert len(dialog._options) == 0
        assert "Label" in dialog._status_label.cget("text")
        dialog.destroy()

    @pytest.mark.gui
    def test_add_multiple_options(self, root):
        """Тест добавления нескольких опций."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        for i in range(3):
            dialog._value_entry.insert(0, f"opt{i}")
            dialog._label_ru_entry.insert(0, f"Опция {i}")
            dialog._on_add()

        assert len(dialog._options) == 3
        dialog.destroy()


# =============================================================================
# TEST: Update Operation
# =============================================================================


class TestUpdateOperation:
    """Test suite for _on_update operation."""

    @pytest.mark.gui
    def test_update_selected_option(self, root, sample_options):
        """Тест обновления выбранной опции."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        # Выбираем первую опцию
        dialog._tree.selection_set("0")

        dialog._value_entry.delete(0, tk.END)
        dialog._value_entry.insert(0, "updated_yes")
        dialog._label_ru_entry.delete(0, tk.END)
        dialog._label_ru_entry.insert(0, "Обновлено")

        dialog._on_update()

        assert dialog._options[0].value == "updated_yes"
        assert dialog._options[0].label_ru == "Обновлено"
        dialog.destroy()

    @pytest.mark.gui
    def test_update_no_selection_shows_error(self, root, sample_options):
        """Тест что обновление без выбора показывает ошибку."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_clear()

        dialog._value_entry.insert(0, "value")
        dialog._label_ru_entry.insert(0, "метка")
        dialog._on_update()

        assert "Select an option" in dialog._status_label.cget("text")
        assert len(dialog._options) == 3  # Не изменилось
        dialog.destroy()

    @pytest.mark.gui
    def test_update_invalid_value(self, root, sample_options):
        """Тест что обновление с дубликатом не выполняется."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("0")  # Выбрана "yes"

        dialog._value_entry.delete(0, tk.END)
        dialog._value_entry.insert(0, "no")  # Дубликат "no"
        dialog._label_ru_entry.delete(0, tk.END)
        dialog._label_ru_entry.insert(0, "Новая метка")  # Устанавливаем label_ru

        dialog._on_update()

        # Опция не изменилась
        assert dialog._options[0].value == "yes"
        assert "already exists" in dialog._status_label.cget("text")
        dialog.destroy()

    @pytest.mark.gui
    def test_update_allows_same_value(self, root, sample_options):
        """Тест что обновление на тот же value разрешено."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("0")  # Выбрана "yes"

        dialog._value_entry.delete(0, tk.END)
        dialog._value_entry.insert(0, "yes")  # Тот же value
        dialog._label_ru_entry.delete(0, tk.END)
        dialog._label_ru_entry.insert(0, "Обновленная метка")

        dialog._on_update()

        assert dialog._options[0].value == "yes"
        assert dialog._options[0].label_ru == "Обновленная метка"
        dialog.destroy()


# =============================================================================
# TEST: Delete Operation
# =============================================================================


class TestDeleteOperation:
    """Test suite for _on_delete operation."""

    @pytest.mark.gui
    def test_delete_selected_option(self, root, sample_options):
        """Тест удаления выбранной опции."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("0")

        with patch.object(dialog, "_refresh_list"):
            with patch("tkinter.messagebox.askyesno", return_value=True):
                dialog._on_delete()

        assert len(dialog._options) == 2
        assert dialog._options[0].value == "no"
        dialog.destroy()

    @pytest.mark.gui
    def test_delete_cancelled(self, root, sample_options):
        """Тест отмены удаления."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("0")

        with patch("tkinter.messagebox.askyesno", return_value=False):
            dialog._on_delete()

        assert len(dialog._options) == 3  # Не изменилось
        dialog.destroy()

    @pytest.mark.gui
    def test_delete_no_selection(self, root, sample_options):
        """Тест удаления без выбора."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_clear()

        dialog._on_delete()

        assert len(dialog._options) == 3  # Не изменилось
        assert "Select an option" in dialog._status_label.cget("text")
        dialog.destroy()

    @pytest.mark.gui
    def test_delete_last_option(self, root):
        """Тест удаления последней опции."""
        dialog = OptionsEditorDialog(
            parent=root,
            current_options=[FieldOption("only", "Единственная")],
        )
        dialog._tree.selection_set("0")

        with patch("tkinter.messagebox.askyesno", return_value=True):
            dialog._on_delete()

        assert len(dialog._options) == 0
        dialog.destroy()

    @pytest.mark.gui
    def test_delete_clears_editor(self, root, sample_options):
        """Тест что удаление очищает редактор."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("0")
        dialog._set_editor_values(dialog._options[0])

        with patch("tkinter.messagebox.askyesno", return_value=True):
            dialog._on_delete()

        assert dialog._value_entry.get() == ""
        dialog.destroy()


# =============================================================================
# TEST: Move Operations
# =============================================================================


class TestMoveOperations:
    """Test suite for move up/down operations."""

    @pytest.mark.gui
    def test_move_up_changes_order(self, root, sample_options):
        """Тест перемещения вверх меняет порядок."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("1")  # "no" на индексе 1

        dialog._on_move_up()

        assert dialog._options[0].value == "no"
        assert dialog._options[1].value == "yes"
        dialog.destroy()

    @pytest.mark.gui
    def test_move_down_changes_order(self, root, sample_options):
        """Тест перемещения вниз меняет порядок."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("1")  # "no" на индексе 1

        dialog._on_move_down()

        assert dialog._options[1].value == "maybe"
        assert dialog._options[2].value == "no"
        dialog.destroy()

    @pytest.mark.gui
    def test_move_up_first_item_no_change(self, root, sample_options):
        """Тест что первый элемент не двигается вверх."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("0")  # Первый элемент

        dialog._on_move_up()

        assert dialog._options[0].value == "yes"
        assert dialog._options[1].value == "no"
        dialog.destroy()

    @pytest.mark.gui
    def test_move_down_last_item_no_change(self, root, sample_options):
        """Тест что последний элемент не двигается вниз."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("2")  # Последний элемент

        dialog._on_move_down()

        assert dialog._options[2].value == "maybe"
        dialog.destroy()

    @pytest.mark.gui
    def test_move_up_no_selection(self, root, sample_options):
        """Тест перемещения вверх без выбора."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_clear()

        dialog._on_move_up()

        # Порядок не изменился
        assert dialog._options[0].value == "yes"
        dialog.destroy()

    @pytest.mark.gui
    def test_move_down_no_selection(self, root, sample_options):
        """Тест перемещения вниз без выбора."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_clear()

        dialog._on_move_down()

        # Порядок не изменился
        assert dialog._options[0].value == "yes"
        dialog.destroy()

    @pytest.mark.gui
    def test_move_up_updates_selection(self, root, sample_options):
        """Тест что перемещение вверх обновляет выбор."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("1")

        dialog._on_move_up()

        selected = dialog._tree.selection()
        assert selected == ("0",)
        dialog.destroy()

    @pytest.mark.gui
    def test_move_down_updates_selection(self, root, sample_options):
        """Тест что перемещение вниз обновляет выбор."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._tree.selection_set("1")

        dialog._on_move_down()

        selected = dialog._tree.selection()
        assert selected == ("2",)
        dialog.destroy()

    @pytest.mark.gui
    def test_move_up_single_item(self, root):
        """Тест перемещения вверх с одной опцией."""
        dialog = OptionsEditorDialog(
            parent=root,
            current_options=[FieldOption("only", "Единственная")],
        )
        dialog._tree.selection_set("0")

        dialog._on_move_up()

        assert dialog._options[0].value == "only"
        dialog.destroy()

    @pytest.mark.gui
    def test_move_down_single_item(self, root):
        """Тест перемещения вниз с одной опцией."""
        dialog = OptionsEditorDialog(
            parent=root,
            current_options=[FieldOption("only", "Единственная")],
        )
        dialog._tree.selection_set("0")

        dialog._on_move_down()

        assert dialog._options[0].value == "only"
        dialog.destroy()


# =============================================================================
# TEST: Dialog Result
# =============================================================================


class TestDialogResult:
    """Test suite for dialog result handling."""

    @pytest.mark.gui
    def test_ok_sets_result_and_closes(self, root, sample_options):
        """Тест OK устанавливает результат и закрывает диалог."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)

        dialog._on_ok()

        assert dialog._result is not None
        assert len(dialog._result) == 3
        assert not dialog.winfo_exists()  # 0 is falsy

    @pytest.mark.gui
    def test_ok_returns_copy(self, root, sample_options):
        """Тест что OK возвращает копию списка."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)

        dialog._on_ok()

        # Копия, не оригинал
        dialog._result.append(FieldOption("new", "Новая"))
        assert len(sample_options) == 3

    @pytest.mark.gui
    def test_ok_empty_list_valid(self, root):
        """Тест что пустой список опций валиден."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        dialog._on_ok()

        assert dialog._result == []
        dialog.destroy()

    @pytest.mark.gui
    def test_ok_validates_options(self, root):
        """Тест что OK валидирует все опции."""
        dialog = OptionsEditorDialog(
            parent=root,
            current_options=[FieldOption("", "Метка")],  # Невалидная
        )

        with patch("tkinter.messagebox.showerror") as mock_error:
            dialog._on_ok()
            mock_error.assert_called_once()

        assert dialog._result is None  # Не установлен
        dialog.destroy()

    @pytest.mark.gui
    def test_cancel_sets_none(self, root, sample_options):
        """Тест что Cancel возвращает None."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)

        dialog._on_cancel()

        assert dialog._result is None
        assert not dialog.winfo_exists()  # 0 is falsy

    @pytest.mark.gui
    def test_close_window_sets_none(self, root, sample_options):
        """Тест что закрытие окна возвращает None."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)

        dialog._on_cancel()

        assert dialog._result is None
        dialog.destroy()

    @pytest.mark.gui
    def test_show_returns_result(self, root, sample_options):
        """Тест что show возвращает результат."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)

        # Мокаем wait_window чтобы не блокировать
        def mock_wait():
            dialog._result = list(dialog._options)

        dialog.wait_window = mock_wait

        result = dialog.show()

        assert result is not None
        assert len(result) == 3
        dialog.destroy()

    @pytest.mark.gui
    def test_show_returns_none_on_cancel(self, root):
        """Тест что show возвращает None при отмене."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        def mock_wait():
            dialog._result = None

        dialog.wait_window = mock_wait

        result = dialog.show()

        assert result is None
        dialog.destroy()


# =============================================================================
# TEST: Selection Change
# =============================================================================


class TestSelectionChange:
    """Test suite for selection change handling."""

    @pytest.mark.gui
    def test_selection_change_loads_values(self, root, sample_options):
        """Тест что изменение выбора загружает значения в редактор."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)

        dialog._tree.selection_set("1")
        dialog._on_selection_change(None)

        assert dialog._value_entry.get() == "no"
        assert dialog._label_ru_entry.get() == "Нет"
        dialog.destroy()

    @pytest.mark.gui
    def test_selection_change_no_selection(self, root, sample_options):
        """Тест что очистка выбора ничего не делает."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)
        dialog._value_entry.insert(0, "test")

        dialog._tree.selection_clear()
        dialog._on_selection_change(None)

        # Значение не изменилось
        assert dialog._value_entry.get() == "test"
        dialog.destroy()


# =============================================================================
# TEST: Refresh List
# =============================================================================


class TestRefreshList:
    """Test suite for _refresh_list method."""

    @pytest.mark.gui
    def test_refresh_list_populates_tree(self, root, sample_options):
        """Тест что refresh_list заполняет Treeview."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)

        children = dialog._tree.get_children()
        assert len(children) == 3

        values = dialog._tree.item("0")["values"]
        assert values[0] == "yes"
        assert values[1] == "Да"
        dialog.destroy()

    @pytest.mark.gui
    def test_refresh_list_clears_existing(self, root, sample_options):
        """Тест что refresh_list очищает существующие записи."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)

        # Добавляем опцию
        dialog._options.append(FieldOption("new", "Новая"))
        dialog._refresh_list()

        children = dialog._tree.get_children()
        assert len(children) == 4
        dialog.destroy()

    @pytest.mark.gui
    def test_refresh_list_empty(self, root):
        """Тест refresh_list с пустым списком."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        children = dialog._tree.get_children()
        assert len(children) == 0
        dialog.destroy()


# =============================================================================
# TEST: UI Creation
# =============================================================================


class TestUICreation:
    """Test suite for UI components creation."""

    @pytest.mark.gui
    def test_treeview_created(self, root):
        """Тест что Treeview создается."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        assert dialog._tree is not None
        dialog.destroy()

    @pytest.mark.gui
    def test_entries_created(self, root):
        """Тест что поля ввода создаются."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        assert dialog._value_entry is not None
        assert dialog._label_ru_entry is not None
        assert dialog._label_en_entry is not None
        dialog.destroy()

    @pytest.mark.gui
    def test_status_label_created(self, root):
        """Тест что status label создается."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        assert dialog._status_label is not None
        dialog.destroy()

    @pytest.mark.gui
    def test_treeview_columns(self, root):
        """Тест настройки колонок Treeview."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])
        columns = dialog._tree.cget("columns")
        assert columns == ("value", "label_ru", "label_en")
        dialog.destroy()


# =============================================================================
# TEST: Complex Scenarios
# =============================================================================


class TestComplexScenarios:
    """Test suite for complex scenarios."""

    @pytest.mark.gui
    def test_add_update_delete_flow(self, root):
        """Тест полного цикла добавление-обновление-удаление."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        # Добавляем опцию
        dialog._value_entry.insert(0, "opt1")
        dialog._label_ru_entry.insert(0, "Опция 1")
        dialog._on_add()
        assert len(dialog._options) == 1

        # Обновляем - сначала выбираем, потом устанавливаем новые значения в редактор
        dialog._tree.selection_set("0")
        # _on_selection_change загрузит значения в редактор, поэтому очищаем и вставляем новые
        dialog._value_entry.delete(0, tk.END)
        dialog._value_entry.insert(0, "opt1_updated")
        dialog._label_ru_entry.delete(0, tk.END)
        dialog._label_ru_entry.insert(0, "Обновленная опция")
        dialog._on_update()
        assert dialog._options[0].value == "opt1_updated"
        assert dialog._options[0].label_ru == "Обновленная опция"

        # Удаляем - нужно снова выбрать элемент после _refresh_list в _on_update
        dialog._tree.selection_set("0")
        with patch("tkinter.messagebox.askyesno", return_value=True):
            dialog._on_delete()
        assert len(dialog._options) == 0

        dialog.destroy()

    @pytest.mark.gui
    def test_reorder_and_result(self, root, sample_options):
        """Тест перестановки и возврата результата."""
        dialog = OptionsEditorDialog(parent=root, current_options=sample_options)

        # Перемещаем последний элемент вверх
        dialog._tree.selection_set("2")
        dialog._on_move_up()
        dialog._on_move_up()

        assert dialog._options[0].value == "maybe"

        # Получаем результат
        dialog._on_ok()
        result = dialog._result

        assert result[0].value == "maybe"
        assert result[1].value == "yes"
        assert result[2].value == "no"
        dialog.destroy()

    @pytest.mark.gui
    def test_multiple_operations(self, root):
        """Тест множественных операций."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        # Добавляем 5 опций
        for i in range(5):
            dialog._value_entry.delete(0, tk.END)
            dialog._label_ru_entry.delete(0, tk.END)
            dialog._value_entry.insert(0, f"opt{i}")
            dialog._label_ru_entry.insert(0, f"Опция {i}")
            dialog._on_add()

        assert len(dialog._options) == 5

        # Перемещаем несколько раз
        dialog._tree.selection_set("4")
        dialog._on_move_up()
        dialog._on_move_up()

        assert dialog._options[2].value == "opt4"

        dialog.destroy()

    @pytest.mark.gui
    def test_unicode_values(self, root):
        """Тест работы с Unicode значениями."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        dialog._value_entry.insert(0, "значение_юникод")
        dialog._label_ru_entry.insert(0, "Метка с эмодзи 🎉")
        dialog._label_en_entry.insert(0, "Label with emoji 🚀")

        dialog._on_add()

        assert len(dialog._options) == 1
        assert dialog._options[0].value == "значение_юникод"
        assert "🎉" in dialog._options[0].label_ru
        dialog.destroy()

    @pytest.mark.gui
    def test_whitespace_handling(self, root):
        """Тест обработки пробелов."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        dialog._value_entry.insert(0, "  value_with_spaces  ")
        dialog._label_ru_entry.insert(0, "  Метка  ")

        dialog._on_add()

        assert dialog._options[0].value == "value_with_spaces"
        assert dialog._options[0].label_ru == "Метка"
        dialog.destroy()


# =============================================================================
# TEST: Edge Cases
# =============================================================================


class TestEdgeCases:
    """Test suite for edge cases."""

    @pytest.mark.gui
    def test_two_items_swap(self, root):
        """Тест перестановки двух элементов."""
        dialog = OptionsEditorDialog(
            parent=root,
            current_options=[
                FieldOption("a", "A"),
                FieldOption("b", "B"),
            ],
        )

        dialog._tree.selection_set("1")
        dialog._on_move_up()

        assert dialog._options[0].value == "b"
        assert dialog._options[1].value == "a"
        dialog.destroy()

    @pytest.mark.gui
    def test_update_same_label_ru(self, root):
        """Тест обновления с тем же label_ru."""
        dialog = OptionsEditorDialog(
            parent=root,
            current_options=[FieldOption("opt", "Метка")],
        )

        dialog._tree.selection_set("0")
        dialog._value_entry.delete(0, tk.END)
        dialog._value_entry.insert(0, "new_value")
        dialog._label_ru_entry.delete(0, tk.END)
        dialog._label_ru_entry.insert(0, "Метка")

        dialog._on_update()

        assert dialog._options[0].value == "new_value"
        dialog.destroy()

    @pytest.mark.gui
    def test_empty_label_en_allowed(self, root):
        """Тест что пустой label_en разрешен."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        dialog._value_entry.insert(0, "value")
        dialog._label_ru_entry.insert(0, "Метка")
        # label_en не заполняем

        dialog._on_add()

        assert len(dialog._options) == 1
        assert dialog._options[0].label_en == ""
        dialog.destroy()

    @pytest.mark.gui
    def test_special_chars_in_value(self, root):
        """Тест специальных символов в значении."""
        dialog = OptionsEditorDialog(parent=root, current_options=[])

        special_value = "value-with_special.chars123"
        dialog._value_entry.insert(0, special_value)
        dialog._label_ru_entry.insert(0, "Метка")

        dialog._on_add()

        assert dialog._options[0].value == special_value
        dialog.destroy()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.form_designer.dialogs.options_editor_dialog"])
