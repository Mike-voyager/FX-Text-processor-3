"""Тесты для inline-виджетов (BaseField) структурированных форм.

Покрывает критические пути:
- InlineCheckboxField: get_value, set_value, validate, wipe_sensitive_data
- InlineDropdownField: get_value, set_value, validate, wipe_sensitive_data
- InlineRadioGroupField: get_value, set_value, validate, wipe_sensitive_data
- InlineMultiLineField: get_value, set_value, validate, wipe_sensitive_data
- NumberEntry: get_value, set_value, validate, clamping
- DateEntry: get_value, set_value, validate
- AutocompleteEntry: get_value, set_value, wipe_sensitive_data
- TableField: get_value, set_value, validate

Author: Mike Voyager
Date: 2026-05
"""

from __future__ import annotations

import tkinter as tk
from datetime import date
from decimal import Decimal
from unittest.mock import MagicMock

import pytest

from src.gui.modes.structured_form.widgets.autocomplete_entry import AutocompleteEntry
from src.gui.modes.structured_form.widgets.base_field import BaseField
from src.gui.modes.structured_form.widgets.date_entry import DateEntry
from src.gui.modes.structured_form.widgets.inline_checkbox_field import (
    InlineCheckboxField,
)
from src.gui.modes.structured_form.widgets.inline_dropdown_field import (
    InlineDropdownField,
)
from src.gui.modes.structured_form.widgets.inline_multi_line_field import (
    InlineMultiLineField,
)
from src.gui.modes.structured_form.widgets.inline_radio_group_field import (
    InlineRadioGroupField,
)
from src.gui.modes.structured_form.widgets.number_entry import NumberEntry
from src.gui.modes.structured_form.widgets.table_field import TableField


@pytest.fixture
def root() -> tk.Tk:
    """Создаёт корневое окно Tkinter."""
    root = tk.Tk()
    yield root
    root.destroy()


# =========================================================================
# InlineCheckboxField
# =========================================================================


class TestInlineCheckboxField:
    """Тесты для InlineCheckboxField."""

    @pytest.fixture
    def field(self, root: tk.Tk) -> InlineCheckboxField:
        """Создаёт поле чекбокса для тестирования."""
        field = InlineCheckboxField(
            parent=root,
            field_id="agreed",
            label="Согласен",
        )
        root.update_idletasks()
        return field

    def test_default_value_is_false(self, field: InlineCheckboxField) -> None:
        """По умолчанию чекбокс сброшен."""
        assert field.get_value() is False

    def test_set_value_true(self, field: InlineCheckboxField) -> None:
        """Установка True отмечает чекбокс."""
        field.set_value(True)
        assert field.get_value() is True

    def test_set_value_false(self, field: InlineCheckboxField) -> None:
        """Установка False сбрасывает чекбокс."""
        field.set_value(True)
        field.set_value(False)
        assert field.get_value() is False

    def test_validate_not_required(self, field: InlineCheckboxField) -> None:
        """Незаполненный необязательный чекбокс валиден."""
        assert field.validate() is True

    def test_validate_required_empty(self, root: tk.Tk) -> None:
        """Обязательный чекбокс без отметки невалиден."""
        field = InlineCheckboxField(
            parent=root,
            field_id="required_cb",
            label="Обязательный",
            required=True,
        )
        root.update_idletasks()
        assert field.validate() is False

    def test_validate_required_checked(self, root: tk.Tk) -> None:
        """Обязательный отмеченный чекбокс валиден."""
        field = InlineCheckboxField(
            parent=root,
            field_id="required_cb",
            label="Обязательный",
            required=True,
        )
        root.update_idletasks()
        field.set_value(True)
        assert field.validate() is True

    def test_on_change_callback(self, root: tk.Tk) -> None:
        """on_change вызывается при изменении значения."""
        changes: list[tuple[str, object]] = []
        field = InlineCheckboxField(
            parent=root,
            field_id="cb",
            label="CB",
            on_change=lambda fid, val: changes.append((fid, val)),
        )
        root.update_idletasks()
        field.set_value(True)
        assert len(changes) == 1
        assert changes[0] == ("cb", True)

    def test_wipe_sensitive_data(self, field: InlineCheckboxField) -> None:
        """Очистка sensitive данных сбрасывает значение."""
        field.set_value(True)
        field.wipe_sensitive_data()
        assert field.get_value() is False

    def test_label_in_container(self, root: tk.Tk) -> None:
        """Метка должна быть внутри контейнера рядом с чекбоксом."""
        field = InlineCheckboxField(
            parent=root,
            field_id="cb",
            label="Тестовая метка",
        )
        root.update_idletasks()
        # Проверяем что _inline_label существует и имеет правильный текст
        assert hasattr(field, "_inline_label")
        assert field._inline_label.cget("text") == "Тестовая метка"


# =========================================================================
# InlineDropdownField
# =========================================================================


class TestInlineDropdownField:
    """Тесты для InlineDropdownField."""

    @pytest.fixture
    def field(self, root: tk.Tk) -> InlineDropdownField:
        """Создаёт выпадающий список для тестирования."""
        field = InlineDropdownField(
            parent=root,
            field_id="status",
            label="Статус",
            options=("Активен", "Неактивен", "Архив"),
        )
        root.update_idletasks()
        return field

    def test_default_first_option(self, field: InlineDropdownField) -> None:
        """По умолчанию выбирается первая опция."""
        assert field.get_value() == "Активен"

    def test_set_value(self, field: InlineDropdownField) -> None:
        """Установка допустимого значения."""
        field.set_value("Неактивен")
        assert field.get_value() == "Неактивен"

    def test_set_invalid_value_fallback(self, field: InlineDropdownField) -> None:
        """Установка недопустимого значения сбрасывает на первую опцию."""
        field.set_value("Неизвестно")
        assert field.get_value() == "Активен"

    def test_validate_valid(self, field: InlineDropdownField) -> None:
        """Выбранная опция валидна."""
        assert field.validate() is True

    def test_validate_empty_required(self, root: tk.Tk) -> None:
        """Пустой обязательный список невалиден."""
        field = InlineDropdownField(
            parent=root,
            field_id="req",
            label="Обязательный",
            required=True,
        )
        root.update_idletasks()
        # Без опций поле пустое
        assert field.validate() is False

    def test_wipe_sensitive_data(self, field: InlineDropdownField) -> None:
        """Очистка sensitive данных."""
        field.set_value("Неактивен")
        field.wipe_sensitive_data()
        assert field.get_value() == ""


# =========================================================================
# InlineRadioGroupField
# =========================================================================


class TestInlineRadioGroupField:
    """Тесты для InlineRadioGroupField."""

    @pytest.fixture
    def field(self, root: tk.Tk) -> InlineRadioGroupField:
        """Создаёт группу радиокнопок для тестирования."""
        field = InlineRadioGroupField(
            parent=root,
            field_id="priority",
            label="Приоритет",
            options=("Низкий", "Средний", "Высокий"),
        )
        root.update_idletasks()
        return field

    def test_default_first_option(self, field: InlineRadioGroupField) -> None:
        """По умолчанию выбирается первая опция."""
        assert field.get_value() == "Низкий"

    def test_set_value(self, field: InlineRadioGroupField) -> None:
        """Установка допустимого значения."""
        field.set_value("Высокий")
        assert field.get_value() == "Высокий"

    def test_set_invalid_value_fallback(self, field: InlineRadioGroupField) -> None:
        """Установка недопустимого значения сбрасывает на первую опцию."""
        field.set_value("Критический")
        assert field.get_value() == "Низкий"

    def test_validate_valid(self, field: InlineRadioGroupField) -> None:
        """Выбранная опция валидна."""
        assert field.validate() is True

    def test_wipe_sensitive_data(self, field: InlineRadioGroupField) -> None:
        """Очистка sensitive данных сбрасывает выбор."""
        field.set_value("Высокий")
        field.wipe_sensitive_data()
        assert field.get_value() == ""


# =========================================================================
# NumberEntry
# =========================================================================


class TestNumberEntry:
    """Тесты для NumberEntry."""

    @pytest.fixture
    def field(self, root: tk.Tk) -> NumberEntry:
        """Создаёт числовое поле для тестирования."""
        field = NumberEntry(
            parent=root,
            field_id="amount",
            label="Сумма",
            min_value=0.0,
            max_value=1000.0,
            decimal_places=2,
        )
        root.update_idletasks()
        return field

    def test_default_value_is_none(self, field: NumberEntry) -> None:
        """По умолчанию значение None."""
        assert field.get_value() is None

    def test_set_value_decimal(self, field: NumberEntry) -> None:
        """Установка Decimal значения."""
        field.set_value(Decimal("123.45"))
        assert field.get_value() == Decimal("123.45")

    def test_set_value_string(self, field: NumberEntry) -> None:
        """Установка строкового значения."""
        field.set_value("100")
        assert field.get_value() == Decimal("100.00")

    def test_set_value_clamps_min(self, field: NumberEntry) -> None:
        """Значение ниже минимума прижимается к min."""
        field.set_value(Decimal("-50"))
        assert field.get_value() == Decimal("0")

    def test_set_value_clamps_max(self, field: NumberEntry) -> None:
        """Значение выше максимума прижимается к max."""
        field.set_value(Decimal("5000"))
        assert field.get_value() == Decimal("1000.00")

    def test_set_value_rounds(self, field: NumberEntry) -> None:
        """Значение округляется до decimal_places."""
        field.set_value(Decimal("123.456"))
        assert field.get_value() == Decimal("123.46")

    def test_validate_valid(self, field: NumberEntry) -> None:
        """Валидное значение проходит проверку."""
        field.set_value(Decimal("500"))
        assert field.validate() is True

    def test_validate_none(self, field: NumberEntry) -> None:
        """Пустое значение проходит проверку (не обязательное)."""
        assert field.validate() is True

    def test_set_value_none_clears(self, field: NumberEntry) -> None:
        """Установка None очищает поле."""
        field.set_value(Decimal("100"))
        field.set_value(None)
        assert field.get_value() is None

    def test_set_value_empty_string(self, field: NumberEntry) -> None:
        """Установка пустой строки очищает поле."""
        field.set_value("")
        assert field.get_value() is None

    def test_on_change_callback(self, root: tk.Tk) -> None:
        """on_change вызывается при установке значения."""
        changes: list[tuple[str, object]] = []
        field = NumberEntry(
            parent=root,
            field_id="num",
            label="Число",
            on_change=lambda fid, val: changes.append((fid, val)),
        )
        root.update_idletasks()
        field.set_value(Decimal("42"))
        assert len(changes) == 1
        assert changes[0][0] == "num"


# =========================================================================
# DateEntry
# =========================================================================


class TestDateEntry:
    """Тесты для DateEntry."""

    @pytest.fixture
    def field(self, root: tk.Tk) -> DateEntry:
        """Создаёт поле даты для тестирования."""
        field = DateEntry(
            parent=root,
            field_id="issue_date",
            label="Дата выдачи",
        )
        root.update_idletasks()
        return field

    def test_default_value_is_none(self, field: DateEntry) -> None:
        """По умолчанию значение None."""
        assert field.get_value() is None

    def test_set_value_date(self, field: DateEntry) -> None:
        """Установка объекта date."""
        field.set_value(date(2026, 5, 15))
        assert field.get_value() == date(2026, 5, 15)

    def test_set_value_string(self, field: DateEntry) -> None:
        """Установка строкового значения DD.MM.YYYY."""
        field.set_value("15.04.2026")
        assert field.get_value() == date(2026, 4, 15)

    def test_set_invalid_string(self, field: DateEntry) -> None:
        """Установка невалидной строки даёт None."""
        field.set_value("не-дата")
        assert field.get_value() is None

    def test_set_value_none(self, field: DateEntry) -> None:
        """Установка None очищает поле."""
        field.set_value(date(2026, 1, 1))
        field.set_value(None)
        assert field.get_value() is None

    def test_validate_valid(self, field: DateEntry) -> None:
        """Валидная дата проходит проверку."""
        field.set_value(date(2026, 5, 15))
        assert field.validate() is True

    def test_validate_none(self, field: DateEntry) -> None:
        """Пустое значение валидно (не обязательное)."""
        assert field.validate() is True

    def test_wipe_sensitive_data(self, field: DateEntry) -> None:
        """Очистка sensitive данных сбрасывает дату."""
        field.set_value(date(2026, 5, 15))
        field.wipe_sensitive_data()
        assert field.get_value() is None


# =========================================================================
# AutocompleteEntry
# =========================================================================


class TestAutocompleteEntry:
    """Тесты для AutocompleteEntry."""

    @pytest.fixture
    def field(self, root: tk.Tk) -> AutocompleteEntry:
        """Создаёт поле с автодополнением для тестирования."""
        field = AutocompleteEntry(
            parent=root,
            field_id="company",
            document_index="DVN-44-K53-IX",
            label="Компания",
        )
        root.update_idletasks()
        return field

    def test_default_value_is_empty(self, field: AutocompleteEntry) -> None:
        """По умолчанию значение пустое."""
        assert field.get_value() in (None, "")

    def test_set_value(self, field: AutocompleteEntry) -> None:
        """Установка значения."""
        field.set_value("ООО Ромашка")
        assert field.get_value() == "ООО Ромашка"

    def test_set_value_none(self, field: AutocompleteEntry) -> None:
        """Установка None даёт пустую строку."""
        field.set_value(None)
        assert field.get_value() == ""

    def test_wipe_sensitive_data(self, field: AutocompleteEntry) -> None:
        """Очистка sensitive данных."""
        field.set_value("Секретные данные")
        field.wipe_sensitive_data()
        assert field.get_value() == ""

    def test_parse_index_hierarchy(self, field: AutocompleteEntry) -> None:
        """Парсинг индекса в иерархию."""
        hierarchy = field._parse_index("DVN-44-K53-IX")
        assert hierarchy == ["DVN", "DVN-44", "DVN-44-K53", "DVN-44-K53-IX"]

    def test_parse_index_empty(self, field: AutocompleteEntry) -> None:
        """Парсинг пустого индекса."""
        hierarchy = field._parse_index("")
        assert hierarchy == []

    def test_validate_empty(self, field: AutocompleteEntry) -> None:
        """Пустое поле валидно."""
        assert field.validate() is True

    def test_validate_with_value(self, field: AutocompleteEntry) -> None:
        """Заполненное поле валидно."""
        field.set_value("Значение")
        assert field.validate() is True


# =========================================================================
# TableField
# =========================================================================


class TestTableField:
    """Тесты для TableField."""

    @pytest.fixture
    def field(self, root: tk.Tk) -> TableField:
        """Создаёт табличное поле для тестирования."""
        field = TableField(
            parent=root,
            field_id="items",
            columns=["Наименование", "Количество", "Цена"],
            rows=2,
        )
        root.update_idletasks()
        return field

    def test_initial_rows(self, field: TableField) -> None:
        """Начальное количество строк соответствует rows."""
        data = field.get_value()
        assert len(data) == 2

    def test_set_value_list(self, field: TableField) -> None:
        """Установка данных как list[list[str]]."""
        field.set_value([["Товар A", "5", "100"], ["Товар B", "3", "200"]])
        data = field.get_value()
        assert len(data) == 2
        assert data[0][0] == "Товар A"

    def test_set_value_none(self, field: TableField) -> None:
        """Установка None очищает до min_rows."""
        field.set_value(None)
        data = field.get_value()
        assert len(data) >= 1  # min_rows = 1

    def test_validate_min_rows(self, field: TableField) -> None:
        """Валидация при допустимом количестве строк."""
        assert field.validate() is True

    def test_wipe_sensitive_data(self, field: TableField) -> None:
        """Очистка sensitive данных."""
        field.set_value([["Секрет", "1", "999"]])
        field.wipe_sensitive_data()
        # Все ячейки пустые
        for row in field.get_value():
            for cell in row:
                assert cell == ""


# =========================================================================
# InlineMultiLineField
# =========================================================================


class TestInlineMultiLineField:
    """Тесты для InlineMultiLineField."""

    @pytest.fixture
    def field(self, root: tk.Tk) -> InlineMultiLineField:
        """Создаёт многострочное поле для тестирования."""
        field = InlineMultiLineField(
            parent=root,
            field_id="notes",
            label="Примечания",
        )
        root.update_idletasks()
        return field

    def test_default_value_is_empty(self, field: InlineMultiLineField) -> None:
        """По умолчанию значение пустое."""
        assert field.get_value() == ""

    def test_set_value(self, field: InlineMultiLineField) -> None:
        """Установка текстового значения."""
        field.set_value("Строка 1\nСтрока 2")
        assert field.get_value() == "Строка 1\nСтрока 2"

    def test_set_value_none(self, field: InlineMultiLineField) -> None:
        """Установка None даёт пустую строку."""
        field.set_value(None)
        assert field.get_value() == ""

    def test_validate_empty_not_required(self, field: InlineMultiLineField) -> None:
        """Пустое необязательное поле валидно."""
        assert field.validate() is True

    def test_validate_required_empty(self, root: tk.Tk) -> None:
        """Пустое обязательное поле невалидно."""
        field = InlineMultiLineField(
            parent=root,
            field_id="req_notes",
            label="Обязательные примечания",
            required=True,
        )
        root.update_idletasks()
        assert field.validate() is False

    def test_validate_max_length(self, root: tk.Tk) -> None:
        """Превышение max_length делает поле невалидным."""
        field = InlineMultiLineField(
            parent=root,
            field_id="short",
            label="Короткое поле",
            max_length=5,
        )
        root.update_idletasks()
        field.set_value("Слишком длинный текст")
        assert field.validate() is False

    def test_wipe_sensitive_data(self, field: InlineMultiLineField) -> None:
        """Очистка sensitive данных."""
        field.set_value("Секретные данные")
        field.wipe_sensitive_data()
        assert field.get_value() == ""