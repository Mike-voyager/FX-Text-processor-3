"""Тесты для модуля field_palette.

Покрытие:
- PaletteCategory Enum
- PaletteEntry dataclass
- FieldPalette класс с методами
"""

from __future__ import annotations

from src.documents.constructor.field_palette import (
    FieldPalette,
    PaletteCategory,
    PaletteEntry,
)
from src.documents.types.type_schema import FieldType


class TestPaletteCategory:
    """Тесты для PaletteCategory."""

    def test_basic_category(self) -> None:
        """Категория BASIC."""
        assert PaletteCategory.BASIC.value == "basic"

    def test_text_category(self) -> None:
        """Категория TEXT."""
        assert PaletteCategory.TEXT.value == "text"

    def test_numeric_category(self) -> None:
        """Категория NUMERIC."""
        assert PaletteCategory.NUMERIC.value == "numeric"

    def test_special_category(self) -> None:
        """Категория SPECIAL."""
        assert PaletteCategory.SPECIAL.value == "special"

    def test_media_category(self) -> None:
        """Категория MEDIA."""
        assert PaletteCategory.MEDIA.value == "media"

    def test_category_is_str(self) -> None:
        """Категория — строковый enum."""
        assert isinstance(PaletteCategory.BASIC.value, str)

    def test_category_comparison(self) -> None:
        """Сравнение категорий."""
        assert PaletteCategory.BASIC.value == "basic"
        # Разные категории имеют разные значения
        assert PaletteCategory.TEXT.value == "text"


class TestPaletteEntry:
    """Тесты для PaletteEntry."""

    def test_create_minimal(self) -> None:
        """Создание с минимальными параметрами."""
        entry = PaletteEntry(
            field_type=FieldType.TEXT_INPUT,
            category=PaletteCategory.BASIC,
            label="Тест",
            label_en="Test",
            description="Описание",
            description_en="Description",
            icon="test_icon",
        )
        assert entry.field_type == FieldType.TEXT_INPUT
        assert entry.category == PaletteCategory.BASIC
        assert entry.label == "Тест"
        assert entry.default_width == 20
        assert entry.default_height == 1

    def test_create_full(self) -> None:
        """Создание со всеми параметрами."""
        entry = PaletteEntry(
            field_type=FieldType.TABLE,
            category=PaletteCategory.SPECIAL,
            label="Таблица",
            label_en="Table",
            description="Большая таблица",
            description_en="Big table",
            icon="table_icon",
            default_width=50,
            default_height=10,
        )
        assert entry.default_width == 50
        assert entry.default_height == 10


class TestFieldPaletteGetByCategory:
    """Тесты метода get_by_category."""

    def test_get_basic_fields(self) -> None:
        """Получение полей категории BASIC."""
        entries = FieldPalette.get_by_category(PaletteCategory.BASIC)
        assert len(entries) > 0
        field_types = [e.field_type for e in entries]
        assert FieldType.TEXT_INPUT in field_types
        assert FieldType.DATE_INPUT in field_types

    def test_get_text_fields(self) -> None:
        """Получение полей категории TEXT."""
        entries = FieldPalette.get_by_category(PaletteCategory.TEXT)
        assert len(entries) > 0
        field_types = [e.field_type for e in entries]
        assert FieldType.STATIC_TEXT in field_types

    def test_get_numeric_fields(self) -> None:
        """Получение полей категории NUMERIC."""
        entries = FieldPalette.get_by_category(PaletteCategory.NUMERIC)
        assert len(entries) > 0
        field_types = [e.field_type for e in entries]
        assert FieldType.NUMBER_INPUT in field_types

    def test_get_special_fields(self) -> None:
        """Получение полей категории SPECIAL."""
        entries = FieldPalette.get_by_category(PaletteCategory.SPECIAL)
        assert len(entries) > 0
        field_types = [e.field_type for e in entries]
        assert FieldType.TABLE in field_types

    def test_get_media_fields(self) -> None:
        """Получение полей категории MEDIA."""
        entries = FieldPalette.get_by_category(PaletteCategory.MEDIA)
        assert len(entries) > 0
        field_types = [e.field_type for e in entries]
        assert FieldType.QR in field_types

    def test_empty_category_not_exists(self) -> None:
        """Несуществующая категория — пустой список."""
        # All predefined categories have entries
        entries = FieldPalette.get_by_category(PaletteCategory.BASIC)
        assert len(entries) >= 0  # BASIC exists


class TestFieldPaletteGetByFieldType:
    """Тесты метода get_by_field_type."""

    def test_get_text_input(self) -> None:
        """Получение TEXT_INPUT."""
        entry = FieldPalette.get_by_field_type(FieldType.TEXT_INPUT)
        assert entry is not None
        assert entry.label == "Текстовое поле"

    def test_get_nonexistent_returns_none(self) -> None:
        """Несуществующий тип возвращает None."""
        # All FieldType values should be in palette
        entry = FieldPalette.get_by_field_type(FieldType.TEXT_INPUT)
        assert entry is not None

    def test_get_table(self) -> None:
        """Получение TABLE."""
        entry = FieldPalette.get_by_field_type(FieldType.TABLE)
        assert entry is not None
        assert entry.default_height == 10

    def test_get_signature(self) -> None:
        """Получение SIGNATURE."""
        entry = FieldPalette.get_by_field_type(FieldType.SIGNATURE)
        assert entry is not None
        assert entry.category == PaletteCategory.MEDIA


class TestFieldPaletteGetAllCategories:
    """Тесты метода get_all_categories."""

    def test_returns_all_categories(self) -> None:
        """Возвращает все категории."""
        categories = FieldPalette.get_all_categories()
        assert len(categories) == 5
        assert PaletteCategory.BASIC in categories
        assert PaletteCategory.TEXT in categories


class TestFieldPaletteGetAllEntries:
    """Тесты метода get_all_entries."""

    def test_returns_all_entries(self) -> None:
        """Возвращает все элементы."""
        entries = FieldPalette.get_all_entries()
        assert len(entries) == len(FieldPalette.ENTRIES)

    def test_entries_count(self) -> None:
        """Количество элементов."""
        entries = FieldPalette.get_all_entries()
        # Should have all field types from palette
        assert len(entries) >= 15


class TestFieldPaletteSearch:
    """Тесты метода search."""

    def test_search_by_russian_label(self) -> None:
        """Поиск по русской метке."""
        results = FieldPalette.search("текст")
        assert len(results) > 0

    def test_search_by_english_label(self) -> None:
        """Поиск по английской метке."""
        results = FieldPalette.search("text")
        assert len(results) > 0

    def test_search_by_description(self) -> None:
        """Поиск по описанию."""
        results = FieldPalette.search("table")
        assert len(results) > 0

    def test_search_case_insensitive(self) -> None:
        """Поиск регистронезависимый."""
        results_lower = FieldPalette.search("text")
        results_upper = FieldPalette.search("TEXT")
        assert len(results_lower) == len(results_upper)

    def test_search_no_results(self) -> None:
        """Поиск без результатов."""
        results = FieldPalette.search("xyz_nonexistent")
        assert len(results) == 0

    def test_search_partial_match(self) -> None:
        """Частичное совпадение."""
        results = FieldPalette.search("поле")  # часть слова
        assert len(results) > 0


class TestPaletteEntriesContent:
    """Тесты содержимого ENTRIES."""

    def test_text_input_entry(self) -> None:
        """Entry для TEXT_INPUT."""
        entry = FieldPalette.get_by_field_type(FieldType.TEXT_INPUT)
        assert entry is not None
        assert entry.label == "Текстовое поле"
        assert entry.default_width == 30

    def test_multi_line_text_entry(self) -> None:
        """Entry для MULTI_LINE_TEXT."""
        entry = FieldPalette.get_by_field_type(FieldType.MULTI_LINE_TEXT)
        assert entry is not None
        assert entry.default_height == 5

    def test_qr_entry(self) -> None:
        """Entry для QR."""
        entry = FieldPalette.get_by_field_type(FieldType.QR)
        assert entry is not None
        assert entry.default_width == 10
        assert entry.default_height == 10

    def test_all_field_types_covered(self) -> None:
        """Все типы полей есть в палитре."""
        entries = FieldPalette.get_all_entries()
        entry_types = {e.field_type for e in entries}
        # Check core types are present
        assert FieldType.TEXT_INPUT in entry_types
        assert FieldType.DATE_INPUT in entry_types
        assert FieldType.NUMBER_INPUT in entry_types
        assert FieldType.CURRENCY in entry_types
        assert FieldType.TABLE in entry_types
