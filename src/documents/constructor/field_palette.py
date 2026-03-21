"""Field palette for visual editor.

Provides:
- FieldPalette: Collection of available field types
- PaletteCategory: Grouping of field types
- PaletteEntry: Individual entry in the palette
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.documents.types.type_schema import FieldType


class PaletteCategory(str, Enum):
    """Категории полей в палитре визуального редактора."""

    BASIC = "basic"  # Базовые поля ввода
    TEXT = "text"  # Текстовые поля
    NUMERIC = "numeric"  # Числовые поля
    SPECIAL = "special"  # Специальные поля
    MEDIA = "media"  # Штрихкоды, QR


@dataclass
class PaletteEntry:
    """Элемент палитры полей.

    Attributes:
        field_type: Тип поля.
        category: Категория в палитре.
        label: Метка для отображения.
        description: Описание поля.
        icon: Имя иконки (для GUI).
        default_width: Ширина по умолчанию в символах.
        default_height: Высота по умолчанию в строках.
    """

    field_type: FieldType
    category: PaletteCategory
    label: str
    label_en: str
    description: str
    description_en: str
    icon: str
    default_width: int = 20
    default_height: int = 1


class FieldPalette:
    """Палитра доступных типов полей для визуального редактора.

    Предоставляет категоризированный список типов полей
    с метаданными для отображения в редакторе.
    """

    # Все доступные типы полей с метаданными
    ENTRIES: tuple[PaletteEntry, ...] = (
        # Basic
        PaletteEntry(
            field_type=FieldType.TEXT_INPUT,
            category=PaletteCategory.BASIC,
            label="Текстовое поле",
            label_en="Text input",
            description="Однострочное текстовое поле",
            description_en="Single-line text input",
            icon="text_field",
            default_width=30,
            default_height=1,
        ),
        PaletteEntry(
            field_type=FieldType.MULTI_LINE_TEXT,
            category=PaletteCategory.BASIC,
            label="Многострочный текст",
            label_en="Multi-line text",
            description="Многострочное текстовое поле",
            description_en="Multi-line text area",
            icon="text_area",
            default_width=40,
            default_height=5,
        ),
        PaletteEntry(
            field_type=FieldType.NUMBER_INPUT,
            category=PaletteCategory.NUMERIC,
            label="Числовое поле",
            label_en="Number input",
            description="Поле для ввода чисел",
            description_en="Numeric input field",
            icon="numbers",
            default_width=15,
            default_height=1,
        ),
        PaletteEntry(
            field_type=FieldType.DATE_INPUT,
            category=PaletteCategory.BASIC,
            label="Дата",
            label_en="Date",
            description="Поле для ввода даты",
            description_en="Date input field",
            icon="calendar_today",
            default_width=12,
            default_height=1,
        ),
        # Text
        PaletteEntry(
            field_type=FieldType.STATIC_TEXT,
            category=PaletteCategory.TEXT,
            label="Статический текст",
            label_en="Static text",
            description="Неизменяемый текст шаблона",
            description_en="Non-editable template text",
            icon="text_fields",
            default_width=30,
            default_height=1,
        ),
        PaletteEntry(
            field_type=FieldType.PHONE,
            category=PaletteCategory.TEXT,
            label="Телефон",
            label_en="Phone",
            description="Поле для ввода телефона",
            description_en="Phone number input",
            icon="phone",
            default_width=18,
            default_height=1,
        ),
        PaletteEntry(
            field_type=FieldType.EMAIL,
            category=PaletteCategory.TEXT,
            label="Email",
            label_en="Email",
            description="Поле для ввода email",
            description_en="Email address input",
            icon="email",
            default_width=25,
            default_height=1,
        ),
        # Numeric
        PaletteEntry(
            field_type=FieldType.CURRENCY,
            category=PaletteCategory.NUMERIC,
            label="Денежная сумма",
            label_en="Currency",
            description="Поле для ввода суммы в валюте",
            description_en="Currency amount input",
            icon="attach_money",
            default_width=15,
            default_height=1,
        ),
        # Special
        PaletteEntry(
            field_type=FieldType.TABLE,
            category=PaletteCategory.SPECIAL,
            label="Таблица",
            label_en="Table",
            description="Таблица с данными",
            description_en="Data table",
            icon="table_chart",
            default_width=50,
            default_height=10,
        ),
        PaletteEntry(
            field_type=FieldType.CALCULATED,
            category=PaletteCategory.SPECIAL,
            label="Вычисляемое поле",
            label_en="Calculated field",
            description="Автоматически вычисляемое значение",
            description_en="Auto-calculated value",
            icon="functions",
            default_width=15,
            default_height=1,
        ),
        PaletteEntry(
            field_type=FieldType.DROPDOWN,
            category=PaletteCategory.SPECIAL,
            label="Выпадающий список",
            label_en="Dropdown",
            description="Выбор из списка вариантов",
            description_en="Selection from options",
            icon="arrow_drop_down_circle",
            default_width=20,
            default_height=1,
        ),
        PaletteEntry(
            field_type=FieldType.CHECKBOX,
            category=PaletteCategory.SPECIAL,
            label="Флажок",
            label_en="Checkbox",
            description="Булев флажок",
            description_en="Boolean checkbox",
            icon="check_box",
            default_width=3,
            default_height=1,
        ),
        PaletteEntry(
            field_type=FieldType.RADIO_GROUP,
            category=PaletteCategory.SPECIAL,
            label="Группа переключателей",
            label_en="Radio group",
            description="Группа радиокнопок",
            description_en="Radio button group",
            icon="radio_button_checked",
            default_width=20,
            default_height=3,
        ),
        PaletteEntry(
            field_type=FieldType.EXCEL_IMPORT,
            category=PaletteCategory.SPECIAL,
            label="Импорт из Excel",
            label_en="Excel import",
            description="Импорт данных из Excel",
            description_en="Import data from Excel",
            icon="table_rows",
            default_width=30,
            default_height=1,
        ),
        # Media
        PaletteEntry(
            field_type=FieldType.BARCODE,
            category=PaletteCategory.MEDIA,
            label="Штрих-код",
            label_en="Barcode",
            description="Штрих-код (EAN, Code128, etc)",
            description_en="Barcode (EAN, Code128, etc)",
            icon="qr_code",
            default_width=20,
            default_height=3,
        ),
        PaletteEntry(
            field_type=FieldType.QR,
            category=PaletteCategory.MEDIA,
            label="QR-код",
            label_en="QR code",
            description="QR-код",
            description_en="QR code",
            icon="qr_code_2",
            default_width=10,
            default_height=10,
        ),
        PaletteEntry(
            field_type=FieldType.SIGNATURE,
            category=PaletteCategory.MEDIA,
            label="Подпись",
            label_en="Signature",
            description="Цифровая подпись",
            description_en="Digital signature",
            icon="draw",
            default_width=20,
            default_height=3,
        ),
        PaletteEntry(
            field_type=FieldType.STAMP,
            category=PaletteCategory.MEDIA,
            label="Печать",
            label_en="Stamp",
            description="Изображение печати/штампа",
            description_en="Stamp/seal image",
            icon="approval",
            default_width=15,
            default_height=5,
        ),
    )

    @classmethod
    def get_by_category(cls, category: PaletteCategory) -> list[PaletteEntry]:
        """Возвращает элементы палитры по категории.

        Args:
            category: Категория для фильтрации.

        Returns:
            Список элементов палитры.
        """
        return [e for e in cls.ENTRIES if e.category == category]

    @classmethod
    def get_by_field_type(
        cls, field_type: FieldType
    ) -> PaletteEntry | None:
        """Возвращает элемент палитры по типу поля.

        Args:
            field_type: Тип поля.

        Returns:
            Элемент палитры или None.
        """
        for entry in cls.ENTRIES:
            if entry.field_type == field_type:
                return entry
        return None

    @classmethod
    def get_all_categories(cls) -> list[PaletteCategory]:
        """Возвращает все доступные категории.

        Returns:
            Список категорий.
        """
        return list(PaletteCategory)

    @classmethod
    def get_all_entries(cls) -> list[PaletteEntry]:
        """Возвращает все элементы палитры.

        Returns:
            Список всех элементов.
        """
        return list(cls.ENTRIES)

    @classmethod
    def search(cls, query: str) -> list[PaletteEntry]:
        """Поиск по меткам и описаниям.

        Args:
            query: Поисковый запрос.

        Returns:
            Список найденных элементов.
        """
        query_lower = query.lower()
        return [
            e
            for e in cls.ENTRIES
            if query_lower in e.label.lower()
            or query_lower in e.label_en.lower()
            or query_lower in e.description.lower()
            or query_lower in e.description_en.lower()
        ]