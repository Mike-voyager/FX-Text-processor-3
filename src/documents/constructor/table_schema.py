"""Модуль схемы таблиц для полей типа TABLE.

Предоставляет:
- SummaryFunction: Enum для итоговых функций таблиц
- ColumnDefinition: Определение колонки таблицы
- TableSchema: Схема таблицы с колонками и настройками

Example:
    >>> from src.documents.constructor.table_schema import (
    ...     SummaryFunction, ColumnDefinition, TableSchema
    ... )
    >>> from src.documents.types.type_schema import FieldType
    >>> schema = TableSchema(
    ...     columns=(
    ...         ColumnDefinition(
    ...             column_id="item",
    ...             header="Наименование",
    ...             column_type=FieldType.TEXT_INPUT,
    ...             width_chars=40,
    ...             editable=True,
    ...         ),
    ...         ColumnDefinition(
    ...             column_id="quantity",
    ...             header="Кол-во",
    ...             column_type=FieldType.NUMBER_INPUT,
    ...             width_chars=10,
    ...             summary_function=SummaryFunction.SUM,
    ...         ),
    ...     ),
    ...     min_rows=1,
    ...     max_rows=100,
    ...     show_summary_row=True,
    ... )
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from src.documents.types.type_schema import FieldType

logger: Final = logging.getLogger(__name__)


class SummaryFunction(str, Enum):
    """Итоговые функции для колонок таблицы.

    Attributes:
        SUM: Сумма значений колонки
        COUNT: Количество строк
        AVG: Среднее значение
        MIN: Минимальное значение
        MAX: Максимальное значение
    """

    SUM = "sum"
    COUNT = "count"
    AVG = "avg"
    MIN = "min"
    MAX = "max"

    @property
    def localized_name(self) -> str:
        """Возвращает локализованное название функции."""
        names = {
            SummaryFunction.SUM: "Сумма",
            SummaryFunction.COUNT: "Количество",
            SummaryFunction.AVG: "Среднее",
            SummaryFunction.MIN: "Минимум",
            SummaryFunction.MAX: "Максимум",
        }
        return names.get(self, self.value)


@dataclass(frozen=True)
class ColumnDefinition:
    """Определение колонки таблицы.

    Attributes:
        column_id: Программное имя колонки (уникальное в пределах таблицы)
        header: Заголовок колонки для отображения
        column_type: Тип данных колонки (TEXT_INPUT, NUMBER_INPUT, CURRENCY и т.д.)
        width_chars: Ширина колонки в символах (None = авто)
        editable: Разрешено ли редактирование
        sortable: Разрешена ли сортировка
        required: Обязательность заполнения
        default_value: Значение по умолчанию
        summary_function: Итоговая функция для summary row
        validation_pattern: Regex-паттерн для валидации
        max_length: Максимальная длина строки

    Example:
        >>> from src.documents.types.type_schema import FieldType
        >>> col = ColumnDefinition(
        ...     column_id="price",
        ...     header="Цена",
        ...     column_type=FieldType.CURRENCY,
        ...     width_chars=15,
        ...     summary_function=SummaryFunction.SUM,
        ... )
    """

    column_id: str
    header: str
    column_type: "FieldType"
    width_chars: int | None = None
    editable: bool = True
    sortable: bool = True
    required: bool = False
    default_value: Any = None
    summary_function: SummaryFunction | None = None
    validation_pattern: str | None = None
    max_length: int | None = None

    def __post_init__(self) -> None:
        """Валидация параметров колонки."""
        if not isinstance(self.column_id, str):
            raise TypeError(f"column_id должен быть str, получен {type(self.column_id).__name__}")
        if not self.column_id:
            raise ValueError("column_id не может быть пустым")
        if not isinstance(self.header, str):
            raise TypeError(f"header должен быть str, получен {type(self.header).__name__}")
        if not self.header:
            raise ValueError("header не может быть пустым")

        # Валидация width_chars
        if self.width_chars is not None:
            if not isinstance(self.width_chars, int):
                raise TypeError(
                    "width_chars должен быть int или None, "
                    f"получен {type(self.width_chars).__name__}"
                )
            if self.width_chars < 1:
                raise ValueError(f"width_chars должен быть >= 1, получен {self.width_chars}")

        # Валидация max_length
        if self.max_length is not None:
            if not isinstance(self.max_length, int):
                raise TypeError(
                    f"max_length должен быть int или None, получен {type(self.max_length).__name__}"
                )
            if self.max_length < 1:
                raise ValueError(f"max_length должен быть >= 1, получен {self.max_length}")

    def get_display_width(self, default_width: int = 20) -> int:
        """Возвращает ширину колонки для отображения.

        Args:
            default_width: Ширина по умолчанию, если width_chars не задан

        Returns:
            Ширина колонки в символах
        """
        return self.width_chars if self.width_chars is not None else default_width

    def can_have_summary(self) -> bool:
        """Проверяет, может ли колонка иметь итоговую функцию.

        Returns:
            True если колонка поддерживает итоговые функции
        """
        # Итоги имеют смысл только для числовых типов
        numeric_types = {"number_input", "currency", "calculated"}
        return self.column_type.value in numeric_types


@dataclass(frozen=True)
class TableSchema:
    """Схема таблицы с определением колонок и настроек.

    Attributes:
        columns: Кортеж определений колонок
        min_rows: Минимальное количество строк
        max_rows: Максимальное количество строк (None = неограничено)
        auto_number: Автоматическая нумерация строк
        show_summary_row: Показывать строку итогов
        summary_functions: Итоговые функции для summary row
        row_height: Высота строки в строках ESC/P

    Example:
        >>> from src.documents.types.type_schema import FieldType
        >>> schema = TableSchema(
        ...     columns=(
        ...         ColumnDefinition("name", "Наименование", FieldType.TEXT_INPUT),
        ...         ColumnDefinition("qty", "Кол-во", FieldType.NUMBER_INPUT),
        ...     ),
        ...     min_rows=1,
        ...     max_rows=50,
        ...     auto_number=True,
        ... )
    """

    columns: tuple[ColumnDefinition, ...]
    min_rows: int = 0
    max_rows: int | None = None
    auto_number: bool = False
    show_summary_row: bool = False
    summary_functions: tuple[SummaryFunction, ...] = field(default_factory=tuple)
    row_height: int = 1

    def __post_init__(self) -> None:
        """Валидация схемы таблицы."""
        # Валидация columns
        if not isinstance(self.columns, tuple):
            raise TypeError(f"columns должен быть tuple, получен {type(self.columns).__name__}")

        # Проверяем уникальность column_id
        column_ids = [col.column_id for col in self.columns]
        if len(column_ids) != len(set(column_ids)):
            duplicates = [cid for cid in column_ids if column_ids.count(cid) > 1]
            raise ValueError(f"Column IDs must be unique, duplicates found: {set(duplicates)}")

        # Валидация min_rows
        if not isinstance(self.min_rows, int):
            raise TypeError(f"min_rows должен быть int, получен {type(self.min_rows).__name__}")
        if self.min_rows < 0:
            raise ValueError(f"min_rows не может быть отрицательным, получен {self.min_rows}")

        # Валидация max_rows
        if self.max_rows is not None:
            if not isinstance(self.max_rows, int):
                raise TypeError(
                    f"max_rows должен быть int или None, получен {type(self.max_rows).__name__}"
                )
            if self.max_rows < 1:
                raise ValueError(f"max_rows должен быть >= 1, получен {self.max_rows}")
            if self.max_rows < self.min_rows:
                raise ValueError(
                    f"max_rows ({self.max_rows}) должен быть >= min_rows ({self.min_rows})"
                )

        # Валидация row_height
        if not isinstance(self.row_height, int):
            raise TypeError(f"row_height должен быть int, получен {type(self.row_height).__name__}")
        if self.row_height < 1:
            raise ValueError(f"row_height должен быть >= 1, получен {self.row_height}")

        # Валидация summary_functions
        if not isinstance(self.summary_functions, tuple):
            raise TypeError(
                "summary_functions должен быть tuple, "
                f"получен {type(self.summary_functions).__name__}"
            )

        # Проверяем, что summary row имеет смысл
        if self.show_summary_row and not self.columns:
            raise ValueError("Cannot show summary row without columns")

        # Проверяем, что summary_functions соответствуют колонкам
        for func in self.summary_functions:
            if not isinstance(func, SummaryFunction):
                raise TypeError(
                    "summary_functions must contain SummaryFunction enum values, "
                    f"got {type(func).__name__}"
                )

    def get_column(self, column_id: str) -> ColumnDefinition:
        """Возвращает определение колонки по ID.

        Args:
            column_id: Идентификатор колонки

        Returns:
            Определение колонки

        Raises:
            KeyError: Если колонка не найдена
        """
        for col in self.columns:
            if col.column_id == column_id:
                return col
        raise KeyError(f"Column not found: {column_id}")

    def has_column(self, column_id: str) -> bool:
        """Проверяет наличие колонки в схеме.

        Args:
            column_id: Идентификатор колонки

        Returns:
            True если колонка существует
        """
        return any(col.column_id == column_id for col in self.columns)

    @property
    def column_count(self) -> int:
        """Возвращает количество колонок."""
        return len(self.columns)

    @property
    def editable_columns(self) -> list[ColumnDefinition]:
        """Возвращает список редактируемых колонок."""
        return [col for col in self.columns if col.editable]

    @property
    def sortable_columns(self) -> list[ColumnDefinition]:
        """Возвращает список сортируемых колонок."""
        return [col for col in self.columns if col.sortable]

    @property
    def required_columns(self) -> list[ColumnDefinition]:
        """Возвращает список обязательных колонок."""
        return [col for col in self.columns if col.required]

    def get_columns_with_summary(self) -> list[ColumnDefinition]:
        """Возвращает колонки с итоговыми функциями.

        Returns:
            Список колонок с summary_function
        """
        return [col for col in self.columns if col.summary_function is not None]

    def validate_row_count(self, row_count: int) -> list[str]:
        """Валидирует количество строк таблицы.

        Args:
            row_count: Текущее количество строк

        Returns:
            Список ошибок (пустой если валидно)
        """
        errors: list[str] = []

        if row_count < self.min_rows:
            errors.append(f"Table must have at least {self.min_rows} rows, got {row_count}")

        if self.max_rows is not None and row_count > self.max_rows:
            errors.append(f"Table can have at most {self.max_rows} rows, got {row_count}")

        return errors

    def get_total_width(self, default_column_width: int = 20) -> int:
        """Вычисляет общую ширину таблицы в символах.

        Args:
            default_column_width: Ширина по умолчанию для колонок без width_chars

        Returns:
            Общая ширина таблицы в символах
        """
        return sum(col.get_display_width(default_column_width) for col in self.columns)

    def to_dict(self) -> dict[str, Any]:
        """Сериализует схему в словарь.

        Returns:
            Словарь с данными схемы
        """
        return {
            "columns": [
                {
                    "column_id": col.column_id,
                    "header": col.header,
                    "column_type": col.column_type.value,
                    "width_chars": col.width_chars,
                    "editable": col.editable,
                    "sortable": col.sortable,
                    "required": col.required,
                    "default_value": col.default_value,
                    "summary_function": col.summary_function.value
                    if col.summary_function
                    else None,
                    "validation_pattern": col.validation_pattern,
                    "max_length": col.max_length,
                }
                for col in self.columns
            ],
            "min_rows": self.min_rows,
            "max_rows": self.max_rows,
            "auto_number": self.auto_number,
            "show_summary_row": self.show_summary_row,
            "summary_functions": [f.value for f in self.summary_functions],
            "row_height": self.row_height,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TableSchema":
        """Создаёт схему из словаря.

        Args:
            data: Словарь с данными схемы

        Returns:
            Экземпляр TableSchema
        """
        from src.documents.types.type_schema import FieldType

        columns = tuple(
            ColumnDefinition(
                column_id=col["column_id"],
                header=col["header"],
                column_type=FieldType(col["column_type"]),
                width_chars=col.get("width_chars"),
                editable=col.get("editable", True),
                sortable=col.get("sortable", True),
                required=col.get("required", False),
                default_value=col.get("default_value"),
                summary_function=SummaryFunction(col["summary_function"])
                if col.get("summary_function")
                else None,
                validation_pattern=col.get("validation_pattern"),
                max_length=col.get("max_length"),
            )
            for col in data.get("columns", [])
        )

        return cls(
            columns=columns,
            min_rows=data.get("min_rows", 0),
            max_rows=data.get("max_rows"),
            auto_number=data.get("auto_number", False),
            show_summary_row=data.get("show_summary_row", False),
            summary_functions=tuple(SummaryFunction(f) for f in data.get("summary_functions", [])),
            row_height=data.get("row_height", 1),
        )


__all__ = [
    "SummaryFunction",
    "ColumnDefinition",
    "TableSchema",
]
