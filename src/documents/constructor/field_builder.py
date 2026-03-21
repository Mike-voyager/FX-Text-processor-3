"""Field builder for visual editor.

Provides:
- FieldBuilder: Constructs field widgets for visual editor
- FieldPosition: Positioning information for fields
- OverflowBehavior: How to handle text overflow
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any

from src.documents.types.type_schema import FieldDefinition, FieldType, OverflowBehavior


@dataclass
class FieldPosition:
    """Позиция поля в документе.

    Attributes:
        x_column: Позиция X в символах ESC/P.
        y_row: Позиция Y в строках ESC/P.
        width_chars: Ширина в символах (None = auto).
        height_rows: Высота в строках (по умолчанию 1).
        overflow_behavior: Поведение при переполнении.
    """

    x_column: int
    y_row: int
    width_chars: int | None = None
    height_rows: int = 1
    overflow_behavior: OverflowBehavior = OverflowBehavior.TRUNCATE


class FieldBuilder:
    """Построитель полей для визуального редактора.

    Создаёт объекты полей с позиционированием и значениями.
    """

    def __init__(self) -> None:
        """Инициализирует построитель полей."""
        self._counter = 0

    def build_field(
        self,
        field_def: FieldDefinition,
        position: FieldPosition,
        value: Any = None,
    ) -> dict[str, Any]:
        """Создаёт объект поля для редактора.

        Args:
            field_def: Определение поля из схемы.
            position: Позиция поля в документе.
            value: Значение поля (по умолчанию - из default_value).

        Returns:
            Словарь с данными поля для редактора.
        """
        self._counter += 1

        return {
            "id": f"field_{self._counter}",
            "field_name": field_def.name,
            "field_type": field_def.field_type.value,
            "label": field_def.label,
            "label_en": field_def.label_en,
            "required": field_def.required,
            "value": value if value is not None else field_def.default_value,
            "position": {
                "x": position.x_column,
                "y": position.y_row,
                "width": position.width_chars,
                "height": position.height_rows,
                "overflow": position.overflow_behavior.value,
            },
            "validation": list(field_def.validation),
            "validation_rules": {
                "min_value": field_def.min_value,
                "max_value": field_def.max_value,
                "min_date": field_def.min_date.isoformat()
                if field_def.min_date
                else None,
                "max_date": field_def.max_date.isoformat()
                if field_def.max_date
                else None,
                "required_if": field_def.required_if,
                "cross_field_rules": list(field_def.cross_field_rules),
            },
            "ux": {
                "tab_index": field_def.tab_index,
                "input_mask": field_def.input_mask,
                "placeholder": field_def.placeholder,
                "autocomplete_source": field_def.autocomplete_source,
                "help_text": field_def.help_text,
                "visibility_condition": field_def.visibility_condition,
                "read_only_condition": field_def.read_only_condition,
                "enabled_condition": field_def.enabled_condition,
            },
        }

    def build_fields_from_schema(
        self,
        fields: list[FieldDefinition],
        start_x: int = 0,
        start_y: int = 0,
        row_height: int = 1,
    ) -> list[dict[str, Any]]:
        """Создаёт список полей из схемы с авто-позиционированием.

        Args:
            fields: Список определений полей.
            start_x: Начальная позиция X.
            start_y: Начальная позиция Y.
            row_height: Высота строки в строках.

        Returns:
            Список объектов полей.
        """
        result: list[dict[str, Any]] = []
        current_x = start_x
        current_y = start_y

        for field_def in fields:
            position = FieldPosition(
                x_column=current_x,
                y_row=current_y,
                height_rows=row_height,
            )

            field_obj = self.build_field(field_def, position)
            result.append(field_obj)

            # Переход к следующей строке
            current_y += row_height

        return result

    def calculate_field_bounds(
        self,
        field_def: FieldDefinition,
        value: str,
        font_width: float = 10.0,
    ) -> tuple[int, int]:
        """Вычисляет размеры поля на основе содержимого.

        Args:
            field_def: Определение поля.
            value: Значение поля.
            font_width: Ширина символа в пикселях.

        Returns:
            Кортеж (width_chars, height_rows).
        """
        if not value:
            return (20, 1)  # Минимальный размер

        text_length = len(str(value))
        width = text_length  # Примерно 1 символ = 1 колонка

        # Оцениваем высоту (перенос по словам)
        max_width = 80  # Максимум символов в строке
        height = (text_length // max_width) + 1

        return (min(width, 80), max(height, 1))


# Export OverflowBehavior from here for convenience
__all__ = [
    "FieldBuilder",
    "FieldPosition",
    "OverflowBehavior",  # Re-export for convenience
]