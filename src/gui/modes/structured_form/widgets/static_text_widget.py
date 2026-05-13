"""Виджет статического текста.

Предоставляет:
- StaticTextWidget: read-only Label с форматированным текстом и поддержкой
  CharSize (DOUBLE_HEIGHT, DOUBLE_WIDTH).

Example:
    >>> widget = StaticTextWidget(
    ...     parent=frame,
    ...     field_def=field_def,
    ... )
    >>> widget.mount(parent_frame)
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Optional

from src.documents.types.type_schema import FieldDefinition
from src.gui.modes.structured_form.widgets.base_field_widget import BaseFieldWidget
from src.model.enums import CharSize


class StaticTextWidget(BaseFieldWidget):
    """Read-only Label с форматированным текстом.

    Attributes:
        _label: Tkinter Label для отображения текста.

    Example:
        >>> widget = StaticTextWidget(parent, field_def)
        >>> widget.set_value("Заголовок")
        >>> widget.get_value()
        'Заголовок'
    """

    _CHAR_SIZE_CONFIG: dict[CharSize, tuple[int, str, str]] = {
        CharSize.NORMAL: (11, "normal", "roman"),
        CharSize.DOUBLE_WIDTH: (14, "bold", "roman"),
        CharSize.DOUBLE_HEIGHT: (16, "normal", "roman"),
        CharSize.DOUBLE_WIDTH_HEIGHT: (18, "bold", "roman"),
        CharSize.CONDENSED: (9, "normal", "roman"),
    }

    def __init__(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        on_change: Optional[Callable[[str, Any], None]] = None,
        on_validate: Optional[Callable[[str, bool, Optional[str]], None]] = None,
    ) -> None:
        """Инициализация статического текстового поля.

        Args:
            parent: Родительский Tkinter виджет.
            field_def: Определение поля из схемы.
            on_change: Callback при изменении (игнорируется).
            on_validate: Callback при валидации (игнорируется).
        """
        super().__init__(parent, field_def, on_change, on_validate)
        self._label: Optional[tk.Label] = None

    def _create_widget(self) -> tk.Widget:
        """Создаёт Label виджет для отображения статического текста.

        Returns:
            Tkinter Frame содержащий Label.
        """
        frame = tk.Frame(self._main_frame)

        text = (
            str(self._field_def.default_value)
            if self._field_def.default_value is not None
            else self._field_def.label
        )
        self._value = text

        font_size, weight, slant = self._get_font_config()
        style_parts: list[str] = []
        if weight != "normal":
            style_parts.append(weight)
        if slant != "roman":
            style_parts.append(slant)
        style: str = " ".join(style_parts) if style_parts else "normal"

        self._label = tk.Label(
            frame,
            text=text,
            anchor=tk.W,
            font=("TkDefaultFont", font_size, style),
            relief=tk.FLAT,
            wraplength=400,
        )
        self._label.pack(fill=tk.X, expand=True)

        return frame

    def _get_font_config(self) -> tuple[int, str, str]:
        """Возвращает настройки шрифта на основе CharSize из FieldDefinition.

        Returns:
            Кортеж (font_size, weight, slant).
        """
        char_size = self._field_def.char_size
        if char_size is None:
            char_size = CharSize.NORMAL
        return self._CHAR_SIZE_CONFIG.get(char_size, self._CHAR_SIZE_CONFIG[CharSize.NORMAL])

    def set_value(self, value: Any) -> None:
        """Устанавливает текст Label без генерации on_change.

        Args:
            value: Новый текст для отображения.
        """
        str_value = str(value) if value is not None else ""
        self._value = str_value
        if self._label is not None:
            self._label.config(text=str_value)

    def get_value(self) -> str:
        """Возвращает текущее отображаемое значение.

        Returns:
            Текст Label.
        """
        return str(self._value) if self._value is not None else ""

    def validate(self) -> bool:
        """Статическое поле всегда валидно.

        Returns:
            True.
        """
        return True

    def wipe_sensitive_data(self) -> None:
        """Очищает чувствительные данные из виджета."""
        self._value = ""
        if self._label is not None:
            self._label.config(text="")

    def _update_font(self) -> None:
        """Обновляет шрифт Label при изменении CPI/Font настроек."""
        if self._label is not None:
            font_size, weight, slant = self._get_font_config()
            style_parts: list[str] = []
            if weight != "normal":
                style_parts.append(weight)
            if slant != "roman":
                style_parts.append(slant)
            style: str = " ".join(style_parts) if style_parts else "normal"
            self._label.config(font=("TkDefaultFont", font_size, style))


__all__: list[str] = ["StaticTextWidget"]
