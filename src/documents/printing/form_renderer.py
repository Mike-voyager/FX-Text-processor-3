"""Рендерер форм в ESC/P байты.

Предоставляет:
- FormRenderer: Рендеринг FormInstance и FormField в ESC/P bytes
- FormInstance: Структурированная форма с полями
- FormField: Отдельное поле формы

Example:
    >>> from src.documents.printing.form_renderer import FormRenderer, FormInstance
    >>> renderer = FormRenderer()
    >>> form = FormInstance(fields=[FormField(name="Name", value="John")])
    >>> escp_data = renderer.render_form(form, RenderSettings())
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final

from src.escp.commands.positioning import set_horizontal_position
from src.escp.commands.text_formatting import (
    ESC_BOLD_OFF,
    ESC_BOLD_ON,
)
from src.model.enums import (
    CodePage,
)

if TYPE_CHECKING:
    from src.documents.printing.document_renderer import RenderSettings

logger: Final = logging.getLogger(__name__)

# ESC/P constants
CRLF = b"\r\n"
LF = b"\n"

# Символы рамок из PC866
BOX_HORIZONTAL = b"\xc4"  # ─
BOX_VERTICAL = b"\xb3"  # │
BOX_TOP_LEFT = b"\xda"  # ┌
BOX_TOP_RIGHT = b"\xbf"  # ┐
BOX_BOTTOM_LEFT = b"\xc0"  # └
BOX_BOTTOM_RIGHT = b"\xd9"  # ┘
BOX_T_RIGHT = b"\xc3"  # ├
BOX_T_LEFT = b"\xb4"  # ┤
BOX_T_DOWN = b"\xc2"  # ┬
BOX_T_UP = b"\xc1"  # ┴
BOX_CROSS = b"\xc5"  # ┼


@dataclass(frozen=True)
class FormField:
    """Поле формы для рендеринга.

    Attributes:
        name: Идентификатор поля
        label: Метка поля (отображаемый текст)
        value: Значение поля
        x: Позиция X в символах
        y: Позиция Y в строках
        width: Ширина поля в символах
        height: Высота поля в строках
        border: Отображать рамку
        bold_label: Жирный шрифт для метки
    """

    name: str
    label: str = ""
    value: str = ""
    x: int = 0
    y: int = 0
    width: int = 20
    height: int = 1
    border: bool = False
    bold_label: bool = True


@dataclass
class FormInstance:
    """Экземпляр формы для рендеринга.

    Attributes:
        fields: Список полей формы
        title: Заголовок формы
        show_borders: Отображать рамки полей
        codepage: Кодовая страница
    """

    fields: list[FormField] = field(default_factory=list)
    title: str = ""
    show_borders: bool = True
    codepage: CodePage = CodePage.PC866

    def add_field(self, field: FormField) -> None:
        """Добавляет поле в форму.

        Args:
            field: Поле для добавления
        """
        self.fields.append(field)

    def get_field(self, name: str) -> FormField | None:
        """Находит поле по имени.

        Args:
            name: Имя поля

        Returns:
            Поле или None
        """
        for f in self.fields:
            if f.name == name:
                return f
        return None


class FormRenderer:
    """Рендерер структурированных форм.

    Преобразует FormInstance с полями в ESC/P команды.
    Поддерживает позиционирование полей, рамки и форматирование.

    Example:
        >>> renderer = FormRenderer()
        >>> form = FormInstance(title="Invoice")
        >>> form.add_field(FormField(name="date", label="Date:", value="2025-01-15"))
        >>> escp = renderer.render_form(form, RenderSettings())
    """

    def __init__(self, codepage: CodePage = CodePage.PC866) -> None:
        """Инициализирует рендерер.

        Args:
            codepage: Кодовая страница для кодирования текста
        """
        self._codepage = codepage
        self._logger = logging.getLogger(__name__)

    def render_form(self, form: FormInstance, settings: RenderSettings) -> bytes:
        """Рендерит форму в ESC/P байты.

        Args:
            form: Форма для рендеринга
            settings: Настройки рендеринга

        Returns:
            ESC/P команды для формы

        Example:
            >>> data = renderer.render_form(form, settings)
            >>> len(data) > 0
            True
        """
        result = bytearray()

        # Заголовок формы
        if form.title:
            result.extend(self._render_title(form.title))
            result.extend(CRLF)

        # Рендеринг полей
        current_row = 0
        for field in sorted(form.fields, key=lambda f: (f.y, f.x)):
            # Переход к нужной строке
            while current_row < field.y:
                result.extend(CRLF)
                current_row += 1

            # Рендеринг поля
            result.extend(self.render_field(field, settings))

        result.extend(CRLF)
        return bytes(result)

    def render_field(self, field: FormField, settings: RenderSettings) -> bytes:
        """Рендерит поле формы с значением.

        Args:
            field: Поле для рендеринга
            settings: Настройки рендеринга

        Returns:
            ESC/P команды для поля

        Example:
            >>> field = FormField(name="name", label="Name:", value="John", width=20)
            >>> data = renderer.render_field(field, settings)
        """
        result = bytearray()

        # Позиционирование
        if field.x > 0:
            cpi_value = settings.cpi.numeric_value or 10
            units_per_char = 60 // cpi_value
            result.extend(set_horizontal_position(field.x * units_per_char))

        # Метка поля (если есть)
        if field.label:
            if field.bold_label:
                result.extend(ESC_BOLD_ON)
            result.extend(self._encode_text(field.label))
            if field.bold_label:
                result.extend(ESC_BOLD_OFF)
            result.extend(b" ")

        # Рамка вокруг значения (если включена)
        if field.border:
            result.extend(self.render_field_border(field))

        # Значение поля
        display_value = self._format_value(field.value, field.width)
        result.extend(self._encode_text(display_value))

        return bytes(result)

    def render_field_border(self, field: FormField) -> bytes:
        """Рендерит рамку поля используя символы псевдографики.

        Использует символы box-drawing из PC866:
        - ┌─┐ верхняя граница
        - │ │ боковые границы
        - └─┘ нижняя граница

        Args:
            field: Поле для которого рисуется рамка

        Returns:
            ESC/P байты для рамки

        Example:
            >>> field = FormField(name="test", width=10, height=1)
            >>> border = renderer.render_field_border(field)
        """
        result = bytearray()

        # Для однострочного поля: [ значение ]
        if field.height == 1:
            result.extend(BOX_VERTICAL)
            result.extend(b" ")
        else:
            # Многострочная рамка (упрощённая версия)
            result.extend(BOX_TOP_LEFT)
            result.extend(BOX_HORIZONTAL * (field.width + 2))
            result.extend(BOX_TOP_RIGHT)
            result.extend(CRLF)

            for _ in range(field.height):
                result.extend(BOX_VERTICAL)
                result.extend(b" " * (field.width + 2))
                result.extend(BOX_VERTICAL)
                result.extend(CRLF)

            result.extend(BOX_BOTTOM_LEFT)
            result.extend(BOX_HORIZONTAL * (field.width + 2))
            result.extend(BOX_BOTTOM_RIGHT)

        return bytes(result)

    def _render_title(self, title: str) -> bytes:
        """Рендерит заголовок формы.

        Args:
            title: Текст заголовка

        Returns:
            ESC/P команды для заголовка
        """
        result = bytearray()
        result.extend(ESC_BOLD_ON)
        result.extend(self._encode_text(title.center(40)))
        result.extend(ESC_BOLD_OFF)
        return bytes(result)

    def _encode_text(self, text: str) -> bytes:
        """Кодирует текст в CP866.

        Args:
            text: Текст для кодирования

        Returns:
            Закодированные байты
        """
        try:
            return text.encode("cp866", errors="replace")
        except TypeError:
            return text.encode("ascii", errors="replace")

    def _format_value(self, value: Any, width: int) -> str:
        """Форматирует значение для отображения.

        Args:
            value: Значение для форматирования
            width: Ширина поля

        Returns:
            Отформатированная строка
        """
        text = str(value) if value is not None else ""
        if len(text) > width:
            return text[:width]
        return text.ljust(width)


__all__ = ["FormRenderer", "FormInstance", "FormField"]
