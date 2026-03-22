"""Style manager for document elements.

Provides:
- StyleManager: Manages style inheritance hierarchy
- StyleProperties: Common style properties
- StyleInheritance: Inheritance chain configuration
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StyleProperties:
    """Свойства стиля для элемента документа.

    Атрибуты соответствуют возможностям ESC/P.

    Note: Не frozen, т.к. используется для накопления стилей через _merge_style.
    """

    """Свойства стиля для элемента документа.

    Атрибуты соответствуют возможностям ESC/P.
    """

    # Text formatting
    bold: bool = False
    italic: bool = False
    underline: bool = False
    double_strike: bool = False
    superscript: bool = False
    subscript: bool = False
    strikethrough: bool = False

    # Font
    font_family: str | None = None  # Courier, Roman, Sans Serif, etc.
    font_size: int | None = None  # Not directly supported by FX-890

    # Sizing
    condensed: bool = False
    double_width: bool = False
    double_height: bool = False
    proportional: bool = False

    # Effects
    outline: bool = False
    shadow: bool = False

    # Custom CSS-like properties (for reference/validation)
    custom: dict[str, Any] = field(default_factory=dict)

    def to_esc_commands(self) -> bytes:
        """Генерирует ESC/P команды для стиля.

        Returns:
            Байты ESC/P команд.
        """
        # Placeholder - ESC/P command generation is delegated to escp/commands
        # This method provides the interface for future implementation
        result = bytearray()
        return bytes(result)

    def to_esc_off_commands(self) -> bytes:
        """Генерирует ESC/P команды для сброса стиля.

        Returns:
            Байты ESC/P команд выключения.
        """
        # Placeholder - ESC/P command generation is delegated to escp/commands
        result = bytearray()
        return bytes(result)


class StyleInheritance:
    """Цепочка наследования стилей.

    Document -> Section -> Paragraph -> Run
    """

    DOCUMENT = "document"
    SECTION = "section"
    PARAGRAPH = "paragraph"
    RUN = "run"


class StyleManager:
    """Менеджер стилей с наследованием.

    Иерархия стилей:
      Document Style → Section Style → Paragraph Style → Run Style

    Дочерний стиль наследует все свойства родителя
    и может переопределить отдельные.
    """

    def __init__(self) -> None:
        """Инициализирует менеджер стилей."""
        self._styles: dict[str, StyleProperties] = {}
        self._inheritance_chain = [
            StyleInheritance.DOCUMENT,
            StyleInheritance.SECTION,
            StyleInheritance.PARAGRAPH,
            StyleInheritance.RUN,
        ]

    def set_style(self, level: str, properties: StyleProperties) -> None:
        """Устанавливает стиль для уровня.

        Args:
            level: Уровень (document, section, paragraph, run).
            properties: Свойства стиля.
        """
        self._styles[level] = properties

    def get_style(self, level: str) -> StyleProperties:
        """Возвращает стиль для уровня.

        Args:
            level: Уровень иерархии.

        Returns:
            Свойства стиля (合并ный результат).
        """
        if level in self._styles:
            return self._styles[level]
        return StyleProperties()

    def get_effective_style(self, level: str) -> StyleProperties:
        """Возвращает эффективный стиль с учётом наследования.

        Объединяет все стили от уровня документа до указанного.

        Args:
            level: Конечный уровень (например, "run").

        Returns:
            Объединённые свойства стиля.
        """
        result = StyleProperties()

        # Find the index of the target level
        try:
            target_idx = self._inheritance_chain.index(level)
        except ValueError:
            # Unknown level - return empty style
            return result

        # Collect all styles up to and including target level
        for i in range(target_idx + 1):
            lvl = self._inheritance_chain[i]
            if lvl in self._styles:
                self._merge_style(result, self._styles[lvl])

        return result

    def _merge_style(self, target: StyleProperties, source: StyleProperties) -> None:
        """Объединяет стили (source переопределяет target).

        Args:
            target: Целевой стиль.
            source: Исходный стиль (более специфичный).
        """
        for field_name in StyleProperties.__dataclass_fields__:
            if field_name == "custom":
                # Merge custom dict
                target.custom.update(source.custom)
            else:
                # Source overrides target (non-None/non-False wins)
                source_val = getattr(source, field_name)
                if source_val is not None and source_val is not False:
                    setattr(target, field_name, source_val)

    def reset_style(self, level: str) -> None:
        """Сбрасывает стиль для уровня.

        Args:
            level: Уровень для сброса.
        """
        if level in self._styles:
            del self._styles[level]

    def reset_all(self) -> None:
        """Сбрасывает все стили."""
        self._styles.clear()

    def inherit_from(self, source_style: StyleProperties) -> StyleProperties:
        """Создаёт копию стиля с наследованием от родителя.

        Args:
            source_style: Родительский стиль.

        Returns:
            Новый экземпляр StyleProperties.
        """
        # Create a copy with the same values
        return StyleProperties(
            bold=source_style.bold,
            italic=source_style.italic,
            underline=source_style.underline,
            double_strike=source_style.double_strike,
            superscript=source_style.superscript,
            subscript=source_style.subscript,
            strikethrough=source_style.strikethrough,
            font_family=source_style.font_family,
            font_size=source_style.font_size,
            condensed=source_style.condensed,
            double_width=source_style.double_width,
            double_height=source_style.double_height,
            proportional=source_style.proportional,
            outline=source_style.outline,
            shadow=source_style.shadow,
            custom=dict(source_style.custom),
        )

    def create_document_style(
        self,
        bold: bool = False,
        italic: bool = False,
        underline: bool = False,
        font_family: str | None = None,
    ) -> StyleProperties:
        """Создаёт стиль документа.

        Args:
            bold: Жирный шрифт.
            italic: Курсив.
            underline: Подчёркивание.
            font_family: Семейство шрифтов.

        Returns:
            Свойства стиля.
        """
        return StyleProperties(
            bold=bold,
            italic=italic,
            underline=underline,
            font_family=font_family,
        )
