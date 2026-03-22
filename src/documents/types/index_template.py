"""Index template definitions for document indexing.

Provides:
- SegmentType: Enum for index segment types
- IndexSegmentDef: Definition of a single index segment
- IndexTemplate: Full index template with multiple segments
"""

from dataclasses import dataclass, field
from enum import Enum


class SegmentType(str, Enum):
    """Тип сегмента в составном индексе документа.

    Последний сегмент всегда должен быть SEQUENCE (римские цифры).
    """

    ROOT_CODE = "root"  # Код типа документа: DVN, INV, DOC
    SUBTYPE = "subtype"  # Код подтипа: 44, 01
    SERIES = "series"  # Серия документа: K53
    CUSTOM = "custom"  # Произвольный сегмент
    SEQUENCE = "sequence"  # Порядковый номер (римские цифры, всегда последний)


@dataclass(frozen=True)
class IndexSegmentDef:
    """Определение одного сегмента в индексе документа.

    Attributes:
        name: Программное имя сегмента.
        segment_type: Тип сегмента из enum SegmentType.
        label: Метка сегмента на русском языке.
        label_en: Метка сегмента на английском языке.
        pattern: Regex-паттерн для валидации значения сегмента.
        allowed_values: Список допустимых значений (None = любое).
        auto_increment: Автоматический инкремент для SEQUENCE сегментов.
    """

    name: str
    segment_type: SegmentType
    label: str
    label_en: str
    pattern: str
    allowed_values: tuple[str, ...] | None = None
    auto_increment: bool = False


@dataclass(frozen=True)
class IndexTemplate:
    """Шаблон генерации и парсинга индексов документов.

    Индекс состоит из сегментов, разделенных разделителем.
    Последний сегмент всегда SEQUENCE (римские цифры).

    Example:
        segments = [
            IndexSegmentDef(
                "type", SegmentType.ROOT_CODE, "Тип", "Type", r"DVN", None, False
            ),
            IndexSegmentDef(
                "subtype",
                SegmentType.SUBTYPE,
                "Подтип",
                "Subtype",
                r"\\d{1,2}",
                None,
                False,
            ),
            IndexSegmentDef(
                "series",
                SegmentType.SERIES,
                "Серия",
                "Series",
                r"[A-Z]\\d{2}",
                None,
                False,
            ),
            IndexSegmentDef(
                "seq",
                SegmentType.SEQUENCE,
                "Номер",
                "Number",
                r"[IVXLCDM]+",
                None,
                True,
            ),
        ]
        template = IndexTemplate(segments=segments)
        # Форматирование: {"type": "DVN", "subtype": "44", "series": "K53"} + sequence=9
        # Результат: "DVN-44-K53-IX"
    """

    segments: tuple[IndexSegmentDef, ...] = field(default_factory=tuple)
    separator: str = "-"

    def __post_init__(self) -> None:
        """Валидация шаблона после инициализации."""
        if not self.segments:
            raise ValueError("IndexTemplate must have at least one segment")

        # Проверяем, что последний сегмент - SEQUENCE
        last_segment = self.segments[-1]
        if last_segment.segment_type != SegmentType.SEQUENCE:
            raise ValueError(f"Last segment must be SEQUENCE, got {last_segment.segment_type}")

    def format(self, values: dict[str, str], sequence: int) -> str:
        """Форматирует индекс из значений сегментов и порядкового номера.

        Args:
            values: Словарь значений сегментов (name -> value).
            sequence: Порядковый номер (будет преобразован в римские цифры).

        Returns:
            Отформатированный индекс, например "DVN-44-K53-IX".

        Raises:
            ValueError: Если значение сегмента не проходит валидацию.
        """
        from src.documents.types.index_formatter import int_to_roman

        parts: list[str] = []

        for segment in self.segments:
            if segment.segment_type == SegmentType.SEQUENCE:
                # Последний сегмент - римские цифры
                parts.append(int_to_roman(sequence))
            else:
                # Остальные сегменты из values
                if segment.name not in values:
                    raise ValueError(f"Missing required segment value: {segment.name}")
                value = values[segment.name]
                parts.append(value)

        return self.separator.join(parts)

    def parse(self, index: str) -> dict[str, str]:
        """Парсит строку индекса в словарь значений сегментов.

        Args:
            index: Строка индекса, например "DVN-44-K53-IX".

        Returns:
            Словарь {segment_name: value}. SEQUENCE сегмент не включен
            (его нужно обрабатывать отдельно с roman_to_int).

        Raises:
            ValueError: Если формат индекса невалиден.
        """
        parts = index.split(self.separator)

        if len(parts) != len(self.segments):
            raise ValueError(f"Index has {len(parts)} segments, expected {len(self.segments)}")

        result: dict[str, str] = {}

        for i, segment in enumerate(self.segments):
            value = parts[i]

            # Валидация по паттерну
            import re

            if not re.match(segment.pattern, value):
                raise ValueError(
                    f"Segment '{segment.name}' value '{value}' "
                    f"doesn't match pattern {segment.pattern}"
                )

            # Валидация по allowed_values
            if segment.allowed_values is not None:
                if value not in segment.allowed_values:
                    raise ValueError(
                        f"Segment '{segment.name}' value '{value}' "
                        f"not in allowed values: {segment.allowed_values}"
                    )

            if segment.segment_type != SegmentType.SEQUENCE:
                result[segment.name] = value
            else:
                # SEQUENCE не добавляем в result (обрабатывается отдельно)
                pass

        return result

    def validate(self, index: str) -> bool:
        """Проверяет, что строка индекса соответствует шаблону.

        Args:
            index: Строка индекса для валидации.

        Returns:
            True если индекс валиден, False в противном случае.
        """
        try:
            self.parse(index)
            return True
        except (ValueError, IndexError):
            return False

    @property
    def sequence_segment(self) -> IndexSegmentDef:
        """Возвращает сегмент SEQUENCE (последний)."""
        return self.segments[-1]

    @property
    def non_sequence_segments(self) -> tuple[IndexSegmentDef, ...]:
        """Возвращает все сегменты кроме SEQUENCE."""
        return self.segments[:-1]
