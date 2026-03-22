"""Тесты для модуля index_template.

Покрытие:
- SegmentType Enum
- IndexSegmentDef dataclass
- IndexTemplate dataclass
- Форматирование и парсинг индексов
- Валидация индексов
"""

from __future__ import annotations

import pytest
from src.documents.types.index_template import (
    IndexSegmentDef,
    IndexTemplate,
    SegmentType,
)

# ============ SegmentType Enum Tests ============


class TestSegmentType:
    """Тесты для SegmentType Enum."""

    def test_segment_type_values(self) -> None:
        """Проверка значений SegmentType."""
        assert SegmentType.ROOT_CODE.value == "root"
        assert SegmentType.SUBTYPE.value == "subtype"
        assert SegmentType.SERIES.value == "series"
        assert SegmentType.CUSTOM.value == "custom"
        assert SegmentType.SEQUENCE.value == "sequence"

    def test_segment_type_is_str(self) -> None:
        """Проверка что SegmentType наследуется от str."""
        assert isinstance(SegmentType.ROOT_CODE, str)


# ============ IndexSegmentDef Tests ============


class TestIndexSegmentDef:
    """Тесты для IndexSegmentDef dataclass."""

    def test_create_segment_minimal(self) -> None:
        """Создание сегмента с минимальными параметрами."""
        segment = IndexSegmentDef(
            name="test",
            segment_type=SegmentType.ROOT_CODE,
            label="Тест",
            label_en="Test",
            pattern=r"[A-Z]{3}",
        )
        assert segment.name == "test"
        assert segment.segment_type == SegmentType.ROOT_CODE
        assert segment.label == "Тест"
        assert segment.label_en == "Test"
        assert segment.pattern == r"[A-Z]{3}"
        assert segment.allowed_values is None
        assert segment.auto_increment is False

    def test_create_segment_full(self) -> None:
        """Создание сегмента со всеми параметрами."""
        segment = IndexSegmentDef(
            name="subtype",
            segment_type=SegmentType.SUBTYPE,
            label="Подтип",
            label_en="Subtype",
            pattern=r"\d{2}",
            allowed_values=("01", "02", "03"),
            auto_increment=True,
        )
        assert segment.allowed_values == ("01", "02", "03")
        assert segment.auto_increment is True

    def test_segment_frozen(self) -> None:
        """IndexSegmentDef immutable."""
        segment = IndexSegmentDef(
            name="test",
            segment_type=SegmentType.ROOT_CODE,
            label="Тест",
            label_en="Test",
            pattern=r"[A-Z]+",
        )
        with pytest.raises(AttributeError):
            segment.name = "new"  # type: ignore


# ============ IndexTemplate Tests ============


class TestIndexTemplate:
    """Тесты для IndexTemplate."""

    def test_create_template_basic(self) -> None:
        """Создание базового шаблона."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"TEST",
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
            separator="-",
        )
        assert len(template.segments) == 2
        assert template.separator == "-"

    def test_create_template_default_separator(self) -> None:
        """Шаблон с сепаратором по умолчанию."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )
        assert template.separator == "-"

    def test_create_template_empty_raises(self) -> None:
        """Пустой шаблон вызывает ValueError."""
        with pytest.raises(ValueError, match="must have at least one segment"):
            IndexTemplate(segments=())


class TestIndexTemplatePostInit:
    """Тесты валидации в __post_init__."""

    def test_post_init_last_not_sequence_raises(self) -> None:
        """Последний не SEQUENCE вызывает ValueError."""
        with pytest.raises(ValueError, match="Last segment must be SEQUENCE"):
            IndexTemplate(
                segments=(
                    IndexSegmentDef(
                        name="type",
                        segment_type=SegmentType.ROOT_CODE,
                        label="Тип",
                        label_en="Type",
                        pattern=r"TEST",
                    ),
                    IndexSegmentDef(
                        name="wrong",
                        segment_type=SegmentType.SERIES,
                        label="Wrong",
                        label_en="Wrong",
                        pattern=r"[A-Z]\d{2}",
                    ),
                )
            )

    def test_post_init_sequence_last_ok(self) -> None:
        """SEQUENCE последний — валидно."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"TEST",
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            )
        )
        assert template.sequence_segment.segment_type == SegmentType.SEQUENCE


class TestIndexTemplateFormat:
    """Тесты для IndexTemplate.format."""

    @pytest.fixture
    def dvn_template(self) -> IndexTemplate:
        """Шаблон как у вербальной ноты (DVN-44-K53-IX)."""
        return IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"DVN",
                ),
                IndexSegmentDef(
                    name="subtype",
                    segment_type=SegmentType.SUBTYPE,
                    label="Подтип",
                    label_en="Subtype",
                    pattern=r"\d{1,2}",
                ),
                IndexSegmentDef(
                    name="series",
                    segment_type=SegmentType.SERIES,
                    label="Серия",
                    label_en="Series",
                    pattern=r"[A-Z]\d{2}",
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
            separator="-",
        )

    def test_format_dvn(self, dvn_template: IndexTemplate) -> None:
        """Форматирование индекса DVN."""
        result = dvn_template.format(
            values={
                "type": "DVN",
                "subtype": "44",
                "series": "K53",
            },
            sequence=9,
        )
        assert result == "DVN-44-K53-IX"

    def test_format_sequence_1(self, dvn_template: IndexTemplate) -> None:
        """Форматирование с sequence=1."""
        result = dvn_template.format(
            values={
                "type": "DVN",
                "subtype": "01",
                "series": "A01",
            },
            sequence=1,
        )
        assert result == "DVN-01-A01-I"

    def test_format_sequence_1999(self, dvn_template: IndexTemplate) -> None:
        """Форматирование с sequence=1999."""
        result = dvn_template.format(
            values={
                "type": "DVN",
                "subtype": "99",
                "series": "Z99",
            },
            sequence=1999,
        )
        assert result == "DVN-99-Z99-MCMXCIX"

    def test_format_missing_value_raises(self, dvn_template: IndexTemplate) -> None:
        """Отсутствующее значение вызывает ValueError."""
        with pytest.raises(ValueError, match="Missing required segment value: subtype"):
            dvn_template.format(
                values={
                    "type": "DVN",
                    # subtype is missing
                    "series": "K53",
                },
                sequence=1,
            )

    def test_format_simple_template(self) -> None:
        """Простой шаблон только с SEQUENCE."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )
        result = template.format(values={}, sequence=42)
        assert result == "XLII"

    def test_format_custom_separator(self) -> None:
        """Шаблон с кастомным сепаратором."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"[A-Z]+",
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
            separator="/",
        )
        result = template.format(values={"type": "DOC"}, sequence=5)
        assert result == "DOC/V"


class TestIndexTemplateParse:
    """Тесты для IndexTemplate.parse."""

    @pytest.fixture
    def dvn_template(self) -> IndexTemplate:
        """Шаблон как у вербальной ноты."""
        return IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"DVN",
                ),
                IndexSegmentDef(
                    name="subtype",
                    segment_type=SegmentType.SUBTYPE,
                    label="Подтип",
                    label_en="Subtype",
                    pattern=r"\d{1,2}",
                ),
                IndexSegmentDef(
                    name="series",
                    segment_type=SegmentType.SERIES,
                    label="Серия",
                    label_en="Series",
                    pattern=r"[A-Z]\d{2}",
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
            separator="-",
        )

    def test_parse_dvn(self, dvn_template: IndexTemplate) -> None:
        """Парсинг индекса DVN."""
        result = dvn_template.parse("DVN-44-K53-IX")
        assert result == {
            "type": "DVN",
            "subtype": "44",
            "series": "K53",
        }

    def test_parse_wrong_segment_count_raises(self, dvn_template: IndexTemplate) -> None:
        """Неверное количество сегментов вызывает ValueError."""
        with pytest.raises(ValueError, match="has 2 segments, expected 4"):
            dvn_template.parse("DVN-44")

    def test_parse_pattern_mismatch_raises(self, dvn_template: IndexTemplate) -> None:
        """Несоответствие паттерну вызывает ValueError."""
        with pytest.raises(ValueError, match="doesn't match pattern"):
            dvn_template.parse("DVN-44-WRONG-IX")

    def test_parse_allowed_values(self) -> None:
        """Валидация по allowed_values."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"[A-Z]+",
                    allowed_values=("DOC", "INV"),
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )
        with pytest.raises(ValueError, match="not in allowed values"):
            template.parse("OTHER-X")

    def test_parse_allowed_values_valid(self) -> None:
        """Валидное значение из allowed_values."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"[A-Z]+",
                    allowed_values=("DOC", "INV"),
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )
        result = template.parse("DOC-X")
        assert result == {"type": "DOC"}


class TestIndexTemplateValidate:
    """Тесты для IndexTemplate.validate."""

    @pytest.fixture
    def simple_template(self) -> IndexTemplate:
        """Простой шаблон."""
        return IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"[A-Z]{3}",
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )

    def test_validate_valid(self, simple_template: IndexTemplate) -> None:
        """Валидный индекс."""
        assert simple_template.validate("DOC-IX") is True

    def test_validate_invalid(self, simple_template: IndexTemplate) -> None:
        """Невалидный индекс."""
        assert simple_template.validate("WRONG") is False

    def test_validate_pattern_fail(self, simple_template: IndexTemplate) -> None:
        """Несоответствие паттерну."""
        assert simple_template.validate("doc-IX") is False


class TestIndexTemplateProperties:
    """Тесты свойств IndexTemplate."""

    @pytest.fixture
    def dvn_template(self) -> IndexTemplate:
        """Шаблон с несколькими сегментами."""
        return IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"DVN",
                ),
                IndexSegmentDef(
                    name="subtype",
                    segment_type=SegmentType.SUBTYPE,
                    label="Подтип",
                    label_en="Subtype",
                    pattern=r"\d{1,2}",
                ),
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )

    def test_sequence_segment(self, dvn_template: IndexTemplate) -> None:
        """sequence_segment возвращает последний."""
        segment = dvn_template.sequence_segment
        assert segment.segment_type == SegmentType.SEQUENCE
        assert segment.name == "seq"

    def test_non_sequence_segments(self, dvn_template: IndexTemplate) -> None:
        """non_sequence_segments возвращает все кроме последнего."""
        segments = dvn_template.non_sequence_segments
        assert len(segments) == 2
        assert segments[0].segment_type == SegmentType.ROOT_CODE
        assert segments[1].segment_type == SegmentType.SUBTYPE

    def test_non_sequence_segments_empty(self) -> None:
        """non_sequence_segments с одним сегментом."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="seq",
                    segment_type=SegmentType.SEQUENCE,
                    label="Номер",
                    label_en="Number",
                    pattern=r"[IVXLCDM]+",
                ),
            ),
        )
        assert template.non_sequence_segments == ()
