"""Тесты для модуля масок ввода.

Tests cover:
- InputMask creation and validation
- apply() method for formatting input
- strip() method for removing mask
- is_complete() method for checking completion
- validate() method for validating raw input
- build_from_template() for creating masks from IndexTemplate
- Character validation for different mask types
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from unittest.mock import Mock

import pytest
from src.documents.constructor.input_mask import (
    _MASK_ALPHANUM,
    _MASK_ANY_LETTER,
    _MASK_DIGIT,
    _MASK_LETTER,
    _MASK_ROMAN,
    _VALID_MASK_CHARS,
    InputMask,
)
from src.documents.types.index_template import (
    IndexSegmentDef,
    IndexTemplate,
    SegmentType,
)

# =============================================================================
# InputMask Creation Tests
# =============================================================================


class TestInputMaskCreation:
    """Тесты создания InputMask."""

    def test_create_basic(self) -> None:
        """Создание с базовыми параметрами."""
        mask = InputMask(pattern="##.##.####")
        assert mask.pattern == "##.##.####"
        assert mask.placeholder == "_"

    def test_create_with_custom_placeholder(self) -> None:
        """Создание с пользовательским placeholder."""
        mask = InputMask(pattern="###-###", placeholder="*")
        assert mask.placeholder == "*"

    def test_create_empty_pattern_raises(self) -> None:
        """Ошибка при пустом pattern."""
        with pytest.raises(ValueError, match="pattern не может быть пустым"):
            InputMask(pattern="")

    def test_create_invalid_pattern_type(self) -> None:
        """Ошибка при некорректном типе pattern."""
        with pytest.raises(TypeError, match="pattern должен быть str"):
            InputMask(pattern=123)  # type: ignore

    def test_create_invalid_placeholder_type(self) -> None:
        """Ошибка при некорректном типе placeholder."""
        with pytest.raises(TypeError, match="placeholder должен быть str"):
            InputMask(pattern="###", placeholder=123)  # type: ignore

    def test_create_placeholder_too_long(self) -> None:
        """Ошибка когда placeholder не один символ."""
        with pytest.raises(ValueError, match="placeholder должен быть одним символом"):
            InputMask(pattern="###", placeholder="__")

    def test_frozen_instance(self) -> None:
        """Проверка неизменяемости объекта."""
        mask = InputMask(pattern="###")
        with pytest.raises(FrozenInstanceError):
            mask.pattern = "####"  # type: ignore

    def test_repr(self) -> None:
        """Строковое представление для отладки."""
        mask = InputMask(pattern="##.##", placeholder="_")
        repr_str = repr(mask)
        assert "InputMask" in repr_str
        assert "##.##" in repr_str
        assert "_" in repr_str


# =============================================================================
# Apply Method Tests
# =============================================================================


class TestInputMaskApply:
    """Тесты метода apply()."""

    def test_apply_date_mask(self) -> None:
        """Применение маски даты."""
        mask = InputMask(pattern="##.##.####")
        result = mask.apply("25122026")
        assert result == "25.12.2026"

    def test_apply_partial_input(self) -> None:
        """Применение с неполным вводом."""
        mask = InputMask(pattern="##.##.####")
        result = mask.apply("2512")
        # Pattern: ## . ## . #### = 8 mask positions, 10 total chars
        # "2512" fills first 4 positions, rest are placeholders
        assert result == "25.12.____"

    def test_apply_empty_input(self) -> None:
        """Применение с пустым вводом."""
        mask = InputMask(pattern="##.##.####")
        result = mask.apply("")
        assert result == "__.__.____"

    def test_apply_phone_mask(self) -> None:
        """Применение маски телефона."""
        mask = InputMask(pattern="+7 (###) ###-##-##")
        result = mask.apply("4951234567")
        assert result == "+7 (495) 123-45-67"

    def test_apply_document_index_mask(self) -> None:
        """Применение маски индекса документа."""
        mask = InputMask(pattern="AAA-##-A##-RR")
        result = mask.apply("DVN44K53IX")
        assert result == "DVN-44-K53-IX"

    def test_apply_with_invalid_char(self) -> None:
        """Обработка невалидного символа — замена на placeholder."""
        mask = InputMask(pattern="###")
        result = mask.apply("1a2")
        # 'a' не является цифрой, заменяется на placeholder
        assert result == "1_2"

    def test_apply_excess_input_truncated(self) -> None:
        """Лишний ввод обрезается."""
        mask = InputMask(pattern="###")
        result = mask.apply("12345")
        assert result == "123"

    def test_apply_invalid_input_type(self) -> None:
        """Ошибка при некорректном типе raw."""
        mask = InputMask(pattern="###")
        with pytest.raises(TypeError, match="raw должен быть str"):
            mask.apply(123)  # type: ignore


# =============================================================================
# Strip Method Tests
# =============================================================================


class TestInputMaskStrip:
    """Тесты метода strip()."""

    def test_strip_complete_mask(self) -> None:
        """Удаление маски из полного значения."""
        mask = InputMask(pattern="##.##.####")
        result = mask.strip("25.12.2026")  # noqa: B005
        assert result == "25122026"

    def test_strip_partial_mask(self) -> None:
        """Удаление маски из частичного значения."""
        mask = InputMask(pattern="##.##.####")
        # Pattern produces "25.12.____" for partial input "2512"
        result = mask.strip("25.12.____")  # noqa: B005
        assert result == "2512"

    def test_strip_empty_mask(self) -> None:
        """Удаление маски когда ничего не введено."""
        mask = InputMask(pattern="##.##.####")
        result = mask.strip("__.__.____")  # noqa: B005
        assert result == ""

    def test_strip_phone_mask(self) -> None:
        """Удаление маски телефона."""
        mask = InputMask(pattern="+7 (###) ###-##-##")
        result = mask.strip("+7 (495) 123-45-67")  # noqa: B005
        assert result == "4951234567"

    def test_strip_invalid_type(self) -> None:
        """Ошибка при некорректном типе masked."""
        mask = InputMask(pattern="###")
        with pytest.raises(TypeError, match="masked должен быть str"):
            mask.strip(123)  # type: ignore


# =============================================================================
# Is Complete Tests
# =============================================================================


class TestInputMaskIsComplete:
    """Тесты метода is_complete()."""

    def test_is_complete_true(self) -> None:
        """Полностью заполненная маска."""
        mask = InputMask(pattern="##.##.####")
        assert mask.is_complete("25.12.2026") is True

    def test_is_complete_false(self) -> None:
        """Частично заполненная маска."""
        mask = InputMask(pattern="##.##.####")
        assert mask.is_complete("25.12.____") is False

    def test_is_complete_empty(self) -> None:
        """Пустая маска."""
        mask = InputMask(pattern="##.##.####")
        assert mask.is_complete("__.__.____") is False

    def test_is_complete_only_separators(self) -> None:
        """Только разделители без ввода."""
        mask = InputMask(pattern="###-###")
        assert mask.is_complete("-__-") is False

    def test_is_complete_invalid_type(self) -> None:
        """Ошибка при некорректном типе masked."""
        mask = InputMask(pattern="###")
        with pytest.raises(TypeError, match="masked должен быть str"):
            mask.is_complete(123)  # type: ignore


# =============================================================================
# Validate Method Tests
# =============================================================================


class TestInputMaskValidate:
    """Тесты метода validate()."""

    def test_validate_valid_input(self) -> None:
        """Валидный ввод соответствует маске."""
        mask = InputMask(pattern="AAA-##")
        assert mask.validate("ABC12") is True

    def test_validate_invalid_length(self) -> None:
        """Неверная длина ввода."""
        mask = InputMask(pattern="AAA-##")
        assert mask.validate("ABC123") is False
        assert mask.validate("ABC1") is False

    def test_validate_invalid_characters(self) -> None:
        """Неверные символы для позиций маски."""
        mask = InputMask(pattern="AAA-##")
        assert mask.validate("12345") is False  # Цифры вместо букв

    def test_validate_empty(self) -> None:
        """Пустой ввод невалиден."""
        mask = InputMask(pattern="###")
        assert mask.validate("") is False

    def test_validate_invalid_type(self) -> None:
        """Некорректный тип возвращает False."""
        mask = InputMask(pattern="###")
        assert mask.validate(123) is False  # type: ignore


# =============================================================================
# Character Validation Tests
# =============================================================================


class TestCharacterValidation:
    """Тесты валидации символов для разных типов маски."""

    def test_digit_mask_validation(self) -> None:
        """Маска # принимает только цифры."""
        mask = InputMask(pattern="###")
        assert mask.validate("123") is True
        assert mask.validate("abc") is False
        assert mask.validate("1a3") is False

    def test_letter_mask_validation(self) -> None:
        """Маска A принимает только латинские буквы."""
        mask = InputMask(pattern="AAA")
        assert mask.validate("ABC") is True
        assert mask.validate("abc") is True
        assert mask.validate("123") is False
        assert mask.validate("АБВ") is False  # Кириллица

    def test_roman_mask_validation(self) -> None:
        """Маска R принимает только римские цифры."""
        mask = InputMask(pattern="RR")
        assert mask.validate("IV") is True
        assert mask.validate("XL") is True
        assert mask.validate("MC") is True
        assert mask.validate("AB") is False
        assert mask.validate("12") is False

    def test_any_letter_mask_validation(self) -> None:
        """Маска L принимает любые буквы."""
        mask = InputMask(pattern="LLL")
        assert mask.validate("ABC") is True
        assert mask.validate("АБВ") is True  # Кириллица
        assert mask.validate("123") is False

    def test_alphanum_mask_validation(self) -> None:
        """Маска N принимает буквы и цифры."""
        mask = InputMask(pattern="NNN")
        assert mask.validate("ABC") is True
        assert mask.validate("123") is True
        assert mask.validate("A1B") is True
        assert mask.validate("!!!") is False


# =============================================================================
# Build From Template Tests
# =============================================================================


class TestBuildFromTemplate:
    """Тесты статического метода build_from_template()."""

    def test_build_from_template_basic(self) -> None:
        """Создание маски из базового шаблона."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"[A-Z]{3}",
                ),
                IndexSegmentDef(
                    name="subtype",
                    segment_type=SegmentType.SUBTYPE,
                    label="Подтип",
                    label_en="Subtype",
                    pattern=r"\d{2}",
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

        mask = InputMask.build_from_template(template)
        # SEQUENCE returns "RRRR" (4 chars) as per implementation
        assert mask.pattern == "AAA-##-RRRR"
        assert mask.placeholder == "_"

    def test_build_from_template_with_series(self) -> None:
        """Создание маски с сегментом SERIES."""
        template = IndexTemplate(
            segments=(
                IndexSegmentDef(
                    name="type",
                    segment_type=SegmentType.ROOT_CODE,
                    label="Тип",
                    label_en="Type",
                    pattern=r"[A-Z]{3}",
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
            )
        )

        mask = InputMask.build_from_template(template)
        # SEQUENCE returns "RRRR" (4 chars) as per implementation
        assert mask.pattern == "AAA-A##-RRRR"

    def test_build_from_template_invalid_template(self) -> None:
        """Ошибка при отсутствии атрибута segments."""
        invalid_template = Mock(spec=[])

        with pytest.raises(TypeError, match="должен иметь атрибут segments"):
            InputMask.build_from_template(invalid_template)


# =============================================================================
# Segment to Mask Tests
# =============================================================================


class TestSegmentToMask:
    """Тесты преобразования сегментов в маски."""

    def test_root_code_segment(self) -> None:
        """ROOT_CODE сегмент преобразуется в AAA."""
        segment = IndexSegmentDef(
            name="type",
            segment_type=SegmentType.ROOT_CODE,
            label="Тип",
            label_en="Type",
            pattern=r"[A-Z]{3}",
        )
        mask = InputMask._segment_to_mask(segment)
        assert mask == "AAA"

    def test_subtype_segment(self) -> None:
        """SUBTYPE сегмент преобразуется в ##."""
        segment = IndexSegmentDef(
            name="subtype",
            segment_type=SegmentType.SUBTYPE,
            label="Подтип",
            label_en="Subtype",
            pattern=r"\d{2}",
        )
        mask = InputMask._segment_to_mask(segment)
        assert mask == "##"

    def test_series_segment(self) -> None:
        """SERIES сегмент преобразуется в A##."""
        segment = IndexSegmentDef(
            name="series",
            segment_type=SegmentType.SERIES,
            label="Серия",
            label_en="Series",
            pattern=r"[A-Z]\d{2}",
        )
        mask = InputMask._segment_to_mask(segment)
        assert mask == "A##"

    def test_sequence_segment(self) -> None:
        """SEQUENCE сегмент преобразуется в RRRR."""
        segment = IndexSegmentDef(
            name="seq",
            segment_type=SegmentType.SEQUENCE,
            label="Номер",
            label_en="Number",
            pattern=r"[IVXLCDM]+",
        )
        mask = InputMask._segment_to_mask(segment)
        assert mask == "RRRR"

    def test_custom_segment_with_digits(self) -> None:
        """CUSTOM сегмент с цифрами."""
        segment = IndexSegmentDef(
            name="custom",
            segment_type=SegmentType.CUSTOM,
            label="Произвольный",
            label_en="Custom",
            pattern=r"\d{3}",
        )
        mask = InputMask._segment_to_mask(segment)
        assert mask == "###"

    def test_custom_segment_with_letters(self) -> None:
        """CUSTOM сегмент с буквами."""
        segment = IndexSegmentDef(
            name="custom",
            segment_type=SegmentType.CUSTOM,
            label="Произвольный",
            label_en="Custom",
            pattern=r"[A-Z]{3}",
        )
        mask = InputMask._segment_to_mask(segment)
        assert mask == "AAA"

    def test_custom_segment_mixed(self) -> None:
        """CUSTOM сегмент со смешанными символами."""
        segment = IndexSegmentDef(
            name="custom",
            segment_type=SegmentType.CUSTOM,
            label="Произвольный",
            label_en="Custom",
            pattern=r"[A-Z]\d{2}",
        )
        mask = InputMask._segment_to_mask(segment)
        assert mask == "NNN"


# =============================================================================
# Expected Length Tests
# =============================================================================


class TestExpectedLength:
    """Тесты метода get_expected_length()."""

    def test_expected_length_date(self) -> None:
        """Ожидаемая длина для маски даты."""
        mask = InputMask(pattern="##.##.####")
        assert mask.get_expected_length() == 8

    def test_expected_length_phone(self) -> None:
        """Ожидаемая длина для маски телефона."""
        mask = InputMask(pattern="+7 (###) ###-##-##")
        assert mask.get_expected_length() == 10

    def test_expected_length_only_separators(self) -> None:
        """Маска без позиций ввода."""
        mask = InputMask(pattern="---")
        assert mask.get_expected_length() == 0


# =============================================================================
# Edge Cases and Boundary Tests
# =============================================================================


class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_apply_exact_length(self) -> None:
        """Ввод точно по длине маски."""
        mask = InputMask(pattern="###")
        result = mask.apply("123")
        assert result == "123"

    def test_apply_shorter_than_mask(self) -> None:
        """Ввод короче маски."""
        mask = InputMask(pattern="#####")
        result = mask.apply("12")
        assert result == "12___"

    def test_strip_with_extra_chars(self) -> None:
        """Strip с лишними символами после маски."""
        mask = InputMask(pattern="###")
        # Лишние символы игнорируются
        result = mask.strip("123extra")
        assert result == "123"

    def test_validate_unicode_in_mask(self) -> None:
        """Маска с Unicode разделителями."""
        mask = InputMask(pattern="##–##")  # En-dash
        result = mask.apply("1234")
        assert result == "12–34"

    def test_is_complete_with_trailing_separators(self) -> None:
        """Проверка завершенности с разделителями в конце."""
        mask = InputMask(pattern="###-")
        assert mask.is_complete("123-") is True


# =============================================================================
# Parametrized Tests
# =============================================================================


@pytest.mark.parametrize(
    "pattern,raw,expected",
    [
        # Date patterns
        ("##.##.####", "25122026", "25.12.2026"),
        ("##.##.####", "2512", "25.12.____"),  # Fixed: pattern has 8 mask positions
        ("##/##/####", "25122026", "25/12/2026"),
        # Phone patterns
        ("+7 (###) ###-##-##", "4951234567", "+7 (495) 123-45-67"),
        ("###-##-##", "1234567", "123-45-67"),
        # Document index patterns
        ("AAA-##-A##-RR", "DVN44K53IX", "DVN-44-K53-IX"),
        ("AAA-##", "ABC12", "ABC-12"),
    ],
)
def test_apply_various_patterns(pattern: str, raw: str, expected: str) -> None:
    """Параметризованные тесты apply()."""
    mask = InputMask(pattern=pattern)
    result = mask.apply(raw)
    assert result == expected


@pytest.mark.parametrize(
    "pattern,masked,expected",
    [
        ("##.##.####", "25.12.2026", "25122026"),
        ("##.##.####", "25.12.____", "2512"),  # Fixed: matches actual pattern output
        ("+7 (###) ###-##-##", "+7 (495) 123-45-67", "4951234567"),
        ("AAA-##", "ABC-12", "ABC12"),
    ],
)
def test_strip_various_patterns(pattern: str, masked: str, expected: str) -> None:
    """Параметризованные тесты strip()."""
    mask = InputMask(pattern=pattern)
    result = mask.strip(masked)
    assert result == expected


@pytest.mark.parametrize(
    "pattern,masked,expected",
    [
        ("##.##.####", "25.12.2026", True),
        ("##.##.####", "25.12.____", False),
        ("###", "123", True),
        ("###", "12_", False),
        ("###", "___", False),
    ],
)
def test_is_complete_various_patterns(pattern: str, masked: str, expected: bool) -> None:
    """Параметризованные тесты is_complete()."""
    mask = InputMask(pattern=pattern)
    result = mask.is_complete(masked)
    assert result is expected


@pytest.mark.parametrize(
    "pattern,raw,expected",
    [
        ("AAA-##", "ABC12", True),
        ("AAA-##", "ABC123", False),  # Too long
        ("AAA-##", "AB1", False),  # Too short
        ("###", "123", True),
        ("###", "abc", False),
        ("RR", "IV", True),
        ("RR", "AB", False),
    ],
)
def test_validate_various_patterns(pattern: str, raw: str, expected: bool) -> None:
    """Параметризованные тесты validate()."""
    mask = InputMask(pattern=pattern)
    result = mask.validate(raw)
    assert result is expected


# =============================================================================
# Mask Constants Tests
# =============================================================================


class TestMaskConstants:
    """Тесты констант маски."""

    def test_mask_digit_constant(self) -> None:
        """Константа для цифр."""
        assert _MASK_DIGIT == "#"

    def test_mask_letter_constant(self) -> None:
        """Константа для латинских букв."""
        assert _MASK_LETTER == "A"

    def test_mask_roman_constant(self) -> None:
        """Константа для римских цифр."""
        assert _MASK_ROMAN == "R"

    def test_mask_any_letter_constant(self) -> None:
        """Константа для любых букв."""
        assert _MASK_ANY_LETTER == "L"

    def test_mask_alphanum_constant(self) -> None:
        """Константа для буквенно-цифровых символов."""
        assert _MASK_ALPHANUM == "N"

    def test_valid_mask_chars(self) -> None:
        """Набор валидных символов маски."""
        expected = {_MASK_DIGIT, _MASK_LETTER, _MASK_ROMAN, _MASK_ANY_LETTER, _MASK_ALPHANUM}
        assert _VALID_MASK_CHARS == expected
