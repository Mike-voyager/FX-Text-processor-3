"""Тесты для модуля index_formatter.

Покрытие:
- int_to_roman
- roman_to_int
- format_index
- parse_index
- validate_index_segment
"""

from __future__ import annotations

import pytest
from src.documents.types.index_formatter import (
    format_index,
    int_to_roman,
    parse_index,
    roman_to_int,
    validate_index_segment,
)

# ============ int_to_roman Tests ============


class TestIntToRoman:
    """Тесты для int_to_roman."""

    @pytest.mark.parametrize(
        "number,expected",
        [
            (1, "I"),
            (2, "II"),
            (3, "III"),
            (4, "IV"),
            (5, "V"),
            (6, "VI"),
            (7, "VII"),
            (8, "VIII"),
            (9, "IX"),
            (10, "X"),
            (11, "XI"),
            (14, "XIV"),
            (15, "XV"),
            (19, "XIX"),
            (20, "XX"),
            (40, "XL"),
            (44, "XLIV"),
            (50, "L"),
            (90, "XC"),
            (100, "C"),
            (400, "CD"),
            (444, "CDXLIV"),
            (500, "D"),
            (900, "CM"),
            (999, "CMXCIX"),
            (1000, "M"),
            (1999, "MCMXCIX"),
            (3999, "MMMCMXCIX"),
        ],
    )
    def test_int_to_roman_standard(self, number: int, expected: str) -> None:
        """Стандартные значения."""
        assert int_to_roman(number) == expected

    def test_int_to_roman_zero_raises(self) -> None:
        """Ноль вызывает ValueError."""
        with pytest.raises(ValueError, match="must be positive"):
            int_to_roman(0)

    def test_int_to_roman_negative_raises(self) -> None:
        """Отрицательное вызывает ValueError."""
        with pytest.raises(ValueError, match="must be positive"):
            int_to_roman(-5)

    def test_int_to_roman_large(self) -> None:
        """Большое число."""
        result = int_to_roman(3888)
        assert result == "MMMDCCCLXXXVIII"


# ============ roman_to_int Tests ============


class TestRomanToInt:
    """Тесты для roman_to_int."""

    @pytest.mark.parametrize(
        "roman,expected",
        [
            ("I", 1),
            ("II", 2),
            ("III", 3),
            ("IV", 4),
            ("V", 5),
            ("VI", 6),
            ("VII", 7),
            ("VIII", 8),
            ("IX", 9),
            ("X", 10),
            ("XI", 11),
            ("XIV", 14),
            ("XV", 15),
            ("XIX", 19),
            ("XX", 20),
            ("XL", 40),
            ("XLIV", 44),
            ("L", 50),
            ("XC", 90),
            ("C", 100),
            ("CD", 400),
            ("CDXLIV", 444),
            ("D", 500),
            ("CM", 900),
            ("CMXCIX", 999),
            ("M", 1000),
            ("MCMXCIX", 1999),
            ("MMMCMXCIX", 3999),
        ],
    )
    def test_roman_to_int_standard(self, roman: str, expected: int) -> None:
        """Стандартные значения."""
        assert roman_to_int(roman) == expected

    @pytest.mark.parametrize("roman", ["i", "I"])
    def test_roman_to_int_case_insensitive(self, roman: str) -> None:
        """Регистронезависимость (только однородный регистр)."""
        assert roman_to_int(roman) == 1

    def test_roman_to_int_mixed_case(self) -> None:
        """Смешанный регистр также поддерживается (преобразуется в upper)."""
        # "Ii" после upper() становится "II" = 2
        assert roman_to_int("Ii") == 2
        assert roman_to_int("iI") == 2

    def test_roman_to_int_empty_raises(self) -> None:
        """Пустая строка вызывает ValueError."""
        with pytest.raises(ValueError, match="Empty string"):
            roman_to_int("")

    def test_roman_to_int_invalid_chars_raises(self) -> None:
        """Недопустимые символы вызывают ValueError."""
        with pytest.raises(ValueError, match="Invalid roman numeral"):
            roman_to_int("ABC")

    def test_roman_to_int_invalid_format_raises(self) -> None:
        """Невалидный формат вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid roman numeral"):
            roman_to_int("IIII")  # IV, не IIII

    def test_roman_to_int_roundtrip(self) -> None:
        """Обратное преобразование."""
        for n in [1, 4, 9, 42, 99, 500, 1999, 3999]:
            roman = int_to_roman(n)
            assert roman_to_int(roman) == n


# ============ format_index Tests ============


class TestFormatIndex:
    """Тесты для format_index."""

    def test_format_index_default_separator(self) -> None:
        """Форматирование с сепаратором по умолчанию."""
        result = format_index(["DVN", "44", "K53", "IX"])
        assert result == "DVN-44-K53-IX"

    def test_format_index_custom_separator(self) -> None:
        """Форматирование с кастомным сепаратором."""
        result = format_index(["DVN", "44", "K53", "IX"], separator="/")
        assert result == "DVN/44/K53/IX"

    def test_format_index_dot_separator(self) -> None:
        """Форматирование с точкой."""
        result = format_index(["DOC", "001"], separator=".")
        assert result == "DOC.001"

    def test_format_index_single_segment(self) -> None:
        """Один сегмент."""
        result = format_index(["ONLY"])
        assert result == "ONLY"

    def test_format_index_empty_segments(self) -> None:
        """Пустые сегменты."""
        result = format_index([])
        assert result == ""


# ============ parse_index Tests ============


class TestParseIndex:
    """Тесты для parse_index."""

    def test_parse_index_default_separator(self) -> None:
        """Парсинг с сепаратором по умолчанию."""
        result = parse_index("DVN-44-K53-IX")
        assert result == ["DVN", "44", "K53", "IX"]

    def test_parse_index_custom_separator(self) -> None:
        """Парсинг с кастомным сепаратором."""
        result = parse_index("DVN/44/K53/IX", separator="/")
        assert result == ["DVN", "44", "K53", "IX"]

    def test_parse_index_dot_separator(self) -> None:
        """Парсинг с точкой."""
        result = parse_index("DOC.001", separator=".")
        assert result == ["DOC", "001"]

    def test_parse_index_single_segment(self) -> None:
        """Один сегмент."""
        result = parse_index("ONLY")
        assert result == ["ONLY"]

    def test_parse_index_empty_string(self) -> None:
        """Пустая строка."""
        result = parse_index("")
        assert result == [""]


# ============ validate_index_segment Tests ============


class TestValidateIndexSegment:
    """Тесты для validate_index_segment."""

    def test_validate_pattern_match(self) -> None:
        """Совпадение с паттерном."""
        assert validate_index_segment("DVN", r"[A-Z]{3}") is True

    def test_validate_pattern_no_match(self) -> None:
        """Несовпадение с паттерном."""
        assert validate_index_segment("dvn", r"[A-Z]{3}") is False

    def test_validate_with_allowed_values_match(self) -> None:
        """Совпадение с allowed_values."""
        assert validate_index_segment("DOC", r"[A-Z]+", ["DOC", "INV"]) is True

    def test_validate_with_allowed_values_no_match(self) -> None:
        """Несовпадение с allowed_values."""
        assert validate_index_segment("OTHER", r"[A-Z]+", ["DOC", "INV"]) is False

    def test_validate_pattern_fails_allowed_values_ok(self) -> None:
        """Паттерн не совпадает — allowed_values не проверяются."""
        assert validate_index_segment("doc", r"[A-Z]+", ["DOC"]) is False

    def test_validate_empty_allowed_values_list(self) -> None:
        """Пустой список allowed_values."""
        assert validate_index_segment("ANY", r"[A-Z]+", []) is False

    def test_validate_no_allowed_values(self) -> None:
        """None для allowed_values."""
        assert validate_index_segment("ANYTHING", r".*") is True

    @pytest.mark.parametrize(
        "value,pattern",
        [
            ("44", r"\d{1,2}"),
            ("K53", r"[A-Z]\d{2}"),
            ("IX", r"[IVXLCDM]+"),
            ("001", r"\d{3}"),
        ],
    )
    def test_validate_common_patterns(self, value: str, pattern: str) -> None:
        """Распространённые паттерны индексов."""
        assert validate_index_segment(value, pattern) is True

    def test_validate_numeric_pattern_fail(self) -> None:
        """Неверный формат числа."""
        assert validate_index_segment("abc", r"\d+") is False

    def test_validate_complex_pattern(self) -> None:
        """Сложный паттерн."""
        assert validate_index_segment("DOC-2026", r"[A-Z]+-\d{4}") is True
        assert validate_index_segment("WRONG", r"[A-Z]+-\d{4}") is False
