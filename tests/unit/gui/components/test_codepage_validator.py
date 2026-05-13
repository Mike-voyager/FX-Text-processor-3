"""Tests for CodepageValidator component.

Модуль тестирует валидатор кодовой страницы PC866:
- Проверка валидных/невалидных символов
- Применение замен
- Граничные случаи

Coverage target: >=90%
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

# Import directly from file to avoid circular imports through __init__.py
# This is a test-only workaround for the existing circular import issue in the codebase
_spec = importlib.util.spec_from_file_location(
    "codepage_validator",
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "src", "gui", "components", "codepage_validator.py")
)
_codepage_validator_module = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules["codepage_validator"] = _codepage_validator_module
_spec.loader.exec_module(_codepage_validator_module)  # type: ignore[union-attr]

CodepageValidator = _codepage_validator_module.CodepageValidator
ValidationResult = _codepage_validator_module.ValidationResult


# Test data constants
YO_LOWER = "\u0451"       # ё
YO_UPPER = "\u0401"       # Ё
EM_DASH = "\u2014"          # —
EN_DASH = "\u2013"          # –
LEFT_DOUBLE_QUOTE = "\u201C"  # "
RIGHT_DOUBLE_QUOTE = "\u201D" # "
LEFT_SINGLE_QUOTE = "\u2018"   # '
RIGHT_SINGLE_QUOTE = "\u2019"   # '
NUMERO_SIGN = "\u2116"        # №
LEFT_ANGLE = "\u00AB"         # «
RIGHT_ANGLE = "\u00BB"        # »
ELLIPSIS = "\u2026"           # …
BULLET = "\u2022"             # •
RIGHT_ARROW = "\u2192"        # →
LEFT_ARROW = "\u2190"         # ←


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_validation_result_creation(self) -> None:
        """Test ValidationResult can be created with all fields."""
        result = ValidationResult(
            char=EM_DASH,
            position=5,
            replacement='-',
            is_valid=False,
        )

        assert result.char == EM_DASH
        assert result.position == 5
        assert result.replacement == '-'
        assert result.is_valid is False

    def test_validation_result_immutable(self) -> None:
        """Test ValidationResult is frozen (immutable)."""
        result = ValidationResult(
            char=EM_DASH,
            position=5,
            replacement='-',
            is_valid=False,
        )

        with pytest.raises(AttributeError):
            result.char = 'x'  # type: ignore[misc]

    def test_validation_result_equality(self) -> None:
        """Test ValidationResult equality comparison."""
        result1 = ValidationResult(EM_DASH, 5, '-', False)
        result2 = ValidationResult(EM_DASH, 5, '-', False)
        result3 = ValidationResult(EM_DASH, 6, '-', False)

        assert result1 == result2
        assert result1 != result3


class TestCodepageValidatorInit:
    """Tests for CodepageValidator initialization."""

    def test_validator_creation(self) -> None:
        """Test CodepageValidator can be instantiated."""
        validator = CodepageValidator()
        assert validator is not None

    def test_validator_has_constants(self) -> None:
        """Test validator has class-level constants."""
        validator = CodepageValidator()

        assert len(validator.PC866_SUPPORTED) > 0
        assert len(validator.REPLACEMENT_MAP) > 0


class TestIsValidChar:
    """Tests for is_valid_char method."""

    @pytest.fixture
    def validator(self) -> CodepageValidator:
        """Create a fresh validator instance."""
        return CodepageValidator()

    def test_ascii_characters_valid(self, validator: CodepageValidator) -> None:
        """Test ASCII characters are valid."""
        for char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789':
            assert validator.is_valid_char(char) is True

    def test_cyrillic_characters_valid(self, validator: CodepageValidator) -> None:
        """Test standard Cyrillic characters are valid."""
        valid_cyrillic = 'АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯабвгдежзийклмнопрстуфхцчшщъыьэюя'
        for char in valid_cyrillic:
            assert validator.is_valid_char(char) is True, f"Char '{char}' should be valid"

    def test_yo_characters_invalid(self, validator: CodepageValidator) -> None:
        """Test ё and Ё are not valid (need replacement)."""
        assert validator.is_valid_char(YO_LOWER) is False
        assert validator.is_valid_char(YO_UPPER) is False

    def test_emdash_invalid(self, validator: CodepageValidator) -> None:
        """Test em-dash is not valid."""
        assert validator.is_valid_char(EM_DASH) is False

    def test_endash_invalid(self, validator: CodepageValidator) -> None:
        """Test en-dash is not valid."""
        assert validator.is_valid_char(EN_DASH) is False

    def test_smart_quotes_invalid(self, validator: CodepageValidator) -> None:
        """Test smart quotes are not valid."""
        assert validator.is_valid_char(LEFT_DOUBLE_QUOTE) is False
        assert validator.is_valid_char(RIGHT_DOUBLE_QUOTE) is False
        assert validator.is_valid_char(LEFT_SINGLE_QUOTE) is False
        assert validator.is_valid_char(RIGHT_SINGLE_QUOTE) is False

    def test_number_sign_invalid(self, validator: CodepageValidator) -> None:
        """Test numero sign is not valid."""
        assert validator.is_valid_char(NUMERO_SIGN) is False

    def test_angle_quotes_invalid(self, validator: CodepageValidator) -> None:
        """Test angle quotes are not valid."""
        assert validator.is_valid_char(LEFT_ANGLE) is False
        assert validator.is_valid_char(RIGHT_ANGLE) is False

    def test_ellipsis_invalid(self, validator: CodepageValidator) -> None:
        """Test ellipsis is not valid."""
        assert validator.is_valid_char(ELLIPSIS) is False

    def test_empty_string_raises(self, validator: CodepageValidator) -> None:
        """Test empty string raises ValueError."""
        with pytest.raises(ValueError):
            validator.is_valid_char('')

    def test_multiple_chars_raises(self, validator: CodepageValidator) -> None:
        """Test multi-character string raises ValueError."""
        with pytest.raises(ValueError):
            validator.is_valid_char('ab')


class TestGetReplacement:
    """Tests for get_replacement method."""

    @pytest.fixture
    def validator(self) -> CodepageValidator:
        """Create a fresh validator instance."""
        return CodepageValidator()

    def test_yo_replacements(self, validator: CodepageValidator) -> None:
        """Test ё/Ё replacements."""
        assert validator.get_replacement(YO_LOWER) == '\u0435'  # е
        assert validator.get_replacement(YO_UPPER) == '\u0415'  # Е

    def test_dash_replacements(self, validator: CodepageValidator) -> None:
        """Test dash replacements."""
        assert validator.get_replacement(EM_DASH) == '-'
        assert validator.get_replacement(EN_DASH) == '-'

    def test_smart_quote_replacements(self, validator: CodepageValidator) -> None:
        """Test smart quote replacements."""
        assert validator.get_replacement(LEFT_DOUBLE_QUOTE) == '"'
        assert validator.get_replacement(RIGHT_DOUBLE_QUOTE) == '"'
        assert validator.get_replacement(LEFT_SINGLE_QUOTE) == "'"
        assert validator.get_replacement(RIGHT_SINGLE_QUOTE) == "'"

    def test_number_sign_replacement(self, validator: CodepageValidator) -> None:
        """Test numero sign replacement."""
        assert validator.get_replacement(NUMERO_SIGN) == 'N'

    def test_angle_quote_replacements(self, validator: CodepageValidator) -> None:
        """Test angle quote replacements."""
        assert validator.get_replacement(LEFT_ANGLE) == '"'
        assert validator.get_replacement(RIGHT_ANGLE) == '"'

    def test_ellipsis_replacement(self, validator: CodepageValidator) -> None:
        """Test ellipsis replacement."""
        assert validator.get_replacement(ELLIPSIS) == '...'

    def test_bullet_replacement(self, validator: CodepageValidator) -> None:
        """Test bullet replacement."""
        assert validator.get_replacement(BULLET) == '-'

    def test_arrow_replacements(self, validator: CodepageValidator) -> None:
        """Test arrow replacements."""
        assert validator.get_replacement(RIGHT_ARROW) == '->'
        assert validator.get_replacement(LEFT_ARROW) == '<-'

    def test_valid_char_returns_none(self, validator: CodepageValidator) -> None:
        """Test valid characters return None."""
        assert validator.get_replacement('A') is None
        assert validator.get_replacement('\u0430') is None  # а
        assert validator.get_replacement('-') is None

    def test_empty_string_raises(self, validator: CodepageValidator) -> None:
        """Test empty string raises ValueError."""
        with pytest.raises(ValueError):
            validator.get_replacement('')

    def test_multiple_chars_raises(self, validator: CodepageValidator) -> None:
        """Test multi-character string raises ValueError."""
        with pytest.raises(ValueError):
            validator.get_replacement('ab')


class TestValidate:
    """Tests for validate method."""

    @pytest.fixture
    def validator(self) -> CodepageValidator:
        """Create a fresh validator instance."""
        return CodepageValidator()

    def test_empty_string(self, validator: CodepageValidator) -> None:
        """Test empty string returns empty list."""
        results = validator.validate('')
        assert results == []

    def test_all_valid_string(self, validator: CodepageValidator) -> None:
        """Test all-valid string returns empty list."""
        results = validator.validate('Hello World!')
        assert results == []

    def test_single_invalid_char(self, validator: CodepageValidator) -> None:
        """Test single invalid character is detected."""
        results = validator.validate(EM_DASH)

        assert len(results) == 1
        assert results[0].char == EM_DASH
        assert results[0].position == 0
        assert results[0].replacement == '-'
        assert results[0].is_valid is False

    def test_multiple_invalid_chars(self, validator: CodepageValidator) -> None:
        """Test multiple invalid characters are detected."""
        # ёлка— where ё and — are invalid
        text = YO_LOWER + '\u0435\u043b\u043a\u0430' + EM_DASH  # ёлка—
        results = validator.validate(text)

        assert len(results) == 2
        assert results[0].char == YO_LOWER
        assert results[0].position == 0
        assert results[1].char == EM_DASH
        assert results[1].position == 5

    def test_mixed_valid_invalid(self, validator: CodepageValidator) -> None:
        """Test mixed valid/invalid characters."""
        text = 'Test ' + EM_DASH + ' 123'
        results = validator.validate(text)

        assert len(results) == 1
        assert results[0].char == EM_DASH
        assert results[0].position == 5

    def test_position_tracking(self, validator: CodepageValidator) -> None:
        """Test positions are tracked correctly."""
        # aёb—c where ё and — are invalid
        text = 'a' + YO_LOWER + 'b' + EM_DASH + 'c'
        results = validator.validate(text)

        assert len(results) == 2
        assert results[0].position == 1  # ё
        assert results[1].position == 3  # —

    def test_cyrillic_text_with_yo(self, validator: CodepageValidator) -> None:
        """Test Cyrillic text with ё characters."""
        text = YO_UPPER + '\u043b\u043a\u0430'  # Ёлка
        results = validator.validate(text)

        assert len(results) == 1
        assert results[0].char == YO_UPPER
        assert results[0].replacement == '\u0415'  # Е

    def test_text_with_quotes(self, validator: CodepageValidator) -> None:
        """Test text with various quote styles."""
        text = LEFT_DOUBLE_QUOTE + 'Hello' + RIGHT_DOUBLE_QUOTE
        results = validator.validate(text)

        assert len(results) == 2
        assert results[0].char == LEFT_DOUBLE_QUOTE
        assert results[1].char == RIGHT_DOUBLE_QUOTE


class TestFixAll:
    """Tests for fix_all method."""

    @pytest.fixture
    def validator(self) -> CodepageValidator:
        """Create a fresh validator instance."""
        return CodepageValidator()

    def test_empty_string(self, validator: CodepageValidator) -> None:
        """Test empty string returns empty string."""
        assert validator.fix_all('') == ''

    def test_no_changes_needed(self, validator: CodepageValidator) -> None:
        """Test valid text is unchanged."""
        text = 'Hello World!'
        assert validator.fix_all(text) == text

    def test_fix_yo(self, validator: CodepageValidator) -> None:
        """Test ё is replaced with е."""
        # ёлка → елка
        # YO_LOWER is ё, е is \u0435, л is \u043b, к is \u043a, а is \u0430
        assert validator.fix_all(YO_LOWER + '\u043b\u043a\u0430') == '\u0435\u043b\u043a\u0430'
        # Ёлка → Елка
        assert validator.fix_all(YO_UPPER + '\u043b\u043a\u0430') == '\u0415\u043b\u043a\u0430'

    def test_fix_emdash(self, validator: CodepageValidator) -> None:
        """Test em-dash is replaced with hyphen."""
        assert validator.fix_all('Hello ' + EM_DASH + ' world') == 'Hello - world'

    def test_fix_endash(self, validator: CodepageValidator) -> None:
        """Test en-dash is replaced with hyphen."""
        assert validator.fix_all('Test' + EN_DASH + '123') == 'Test-123'

    def test_fix_smart_quotes(self, validator: CodepageValidator) -> None:
        """Test smart quotes are replaced."""
        assert validator.fix_all(LEFT_DOUBLE_QUOTE + 'test' + RIGHT_DOUBLE_QUOTE) == '"test"'
        assert validator.fix_all(LEFT_SINGLE_QUOTE + 'test' + RIGHT_SINGLE_QUOTE) == "'test'"

    def test_fix_number_sign(self, validator: CodepageValidator) -> None:
        """Test numero sign is replaced with N."""
        assert validator.fix_all(NUMERO_SIGN + ' 123') == 'N 123'

    def test_fix_angle_quotes(self, validator: CodepageValidator) -> None:
        """Test angle quotes are replaced."""
        assert validator.fix_all(LEFT_ANGLE + '\u0442\u0435\u043a\u0441\u0442' + RIGHT_ANGLE) == '"\u0442\u0435\u043a\u0441\u0442"'

    def test_fix_ellipsis(self, validator: CodepageValidator) -> None:
        """Test ellipsis is replaced with three dots."""
        assert validator.fix_all('Text' + ELLIPSIS) == 'Text...'

    def test_fix_bullet(self, validator: CodepageValidator) -> None:
        """Test bullet is replaced with hyphen."""
        assert validator.fix_all('Item ' + BULLET + ' List') == 'Item - List'

    def test_fix_arrows(self, validator: CodepageValidator) -> None:
        """Test arrows are replaced."""
        assert validator.fix_all(RIGHT_ARROW) == '->'
        assert validator.fix_all(LEFT_ARROW) == '<-'

    def test_multiple_fixes(self, validator: CodepageValidator) -> None:
        """Test multiple replacements in one text."""
        # ёлка — "test" → елка - "test"
        # ёлка = ё + л + к + а = YO_LOWER + \u043b + \u043a + \u0430
        input_text = YO_LOWER + '\u043b\u043a\u0430 ' + EM_DASH + ' \u201Ctest\u201D'
        expected = '\u0435\u043b\u043a\u0430 - \"test\"'
        assert validator.fix_all(input_text) == expected

    def test_cyrillic_sentence(self, validator: CodepageValidator) -> None:
        """Test full Cyrillic sentence."""
        # Ёлка — зелёная → Елка - зеленая
        input_text = YO_UPPER + '\u043b\u043a\u0430 ' + EM_DASH + ' \u0437\u0435\u043b' + YO_LOWER + '\u0443\u044f'
        expected = '\u0415\u043b\u043a\u0430 - \u0437\u0435\u043b\u0435\u0443\u044f'
        assert validator.fix_all(input_text) == expected


class TestCountInvalid:
    """Tests for count_invalid method."""

    @pytest.fixture
    def validator(self) -> CodepageValidator:
        """Create a fresh validator instance."""
        return CodepageValidator()

    def test_empty_string(self, validator: CodepageValidator) -> None:
        """Test empty string returns 0."""
        assert validator.count_invalid('') == 0

    def test_all_valid(self, validator: CodepageValidator) -> None:
        """Test all-valid text returns 0."""
        assert validator.count_invalid('Hello World') == 0

    def test_all_cyrillic_valid(self, validator: CodepageValidator) -> None:
        """Test valid Cyrillic text returns 0."""
        assert validator.count_invalid('\u041f\u0440\u0438\u0432\u0435\u0442 \u043c\u0438\u0440') == 0

    def test_single_invalid(self, validator: CodepageValidator) -> None:
        """Test single invalid character counted."""
        assert validator.count_invalid(EM_DASH) == 1

    def test_multiple_invalid(self, validator: CodepageValidator) -> None:
        """Test multiple invalid characters counted."""
        # ёлка— where ё and — are invalid
        text = YO_LOWER + '\u0435\u043b\u043a\u0430' + EM_DASH
        assert validator.count_invalid(text) == 2

    def test_mixed_text(self, validator: CodepageValidator) -> None:
        """Test mixed valid/invalid text."""
        assert validator.count_invalid('Hello ' + EM_DASH + ' \u043c\u0438\u0440') == 1


class TestHasReplacement:
    """Tests for has_replacement method."""

    @pytest.fixture
    def validator(self) -> CodepageValidator:
        """Create a fresh validator instance."""
        return CodepageValidator()

    def test_has_replacement_true(self, validator: CodepageValidator) -> None:
        """Test characters with replacements return True."""
        assert validator.has_replacement(YO_LOWER) is True
        assert validator.has_replacement(EM_DASH) is True

    def test_has_replacement_false(self, validator: CodepageValidator) -> None:
        """Test characters without replacements return False."""
        assert validator.has_replacement('A') is False
        assert validator.has_replacement('\u0430') is False

    def test_empty_string_raises(self, validator: CodepageValidator) -> None:
        """Test empty string raises ValueError."""
        with pytest.raises(ValueError):
            validator.has_replacement('')


class TestGetValidChars:
    """Tests for get_valid_chars method."""

    def test_returns_frozenset(self) -> None:
        """Test method returns a frozenset."""
        validator = CodepageValidator()
        chars = validator.get_valid_chars()

        assert isinstance(chars, frozenset)
        assert len(chars) > 0

    def test_contains_ascii(self) -> None:
        """Test returned set contains ASCII."""
        validator = CodepageValidator()
        chars = validator.get_valid_chars()

        assert 'A' in chars
        assert 'z' in chars
        assert '5' in chars

    def test_contains_cyrillic(self) -> None:
        """Test returned set contains Cyrillic."""
        validator = CodepageValidator()
        chars = validator.get_valid_chars()

        assert '\u0410' in chars  # А
        assert '\u044f' in chars  # я


class TestGetReplacementChars:
    """Tests for get_replacement_chars method."""

    def test_returns_frozenset(self) -> None:
        """Test method returns a frozenset."""
        validator = CodepageValidator()
        chars = validator.get_replacement_chars()

        assert isinstance(chars, frozenset)
        assert len(chars) > 0

    def test_contains_replacable_chars(self) -> None:
        """Test returned set contains replacable characters."""
        validator = CodepageValidator()
        chars = validator.get_replacement_chars()

        assert YO_LOWER in chars
        assert EM_DASH in chars
        assert NUMERO_SIGN in chars


class TestEdgeCases:
    """Edge case tests."""

    @pytest.fixture
    def validator(self) -> CodepageValidator:
        """Create a fresh validator instance."""
        return CodepageValidator()

    def test_newline_handling(self, validator: CodepageValidator) -> None:
        """Test newlines are valid."""
        assert validator.is_valid_char('\n') is True
        assert validator.count_invalid('Line1\nLine2') == 0

    def test_tab_handling(self, validator: CodepageValidator) -> None:
        """Test tabs are valid."""
        assert validator.is_valid_char('\t') is True
        assert validator.count_invalid('Col1\tCol2') == 0

    def test_whitespace_handling(self, validator: CodepageValidator) -> None:
        """Test various whitespace is valid."""
        assert validator.is_valid_char(' ') is True
        assert validator.is_valid_char('\r') is True
        assert validator.count_invalid('  text  ') == 0

    def test_unicode_beyond_bmp(self, validator: CodepageValidator) -> None:
        """Test characters beyond BMP are invalid."""
        # Emoji and other non-BMP characters
        assert validator.is_valid_char('😀') is False

    def test_control_characters(self, validator: CodepageValidator) -> None:
        """Test control characters handling."""
        # Standard ASCII controls should be valid (part of PC866)
        assert validator.is_valid_char('\x00') is True
        assert validator.is_valid_char('\x1f') is True

    def test_special_punctuation(self, validator: CodepageValidator) -> None:
        """Test special punctuation characters."""
        # Standard ASCII punctuation is valid
        assert validator.is_valid_char('!') is True
        assert validator.is_valid_char('@') is True
        assert validator.is_valid_char('#') is True
        assert validator.is_valid_char('$') is True
        assert validator.is_valid_char('%') is True
        assert validator.is_valid_char('^') is True
        assert validator.is_valid_char('\u0026') is True
        assert validator.is_valid_char('*') is True
        assert validator.is_valid_char('(') is True
        assert validator.is_valid_char(')') is True

    def test_very_long_text(self, validator: CodepageValidator) -> None:
        """Test handling of very long text."""
        long_text = 'A' * 10000 + YO_LOWER + 'B' * 10000
        results = validator.validate(long_text)

        assert len(results) == 1
        assert results[0].position == 10000
        assert results[0].char == YO_LOWER

    def test_all_replacement_map_chars(self, validator: CodepageValidator) -> None:
        """Test all characters in REPLACEMENT_MAP have replacements."""
        for char in validator.REPLACEMENT_MAP:
            replacement = validator.get_replacement(char)
            assert replacement is not None
            assert isinstance(replacement, str)
