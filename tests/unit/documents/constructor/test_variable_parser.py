"""Тесты для модуля variable_parser.

Покрытие:
- VariableParser инициализация
- parse() метод с разными синтаксисами
- extract_variables()
- substitute_batch()
- parse_esc_variables()
- has_variables()
- validate_variables()
"""

from __future__ import annotations

import pytest
from src.documents.constructor.variable_parser import VariableParser


class TestVariableParserInit:
    """Тесты инициализации VariableParser."""

    def test_create_parser(self) -> None:
        """Создание парсера."""
        parser = VariableParser()
        assert parser is not None

    def test_esc_variables_defined(self) -> None:
        """ESC переменные определены."""
        assert "PAGE_BREAK" in VariableParser.ESC_VARIABLES
        assert "RESET_PRINTER" in VariableParser.ESC_VARIABLES
        assert "LINE_FEED" in VariableParser.ESC_VARIABLES


class TestVariableParserParse:
    """Тесты метода parse."""

    @pytest.fixture
    def parser(self) -> VariableParser:
        """Фикстура для парсера."""
        return VariableParser()

    def test_parse_double_braces(self, parser: VariableParser) -> None:
        """Подстановка {{variable}}."""
        result = parser.parse("Hello {{name}}!", {"name": "World"})
        assert result == "Hello World!"

    def test_parse_single_braces(self, parser: VariableParser) -> None:
        """Подстановка {variable}."""
        result = parser.parse("Value: {value}", {"value": 42})
        assert result == "Value: 42"

    def test_parse_dollar_braces(self, parser: VariableParser) -> None:
        """Подстановка ${variable} (синтаксис доллара)."""
        # ${var} pattern is processed - use a variable name
        result = parser.parse("${TEST_VAR}", {"TEST_VAR": "replaced"})
        assert "replaced" in result

    def test_dollar_braces_extracted(self, parser: VariableParser) -> None:
        """Извлечение переменных ${var}."""
        result = parser.extract_variables("${VAR1} and ${VAR2}")
        assert "VAR1" in result
        assert "VAR2" in result

    def test_parse_multiple_variables(self, parser: VariableParser) -> None:
        """Несколько переменных."""
        result = parser.parse(
            "{{greeting}}, {name}!",
            {"greeting": "Hello", "name": "Alice"},
        )
        assert result == "Hello, Alice!"

    def test_parse_missing_variable_keeps_placeholder(self, parser: VariableParser) -> None:
        """Отсутствующая переменная оставляет placeholder."""
        result = parser.parse("Hello {{missing}}!", {})
        assert result == "Hello {{missing}}!"

    def test_parse_empty_variables(self, parser: VariableParser) -> None:
        """Пустой словарь переменных."""
        result = parser.parse("Hello {{name}}!", {})
        assert result == "Hello {{name}}!"

    def test_parse_no_variables(self, parser: VariableParser) -> None:
        """Строка без переменных."""
        result = parser.parse("Plain text", {"var": "value"})
        assert result == "Plain text"

    def test_parse_number_value(self, parser: VariableParser) -> None:
        """Числовое значение конвертируется в строку."""
        result = parser.parse("Count: {{num}}", {"num": 123})
        assert result == "Count: 123"

    def test_parse_none_value(self, parser: VariableParser) -> None:
        """None значение конвертируется в строку 'None'."""
        result = parser.parse("Value: {{var}}", {"var": None})
        # None is converted to string
        assert result == "Value: None"


class TestExtractVariables:
    """Тесты метода extract_variables."""

    @pytest.fixture
    def parser(self) -> VariableParser:
        """Фикстура для парсера."""
        return VariableParser()

    def test_extract_double_braces(self, parser: VariableParser) -> None:
        """Извлечение {{var}}."""
        result = parser.extract_variables("{{name}} and {{age}}")
        assert result == ["age", "name"]  # sorted

    def test_extract_single_braces(self, parser: VariableParser) -> None:
        """Извлечение {var}."""
        result = parser.extract_variables("{x} {y}")
        assert result == ["x", "y"]

    def test_extract_dollar_braces(self, parser: VariableParser) -> None:
        """Извлечение ${var}."""
        result = parser.extract_variables("${HOME} ${USER}")
        assert result == ["HOME", "USER"]

    def test_extract_mixed_syntaxes(self, parser: VariableParser) -> None:
        """Смешанные синтаксисы."""
        result = parser.extract_variables("{{a}} {b} ${c}")
        assert result == ["a", "b", "c"]

    def test_extract_no_variables(self, parser: VariableParser) -> None:
        """Нет переменных."""
        result = parser.extract_variables("Plain text")
        assert result == []

    def test_extract_duplicates_removed(self, parser: VariableParser) -> None:
        """Дубликаты удаляются."""
        result = parser.extract_variables("{{x}} {{x}} {x}")
        assert result == ["x"]


class TestSubstituteBatch:
    """Тесты метода substitute_batch."""

    @pytest.fixture
    def parser(self) -> VariableParser:
        """Фикстура для парсера."""
        return VariableParser()

    def test_batch_substitution(self, parser: VariableParser) -> None:
        """Пакетная подстановка."""
        templates = ["Hello {{name}}", "Bye {{name}}"]
        result = parser.substitute_batch(templates, {"name": "Alice"})
        assert result == ["Hello Alice", "Bye Alice"]

    def test_batch_empty_list(self, parser: VariableParser) -> None:
        """Пустой список шаблонов."""
        result = parser.substitute_batch([], {"x": "y"})
        assert result == []


class TestParseEscVariables:
    """Тесты метода parse_esc_variables."""

    @pytest.fixture
    def parser(self) -> VariableParser:
        """Фикстура для парсера."""
        return VariableParser()

    def test_page_break(self, parser: VariableParser) -> None:
        """PAGE_BREAK -> 0x0C."""
        result = parser.parse_esc_variables("{{PAGE_BREAK}}")
        assert result == b"\x0c"

    def test_reset_printer(self, parser: VariableParser) -> None:
        """RESET_PRINTER -> ESC @."""
        result = parser.parse_esc_variables("{{RESET_PRINTER}}")
        assert result == b"\x1b\x40"

    def test_line_feed(self, parser: VariableParser) -> None:
        """LINE_FEED -> 0x0A."""
        result = parser.parse_esc_variables("{{LINE_FEED}}")
        assert result == b"\x0a"

    def test_multiple_esc_variables(self, parser: VariableParser) -> None:
        """Несколько ESC переменных."""
        result = parser.parse_esc_variables("{{RESET_PRINTER}}text{{PAGE_BREAK}}")
        assert result == b"\x1b\x40text\x0c"


class TestHasVariables:
    """Тесты метода has_variables."""

    @pytest.fixture
    def parser(self) -> VariableParser:
        """Фикстура для парсера."""
        return VariableParser()

    def test_has_variables_true(self, parser: VariableParser) -> None:
        """Есть переменные."""
        assert parser.has_variables("{{var}}") is True

    def test_has_variables_false(self, parser: VariableParser) -> None:
        """Нет переменных."""
        assert parser.has_variables("Plain text") is False

    def test_has_variables_empty(self, parser: VariableParser) -> None:
        """Пустая строка."""
        assert parser.has_variables("") is False


class TestValidateVariables:
    """Тесты метода validate_variables."""

    @pytest.fixture
    def parser(self) -> VariableParser:
        """Фикстура для парсера."""
        return VariableParser()

    def test_all_present(self, parser: VariableParser) -> None:
        """Все переменные на месте."""
        result = parser.validate_variables(
            "{{name}} {{age}}",
            {"name": "Alice", "age": 30},
        )
        assert result == []

    def test_one_missing(self, parser: VariableParser) -> None:
        """Одна переменная отсутствует."""
        result = parser.validate_variables(
            "{{name}} {{age}}",
            {"name": "Alice"},
        )
        assert result == ["age"]

    def test_multiple_missing(self, parser: VariableParser) -> None:
        """Несколько переменных отсутствуют."""
        result = parser.validate_variables(
            "{{a}} {{b}} {{c}}",
            {"a": "1"},
        )
        assert result == ["b", "c"]

    def test_no_variables_required(self, parser: VariableParser) -> None:
        """Нет переменных в шаблоне."""
        result = parser.validate_variables("Plain text", {})
        assert result == []


class TestVariablePatterns:
    """Тесты паттернов переменных."""

    def test_variable_pattern_double_braces(self) -> None:
        """Паттерн {{var}}."""

        pattern = VariableParser.PATTERN_DOUBLE_BRACES
        assert pattern.findall("{{test}}") == ["test"]
        assert pattern.findall("{{var_name}}") == ["var_name"]

    def test_variable_pattern_underscore(self) -> None:
        """Поддержка underscore."""

        pattern = VariableParser.PATTERN_DOUBLE_BRACES
        assert pattern.findall("{{my_var}}") == ["my_var"]

    def test_variable_pattern_numbers(self) -> None:
        """Поддержка цифр."""

        pattern = VariableParser.PATTERN_DOUBLE_BRACES
        assert pattern.findall("{{var123}}") == ["var123"]

    def test_variable_pattern_no_leading_digit(self) -> None:
        """Не начинается с цифры."""

        pattern = VariableParser.PATTERN_DOUBLE_BRACES
        assert pattern.findall("{{123var}}") == []  # Invalid variable name
