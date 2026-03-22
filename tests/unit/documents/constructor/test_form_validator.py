"""Тесты для модуля form_validator.

Покрытие:
- Severity Enum
- ValidationResult dataclass
- FormValidator.validate_field (уровень 1)
- FormValidator.validate_form (уровень 2)
- FormValidator.validate_cross_fields (уровень 3)
- Вспомогательные функции
"""

from datetime import date, datetime
from typing import Any, Dict

import pytest
from src.documents.constructor.form_validator import (
    FormValidator,
    Severity,
    ValidationError,
    ValidationResult,
    _evaluate_cross_field_rule,
    _evaluate_required_if,
    _safe_parse_date,
    _safe_parse_number,
)
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema
from src.model.document import Document

# ============ Severity Enum Tests ============


class TestSeverity:
    """Тесты для Severity Enum."""

    def test_severity_values(self) -> None:
        """Проверка значений Severity."""
        assert Severity.ERROR.value == "error"
        assert Severity.WARNING.value == "warning"
        assert Severity.INFO.value == "info"

    def test_severity_comparison(self) -> None:
        """Проверка сравнения Severity."""
        assert Severity.ERROR != Severity.WARNING  # type: ignore[comparison-overlap]
        assert Severity.WARNING != Severity.INFO  # type: ignore[comparison-overlap]
        assert Severity.ERROR == Severity.ERROR


# ============ ValidationResult Tests ============


class TestValidationResult:
    """Тесты для ValidationResult dataclass."""

    def test_create_validation_result(self) -> None:
        """Создание ValidationResult с базовыми параметрами."""
        result = ValidationResult(
            field_id="test_field",
            severity=Severity.ERROR,
            code="test_code",
            message="Test message",
        )
        assert result.field_id == "test_field"
        assert result.severity == Severity.ERROR
        assert result.code == "test_code"
        assert result.message == "Test message"

    def test_create_validation_result_no_field(self) -> None:
        """Создание ValidationResult без field_id (для ошибок уровня формы)."""
        result = ValidationResult(
            field_id=None,
            severity=Severity.ERROR,
            code="form_error",
            message="Form level error",
        )
        assert result.field_id is None
        assert result.severity == Severity.ERROR

    def test_validation_result_immutable(self) -> None:
        """Проверка неизменяемости ValidationResult (frozen dataclass)."""
        result = ValidationResult(
            field_id="test",
            severity=Severity.ERROR,
            code="code",
            message="message",
        )
        with pytest.raises(AttributeError):
            result.field_id = "new_id"  # type: ignore


# ============ Helper Functions Tests ============


class TestSafeParseDate:
    """Тесты для _safe_parse_date."""

    def test_parse_date_object(self) -> None:
        """Парсинг объекта date."""
        d = date(2026, 3, 22)
        assert _safe_parse_date(d) == d

    def test_parse_datetime_object(self) -> None:
        """Парсинг объекта datetime."""
        dt = datetime(2026, 3, 22, 10, 30)
        assert _safe_parse_date(dt) == date(2026, 3, 22)

    def test_parse_iso_string(self) -> None:
        """Парсинг строки в формате ISO."""
        assert _safe_parse_date("2026-03-22") == date(2026, 3, 22)

    def test_parse_european_string(self) -> None:
        """Парсинг строки в европейском формате."""
        assert _safe_parse_date("22.03.2026") == date(2026, 3, 22)

    def test_parse_invalid_string(self) -> None:
        """Парсинг невалидной строки."""
        assert _safe_parse_date("not a date") is None

    def test_parse_none(self) -> None:
        """Парсинг None."""
        assert _safe_parse_date(None) is None


class TestSafeParseNumber:
    """Тесты для _safe_parse_number."""

    def test_parse_int(self) -> None:
        """Парсинг целого числа."""
        assert _safe_parse_number(42) == 42.0

    def test_parse_float(self) -> None:
        """Парсинг float."""
        assert _safe_parse_number(3.14) == 3.14

    def test_parse_string_number(self) -> None:
        """Парсинг строки с числом."""
        assert _safe_parse_number("123.45") == 123.45

    def test_parse_string_with_comma(self) -> None:
        """Парсинг строки с запятой вместо точки."""
        assert _safe_parse_number("123,45") == 123.45

    def test_parse_string_with_spaces(self) -> None:
        """Парсинг строки с пробелами."""
        assert _safe_parse_number("1 000.50") == 1000.5

    def test_parse_invalid_string(self) -> None:
        """Парсинг невалидной строки."""
        assert _safe_parse_number("not a number") is None


class TestEvaluateRequiredIf:
    """Тесты для _evaluate_required_if."""

    def test_equal_condition_true(self) -> None:
        """Условие равенства выполнено."""
        ctx: Dict[str, Any] = {"type": "invoice"}
        assert _evaluate_required_if("type == 'invoice'", ctx) is True

    def test_equal_condition_false(self) -> None:
        """Условие равенства не выполнено."""
        ctx: Dict[str, Any] = {"type": "receipt"}
        assert _evaluate_required_if("type == 'invoice'", ctx) is False

    def test_not_equal_condition_true(self) -> None:
        """Условие неравенства выполнено."""
        ctx: Dict[str, Any] = {"type": "receipt"}
        assert _evaluate_required_if("type != 'invoice'", ctx) is True

    def test_in_condition_true(self) -> None:
        """Условие 'in' выполнено."""
        ctx: Dict[str, Any] = {"status": "active"}
        assert _evaluate_required_if("status in ('active', 'pending')", ctx) is True

    def test_in_condition_false(self) -> None:
        """Условие 'in' не выполнено."""
        ctx: Dict[str, Any] = {"status": "deleted"}
        assert _evaluate_required_if("status in ('active', 'pending')", ctx) is False

    def test_empty_condition(self) -> None:
        """Пустое условие."""
        assert _evaluate_required_if("", {}) is False


class TestEvaluateCrossFieldRule:
    """Тесты для _evaluate_cross_field_rule."""

    def test_greater_than_true(self) -> None:
        """Правило 'больше' выполнено."""
        ctx: Dict[str, Any] = {"start": 10, "end": 20}
        is_valid, msg = _evaluate_cross_field_rule("end > start", ctx)
        assert is_valid is True
        assert msg == ""

    def test_greater_than_false(self) -> None:
        """Правило 'больше' не выполнено."""
        ctx: Dict[str, Any] = {"start": 20, "end": 10}
        is_valid, msg = _evaluate_cross_field_rule("end > start", ctx)
        assert is_valid is False
        assert "должно быть больше" in msg

    def test_less_than_true(self) -> None:
        """Правило 'меньше' выполнено."""
        ctx: Dict[str, Any] = {"min": 5, "max": 10}
        is_valid, msg = _evaluate_cross_field_rule("min < max", ctx)
        assert is_valid is True

    def test_less_than_false(self) -> None:
        """Правило 'меньше' не выполнено."""
        ctx: Dict[str, Any] = {"min": 15, "max": 10}
        is_valid, msg = _evaluate_cross_field_rule("min < max", ctx)
        assert is_valid is False


# ============ FormValidator Tests ============


class TestFormValidatorInit:
    """Тесты инициализации FormValidator."""

    def test_create_default(self) -> None:
        """Создание валидатора с настройками по умолчанию."""
        validator = FormValidator()
        assert validator.strict_mode is False

    def test_create_strict_mode(self) -> None:
        """Создание валидатора в strict режиме."""
        validator = FormValidator(strict_mode=True)
        assert validator.strict_mode is True


class TestValidateField:
    """Тесты validate_field (Уровень 1)."""

    @pytest.fixture
    def validator(self) -> FormValidator:
        """Фикстура валидатора."""
        return FormValidator()

    def test_required_field_empty(self, validator: FormValidator) -> None:
        """Обязательное поле пустое — ошибка."""
        field_def = FieldDefinition(
            field_id="name",
            field_type=FieldType.TEXT_INPUT,
            label="Имя",
            required=True,
        )
        results = validator.validate_field("name", "", field_def)
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR
        assert results[0].code == "required_field_empty"

    def test_required_field_none(self, validator: FormValidator) -> None:
        """Обязательное поле None — ошибка."""
        field_def = FieldDefinition(
            field_id="name",
            field_type=FieldType.TEXT_INPUT,
            label="Имя",
            required=True,
        )
        results = validator.validate_field("name", None, field_def)
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR

    def test_optional_field_empty(self, validator: FormValidator) -> None:
        """Необязательное поле пустое — OK."""
        field_def = FieldDefinition(
            field_id="name",
            field_type=FieldType.TEXT_INPUT,
            label="Имя",
            required=False,
        )
        results = validator.validate_field("name", "", field_def)
        assert len(results) == 0

    def test_required_field_with_value(self, validator: FormValidator) -> None:
        """Обязательное поле с значением — OK."""
        field_def = FieldDefinition(
            field_id="name",
            field_type=FieldType.TEXT_INPUT,
            label="Имя",
            required=True,
        )
        results = validator.validate_field("name", "John", field_def)
        assert len(results) == 0

    def test_number_min_value_violation(self, validator: FormValidator) -> None:
        """Число меньше минимума — ошибка."""
        field_def = FieldDefinition(
            field_id="amount",
            field_type=FieldType.NUMBER_INPUT,
            label="Сумма",
            required=True,
            min_value=0.01,
        )
        results = validator.validate_field("amount", "0", field_def)
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR
        assert results[0].code == "value_below_minimum"

    def test_number_max_value_violation(self, validator: FormValidator) -> None:
        """Число больше максимума — ошибка."""
        field_def = FieldDefinition(
            field_id="amount",
            field_type=FieldType.NUMBER_INPUT,
            label="Сумма",
            required=True,
            max_value=1000,
        )
        results = validator.validate_field("amount", "1500", field_def)
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR
        assert results[0].code == "value_above_maximum"

    def test_number_valid_range(self, validator: FormValidator) -> None:
        """Число в допустимом диапазоне — OK."""
        field_def = FieldDefinition(
            field_id="amount",
            field_type=FieldType.NUMBER_INPUT,
            label="Сумма",
            required=True,
            min_value=0.01,
            max_value=1000,
        )
        results = validator.validate_field("amount", "500", field_def)
        assert len(results) == 0

    def test_number_invalid_format(self, validator: FormValidator) -> None:
        """Некорректный формат числа — ошибка."""
        field_def = FieldDefinition(
            field_id="amount",
            field_type=FieldType.NUMBER_INPUT,
            label="Сумма",
            required=True,
        )
        results = validator.validate_field("amount", "not a number", field_def)
        assert len(results) == 1
        assert results[0].code == "invalid_number_format"

    def test_date_min_date_violation(self, validator: FormValidator) -> None:
        """Дата раньше минимальной — ошибка."""
        field_def = FieldDefinition(
            field_id="start_date",
            field_type=FieldType.DATE_INPUT,
            label="Дата начала",
            required=True,
            min_date=date(2026, 1, 1),
        )
        results = validator.validate_field("start_date", "2025-12-31", field_def)
        assert len(results) == 1
        assert results[0].code == "date_before_minimum"

    def test_date_max_date_violation(self, validator: FormValidator) -> None:
        """Дата позже максимальной — ошибка."""
        field_def = FieldDefinition(
            field_id="end_date",
            field_type=FieldType.DATE_INPUT,
            label="Дата окончания",
            required=True,
            max_date=date(2026, 12, 31),
        )
        results = validator.validate_field("end_date", "2027-01-01", field_def)
        assert len(results) == 1
        assert results[0].code == "date_after_maximum"

    def test_date_valid_range(self, validator: FormValidator) -> None:
        """Дата в допустимом диапазоне — OK."""
        field_def = FieldDefinition(
            field_id="date",
            field_type=FieldType.DATE_INPUT,
            label="Дата",
            required=True,
            min_date=date(2026, 1, 1),
            max_date=date(2026, 12, 31),
        )
        results = validator.validate_field("date", "2026-06-15", field_def)
        assert len(results) == 0

    def test_pattern_mismatch(self, validator: FormValidator) -> None:
        """Несоответствие шаблону — ошибка."""
        field_def = FieldDefinition(
            field_id="code",
            field_type=FieldType.TEXT_INPUT,
            label="Код",
            required=True,
            validation_pattern=r"^[A-Z]{3}-\d{4}$",
        )
        results = validator.validate_field("code", "invalid", field_def)
        assert len(results) == 1
        assert results[0].code == "pattern_mismatch"

    def test_pattern_match(self, validator: FormValidator) -> None:
        """Соответствие шаблону — OK."""
        field_def = FieldDefinition(
            field_id="code",
            field_type=FieldType.TEXT_INPUT,
            label="Код",
            required=True,
            validation_pattern=r"^[A-Z]{3}-\d{4}$",
        )
        results = validator.validate_field("code", "ABC-1234", field_def)
        assert len(results) == 0

    def test_max_length_exceeded(self, validator: FormValidator) -> None:
        """Превышение максимальной длины — ошибка."""
        field_def = FieldDefinition(
            field_id="name",
            field_type=FieldType.TEXT_INPUT,
            label="Имя",
            required=True,
            max_length=10,
        )
        results = validator.validate_field("name", "This is a very long name", field_def)
        assert len(results) == 1
        assert results[0].code == "max_length_exceeded"

    def test_max_length_ok(self, validator: FormValidator) -> None:
        """Длина в пределах — OK."""
        field_def = FieldDefinition(
            field_id="name",
            field_type=FieldType.TEXT_INPUT,
            label="Имя",
            required=True,
            max_length=10,
        )
        results = validator.validate_field("name", "Short", field_def)
        assert len(results) == 0

    def test_options_invalid(self, validator: FormValidator) -> None:
        """Значение не в списке options — ошибка."""
        field_def = FieldDefinition(
            field_id="status",
            field_type=FieldType.DROPDOWN,
            label="Статус",
            required=True,
            options=("active", "pending", "completed"),
        )
        results = validator.validate_field("status", "deleted", field_def)
        assert len(results) == 1
        assert results[0].code == "invalid_option"

    def test_options_valid(self, validator: FormValidator) -> None:
        """Значение в списке options — OK."""
        field_def = FieldDefinition(
            field_id="status",
            field_type=FieldType.DROPDOWN,
            label="Статус",
            required=True,
            options=("active", "pending", "completed"),
        )
        results = validator.validate_field("status", "active", field_def)
        assert len(results) == 0

    def test_required_if_condition_met(self, validator: FormValidator) -> None:
        """Условная обязательность: условие выполнено, поле пустое — ошибка."""
        field_def = FieldDefinition(
            field_id="invoice_number",
            field_type=FieldType.TEXT_INPUT,
            label="Номер счёта",
            required=False,
            required_if="type == 'invoice'",
        )
        context: Dict[str, Any] = {"type": "invoice"}
        results = validator.validate_field("invoice_number", "", field_def, context)
        assert len(results) == 1
        assert results[0].code == "conditional_required_field_empty"

    def test_required_if_condition_not_met(self, validator: FormValidator) -> None:
        """Условная обязательность: условие не выполнено, поле пустое — OK."""
        field_def = FieldDefinition(
            field_id="invoice_number",
            field_type=FieldType.TEXT_INPUT,
            label="Номер счёта",
            required=False,
            required_if="type == 'invoice'",
        )
        context: Dict[str, Any] = {"type": "receipt"}
        results = validator.validate_field("invoice_number", "", field_def, context)
        assert len(results) == 0

    def test_email_invalid(self, validator: FormValidator) -> None:
        """Некорректный email — ошибка."""
        field_def = FieldDefinition(
            field_id="email",
            field_type=FieldType.EMAIL,
            label="Email",
            required=True,
        )
        results = validator.validate_field("email", "not-an-email", field_def)
        assert len(results) == 1
        assert results[0].code == "invalid_email_format"

    def test_email_valid(self, validator: FormValidator) -> None:
        """Корректный email — OK."""
        field_def = FieldDefinition(
            field_id="email",
            field_type=FieldType.EMAIL,
            label="Email",
            required=True,
        )
        results = validator.validate_field("email", "user@example.com", field_def)
        assert len(results) == 0

    def test_phone_invalid(self, validator: FormValidator) -> None:
        """Некорректный телефон — ошибка."""
        field_def = FieldDefinition(
            field_id="phone",
            field_type=FieldType.PHONE,
            label="Телефон",
            required=True,
        )
        results = validator.validate_field("phone", "123", field_def)
        assert len(results) == 1
        assert results[0].code == "invalid_phone_format"

    def test_phone_valid(self, validator: FormValidator) -> None:
        """Корректный телефон — OK."""
        field_def = FieldDefinition(
            field_id="phone",
            field_type=FieldType.PHONE,
            label="Телефон",
            required=True,
        )
        results = validator.validate_field("phone", "+7 (495) 123-45-67", field_def)
        assert len(results) == 0


class TestValidateForm:
    """Тесты validate_form (Уровень 2)."""

    @pytest.fixture
    def validator(self) -> FormValidator:
        """Фикстура валидатора."""
        return FormValidator()

    @pytest.fixture
    def sample_schema(self) -> TypeSchema:
        """Фикстура схемы для тестов."""
        return TypeSchema(
            fields=(
                FieldDefinition(
                    field_id="name",
                    field_type=FieldType.TEXT_INPUT,
                    label="Имя",
                    required=True,
                    max_length=50,
                ),
                FieldDefinition(
                    field_id="amount",
                    field_type=FieldType.NUMBER_INPUT,
                    label="Сумма",
                    required=True,
                    min_value=0.01,
                ),
                FieldDefinition(
                    field_id="email",
                    field_type=FieldType.EMAIL,
                    label="Email",
                    required=False,
                ),
            )
        )

    def test_valid_form(self, validator: FormValidator, sample_schema: TypeSchema) -> None:
        """Валидная форма — нет ошибок."""
        doc = Document()
        values: Dict[str, Any] = {
            "name": "John Doe",
            "amount": "100.50",
            "email": "john@example.com",
        }
        results = validator.validate_form(doc, sample_schema, values)
        assert len(results) == 0

    def test_invalid_form_multiple_errors(
        self, validator: FormValidator, sample_schema: TypeSchema
    ) -> None:
        """Невалидная форма с несколькими ошибками."""
        doc = Document()
        values: Dict[str, Any] = {
            "name": "",  # Пустое обязательное
            "amount": "-10",  # Отрицательное
            "email": "invalid",  # Некорректный email
        }
        results = validator.validate_form(doc, sample_schema, values)
        assert len(results) == 3
        assert any(r.field_id == "name" for r in results)
        assert any(r.field_id == "amount" for r in results)
        assert any(r.field_id == "email" for r in results)

    def test_partial_form(self, validator: FormValidator, sample_schema: TypeSchema) -> None:
        """Частично заполненная форма."""
        doc = Document()
        values: Dict[str, Any] = {
            "name": "John",
            "amount": "100",
            # email отсутствует, но он необязательный
        }
        results = validator.validate_form(doc, sample_schema, values)
        assert len(results) == 0


class TestValidateCrossFields:
    """Тесты validate_cross_fields (Уровень 3)."""

    @pytest.fixture
    def validator(self) -> FormValidator:
        """Фикстура валидатора."""
        return FormValidator()

    def test_cross_field_greater_than_valid(self, validator: FormValidator) -> None:
        """Кросс-полевое правило 'больше' выполнено."""
        schema = TypeSchema(
            fields=(
                FieldDefinition(
                    field_id="start",
                    field_type=FieldType.NUMBER_INPUT,
                    label="Начало",
                    required=True,
                ),
                FieldDefinition(
                    field_id="end",
                    field_type=FieldType.NUMBER_INPUT,
                    label="Окончание",
                    required=True,
                    cross_field_rules=("end > start",),
                ),
            )
        )
        doc = Document()
        values: Dict[str, Any] = {"start": 10, "end": 20}
        results = validator.validate_cross_fields(doc, schema, values)
        assert len(results) == 0

    def test_cross_field_greater_than_invalid(self, validator: FormValidator) -> None:
        """Кросс-полевое правило 'больше' не выполнено."""
        schema = TypeSchema(
            fields=(
                FieldDefinition(
                    field_id="start",
                    field_type=FieldType.NUMBER_INPUT,
                    label="Начало",
                    required=True,
                ),
                FieldDefinition(
                    field_id="end",
                    field_type=FieldType.NUMBER_INPUT,
                    label="Окончание",
                    required=True,
                    cross_field_rules=("end > start",),
                ),
            )
        )
        doc = Document()
        values: Dict[str, Any] = {"start": 20, "end": 10}
        results = validator.validate_cross_fields(doc, schema, values)
        assert len(results) == 1
        assert results[0].severity == Severity.ERROR
        assert results[0].code == "cross_field_rule_violation"


class TestValidateAll:
    """Тесты validate_all (все уровни)."""

    @pytest.fixture
    def validator(self) -> FormValidator:
        """Фикстура валидатора."""
        return FormValidator()

    def test_full_validation(self, validator: FormValidator) -> None:
        """Полная валидация всех уровней."""
        schema = TypeSchema(
            fields=(
                FieldDefinition(
                    field_id="name",
                    field_type=FieldType.TEXT_INPUT,
                    label="Имя",
                    required=True,
                ),
                FieldDefinition(
                    field_id="end",
                    field_type=FieldType.NUMBER_INPUT,
                    label="Окончание",
                    required=True,
                    cross_field_rules=("end > start",),
                ),
            )
        )
        doc = Document()
        values: Dict[str, Any] = {"name": "", "start": 20, "end": 10}
        results = validator.validate_all(doc, schema, values)
        # Должны быть ошибки с обоих уровней
        assert len(results) >= 2


class TestValidationError:
    """Тесты ValidationError исключения."""

    def test_validation_error_message(self) -> None:
        """Сообщение исключения содержит описания ошибок."""
        results = [
            ValidationResult(
                field_id="name",
                severity=Severity.ERROR,
                code="required",
                message="Имя обязательно",
            ),
            ValidationResult(
                field_id="amount",
                severity=Severity.ERROR,
                code="invalid",
                message="Некорректная сумма",
            ),
        ]
        error = ValidationError(results)
        assert "name: Имя обязательно" in str(error)
        assert "amount: Некорректная сумма" in str(error)

    def test_validation_error_results(self) -> None:
        """Исключение хранит результаты валидации."""
        results = [
            ValidationResult(
                field_id="name",
                severity=Severity.ERROR,
                code="required",
                message="Имя обязательно",
            ),
        ]
        error = ValidationError(results)
        assert error.results == results


class TestHelperMethods:
    """Тесты вспомогательных методов FormValidator."""

    @pytest.fixture
    def validator(self) -> FormValidator:
        """Фикстура валидатора."""
        return FormValidator()

    def test_has_errors_true(self, validator: FormValidator) -> None:
        """has_errors возвращает True при наличии ERROR."""
        results = [
            ValidationResult("field1", Severity.ERROR, "code1", "msg1"),
            ValidationResult("field2", Severity.WARNING, "code2", "msg2"),
        ]
        assert validator.has_errors(results) is True

    def test_has_errors_false(self, validator: FormValidator) -> None:
        """has_errors возвращает False если нет ERROR."""
        results = [
            ValidationResult("field1", Severity.WARNING, "code1", "msg1"),
            ValidationResult("field2", Severity.INFO, "code2", "msg2"),
        ]
        assert validator.has_errors(results) is False

    def test_has_errors_strict_mode(self) -> None:
        """has_errors в strict_mode считает WARNING как ERROR."""
        validator = FormValidator(strict_mode=True)
        results = [
            ValidationResult("field1", Severity.WARNING, "code1", "msg1"),
        ]
        assert validator.has_errors(results) is True

    def test_get_errors(self, validator: FormValidator) -> None:
        """get_errors возвращает только ERROR."""
        results = [
            ValidationResult("field1", Severity.ERROR, "code1", "msg1"),
            ValidationResult("field2", Severity.WARNING, "code2", "msg2"),
            ValidationResult("field3", Severity.ERROR, "code3", "msg3"),
        ]
        errors = validator.get_errors(results)
        assert len(errors) == 2
        assert all(r.severity == Severity.ERROR for r in errors)

    def test_get_warnings(self, validator: FormValidator) -> None:
        """get_warnings возвращает только WARNING."""
        results = [
            ValidationResult("field1", Severity.ERROR, "code1", "msg1"),
            ValidationResult("field2", Severity.WARNING, "code2", "msg2"),
            ValidationResult("field3", Severity.INFO, "code3", "msg3"),
        ]
        warnings = validator.get_warnings(results)
        assert len(warnings) == 1
        assert warnings[0].severity == Severity.WARNING


# ============ Parametrized Tests ============


@pytest.mark.parametrize(
    "value,field_type,expected_errors",
    [
        ("test", FieldType.TEXT_INPUT, 0),
        ("", FieldType.TEXT_INPUT, 0),  # Необязательное
        ("abc", FieldType.NUMBER_INPUT, 1),  # Не число
        ("100", FieldType.NUMBER_INPUT, 0),
        ("user@example.com", FieldType.EMAIL, 0),
        ("invalid", FieldType.EMAIL, 1),
    ],
)
def test_field_type_validation(value: str, field_type: FieldType, expected_errors: int) -> None:
    """Параметризованный тест валидации по типам полей."""
    validator = FormValidator()
    field_def = FieldDefinition(
        field_id="test",
        field_type=field_type,
        label="Test",
        required=False,
    )
    results = validator.validate_field("test", value, field_def)
    assert len(results) == expected_errors


@pytest.mark.parametrize(
    "condition,context,expected",
    [
        ("type == 'invoice'", {"type": "invoice"}, True),
        ("type == 'invoice'", {"type": "receipt"}, False),
        ("status != 'deleted'", {"status": "active"}, True),
        ("status != 'deleted'", {"status": "deleted"}, False),
        ("type in ('a', 'b')", {"type": "a"}, True),
        ("type in ('a', 'b')", {"type": "c"}, False),
    ],
)
def test_required_if_parametrized(condition: str, context: Dict[str, Any], expected: bool) -> None:
    """Параметризованный тест required_if условий."""
    assert _evaluate_required_if(condition, context) == expected
