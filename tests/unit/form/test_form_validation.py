import pytest
from typing import Any, Dict, Optional
from src.form.validation import (
    FormValidator,
    ValidationError,
    ValidationResult,
    Validator,
    min_length,
    max_length,
    greater_than,
    required,
)


def test_basic_valid_pass() -> None:
    schema: dict[str, list[str | Validator]] = {
        "name": ["string", required],
        "age": ["int", required],
    }
    validator = FormValidator(schema)
    res = validator.validate({"name": "ivan", "age": 10})
    assert res.ok


def test_basic_valid_fail() -> None:
    schema: dict[str, list[str | Validator]] = {
        "name": ["string", required],
        "age": ["int", required],
    }
    validator = FormValidator(schema)
    res = validator.validate({"name": "", "age": "ten"})
    assert not res.ok
    assert any(e.field == "name" for e in res.errors)
    assert any(e.field == "age" for e in res.errors)


def test_min_max_length() -> None:
    schema: dict[str, list[str | Validator]] = {"v": ["string", min_length(2), max_length(3)]}
    validator = FormValidator(schema)
    bad = validator.validate({"v": "A"})
    assert not bad.ok and "length" in bad.errors[0].args[0]
    bad2 = validator.validate({"v": "AAAA"})
    assert not bad2.ok
    good = validator.validate({"v": "AB"})
    assert good.ok


def test_required_empty_string() -> None:
    schema: dict[str, list[str | Validator]] = {"x": [required]}
    validator = FormValidator(schema)
    res = validator.validate({"x": ""})
    assert not res.ok


def test_required_none() -> None:
    schema: dict[str, list[str | Validator]] = {"x": [required]}
    validator = FormValidator(schema)
    res = validator.validate({"x": None})
    assert not res.ok


def test_extra_fields() -> None:
    schema: dict[str, list[str | Validator]] = {"a": ["string"]}
    validator = FormValidator(schema, allow_extra=False)
    res = validator.validate({"a": "1", "b": 2})
    assert not res.ok and any("Extra field" in str(e) for e in res.errors)


def test_greater_than_success_fail() -> None:
    schema: dict[str, list[str | Validator]] = {"x": ["int"], "y": ["int", greater_than("x")]}
    validator = FormValidator(schema)
    ok = validator.validate({"x": 1, "y": 2})
    fail = validator.validate({"x": 3, "y": 2})
    assert ok.ok
    assert not fail.ok and "Must be greater than" in fail.errors[0].args[0]


def test_custom_validator() -> None:
    def even(value: Any, context: Dict[str, Any]) -> Optional[str]:
        return None if value % 2 == 0 else "not even"

    schema: dict[str, list[str | Validator]] = {"n": ["int", even]}
    validator = FormValidator(schema)
    assert validator.validate({"n": 4}).ok
    assert not validator.validate({"n": 3}).ok


def test_stop_on_error() -> None:
    called: list[bool] = []

    def fail(value: Any, context: Dict[str, Any]) -> str:
        called.append(True)
        return "fail"

    schema: dict[str, list[str | Validator]] = {"a": [fail, fail, fail]}
    validator = FormValidator(schema, stop_on_error=True)
    res = validator.validate({"a": 1})
    assert len(called) == 1
    assert not res.ok


def test_validation_result_methods() -> None:
    v = ValidationResult()
    assert v.ok
    v.add(ValidationError("some error", "f"))
    assert not v.ok
    assert isinstance(v.errors[0], ValidationError)


def test_edge_types() -> None:
    schema: dict[str, list[str | Validator]] = {}
    validator = FormValidator(schema)
    assert validator.validate({}).ok
    assert validator.validate({"x": 1}).ok


def test_cross_context_injection() -> None:
    def match_other(value: Any, context: Dict[str, Any]) -> Optional[str]:
        return None if value == context.get("target") else "no match"

    schema: dict[str, list[str | Validator]] = {"x": [match_other]}
    validator = FormValidator(schema)
    assert validator.validate({"x": 5}, context={"target": 5}).ok
    assert not validator.validate({"x": 2}, context={"target": 5}).ok


def test_repr_and_str_error() -> None:
    e = ValidationError("fail", "f")
    assert "fail" in str(e)
    assert hasattr(e, "field")
