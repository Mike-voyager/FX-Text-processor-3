from typing import Any, Optional

import pytest

from src.form.form_schema import (
    FORM_SCHEMA_DEFAULT,
    FormSchema,
    SchemaError,
    ValidationError,
    form_schema_from_registry,
)


def valid_form() -> dict[str, Any]:
    return {
        "kind": "regular",
        "layout_type": "grid",
        "elements": [
            {"type": "label", "id": "el1", "label": "Name", "style": {}},
            {
                "type": "input",
                "id": "el2",
                "label": "Value",
                "style": {},
                "placeholder": "Enter...",
            },
        ],
        "groups": [
            {
                "name": "main",
                "element_ids": ["el1", "el2"],
                "permissions": ["user"],
                "security_level": "standard",
            }
        ],
    }


def special_form() -> dict[str, Any]:
    return {
        "kind": "special",
        "layout_type": "grid",
        "elements": [
            {"type": "stamp", "id": "st1", "border_text": "Org", "qr_data": "data"},
            {
                "type": "qr",
                "id": "qr1",
                "data": "payload",
                "size": 10,
                "error_correction": "M",
            },
            {"type": "watermark", "id": "wm1", "text": "Protected", "opacity": 0.2},
            {
                "type": "signature",
                "id": "sig1",
                "algorithm": "ed25519",
                "key_id": "key1",
            },
        ],
        "groups": [],
    }


def test_valid_form_success() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    assert schema.validate_form(valid_form())


def test_valid_form_missing_keys() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    del bad["layout_type"]
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Missing required form keys" in str(exc.value)


def test_element_type_unknown() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    bad["elements"][0]["type"] = "unknown"
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Unknown element type" in str(exc.value)


def test_element_missing_required_field() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    del bad["elements"][0]["label"]
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "missing required fields" in str(exc.value)


def test_element_unknown_field() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    bad["elements"][0]["unknown_field"] = 123
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Unknown element field" in str(exc.value)


def test_group_missing_field() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    del bad["groups"][0]["permissions"]
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Group missing field" in str(exc.value)


def test_duplicate_element_ids() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    bad["elements"].append({"type": "input", "id": "el1", "label": "Duplicated"})
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Duplicate element id" in str(exc.value)


def test_alias_target_check() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    bad["elements"].append({"type": "alias", "id": "al1", "alias_of": "no_such_id"})
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Alias target id" in str(exc.value)


def test_group_reference_missing_id() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    bad["elements"].append({"type": "label", "id": "extra"})
    bad["elements"].append(
        {
            "type": "group",
            "id": "g1",
            "elements": ["el1", "missing_id"],
            "group_kind": "default",
        }
    )
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Group references missing id" in str(exc.value)


def test_check_nesting_depth() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    form = valid_form()
    deep = {}  # type: dict[str, Any]
    cur = deep
    for i in range(52):
        cur["a"] = {}
        cur = cur["a"]
    form["elements"][0]["deep"] = deep
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(form)
    assert "Nesting depth" in str(exc.value)


def test_describe_schema() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    desc = schema.describe(include_i18n=True)
    assert desc["version"] == "1.1"
    assert "element_types" in desc
    assert "i18n" in desc


def test_compliance_regular_pass() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    f = valid_form()
    assert schema.is_compliant(f, "regular")


def test_compliance_special_missing() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    f = dict(special_form())
    f["elements"] = f["elements"][:-1]  # remove signature
    with pytest.raises(ValidationError) as exc:
        schema.is_compliant(f, "special")
    assert "compliant" in str(exc.value) or "predicate" in str(exc.value)


def test_compliance_special_ok() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    f = special_form()
    assert schema.is_compliant(f, "special")


def test_dynamic_element_type_register() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    schema.register_element_type(
        "custom", {"fields": ["id", "custom"], "required": ["custom"]}
    )
    types = schema.list_supported_element_types()
    assert "custom" in types
    schema.unregister_element_type("custom")
    types2 = schema.list_supported_element_types()
    assert "custom" not in types2


def test_register_field_validator() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    called = []

    def v(val: Any) -> Optional[str]:
        if val != "ok":
            return "fail"
        called.append(val)
        return None

    schema.register_field_validator("input", "placeholder", v)
    bad = dict(valid_form())
    bad["elements"][1]["placeholder"] = "bad"
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Custom validation failed" in str(exc.value)
    bad["elements"][1]["placeholder"] = "ok"
    # Should not raise
    assert schema.validate_form(bad)
    assert called == ["ok"]


def test_form_schema_from_registry() -> None:
    class DummyField:
        default = None

    class Dummy:
        __doc__ = "dummy doc"
        __dataclass_fields__ = {"id": DummyField(), "val": DummyField()}

    class DummyReg:
        def all_types(self) -> list[str]:
            return ["dummy"]

        def get(self, key: str) -> Any:
            return Dummy

    schema = form_schema_from_registry(DummyReg())
    assert "dummy" in schema.list_supported_element_types()


def test_group_duplicate_name() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    bad["groups"].append(
        {
            "name": "main",  # дубликат имени группы
            "element_ids": ["el1"],
            "permissions": ["user"],
            "security_level": "standard",
        }
    )
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Duplicate group id (name)" in str(exc.value)


def test_register_and_unregister_element_type_runtime() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    # Добавим новый тип, затем удалим
    new_type = "mycustom"
    schema.register_element_type(
        new_type, {"fields": ["id", "custom", "extra"], "required": ["custom"]}
    )
    # Проверка добавления
    assert new_type in schema.list_supported_element_types()
    # Проверим, что схема работает с новым типом
    valid = dict(valid_form())
    valid["elements"].append({"type": new_type, "id": "mc1", "custom": "X"})
    assert schema.validate_form(valid)
    # Удалим тип
    schema.unregister_element_type(new_type)
    assert new_type not in schema.list_supported_element_types()


def test_schema_describe_without_i18n() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    desc = schema.describe()
    # Проверка, что поле i18n у элементов исчезает
    for element_schema in desc["element_types"].values():
        assert "i18n" not in element_schema


def test_field_validator_multiple() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    called = []

    def v1(val: Any) -> Optional[str]:
        if val == "X":
            called.append("v1")
        return None

    def v2(val: Any) -> Optional[str]:
        if val not in ["ok", "X"]:
            return "fail"
        called.append("v2")
        return None

    schema.register_field_validator("input", "placeholder", v1)
    schema.register_field_validator("input", "placeholder", v2)
    bad = dict(valid_form())
    bad["elements"][1]["placeholder"] = "bad"
    with pytest.raises(ValidationError):
        schema.validate_form(bad)
    bad["elements"][1]["placeholder"] = "ok"
    assert schema.validate_form(bad)
    bad["elements"][1]["placeholder"] = "X"
    assert schema.validate_form(bad)
    assert "v1" in called and "v2" in called


def test_compliance_regular_missing_type() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    form = dict(valid_form())
    # remove one element type
    form["elements"] = form["elements"][1:]
    assert schema.is_compliant(form, "regular")


def test_unregistered_element_type_error() -> None:
    schema = FormSchema(FORM_SCHEMA_DEFAULT)
    bad = dict(valid_form())
    bad["elements"].append({"type": "superhidden", "id": "z99"})
    with pytest.raises(ValidationError) as exc:
        schema.validate_form(bad)
    assert "Unknown element type" in str(exc.value)
