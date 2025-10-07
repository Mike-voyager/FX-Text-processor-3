import pytest
from dataclasses import dataclass
from src.form.form_elements import (
    BaseFormElement,
    AliasFormElement,
    GroupFormElement,
    ExtensionFormElement,
    element_from_dict,
    FormElementRegistry,
    element_class,
)


def test_baseelement_validate_ok() -> None:
    el = BaseFormElement(type="custom", id="simple1")
    el.validate()
    d = el.as_dict()
    assert d["type"] == "custom"


def test_baseelement_validate_bad_type() -> None:
    el = BaseFormElement(type="")
    with pytest.raises(ValueError):
        el.validate()
    el2 = BaseFormElement(type="   ")
    with pytest.raises(ValueError):
        el2.validate()
    with pytest.raises(Exception):
        el3 = element_from_dict({"type": None})
        el3.validate()


def test_baseelement_validate_bad_id() -> None:
    el = BaseFormElement(type="base", id="bad_id!")
    with pytest.raises(ValueError):
        el.validate()
    el2 = BaseFormElement(type="base", id="ID-123_ok")
    el2.validate()


def test_alias_validate_ok() -> None:
    # Создаём правильный тип с правильными параметрами
    el = element_from_dict({"type": "alias", "id": "a1", "alias_of": "target"})
    el.validate()
    assert el.kind.value == "alias"


def test_alias_validate_bad() -> None:
    el = element_from_dict({"type": "alias", "alias_of": ""})
    with pytest.raises(ValueError):
        el.validate()
    el2 = element_from_dict({"type": "alias", "alias_of": None})
    with pytest.raises(Exception):
        el2.validate()


def test_group_validate_ok() -> None:
    el = element_from_dict({"type": "group", "elements": ["id1", "id2"]})
    el.validate()
    if isinstance(el, GroupFormElement):
        assert isinstance(el.elements, list)  # type: ignore[attr-defined]
    assert el.kind.value == "group"


def test_group_validate_empty_or_bad() -> None:
    el = element_from_dict({"type": "group", "elements": []})
    with pytest.raises(ValueError):
        el.validate()
    el2 = element_from_dict({"type": "group", "elements": [123]})
    with pytest.raises(ValueError):
        el2.validate()
    el3 = element_from_dict({"type": "group", "elements": None})
    with pytest.raises(Exception):
        el3.validate()


def test_extension_validate_ok() -> None:
    # Создаём правильный тип с правильными параметрами
    el = element_from_dict({"type": "extension", "extra": {"foo": "bar"}})
    el.validate()


def test_extension_validate_bad_extra() -> None:
    el = element_from_dict({"type": "extension", "extra": "bad"})
    with pytest.raises(ValueError):
        el.validate()


def test_factory_dispatches_known_types() -> None:
    d = {"type": "alias", "id": "a", "alias_of": "b"}
    el = element_from_dict(d)
    assert isinstance(el, AliasFormElement)
    el.validate()


def test_factory_dispatches_unknown_type_to_base() -> None:
    d = {"type": "unknown_type", "id": "test"}
    el = element_from_dict(d)
    assert isinstance(el, BaseFormElement)
    el.validate()


def test_docstring_retrieval_of_elements() -> None:
    doc = FormElementRegistry.doc("alias")
    assert isinstance(doc, str) and "алиас" in doc.lower()
    doc2 = FormElementRegistry.doc("badtype")
    assert doc2 == ""


def test_registry_registration_and_unregister() -> None:
    @element_class("customplug", order=88)
    @dataclass
    class PlugElement(BaseFormElement):
        custom: str = "abc"

    assert "customplug" in FormElementRegistry.all_types()
    FormElementRegistry.unregister("customplug")
    assert "customplug" not in FormElementRegistry.all_types()


def test_factory_with_extra_fields_collects_unknown() -> None:
    d = {"type": "alias", "id": "xx", "alias_of": "yy", "foo": "bar", "ggg": 123}
    el = element_from_dict(d, collect_unused=True)
    assert hasattr(el, "_unknown_attrs") and "foo" in el._unknown_attrs


def test_registry_reregistration_logs_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level("WARNING"):

        @element_class("group")
        @dataclass
        class DummyGroup(BaseFormElement):
            pass

        assert any("Re-registering element type 'group'" in m for m in caplog.messages)


def test_example_integration_with_element_class_decorator() -> None:
    @element_class("testplug", order=25)
    @dataclass
    class TestPlug(BaseFormElement):
        code: str = ""

    inst = element_from_dict({"type": "testplug", "id": "tt1", "code": "ABC"})
    assert isinstance(inst, TestPlug)
    if hasattr(inst, "code"):
        assert getattr(inst, "code") == "ABC"
    inst.validate()
