import pytest
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Set, List, Callable
from src.form.form_builder import (
    FormBuilder,
    FormBuilderError,
    FormLayout,
    FormKind,
    FormGroup,
    TableElement,
    ImageElement,
    VariableElement,
    QRElement,
    WatermarkElement,
    SignatureElement,
    AuditElement,
    FormElement,
    FormElementType,
    validate_form_structure,
    validate_special_form_security,
    import_from_json,
    export_to_json,
)


def make_special_form_elements(include: Set[str]) -> List[FormElement]:
    elements: List[FormElement] = []
    if "qr" in include:
        elements.append(QRElement(id="qr123", data="SECURE-DATA"))
    if "watermark" in include:
        elements.append(WatermarkElement(id="wm1", text="CONFIDENTIAL"))
    if "signature" in include:
        elements.append(SignatureElement(id="sig1", key_id="authkey-001"))
    return elements


def test_regular_form_build_and_serialize() -> None:
    builder = FormBuilder()
    table = TableElement(id="tbl1", rows=2, cols=3)
    v = VariableElement(id="var1", name="org", value="Acme")
    img = ImageElement(id="img1", path="/logo.bmp")
    builder.add_element(table)
    builder.add_element(v)
    builder.add_element(img)
    group = FormGroup(name="main", element_ids=["tbl1", "var1"], permissions=["user"])
    builder.layout.groups.append(group)
    builder.layout.template = "STD"
    d = builder.build()
    assert d["kind"] == FormKind.REGULAR.value
    tbl1 = next(e for e in d["elements"] if e["id"] == "tbl1")
    assert tbl1["rows"] == 2
    var1 = next(e for e in d["elements"] if e["id"] == "var1")
    assert var1["value"] == "Acme"
    # Test repeated serialization/import
    b2 = FormBuilder.from_dict(d)
    elem_tbl1 = b2.get_element("tbl1")
    assert isinstance(elem_tbl1, TableElement)
    assert elem_tbl1.rows == 2
    elem_var1 = b2.get_element("var1")
    assert isinstance(elem_var1, VariableElement)
    assert elem_var1.value == "Acme"


@pytest.mark.parametrize(
    "missing",
    [
        set(),
        {"qr"},
        {"watermark"},
        {"signature"},
        {"qr", "watermark"},
        {"qr", "signature"},
        {"watermark", "signature"},
        {"qr", "watermark", "signature"},
    ],
)
def test_special_form_security_enforce(missing: Set[str]) -> None:
    inc = {"qr", "watermark", "signature"} - missing
    layout = FormLayout(kind=FormKind.SPECIAL)
    builder = FormBuilder(layout)
    for el in make_special_form_elements(inc):
        builder.add_element(el)
    if missing:
        with pytest.raises(FormBuilderError) as e:
            builder.build()
        assert "missing required security elements" in str(e.value)
    else:
        d = builder.build()
        # Audit элемент добавлен автоматически
        audits = [e for e in d["elements"] if e["type"] == "audit"]
        assert len(audits) > 0
        audit = audits[0]
        assert "timestamp" in audit


def test_variable_inject_preserves_value_on_export_import() -> None:
    builder = FormBuilder()
    v = VariableElement(id="name", name="operator")
    builder.add_element(v)
    builder.inject_variables({"operator": "Тестовый Оператор"})
    assert v.value == "Тестовый Оператор"
    d = builder.to_dict()
    var_el = next(e for e in d["elements"] if e["id"] == "name")
    assert var_el["value"] == "Тестовый Оператор"
    b2 = FormBuilder.from_dict(d)
    v2 = b2.get_element("name")
    assert isinstance(v2, VariableElement)
    assert v2.value == "Тестовый Оператор"


@pytest.mark.parametrize(
    "el_cls,kwargs,should_raise",
    [
        (QRElement, dict(id="q1", data="data", error_correction="L"), False),
        (QRElement, dict(id="q2", data="", error_correction="M"), True),
        (QRElement, dict(id="q3", data="ok", error_correction="X"), True),
        (WatermarkElement, dict(id="wm0", text="W", opacity=0.3), False),
        (WatermarkElement, dict(id="wm1", text="", image_path=None), True),
        (WatermarkElement, dict(id="wm2", text="W", opacity=2.0), True),
        (SignatureElement, dict(id="sig0", key_id="x", algorithm="ed25519"), False),
        (SignatureElement, dict(id="sig1", key_id="", algorithm="ed25519"), True),
        (SignatureElement, dict(id="sig3", key_id="y", algorithm="UNKNOWN"), True),
        (AuditElement, dict(id="a1", action="created"), False),
        (AuditElement, dict(id="a2", action=""), True),
    ],
)
def test_security_elements_validation(
    el_cls: type, kwargs: Dict[str, Any], should_raise: bool
) -> None:
    if should_raise:
        with pytest.raises(FormBuilderError):
            el_cls(**kwargs).validate()
    else:
        el_cls(**kwargs).validate()  # should not raise


def test_duplicate_id_validation() -> None:
    builder = FormBuilder()
    builder.add_element(TableElement(id="dupl", rows=1, cols=1))
    with pytest.raises(FormBuilderError):
        builder.add_element(ImageElement(id="dupl", path="x"))


def test_remove_and_copy_and_move() -> None:
    builder = FormBuilder()
    t = TableElement(id="tbl", rows=1, cols=2)
    builder.add_element(t)
    builder.copy_element("tbl", "tbl2")
    elem_tbl2 = builder.get_element("tbl2")
    assert isinstance(elem_tbl2, TableElement)
    assert elem_tbl2.rows == 1
    builder.move_element("tbl2", 0)
    assert builder.layout.elements[0].id == "tbl2"
    builder.remove_element_by_id("tbl")
    with pytest.raises(FormBuilderError):
        builder.get_element("tbl")


def test_group_elements_with_level_and_permission() -> None:
    builder = FormBuilder()
    v1, v2 = VariableElement(id="v1", name="a"), VariableElement(id="v2", name="b")
    builder.add_element(v1)
    builder.add_element(v2)
    builder.group_elements(
        "admins", ["v1", "v2"], permissions=["admin"], security_level="confidential"
    )
    group = builder.layout.groups[0]
    assert group.permissions == ["admin"]
    assert group.security_level == "confidential"


def test_import_export_json(tmp_path: Path) -> None:
    builder = FormBuilder()
    builder.add_element(QRElement(id="q", data="q"))
    builder.add_element(WatermarkElement(id="w", text="W"))
    builder.add_element(SignatureElement(id="s", key_id="KEY"))
    builder.layout.kind = FormKind.SPECIAL
    file_path = tmp_path / "special.json"
    builder.export_to_json(str(file_path))
    data = import_from_json(str(file_path))
    b2 = FormBuilder.from_dict(data)
    etypes = set(el.type for el in b2.layout.elements)
    assert {"qr", "watermark", "signature"}.issubset(etypes)
    assert b2.layout.kind == FormKind.SPECIAL


def test_build_with_custom_validation() -> None:
    builder = FormBuilder()
    t = TableElement(id="tbl", rows=2, cols=2)
    builder.add_element(t)
    calls: Dict[str, bool] = {}

    def custom_rule(form_dict: Dict[str, Any]) -> None:
        calls["checked"] = True

    builder.set_custom_validation(custom_rule)
    builder.build()
    assert "checked" in calls


def test_invalid_layout_type_and_elements() -> None:
    # Invalid layout type
    form_dict = {"kind": "regular", "layout_type": "BAD", "elements": [], "groups": []}
    with pytest.raises(FormBuilderError):
        validate_form_structure(form_dict)
    # Elements not a list
    form_dict2 = {
        "kind": "regular",
        "layout_type": "grid",
        "elements": "notalist",
        "groups": [],
    }
    with pytest.raises(FormBuilderError):
        validate_form_structure(form_dict2)


def test_event_hook_is_called() -> None:
    events: List[Any] = []

    def hook(ev: str, payload: dict) -> None:
        events.append((ev, payload))

    builder = FormBuilder()
    builder.add_event_hook(hook)
    table = TableElement(id="abc", rows=1, cols=1)
    builder.add_element(table)
    builder.build()
    assert events[0][0] == "add_element"
    assert events[-1][0] == "build"


def test_audit_auto_added_for_special() -> None:
    builder = FormBuilder(FormLayout(kind=FormKind.SPECIAL))
    builder.add_element(QRElement(id="q", data="X"))
    builder.add_element(WatermarkElement(id="w", text="T"))
    builder.add_element(SignatureElement(id="s", key_id="2"))
    data = builder.build()
    audits = [e for e in data["elements"] if e["type"] == "audit"]
    assert audits
    audit = audits[0]
    assert "timestamp" in audit
    datetime.fromisoformat(audit["timestamp"])


def test_validate_special_form_security_function() -> None:
    # Positive: all present
    present = {"qr", "watermark", "signature", "table"}
    validate_special_form_security(present)
    # Negative: missing one
    not_enough = {"qr", "table"}
    with pytest.raises(FormBuilderError):
        validate_special_form_security(not_enough)


def test_from_dict_unknown_element_type() -> None:
    # элемент с type='unknown'
    raw = {
        "kind": "regular",
        "layout_type": "grid",
        "elements": [{"type": "unknown", "id": "x"}],
        "groups": [],
    }
    builder = FormBuilder.from_dict(raw)
    e = builder.get_element("x")
    assert isinstance(e, FormElement)
    assert e.type == "unknown"


def test_remove_nonexisting_element_raises() -> None:
    builder = FormBuilder()
    with pytest.raises(FormBuilderError):
        builder.remove_element_by_id("noid")


def test_move_nonexisting_element_raises() -> None:
    builder = FormBuilder()
    with pytest.raises(FormBuilderError):
        builder.move_element("bad", 0)


def test_group_elements_none_found() -> None:
    builder = FormBuilder()
    builder.group_elements("empty", ["no-such-id"])
    assert builder.layout.groups[0].element_ids == []


def test_signature_element_validate_last_branch() -> None:
    # Покрыть ветвь алгоритма RSA-4096 (ветвление if self.algorithm not in ("ed25519", "rsa-4096")):
    s = SignatureElement(id="sigx", key_id="k", algorithm="rsa-4096")
    s.validate()
    # Теперь невалидный алгоритм (уже покрыто), RSA‑4096 — нет


def test_check_unique_id_none_skips() -> None:
    builder = FormBuilder()
    v = VariableElement(name="one", id=None)
    # Не выбросит, т.к. id=None, ветка "if elem.id is None: return"
    builder._check_unique_id(v)


def test_emit_event_branch_with_no_hooks() -> None:
    builder = FormBuilder()
    builder._emit_event("evt", {"foo": "bar"})  # Нет хуков — просто срабатывает pass


def test_remove_element_by_id_error() -> None:
    builder = FormBuilder()
    with pytest.raises(FormBuilderError):
        builder.remove_element_by_id("notfoundid")


def test_move_element_error() -> None:
    builder = FormBuilder()
    with pytest.raises(FormBuilderError):
        builder.move_element("notfoundid", 0)


def test_find_element_idx_not_found() -> None:
    builder = FormBuilder()
    with pytest.raises(FormBuilderError):
        builder._find_element_idx("ghost")


def test_custom_rules_none_branch() -> None:
    builder = FormBuilder()
    t = TableElement(id="t5", rows=1, cols=1)
    builder.add_element(t)
    builder._custom_rules = None  # Типизировано как Optional -- теперь можно
    builder.build()


def test_audit_element_validates_all_fields() -> None:
    audit = AuditElement(
        id="a",
        user_id="u",
        action="export",
        timestamp="2020-01-01T12:00:00",
        hash_chain="abc",
    )
    audit.validate()


def test_from_dict_no_template_security_metadata_branches() -> None:
    # Покрытие путей отсутствия template и security_metadata
    raw = {
        "kind": "regular",
        "layout_type": "grid",
        "elements": [],
        "groups": [],
        # template=None, security_metadata=None
    }
    builder = FormBuilder.from_dict(raw)
    assert builder.layout.template is None
    assert builder.layout.security_metadata is None


def test_remove_element_on_empty_list() -> None:
    builder = FormBuilder()
    with pytest.raises(FormBuilderError):
        builder.remove_element_by_id("a")


def test_group_elements_all_ids_not_found() -> None:
    builder = FormBuilder()
    builder.group_elements("g", ["not_found"])
    group = builder.layout.groups[0]
    assert group.element_ids == []


def test_import_from_json_non_dict(tmp_path: Path) -> None:
    file_path = tmp_path / "somenotdict.json"
    file_path.write_text('["not a dict"]', encoding="utf-8")
    with pytest.raises(ValueError):
        import_from_json(str(file_path))


def test_to_dict_handles_empty() -> None:
    builder = FormBuilder()
    d = builder.to_dict()
    assert isinstance(d, dict)
    assert isinstance(d["elements"], list)
    assert d["kind"] == "regular"
