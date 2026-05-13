from pathlib import Path

import pytest

from src.form.form_palette import FormPalette


def test_list_element_types_case_insensitive() -> None:
    palette = FormPalette()
    # Add two types differing only by case/preset_name
    custom = {"type": "Xx", "label": "A", "preset_name": "Yy"}
    palette.add_custom_preset(custom)
    types = palette.list_element_types()
    types_lower = [t.lower() for t in types]
    assert "xx" in types_lower


def test_get_preset_with_preset_name() -> None:
    palette = FormPalette()
    custom1 = {"type": "val", "label": "Одно", "preset_name": "p1"}
    custom2 = {"type": "val", "label": "Два", "preset_name": "p2"}
    palette.add_custom_preset(custom1)
    palette.add_custom_preset(custom2)
    p1 = palette.get_preset("val", preset_name="p1")
    assert p1 is not None and p1["label"] == "Одно"
    p2 = palette.get_preset("val", preset_name="p2")
    assert p2 is not None and p2["label"] == "Два"
    # Без указания preset_name выдаётся первый (по добавлению)
    pf = palette.get_preset("val")
    assert pf is not None and pf["label"] in {"Одно", "Два"}


def test_update_custom_preset() -> None:
    palette = FormPalette()
    original = {"type": "upd", "label": "Первый", "preset_name": "p"}
    updated = {"type": "upd", "label": "Обновлён", "preset_name": "p"}
    palette.add_custom_preset(original)
    palette.update_custom_preset("upd", "p", updated)
    now = palette.get_preset("upd", "p")
    assert now is not None and now["label"] == "Обновлён"
    # Обновление несуществующего — ошибка
    with pytest.raises(ValueError):
        palette.update_custom_preset(
            "none", "none", {"type": "none", "label": "x", "preset_name": "none"}
        )


def test_remove_custom_preset_with_preset_name() -> None:
    palette = FormPalette()
    palette.add_custom_preset({"type": "delx", "label": "1", "preset_name": "a"})
    palette.add_custom_preset({"type": "delx", "label": "2", "preset_name": "b"})
    palette.remove_custom_preset("delx", preset_name="a")
    assert palette.get_preset("delx", preset_name="a") is None
    assert palette.get_preset("delx", preset_name="b") is not None
    palette.remove_custom_preset("delx")
    assert palette.get_preset("delx", preset_name="b") is None


def test_permissions_enforced_by_plugin_register() -> None:
    palette = FormPalette()
    # plugin can define its own permission
    plugin = {
        "type": "sys",
        "label": "Системн.",
        "preset_name": "sys",
        "permissions": ["super"],
    }
    palette.register_plugin_preset(plugin)
    # Should not be available to "user"
    assert palette.get_preset("sys", role="user") is None
    assert palette.get_preset("sys", role="super") is not None


def test_import_palette_invalid(tmp_path: Path) -> None:
    file_path = tmp_path / "badp.json"
    # missing type field in one preset
    file_path.write_text(
        '{"presets":[{"label":"Bad","preset_name":"b"}],"custom":[]}', encoding="utf-8"
    )
    palette = FormPalette()
    palette.import_palette(str(file_path))
    # Import does not raise, but logs warning


def test_add_custom_strip_whitespace_and_case() -> None:
    palette = FormPalette()
    custom = {"type": " ABC ", "label": "A", "preset_name": " PQR "}
    palette.add_custom_preset(custom)
    assert "abc" in [t.lower() for t in palette.list_element_types()]
    assert palette.get_preset("abc", preset_name="pqr") is not None


def test_all_presets_category_icon_order_i18n() -> None:
    palette = FormPalette()
    for p in palette.list_presets():
        assert "category" in p
        assert "order" in p
        assert "icon" in p
        assert "i18n" in p


def test_export_import_preserves_case_and_order(tmp_path: Path) -> None:
    palette = FormPalette()
    palette.add_custom_preset(
        {"type": "Ccc", "label": "Test", "preset_name": "vvv", "order": 12}
    )
    path = tmp_path / "exp.json"
    palette.export_palette(str(path))
    palette.reset_to_default()
    palette.import_palette(str(path))
    custom = palette.get_preset("Ccc", preset_name="vvv")
    assert custom is not None and custom["order"] == 12


def test_add_custom_missing_optional_fields() -> None:
    palette = FormPalette()
    c = {"type": "XXX", "label": "Lbl", "preset_name": "PPP"}
    palette.add_custom_preset(c)
    pc = palette.get_preset("xxx", preset_name="ppp")
    assert pc is not None and all(
        k in pc for k in ("icon", "category", "order", "i18n")
    )


def test_plugin_api_is_alias_for_custom() -> None:
    palette = FormPalette()
    plugin = {"type": "Z", "label": "Pl", "preset_name": "Z"}
    palette.register_plugin_preset(plugin)
    assert palette.get_preset("z", preset_name="z") is not None


def test_import_palette_empty_presets(tmp_path: Path) -> None:
    file_path = tmp_path / "empty_presets.json"
    file_path.write_text(
        '{"presets":[], "custom":[{"type":"t","label":"L","preset_name":"t"}]}',
        encoding="utf-8",
    )
    palette = FormPalette()
    palette.import_palette(str(file_path))
    assert palette.get_preset("t", preset_name="t") is not None


def test_import_palette_missing_both(tmp_path: Path) -> None:
    # ни "presets", ни "custom"
    file_path = tmp_path / "nones.json"
    file_path.write_text("{}", encoding="utf-8")
    palette = FormPalette()
    palette.import_palette(str(file_path))
    assert palette.list_element_types()  # defaults are kept


def test_export_palette_edge(tmp_path: Path) -> None:
    palette = FormPalette()
    custom = {"type": "Xedge", "label": "Lbl", "preset_name": "e"}
    palette.add_custom_preset(custom)
    file_path = tmp_path / "exp.json"
    palette.export_palette(str(file_path))
    content = file_path.read_text(encoding="utf-8")
    assert "Xedge" in content


def test_patch_fields_on_missing_optional() -> None:
    palette = FormPalette()
    d = {"type": "OT", "label": "L", "preset_name": "PP"}
    # Не указываем category/icon/order/i18n/permissions
    patched = palette._validate_and_patch_preset(d.copy())
    for k in ("category", "icon", "order", "i18n", "permissions"):
        assert k in patched


def test_patch_fields_on_invalid_type_spaces() -> None:
    palette = FormPalette()
    bad = {"type": " b a d ", "label": "L", "preset_name": "p"}
    with pytest.raises(ValueError):
        palette.add_custom_preset(bad)


def test_import_palette_presets_with_missing_fields(tmp_path: Path) -> None:
    file_path = tmp_path / "mf.json"
    file_path.write_text(
        '{"presets":[{"type":"MF","label":"X","preset_name":"mf"}]}', encoding="utf-8"
    )
    palette = FormPalette()
    palette.import_palette(str(file_path))
    p = palette.get_preset("MF", preset_name="mf")
    # patched fields must be present even in "patched" by import
    assert p and all(
        k in p for k in ("category", "icon", "order", "i18n", "permissions")
    )


def test_import_custom_missing_type_field(tmp_path: Path) -> None:
    file_path = tmp_path / "badcustom.json"
    file_path.write_text(
        '{"custom":[{"label":"Lbl","preset_name":"myp"}]}', encoding="utf-8"
    )
    palette = FormPalette()
    palette.import_palette(str(file_path))
    # should not crash, nothing added
    assert isinstance(palette.list_element_types(), list)


def test_list_presets_order_sort() -> None:
    palette = FormPalette()
    palette.add_custom_preset(
        {"type": "t", "label": "A", "preset_name": "a", "order": 222}
    )
    palette.add_custom_preset(
        {"type": "t", "label": "B", "preset_name": "b", "order": 10}
    )
    ordered = palette.list_presets()
    idx1 = next(i for i, p in enumerate(ordered) if p["label"] == "B")
    idx2 = next(i for i, p in enumerate(ordered) if p["label"] == "A")
    assert idx1 < idx2


def test_list_element_types_ignores_broken() -> None:
    palette = FormPalette()
    # Вставим явно битый dict (нет type)
    palette._custom.append({"label": "bad", "preset_name": "oops"})
    # Не должно падать:
    types = palette.list_element_types()
    assert isinstance(types, list)


def test_get_preset_none_type_and_empty_string() -> None:
    palette = FormPalette()
    palette._custom.append({"type": None, "label": "bad", "preset_name": "a"})
    palette._custom.append({"type": "", "label": "bad2", "preset_name": "a"})
    res1 = palette.get_preset(None)  # type: ignore
    res2 = palette.get_preset("")
    assert res1 is None and res2 is None


def test_add_custom_duplicate_type_and_preset_name_case_insensitive() -> None:
    palette = FormPalette()
    palette.add_custom_preset({"type": "MyType", "label": "1", "preset_name": "Vv"})
    with pytest.raises(ValueError):
        palette.add_custom_preset({"type": "mytype", "label": "2", "preset_name": "vv"})


def test_add_custom_non_str_type() -> None:
    palette = FormPalette()
    # type не строка
    with pytest.raises(ValueError):
        palette.add_custom_preset({"type": 123, "label": "fail", "preset_name": "fail"})
