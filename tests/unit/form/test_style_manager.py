from typing import Any

import pytest

from src.form.style_manager import StyleManager, StyleManagerError
from src.model.enums import (
    BarcodeType,
    CharactersPerInch,
    Color,
    DitheringAlgorithm,
    FontFamily,
    GraphicsMode,
    PrintQuality,
    TextStyle,
)


def test_register_defaults() -> None:
    mgr = StyleManager()
    # Проверяем все дефолтные стили
    defaults = ["DefaultText", "DefaultTable", "DefaultBarcode", "DefaultImage"]
    for key in defaults:
        assert key in mgr.list_styles()
        params = mgr.get_style_params(key)
        assert isinstance(params, dict)
        assert "color" in params  # Теперь во всех стилях есть color
        assert params["color"] == Color.BLACK


def test_create_and_get_custom_style() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template(
        "CustomText",
        "text",
        {"text_style": TextStyle.BOLD, "font_family": FontFamily.ROMAN},
    )
    assert "CustomText" in mgr.list_styles()
    style = mgr.get_style("CustomText")
    assert style.get_param("font_family") == FontFamily.ROMAN
    assert style.get_param("text_style") == TextStyle.BOLD


def test_style_inheritance() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template("ParentText", "text", {"color": Color.BLACK})
    mgr.create_style_from_template(
        "ChildText", "text", {"font_family": FontFamily.SANS_SERIF}, parent="ParentText"
    )

    child = mgr.get_style("ChildText")
    parent = mgr.get_style("ParentText")
    assert child.parent == parent
    # Наследование: если параметр отсутствует в Child, берется из Parent
    assert child.get_param("color") == Color.BLACK


def test_style_validation_cpi_font() -> None:
    mgr = StyleManager()
    # Недопустимая пара font+cpi должна вызвать ошибку
    with pytest.raises(StyleManagerError):
        mgr.create_style_from_template(
            "InvalidCombo",
            "text",
            {"font_family": FontFamily.USD, "cpi": CharactersPerInch.CPI_20},
        )


def test_remove_style() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template("TempStyle", "text")
    mgr.remove_style("TempStyle")
    assert "TempStyle" not in mgr.list_styles()
    with pytest.raises(StyleManagerError):
        mgr.get_style("TempStyle")


def test_apply_style_object() -> None:
    mgr = StyleManager()
    obj = {"foo": "bar"}
    mgr.create_style_from_template(
        "TextApply", "text", {"font_family": FontFamily.ROMAN}
    )
    result = mgr.apply_style(obj, "TextApply")
    assert result["foo"] == "bar"
    assert result["font_family"] == FontFamily.ROMAN


def test_export_import_styles() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template(
        "ExportTest",
        "text",
        {"font_family": FontFamily.ROMAN, "text_style": TextStyle.BOLD},
    )

    # Экспорт должен работать с Enum объектами
    export_json = mgr.export_styles()
    assert isinstance(export_json, str)

    # Импорт в другой менеджер
    mgr2 = StyleManager()
    mgr2.import_styles(export_json)
    assert "ExportTest" in mgr2.list_styles()


def test_describe_style() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template(
        "DescStyle", "text", {"font_family": FontFamily.ROMAN}
    )
    desc = mgr.describe_style("DescStyle")
    assert isinstance(desc, dict)
    assert "font_family" in desc


def test_list_styles() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template("ListTest", "text")
    styles = mgr.list_styles()
    assert "ListTest" in styles
    assert "DefaultText" in styles


def test_cache_consistency() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template("CacheStyle", "text", {"color": Color.BLACK})

    # Доступ к параметрам работает
    params = mgr.get_style_params("CacheStyle")
    assert params["color"] == Color.BLACK

    # После удаления get_style_params должен падать
    mgr.remove_style("CacheStyle")
    with pytest.raises(StyleManagerError):
        mgr.get_style_params("CacheStyle")


def test_style_validation_barcode() -> None:
    mgr = StyleManager()
    # Валидный barcode стиль работает
    mgr.create_style_from_template(
        "ValidBarcode", "barcode", {"barcode_type": BarcodeType.EAN13}
    )
    assert "ValidBarcode" in mgr.list_styles()


def test_style_validation_graphics() -> None:
    mgr = StyleManager()
    # Валидный image стиль работает
    mgr.create_style_from_template("ValidImage", "image")
    assert "ValidImage" in mgr.list_styles()


def test_invalid_style_access() -> None:
    mgr = StyleManager()
    with pytest.raises(StyleManagerError):
        mgr.get_style("NonExistentStyle")
    with pytest.raises(StyleManagerError):
        mgr.get_style_params("NonExistentStyle")


def test_style_duplication_error() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template("DupStyle", "text")
    # Повторное создание стиля с тем же именем должно вызвать ошибку
    with pytest.raises(StyleManagerError):
        mgr.create_style_from_template("DupStyle", "text")


def test_textStyle_serialization() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template(
        "TextStyleTest", "text", {"text_style": TextStyle.BOLD | TextStyle.ITALIC}
    )
    # Экспорт должен работать с Flag enum
    export_json = mgr.export_styles()
    assert "TextStyleTest" in export_json


def test_import_styles_with_unknown_key() -> None:
    mgr = StyleManager()
    bad_json = '{"BadStyle":{"font_family":"unknown","name":"BadStyle"}}'
    mgr.import_styles(bad_json)
    # Несмотря на unknown, структура появляется - типизация не строгая на этапе импорта
    assert "BadStyle" in mgr.list_styles()


def test_import_styles_with_bit_flag_textstyle() -> None:
    mgr = StyleManager()
    raw = '{"FlagStyle":{"font_family":"draft","text_style":3,"name":"FlagStyle"}}'
    mgr.import_styles(raw)
    style = mgr.get_style("FlagStyle")
    assert style.get_param("text_style") == TextStyle(3)
    assert isinstance(style.get_param("text_style"), TextStyle)


def test_parent_chain_lookup() -> None:
    mgr = StyleManager()
    # Создаём стили вручную, без дефолтных шаблонных полей
    mgr.add_style("BaseParent", {"color": Color.BLACK})
    mgr.add_style("MidParent", {"font_family": FontFamily.USD}, parent="BaseParent")
    mgr.add_style("FinalChild", {"cpi": CharactersPerInch.CPI_10}, parent="MidParent")
    final = mgr.get_style("FinalChild")
    assert final.get_param("color") == Color.BLACK
    assert final.get_param("font_family") == FontFamily.USD
    assert final.get_param("cpi") == CharactersPerInch.CPI_10


def test_apply_style_missing_key() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template(
        "PartStyle", "text", {"font_family": FontFamily.ROMAN}
    )
    obj: dict[str, Any] = {}
    result = mgr.apply_style(obj, "PartStyle")
    assert result["font_family"] == FontFamily.ROMAN
    # Не должно быть других ключей


def test_remove_and_readd_style() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template(
        "TempStyle", "text", {"font_family": FontFamily.SANS_SERIF}
    )
    mgr.remove_style("TempStyle")
    mgr.create_style_from_template(
        "TempStyle", "text", {"font_family": FontFamily.DRAFT}
    )
    style = mgr.get_style("TempStyle")
    assert style.get_param("font_family") == FontFamily.DRAFT


def test_import_styles_invalid_json() -> None:
    mgr = StyleManager()
    with pytest.raises(Exception):
        mgr.import_styles("not a json string")


def test_export_style_with_flags_and_enums() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template(
        "EnumTest",
        "text",
        {
            "font_family": FontFamily.HSD,
            "print_quality": PrintQuality.DRAFT,
            "text_style": TextStyle.BOLD | TextStyle.ITALIC,
            "graphics_mode": GraphicsMode.DOUBLE_DENSITY,
            "dithering_algorithm": DitheringAlgorithm.ORDERED_BAYER,
        },
    )
    export = mgr.export_styles()
    assert "EnumTest" in export


def test_import_export_full_cycle() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template(
        "FullCycle",
        "text",
        {"font_family": FontFamily.ROMAN, "text_style": TextStyle.BOLD},
    )
    json_str = mgr.export_styles()
    mgr2 = StyleManager()
    mgr2.import_styles(json_str)
    style = mgr2.get_style("FullCycle")
    assert style.get_param("font_family") == FontFamily.ROMAN
    assert style.get_param("text_style") == TextStyle.BOLD


def test_parent_deep_inheritance_resolves() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template("Root", "text", {"color": Color.BLACK})
    mgr.create_style_from_template("Mid", "text", {}, parent="Root")
    mgr.create_style_from_template("Leaf", "text", {}, parent="Mid")
    # Лист через цепочку должен получить цвет
    assert mgr.get_style("Leaf").get_param("color") == Color.BLACK


def test_apply_style_to_existing_keys() -> None:
    mgr = StyleManager()
    mgr.create_style_from_template("Override", "text", {"color": Color.BLACK})
    obj: dict[str, Any] = {"color": Color.BLACK, "extra": 123}
    result = mgr.apply_style(obj, "Override")
    assert result["color"] == Color.BLACK
    assert result["extra"] == 123


def test_export_style_unknown_field() -> None:
    mgr = StyleManager()
    mgr.add_style("UnknownField", {"glitter": "yes", "font_family": FontFamily.DRAFT})
    json_str = mgr.export_styles()
    assert "UnknownField" in json_str


def test_default_style_modification() -> None:
    mgr = StyleManager()
    params = mgr.get_style_params("DefaultText")
    assert params["color"] == Color.BLACK
    # Модифицируем value прямо вручную и пересохраняем
    params["color"] = Color.BLACK
    mgr.remove_style("DefaultText")
    mgr.add_style("DefaultText", params)
    assert mgr.get_style_params("DefaultText")["color"] == Color.BLACK


def test_cache_lru_behavior() -> None:
    mgr = StyleManager()
    names = []
    for i in range(135):  # lru_cache ограничен до 128, выйдем за пределы
        style_name = f"CacheStyle{i}"
        mgr.create_style_from_template(
            style_name, "text", {"font_family": FontFamily.DRAFT}
        )
        names.append(style_name)
        mgr.get_style_params(style_name)
    # Все стили зарегистрированы, кэш очищается автоматически
    for name in names:
        assert mgr.get_style_params(name)["font_family"] == FontFamily.DRAFT
