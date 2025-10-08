# style_manager.py

from typing import Dict, Any, Optional, Union, List, Type
import json
from functools import lru_cache
from model.enums import (
    FontFamily,
    CharactersPerInch,
    PrintQuality,
    LineSpacing,
    CodePage,
    Color,
    Alignment,
    TabAlignment,
    TableStyle,
    TextStyle,
    MarginUnits,
    Orientation,
    PageSize,
    BarcodeType,
    Matrix2DCodeType,
    GraphicsMode,
    PaperType,
    ListType,
    PrintDirection,
    PaperSource,
    DitheringAlgorithm,
    ImagePosition,
    validate_cpi_font_combination,
    validate_quality_font_combination,
    validate_codepage,
    validate_margin,
    validate_barcode,
    validate_graphics_mode,
)


class StyleManagerError(Exception):
    pass


class Style:
    def __init__(self, name: str, params: Dict[str, Any], parent: Optional["Style"] = None):
        self.name = name
        self.params = dict(params)
        self.parent = parent

    def get_param(self, key: str) -> Any:
        # Возвращает значение, заданное явно, либо ищет по родительской цепи
        if key in self.params:
            return self.params[key]
        elif self.parent:
            return self.parent.get_param(key)
        else:
            return None  # не возвращаем дефолт!

    def validate(self) -> None:
        font = self.params.get("font_family")
        cpi = self.params.get("cpi")
        quality = self.params.get("print_quality")
        codepage = self.params.get("codepage")
        margin_units = self.params.get("margin_units")
        barcode = self.params.get("barcode_type")
        graphics_mode = self.params.get("graphics_mode")
        if font and cpi and not validate_cpi_font_combination(cpi, font):
            raise StyleManagerError(f"Font-family {font} incompatible with CPI {cpi}")
        if quality and font and not validate_quality_font_combination(quality, font):
            raise StyleManagerError(f"Print-quality {quality} incompatible with font {font}")
        if codepage and not validate_codepage(codepage):
            raise StyleManagerError(f"Codepage {codepage} not supported by FX-890")
        if barcode and not validate_barcode(barcode):
            raise StyleManagerError(f"Barcode {barcode} not supported FX-890 hardware")
        if graphics_mode and not validate_graphics_mode(graphics_mode):
            raise StyleManagerError(f"Graphics mode {graphics_mode} not supported")
        if margin_units:
            for key in ("margin_left", "margin_right", "margin_top", "margin_bottom"):
                if key not in self.params:
                    continue
            left = self.params.get("margin_left", 0)
            right = self.params.get("margin_right", 0)
            top = self.params.get("margin_top", 0)
            bottom = self.params.get("margin_bottom", 0)
            valid, msg = validate_margin(left, right, top, bottom, margin_units)
            if not valid:
                raise StyleManagerError(msg)

    def to_dict(self) -> Dict[str, Any]:
        data = dict(self.params)
        data["name"] = self.name
        if self.parent:
            data["parent"] = self.parent.name
        return data

    def describe(self) -> Dict[str, str]:
        result = {}
        for key, value in self.params.items():
            if hasattr(value, "localized_name"):
                result[key] = value.localized_name("ru")
            else:
                result[key] = str(value)
        return result


class StyleManager:
    def __init__(self) -> None:
        self.styles: Dict[str, Style] = {}
        self.type_templates: Dict[str, Dict[str, Any]] = {}
        self._param_cache: Dict[str, Dict[str, Any]] = {}  # Кэш: style_name -> параметр: значение
        self.register_default_styles()
        self.register_type_templates()

    def register_default_styles(self) -> None:
        # Добавляем color во все дефолтные стили
        self.add_style(
            "DefaultText",
            {
                "font_family": FontFamily.DRAFT,
                "cpi": CharactersPerInch.CPI_10,
                "print_quality": PrintQuality.DRAFT,
                "alignment": Alignment.LEFT,
                "color": Color.BLACK,  # Обязательно для всех
                "text_style": TextStyle(0),
                "line_spacing": LineSpacing.ONE_SIXTH_INCH,
                "margin_units": MarginUnits.INCHES,
                "margin_left": 0.13,
                "margin_right": 0.13,
                "margin_top": 0.13,
                "margin_bottom": 0.13,
            },
        )
        self.add_style(
            "DefaultTable",
            {
                "table_style": TableStyle.GRID,
                "font_family": FontFamily.DRAFT,
                "cpi": CharactersPerInch.CPI_10,
                "alignment": Alignment.LEFT,
                "color": Color.BLACK,  # Добавлено
            },
        )
        self.add_style(
            "DefaultBarcode",
            {
                "barcode_type": BarcodeType.CODE128,
                "alignment": Alignment.CENTER,
                "font_family": FontFamily.ROMAN,
                "cpi": CharactersPerInch.CPI_12,
                "print_quality": PrintQuality.NLQ,
                "color": Color.BLACK,  # Добавлено
            },
        )
        self.add_style(
            "DefaultImage",
            {
                "graphics_mode": GraphicsMode.DOUBLE_DENSITY,
                "dithering_algorithm": DitheringAlgorithm.FLOYD_STEINBERG,
                "image_position": ImagePosition.INLINE,
                "color": Color.BLACK,  # Добавлено для консистентности
            },
        )

    def register_type_templates(self) -> None:
        # Встроенные шаблоны параметров для быстрого создания новых стилей
        self.type_templates = {
            "text": {
                "font_family": FontFamily.DRAFT,
                "cpi": CharactersPerInch.CPI_10,
                "print_quality": PrintQuality.DRAFT,
                "alignment": Alignment.LEFT,
                "color": Color.BLACK,
                "text_style": TextStyle(0),
                "line_spacing": LineSpacing.ONE_SIXTH_INCH,
                "margin_units": MarginUnits.INCHES,
                "margin_left": 0.13,
                "margin_right": 0.13,
                "margin_top": 0.13,
                "margin_bottom": 0.13,
            },
            "table": {
                "table_style": TableStyle.GRID,
                "font_family": FontFamily.DRAFT,
                "cpi": CharactersPerInch.CPI_10,
                "alignment": Alignment.LEFT,
                "color": Color.BLACK,
            },
            "barcode": {
                "barcode_type": BarcodeType.CODE128,
                "alignment": Alignment.CENTER,
                "font_family": FontFamily.ROMAN,
                "cpi": CharactersPerInch.CPI_12,
                "print_quality": PrintQuality.NLQ,
                "color": Color.BLACK,
            },
            "image": {
                "graphics_mode": GraphicsMode.DOUBLE_DENSITY,
                "dithering_algorithm": DitheringAlgorithm.FLOYD_STEINBERG,
                "image_position": ImagePosition.INLINE,
            },
        }

    def create_style_from_template(
        self,
        name: str,
        type_: str,
        overrides: Optional[Dict[str, Any]] = None,
        parent: Optional[str] = None,
    ) -> None:
        # Быстрое создание нового стиля по встроенному шаблону и с кастомизацией
        params = dict(self.type_templates.get(type_, {}))
        if overrides:
            params.update(overrides)
        self.add_style(name, params, parent=parent)

    def add_style(self, name: str, params: Dict[str, Any], parent: Optional[str] = None) -> None:
        if name in self.styles:
            raise StyleManagerError(f"Style '{name}' already exists.")
        parent_style = self.styles[parent] if parent else None
        style = Style(name, params, parent_style)
        style.validate()
        self.styles[name] = style
        self._param_cache[name] = dict(style.params)  # Кэшируем параметры для быстрого доступа

    def remove_style(self, name: str) -> None:
        if name not in self.styles:
            raise StyleManagerError(f"Style '{name}' not found.")
        del self.styles[name]
        if name in self._param_cache:
            del self._param_cache[name]
        # Очищаем LRU cache
        self.get_style_params.cache_clear()
        for s in self.styles.values():
            if s.parent and s.parent.name == name:
                s.parent = None

    def get_style(self, name: str) -> Style:
        if name not in self.styles:
            raise StyleManagerError(f"Style '{name}' not found.")
        return self.styles[name]

    @lru_cache(maxsize=128)
    def get_style_params(self, name: str) -> Dict[str, Any]:
        # Проверяем существование стиля перед возвратом кэша
        if name not in self.styles:
            raise StyleManagerError(f"Style '{name}' not found.")
        if name not in self._param_cache:
            style = self.get_style(name)
            self._param_cache[name] = dict(style.params)
        return dict(self._param_cache[name])

    def apply_style(self, obj: Dict[str, Any], style_name: str) -> Dict[str, Any]:
        params = self.get_style_params(style_name)
        result = dict(obj)
        result.update(params)
        return result

    def export_styles(self) -> str:
        data = {}
        for name, style in self.styles.items():
            style_dict = {}
            for key, value in style.params.items():
                style_dict[key] = self._serialize_value(value)
            style_dict["name"] = name
            if style.parent:
                style_dict["parent"] = style.parent.name
            data[name] = style_dict
        return json.dumps(data, ensure_ascii=False, indent=2)

    def import_styles(self, data: Union[str, Dict[str, Any]]) -> None:
        from src.model.enums import (
            FontFamily,
            CharactersPerInch,
            PrintQuality,
            Color,
            TextStyle,
            TableStyle,
            BarcodeType,
            GraphicsMode,
            DitheringAlgorithm,
        )

        self.styles.clear()
        self._param_cache.clear()
        if isinstance(data, str):
            data = json.loads(data)
        if not isinstance(data, dict):
            raise StyleManagerError("Expected dict for import_styles")
        enum_map = {
            "font_family": FontFamily,
            "cpi": CharactersPerInch,
            "print_quality": PrintQuality,
            "color": Color,
            "text_style": TextStyle,
            "table_style": TableStyle,
            "barcode_type": BarcodeType,
            "graphics_mode": GraphicsMode,
            "dithering_algorithm": DitheringAlgorithm,
        }
        for name, style_dict in data.items():
            style_params: dict[str, Any] = {}
            for k, v in style_dict.items():
                if k in ("name", "parent"):
                    continue
                if k in enum_map:
                    # Преобразовываем обратно по ожидаемому типу
                    try:
                        style_params[k] = enum_map[k](v)
                    except Exception:
                        style_params[k] = v
                else:
                    style_params[k] = v
            self.styles[name] = Style(name, style_params, None)
        for name, style_dict in data.items():
            parent_name = style_dict.get("parent")
            if parent_name and parent_name in self.styles:
                self.styles[name].parent = self.styles[parent_name]
        for name, style in self.styles.items():
            self._param_cache[name] = dict(style.params)

    def list_styles(self) -> List[str]:
        return list(self.styles.keys())

    def describe_style(self, name: str) -> Dict[str, str]:
        style = self.get_style(name)
        return style.describe()

    def _serialize_value(self, value: Any) -> Any:
        if hasattr(value, "value"):
            return value.value
        elif hasattr(value, "name"):
            return value.name
        elif isinstance(value, TextStyle):
            return value.value
        return value

    def get_param_with_default(self, style_name: str, key: str, default: Any) -> Any:
        style = self.get_style(style_name)
        value = style.get_param(key)
        return value if value is not None else default
