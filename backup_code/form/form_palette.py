"""RU: Палитра элементов форм — предустановленные типы, композитные и стандартные пресеты для визуального редактора."""

import copy
import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DEFAULT_PALETTE: List[Dict[str, Any]] = [
    {
        "type": "label",
        "label": "Текст",
        "preset_name": "label",
        "default_text": "Надпись",
        "i18n": {"en": "Label", "ru": "Текст"},
        "category": "basic",
        "icon": "label",
        "order": 1,
        "permissions": [],
    },
    {
        "type": "input",
        "label": "Поле",
        "preset_name": "input",
        "placeholder": "Введите...",
        "i18n": {"en": "Input", "ru": "Поле"},
        "category": "basic",
        "icon": "input",
        "order": 2,
        "permissions": [],
    },
    {
        "type": "qr",
        "label": "QR-код",
        "preset_name": "qr",
        "data": "",
        "i18n": {"en": "QR Code", "ru": "QR-код"},
        "category": "security",
        "icon": "qr_code",
        "order": 3,
        "permissions": [],
    },
    {
        "type": "signature",
        "label": "Подпись",
        "preset_name": "signature",
        "key_id": "",
        "i18n": {"en": "Signature", "ru": "Подпись"},
        "category": "security",
        "icon": "signature",
        "order": 4,
        "permissions": ["admin", "operator"],
    },
    {
        "type": "watermark",
        "label": "Водяной знак",
        "preset_name": "watermark",
        "text": "Секретно",
        "i18n": {"en": "Watermark", "ru": "Водяной знак"},
        "category": "security",
        "icon": "watermark",
        "order": 5,
        "permissions": ["admin", "operator"],
    },
    {
        "type": "table",
        "label": "Таблица",
        "preset_name": "table",
        "rows": 2,
        "cols": 2,
        "i18n": {"en": "Table", "ru": "Таблица"},
        "category": "layout",
        "icon": "table",
        "order": 6,
        "permissions": [],
    },
    {
        "type": "variable",
        "label": "Переменная",
        "preset_name": "variable",
        "name": "",
        "i18n": {"en": "Variable", "ru": "Переменная"},
        "category": "logic",
        "icon": "variable",
        "order": 7,
        "permissions": [],
    },
    {
        "type": "image",
        "label": "Картинка",
        "preset_name": "image",
        "path": "",
        "i18n": {"en": "Image", "ru": "Картинка"},
        "category": "basic",
        "icon": "image",
        "order": 8,
        "permissions": [],
    },
    {
        "type": "stamp",
        "label": "Электронная печать",
        "preset_name": "electronic_stamp",
        "border_style": "circle",
        "border_text": "ООО ОРГАНИЗАЦИЯ",
        "center_text": "М.П.",
        "logo_path": "",
        "font_size": 13,
        "qr_data": "",
        "qr_type": "qr",
        "qr_position": "center",
        "qr_size": 0.25,
        "qr_error_correction": "M",
        "signature_data": "",
        "organization_id": "",
        "stamp_authority": "Директор",
        "timestamp": "",
        "document_hash": "",
        "validity_period": None,
        "usage_counter": None,
        "i18n": {"en": "Electronic Stamp", "ru": "Электронная печать"},
        "category": "security",
        "icon": "stamp",
        "order": 9,
        "permissions": ["admin", "operator"],
    },
]


def _norm(val: Optional[str]) -> str:
    if not isinstance(val, str):
        return ""
    return val.lower().strip()


def _is_valid_type(el: Dict[str, Any]) -> bool:
    return "type" in el and isinstance(el["type"], str) and el["type"].strip() != ""


def _is_valid_preset_name(el: Dict[str, Any]) -> bool:
    return (
        "preset_name" in el
        and isinstance(el["preset_name"], str)
        and el["preset_name"].strip() != ""
    )


class FormPalette:
    def __init__(self) -> None:
        self._presets: List[Dict[str, Any]] = copy.deepcopy(_DEFAULT_PALETTE)
        self._custom: List[Dict[str, Any]] = []

    def list_element_types(self, role: Optional[str] = None) -> List[str]:
        all_presets = self._presets + self._custom
        if role is not None:
            types = [
                _norm(el["type"])
                for el in all_presets
                if _is_valid_type(el) and self._has_permission(el, role)
            ]
        else:
            types = [_norm(el["type"]) for el in all_presets if _is_valid_type(el)]
        return sorted(set(types))

    def get_preset(
        self, type_: str, preset_name: Optional[str] = None, role: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        canonical_type = _norm(type_)
        candidates = [
            el
            for el in self._custom + self._presets
            if _is_valid_type(el) and _norm(el["type"]) == canonical_type
        ]
        if preset_name is not None:
            canonical_name = _norm(preset_name)
            candidates = [
                el
                for el in candidates
                if _is_valid_preset_name(el)
                and _norm(el.get("preset_name", "")) == canonical_name
            ]
        if role is not None:
            candidates = [el for el in candidates if self._has_permission(el, role)]
        if candidates:
            return copy.deepcopy(candidates[0])
        logger.warning(
            "Preset not found for type: %r preset_name: %r role: %r",
            type_,
            preset_name,
            role,
        )
        return None

    def list_presets(self, role: Optional[str] = None) -> List[Dict[str, Any]]:
        all_presets = self._presets + self._custom
        out = [
            copy.deepcopy(p)
            for p in all_presets
            if _is_valid_type(p)
            and _is_valid_preset_name(p)
            and (role is None or self._has_permission(p, role))
        ]
        out.sort(key=lambda p: p.get("order", 100))
        return out

    def add_custom_preset(self, preset: Dict[str, Any]) -> None:
        preset = self._validate_and_patch_preset(preset)
        key = (_norm(preset["type"]), _norm(preset["preset_name"]))
        existing = {
            (_norm(p["type"]), _norm(p.get("preset_name", "")))
            for p in self._custom
            if _is_valid_type(p) and _is_valid_preset_name(p)
        }
        if key in existing:
            raise ValueError(
                f"Custom preset with type '{preset['type']}', preset_name '{preset['preset_name']}' already exists"
            )
        self._custom.append(copy.deepcopy(preset))
        logger.info(
            "Custom preset added: type=%s preset_name=%s",
            preset["type"],
            preset["preset_name"],
        )

    def update_custom_preset(
        self, type_: str, preset_name: str, new_preset: Dict[str, Any]
    ) -> None:
        type_ = _norm(type_)
        preset_name = _norm(preset_name)
        found = False
        for idx, p in enumerate(self._custom):
            if (
                _is_valid_type(p)
                and _is_valid_preset_name(p)
                and _norm(p["type"]) == type_
                and _norm(p.get("preset_name", "")) == preset_name
            ):
                self._custom[idx] = self._validate_and_patch_preset(new_preset)
                found = True
                logger.info(
                    "Custom preset updated: type=%s preset_name=%s", type_, preset_name
                )
                break
        if not found:
            raise ValueError(
                f"Custom preset to update not found: type={type_} preset_name={preset_name}"
            )

    def remove_custom_preset(
        self, type_: str, preset_name: Optional[str] = None
    ) -> None:
        type_ = _norm(type_)
        before = len(self._custom)
        if preset_name is None:
            self._custom = [
                p
                for p in self._custom
                if not (_is_valid_type(p) and _norm(p["type"]) == type_)
            ]
        else:
            preset_name = _norm(preset_name)
            self._custom = [
                p
                for p in self._custom
                if not (
                    _is_valid_type(p)
                    and _is_valid_preset_name(p)
                    and _norm(p["type"]) == type_
                    and _norm(p.get("preset_name", "")) == preset_name
                )
            ]
        logger.info(
            "Removed custom preset type=%s preset_name=%s (was %d -> now %d)",
            type_,
            preset_name,
            before,
            len(self._custom),
        )

    def reset_to_default(self) -> None:
        self._custom.clear()
        logger.info("Palette reset to default")

    def import_palette(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "presets" in data and isinstance(data["presets"], list):
            raw = [
                self._validate_and_patch_preset(p, raise_exc=False)
                for p in data["presets"]
            ]
            valid = [p for p in raw if _is_valid_type(p) and _is_valid_preset_name(p)]
            n_drop = len(raw) - len(valid)
            if n_drop:
                logger.warning(
                    "Dropped %s invalid presets from import (missing type or preset_name)",
                    n_drop,
                )
            self._presets = valid
        if "custom" in data and isinstance(data["custom"], list):
            raw = [
                self._validate_and_patch_preset(p, raise_exc=False)
                for p in data["custom"]
            ]
            valid = [p for p in raw if _is_valid_type(p) and _is_valid_preset_name(p)]
            n_drop = len(raw) - len(valid)
            if n_drop:
                logger.warning(
                    "Dropped %s invalid custom presets from import (missing type or preset_name)",
                    n_drop,
                )
            self._custom = valid
        logger.info("Palette imported from %s", path)

    def export_palette(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {"presets": self._presets, "custom": self._custom},
                f,
                ensure_ascii=False,
                indent=2,
            )
        logger.info("Palette exported to %s", path)

    def register_plugin_preset(self, preset: Dict[str, Any]) -> None:
        self.add_custom_preset(preset)

    def _validate_and_patch_preset(
        self, preset: Dict[str, Any], raise_exc: bool = True
    ) -> Dict[str, Any]:
        required = {"type", "label", "preset_name"}
        missing = required - set(preset)
        if missing:
            msg = f"Preset missing required fields: {missing}"
            if raise_exc:
                raise ValueError(msg)
            else:
                logger.warning(msg)
                return preset
        for key in ("type", "preset_name"):
            if key in preset and isinstance(preset[key], str):
                preset[key] = preset[key].strip()
        for key in ("type", "preset_name"):
            if (
                not isinstance(preset.get(key, None), str)
                or " " in preset[key]
                or not preset[key]
            ):
                msg = f"{key} must be string, non-empty and without spaces"
                if raise_exc:
                    raise ValueError(msg)
                else:
                    logger.warning(msg)
                    return preset
        patch_defaults = {
            "i18n": {"en": preset.get("label", ""), "ru": preset.get("label", "")},
            "category": "custom",
            "icon": "custom",
            "order": 1000,
            "permissions": [],
        }
        for k, v in patch_defaults.items():
            if k not in preset:
                preset[k] = v
        for key in ("type", "preset_name"):
            if (
                not isinstance(preset[key], str)
                or " " in preset[key]
                or not preset[key]
            ):
                msg = f"{key} must be string, non-empty and without spaces"
                if raise_exc:
                    raise ValueError(msg)
                else:
                    logger.warning(msg)
        return preset

    @staticmethod
    def _has_permission(preset: Dict[str, Any], role: Optional[str]) -> bool:
        perms = preset.get("permissions", [])
        if not perms:
            return True
        return role in perms
