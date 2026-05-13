"""RU: Построитель форм для FX-Text-processor-3 с поддержкой обычных и специальных (защищённых) форм, QR-кодов, цифровых подписей, водяных знаков и композитных электронных печатей только для спецформ."""

from __future__ import annotations

import copy
import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, TypeVar, Union

logger = logging.getLogger(__name__)
T = TypeVar("T", bound="FormElement")


class FormKind(str, Enum):
    REGULAR = "regular"
    SPECIAL = "special"


class FormElementType(str, Enum):
    TABLE = "table"
    IMAGE = "image"
    VARIABLE = "variable"
    LABEL = "label"
    INPUT = "input"
    QR = "qr"
    WATERMARK = "watermark"
    SIGNATURE = "signature"
    AUDIT = "audit"
    STAMP = "stamp"
    CUSTOM = "custom"


class FormBuilderError(Exception):
    pass


def _generate_unique_id(prefix: str = "el") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@dataclass
class FormElement:
    type: Union[FormElementType, str]
    id: Optional[str] = None
    label: Optional[str] = None
    style: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        if not self.type:
            raise FormBuilderError("Element type is required.")
        if self.id is not None and not isinstance(self.id, str):
            raise FormBuilderError("Element id must be a string.")


@dataclass
class TableElement(FormElement):
    type: Union[FormElementType, str] = FormElementType.TABLE
    rows: int = 1
    cols: int = 1
    data: Optional[List[List[Any]]] = None

    def validate(self) -> None:
        super().validate()
        if self.rows <= 0 or self.cols <= 0:
            raise FormBuilderError("Table dimension must be >0.")


@dataclass
class ImageElement(FormElement):
    type: Union[FormElementType, str] = FormElementType.IMAGE
    path: Optional[str] = None

    def validate(self) -> None:
        super().validate()
        if self.path is None:
            raise FormBuilderError("Image path required.")


@dataclass
class VariableElement(FormElement):
    type: Union[FormElementType, str] = FormElementType.VARIABLE
    name: str = ""
    format: Optional[str] = None
    value: Optional[Any] = None

    def validate(self) -> None:
        super().validate()
        if not self.name:
            raise FormBuilderError("Variable name required.")


@dataclass
class QRElement(FormElement):
    type: Union[FormElementType, str] = FormElementType.QR
    data: str = ""
    version: Optional[int] = None
    error_correction: str = "M"
    size: int = 10

    def validate(self) -> None:
        super().validate()
        if not self.data:
            raise FormBuilderError("QR data required.")
        if self.error_correction not in ("L", "M", "Q", "H"):
            raise FormBuilderError("Invalid QR error correction level.")


@dataclass
class WatermarkElement(FormElement):
    type: Union[FormElementType, str] = FormElementType.WATERMARK
    text: str = ""
    image_path: Optional[str] = None
    opacity: float = 0.15
    rotation: int = 45

    def validate(self) -> None:
        super().validate()
        if not self.text and not self.image_path:
            raise FormBuilderError("Watermark requires text or image.")
        if not (0.0 <= self.opacity <= 1.0):
            raise FormBuilderError("Watermark opacity must be 0.0-1.0.")


@dataclass
class SignatureElement(FormElement):
    type: Union[FormElementType, str] = FormElementType.SIGNATURE
    algorithm: str = "ed25519"
    key_id: Optional[str] = None
    signature: Optional[str] = None
    timestamp: Optional[str] = None

    def validate(self) -> None:
        super().validate()
        if not self.key_id:
            raise FormBuilderError("Signature key_id required.")
        if self.algorithm not in ("ed25519", "rsa-4096"):
            raise FormBuilderError("Unsupported signature algorithm.")


@dataclass
class AuditElement(FormElement):
    type: Union[FormElementType, str] = FormElementType.AUDIT
    user_id: Optional[str] = None
    action: str = ""
    timestamp: Optional[str] = None
    hash_chain: Optional[str] = None

    def validate(self) -> None:
        super().validate()
        if not self.action:
            raise FormBuilderError("Audit action required.")


@dataclass
class StampElement(FormElement):
    """Electronic stamp with classic appearance + QR/DataMatrix for verification.
    Only for SPECIAL forms!"""

    type: Union[FormElementType, str] = FormElementType.STAMP
    border_style: str = "circle"  # circle, square, oval, custom
    border_text: str = ""
    center_text: str = ""
    logo_path: Optional[str] = None
    font_size: int = 12
    qr_data: str = ""
    qr_type: str = "qr"  # qr, datamatrix, pdf417
    qr_position: str = "center"  # center, corner, bottom, top
    qr_size: float = 0.25  # relative size (0.1-0.5)
    qr_error_correction: str = "M"
    signature_data: Optional[str] = None
    organization_id: Optional[str] = None
    stamp_authority: Optional[str] = None
    timestamp: Optional[str] = None
    document_hash: Optional[str] = None
    validity_period: Optional[int] = None
    usage_counter: Optional[int] = None

    def validate(self) -> None:
        super().validate()
        # Обязательные поля для печати
        if not self.qr_data:
            raise FormBuilderError("QR data required for electronic stamp")
        if not self.border_text and not self.center_text:
            raise FormBuilderError(
                "Either border_text or center_text required for stamp"
            )
        if self.qr_size < 0.1 or self.qr_size > 0.5:
            raise FormBuilderError("QR size must be between 0.1 and 0.5")
        if self.qr_error_correction not in ("L", "M", "Q", "H"):
            raise FormBuilderError("Invalid QR error correction level")
        if self.border_style not in ("circle", "square", "oval", "custom"):
            raise FormBuilderError("Invalid border style")
        if self.qr_position not in ("center", "corner", "bottom", "top"):
            raise FormBuilderError("Invalid QR position")
        if self.qr_type not in ("qr", "datamatrix", "pdf417"):
            raise FormBuilderError("Unsupported QR type")
        if self.font_size < 6 or self.font_size > 24:
            raise FormBuilderError("Font size must be between 6 and 24")


@dataclass
class FormGroup:
    name: str
    element_ids: List[str] = field(default_factory=list)
    permissions: Optional[List[str]] = None
    security_level: str = "standard"


@dataclass
class FormLayout:
    kind: FormKind = FormKind.REGULAR
    layout_type: str = "grid"
    size: Tuple[int, int] = (210, 297)
    elements: List[FormElement] = field(default_factory=list)
    groups: List[FormGroup] = field(default_factory=list)
    template: Optional[str] = None
    security_metadata: Optional[Dict[str, Any]] = None


class FormBuilder:
    _custom_rules: Optional[Callable[[Dict[str, Any]], None]]

    def __init__(self, layout: Optional[FormLayout] = None) -> None:
        self.layout = layout or FormLayout()
        self._event_hooks: List[Callable[[str, Dict[str, Any]], None]] = []
        logger.info(
            "FormBuilder initialized: kind=%s, layout_type=%s",
            self.layout.kind,
            self.layout.layout_type,
        )

    def add_element(self, element: FormElement) -> None:
        if element.id is None:
            element.id = _generate_unique_id(str(element.type))
            logger.debug("Auto-assigned element id: %s", element.id)
        element.validate()
        self._check_unique_id(element)
        self.layout.elements.append(element)
        logger.debug("Added element: type=%s, id=%s", element.type, element.id)
        self._emit_event("add_element", element.as_dict())

    def remove_element_by_id(self, element_id: str) -> None:
        idx = self._find_element_idx(element_id)
        removed = self.layout.elements.pop(idx)
        logger.debug("Removed element by id=%s", element_id)
        self._emit_event("remove_element", removed.as_dict())

    def get_element(self, element_id: str) -> FormElement:
        idx = self._find_element_idx(element_id)
        return self.layout.elements[idx]

    def copy_element(self, element_id: str, new_id: Optional[str] = None) -> None:
        orig = copy.deepcopy(self.get_element(element_id))
        orig.id = new_id or _generate_unique_id(str(orig.type))
        self.add_element(orig)
        logger.info("Copied element %s to %s", element_id, orig.id)

    def move_element(self, element_id: str, new_index: int) -> None:
        idx = self._find_element_idx(element_id)
        elem = self.layout.elements.pop(idx)
        self.layout.elements.insert(new_index, elem)
        logger.info("Moved element %s to position %d", element_id, new_index)

    def group_elements(
        self,
        group_name: str,
        element_ids: List[str],
        permissions: Optional[List[str]] = None,
        security_level: str = "standard",
    ) -> None:
        ids_checked = [
            eid for eid in element_ids if any(e.id == eid for e in self.layout.elements)
        ]
        group = next((g for g in self.layout.groups if g.name == group_name), None)
        if group:
            group.element_ids = ids_checked
            group.permissions = permissions
            group.security_level = security_level
        else:
            self.layout.groups.append(
                FormGroup(
                    name=group_name,
                    element_ids=ids_checked,
                    permissions=permissions,
                    security_level=security_level,
                )
            )
        logger.info(
            "Group %s defined: %d elements, level=%s",
            group_name,
            len(ids_checked),
            security_level,
        )

    def apply_template(self, template_str: str) -> None:
        self.layout.template = template_str
        logger.info("Applied template: %s", template_str)
        self._emit_event("apply_template", {"template": template_str})

    def inject_variables(self, variable_map: Dict[str, Any]) -> None:
        filled = 0
        for el in self.layout.elements:
            if isinstance(el, VariableElement) and el.name in variable_map:
                el.value = variable_map[el.name]
                filled += 1
                logger.debug("Injected variable %s=%r", el.name, variable_map[el.name])
        logger.info("Injected %d variables", filled)
        self._emit_event("inject_variables", variable_map)

    def build(self) -> Dict[str, Any]:
        validate_form_structure(self.to_dict(), custom_rules=self.custom_rules)
        if self.layout.kind == FormKind.SPECIAL:
            self._ensure_audit_trail()
        logger.info(
            "Form built: kind=%s, %d elements",
            self.layout.kind,
            len(self.layout.elements),
        )
        result = self.to_dict()
        self._emit_event("build", result)
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.layout.kind.value,
            "layout_type": self.layout.layout_type,
            "size": self.layout.size,
            "elements": [el.as_dict() for el in self.layout.elements],
            "groups": [asdict(gr) for gr in self.layout.groups],
            "template": self.layout.template,
            "security_metadata": self.layout.security_metadata,
        }

    @property
    def custom_rules(self) -> Optional[Callable[[Dict[str, Any]], None]]:
        return getattr(self, "_custom_rules", None)

    def set_custom_validation(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        self._custom_rules = fn

    @classmethod
    def from_dict(cls: Type[FormBuilder], form_dict: Dict[str, Any]) -> FormBuilder:
        elements_in = form_dict.get("elements", [])
        elements: List[FormElement] = []
        for obj in elements_in:
            element_type = obj.get("type")
            if element_type == FormElementType.TABLE.value:
                elements.append(TableElement(**obj))
            elif element_type == FormElementType.IMAGE.value:
                elements.append(ImageElement(**obj))
            elif element_type == FormElementType.VARIABLE.value:
                elements.append(VariableElement(**obj))
            elif element_type == FormElementType.QR.value:
                elements.append(QRElement(**obj))
            elif element_type == FormElementType.WATERMARK.value:
                elements.append(WatermarkElement(**obj))
            elif element_type == FormElementType.SIGNATURE.value:
                elements.append(SignatureElement(**obj))
            elif element_type == FormElementType.AUDIT.value:
                elements.append(AuditElement(**obj))
            elif element_type == FormElementType.STAMP.value:
                elements.append(StampElement(**obj))
            else:
                elements.append(FormElement(**obj))
        groups = [FormGroup(**g) for g in form_dict.get("groups", [])]
        kind = FormKind(form_dict.get("kind", FormKind.REGULAR))
        layout_type = form_dict.get("layout_type", "grid")
        size_raw = form_dict.get("size", (210, 297))
        if (
            isinstance(size_raw, (list, tuple))
            and len(size_raw) == 2
            and all(isinstance(x, (int, float)) for x in size_raw)
        ):
            size = (int(size_raw[0]), int(size_raw[1]))
        else:
            size = (210, 297)
        template = form_dict.get("template")
        security_metadata = form_dict.get("security_metadata")
        layout = FormLayout(
            kind=kind,
            layout_type=layout_type,
            size=size,
            elements=elements,
            groups=groups,
            template=template,
            security_metadata=security_metadata,
        )
        return cls(layout=layout)

    def import_from_json(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        imported = FormBuilder.from_dict(data)
        self.layout = imported.layout
        logger.info("Form imported from %s", path)

    def export_to_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)
        logger.info("Form exported to %s", path)

    def _check_unique_id(self, elem: FormElement) -> None:
        if elem.id is None:
            return
        if any(e.id == elem.id for e in self.layout.elements):
            raise FormBuilderError(f"Element id '{elem.id}' already exists.")

    def _find_element_idx(self, element_id: str) -> int:
        for i, e in enumerate(self.layout.elements):
            if e.id == element_id:
                return i
        raise FormBuilderError(f"Element '{element_id}' not found.")

    def _ensure_audit_trail(self) -> None:
        has_audit = any(isinstance(el, AuditElement) for el in self.layout.elements)
        if not has_audit:
            audit_el = AuditElement(
                id=_generate_unique_id("audit"),
                action="form_built",
                timestamp=datetime.now().isoformat(),
            )
            self.layout.elements.append(audit_el)
            logger.info("Added automatic audit element")

    def _emit_event(self, event: str, payload: Dict[str, Any]) -> None:
        for hook in self._event_hooks:
            try:
                hook(event, payload)
            except Exception as ex:
                logger.warning("Event hook error: %r", ex)

    def add_event_hook(self, fn: Callable[[str, Dict[str, Any]], None]) -> None:
        self._event_hooks.append(fn)


def validate_form_structure(
    form_dict: Dict[str, Any],
    custom_rules: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> None:
    kind = FormKind(form_dict.get("kind", FormKind.REGULAR))
    layout_type = form_dict.get("layout_type")
    elements = form_dict.get("elements", [])
    if layout_type not in ("grid", "absolute"):
        raise FormBuilderError(f"Unsupported layout_type: {layout_type!r}")
    if not isinstance(elements, list):
        raise FormBuilderError("Form 'elements' must be a list")
    seen_ids = set()
    element_types = set()
    for elem in elements:
        if "type" not in elem:
            raise FormBuilderError("Each form element must have a type")
        eid = elem.get("id")
        if eid is not None:
            if eid in seen_ids:
                raise FormBuilderError(f"Duplicate element id: {eid}")
            seen_ids.add(eid)
        element_types.add(elem.get("type"))
    # Special form security validation
    if kind == FormKind.SPECIAL:
        validate_special_form_security(element_types)
    if custom_rules:
        custom_rules(form_dict)
    logger.debug("Form structure validated: kind=%s, %d elements", kind, len(elements))


def validate_special_form_security(element_types: Set[str]) -> None:
    """Для SPECIAL-форм: STAMP автоматически покрывает QR и SIGNATURE"""
    required_security = {
        FormElementType.QR.value,
        FormElementType.WATERMARK.value,
        FormElementType.SIGNATURE.value,
    }
    # STAMP как универсальный security элемент
    if FormElementType.STAMP.value in element_types:
        required_security.discard(FormElementType.QR.value)
        required_security.discard(FormElementType.SIGNATURE.value)
    missing = required_security - element_types
    if missing:
        missing_names = [t.replace("_", " ").title() for t in missing]
        raise FormBuilderError(
            f"Special form missing required security elements: {', '.join(missing_names)}. "
            f"Special forms must include QR code, watermark, and digital signature "
            f"(or electronic stamp which includes QR and signature)."
        )
    logger.debug("Special form security validation passed")


def import_from_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(
            f"JSON root in {path} must be an object (dict), got {type(data).__name__}"
        )
    return data


def export_to_json(form: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(form, f, ensure_ascii=False, indent=2)
