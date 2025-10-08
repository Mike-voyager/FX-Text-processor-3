"""RU: Расширяемая контракт-схема форм FX-Text-processor-3 с поддержкой плагинов, кастомных правил, валидации структуры и связей."""

"""EN: Extensible contract-driven schema for FX-Text-processor-3 forms; plugin, custom field/type, validation, i18n, and registry support."""

from typing import Dict, Any, List, Optional, Set, Tuple, Union, Callable
import logging
import copy

logger = logging.getLogger(__name__)


class SchemaError(Exception):
    """Ошибка схемы форм."""


class ValidationError(Exception):
    """Ошибка валидации формы."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        index: Optional[int] = None,
        nested: Optional[List["ValidationError"]] = None,
    ) -> None:
        super().__init__(message)
        self.field = field
        self.index = index
        self.nested = nested or []


FORM_SCHEMA_DEFAULT: Dict[str, Any] = {
    "version": "1.1",
    "required_keys": ["kind", "layout_type", "elements"],
    "element_types": {
        "label": {
            "fields": ["id", "label", "style"],
            "required": ["label"],
            "i18n": {"en": "Label", "ru": "Текст"},
            "desc": "Simple text label",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        },
        "input": {
            "fields": ["id", "label", "style", "placeholder"],
            "required": ["label"],
            "i18n": {"en": "Input", "ru": "Поле"},
            "desc": "Input field",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        },
        "qr": {
            "fields": ["id", "data", "size", "error_correction"],
            "required": ["data"],
            "i18n": {"en": "QR Code", "ru": "QR-код"},
            "desc": "QR element",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        },
        "table": {
            "fields": ["id", "rows", "cols", "data"],
            "required": ["rows", "cols"],
            "i18n": {"en": "Table", "ru": "Таблица"},
            "desc": "Table",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        },
        "variable": {
            "fields": ["id", "name", "value", "format"],
            "required": ["name"],
            "i18n": {"en": "Variable", "ru": "Переменная"},
            "desc": "Variable",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        },
        "image": {
            "fields": ["id", "path", "style"],
            "required": ["path"],
            "i18n": {"en": "Image", "ru": "Картинка"},
            "desc": "Image",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        },
        "signature": {
            "fields": ["id", "algorithm", "key_id"],
            "required": ["algorithm", "key_id"],
            "i18n": {"en": "Signature", "ru": "Подпись"},
            "desc": "Digital signature",
            "deprecated": False,
            "readonly": True,
            "hidden": False,
        },
        "watermark": {
            "fields": ["id", "text", "image_path", "opacity"],
            "required": ["text"],
            "i18n": {"en": "Watermark", "ru": "Водяной знак"},
            "desc": "Watermark",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        },
        "stamp": {
            "fields": ["id", "border_text", "center_text", "qr_data"],
            "required": ["border_text", "qr_data"],
            "i18n": {"en": "Electronic Stamp", "ru": "Электронная печать"},
            "desc": "Electronic stamp",
            "deprecated": False,
            "readonly": True,
            "hidden": False,
        },
        "audit": {
            "fields": ["id", "user_id", "action", "timestamp"],
            "required": ["action"],
            "i18n": {"en": "Audit", "ru": "Аудит"},
            "desc": "Audit log element",
            "deprecated": False,
            "readonly": True,
            "hidden": True,
        },
        "alias": {
            "fields": ["id", "alias_of", "alias_label"],
            "required": ["alias_of"],
            "i18n": {"en": "Alias", "ru": "Алиас"},
            "desc": "Element alias",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        },
        "group": {
            "fields": ["id", "elements", "group_kind"],
            "required": ["elements"],
            "i18n": {"en": "Group", "ru": "Группа"},
            "desc": "Element group",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        },
        "extension": {
            "fields": ["id", "extra"],
            "required": ["extra"],
            "i18n": {"en": "Extension", "ru": "Расширение"},
            "desc": "Plugin/extension point",
            "deprecated": False,
            "readonly": False,
            "hidden": True,
        },
    },
    "group_fields": ["name", "element_ids", "permissions", "security_level"],
    "security_levels": ["standard", "advanced", "special"],
    "compliance": {
        "special": {
            "predicate": "all(x in types for x in ['qr','watermark','signature','stamp'])",
        },
        "regular": {
            "must_have": [],
        },
    },
    "max_nesting_depth": 50,
    "i18n": {
        "form": {"en": "Form", "ru": "Форма"},
        "elements": {"en": "Elements", "ru": "Элементы"},
    },
}


class FormSchema:
    """
    Contract-driven, extensible schema engine for FX-Text-processor-3.
    Supports plugins, custom types/fields, compliance checks, i18n/description, deprecated/readonly, and registry linking.

    text
    Example usage:
        schema = FormSchema(FORM_SCHEMA_DEFAULT)
        is_valid = schema.validate_form(form_dict)
        types = schema.list_supported_element_types()
        schema.register_element_type("custom", {...})
        schema.register_field_validator("input", "placeholder", custom_validator)
    """

    def __init__(self, spec: Dict[str, Any], version: str = "1.1") -> None:
        self.spec: Dict[str, Any] = copy.deepcopy(spec)
        self.version = version
        self.field_validators: Dict[Tuple[str, str], List[Callable[[Any], Union[str, None]]]] = {}

    def validate_form(self, form: Dict[str, Any]) -> bool:
        """Validates full structure, required keys, unique IDs, depth, element fields, custom field validators, aliases/groups links, compliance."""
        errors: List[ValidationError] = []
        required = set(self.spec.get("required_keys", []))
        actual = set(form.keys())
        missing = required - actual
        if missing:
            errors.append(ValidationError(f"Missing required form keys: {missing}"))
        elements = form.get("elements", [])
        if not isinstance(elements, list):
            errors.append(ValidationError("Form 'elements' must be a list."))
        # Nesting depth check
        try:
            self.check_nesting_depth(form, self.spec.get("max_nesting_depth", 50))
        except ValidationError as ve:
            errors.append(ve)
        # Unique id check
        try:
            self.check_unique_ids(form)
        except ValidationError as ve:
            errors.append(ve)
        elt_types = self.list_supported_element_types()
        # Element-level validation
        for i, el in enumerate(elements):
            t = el.get("type")
            if not t or t not in elt_types:
                errors.append(ValidationError(f"Unknown element type: {t}", field="type", index=i))
                continue
            schema = self.get_element_schema(t)
            req = set(schema.get("required", [])) if schema else set()
            present = set(el.keys())
            missing_fields = req - present
            if missing_fields:
                errors.append(
                    ValidationError(
                        f"Element '{t}' missing required fields: {missing_fields}", index=i
                    )
                )
            # Deprecated/readonly/hidden fields
            for field in present:
                fspec = schema.get("fields", []) if schema else []
                # field 'type' всегда допустим для любого элемента!
                if field != "type" and field not in fspec and not field.startswith("_"):
                    errors.append(
                        ValidationError(f"Unknown element field: {field}", field=field, index=i)
                    )
                # Run custom validators
                val_key = (t, field)
                for validator in self.field_validators.get(val_key, []):
                    msg = validator(el[field])
                    if msg:
                        errors.append(
                            ValidationError(
                                f"Custom validation failed for {field}: {msg}", field=field, index=i
                            )
                        )
            # Aliases/groups links
            if t == "alias":
                target_id = el.get("alias_of")
                if not any(e.get("id") == target_id for e in elements):
                    errors.append(
                        ValidationError(
                            f"Alias target id '{target_id}' does not exist.",
                            field="alias_of",
                            index=i,
                        )
                    )
            if t == "group":
                ids = el.get("elements", [])
                for eid in ids:
                    if not any(e.get("id") == eid for e in elements):
                        errors.append(
                            ValidationError(
                                f"Group references missing id: {eid}", field="elements", index=i
                            )
                        )
        # Group structure
        groups = form.get("groups", [])
        for gi, gr in enumerate(groups):
            for field in self.spec.get("group_fields", []):
                if field not in gr:
                    errors.append(
                        ValidationError(f"Group missing field: {field}", field=field, index=gi)
                    )
        # Compliance check (if exists)
        compliance_level = form.get("kind", "regular")
        try:
            self.is_compliant(form, str(compliance_level))
        except ValidationError as ve:
            errors.append(ve)
        if errors:
            raise ValidationError(f"Validation failed: {[str(e) for e in errors]}", nested=errors)
        logger.info("Form passed schema validation.")
        return True

    def get_element_schema(self, type_name: str) -> Optional[Dict[str, Any]]:
        el = self.spec.get("element_types", {}).get(type_name)
        if isinstance(el, dict):
            return el
        return None

    def list_supported_element_types(self) -> List[str]:
        """All supported types."""
        return sorted(self.spec.get("element_types", {}).keys())

    def describe(self, include_i18n: bool = False) -> Dict[str, Any]:
        """Returns schema description, optionally with i18n and field metadata."""
        sd = copy.deepcopy(self.spec)
        if not include_i18n:
            for et in sd.get("element_types", {}).values():
                et.pop("i18n", None)
        return sd

    def is_compliant(self, form: Dict[str, Any], compliance_level: str) -> bool:
        """
        Checks compliance.
        supports predicate (eval) or must_have.
        Example predicate: "all(x in types for x in [...])"
        """
        cmp_spec = self.spec.get("compliance", {}).get(compliance_level, {})
        elements = form.get("elements", [])
        types: Set[str] = {e.get("type") for e in elements}
        # Predicate-support
        predicate = cmp_spec.get("predicate")
        must_have = set(cmp_spec.get("must_have", []))
        missing = set()
        if predicate:
            try:
                is_ok = eval(predicate, {"types": types, "all": all, "any": any})
            except Exception as ex:
                raise ValidationError(f"Compliance predicate error: {ex}")
            if not is_ok:
                missing = set([s for s in predicate.split("'") if s in types])
                raise ValidationError(f"Form not compliant: predicate failed. Missing: {missing}")
        if must_have:
            missing = must_have - types
            if missing:
                raise ValidationError(f"Form not compliant: missing required types {missing}")
        logger.info("[COMPLIANCE] form passed for level %r.", compliance_level)
        return True

    def check_nesting_depth(self, obj: Any, max_depth: int = 50) -> bool:
        """Recursively checks object for nesting depth limit [protection]."""

        def _check(val: Any, depth: int) -> None:
            if depth > max_depth:
                raise ValidationError(f"Nesting depth > {max_depth}", index=depth)
            if isinstance(val, dict):
                for v in val.values():
                    _check(v, depth + 1)
            elif isinstance(val, list):
                for v in val:
                    _check(v, depth + 1)

        _check(obj, 0)
        return True

    def check_unique_ids(self, form: Dict[str, Any]) -> bool:
        """Checks unique ids in elements/groups."""
        ids: Set[str] = set()
        for i, el in enumerate(form.get("elements", [])):
            eid = el.get("id")
            if eid:
                if eid in ids:
                    raise ValidationError(f"Duplicate element id: {eid}", field="id", index=i)
                ids.add(eid)
        for gi, gr in enumerate(form.get("groups", [])):
            name = gr.get("name")
            if name and name in ids:
                raise ValidationError(
                    f"Duplicate group id (name): {name}", field="group:name", index=gi
                )
            ids.add(name)
        return True

    def register_element_type(self, type_name: str, schema: Dict[str, Any]) -> None:
        """Dynamic add type."""
        self.spec.setdefault("element_types", {})[type_name] = schema
        logger.info("Registered new element type: %r", type_name)

    def unregister_element_type(self, type_name: str) -> None:
        """Remove type."""
        et = self.spec.get("element_types", {})
        if type_name in et:
            del et[type_name]
            logger.info("Unregistered element type: %r", type_name)

    def register_field_validator(
        self, type_name: str, field_name: str, validator: Callable[[Any], Union[str, None]]
    ) -> None:
        """Custom field-level validator."""
        key = (type_name, field_name)
        self.field_validators.setdefault(key, []).append(validator)
        logger.info("Registered field validator for %r.%r", type_name, field_name)


def form_schema_from_registry(registry: Any) -> FormSchema:
    """Auto-generates schema from registry (form_elements.FormElementRegistry-compatible)."""
    element_types: Dict[str, Any] = {}
    for key in getattr(registry, "all_types", lambda: [])():
        cls = registry.get(key)
        doc = getattr(cls, "__doc__", "") if cls else ""
        fields = getattr(cls, "__dataclass_fields__", {})
        et_entry = {
            "fields": list(fields.keys()),
            "required": [f for f in fields if fields[f].default is None],
            "desc": doc or "",
            "deprecated": False,
            "readonly": False,
            "hidden": False,
        }
        element_types[key] = et_entry
    spec = copy.deepcopy(FORM_SCHEMA_DEFAULT)
    spec["element_types"].update(element_types)
    return FormSchema(spec)
