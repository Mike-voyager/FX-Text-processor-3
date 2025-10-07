"""RU: Базовые и расширенные классы элементов форм для FX-Text-processor-3.
Поддержка registry-паттерна, алиасов, группировки, extension-point для плагинов, сбор неиспользуемых полей,
auto-unregister, приоритетов, строгой валидации type/id, docstring-метаданных и unit-тест для edge-case.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, Optional, List, Type, TypeVar, Callable, Union, Tuple
from enum import Enum
import copy
import re
import logging

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="BaseFormElement")

__all__ = [
    "BaseFormElement",
    "AliasFormElement",
    "GroupFormElement",
    "ExtensionFormElement",
    "element_from_dict",
    "FormElementRegistry",
    "element_class",
]


class ElementKind(str, Enum):
    BASE = "base"
    EXTENSION = "extension"
    ALIAS = "alias"
    GROUP = "group"


class FormElementRegistry:
    """Глобальный реестр элементов форм для кастомных расширений и плагинов."""

    _registry: Dict[str, Tuple[Type["BaseFormElement"], str, int]] = {}

    @classmethod
    def register(
        cls, type_key: str, element_cls: Type["BaseFormElement"], order: int = 100
    ) -> None:
        key = type_key.lower().strip()
        doc = element_cls.__doc__ if element_cls.__doc__ else ""
        if key in cls._registry:
            logger.warning(
                f"Re-registering element type '{key}', was {cls._registry[key][0]}, now {element_cls}"
            )
        cls._registry[key] = (element_cls, doc, order)

    @classmethod
    def get(cls, type_key: str) -> Optional[Type["BaseFormElement"]]:
        key = (type_key or "").lower().strip()
        triple = cls._registry.get(key)
        return triple[0] if triple else None

    @classmethod
    def doc(cls, type_key: str) -> str:
        key = (type_key or "").lower().strip()
        triple = cls._registry.get(key)
        return triple[1] if triple else ""

    @classmethod
    def unregister(cls, type_key: str) -> None:
        key = type_key.lower().strip()
        if key in cls._registry:
            del cls._registry[key]

    @classmethod
    def all_types(cls) -> List[str]:
        # return keys sorted by order
        return [k for k, _ in sorted(cls._registry.items(), key=lambda x: x[1][2])]


def element_class(
    type_key: str, order: int = 100
) -> Callable[[Type["BaseFormElement"]], Type["BaseFormElement"]]:
    """Декоратор для auto-registration кастомных/плагинных типов"""

    def wrapper(cls: Type["BaseFormElement"]) -> Type["BaseFormElement"]:
        FormElementRegistry.register(type_key, cls, order=order)
        return cls

    return wrapper


@dataclass
class BaseFormElement:
    """Базовый класс расширенного элемента формы."""

    type: str
    id: Optional[str] = None
    label: Optional[str] = None
    style: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None

    kind: ElementKind = ElementKind.BASE
    _unknown_attrs: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def as_dict(self) -> Dict[str, Any]:
        if hasattr(self, "__dataclass_fields__"):
            d = asdict(self)
        else:
            d = dict(self.__dict__)
        if self._unknown_attrs:
            d["_unknown_attrs"] = dict(self._unknown_attrs)
        return d

    def validate(self) -> None:
        if not self.type or not isinstance(self.type, str) or not self.type.strip():
            raise ValueError("Element type must be string and non-empty")
        # strict ID: alphanumeric, optional [_-]
        if self.id is not None:
            if not isinstance(self.id, str) or not re.fullmatch(r"^[a-zA-Z0-9_\-]+$", self.id):
                raise ValueError("Element id must be an alphanumeric string (a-zA-Z0-9_-) or None")

    @classmethod
    def from_dict(cls: Type[T], data: Dict[str, Any], collect_unused: bool = False) -> T:
        allowed = set(f.name for f in cls.__dataclass_fields__.values() if f.init)
        filtered = {k: v for k, v in data.items() if k in allowed}
        unknown = {k: v for k, v in data.items() if k not in allowed}
        obj = cls(**filtered)
        if collect_unused and unknown:
            obj._unknown_attrs.update(unknown)
        return obj


@element_class("alias", order=10)
@dataclass
class AliasFormElement(BaseFormElement):
    """Элемент-алиас: ссылается на другой элемент по id или имени."""

    alias_of: str = ""
    alias_label: Optional[str] = None

    kind: ElementKind = ElementKind.ALIAS

    def validate(self) -> None:
        super().validate()
        if not isinstance(self.alias_of, str) or not self.alias_of.strip():
            raise ValueError("Alias must declare alias_of (id or name, str, non-empty)")


@element_class("group", order=20)
@dataclass
class GroupFormElement(BaseFormElement):
    """Группа элементов для batch и структурных операций (ids of children)."""

    elements: List[str] = field(default_factory=list)
    group_kind: str = "default"
    kind: ElementKind = ElementKind.GROUP

    def validate(self) -> None:
        super().validate()
        if (
            not self.elements
            or not isinstance(self.elements, list)
            or not all(isinstance(e, str) for e in self.elements)
        ):
            raise ValueError("GroupFormElement must have a non-empty list of element ids (str)")


@element_class("extension", order=999)
@dataclass
class ExtensionFormElement(BaseFormElement):
    """Элемент произвольного типа для системных плагинов и future-расширений."""

    extra: Dict[str, Any] = field(default_factory=dict)
    kind: ElementKind = ElementKind.EXTENSION

    def validate(self) -> None:
        super().validate()
        if self.extra is not None and not isinstance(self.extra, dict):
            raise ValueError("Extension element 'extra' must be dict")


# Регистрация встроенного базового класса (для обратной совместимости)
FormElementRegistry.register("base", BaseFormElement, order=0)


def element_from_dict(data: Dict[str, Any], collect_unused: bool = False) -> BaseFormElement:
    """
    Factory function to create a form element instance from a dictionary.
    Uses the 'type' key to determine the element class.
    """
    type_key = data.get("type", "base")
    cls = FormElementRegistry.get(type_key) or BaseFormElement
    return cls.from_dict(data, collect_unused=collect_unused)
