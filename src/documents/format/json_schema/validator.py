"""Валидатор JSON Schema для документов и шаблонов.

Предоставляет:
- SchemaValidator: Валидация данных по JSON Schema
- SchemaRegistry: Реестр схем

Example:
    >>> from src.documents.format.json_schema.validator import SchemaValidator
    >>> validator = SchemaValidator()
    >>> result = validator.validate_document(document_data)
    >>> if result.is_valid:
    ...     print("Document is valid")
    ... else:
    ...     for error in result.errors:
    ...         print(f"Error: {error}")
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Final

# Путь к директории с JSON Schema
SCHEMA_DIR: Final[Path] = Path(__file__).parent

logger: Final = logging.getLogger(__name__)


@dataclass
class ValidationError:
    """Ошибка валидации.

    Attributes:
        message: Сообщение об ошибке
        path: Путь к полю с ошибкой (JSONPath-style)
        schema_path: Путь в схеме
        severity: Уровень ошибки (error, warning)
    """

    message: str
    path: str = ""
    schema_path: str = ""
    severity: str = "error"


@dataclass
class ValidationResult:
    """Результат валидации.

    Attributes:
        is_valid: Валидны ли данные
        errors: Список ошибок
        warnings: Список предупреждений
    """

    is_valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)

    def add_error(self, message: str, path: str = "", schema_path: str = "") -> None:
        """Добавляет ошибку."""
        self.errors.append(ValidationError(message, path, schema_path, "error"))
        self.is_valid = False

    def add_warning(self, message: str, path: str = "", schema_path: str = "") -> None:
        """Добавляет предупреждение."""
        self.warnings.append(ValidationError(message, path, schema_path, "warning"))


class SchemaRegistry:
    """Реестр JSON Schema.

    Хранит и предоставляет доступ к JSON Schema для валидации
    документов и шаблонов.

    Example:
        >>> registry = SchemaRegistry()
        >>> doc_schema = registry.get_document_schema("1.0")
        >>> template_schema = registry.get_template_schema("1.0")
    """

    def __init__(self) -> None:
        """Инициализирует реестр схем."""
        self._schemas: dict[str, dict[str, Any]] = {}
        self._logger = logging.getLogger(__name__)
        self._load_schemas()

    def _load_schemas(self) -> None:
        """Загружает схемы из файлов."""
        schema_files = [
            ("document_v1.0", "document_v1.0.json"),
            ("template_v1.0", "template_v1.0.json"),
        ]

        for name, filename in schema_files:
            schema_path = SCHEMA_DIR / filename
            if schema_path.exists():
                try:
                    with open(schema_path, "r", encoding="utf-8") as f:
                        self._schemas[name] = json.load(f)
                    self._logger.debug(f"Loaded schema: {name}")
                except (json.JSONDecodeError, IOError) as e:
                    self._logger.warning(f"Failed to load schema {name}: {e}")
            else:
                self._logger.warning(f"Schema file not found: {schema_path}")
                # Загружаем embedded схемы как fallback
                self._schemas[name] = self._get_embedded_schema(name)

    def _get_embedded_schema(self, name: str) -> dict[str, Any]:
        """Возвращает embedded схему если файл не найден.

        Args:
            name: Имя схемы

        Returns:
            Словарь со схемой
        """
        # Базовая схема документа
        if name == "document_v1.0":
            return {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "fx-document-v1.0",
                "title": "FX Super Document",
                "description": "Schema for FX Text Processor document files",
                "type": "object",
                "required": ["format_version", "generator", "document"],
                "properties": {
                    "format_version": {
                        "type": "string",
                        "enum": ["1.0"],
                        "description": "Document format version",
                    },
                    "generator": {
                        "type": "string",
                        "description": "Application that generated the document",
                    },
                    "document": {
                        "type": "object",
                        "required": ["metadata", "sections"],
                        "properties": {
                            "metadata": {
                                "type": "object",
                                "properties": {
                                    "title": {"type": "string"},
                                    "author": {"type": "string"},
                                    "created": {"type": "string", "format": "date-time"},
                                    "modified": {"type": "string", "format": "date-time"},
                                    "version": {"type": "string"},
                                },
                            },
                            "sections": {"type": "array", "items": {"type": "object"}},
                        },
                    },
                },
            }

        # Базовая схема шаблона
        if name == "template_v1.0":
            return {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "fx-template-v1.0",
                "title": "FX Super Template",
                "description": "Schema for FX Text Processor template files",
                "type": "object",
                "required": ["format_version", "generator", "template"],
                "properties": {
                    "format_version": {
                        "type": "string",
                        "enum": ["1.0"],
                        "description": "Template format version",
                    },
                    "generator": {
                        "type": "string",
                        "description": "Application that generated the template",
                    },
                    "template": {
                        "type": "object",
                        "required": ["fields"],
                        "properties": {
                            "fields": {"type": "array"},
                            "version": {"type": "string"},
                            "compatibility_version": {"type": "string"},
                            "deprecated_fields": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                },
            }

        return {}

    def get_schema(self, name: str) -> dict[str, Any] | None:
        """Возвращает схему по имени.

        Args:
            name: Имя схемы (например, "document_v1.0")

        Returns:
            Словарь со схемой или None
        """
        return self._schemas.get(name)

    def get_document_schema(self, version: str = "1.0") -> dict[str, Any] | None:
        """Возвращает схему документа.

        Args:
            version: Версия формата (по умолчанию "1.0")

        Returns:
            Словарь со схемой или None
        """
        return self.get_schema(f"document_v{version}")

    def get_template_schema(self, version: str = "1.0") -> dict[str, Any] | None:
        """Возвращает схему шаблона.

        Args:
            version: Версия формата (по умолчанию "1.0")

        Returns:
            Словарь со схемой или None
        """
        return self.get_schema(f"template_v{version}")


class SchemaValidator:
    """Валидатор данных по JSON Schema.

    Выполняет валидацию документов и шаблонов.
    Поддерживает валидацию с детальными сообщениями об ошибках.

    Example:
        >>> validator = SchemaValidator()
        >>> document_data = {"format_version": "1.0", ...}
        >>> result = validator.validate_document(document_data)
        >>> if not result.is_valid:
        ...     for error in result.errors:
        ...         print(f"{error.path}: {error.message}")
    """

    def __init__(self) -> None:
        """Инициализирует валидатор."""
        self._registry = SchemaRegistry()
        self._logger = logging.getLogger(__name__)

    def validate_document(
        self,
        data: dict[str, Any],
        version: str = "1.0",
    ) -> ValidationResult:
        """Валидирует данные документа.

        Args:
            data: Данные документа
            version: Версия схемы

        Returns:
            Результат валидации
        """
        schema = self._registry.get_document_schema(version)
        if schema is None:
            result = ValidationResult(is_valid=False)
            result.add_error(f"Document schema v{version} not found")
            return result

        return self._validate_with_schema(data, schema)

    def validate_template(
        self,
        data: dict[str, Any],
        version: str = "1.0",
    ) -> ValidationResult:
        """Валидирует данные шаблона.

        Args:
            data: Данные шаблона
            version: Версия схемы

        Returns:
            Результат валидации
        """
        schema = self._registry.get_template_schema(version)
        if schema is None:
            result = ValidationResult(is_valid=False)
            result.add_error(f"Template schema v{version} not found")
            return result

        return self._validate_with_schema(data, schema)

    def _validate_with_schema(
        self,
        data: dict[str, Any],
        schema: dict[str, Any],
    ) -> ValidationResult:
        """Валидирует данные по схеме.

        Args:
            data: Данные для валидации
            schema: JSON Schema

        Returns:
            Результат валидации
        """
        result = ValidationResult(is_valid=True)

        # Проверка обязательных полей
        required = schema.get("required", [])
        for field_name in required:
            if field_name not in data:
                result.add_error(f"Missing required field: {field_name}", path=field_name)

        # Проверка типов
        properties = schema.get("properties", {})
        for prop_name, prop_schema in properties.items():
            if prop_name in data:
                prop_value = data[prop_name]
                prop_type = prop_schema.get("type")

                if prop_type and not self._check_type(prop_value, prop_type):
                    result.add_error(
                        f"Expected type {prop_type}, got {type(prop_value).__name__}",
                        path=prop_name,
                    )

                # Проверка enum
                enum_values = prop_schema.get("enum")
                if enum_values and prop_value not in enum_values:
                    result.add_error(f"Value must be one of: {enum_values}", path=prop_name)

        return result

    def _check_type(self, value: Any, expected_type: str) -> bool:
        """Проверяет соответствие типа.

        Args:
            value: Значение
            expected_type: Ожидаемый тип

        Returns:
            True если тип соответствует
        """
        type_map: dict[str, type | tuple[type, ...]] = {
            "string": str,
            "integer": int,
            "number": (int, float),
            "boolean": bool,
            "array": list,
            "object": dict,
            "null": type(None),
        }

        expected = type_map.get(expected_type)
        if expected is None:
            return True  # Неизвестный тип — не проверяем

        return isinstance(value, expected)

    def validate_field_type(
        self,
        field_type: str,
        value: Any,
    ) -> ValidationResult:
        """Валидирует значение поля по его типу.

        Args:
            field_type: Тип поля (из FieldType)
            value: Значение

        Returns:
            Результат валидации
        """
        result = ValidationResult(is_valid=True)

        type_validators: dict[str, Callable[[Any], bool]] = {
            "text_input": lambda v: isinstance(v, str),
            "number_input": lambda v: isinstance(v, (int, float)),
            "date_input": lambda v: isinstance(v, str),  # ISO format
            "checkbox": lambda v: isinstance(v, bool),
            "dropdown": lambda v: isinstance(v, str),
            "email": lambda v: isinstance(v, str) and "@" in v,
            "phone": lambda v: isinstance(v, str),
        }

        validator = type_validators.get(field_type)
        if validator and value is not None:
            if not validator(value):
                result.add_error(f"Invalid value for type {field_type}: {value!r}")

        return result


__all__ = [
    "SchemaValidator",
    "SchemaRegistry",
    "ValidationError",
    "ValidationResult",
]
