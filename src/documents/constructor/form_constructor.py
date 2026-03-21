"""Form constructor - creates Document from DocumentType.

Provides:
- FormConstructor: Main class for document creation
"""

from datetime import datetime
from pathlib import Path
from typing import Any

from src.documents.types.inheritance import resolve_schema
from src.documents.types.registry import TypeRegistry
from src.documents.types.type_schema import FieldType, TypeSchema


class FormConstructor:
    """Конструктор форм документов.

    Создаёт Document из шаблона (DocumentType + TypeSchema).

    Пример использования:
        >>> constructor = FormConstructor()
        >>> doc = constructor.create_from_type("DVN", title="Test Note")
        >>> print(doc.metadata.title)
        'Test Note'
    """

    def __init__(self, registry: TypeRegistry | None = None) -> None:
        """Инициализирует конструктор.

        Args:
            registry: Экземпляр TypeRegistry (по умолчанию - singleton).
        """
        self._registry = registry or TypeRegistry.get_instance()

    def create_from_type(
        self, type_code: str, **initial_values: Any
    ) -> dict[str, Any]:
        """Создаёт документ из типа.

        Args:
            type_code: Код типа документа (например, "DVN", "INV").
            **initial_values: Начальные значения для полей.

        Returns:
            Словарь с данными документа, готовыми для сериализации
            или создания полной модели Document.

        Raises:
            KeyError: Если тип документа не найден.
        """
        # Получаем тип документа
        doc_type = self._registry.get(type_code)

        # Разрешаем схему (наследование полей)
        schema = resolve_schema(doc_type, self._registry)

        # Создаём начальные данные
        data: dict[str, Any] = {
            "_type": type_code,
            "_code": doc_type.code,
            "_name": doc_type.name,
            "metadata": {
                "title": initial_values.get("title", ""),
                "document_type": type_code,
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat(),
                "author": initial_values.get("author", "operator"),
                "version": "1.0",
            },
            "fields": {},
        }

        # Заполняем поля значениями по умолчанию
        for field_def in schema.fields:
            if field_def.name in initial_values:
                # Используем переданное значение
                data["fields"][field_def.name] = initial_values[field_def.name]
            elif field_def.default_value is not None:
                # Используем значение по умолчанию
                data["fields"][field_def.name] = field_def.default_value
            else:
                # Пустое значение
                data["fields"][field_def.name] = self._get_empty_value(
                    field_def.field_type
                )

        return data

    def create_from_template(self, template_path: Path) -> dict[str, Any]:
        """Создаёт документ из шаблона.

        Args:
            template_path: Путь к файлу шаблона (.fxstpl).

        Returns:
            Словарь с данными документа.
        """
        import json

        with open(template_path, "r", encoding="utf-8") as f:
            template_data = json.load(f)

        # Проверяем тип документа из шаблона
        type_code = template_data.get("_type")
        if not type_code:
            raise ValueError("Template missing '_type' field")

        # Создаём из типа с переопределёнными значениями из шаблона
        initial_values = template_data.get("fields", {})
        return self.create_from_type(type_code, **initial_values)

    def _get_empty_value(self, field_type: FieldType) -> Any:
        """Возвращает пустое значение для типа поля."""
        empty_values = {
            FieldType.STATIC_TEXT: "",
            FieldType.TEXT_INPUT: "",
            FieldType.NUMBER_INPUT: 0,
            FieldType.DATE_INPUT: None,
            FieldType.TABLE: [],
            FieldType.EXCEL_IMPORT: None,
            FieldType.CALCULATED: None,
            FieldType.QR: None,
            FieldType.BARCODE: None,
            FieldType.SIGNATURE: None,
            FieldType.STAMP: None,
            FieldType.CHECKBOX: False,
            FieldType.DROPDOWN: None,
            FieldType.RADIO_GROUP: None,
            FieldType.CURRENCY: 0.0,
            FieldType.MULTI_LINE_TEXT: "",
            FieldType.PHONE: "",
            FieldType.EMAIL: "",
        }
        return empty_values.get(field_type, None)

    def validate_data(
        self, type_code: str, data: dict[str, Any]
    ) -> dict[str, list[str]]:
        """Валидирует данные документа по схеме типа.

        Args:
            type_code: Код типа документа.
            data: Данные для валидации.

        Returns:
            Словарь {field_name: [errors]} - пустой если валидно.
        """
        doc_type = self._registry.get(type_code)
        schema = resolve_schema(doc_type, self._registry)

        errors: dict[str, list[str]] = {}

        fields_data = data.get("fields", {})

        for field_def in schema.fields:
            value = fields_data.get(field_def.name)

            # Проверка обязательности
            if field_def.required and (
                value is None or value == "" or value == []
            ):
                if field_def.name not in errors:
                    errors[field_def.name] = []
                errors[field_def.name].append(f"Field '{field_def.label}' is required")
                continue

            # Проверка типа
            if value is not None and value != "":
                field_errors = schema.validate_value(field_def.name, value)
                if field_errors:
                    errors[field_def.name] = field_errors

        return errors

    def get_form_schema(self, type_code: str) -> TypeSchema:
        """Возвращает схему полей для типа документа.

        Args:
            type_code: Код типа документа.

        Returns:
            TypeSchema с определениями всех полей.
        """
        doc_type = self._registry.get(type_code)
        return resolve_schema(doc_type, self._registry)

    def list_available_types(self) -> list[tuple[str, str]]:
        """Возвращает список доступных типов документов.

        Returns:
            Список кортежей (code, name).
        """
        return [(dt.code, dt.name) for dt in self._registry.list_all()]