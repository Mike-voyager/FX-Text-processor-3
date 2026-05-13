"""Form constructor - creates structured forms from templates.

Provides:
- FormConstructor: Main class for form creation, duplication, and merging
- FormInstance: Data class representing a form instance
- FormTemplate: Data class representing a form template
- ValidationReport: Data class for validation results

Example:
    >>> from src.documents.constructor.form_constructor import FormConstructor
    >>> from src.documents.types.registry import TypeRegistry
    >>> from src.documents.constructor.form_validator import FormValidator
    >>> registry = TypeRegistry.get_instance()
    >>> validator = FormValidator()
    >>> constructor = FormConstructor(registry, validator)
    >>> form = constructor.create_form("DVN", "44", "K53")
"""

from __future__ import annotations

import logging
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID, uuid4

if TYPE_CHECKING:
    from src.documents.constructor.form_validator import FormValidator
    from src.documents.types.registry import TypeRegistry
    from src.documents.types.type_schema import FieldDefinition

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FormTemplate:
    """Шаблон формы для создания документов.

    Attributes:
        type_code: Код типа документа (например, "DVN", "INV").
        subtype: Код подтипа (например, "44", "01").
        series: Серия документа (например, "K53").
        field_defaults: Значения полей по умолчанию.
        metadata: Метаданные шаблона.
        template_id: Уникальный идентификатор шаблона.
    """

    type_code: str
    subtype: str
    series: str
    field_defaults: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    template_id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        """Валидация после инициализации."""
        if not self.type_code:
            raise ValueError("type_code cannot be empty")


@dataclass
class FormInstance:
    """Экземпляр формы документа.

    Attributes:
        form_id: Уникальный идентификатор формы.
        type_code: Код типа документа.
        subtype: Код подтипа.
        series: Серия документа.
        index: Полный индекс документа (например, "DVN-44-K53-IX").
        fields: Значения полей формы.
        metadata: Метаданные формы.
        created_at: Время создания.
        modified_at: Время последнего изменения.
        status: Статус формы (draft, filled, validated, signed, etc.).
        parent_id: ID родительской формы (при дублировании).
        merged_from: Список ID форм, из которых была создана merge.
    """

    form_id: UUID = field(default_factory=uuid4)
    type_code: str = ""
    subtype: str = ""
    series: str = ""
    index: str = ""
    fields: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    modified_at: datetime = field(default_factory=datetime.now)
    status: str = "draft"
    parent_id: UUID | None = None
    merged_from: list[UUID] = field(default_factory=list)

    def update_field(self, field_id: str, value: Any) -> None:
        """Обновляет значение поля.

        Args:
            field_id: Идентификатор поля.
            value: Новое значение.
        """
        self.fields[field_id] = value
        self.modified_at = datetime.now()

    def get_field(self, field_id: str, default: Any = None) -> Any:
        """Возвращает значение поля.

        Args:
            field_id: Идентификатор поля.
            default: Значение по умолчанию.

        Returns:
            Значение поля или default.
        """
        return self.fields.get(field_id, default)

    def to_dict(self) -> dict[str, Any]:
        """Сериализует форму в словарь.

        Returns:
            Словарь с данными формы.
        """
        return {
            "form_id": str(self.form_id),
            "type_code": self.type_code,
            "subtype": self.subtype,
            "series": self.series,
            "index": self.index,
            "fields": deepcopy(self.fields),
            "metadata": deepcopy(self.metadata),
            "created_at": self.created_at.isoformat(),
            "modified_at": self.modified_at.isoformat(),
            "status": self.status,
            "parent_id": str(self.parent_id) if self.parent_id else None,
            "merged_from": [str(fid) for fid in self.merged_from],
        }


@dataclass
class ValidationReport:
    """Отчёт о валидации формы.

    Attributes:
        is_valid: True если форма валидна.
        field_errors: Словарь ошибок {field_id: [messages]}.
        form_errors: Список ошибок уровня формы.
        warnings: Список предупреждений.
        timestamp: Время валидации.
    """

    is_valid: bool = True
    field_errors: dict[str, list[str]] = field(default_factory=dict)
    form_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def add_field_error(self, field_id: str, message: str) -> None:
        """Добавляет ошибку поля.

        Args:
            field_id: Идентификатор поля.
            message: Сообщение об ошибке.
        """
        if field_id not in self.field_errors:
            self.field_errors[field_id] = []
        self.field_errors[field_id].append(message)
        self.is_valid = False

    def add_form_error(self, message: str) -> None:
        """Добавляет ошибку уровня формы.

        Args:
            message: Сообщение об ошибке.
        """
        self.form_errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        """Добавляет предупреждение.

        Args:
            message: Текст предупреждения.
        """
        self.warnings.append(message)

    def merge(self, other: ValidationReport) -> ValidationReport:
        """Объединяет с другим отчётом.

        Args:
            other: Другой отчёт для объединения.

        Returns:
            Новый объединённый отчёт.
        """
        merged = ValidationReport(
            is_valid=self.is_valid and other.is_valid,
            field_errors=deepcopy(self.field_errors),
            form_errors=self.form_errors.copy(),
            warnings=self.warnings.copy(),
        )

        # Объединяем ошибки полей
        for field_id, errors in other.field_errors.items():
            if field_id not in merged.field_errors:
                merged.field_errors[field_id] = []
            merged.field_errors[field_id].extend(errors)

        # Объединяем ошибки формы
        merged.form_errors.extend(other.form_errors)
        merged.warnings.extend(other.warnings)

        return merged


# Protocol for form storage (for dependency injection)
class FormStorage(Protocol):
    """Протокол хранилища форм."""

    def get(self, form_id: UUID) -> FormInstance | None:
        """Возвращает форму по ID."""
        ...

    def save(self, form: FormInstance) -> None:
        """Сохраняет форму."""
        ...


class FormConstructor:
    """Конструктор форм документов.

    Создаёт структурированные формы из шаблонов типов документов.
    Поддерживает дублирование, слияние и валидацию форм.

    Attributes:
        _registry: Реестр типов документов.
        _validator: Валидатор форм.
        _storage: Хранилище форм (опционально).
        _forms: Кэш созданных форм (без хранилища).

    Example:
        >>> registry = TypeRegistry.get_instance()
        >>> validator = FormValidator()
        >>> constructor = FormConstructor(registry, validator)
        >>> form = constructor.create_form("DVN", "44", "K53")
    """

    def __init__(
        self,
        type_registry: "TypeRegistry",
        validator: "FormValidator",
        storage: FormStorage | None = None,
    ) -> None:
        """Инициализирует конструктор форм.

        Args:
            type_registry: Реестр типов документов.
            validator: Валидатор форм.
            storage: Опциональное хранилище форм.
        """
        self._registry = type_registry
        self._validator = validator
        self._storage = storage
        self._forms: dict[UUID, FormInstance] = {}

        logger.debug("FormConstructor initialized")

    def create_form(
        self,
        type_code: str,
        subtype: str,
        series: str,
        sequence: int | None = None,
        initial_values: dict[str, Any] | None = None,
    ) -> FormInstance:
        """Создаёт новый экземпляр формы из шаблона типа.

        Args:
            type_code: Код типа документа (например, "DVN").
            subtype: Код подтипа (например, "44").
            series: Серия документа (например, "K53").
            sequence: Порядковый номер (для индекса, опционально).
            initial_values: Начальные значения полей.

        Returns:
            Созданный экземпляр формы.

        Raises:
            KeyError: Если тип документа не найден.
            ValueError: Если подтип не найден.
        """
        from src.documents.types.index_formatter import int_to_roman
        from src.documents.types.inheritance import resolve_schema

        # Получаем тип документа
        doc_type = self._registry.get(type_code)

        # Проверяем подтип
        if doc_type.has_subtypes:
            subtype_obj = doc_type.get_subtype(subtype)
            if subtype_obj is None:
                raise ValueError(f"Subtype '{subtype}' not found for type '{type_code}'")

        # Разрешаем схему полей
        schema = resolve_schema(doc_type, self._registry)

        # Формируем индекс
        index_parts = [type_code, subtype, series]
        if sequence is not None:
            index_parts.append(int_to_roman(sequence))
        index = "-".join(index_parts)

        # Создаём поля с значениями по умолчанию
        fields: dict[str, Any] = {}
        for field_def in schema.fields:
            if initial_values and field_def.field_id in initial_values:
                fields[field_def.field_id] = initial_values[field_def.field_id]
            elif field_def.default_value is not None:
                fields[field_def.field_id] = field_def.default_value
            else:
                fields[field_def.field_id] = self._get_empty_value(field_def)

        # Создаём экземпляр формы
        form = FormInstance(
            type_code=type_code,
            subtype=subtype,
            series=series,
            index=index,
            fields=fields,
            metadata={
                "document_name": doc_type.name,
                "schema_version": schema.version,
            },
            status="draft",
        )

        # Сохраняем в кэш или хранилище
        if self._storage:
            self._storage.save(form)
        else:
            self._forms[form.form_id] = form

        logger.info(f"Created form {form.form_id} of type {type_code} ({index})")
        return form

    def create_from_template(self, template: FormTemplate) -> FormInstance:
        """Создаёт форму из загруженного шаблона.

        Args:
            template: Шаблон формы.

        Returns:
            Созданный экземпляр формы.
        """
        form = self.create_form(
            type_code=template.type_code,
            subtype=template.subtype,
            series=template.series,
            initial_values=template.field_defaults,
        )

        # Обновляем метаданные из шаблона
        form.metadata.update(template.metadata)

        logger.info(f"Created form {form.form_id} from template {template.template_id}")
        return form

    def duplicate_form(self, form_id: UUID) -> FormInstance:
        """Дублирует существующую форму.

        Создаёт новую форму с теми же полями и значениями,
        но с новым ID и обновлённым временем создания.

        Args:
            form_id: ID формы для дублирования.

        Returns:
            Новый экземпляр формы (дубликат).

        Raises:
            KeyError: Если форма не найдена.
        """
        # Получаем исходную форму
        original = self._get_form(form_id)
        if original is None:
            raise KeyError(f"Form {form_id} not found")

        # Создаём копию
        new_form = FormInstance(
            type_code=original.type_code,
            subtype=original.subtype,
            series=original.series,
            index=original.index,
            fields=deepcopy(original.fields),
            metadata=deepcopy(original.metadata),
            status="draft",  # Дубликат начинает как черновик
            parent_id=original.form_id,
        )

        # Сохраняем
        if self._storage:
            self._storage.save(new_form)
        else:
            self._forms[new_form.form_id] = new_form

        logger.info(f"Duplicated form {form_id} to {new_form.form_id}")
        return new_form

    def merge_forms(self, form_ids: list[UUID]) -> FormInstance:
        """Объединяет несколько форм в одну.

        Объединяет поля всех форм. При конфликте field_id
        используется значение из последней формы.

        Args:
            form_ids: Список ID форм для объединения.

        Returns:
            Новая форма с объединёнными полями.

        Raises:
            KeyError: Если какая-либо форма не найдена.
            ValueError: Если список пуст или меньше 2 форм.
        """
        if len(form_ids) < 2:
            raise ValueError("Need at least 2 forms to merge")

        # Получаем все формы
        forms_to_merge: list[FormInstance] = []
        for fid in form_ids:
            form = self._get_form(fid)
            if form is None:
                raise KeyError(f"Form {fid} not found")
            forms_to_merge.append(form)

        # Используем первую форму как базу
        base = forms_to_merge[0]

        # Объединяем поля (последняя форма "побеждает" при конфликтах)
        merged_fields: dict[str, Any] = deepcopy(base.fields)
        for form in forms_to_merge[1:]:
            merged_fields.update(deepcopy(form.fields))

        # Создаём новую форму
        merged = FormInstance(
            type_code=base.type_code,
            subtype=base.subtype,
            series=base.series,
            index=f"{base.index}-MERGED",  # Помечаем как merged
            fields=merged_fields,
            metadata={
                **deepcopy(base.metadata),
                "merged_from": [str(fid) for fid in form_ids],
                "merge_count": len(form_ids),
            },
            status="draft",
            merged_from=list(form_ids),
        )

        # Сохраняем
        if self._storage:
            self._storage.save(merged)
        else:
            self._forms[merged.form_id] = merged

        logger.info(f"Merged {len(form_ids)} forms into {merged.form_id}")
        return merged

    def validate_form(self, form: FormInstance) -> ValidationReport:
        """Валидирует поля формы.

        Выполняет валидацию всех полей формы по схеме типа.

        Args:
            form: Форма для валидации.

        Returns:
            Отчёт о валидации.
        """
        from src.documents.types.inheritance import resolve_schema

        report = ValidationReport()

        try:
            # Получаем тип и схему
            doc_type = self._registry.get(form.type_code)
            schema = resolve_schema(doc_type, self._registry)

            # Валидируем каждое поле
            for field_def in schema.fields:
                value = form.fields.get(field_def.field_id)
                errors = schema.validate_value(field_def.field_id, value)
                if errors:
                    for error in errors:
                        report.add_field_error(field_def.field_id, error)

            # Дополнительная валидация через FormValidator (кросс-полевая валидация)
            if self._validator is not None:
                cross_result = self._validator.validate(form, schema)
                if not cross_result.is_valid:
                    for field_id, errors in cross_result.field_errors.items():
                        for err in errors:
                            report.add_field_error(field_id, err.message)
                    for error in cross_result.cross_field_errors:
                        report.add_form_error(error)
                for warning in cross_result.warnings:
                    report.add_warning(warning)

        except KeyError as e:
            report.add_form_error(f"Document type not found: {e}")
        except Exception as e:
            report.add_form_error(f"Validation error: {e}")
            logger.exception(f"Error validating form {form.form_id}")

        return report

    def load_template(self, template_path: Path) -> FormTemplate:
        """Загружает шаблон из файла.

        Args:
            template_path: Путь к файлу шаблона (.fxstpl).

        Returns:
            Загруженный шаблон.

        Raises:
            FileNotFoundError: Если файл не найден.
            ValueError: Если формат файла невалиден.
        """
        import json

        if not template_path.exists():
            raise FileNotFoundError(f"Template file not found: {template_path}")

        with open(template_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Валидация обязательных полей
        required = ["type_code", "subtype", "series"]
        for field in required:
            if field not in data:
                raise ValueError(f"Template missing required field: {field}")

        return FormTemplate(
            type_code=data["type_code"],
            subtype=data["subtype"],
            series=data["series"],
            field_defaults=data.get("field_defaults", {}),
            metadata=data.get("metadata", {}),
            template_id=UUID(data.get("template_id", str(uuid4()))),
        )

    def save_template(self, template: FormTemplate, template_path: Path) -> None:
        """Сохраняет шаблон в файл.

        Args:
            template: Шаблон для сохранения.
            template_path: Путь для сохранения (.fxstpl).
        """
        import json

        data = {
            "type_code": template.type_code,
            "subtype": template.subtype,
            "series": template.series,
            "field_defaults": template.field_defaults,
            "metadata": template.metadata,
            "template_id": str(template.template_id),
            "created_at": datetime.now().isoformat(),
        }

        template_path.parent.mkdir(parents=True, exist_ok=True)
        with open(template_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        logger.info(f"Saved template {template.template_id} to {template_path}")

    def _get_form(self, form_id: UUID) -> FormInstance | None:
        """Получает форму по ID.

        Args:
            form_id: ID формы.

        Returns:
            Форма или None если не найдена.
        """
        if self._storage:
            return self._storage.get(form_id)
        return self._forms.get(form_id)

    def _get_empty_value(self, field_def: "FieldDefinition") -> Any:
        """Возвращает пустое значение для типа поля.

        Args:
            field_def: Определение поля.

        Returns:
            Пустое значение для данного типа.
        """
        from src.documents.types.type_schema import FieldType

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
        return empty_values.get(field_def.field_type, None)
