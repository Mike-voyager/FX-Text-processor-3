"""Schema inheritance utilities.

Provides:
- resolve_schema: Resolves complete schema by merging parent and child fields
"""

from src.documents.types.document_type import DocumentType
from src.documents.types.registry import TypeRegistry
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema


def resolve_schema(doc_type: DocumentType, registry: TypeRegistry) -> TypeSchema:
    """Разрешает полную схему, объединяя поля родителя и потомка.

    Дочерний тип наследует ВСЕ поля родителя и может добавлять свои.
    При конфликте field_id — поле потомка переопределяет родительское.

    Args:
        doc_type: Тип документа для разрешения схемы.
        registry: Экземпляр TypeRegistry для поиска родительских типов.

    Returns:
        Полная схема с унаследованными и переопределёнными полями.

    Example:
        >>> registry = TypeRegistry.get_instance()
        >>> dvn = registry.get("DVN")
        >>> schema = resolve_schema(dvn, registry)
        >>> # Все поля DVN + поля родителя (если есть)
    """
    # Если нет родителя, возвращаем схему как есть
    if doc_type.parent_code is None:
        return doc_type.field_schema

    try:
        parent_type = registry.get(doc_type.parent_code)
    except KeyError:
        # Родитель не найден — возвращаем схему потомка
        return doc_type.field_schema

    # Рекурсивно разрешаем схему родителя
    parent_schema = resolve_schema(parent_type, registry)

    # Объединяем поля
    merged_fields: dict[str, FieldDefinition] = {}

    # Сначала добавляем поля родителя
    for field_def in parent_schema.fields:
        # Помечаем как унаследованные
        inherited_field = FieldDefinition(
            field_id=field_def.field_id,
            field_type=field_def.field_type,
            label=field_def.label,
            label_i18n=field_def.label_i18n,
            required=field_def.required,
            readonly=field_def.readonly,
            default_value=field_def.default_value,
            validation_pattern=field_def.validation_pattern,
            max_length=field_def.max_length,
            options=field_def.options,
            escp_variable=field_def.escp_variable,
            inherited_from=parent_type.code,
            min_value=field_def.min_value,
            max_value=field_def.max_value,
            min_date=field_def.min_date,
            max_date=field_def.max_date,
            required_if=field_def.required_if,
            cross_field_rules=field_def.cross_field_rules,
            visibility_condition=field_def.visibility_condition,
            read_only_condition=field_def.read_only_condition,
            enabled_condition=field_def.enabled_condition,
            tab_index=field_def.tab_index,
            input_mask=field_def.input_mask,
            placeholder=field_def.placeholder,
            autocomplete_source=field_def.autocomplete_source,
            help_text=field_def.help_text,
            table_schema=field_def.table_schema,
        )
        merged_fields[field_def.field_id] = inherited_field

    # Затем добавляем/переопределяем поля потомка
    for field_def in doc_type.field_schema.fields:
        merged_fields[field_def.field_id] = field_def

    # Формируем итоговую схему
    return TypeSchema(
        fields=tuple(merged_fields.values()),
        version=doc_type.field_schema.version,
        compatibility_version=doc_type.field_schema.compatibility_version,
        deprecated_fields=doc_type.field_schema.deprecated_fields,
    )


def merge_schemas(base: TypeSchema, override: TypeSchema) -> TypeSchema:
    """Объединяет две схемы, где override переопределяет base.

    Args:
        base: Базовая схема.
        override: Схема с переопределениями.

    Returns:
        Объединённая схема.
    """
    merged: dict[str, FieldDefinition] = {}

    # Добавляем поля из base
    for field_def in base.fields:
        merged[field_def.field_id] = field_def

    # Переопределяем/добавляем поля из override
    for field_def in override.fields:
        merged[field_def.field_id] = field_def

    return TypeSchema(
        fields=tuple(merged.values()),
        version=override.version or base.version,
        compatibility_version=override.compatibility_version or base.compatibility_version,
        deprecated_fields=override.deprecated_fields or base.deprecated_fields,
    )


def get_inherited_field_names(schema: TypeSchema) -> set[str]:
    """Возвращает имена всех унаследованных полей.

    Args:
        schema: Схема для анализа.

    Returns:
        Множество имён унаследованных полей.
    """
    return {f.field_id for f in schema.fields if f.inherited_from is not None}


def get_own_field_names(schema: TypeSchema) -> set[str]:
    """Возвращает имена собственных полей (не унаследованных).

    Args:
        schema: Схема для анализа.

    Returns:
        Множество имён собственных полей.
    """
    return {f.field_id for f in schema.fields if f.inherited_from is None}


def filter_fields_by_type(schema: TypeSchema, field_type: FieldType) -> list[FieldDefinition]:
    """Возвращает поля указанного типа.

    Args:
        schema: Схема для фильтрации.
        field_type: Тип поля для поиска.

    Returns:
        Список полей указанного типа.
    """
    return [f for f in schema.fields if f.field_type == field_type]


def get_required_fields(schema: TypeSchema) -> list[FieldDefinition]:
    """Возвращает все обязательные поля.

    Args:
        schema: Схема для анализа.

    Returns:
        Список обязательных полей.
    """
    return [f for f in schema.fields if f.required]


def get_optional_fields(schema: TypeSchema) -> list[FieldDefinition]:
    """Возвращает все необязательные поля.

    Args:
        schema: Схема для анализа.

    Returns:
        Список необязательных полей.
    """
    return [f for f in schema.fields if not f.required]
