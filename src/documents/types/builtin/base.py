"""Base document type - DOC.

This is the root document type that other types can inherit from.
"""

from src.documents.types.document_type import DocumentType
from src.documents.types.index_template import IndexSegmentDef, IndexTemplate, SegmentType
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema

# Базовый документ - простой с одним сегментом (SEQUENCE)
DOC = DocumentType(
    code="DOC",
    name="Базовый документ",
    parent_code=None,
    index_template=IndexTemplate(
        segments=(
            IndexSegmentDef(
                name="type",
                segment_type=SegmentType.ROOT_CODE,
                label="Тип",
                label_en="Type",
                pattern=r"DOC",
                allowed_values=None,
                auto_increment=False,
            ),
            IndexSegmentDef(
                name="seq",
                segment_type=SegmentType.SEQUENCE,
                label="Номер",
                label_en="Number",
                pattern=r"[IVXLCDM]+",
                allowed_values=None,
                auto_increment=True,
            ),
        ),
        separator="-",
    ),
    field_schema=TypeSchema(
        fields=(
            FieldDefinition(
                name="title",
                field_type=FieldType.TEXT_INPUT,
                label="Название",
                label_en="Title",
                required=True,
                validation=("min_length:1", "max_length:200"),
            ),
            FieldDefinition(
                name="content",
                field_type=FieldType.MULTI_LINE_TEXT,
                label="Содержание",
                label_en="Content",
                required=False,
            ),
            FieldDefinition(
                name="author",
                field_type=FieldType.TEXT_INPUT,
                label="Автор",
                label_en="Author",
                required=True,
                default_value="operator",
            ),
            FieldDefinition(
                name="created_date",
                field_type=FieldType.DATE_INPUT,
                label="Дата создания",
                label_en="Created date",
                required=True,
            ),
        ),
        version="1.0",
    ),
)

