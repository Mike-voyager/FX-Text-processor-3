"""Verbal note document type - DVN (Вербальная нота).

Diplomatic/official note with hierarchical index (DVN-44-K53-IX).
"""

from src.documents.types.document_type import DocumentType, DocumentSubtype
from src.documents.types.index_template import IndexSegmentDef, IndexTemplate, SegmentType
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema

# Вербальная нота - полная структура с подтипом и серией
DVN = DocumentType(
    code="DVN",
    name="Вербальная нота",
    parent_code=None,
    index_template=IndexTemplate(
        segments=(
            IndexSegmentDef(
                name="type",
                segment_type=SegmentType.ROOT_CODE,
                label="Тип",
                label_en="Type",
                pattern=r"DVN",
                allowed_values=None,
                auto_increment=False,
            ),
            IndexSegmentDef(
                name="subtype",
                segment_type=SegmentType.SUBTYPE,
                label="Подтип",
                label_en="Subtype",
                pattern=r"\d{1,2}",
                allowed_values=None,
                auto_increment=False,
            ),
            IndexSegmentDef(
                name="series",
                segment_type=SegmentType.SERIES,
                label="Серия",
                label_en="Series",
                pattern=r"[A-Z]\d{2}",
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
                name="index",
                field_type=FieldType.TEXT_INPUT,
                label="Индекс документа",
                label_en="Document index",
                required=True,
                readonly=True,
                validation=("regex:^DVN-\\d{1,2}-[A-Z]\\d{2}-[IVXLCDM]+$",),
            ),
            FieldDefinition(
                name="date",
                field_type=FieldType.DATE_INPUT,
                label="Дата",
                label_en="Date",
                required=True,
            ),
            FieldDefinition(
                name="from_entity",
                field_type=FieldType.TEXT_INPUT,
                label="От кого",
                label_en="From",
                required=True,
                validation=("min_length:1", "max_length:200"),
            ),
            FieldDefinition(
                name="to_entity",
                field_type=FieldType.TEXT_INPUT,
                label="Кому",
                label_en="To",
                required=True,
                validation=("min_length:1", "max_length:200"),
            ),
            FieldDefinition(
                name="topic",
                field_type=FieldType.TEXT_INPUT,
                label="Тема",
                label_en="Topic",
                required=True,
                validation=("min_length:1", "max_length:300"),
            ),
            FieldDefinition(
                name="reference_number",
                field_type=FieldType.TEXT_INPUT,
                label="Исходящий номер",
                label_en="Reference number",
                required=False,
                validation=("max_length:50",),
            ),
            FieldDefinition(
                name="reference_date",
                field_type=FieldType.DATE_INPUT,
                label="Дата исходящего",
                label_en="Reference date",
                required=False,
            ),
            FieldDefinition(
                name="content",
                field_type=FieldType.MULTI_LINE_TEXT,
                label="Содержание",
                label_en="Content",
                required=True,
                validation=("min_length:1",),
            ),
            FieldDefinition(
                name="attachments",
                field_type=FieldType.TABLE,
                label="Приложения",
                label_en="Attachments",
                required=False,
            ),
            FieldDefinition(
                name="executor",
                field_type=FieldType.TEXT_INPUT,
                label="Исполнитель",
                label_en="Executor",
                required=True,
                validation=("min_length:1", "max_length:100"),
            ),
            FieldDefinition(
                name="executor_contact",
                field_type=FieldType.TEXT_INPUT,
                label="Контакт исполнителя",
                label_en="Executor contact",
                required=False,
            ),
            FieldDefinition(
                name="approved_by",
                field_type=FieldType.TEXT_INPUT,
                label="Утвердил",
                label_en="Approved by",
                required=False,
                validation=("max_length:100",),
            ),
            FieldDefinition(
                name="signature",
                field_type=FieldType.SIGNATURE,
                label="Подпись",
                label_en="Signature",
                required=False,
            ),
            FieldDefinition(
                name="stamp",
                field_type=FieldType.STAMP,
                label="Печать",
                label_en="Stamp",
                required=False,
            ),
            FieldDefinition(
                name="qr_code",
                field_type=FieldType.QR,
                label="QR-код",
                label_en="QR code",
                required=False,
            ),
        ),
        version="1.0",
    ),
    subtypes=(
        DocumentSubtype(
            code="01",
            name="Обычная",
        ),
        DocumentSubtype(
            code="44",
            name="Специальная",
        ),
    ),
)

