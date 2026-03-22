"""Verbal note document type - DVN (Вербальная нота).

Diplomatic/official note with hierarchical index (DVN-44-K53-IX).
"""

from src.documents.types.document_type import DocumentMode, DocumentSubtype, DocumentType
from src.documents.types.index_template import IndexSegmentDef, IndexTemplate, SegmentType
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema

# Вербальная нота - полная структура с подтипом и серией
DVN = DocumentType(
    code="DVN",
    name="Вербальная нота",
    parent_code=None,
    document_mode=DocumentMode.STRUCTURED_FORM,
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
                field_id="index",
                field_type=FieldType.TEXT_INPUT,
                label="Индекс документа",
                label_i18n={"en": "Document index"},
                required=True,
                readonly=True,
                validation_pattern=r"^DVN-\d{1,2}-[A-Z]\d{2}-[IVXLCDM]+$",
            ),
            FieldDefinition(
                field_id="date",
                field_type=FieldType.DATE_INPUT,
                label="Дата",
                label_i18n={"en": "Date"},
                required=True,
            ),
            FieldDefinition(
                field_id="from_entity",
                field_type=FieldType.TEXT_INPUT,
                label="От кого",
                label_i18n={"en": "From"},
                required=True,
                validation_pattern=r"^.{1,200}$",
            ),
            FieldDefinition(
                field_id="to_entity",
                field_type=FieldType.TEXT_INPUT,
                label="Кому",
                label_i18n={"en": "To"},
                required=True,
                validation_pattern=r"^.{1,200}$",
            ),
            FieldDefinition(
                field_id="topic",
                field_type=FieldType.TEXT_INPUT,
                label="Тема",
                label_i18n={"en": "Topic"},
                required=True,
                validation_pattern=r"^.{1,300}$",
            ),
            FieldDefinition(
                field_id="reference_number",
                field_type=FieldType.TEXT_INPUT,
                label="Исходящий номер",
                label_i18n={"en": "Reference number"},
                required=False,
                validation_pattern=r"^.{0,50}$",
            ),
            FieldDefinition(
                field_id="reference_date",
                field_type=FieldType.DATE_INPUT,
                label="Дата исходящего",
                label_i18n={"en": "Reference date"},
                required=False,
            ),
            FieldDefinition(
                field_id="content",
                field_type=FieldType.MULTI_LINE_TEXT,
                label="Содержание",
                label_i18n={"en": "Content"},
                required=True,
            ),
            FieldDefinition(
                field_id="attachments",
                field_type=FieldType.TABLE,
                label="Приложения",
                label_i18n={"en": "Attachments"},
                required=False,
            ),
            FieldDefinition(
                field_id="executor",
                field_type=FieldType.TEXT_INPUT,
                label="Исполнитель",
                label_i18n={"en": "Executor"},
                required=True,
                validation_pattern=r"^.{1,100}$",
            ),
            FieldDefinition(
                field_id="executor_contact",
                field_type=FieldType.TEXT_INPUT,
                label="Контакт исполнителя",
                label_i18n={"en": "Executor contact"},
                required=False,
            ),
            FieldDefinition(
                field_id="approved_by",
                field_type=FieldType.TEXT_INPUT,
                label="Утвердил",
                label_i18n={"en": "Approved by"},
                required=False,
                validation_pattern=r"^.{0,100}$",
            ),
            FieldDefinition(
                field_id="signature",
                field_type=FieldType.SIGNATURE,
                label="Подпись",
                label_i18n={"en": "Signature"},
                required=False,
            ),
            FieldDefinition(
                field_id="stamp",
                field_type=FieldType.STAMP,
                label="Печать",
                label_i18n={"en": "Stamp"},
                required=False,
            ),
            FieldDefinition(
                field_id="qr_code",
                field_type=FieldType.QR,
                label="QR-код",
                label_i18n={"en": "QR code"},
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
