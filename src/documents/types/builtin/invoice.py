"""Invoice document type - INV (Счёт).

Simple invoice with basic fields.
"""

from src.documents.types.document_type import DocumentMode, DocumentType
from src.documents.types.index_template import IndexSegmentDef, IndexTemplate, SegmentType
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema

# Счёт - с серией и номером
INV = DocumentType(
    code="INV",
    name="Счёт",
    parent_code=None,
    document_mode=DocumentMode.STRUCTURED_FORM,
    index_template=IndexTemplate(
        segments=(
            IndexSegmentDef(
                name="type",
                segment_type=SegmentType.ROOT_CODE,
                label="Тип",
                label_en="Type",
                pattern=r"INV",
                allowed_values=None,
                auto_increment=False,
            ),
            IndexSegmentDef(
                name="series",
                segment_type=SegmentType.SERIES,
                label="Серия",
                label_en="Series",
                pattern=r"[A-Z]{1,3}",
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
                field_id="invoice_number",
                field_type=FieldType.TEXT_INPUT,
                label="Номер счёта",
                label_i18n={"en": "Invoice number"},
                required=True,
                validation_pattern=r"^.{1,50}$",
                placeholder="INV-001",
            ),
            FieldDefinition(
                field_id="date",
                field_type=FieldType.DATE_INPUT,
                label="Дата",
                label_i18n={"en": "Date"},
                required=True,
            ),
            FieldDefinition(
                field_id="supplier",
                field_type=FieldType.TEXT_INPUT,
                label="Поставщик",
                label_i18n={"en": "Supplier"},
                required=True,
                validation_pattern=r"^.{1,200}$",
            ),
            FieldDefinition(
                field_id="supplier_inn",
                field_type=FieldType.TEXT_INPUT,
                label="ИНН поставщика",
                label_i18n={"en": "Supplier TIN"},
                required=True,
                validation_pattern=r"^\d{10}|\d{12}$",
                placeholder="1234567890",
            ),
            FieldDefinition(
                field_id="buyer",
                field_type=FieldType.TEXT_INPUT,
                label="Покупатель",
                label_i18n={"en": "Buyer"},
                required=True,
                validation_pattern=r"^.{1,200}$",
            ),
            FieldDefinition(
                field_id="buyer_inn",
                field_type=FieldType.TEXT_INPUT,
                label="ИНН покупателя",
                label_i18n={"en": "Buyer TIN"},
                required=True,
                validation_pattern=r"^\d{10}|\d{12}$",
                placeholder="1234567890",
            ),
            FieldDefinition(
                field_id="items_table",
                field_type=FieldType.TABLE,
                label="Товары и услуги",
                label_i18n={"en": "Items and services"},
                required=True,
            ),
            FieldDefinition(
                field_id="subtotal",
                field_type=FieldType.CURRENCY,
                label="Сумма без НДС",
                label_i18n={"en": "Subtotal"},
                required=True,
            ),
            FieldDefinition(
                field_id="vat",
                field_type=FieldType.CURRENCY,
                label="НДС",
                label_i18n={"en": "VAT"},
                required=True,
            ),
            FieldDefinition(
                field_id="total",
                field_type=FieldType.CALCULATED,
                label="Итого",
                label_i18n={"en": "Total"},
                required=True,
            ),
            FieldDefinition(
                field_id="payment_details",
                field_type=FieldType.MULTI_LINE_TEXT,
                label="Платёжные реквизиты",
                label_i18n={"en": "Payment details"},
                required=False,
            ),
            FieldDefinition(
                field_id="notes",
                field_type=FieldType.MULTI_LINE_TEXT,
                label="Примечание",
                label_i18n={"en": "Notes"},
                required=False,
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
        ),
        version="1.0",
    ),
)
