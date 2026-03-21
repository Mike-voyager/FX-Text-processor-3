"""Invoice document type - INV (Счёт).

Simple invoice with basic fields.
"""

from src.documents.types.document_type import DocumentType
from src.documents.types.index_template import IndexSegmentDef, IndexTemplate, SegmentType
from src.documents.types.type_schema import FieldDefinition, FieldType, TypeSchema

# Счёт - с серией и номером
INV = DocumentType(
    code="INV",
    name="Счёт",
    parent_code=None,
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
                name="invoice_number",
                field_type=FieldType.TEXT_INPUT,
                label="Номер счёта",
                label_en="Invoice number",
                required=True,
                validation=("min_length:1", "max_length:50"),
                placeholder="INV-001",
            ),
            FieldDefinition(
                name="date",
                field_type=FieldType.DATE_INPUT,
                label="Дата",
                label_en="Date",
                required=True,
            ),
            FieldDefinition(
                name="supplier",
                field_type=FieldType.TEXT_INPUT,
                label="Поставщик",
                label_en="Supplier",
                required=True,
                validation=("min_length:1", "max_length:200"),
            ),
            FieldDefinition(
                name="supplier_inn",
                field_type=FieldType.TEXT_INPUT,
                label="ИНН поставщика",
                label_en="Supplier TIN",
                required=True,
                validation=("regex:^\\d{10}|\\d{12}$",),
                placeholder="1234567890",
            ),
            FieldDefinition(
                name="buyer",
                field_type=FieldType.TEXT_INPUT,
                label="Покупатель",
                label_en="Buyer",
                required=True,
                validation=("min_length:1", "max_length:200"),
            ),
            FieldDefinition(
                name="buyer_inn",
                field_type=FieldType.TEXT_INPUT,
                label="ИНН покупателя",
                label_en="Buyer TIN",
                required=True,
                validation=("regex:^\\d{10}|\\d{12}$",),
                placeholder="1234567890",
            ),
            FieldDefinition(
                name="items_table",
                field_type=FieldType.TABLE,
                label="Товары и услуги",
                label_en="Items and services",
                required=True,
            ),
            FieldDefinition(
                name="subtotal",
                field_type=FieldType.CURRENCY,
                label="Сумма без НДС",
                label_en="Subtotal",
                required=True,
            ),
            FieldDefinition(
                name="vat",
                field_type=FieldType.CURRENCY,
                label="НДС",
                label_en="VAT",
                required=True,
            ),
            FieldDefinition(
                name="total",
                field_type=FieldType.CALCULATED,
                label="Итого",
                label_en="Total",
                required=True,
            ),
            FieldDefinition(
                name="payment_details",
                field_type=FieldType.MULTI_LINE_TEXT,
                label="Платёжные реквизиты",
                label_en="Payment details",
                required=False,
            ),
            FieldDefinition(
                name="notes",
                field_type=FieldType.MULTI_LINE_TEXT,
                label="Примечание",
                label_en="Notes",
                required=False,
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
        ),
        version="1.0",
    ),
)

