import pytest

from src.model.barcodegen import Barcode
from src.model.enums import BarcodeType, Matrix2DCodeType


def test_barcode_minimal_1d() -> None:
    b = Barcode(type=BarcodeType.EAN13, data="1234567890123")
    assert b.type == BarcodeType.EAN13
    assert b.data == "1234567890123"
    assert b.show_label is True


def test_barcode_minimal_2d() -> None:
    b = Barcode(type=Matrix2DCodeType.QR, data="my qr payload")
    assert b.type == Matrix2DCodeType.QR
    assert b.data == "my qr payload"


def test_barcode_full_fields_1d() -> None:
    b = Barcode(
        type=BarcodeType.CODE128,
        data="MYDATA",
        caption="TestCode",
        options={"scale": 2.0},
        position=(10, 20),
        size=(120, 80),
        rotation=90,
        show_label=False,
        foreground="#000",
        background="#fff",
        gs1_mode=True,
        parent_section="sec1",
        parent_table="tbl1",
        anchor_id="cellA1",
        border={"color": "black", "width": 2},
        padding=(2, 2, 2, 2),
        opacity=0.8,
        z_order=5,
        user_label="main-barcode",
        object_id="BARC123456",
        readonly=True,
        hidden=True,
        data_source="ext_db",
        auto_regenerate_on_save=True,
        created_at="2025-10-07T10:02:00",
        updated_at="2025-10-07T15:00:01",
        created_by="userX",
        updated_by="userY",
        validation_state="valid",
        validation_error_message=None,
        is_signature=True,
        signature_type="pkcs7",
        signature_payload=b"\xff\x01\x02",
        signer_info="alice@example.com",
        signing_datetime="2025-10-07T15:10:10",
        certificate_thumbprint="ABCDEF123456",
        validation_status="valid",
        validation_message="Signature valid",
        crypto_metadata={"oid": "1.2.643..."},
        metadata={"custom1": 42},
        custom_fields={"extra": "val42"},
    )
    assert b.is_signature
    assert b.signature_type == "pkcs7"
    assert b.certificate_thumbprint
    d = b.to_dict()
    assert d["is_signature"] is True
    b2 = Barcode.from_dict(d)
    assert b2 == b


def test_barcode_full_fields_2d() -> None:
    b = Barcode(
        type=Matrix2DCodeType.PDF417,
        data="DATA",
        caption="2D SIGN",
        is_signature=True,
        signature_type="gost",
        signer_info="root@acme.com",
        show_label=False,
    )
    assert b.type == Matrix2DCodeType.PDF417
    assert b.is_signature
    assert b.signature_type == "gost"
    d = b.to_dict()
    b2 = Barcode.from_dict(d)
    assert b2 == b


def test_barcode_str_1d() -> None:
    b = Barcode(type=BarcodeType.CODE39, data="CODE39CODEDATA")
    s = str(b)
    assert s.startswith("<Barcode type=BarcodeType.CODE39 data=CODE39CODEDATA")


def test_barcode_str_2d() -> None:
    b = Barcode(type=Matrix2DCodeType.DATAMATRIX, data="DMx2" * 5, is_signature=True)
    s = str(b)
    assert "[SIG]" in s


def test_barcode_metadata_and_custom_fields() -> None:
    b = Barcode(type=BarcodeType.CODE93, data="test")
    b.metadata["foo"] = 123
    b.custom_fields["bar"] = 456
    assert b.metadata["foo"] == 123
    assert b.custom_fields["bar"] == 456


@pytest.mark.parametrize(
    "typecls, enumval, data",
    [
        (BarcodeType, BarcodeType.EAN8, "12345678"),
        (BarcodeType, BarcodeType.CODE128, "CODE128DATA"),
        (Matrix2DCodeType, Matrix2DCodeType.QR, "qr_payload"),
        (Matrix2DCodeType, Matrix2DCodeType.DATAMATRIX, "dm_payload"),
    ],
)
def test_barcode_serialization_both_types(
    typecls: type, enumval: BarcodeType | Matrix2DCodeType, data: str
) -> None:
    b = Barcode(type=enumval, data=data)
    b2 = Barcode.from_dict(b.to_dict())
    assert b2.data == data
    assert b2.type == enumval


def test_barcode_signature_logic_status() -> None:
    b = Barcode(type=Matrix2DCodeType.QR, data="signed-data", is_signature=True)
    assert b.is_signature
    b.validation_status = "invalid"
    b.validation_message = "bad signature"
    assert b.validation_status == "invalid"


def test_validate_no_exception() -> None:
    b = Barcode(type=BarcodeType.EAN13, data="1234567890123")
    b.validate()  # долен не падать по-умолчанию
