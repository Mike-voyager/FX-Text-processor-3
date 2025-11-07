from io import BytesIO
from typing import Any, Dict
from unittest.mock import Mock, patch

import pytest
from PIL import Image

from src.barcodegen.barcode_generator import BarcodeGenerator, BarcodeGenError
from src.model.enums import BarcodeType


class TestBarcodeGenerator:
    """Test suite for BarcodeGenerator with strict type hints and edge-case validation."""

    @pytest.fixture
    def valid_ean13_generator(self) -> BarcodeGenerator:
        return BarcodeGenerator(BarcodeType.EAN13, "1234567890123")

    @pytest.fixture
    def valid_code39_generator(self) -> BarcodeGenerator:
        return BarcodeGenerator(BarcodeType.CODE39, "ABC123")

    # === Initialization ===
    def test_init_basic(self) -> None:
        gen = BarcodeGenerator(BarcodeType.EAN13, "1234567890123")
        assert gen.barcode_type == BarcodeType.EAN13
        assert gen.data == "1234567890123"
        assert gen.options == {}

    def test_init_with_options(self) -> None:
        options: Dict[str, Any] = {"quiet_zone": 5, "module_width": 0.3}
        gen = BarcodeGenerator(BarcodeType.CODE128, "TEST", options)
        assert gen.options == options

    def test_init_none_options(self) -> None:
        gen = BarcodeGenerator(BarcodeType.EAN13, "1234567890123", None)
        assert gen.options == {}

    # === Validation ===
    def test_validate_success_ean13(
        self, valid_ean13_generator: BarcodeGenerator
    ) -> None:
        valid_ean13_generator.validate()

    def test_validate_success_code39(
        self, valid_code39_generator: BarcodeGenerator
    ) -> None:
        valid_code39_generator.validate()

    def test_validate_empty_data(self) -> None:
        gen = BarcodeGenerator(BarcodeType.EAN13, "")
        with pytest.raises(BarcodeGenError, match="non-empty"):
            gen.validate()

    # EAN validation and lengths
    @pytest.mark.parametrize(
        "barcode_type,valid_data,invalid_data,expected_length",
        [
            (BarcodeType.EAN8, "12345678", "1234567", 8),
            (BarcodeType.EAN13, "1234567890123", "123456789012", 13),
            (BarcodeType.EAN14, "12345678901234", "1234567890123", 14),
        ],
    )
    def test_validate_ean_length(
        self,
        barcode_type: BarcodeType,
        valid_data: str,
        invalid_data: str,
        expected_length: int,
    ) -> None:
        gen = BarcodeGenerator(barcode_type, valid_data)
        gen.validate()
        gen_invalid = BarcodeGenerator(barcode_type, invalid_data)
        with pytest.raises(BarcodeGenError, match=f"must be {expected_length} digits"):
            gen_invalid.validate()

    # UPC validation
    def test_validate_upca_success(self) -> None:
        gen = BarcodeGenerator(BarcodeType.UPCA, "123456789012")
        gen.validate()

    def test_validate_upca_invalid_length(self) -> None:
        gen = BarcodeGenerator(BarcodeType.UPCA, "12345678901")
        with pytest.raises(BarcodeGenError, match="12 digits"):
            gen.validate()

    # Code39 validation — must NOT accept lowercase or forbidden chars
    @pytest.mark.parametrize(
        "invalid_data,expected_msg",
        [
            ("test123", "uppercase"),
            ("ABC@123", "A-Z"),
            ("TEST*DATA", "A-Z"),
            ("ABC#DEF", "A-Z"),
        ],
    )
    def test_validate_code39_invalid_chars(
        self, invalid_data: str, expected_msg: str
    ) -> None:
        gen = BarcodeGenerator(BarcodeType.CODE39, invalid_data)
        with pytest.raises(BarcodeGenError, match=expected_msg):
            gen.validate()

    @pytest.mark.parametrize(
        "valid_data", ["ABC123", "TEST-DATA", "HELLO WORLD", "123.456", "A$B/C+D%E"]
    )
    def test_validate_code39_valid_chars(self, valid_data: str) -> None:
        gen = BarcodeGenerator(BarcodeType.CODE39, valid_data)
        gen.validate()

    # Itf edge-case
    def test_validate_itf_odd_length(self) -> None:
        gen = BarcodeGenerator(BarcodeType.ITF, "123")
        with pytest.raises(BarcodeGenError, match="even number"):
            gen.validate()

    def test_validate_itf_non_digits(self) -> None:
        gen = BarcodeGenerator(BarcodeType.ITF, "12AB")
        with pytest.raises(BarcodeGenError, match="even number"):
            gen.validate()

    # MSI and Pharmacode basic coverage
    def test_validate_msi_non_digits(self) -> None:
        gen = BarcodeGenerator(BarcodeType.MSI, "123ABC")
        with pytest.raises(BarcodeGenError, match="only digits"):
            gen.validate()

    def test_validate_pharmacode_invalid(self) -> None:
        gen = BarcodeGenerator(BarcodeType.PHARMACODE, "2")
        with pytest.raises(BarcodeGenError, match="between 3 and 131070"):
            gen.validate()

    # Codabar
    def test_validate_codabar_invalid_chars(self) -> None:
        gen = BarcodeGenerator(BarcodeType.CODABAR, "A123@B")
        with pytest.raises(BarcodeGenError, match="only 0-9"):
            gen.validate()

    # Postnet wrong length
    def test_validate_postnet_invalid_length(self) -> None:
        gen = BarcodeGenerator(BarcodeType.POSTNET, "1234")
        with pytest.raises(BarcodeGenError, match="must be 5, 9, or 11"):
            gen.validate()

    # Code11 wrong chars
    def test_validate_code11_invalid_chars(self) -> None:
        gen = BarcodeGenerator(BarcodeType.CODE11, "123ABC")
        with pytest.raises(BarcodeGenError, match="digits and dash"):
            gen.validate()

    # === Image Rendering/BYTE ---
    @patch("src.barcodegen.barcode_generator.pybarcode.get_barcode_class")
    def test_render_image_success(
        self, mock_get_barcode_class: Mock, valid_ean13_generator: BarcodeGenerator
    ) -> None:
        mock_barcode_class = Mock()
        mock_barcode_inst = Mock()
        mock_image = Mock(spec=Image.Image)
        mock_get_barcode_class.return_value = mock_barcode_class
        mock_barcode_class.return_value = mock_barcode_inst
        mock_barcode_inst.render.return_value = mock_image
        result = valid_ean13_generator.render_image(width=200, height=100)
        assert result == mock_image

    # === Supported Types ===
    def test_supported_types(self) -> None:
        supported = BarcodeGenerator.supported_types()
        assert BarcodeType.EAN13 in supported
        assert BarcodeType.CODE39 in supported
        assert isinstance(supported, set)

    def test_barcode_name_map(self) -> None:
        name_map = BarcodeGenerator.barcode_name_map()
        assert name_map[BarcodeType.EAN13] == "ean13"
        assert name_map[BarcodeType.CODE39] == "code39"
        assert isinstance(name_map, dict)

    def test_all_supported_types_in_map(self) -> None:
        name_map = BarcodeGenerator.barcode_name_map()
        supported = BarcodeGenerator.supported_types()
        for barcode_type in supported:
            assert barcode_type in name_map
            assert isinstance(name_map[barcode_type], str)

    def test_validate_code39_lowercase(self) -> None:
        gen = BarcodeGenerator(BarcodeType.CODE39, "abcDEF")
        with pytest.raises(BarcodeGenError, match="uppercase"):
            gen.validate()

    @patch("src.barcodegen.barcode_generator.pybarcode.get_barcode_class")
    def test_render_image_unsupported_type(self, mock_get_barcode_class: Mock) -> None:
        mock_get_barcode_class.side_effect = Exception(
            "BarcodeNotFoundError: not found"
        )
        gen = BarcodeGenerator(BarcodeType.TRIOPTIC, "TEST")
        result = gen.render_image(width=200, height=80)
        assert isinstance(result, Image.Image)
        assert result.size == (200, 80)

    @patch.object(BarcodeGenerator, "render_image")
    def test_render_bytes_success(self, mock_render_image: Mock) -> None:
        mock_image = Mock(spec=Image.Image)
        mock_render_image.return_value = mock_image
        gen = BarcodeGenerator(BarcodeType.CODE128, "TEST")
        result = gen.render_bytes()
        assert isinstance(result, bytes)
        assert mock_image.save.call_count == 1
        args, kwargs = mock_image.save.call_args
        assert isinstance(args[0], BytesIO)
        assert kwargs["format"] == "PNG"


def test_validate_ean14_success() -> None:
    gen = BarcodeGenerator(BarcodeType.EAN14, "12345678901234")
    gen.validate()


def test_validate_pharmacode_non_numeric() -> None:
    gen = BarcodeGenerator(BarcodeType.PHARMACODE, "ABC")
    with pytest.raises(BarcodeGenError, match="between 3 and 131070"):
        gen.validate()


def test_validate_code93_success() -> None:
    gen = BarcodeGenerator(BarcodeType.CODE93, "TEST123")
    gen.validate()


def test_validate_code128_success() -> None:
    gen = BarcodeGenerator(BarcodeType.CODE128, "Test123!@#")
    gen.validate()


def test_validate_itf_success() -> None:
    gen = BarcodeGenerator(BarcodeType.ITF, "1234")
    gen.validate()


def test_validate_msi_success() -> None:
    gen = BarcodeGenerator(BarcodeType.MSI, "123456")
    gen.validate()


def test_validate_codabar_success() -> None:
    gen = BarcodeGenerator(BarcodeType.CODABAR, "A123B")
    gen.validate()


def test_validate_postnet_success() -> None:
    gen = BarcodeGenerator(BarcodeType.POSTNET, "12345")
    gen.validate()


def test_validate_code11_success() -> None:
    gen = BarcodeGenerator(BarcodeType.CODE11, "123-456")
    gen.validate()


def test_render_image_truly_unsupported_type() -> None:
    gen = BarcodeGenerator(BarcodeType.TELEPEN, "TEST")
    result = gen.render_image(width=150, height=60)
    assert isinstance(result, Image.Image)
    assert result.size == (150, 60)


from unittest.mock import Mock, patch


@patch("src.barcodegen.barcode_generator.pybarcode.get_barcode_class")
def test_render_image_barcode_creation_error(mock_get_barcode_class: Mock) -> None:
    mock_barcode_class = Mock()
    mock_barcode_class.side_effect = Exception("Barcode creation failed")
    mock_get_barcode_class.return_value = mock_barcode_class

    gen = BarcodeGenerator(BarcodeType.EAN13, "1234567890123")
    result = gen.render_image()
    assert isinstance(result, Image.Image)
    assert result.size == (400, 120)


def test_validate_empty_string_raises() -> None:
    gen = BarcodeGenerator(BarcodeType.EAN13, "   ")
    with pytest.raises(BarcodeGenError, match="non-empty"):
        gen.validate()

@pytest.mark.parametrize("barcode_type,bad_data,expected_msg", [
    (BarcodeType.EAN8, "A1234567", "digits only"),
    (BarcodeType.EAN13, "1234ABC890123", "digits only"),
    (BarcodeType.ITF, "2468A", "even number"),
])
def test_validate_digits_strict(barcode_type: BarcodeType, bad_data: str, expected_msg: str) -> None:
    gen = BarcodeGenerator(barcode_type, bad_data)
    with pytest.raises(BarcodeGenError, match=expected_msg):
        gen.validate()

def test_render_image_returns_placeholder_on_type_error() -> None:
    gen = BarcodeGenerator(BarcodeType.TELEPEN, "FAILNOTYPE")
    img = gen.render_image(width=88, height=44)
    assert isinstance(img, Image.Image)
    assert img.size == (88, 44)
    assert img.mode == "RGB"

def test_render_bytes_is_correct_type() -> None:
    gen = BarcodeGenerator(BarcodeType.CODE128, "DATA")
    data_bytes = gen.render_bytes()
    assert isinstance(data_bytes, bytes)
    assert data_bytes[:4] == b'\x89PNG'  # PNG magic bytes

def test_supported_types_and_name_map_are_consistent() -> None:
    types = BarcodeGenerator.supported_types()
    name_map = BarcodeGenerator.barcode_name_map()
    for t in types:
        assert t in name_map

@pytest.mark.parametrize("invalid_type", [999, "UNKNOWN", None])
def test_init_with_invalid_type_fails(invalid_type: Any) -> None:
    with pytest.raises(Exception):
        BarcodeGenerator(invalid_type, "123")
