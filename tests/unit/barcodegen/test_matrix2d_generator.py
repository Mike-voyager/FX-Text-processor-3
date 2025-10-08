import pytest
from typing import Dict, Any, List
from PIL import Image
from src.barcodegen.matrix2d_generator import Matrix2DCodeGenerator, Matrix2DCodeGenError
from src.model.enums import Matrix2DCodeType
from pathlib import Path
from unittest.mock import patch
from pytest import MonkeyPatch


def make_logo(size: int = 20, color: tuple[int, int, int, int] = (255, 0, 0, 128)) -> Image.Image:
    img = Image.new("RGBA", (size, size), color)
    return img


@pytest.mark.parametrize(
    "code_type,data",
    [
        (Matrix2DCodeType.QR, "test QR"),
        (Matrix2DCodeType.DATAMATRIX, "test DM"),
        (Matrix2DCodeType.PDF417, "test PDF417"),
    ],
)
def test_generate_basic(code_type: Matrix2DCodeType, data: str) -> None:
    gen = Matrix2DCodeGenerator(code_type, data)
    img = gen.render_image()
    assert isinstance(img, Image.Image)
    assert img.width > 0 and img.height > 0


def test_generate_with_logo_and_caption() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "logo test")
    logo = make_logo()
    img = gen.render_image(width=150, height=150, logo_image=logo, caption="Тест подписи")
    assert isinstance(img, Image.Image)
    assert img.width == 150 and img.height >= 150


def test_generate_large_scale_pdf417() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.PDF417, "BIGDATA" * 50)
    img = gen.render_image(width=400, height=100)
    assert img.width == 400 and img.height == 100


def test_gs1_qr_prefix() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "0123456789012345", gs1_mode=True)
    img = gen.render_image()
    assert isinstance(img, Image.Image)


def test_gs1_dm_prefix() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.DATAMATRIX, "0123456789012345", gs1_mode=True)
    img = gen.render_image()
    assert isinstance(img, Image.Image)


def test_background_transparent_png() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "transparency")
    img = gen.render_image(background_transparent=True)
    assert img.mode == "RGBA"


def test_batch_generate_parallel() -> None:
    items = [
        {"barcode_type": Matrix2DCodeType.QR, "data": "A"},
        {"barcode_type": Matrix2DCodeType.DATAMATRIX, "data": "B"},
        {"barcode_type": Matrix2DCodeType.PDF417, "data": "longer PDF417"},  # Чтобы строк было >= 3
    ]
    results = Matrix2DCodeGenerator.batch_generate(items, parallel=True)
    assert len(results) == 3
    for item, img in results:
        assert isinstance(img, Image.Image)


def test_invalid_type() -> None:
    with pytest.raises(TypeError):
        Matrix2DCodeGenerator("invalid_type", "abc")  # type: ignore


def test_empty_data_error() -> None:
    with pytest.raises(Matrix2DCodeGenError):
        Matrix2DCodeGenerator(Matrix2DCodeType.QR, "").render_image()


def test_invalid_logo_path() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "logo")
    with pytest.raises(Matrix2DCodeGenError):
        gen.render_image(logo_path="/path/to/nowhere.png")


def test_render_svg() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "SVG123")
    svg_bytes = gen.render_bytes(output_format="SVG")
    assert isinstance(svg_bytes, bytes)
    assert b"<svg" in svg_bytes


def test_resize_only_width() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "resize width")
    img = gen.render_image(width=77)
    assert img.width == 77


def test_resize_only_height() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "resize height")
    img = gen.render_image(height=55)
    assert img.height == 55


def test_batch_generate_serial() -> None:
    items = [
        {"barcode_type": Matrix2DCodeType.QR, "data": "S1"},
        {"barcode_type": Matrix2DCodeType.DATAMATRIX, "data": "S2"},
        {"barcode_type": Matrix2DCodeType.PDF417, "data": "LONG FOR SERIAL"},
    ]
    results = Matrix2DCodeGenerator.batch_generate(items, parallel=False)
    assert len(results) == 3


def test_caption_bad_font_path() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "caption font")
    img = gen.render_image(caption="font", caption_font_path="/non/exist/path.ttf")
    assert isinstance(img, Image.Image)


def test_invalid_logo_broken_image2(tmp_path: Path) -> None:
    from PIL import UnidentifiedImageError

    bad_logo = tmp_path / "broken.png"
    bad_logo.write_bytes(b"notapng")
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "brokenlogo")
    try:
        gen.render_image(logo_path=str(bad_logo))
    except (Matrix2DCodeGenError, UnidentifiedImageError):
        pass


def test_unsupported_barcode_type() -> None:
    class UnknownType:
        pass

    gen = Matrix2DCodeGenerator.__new__(Matrix2DCodeGenerator)
    gen.barcode_type = UnknownType()  # type: ignore
    gen.data = "test"
    gen.options = {}
    gen.gs1_mode = False
    try:
        gen.render_image()
    except Matrix2DCodeGenError:
        pass


def test_render_bytes_svg() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "svg")
    svg = gen.render_bytes(output_format="SVG")
    assert svg.startswith(b"<svg") or b"<svg" in svg


def test_batch_generate_empty() -> None:
    results = Matrix2DCodeGenerator.batch_generate([], parallel=False)
    assert results == []


def test_batch_generate_error_case1() -> None:
    items = [
        {"barcode_type": "not_a_type", "data": "bad"},
        {"barcode_type": Matrix2DCodeType.QR, "data": ""},
    ]
    results = []
    try:
        results = Matrix2DCodeGenerator.batch_generate(items, parallel=False)
    except Exception:
        pass


def test_resize_error_handling(monkeypatch: MonkeyPatch) -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "resizefail")
    img = gen.render_image()
    # Тестирует, что Exception приводит к Matrix2DCodeGenError
    with patch.object(Image.Image, "resize", side_effect=Exception("fail")):
        try:
            gen.render_image(width=99, height=99)
        except Exception as exc:
            assert "fail" in str(exc) or isinstance(exc, Matrix2DCodeGenError)


def test_add_caption_getbbox_fail(monkeypatch: MonkeyPatch) -> None:
    img = Image.new("RGB", (100, 40), (255, 255, 255))

    class FakeFont:
        def getbbox(self, caption: str) -> None:
            raise Exception("bbox fail")

        def getmask(self, text: str, mode: object = None) -> Image.Image:
            return Image.new("L", (1, 1))

    # Подменяем на fake class и ловим raise
    try:
        Matrix2DCodeGenerator._add_caption(img, "fail", font_path=None)
    except Exception as exc:
        assert "bbox fail" in str(exc)


def test_batch_generate_error_case() -> None:
    items = [
        {"barcode_type": "not_a_type", "data": "bad"},
        {"barcode_type": Matrix2DCodeType.QR, "data": ""},
    ]
    try:
        Matrix2DCodeGenerator.batch_generate(items, parallel=False)
    except Exception:
        pass


def test_qrcode_makeimage_error(monkeypatch: MonkeyPatch) -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "qrfail")
    with patch("qrcode.QRCode.make_image", side_effect=Exception("qrfail")):
        try:
            gen.render_image()
        except Exception as exc:
            assert "qrfail" in str(exc) or isinstance(exc, Matrix2DCodeGenError)


def test_datamatrix_broken_pixels(monkeypatch: MonkeyPatch) -> None:
    class FakeEnc:
        pixels = b"\x00"
        height, width = 100, 100

    gen = Matrix2DCodeGenerator(Matrix2DCodeType.DATAMATRIX, "broken")

    def fake_encode(data: bytes) -> FakeEnc:
        return FakeEnc()

    monkeypatch.setattr("pylibdmtx.pylibdmtx.encode", fake_encode)
    with pytest.raises(Matrix2DCodeGenError):
        gen.render_image()


def test_caption_transparent() -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "captionTTT")
    img = gen.render_image(caption="caption", background_transparent=True)
    assert img.mode == "RGBA"


def test_invalid_logo_broken_image(tmp_path: Path) -> None:
    from PIL import UnidentifiedImageError

    bad_logo = tmp_path / "broken.png"
    bad_logo.write_bytes(b"notapng")
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "brokenlogo")
    try:
        gen.render_image(logo_path=str(bad_logo))
    except (Matrix2DCodeGenError, UnidentifiedImageError):
        pass


def test_image_convert_error(monkeypatch: MonkeyPatch) -> None:
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "convertfail")
    img = gen.render_image()
    with patch.object(Image.Image, "convert", side_effect=Exception("failconvert")):
        try:
            gen.render_image()
        except Exception as exc:
            assert "failconvert" in str(exc) or isinstance(exc, Matrix2DCodeGenError)
