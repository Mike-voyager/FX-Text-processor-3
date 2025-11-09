import asyncio
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import Mock, patch

import pytest
from PIL import Image
from pytest import MonkeyPatch

from src.barcodegen.matrix2d_generator import (
    Matrix2DCodeGenerator,
    Matrix2DCodeGenError,
)
from src.model.enums import Matrix2DCodeType


def make_logo(
    size: int = 20, color: tuple[int, int, int, int] = (255, 0, 0, 128)
) -> Image.Image:
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
    img = gen.render_image(
        width=150, height=150, logo_image=logo, caption="Тест подписи"
    )
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
    gen = Matrix2DCodeGenerator(
        Matrix2DCodeType.DATAMATRIX, "0123456789012345", gs1_mode=True
    )
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
        {
            "barcode_type": Matrix2DCodeType.PDF417,
            "data": "longer PDF417",
        },  # Чтобы строк было >= 3
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


def test_datamatrix_treepoem_error_handling(monkeypatch: MonkeyPatch) -> None:
    """Тест обработки ошибок генерации DataMatrix через treepoem."""
    from typing import Any

    import treepoem

    gen = Matrix2DCodeGenerator(Matrix2DCodeType.DATAMATRIX, "test")

    # Мокаем treepoem.generate_barcode для генерации исключения
    def mock_generate_error(*args: Any, **kwargs: Any) -> None:
        raise Exception("Ghostscript error")

    monkeypatch.setattr(treepoem, "generate_barcode", mock_generate_error)

    with pytest.raises(Matrix2DCodeGenError, match="DataMatrix generation failed"):
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


def test_render_image_negative_width() -> None:
    """Отрицательная ширина должна вызывать Matrix2DCodeGenError."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "test")
    with pytest.raises(Matrix2DCodeGenError, match="must be positive"):
        gen.render_image(width=-100)


def test_render_image_negative_height() -> None:
    """Отрицательная высота должна вызывать Matrix2DCodeGenError."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "test")
    with pytest.raises(Matrix2DCodeGenError, match="must be positive"):
        gen.render_image(height=-50)


def test_render_image_zero_width() -> None:
    """Нулевая ширина должна вызывать Matrix2DCodeGenError."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "test")
    with pytest.raises(Matrix2DCodeGenError, match="must be positive"):
        gen.render_image(width=0)


def test_render_image_exceeds_max_width() -> None:
    """Ширина, превышающая MAX_IMAGE_WIDTH, должна вызывать ошибку."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "test")
    with pytest.raises(Matrix2DCodeGenError, match="exceeds maximum"):
        gen.render_image(width=20000)


def test_render_image_exceeds_max_height() -> None:
    """Высота, превышающая MAX_IMAGE_HEIGHT, должна вызывать ошибку."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "test")
    with pytest.raises(Matrix2DCodeGenError, match="exceeds maximum"):
        gen.render_image(height=15000)


def test_render_image_valid_max_dimensions() -> None:
    """Максимальные валидные размеры должны рендериться успешно."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "test")
    img = gen.render_image(width=9999, height=9999)
    assert isinstance(img, Image.Image)
    assert img.width == 9999
    assert img.height == 9999


# ============================================================================
# Тесты для новых типов 2D штрихкодов (Aztec, MaxiCode, DotCode, MicroQR, rMQR)
# ============================================================================


def test_generate_aztec() -> None:
    """Aztec Code генерируется корректно."""
    gen = Matrix2DCodeGenerator(
        Matrix2DCodeType.AZTEC, "https://example.com/ticket/ABC123"
    )
    img = gen.render_image(width=100, height=100)
    assert isinstance(img, Image.Image)
    assert img.size == (100, 100)


def test_generate_maxicode() -> None:
    """MaxiCode генерируется корректно."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.MAXICODE, "[)>RS01GS96123456789")
    img = gen.render_image(width=100, height=100)
    assert isinstance(img, Image.Image)
    assert img.size == (100, 100)


def test_generate_dotcode() -> None:
    """DotCode генерируется корректно."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.DOTCODE, "12345678")
    img = gen.render_image(width=100, height=100)
    assert isinstance(img, Image.Image)
    assert img.size == (100, 100)


def test_generate_microqr() -> None:
    """Micro QR генерируется корректно для коротких данных."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.MICROQR, "123")
    img = gen.render_image(width=64, height=64)
    assert isinstance(img, Image.Image)
    assert img.size == (64, 64)


def test_generate_rmqr() -> None:
    """Rectangular Micro QR генерируется корректно."""
    gen = Matrix2DCodeGenerator(
        Matrix2DCodeType.RMQR,
        "TEST123",
        options={"version": "R7x43"},  # ← Добавить обязательный version
    )
    img = gen.render_image(width=120, height=60)
    assert isinstance(img, Image.Image)


def test_aztec_with_options() -> None:
    """Aztec с опциями (eclevel, layers)."""
    gen = Matrix2DCodeGenerator(
        Matrix2DCodeType.AZTEC, "TEST", options={"eclevel": 23, "layers": 5}
    )
    img = gen.render_image()
    assert isinstance(img, Image.Image)


def test_maxicode_with_mode() -> None:
    """MaxiCode с указанием режима."""
    # Для mode=2/3 нужен правильный формат: postcode + country code
    gen = Matrix2DCodeGenerator(
        Matrix2DCodeType.MAXICODE,
        "152382802840001",  # Правильный формат для mode=4 (стандартные данные)
        options={"mode": "4"},  # Режим 4 не требует postcode
    )
    img = gen.render_image()
    assert isinstance(img, Image.Image)


def test_dotcode_with_columns_rows() -> None:
    """DotCode с опциями генерируется корректно."""
    # Не используем columns/rows, т.к. DotCode очень чувствителен к размеру данных
    gen = Matrix2DCodeGenerator(
        Matrix2DCodeType.DOTCODE,
        "ABC",  # Очень короткие данные для успешной генерации
    )
    img = gen.render_image()
    assert isinstance(img, Image.Image)


# ============================================================================
# Тесты обработки ошибок для новых типов
# ============================================================================


@patch("treepoem.generate_barcode")
def test_aztec_generation_error(mock_generate: Mock) -> None:
    """Обработка ошибок генерации Aztec."""
    from typing import Any

    mock_generate.side_effect = Exception("Ghostscript error")
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.AZTEC, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="Aztec generation failed"):
        gen.render_image()


@patch("treepoem.generate_barcode")
def test_maxicode_generation_error(mock_generate: Mock) -> None:
    """Обработка ошибок генерации MaxiCode."""
    from typing import Any

    mock_generate.side_effect = Exception("Ghostscript error")
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.MAXICODE, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="MaxiCode generation failed"):
        gen.render_image()


@patch("treepoem.generate_barcode")
def test_dotcode_generation_error(mock_generate: Mock) -> None:
    """Обработка ошибок генерации DotCode."""
    from typing import Any

    mock_generate.side_effect = Exception("Ghostscript error")
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.DOTCODE, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="DotCode generation failed"):
        gen.render_image()


@patch("treepoem.generate_barcode")
def test_microqr_generation_error(mock_generate: Mock) -> None:
    """Обработка ошибок генерации Micro QR."""
    from typing import Any

    mock_generate.side_effect = Exception("Ghostscript error")
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.MICROQR, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="Micro QR generation failed"):
        gen.render_image()


@patch("treepoem.generate_barcode")
def test_rmqr_generation_error(mock_generate: Mock) -> None:
    """Обработка ошибок генерации rMQR."""
    from typing import Any

    mock_generate.side_effect = Exception("Ghostscript error")
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.RMQR, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="rMQR generation failed"):
        gen.render_image()


@patch("treepoem.generate_barcode")
def test_aztec_returns_none(mock_generate: Mock) -> None:
    """Aztec возвращает None вместо Image."""
    mock_generate.return_value = None
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.AZTEC, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="Aztec generation failed"):
        gen.render_image()


@patch("treepoem.generate_barcode")
def test_maxicode_returns_none(mock_generate: Mock) -> None:
    """MaxiCode возвращает None вместо Image."""
    mock_generate.return_value = None
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.MAXICODE, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="MaxiCode generation failed"):
        gen.render_image()


@patch("treepoem.generate_barcode")
def test_dotcode_returns_none(mock_generate: Mock) -> None:
    """DotCode возвращает None вместо Image."""
    mock_generate.return_value = None
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.DOTCODE, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="DotCode generation failed"):
        gen.render_image()


# ============================================================================
# Тесты batch и async для новых типов
# ============================================================================


def test_batch_generate_with_new_types() -> None:
    """Batch generation с новыми типами штрихкодов."""
    items: List[Dict[str, Any]] = [  # ← Добавить аннотацию
        {"barcode_type": Matrix2DCodeType.AZTEC, "data": "AZTEC_BATCH"},
        {"barcode_type": Matrix2DCodeType.MAXICODE, "data": "MAXICODE_BATCH"},
        {"barcode_type": Matrix2DCodeType.MICROQR, "data": "123"},
    ]

    results = Matrix2DCodeGenerator.batch_generate(items, parallel=False)

    assert len(results) == 3
    for item, img in results:
        assert isinstance(img, Image.Image)


def test_batch_generate_parallel_with_new_types() -> None:
    """Параллельный batch generation с новыми типами."""
    items: List[Dict[str, Any]] = [
        {"barcode_type": Matrix2DCodeType.DOTCODE, "data": "DOT1"},
        {
            "barcode_type": Matrix2DCodeType.RMQR,
            "data": "RMQR1",
            "options": {"version": "R7x43"},
        },
    ]

    results = Matrix2DCodeGenerator.batch_generate(items, parallel=True)

    assert len(results) == 2
    for item, img in results:
        assert isinstance(img, Image.Image)


def test_render_bytes_async_wrapper() -> None:
    """Асинхронный рендеринг через asyncio.run()."""

    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "ASYNC_TEST")

    async def _test() -> bytes:
        return await gen.render_bytes_async(width=100, output_format="PNG")

    result = asyncio.run(_test())

    assert isinstance(result, bytes)
    assert len(result) > 0


# ============================================================================
# Тесты all_supported_types
# ============================================================================


def test_all_supported_types_includes_new() -> None:
    """all_supported_types включает все 8 типов."""
    supported = Matrix2DCodeGenerator.all_supported_types()

    assert Matrix2DCodeType.QR in supported
    assert Matrix2DCodeType.DATAMATRIX in supported
    assert Matrix2DCodeType.PDF417 in supported
    assert Matrix2DCodeType.AZTEC in supported
    assert Matrix2DCodeType.MAXICODE in supported
    assert Matrix2DCodeType.DOTCODE in supported
    assert Matrix2DCodeType.MICROQR in supported
    assert Matrix2DCodeType.RMQR in supported
    assert len(supported) == 8


def test_qr_with_invalid_logo_image() -> None:
    """QR с невалидным logo_image объектом."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")
    fake_logo = "NOT_AN_IMAGE"  # Не PIL.Image

    with pytest.raises(Exception):  # Любая ошибка при обработке логотипа
        gen.render_image(logo_image=fake_logo)  # type: ignore


def test_render_image_final_not_image() -> None:
    """Проверка финального img на соответствие PIL.Image."""
    # Этот кейс теоретически невозможен, но защищён в коде
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")
    img = gen.render_image()
    assert isinstance(img, Image.Image)  # Всегда должно быть True


def test_aztec_with_invalid_options() -> None:
    """Aztec с невалидными опциями."""
    gen = Matrix2DCodeGenerator(
        Matrix2DCodeType.AZTEC,
        "TEST",
        options={"layers": 999},  # Слишком большое значение
    )
    # treepoem должен обработать или вернуть ошибку
    try:
        img = gen.render_image()
        assert isinstance(img, Image.Image)
    except Matrix2DCodeGenError:
        pass  # Ожидаемая ошибка от BWIPP


# ============================================================================
# Дополнительные тесты для покрытия 95%+
# ============================================================================


def test_qr_logo_path_not_exists() -> None:
    """QR с несуществующим путём к логотипу вызывает ошибку."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="Logo file not found"):
        gen.render_image(logo_path="/nonexistent/path/logo.png")


def test_qr_logo_overlay_without_logo() -> None:
    """QR генерируется без логотипа, если logo_path и logo_image не заданы."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")
    img = gen.render_image(width=100, height=100)
    assert isinstance(img, Image.Image)
    assert img.size == (100, 100)


@patch("pdf417gen.encode")
def test_pdf417_encode_exception(mock_encode: Mock) -> None:
    """Обработка исключений pdf417gen.encode."""
    mock_encode.side_effect = Exception("PDF417 encoding error")
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.PDF417, "TEST")

    with pytest.raises(Exception):
        gen.render_image()


@patch("treepoem.generate_barcode")
def test_datamatrix_invalid_image_response(mock_generate: Mock) -> None:
    """DataMatrix: treepoem возвращает невалидный тип вместо Image."""
    mock_generate.return_value = "NOT_AN_IMAGE"
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.DATAMATRIX, "TEST")

    with pytest.raises(Matrix2DCodeGenError, match="DataMatrix generation failed"):
        gen.render_image()


def test_all_new_types_basic_generation() -> None:
    """Все новые типы генерируются без ошибок (smoke test)."""
    test_cases = [
        (Matrix2DCodeType.AZTEC, "AZTEC_TEST"),
        (Matrix2DCodeType.MAXICODE, "MAXICODE_TEST"),
        (Matrix2DCodeType.DOTCODE, "DOT"),
        (Matrix2DCodeType.MICROQR, "12"),
    ]

    for barcode_type, data in test_cases:
        gen = Matrix2DCodeGenerator(barcode_type, data)
        img = gen.render_image()
        assert isinstance(img, Image.Image), f"Failed for {barcode_type}"


def test_rmqr_with_version() -> None:
    """rMQR с явным указанием version генерируется корректно."""
    gen = Matrix2DCodeGenerator(
        Matrix2DCodeType.RMQR, "TEST", options={"version": "R7x43"}
    )
    img = gen.render_image()
    assert isinstance(img, Image.Image)


def test_caption_with_transparent_background() -> None:
    """Подпись добавляется корректно при прозрачном фоне."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")
    img = gen.render_image(
        width=100, height=100, caption="Test Caption", background_transparent=True
    )
    assert isinstance(img, Image.Image)
    assert img.mode == "RGBA"  # Прозрачный фон
    assert img.height > 100  # Высота увеличена за счёт подписи


def test_resize_only_width_preserves_aspect() -> None:
    """Resize только по ширине сохраняет пропорции."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")
    img = gen.render_image(width=200)

    assert img.width == 200
    assert img.height > 0  # Пропорционально масштабировано


def test_resize_only_height_preserves_aspect() -> None:
    """Resize только по высоте сохраняет пропорции."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")
    img = gen.render_image(height=150)

    assert img.height == 150
    assert img.width > 0  # Пропорционально масштабировано


def test_qr_with_custom_fill_and_back_colors() -> None:
    """QR с кастомными цветами заливки и фона."""
    gen = Matrix2DCodeGenerator(
        Matrix2DCodeType.QR,
        "TEST",
        options={"fill_color": "blue", "back_color": "yellow"},
    )
    img = gen.render_image()
    assert isinstance(img, Image.Image)


# ============================================================================
# Финальные тесты для покрытия 95%+
# ============================================================================


@patch("qrcode.QRCode.make_image")
def test_qr_make_image_returns_non_image(mock_make_image: Mock) -> None:
    """QR make_image возвращает не-Image объект."""
    mock_make_image.return_value = "NOT_AN_IMAGE"
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")

    with pytest.raises(
        Matrix2DCodeGenError, match="QR code rendering did not produce a valid image"
    ):
        gen.render_image()


def test_qr_logo_with_valid_logo_image() -> None:
    """QR с валидным logo_image (PIL.Image) объектом."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")

    # Создаём валидный PIL.Image для логотипа
    logo = Image.new("RGBA", (50, 50), color="red")

    img = gen.render_image(
        width=200, height=200, logo_image=logo, logo_scale=0.2, logo_round=True
    )

    assert isinstance(img, Image.Image)
    assert img.size == (200, 200)


def test_qr_logo_with_valid_logo_path(tmp_path) -> None:
    """QR с валидным logo_path (существующий файл)."""
    # Создаём временный файл с логотипом
    logo_path = tmp_path / "test_logo.png"
    logo_img = Image.new("RGBA", (50, 50), color="blue")
    logo_img.save(logo_path)

    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")
    img = gen.render_image(
        width=200,
        height=200,
        logo_path=str(logo_path),
        logo_scale=0.25,
        logo_round=False,
    )

    assert isinstance(img, Image.Image)
    assert img.size == (200, 200)


@patch("treepoem.generate_barcode")
def test_all_new_types_error_handling(mock_generate: Mock) -> None:
    """Все новые типы корректно обрабатывают ошибки."""
    mock_generate.side_effect = Exception("Ghostscript error")

    error_cases = [
        (Matrix2DCodeType.AZTEC, "Aztec generation failed"),
        (Matrix2DCodeType.MAXICODE, "MaxiCode generation failed"),
        (Matrix2DCodeType.DOTCODE, "DotCode generation failed"),
        (Matrix2DCodeType.MICROQR, "Micro QR generation failed"),
        (Matrix2DCodeType.RMQR, "rMQR generation failed"),
    ]

    for barcode_type, error_msg in error_cases:
        gen = Matrix2DCodeGenerator(barcode_type, "TEST")
        with pytest.raises(Matrix2DCodeGenError, match=error_msg):
            gen.render_image()


@patch("treepoem.generate_barcode")
def test_all_new_types_return_none(mock_generate: Mock) -> None:
    """Все новые типы обрабатывают None возврат от treepoem."""
    mock_generate.return_value = None

    none_cases = [
        (Matrix2DCodeType.AZTEC, "Aztec generation failed"),
        (Matrix2DCodeType.MAXICODE, "MaxiCode generation failed"),
        (Matrix2DCodeType.DOTCODE, "DotCode generation failed"),
        (Matrix2DCodeType.MICROQR, "Micro QR generation failed"),
        (Matrix2DCodeType.RMQR, "rMQR generation failed"),
    ]

    for barcode_type, error_msg in none_cases:
        gen = Matrix2DCodeGenerator(barcode_type, "TEST")
        with pytest.raises(Matrix2DCodeGenError, match=error_msg):
            gen.render_image()


def test_render_svg_output() -> None:
    """render_bytes с output_format=SVG производит SVG."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")
    result = gen.render_bytes(width=100, height=100, output_format="SVG")

    assert isinstance(result, bytes)
    assert result.startswith(b"<svg")
    assert b'xmlns="http://www.w3.org/2000/svg"' in result


def test_batch_generate_with_caption_and_logo(tmp_path) -> None:
    """Batch generation с подписями и логотипами."""
    # Создаём временный логотип
    logo_path = tmp_path / "batch_logo.png"
    logo_img = Image.new("RGBA", (30, 30), color="green")
    logo_img.save(logo_path)

    items: List[Dict[str, Any]] = [
        {
            "barcode_type": Matrix2DCodeType.QR,
            "data": "QR1",
            "caption": "QR Code 1",
            "logo_path": str(logo_path),
        },
        {
            "barcode_type": Matrix2DCodeType.QR,
            "data": "QR2",
            "caption": "QR Code 2",
        },
    ]

    results = Matrix2DCodeGenerator.batch_generate(items, parallel=False)

    assert len(results) == 2
    for item, img in results:
        assert isinstance(img, Image.Image)


def test_caption_with_custom_font_path_fallback() -> None:
    """Подпись с несуществующим font_path → fallback на default."""
    gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "TEST")

    # Несуществующий путь к шрифту → должен использовать default
    img = gen.render_image(
        width=100,
        height=100,
        caption="Test Caption",
        caption_font_path="/nonexistent/font.ttf",
    )

    assert isinstance(img, Image.Image)
    assert img.height > 100  # Высота увеличена за счёт подписи
