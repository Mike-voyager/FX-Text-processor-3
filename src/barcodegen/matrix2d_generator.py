"""
RU: Генерация 2D-штрихкодов (QR, DataMatrix, PDF417, Aztec, MaxiCode, DotCode, MicroQR, rMQR) с поддержкой GS1, логотипа
EN: 2D barcode generator (QR, DataMatrix, PDF417, Aztec, MaxiCode, DotCode, MicroQR, rMQR) with GS1, logo and caption support

Provides:
- QR, DataMatrix, PDF417, Aztec, MaxiCode, DotCode, MicroQR, rMQR image generation
- GS1 payload processing
- Logo overlays, captions
- Batch and async generation
- Typed public API

Requirements: Pillow, qrcode, pdf417gen, treepoem (для DataMatrix, Aztec, MaxiCode, DotCode, MicroQR, rMQR + Ghostscript)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Final, List, Optional, Set, Tuple, Union

import pdf417gen
import qrcode
from PIL import Image, ImageDraw, ImageFont
from PIL.ImageFont import FreeTypeFont
from PIL.ImageFont import ImageFont as PILImageFont
from qrcode.constants import ERROR_CORRECT_H, ERROR_CORRECT_M

from src.model.enums import Matrix2DCodeType

# Pillow compatibility layer (L -> new Resampling)
try:
    from PIL.Image import Resampling

    RESAMPLE_LANCZOS = Resampling.LANCZOS
    RESAMPLE_BOX = Resampling.BOX
except ImportError:
    RESAMPLE_LANCZOS = Image.LANCZOS  # type: ignore[assignment]
    RESAMPLE_BOX = Image.BOX  # type: ignore[assignment]

logger = logging.getLogger(__name__)

__all__ = [
    "Matrix2DCodeGenerator",
    "Matrix2DCodeGenError",
]

# Максимальные размеры для предотвращения исчерпания памяти
# ~100MB для RGB изображения при максимальных размерах
MAX_IMAGE_WIDTH: Final[int] = 10000
MAX_IMAGE_HEIGHT: Final[int] = 10000

# Константы разметки подписи
CAPTION_VERTICAL_SPACING: Final[int] = 8  # Полный вертикальный интервал для подписи
CAPTION_TOP_MARGIN: Final[int] = 4  # Расстояние между штрихкодом и текстом подписи


class Matrix2DCodeGenError(Exception):
    """2D barcode generation error (Ошибка генерации 2D-штрихкода)."""


class Matrix2DCodeGenerator:
    """2D-code generator for QR/DataMatrix/PDF417/Aztec/MaxiCode/DotCode/MicroQR/rMQR with rich rendering options.

    Args:
        barcode_type: Barcode type (QR, DataMatrix, PDF417, Aztec, MaxiCode, DotCode, MicroQR, rMQR).
        data: Source data to encode.
        options: Rendering options (interpreted per barcode type).
        gs1_mode: Enable GS1 prefix preprocessing.

    Examples:
        >>> gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "test123")
        >>> img = gen.render_image(width=200, height=200, caption="Demo")
        >>> aztec = Matrix2DCodeGenerator(Matrix2DCodeType.AZTEC, "https://example.com/ticket")
        >>> microqr = Matrix2DCodeGenerator(Matrix2DCodeType.MICROQR, "123")
    """

    _qr_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.QR}
    _datamatrix_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.DATAMATRIX}
    _pdf417_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.PDF417}
    _aztec_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.AZTEC}
    _maxicode_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.MAXICODE}
    _dotcode_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.DOTCODE}
    _microqr_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.MICROQR}
    _rmqr_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.RMQR}

    def __init__(
        self,
        barcode_type: Matrix2DCodeType,
        data: str,
        options: Optional[Dict[str, Any]] = None,
        gs1_mode: bool = False,
    ) -> None:
        if not isinstance(barcode_type, Matrix2DCodeType):
            logger.error(
                "barcode_type must be Matrix2DCodeType, got %r", type(barcode_type)
            )
            raise TypeError("barcode_type must be Matrix2DCodeType")
        self.barcode_type = barcode_type
        self.data = data
        self.options = options or {}
        self.gs1_mode = gs1_mode

    def validate(self) -> None:
        """Validate data and barcode type for this generator instance.

        Raises:
            Matrix2DCodeGenError: For empty data or unsupported type.
        """
        if not isinstance(self.data, str) or not self.data.strip():
            logger.error("Input data is empty or not string, got %r", self.data)
            raise Matrix2DCodeGenError("Data must be a non-empty string")
        if self.barcode_type not in self.all_supported_types():
            logger.error("Barcode type %r not supported", self.barcode_type)
            raise Matrix2DCodeGenError(
                f"Barcode type {self.barcode_type!r} not supported for 2D generation"
            )

    def get_payload(self) -> str:
        """Return data with GS1 prefixes as needed for barcode type.

        Returns:
            str: Encoded payload with GS1 prefix if applicable.
        """
        if self.gs1_mode:
            if self.barcode_type in self._qr_types:
                if not self.data.startswith("]C1"):
                    return "]C1" + self.data
            elif self.barcode_type in self._datamatrix_types:
                if not self.data.startswith("\x1d"):
                    return "\x1d" + self.data
        return self.data

    def render_image(
        self,
        width: Optional[int] = None,
        height: Optional[int] = None,
        options: Optional[Dict[str, Any]] = None,
        logo_path: Optional[str] = None,
        logo_image: Optional[Image.Image] = None,
        logo_scale: float = 0.25,
        logo_round: bool = True,
        caption: Optional[str] = None,
        caption_font_path: Optional[str] = None,
        caption_font_size: int = 14,
        output_format: str = "PNG",
        background_transparent: bool = False,
    ) -> Image.Image:
        """
        Render 2D code as PIL Image with optional logo/caption/scaling.

        Args:
            width: Target width.
            height: Target height.
            options: Per-type rendering options.
            logo_path: Optional logo to overlay (centered).
            logo_image: Optional PIL image as logo overlay.
            logo_scale: Logo scale relative to code min(width, height).
            logo_round: Render logo with circular mask.
            caption: Optional caption (text) under the code.
            caption_font_path: Path to caption font file.
            caption_font_size: Caption text size.
            output_format: Output format for saving ("PNG", "SVG" etc.).
            background_transparent: Alpha background if True.

        Returns:
            Rendered PIL Image (RGB or RGBA).
        Raises:
            Matrix2DCodeGenError: on invalid state or IO errors.

        Example:
            >>> img = gen.render_image(width=120, logo_path="logo.png", caption="test")
        """
        import qrcode.image.pil

        # Валидация размеров перед рендерингом
        if width is not None:
            if width <= 0:
                raise Matrix2DCodeGenError(f"Width must be positive, got {width}")
            if width > MAX_IMAGE_WIDTH:
                raise Matrix2DCodeGenError(
                    f"Width {width} exceeds maximum {MAX_IMAGE_WIDTH}px"
                )
        if height is not None:
            if height <= 0:
                raise Matrix2DCodeGenError(f"Height must be positive, got {height}")
            if height > MAX_IMAGE_HEIGHT:
                raise Matrix2DCodeGenError(
                    f"Height {height} exceeds maximum {MAX_IMAGE_HEIGHT}px"
                )

        self.validate()
        opts = dict(self.options)
        if options:
            opts.update(options)
        payload = self.get_payload()

        # Объявляем img с типом для mypy
        img: Image.Image

        # --- QR
        if self.barcode_type in self._qr_types:
            qr_version = opts.get("version", None)
            box_size = opts.get("box_size", 10)
            border = opts.get("border", 4)
            error_correction = opts.get(
                "error_correction",
                ERROR_CORRECT_H if (logo_path or logo_image) else ERROR_CORRECT_M,
            )
            fill_color = opts.get("fill_color", "black")
            back_color = (
                opts.get("back_color", "white") if not background_transparent else None
            )
            qr = qrcode.QRCode(
                version=qr_version,
                error_correction=error_correction,
                box_size=box_size,
                border=border,
            )
            qr.add_data(payload)
            qr.make(fit=True)
            qr_img = qr.make_image(
                fill_color=fill_color,
                back_color=back_color,
                image_factory=qrcode.image.pil.PilImage,
            )
            if hasattr(qr_img, "get_image"):
                qr_img = qr_img.get_image()
            if not isinstance(qr_img, Image.Image):
                logger.error("QR code did not produce a PIL.Image")
                raise Matrix2DCodeGenError(
                    "QR code rendering did not produce a valid image"
                )
            qr_img = qr_img.convert("RGBA" if background_transparent else "RGB")
            # Overlay logo
            if logo_path or logo_image:
                logo = logo_image
                if logo is None and logo_path:
                    if not os.path.exists(logo_path):
                        logger.error("Logo file not found: %r", logo_path)
                        raise Matrix2DCodeGenError(f"Logo file not found: {logo_path}")
                    logo = Image.open(logo_path).convert("RGBA")
                if logo is not None:
                    min_side = min(qr_img.width, qr_img.height)
                    logo_size = max(
                        10, min(int(min_side * logo_scale), int(min_side * 0.5))
                    )
                    logo = logo.resize(
                        (logo_size, logo_size), resample=RESAMPLE_LANCZOS
                    )
                    if logo_round:
                        mask = Image.new("L", (logo_size, logo_size), 0)
                        draw = ImageDraw.Draw(mask)
                        draw.ellipse((0, 0, logo_size, logo_size), fill=255)
                        logo.putalpha(mask)
                    qr_img = qr_img.convert("RGBA")
                    px = (qr_img.width - logo.width) // 2
                    py = (qr_img.height - logo.height) // 2
                    qr_img.alpha_composite(logo, (px, py))
                    if not background_transparent:
                        qr_img = qr_img.convert("RGB")
            img = qr_img

        # --- DataMatrix
        elif self.barcode_type in self._datamatrix_types:
            try:
                import treepoem
            except ImportError:
                logger.error("treepoem not installed for DataMatrix")
                raise Matrix2DCodeGenError(
                    "treepoem not installed (install with: pip install treepoem)"
                )

            try:
                dm_opts = {}
                if "columns" in opts:
                    dm_opts["columns"] = opts["columns"]

                dm_img = treepoem.generate_barcode(
                    barcode_type="datamatrix",
                    data=payload,
                    options=dm_opts,
                )

                if dm_img is None or not isinstance(dm_img, Image.Image):
                    logger.error("treepoem did not produce a valid DataMatrix image")
                    raise Matrix2DCodeGenError(
                        "DataMatrix generation failed via treepoem"
                    )

                img = dm_img.convert("RGBA" if background_transparent else "RGB")

            except Matrix2DCodeGenError:
                raise
            except Exception as e:
                logger.error("DataMatrix generation error: %r", e)
                raise Matrix2DCodeGenError(f"DataMatrix generation failed: {e}") from e

        # --- PDF417
        elif self.barcode_type in self._pdf417_types:
            codes = pdf417gen.encode(
                payload,
                columns=opts.get("columns", 6),
                security_level=opts.get("security_level", 2),
            )
            pdf_img = pdf417gen.render_image(codes, scale=opts.get("scale", 3)).convert(
                "RGBA" if background_transparent else "RGB"
            )
            img = pdf_img

        # --- Aztec
        elif self.barcode_type in self._aztec_types:
            try:
                import treepoem
            except ImportError:
                raise Matrix2DCodeGenError(
                    "treepoem not installed (pip install treepoem)"
                )

            try:
                aztec_opts = {}
                if "eclevel" in opts:
                    aztec_opts["eclevel"] = opts["eclevel"]
                if "layers" in opts:
                    aztec_opts["layers"] = opts["layers"]

                aztec_img = treepoem.generate_barcode(
                    barcode_type="azteccode",
                    data=payload,
                    options=aztec_opts,
                )

                if not isinstance(aztec_img, Image.Image):
                    raise Matrix2DCodeGenError("Aztec generation failed")

                img = aztec_img.convert("RGBA" if background_transparent else "RGB")

            except Matrix2DCodeGenError:
                raise
            except Exception as e:
                logger.error("Aztec generation error: %r", e)
                raise Matrix2DCodeGenError(f"Aztec generation failed: {e}") from e

        # --- MaxiCode
        elif self.barcode_type in self._maxicode_types:
            try:
                import treepoem
            except ImportError:
                raise Matrix2DCodeGenError(
                    "treepoem not installed (pip install treepoem)"
                )

            try:
                maxicode_opts = {}
                if "mode" in opts:
                    maxicode_opts["mode"] = opts["mode"]

                maxicode_img = treepoem.generate_barcode(
                    barcode_type="maxicode",
                    data=payload,
                    options=maxicode_opts,
                )

                if not isinstance(maxicode_img, Image.Image):
                    raise Matrix2DCodeGenError("MaxiCode generation failed")

                img = maxicode_img.convert("RGBA" if background_transparent else "RGB")

            except Matrix2DCodeGenError:
                raise
            except Exception as e:
                logger.error("MaxiCode generation error: %r", e)
                raise Matrix2DCodeGenError(f"MaxiCode generation failed: {e}") from e

        # --- DotCode
        elif self.barcode_type in self._dotcode_types:
            try:
                import treepoem
            except ImportError:
                raise Matrix2DCodeGenError(
                    "treepoem not installed (pip install treepoem)"
                )

            try:
                dotcode_opts = {}
                if "columns" in opts:
                    dotcode_opts["columns"] = opts["columns"]
                if "rows" in opts:
                    dotcode_opts["rows"] = opts["rows"]

                dotcode_img = treepoem.generate_barcode(
                    barcode_type="dotcode",
                    data=payload,
                    options=dotcode_opts,
                )

                if not isinstance(dotcode_img, Image.Image):
                    raise Matrix2DCodeGenError("DotCode generation failed")

                img = dotcode_img.convert("RGBA" if background_transparent else "RGB")

            except Matrix2DCodeGenError:
                raise
            except Exception as e:
                logger.error("DotCode generation error: %r", e)
                raise Matrix2DCodeGenError(f"DotCode generation failed: {e}") from e

        # --- Micro QR
        elif self.barcode_type in self._microqr_types:
            try:
                import treepoem
            except ImportError:
                raise Matrix2DCodeGenError(
                    "treepoem not installed (pip install treepoem)"
                )

            try:
                microqr_opts = {}
                if "eclevel" in opts:
                    microqr_opts["eclevel"] = opts["eclevel"]

                microqr_img = treepoem.generate_barcode(
                    barcode_type="microqrcode",
                    data=payload,
                    options=microqr_opts,
                )

                if not isinstance(microqr_img, Image.Image):
                    raise Matrix2DCodeGenError("Micro QR generation failed")

                img = microqr_img.convert("RGBA" if background_transparent else "RGB")

            except Matrix2DCodeGenError:
                raise
            except Exception as e:
                logger.error("Micro QR generation error: %r", e)
                raise Matrix2DCodeGenError(f"Micro QR generation failed: {e}") from e

        # --- Rectangular Micro QR (rMQR)
        elif self.barcode_type in self._rmqr_types:
            try:
                import treepoem
            except ImportError:
                raise Matrix2DCodeGenError(
                    "treepoem not installed (pip install treepoem)"
                )

            try:
                rmqr_opts = {}
                if "version" in opts:
                    rmqr_opts["version"] = opts["version"]

                rmqr_img = treepoem.generate_barcode(
                    barcode_type="rectangularmicroqrcode",
                    data=payload,
                    options=rmqr_opts,
                )

                if not isinstance(rmqr_img, Image.Image):
                    raise Matrix2DCodeGenError("rMQR generation failed")

                img = rmqr_img.convert("RGBA" if background_transparent else "RGB")

            except Matrix2DCodeGenError:
                raise
            except Exception as e:
                logger.error("rMQR generation error: %r", e)
                raise Matrix2DCodeGenError(f"rMQR generation failed: {e}") from e

        else:
            logger.error("Unsupported 2D barcode type %r", self.barcode_type)
            raise Matrix2DCodeGenError(
                f"Unsupported 2D barcode type: {self.barcode_type!r}"
            )

        # --- Resize
        if not isinstance(img, Image.Image):
            logger.error("Final image is not PIL.Image")
            raise Matrix2DCodeGenError("Final image is not a valid PIL image")
        if width and height:
            img = img.resize((width, height), resample=RESAMPLE_BOX)
        elif width:
            h = int(round(img.height * (width / img.width)))
            img = img.resize((width, h), resample=RESAMPLE_BOX)
        elif height:
            w = int(round(img.width * (height / img.height)))
            img = img.resize((w, height), resample=RESAMPLE_BOX)

        # --- Caption
        if caption:
            img = self._add_caption(
                img,
                caption,
                font_path=caption_font_path,
                font_size=caption_font_size,
                transparent=background_transparent,
            )
        logger.info(
            "2D code generated: %s type, %r chars", self.barcode_type.name, len(payload)
        )
        return img

    @staticmethod
    def _add_caption(
        img: Image.Image,
        caption: str,
        font_path: Optional[str] = None,
        font_size: int = 14,
        transparent: bool = False,
    ) -> Image.Image:
        """Draw a caption below the image.

        Args:
            img: Input image.
            caption: Caption text.
            font_path: Font to use for text.
            font_size: Text size.
            transparent: RGBA mode if True.

        Returns:
            New Image.Image with appended caption.

        Example:
            >>> Matrix2DCodeGenerator._add_caption(img, "test")
        """
        font: Union[FreeTypeFont, PILImageFont] = ImageFont.load_default()
        try:
            if font_path:
                font = ImageFont.truetype(font_path, font_size)
        except Exception as e:
            logger.warning("Failed to load caption font (%r): %r", font_path, e)
            font = ImageFont.load_default()
        txt_bbox = font.getbbox(caption)
        txt_width = txt_bbox[2] - txt_bbox[0]
        txt_height = txt_bbox[3] - txt_bbox[1]
        new_h = img.height + txt_height + CAPTION_VERTICAL_SPACING
        result = Image.new(
            "RGBA" if transparent else "RGB",
            (int(img.width), int(new_h)),
            (255, 255, 255, 0) if transparent else (255, 255, 255),
        )
        result.paste(img, (0, 0))
        draw = ImageDraw.Draw(result)
        pos = ((img.width - txt_width) // 2, img.height + CAPTION_TOP_MARGIN)
        color = (0, 0, 0, 255) if transparent else (0, 0, 0)
        draw.text(pos, caption, font=font, fill=color)
        if not transparent:
            result = result.convert("RGB")
        return result

    def render_bytes(self, *args: Any, **kwargs: Any) -> bytes:
        """Render code image to bytes (PNG/SVG/other).

        Returns:
            Encoded image bytes (PNG/SVG).

        Example:
            >>> gen.render_bytes(width=100, output_format="PNG")
        """
        img = self.render_image(*args, **kwargs)
        from io import BytesIO

        buf = BytesIO()
        fmt = kwargs.get("output_format", "PNG").upper()
        if fmt == "SVG":
            import base64

            PNGbuf = BytesIO()
            img.save(PNGbuf, format="PNG")
            b64 = base64.b64encode(PNGbuf.getvalue()).decode("ascii")
            svg = (
                f'<svg width="{img.width}" height="{img.height}" xmlns="http://www.w3.org/2000/svg">'
                f'<image href="data:image/png;base64,{b64}" height="{img.height}" width="{img.width}"/></svg>'
            )
            logger.info("SVG output produced for barcode")
            return svg.encode("utf8")
        img.save(buf, format=fmt)
        buf.seek(0)
        logger.debug("Output rendered as %s (%d bytes)", fmt, buf.getbuffer().nbytes)
        return buf.read()

    @classmethod
    def all_supported_types(cls) -> Set[Matrix2DCodeType]:
        """Get all supported 2D barcode types."""
        return (
            cls._qr_types
            | cls._datamatrix_types
            | cls._pdf417_types
            | cls._aztec_types
            | cls._maxicode_types
            | cls._dotcode_types
            | cls._microqr_types
            | cls._rmqr_types
        )

    @classmethod
    def batch_generate(
        cls, items: List[Dict[str, Any]], parallel: bool = False
    ) -> List[Tuple[Dict[str, Any], Image.Image]]:
        """Batch-generate barcodes for items.

        Args:
            items: List of dicts {barcode_type, data, ...}.
            parallel: Enable parallel threads.

        Returns:
            List of (input_dict, Image.Image) tuples.

        Example:
            >>> Matrix2DCodeGenerator.batch_generate([{"barcode_type": ..., "data": ...}])
        """
        from concurrent.futures import ThreadPoolExecutor

        def gen(item: Dict[str, Any]) -> Tuple[Dict[str, Any], Image.Image]:
            generator = cls(
                barcode_type=item["barcode_type"],
                data=item["data"],
                options=item.get("options"),
                gs1_mode=item.get("gs1_mode", False),
            )
            img = generator.render_image(
                options=item.get("render_options"),
                logo_path=item.get("logo_path"),
                logo_image=item.get("logo_image"),
                logo_scale=item.get("logo_scale", 0.25),
                logo_round=item.get("logo_round", True),
                caption=item.get("caption"),
                caption_font_path=item.get("caption_font_path"),
                caption_font_size=item.get("caption_font_size", 14),
                output_format=item.get("output_format", "PNG"),
                background_transparent=item.get("background_transparent", False),
            )
            return item, img

        if parallel:
            with ThreadPoolExecutor() as pool:
                result = list(pool.map(gen, items))
        else:
            result = [gen(i) for i in items]
        logger.info("Batch barcode generation complete: %d items", len(items))
        return result

    async def render_bytes_async(self, *args: Any, **kwargs: Any) -> bytes:
        """Async wrapper for render_bytes (for thread pools)."""
        import asyncio

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, lambda: self.render_bytes(*args, **kwargs)
        )
