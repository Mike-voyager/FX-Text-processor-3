"""
RU: Генерация 2D-штрихкодов (QR, DataMatrix, PDF417) с поддержкой GS1, логотипа
EN: 2D barcode (QR, DataMatrix, PDF417) generator with GS1, logo and caption support

Provides:

QR, DataMatrix, PDF417 image generation

GS1 payload processing

Logo overlays, captions

Batch and async generation

Typed public API

Requirements: Pillow, qrcode, pdf417gen, pylibdmtx (for DataMatrix)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple

import pdf417gen
from PIL import Image, ImageDraw, ImageFont
from qrcode.constants import ERROR_CORRECT_H, ERROR_CORRECT_M

from src.model.enums import Matrix2DCodeType

# Pillow compatibility layer (L -> new Resampling)
try:
    from PIL.Image import Resampling  # type: ignore

    RESAMPLE_LANCZOS = Resampling.LANCZOS
    RESAMPLE_BOX = Resampling.BOX
except ImportError:
    RESAMPLE_LANCZOS = Image.LANCZOS  # type: ignore
    RESAMPLE_BOX = Image.BOX  # type: ignore

logger = logging.getLogger(__name__)


class Matrix2DCodeGenError(Exception):
    """2D barcode generation error (Ошибка генерации 2D-штрихкода)."""


class Matrix2DCodeGenerator:
    """2D-code generator for QR/DataMatrix/PDF417 with rich rendering options.

    text
    Args:
        barcode_type: Barcode type (QR, DataMatrix, PDF417).
        data: Source data to encode.
        options: Rendering options (interpreted per barcode type).
        gs1_mode: Enable GS1 prefix preprocessing.

    Examples:
        >>> gen = Matrix2DCodeGenerator(Matrix2DCodeType.QR, "test123")
        >>> img = gen.render_image(width=200, height=200, caption="Demo")
    """

    _qr_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.QR}
    _datamatrix_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.DATAMATRIX}
    _pdf417_types: Set[Matrix2DCodeType] = {Matrix2DCodeType.PDF417}

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

        self.validate()
        opts = dict(self.options)
        if options:
            opts.update(options)
        payload = self.get_payload()

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
                from pylibdmtx.pylibdmtx import encode
            except ImportError:
                logger.error("pylibdmtx not installed for DataMatrix")
                raise Matrix2DCodeGenError(
                    "pylibdmtx not installed (install with: pip install pylibdmtx)"
                )
            encoded = encode(payload.encode("utf8"))
            import io

            import numpy as np  # import вне блока, если используешь часто

            dm_img: Optional[Image.Image] = None
            pilimage = getattr(encoded, "pilimage", None)
            if pilimage is not None and isinstance(pilimage, Image.Image):
                dm_img = pilimage
            else:
                png_data = getattr(encoded, "png", None)
                if png_data is not None:
                    try:
                        candidate = Image.open(io.BytesIO(png_data))
                        if isinstance(candidate, Image.Image):
                            dm_img = candidate
                    except Exception as exc:
                        logger.error("Failed to load DM PNG: %r", exc)
                        dm_img = None
                # Fallback: raw bitmap
                if dm_img is None and hasattr(encoded, "pixels"):
                    try:
                        arr = np.frombuffer(encoded.pixels, dtype=np.uint8)
                        arr = np.unpackbits(arr)[: encoded.width * encoded.height]
                        arr = arr.reshape((encoded.height, encoded.width))
                        dm_img = Image.fromarray(arr * 255).convert("L")
                    except Exception as exc:
                        logger.error("Failed to convert DM bitmap: %r", exc)
                        dm_img = None

            if dm_img is None or not isinstance(dm_img, Image.Image):
                logger.error("Unable to extract DataMatrix image")
                raise Matrix2DCodeGenError(
                    "Unable to extract image from pylibdmtx result"
                )
            img = dm_img.convert("RGBA" if background_transparent else "RGB")

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
        font = ImageFont.load_default()
        try:
            if font_path:
                font = ImageFont.truetype(font_path, font_size)
        except Exception as e:
            logger.warning("Failed to load caption font (%r): %r", font_path, e)
            font = ImageFont.load_default()
        txt_bbox = font.getbbox(caption)
        txt_width = txt_bbox[2] - txt_bbox[0]
        txt_height = txt_bbox[3] - txt_bbox[1]
        new_h = img.height + txt_height + 8
        result = Image.new(
            "RGBA" if transparent else "RGB",
            (int(img.width), int(new_h)),
            (255, 255, 255, 0) if transparent else (255, 255, 255),
        )
        result.paste(img, (0, 0))
        draw = ImageDraw.Draw(result)
        pos = ((img.width - txt_width) // 2, img.height + 4)
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
        return cls._qr_types | cls._datamatrix_types | cls._pdf417_types

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
        # Prefer off-main-thread to avoid Tk-interference
        return await loop.run_in_executor(
            None, lambda: self.render_bytes(*args, **kwargs)
        )
