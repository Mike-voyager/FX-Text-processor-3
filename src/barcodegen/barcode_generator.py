from __future__ import annotations

import logging
from io import BytesIO
from typing import TYPE_CHECKING, Any, Dict, Optional, Set

from PIL import Image

if TYPE_CHECKING:
    from src.model.enums import BarcodeType

import barcode as pybarcode
from barcode.errors import BarcodeNotFoundError
from barcode.writer import ImageWriter

from src.model.enums import BarcodeType

logger = logging.getLogger(__name__)


class BarcodeGenError(Exception):
    """Barcode generation/validation error."""


class BarcodeGenerator:
    """
    Universal API for 1D barcode generation.

    Args:
        barcode_type: Enum specifying barcode format (EAN, UPC, Code39, etc.)
        data: Payload string
        options: Optional extra options for barcode generation
    """

    _pybarcode_support: Dict[BarcodeType, str] = {
        BarcodeType.EAN8: "ean8",
        BarcodeType.EAN13: "ean13",
        BarcodeType.EAN14: "ean14",
        BarcodeType.UPCA: "upc",
        BarcodeType.UPCE: "upc",
        BarcodeType.CODE39: "code39",
        BarcodeType.CODE93: "code93",
        BarcodeType.CODE128: "code128",
        BarcodeType.ITF: "itf",
        BarcodeType.MSI: "msi",
        BarcodeType.PHARMACODE: "pharmacode",
        BarcodeType.CODABAR: "codabar",
        BarcodeType.CODE11: "code11",
        BarcodeType.STANDARD2OF5: "standard2of5",
        BarcodeType.GS1128: "gs1128",
        BarcodeType.POSTNET: "postnet",
        BarcodeType.PLESSEY: "plessey",
        BarcodeType.TELEPEN: "telepen",
        BarcodeType.TRIOPTIC: "trioptic",
    }

    def __init__(
        self,
        barcode_type: BarcodeType,
        data: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not isinstance(barcode_type, BarcodeType):
            raise TypeError(
                f"barcode_type must be BarcodeType enum, got {type(barcode_type)!r}"
            )
        self.barcode_type = barcode_type
        self.data = data
        self.options: Dict[str, Any] = options or {}

    def validate(self) -> None:
        """
        Validate data against the barcode format rules.
        Проверяет входные данные и доменные ограничения для типа штрихкода.
        Raises:
            BarcodeGenError: при ошибке данных или несоответствии доменным ограничениям.
        """
        if not isinstance(self.data, str) or not self.data.strip():
            raise BarcodeGenError("Barcode data must be non-empty string")

        if self.barcode_type in (
            BarcodeType.EAN8,
            BarcodeType.EAN13,
            BarcodeType.EAN14,
            BarcodeType.GS1128,
        ):
            if not self.data.isdigit():
                raise BarcodeGenError(
                    f"{self.barcode_type.name} barcode requires digits only."
                )
            if self.barcode_type == BarcodeType.EAN8 and len(self.data) != 8:
                raise BarcodeGenError("EAN8 must be 8 digits.")
            elif self.barcode_type == BarcodeType.EAN13 and len(self.data) != 13:
                raise BarcodeGenError("EAN13 must be 13 digits.")
            elif self.barcode_type == BarcodeType.EAN14 and len(self.data) != 14:
                raise BarcodeGenError("EAN14 must be 14 digits.")

        elif self.barcode_type == BarcodeType.UPCA and len(self.data) != 12:
            raise BarcodeGenError("UPC-A must be 12 digits.")

        elif self.barcode_type == BarcodeType.CODE39:
            valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.$/+% ")
            if any(c.islower() for c in self.data):
                raise BarcodeGenError(
                    "CODE39 supports only uppercase A-Z, 0-9, and -.$/+% chars"
                )
            if not all(c in valid_chars for c in self.data):
                raise BarcodeGenError("CODE39 supports only A-Z, 0-9, and -.$/+% chars")

        elif self.barcode_type == BarcodeType.CODE93:
            if len(self.data) > 80:
                raise BarcodeGenError("CODE93 data too long (max ~80)")
            # Дополнительная проверка символов по необходимости

        elif self.barcode_type == BarcodeType.CODE128 and len(self.data) > 80:
            raise BarcodeGenError("CODE128 data too long (max ~80)")

        elif self.barcode_type == BarcodeType.ITF and (
            not self.data.isdigit() or len(self.data) % 2 != 0
        ):
            raise BarcodeGenError("ITF must be even number of digits.")

        elif self.barcode_type == BarcodeType.MSI and not self.data.isdigit():
            raise BarcodeGenError("MSI must contain only digits.")

        elif self.barcode_type == BarcodeType.CODABAR:
            valid_chars = set("0123456789-$:/.+ABCD")
            if not all(c in valid_chars for c in self.data.upper()):
                raise BarcodeGenError(
                    "Codabar supports only 0-9, -$:/.+, and start/stop chars A-D"
                )

        elif self.barcode_type == BarcodeType.POSTNET and (
            not self.data.isdigit() or len(self.data) not in (5, 9, 11)
        ):
            raise BarcodeGenError("POSTNET must be 5, 9, or 11 digits")

        elif self.barcode_type == BarcodeType.PHARMACODE:
            if not self.data.isdigit() or not (3 <= int(self.data) <= 131070):
                raise BarcodeGenError("Pharmacode must be integer between 3 and 131070")

        elif self.barcode_type == BarcodeType.CODE11:
            valid_chars = set("0123456789-")
            if not all(c in valid_chars for c in self.data):
                raise BarcodeGenError(
                    "Code11 supports only digits and dash ('-') chars"
                )
        # Возможны дополнительные проверки для custom типов

    def render_image(
        self,
        width: int = 400,
        height: int = 120,
        options: Optional[Dict[str, Any]] = None,
    ) -> Image.Image:
        self.validate()
        logger.debug(
            "Rendering image for barcode [%s] data=%s",
            self.barcode_type,
            self.data,
        )

        barcode_name = self._pybarcode_support.get(self.barcode_type)
        if not barcode_name:
            logger.warning(
                "Barcode type %s not supported by python-barcode, returning placeholder.",
                self.barcode_type,
            )
            return Image.new("RGB", (width, height), color="white")

        try:
            bclass = pybarcode.get_barcode_class(barcode_name)
            barcode_inst = bclass(
                self.data,
                writer=ImageWriter(),
                **self.options,
            )
            img = barcode_inst.render(
                writer_options={
                    "module_width": 0.2,
                    "font_size": 12,
                    "dpi": 144,
                    "text_distance": 1,
                    "quiet_zone": 2,
                    "write_text": True,
                    "width": width,
                    "height": height,
                    **(options or {}),
                }
            )
            if isinstance(img, Image.Image):
                return img
            else:
                logger.error(
                    "Barcode output is not an Image.Image object; returning placeholder."
                )
                return Image.new("RGB", (width, height), color="white")
        except BarcodeNotFoundError as e:
            logger.error(
                "Barcode class not found for type: %s; %s",
                self.barcode_type,
                e,
            )
            return Image.new("RGB", (width, height), color="white")
        except Exception as e:
            logger.error(
                "Barcode image generation failed: %s; %s",
                self.barcode_type,
                e,
            )
            return Image.new("RGB", (width, height), color="white")

    def render_bytes(self, options: Optional[Dict[str, Any]] = None) -> bytes:
        img = self.render_image(options=options)
        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return buf.read()

    @classmethod
    def supported_types(cls) -> Set[BarcodeType]:
        return set(cls._pybarcode_support.keys())

    @classmethod
    def barcode_name_map(cls) -> Dict[BarcodeType, str]:
        return dict(cls._pybarcode_support)
