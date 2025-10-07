from __future__ import annotations
from typing import Optional, Dict, Set
import logging
from PIL import Image
import barcode as pybarcode
from barcode.writer import ImageWriter
from src.model.enums import BarcodeType
from barcode.errors import BarcodeNotFoundError

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

    _pybarcode_support = {
        BarcodeType.EAN8: "ean8",
        BarcodeType.EAN13: "ean13",
        BarcodeType.EAN14: "ean14",
        BarcodeType.UPCA: "upc",
        BarcodeType.UPCE: "upc",  # some libs accept UPCE as UPC
        BarcodeType.CODE39: "code39",
        BarcodeType.CODE93: "code93",  # ☑️ may require additional library or patch
        BarcodeType.CODE128: "code128",
        BarcodeType.ITF: "itf",
        BarcodeType.MSI: "msi",
        BarcodeType.PHARMACODE: "pharmacode",
        BarcodeType.CODABAR: "codabar",  # ☑️ should be supported by barcode library
        BarcodeType.CODE11: "code11",  # ☑️ extension, may need custom backend
        BarcodeType.STANDARD2OF5: "standard2of5",  # ☑️ if supported/needed (sometimes called industrial2of5)
        BarcodeType.GS1128: "gs1128",  # GS1-128, typically supported via Code128 extension
        BarcodeType.POSTNET: "postnet",
        BarcodeType.PLESSEY: "plessey",  # ☑️ for retail/legacy systems
        BarcodeType.TELEPEN: "telepen",  # ☑️ academic legacy
        BarcodeType.TRIOPTIC: "trioptic",  # ☑️ specialty lens code
        # Add other custom or patched names if your library supports them
    }

    def __init__(
        self,
        barcode_type: BarcodeType,
        data: str,
        options: Optional[Dict] = None,
    ) -> None:
        self.barcode_type = barcode_type
        self.data = data
        self.options = options or {}

    def validate(self) -> None:
        """Validate data against the barcode format rules.

        Raises:
            BarcodeGenError: On validation failure.
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
                raise BarcodeGenError(f"{self.barcode_type.name} barcode requires digits only.")
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
            # Добавьте запрет на строчные буквы
            if any(c.islower() for c in self.data):
                raise BarcodeGenError("CODE39 supports only uppercase A-Z, 0-9, and -.$/+% chars")
            if not all(c in valid_chars for c in self.data):
                raise BarcodeGenError("CODE39 supports only A-Z, 0-9, and -.$/+% chars")
        elif self.barcode_type == BarcodeType.CODE93:
            if len(self.data) > 80:
                raise BarcodeGenError("CODE93 data too long (max ~80)")
            # Add optional character validation as needed
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
                raise BarcodeGenError("Codabar supports only 0-9, -$:/.+, and start/stop chars A-D")
        elif self.barcode_type == BarcodeType.POSTNET and (
            not self.data.isdigit() or len(self.data) not in (5, 9, 11)
        ):
            raise BarcodeGenError("POSTNET must be 5, 9, or 11 digits")
        elif self.barcode_type == BarcodeType.PHARMACODE:
            if not self.data.isdigit() or not (3 <= int(self.data) <= 131070):
                raise BarcodeGenError("Pharmacode must be integer between 3 and 131070")
        elif self.barcode_type == BarcodeType.CODE11:
            # Optional: validate allowed chars (digits and '-')
            valid_chars = set("0123456789-")
            if not all(c in valid_chars for c in self.data):
                raise BarcodeGenError("Code11 supports only digits and dash ('-') chars")
        # Extend with further custom format checks as needed

    def render_image(
        self, width: int = 400, height: int = 120, options: Optional[Dict] = None
    ) -> Image.Image:
        """
        Generate barcode as PIL Image.

        Args:
            width: Image width (pixels)
            height: Image height (pixels)
            options: Extra options for rendering

        Returns:
            Image.Image: Ready barcode image

        Raises:
            BarcodeGenError: On generation/render failure
        """
        self.validate()
        logger.debug("Rendering image for barcode [%s] data=%s", self.barcode_type, self.data)

        barcode_name = self._pybarcode_support.get(self.barcode_type)
        if not barcode_name:
            logger.warning(
                "Barcode type %s not supported by python-barcode, returning placeholder.",
                self.barcode_type,
            )
            img = Image.new("RGB", (width, height), color="white")
            return img

        try:
            bclass = pybarcode.get_barcode_class(barcode_name)
            barcode_inst = bclass(
                self.data,
                writer=ImageWriter(),
                **(self.options or {}),
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
            return img
        except (BarcodeNotFoundError, Exception) as e:
            logger.error("Barcode image generation failed: %s; %s", self.barcode_type, e)
            return Image.new("RGB", (width, height), color="white")

    def render_bytes(self, options: Optional[Dict] = None) -> bytes:
        """
        Generate barcode as PNG bytes for saving/embedding.
        """
        img = self.render_image(options=options)
        from io import BytesIO

        buf = BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        return buf.read()

    @classmethod
    def supported_types(cls) -> Set[BarcodeType]:
        """
        All barcode types supported for generation.
        """
        return set(cls._pybarcode_support.keys())

    @classmethod
    def barcode_name_map(cls) -> Dict[BarcodeType, str]:
        """
        Mapping from BarcodeType to pybarcode name.
        """
        return dict(cls._pybarcode_support)
