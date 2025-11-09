from __future__ import annotations

import logging
from io import BytesIO
from typing import TYPE_CHECKING, Any, Dict, Optional, Set, TypedDict

from PIL import Image

if TYPE_CHECKING:
    from src.model.enums import BarcodeType

import barcode as pybarcode
from barcode.errors import BarcodeNotFoundError
from barcode.writer import ImageWriter

from src.model.enums import BarcodeType

logger = logging.getLogger(__name__)

__all__ = [
    "BarcodeGenerator",
    "BarcodeGenError",
    "BarcodeRenderOptions",
    "BarcodeOptions",
]


class BarcodeRenderOptions(TypedDict, total=False):
    """Типобезопасные опции рендеринга штрихкода."""

    module_width: float
    font_size: int
    dpi: int
    text_distance: float
    quiet_zone: int
    write_text: bool


class BarcodeOptions(TypedDict, total=False):
    """
    Типобезопасные опции создания штрихкода.

    Эти опции передаются в конструктор python-barcode при создании
    экземпляра штрихкода. Все поля опциональны (total=False).

    Полный список опций см. в документации python-barcode:
    https://python-barcode.readthedocs.io/

    Example:
        >>> options: BarcodeOptions = {
        ...     "quiet_zone": 10,
        ...     "module_width": 0.3,
        ...     "write_text": True
        ... }
        >>> gen = BarcodeGenerator(BarcodeType.CODE128, "TEST", options)
    """

    # Общие опции для всех типов штрихкодов
    quiet_zone: int  # Ширина пустой зоны вокруг штрихкода (в модулях)
    module_width: float  # Ширина одного модуля/бара (в мм)
    module_height: float  # Высота модулей (в мм)
    font_size: int  # Размер шрифта для HRI (Human Readable Interpretation)
    text_distance: float  # Расстояние между штрихкодом и текстом (в мм)
    background: str  # Цвет фона (например, "white")
    foreground: str  # Цвет штрихкода (например, "black")
    write_text: bool  # Включить/выключить текст под штрихкодом
    text: str  # Переопределить текст под штрихкодом


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
        options: Optional[BarcodeOptions] = None,
    ) -> None:
        if not isinstance(barcode_type, BarcodeType):
            raise TypeError(
                f"barcode_type must be BarcodeType enum, got {type(barcode_type)!r}"
            )
        self.barcode_type = barcode_type
        self.data = data
        # Исправление: приводим TypedDict к dict для совместимости
        self.options: Dict[str, Any] = dict(options) if options else {}

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
        options: Optional[BarcodeRenderOptions] = None,
        strict: bool = True,
    ) -> Image.Image:
        """
        Рендеринг изображения штрихкода с опциональным строгим контролем ошибок.

        Args:
            width: Ширина изображения в пикселях (по умолчанию: 400).
            height: Высота изображения в пикселях (по умолчанию: 120).
            options: Опции рендеринга (module_width, dpi и т.д.).
            strict: Если True, генерировать BarcodeGenError при ошибках рендеринга.
                   Если False (по умолчанию), возвращать белое placeholder изображение и логировать предупреждение.

        Returns:
            PIL Image объект (RGB режим).

        Raises:
            BarcodeGenError: Если strict=True и генерация завершилась с ошибкой.
        """
        self.validate()
        logger.debug(
            "Rendering image for barcode [%s] data=%s",
            self.barcode_type,
            self.data,
        )

        barcode_name = self._pybarcode_support.get(self.barcode_type)
        if not barcode_name:
            msg = f"Barcode type {self.barcode_type} not supported by python-barcode"
            if strict:
                raise BarcodeGenError(msg)
            logger.warning(f"{msg}; returning placeholder")
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
                msg = "Barcode output is not an Image.Image object"
                if strict:
                    raise BarcodeGenError(msg)
                logger.warning(f"{msg}; returning placeholder")
                return Image.new("RGB", (width, height), "white")
        except BarcodeNotFoundError as e:
            msg = f"Barcode class not found for type: {self.barcode_type}"
            if strict:
                raise BarcodeGenError(msg) from e
            logger.warning(f"{msg}; returning placeholder")
            return Image.new("RGB", (width, height), "white")
        except Exception as e:
            msg = f"Barcode image generation failed: {self.barcode_type}"
            if strict:
                raise BarcodeGenError(msg) from e
            logger.warning(f"{msg}; returning placeholder")
            return Image.new("RGB", (width, height), "white")

    def render_bytes(self, options: Optional[BarcodeRenderOptions] = None) -> bytes:
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
