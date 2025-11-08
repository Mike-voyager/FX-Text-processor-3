"""
model/enums.py

(Краткое RU: Перечисления для моделей документа FX-890, только поддерживаемые режимы по мануалам.)

EN: Domain enums for FX-890 Text Editor (document model, fully type-safe, based strictly on FX-890 hardware limits and official ESC/P specification).
NO protocol/ESC/P command logic here!

- Only supported fonts, CPI, qualities, barcodes, codepages.
- Only black ribbon (colors excluded).
- Paper sizes/types matching FX-890 feed hardware.
- Only FX-890 raster graphics modes.
- Full validation for cross-type hardware compatibility.

See Also:
    - Epson FX-890 User & Service Manuals
    - src/escp/commands (for protocol logic)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum, Flag, auto
from typing import Final, List, Literal, Mapping, Optional, Set, Tuple

_logger: Final[logging.Logger] = logging.getLogger(__name__)

# === HARDWARE CONSTANTS ===
MAX_MULTIPART_COPIES: Final[int] = 6
MAX_PRINT_WIDTH_INCHES: Final[float] = 10.1
MIN_PRINT_WIDTH_INCHES: Final[float] = 3.9
MAX_PRINT_HEIGHT_INCHES_SINGLE: Final[float] = 14.3
MAX_PRINT_HEIGHT_INCHES_CONTINUOUS: Final[float] = 22.0
MIN_MARGIN_INCHES: Final[float] = 0.13  # Per Epson manual, both left/right/top/bottom

# === DOMAINS ===


class FontFamily(str, Enum):
    USD = "usd"
    HSD = "hsd"
    DRAFT = "draft"
    ROMAN = "roman"
    SANS_SERIF = "sans"

    @property
    def is_nlq(self) -> bool:
        return self in {FontFamily.ROMAN, FontFamily.SANS_SERIF}

    @property
    def supports_proportional(self) -> bool:
        return self.is_nlq

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        names_ru = {
            self.USD: "Сверхбыстрый черновик",
            self.HSD: "Быстрый черновик",
            self.DRAFT: "Черновик",
            self.ROMAN: "Роман, высокое качество",
            self.SANS_SERIF: "Без засечек, высокое качество",
        }
        names_en = {
            self.USD: "Ultra Speed Draft",
            self.HSD: "High Speed Draft",
            self.DRAFT: "Draft",
            self.ROMAN: "Roman (NLQ)",
            self.SANS_SERIF: "Sans Serif (NLQ)",
        }
        return names_ru[self] if lang == "ru" else names_en[self]


class CharactersPerInch(str, Enum):
    CPI_10 = "10cpi"
    CPI_12 = "12cpi"
    CPI_15 = "15cpi"
    CPI_17 = "17cpi"
    CPI_20 = "20cpi"
    PROPORTIONAL = "proportional"

    @property
    def numeric_value(self) -> Optional[int]:
        mapping = {
            self.CPI_10: 10,
            self.CPI_12: 12,
            self.CPI_15: 15,
            self.CPI_17: 17,
            self.CPI_20: 20,
        }
        return mapping.get(self, None)

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class PrintQuality(str, Enum):
    USD = "usd"
    HSD = "hsd"
    DRAFT = "draft"
    NLQ = "nlq"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class LineSpacing(str, Enum):
    ONE_SIXTH_INCH = "1/6"
    ONE_EIGHTH_INCH = "1/8"
    CUSTOM = "custom"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class CodePage(str, Enum):
    PC437 = "pc437"
    PC850 = "pc850"
    PC437_GREEK = "pc437_greek"
    PC853 = "pc853"
    PC855 = "pc855"
    PC852 = "pc852"
    PC857 = "pc857"
    PC866 = "pc866"
    PC869 = "pc869"
    MAZOWIA = "mazowia"
    MJK = "mjk"
    ISO_8859_7 = "iso_8859_7"
    ISO_LATIN1T = "iso_latin1t"
    BULGARIA = "bulgaria"
    PC774 = "pc774"
    ESTONIA = "estonia"
    ISO_8859_2 = "iso_8859_2"
    PC866_LAT = "pc866_lat"
    PC866_UKR = "pc866_ukr"
    PCAPTEC = "pcaptec"
    PC720 = "pc720"
    PCAR864 = "pcar864"
    PC860 = "pc860"
    PC863 = "pc863"
    PC865 = "pc865"
    PC861 = "pc861"
    BRASCII = "brascii"
    ABICOMP = "abicomp"
    ROMAN8 = "roman8"
    ISO_8859_1 = "iso_8859_1"
    PC858 = "pc858"
    ISO_8859_15 = "iso_8859_15"
    PC771 = "pc771"
    PC437_SLOVENI = "pc437_sloveni"
    PC_MC = "pc_mc"
    PC1250 = "pc1250"
    PC1251 = "pc1251"

    @property
    def is_fx890_hardware(self) -> bool:
        return True

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        names_ru = {
            self.PC437: "PC437 (США)",
            self.PC437_GREEK: "PC437 (Греческий)",
            self.PC850: "PC850 (Западная Европа)",
            self.PC852: "PC852 (Восточная Европа)",
            self.PC855: "PC855 (Кириллица 2)",
            self.PC866: "PC866 (Кириллица)",
            self.PC857: "PC857 (Турция)",
            self.PC861: "PC861 (Исландский)",
            self.PC863: "PC863 (Канада)",
            self.PC865: "PC865 (Дания/Норвегия)",
            self.PC858: "PC858 (с евро)",
            self.PC869: "PC869 (Греческий 2)",
            self.MAZOWIA: "Mazowia",
            self.MJK: "MJK код",
            self.ISO_8859_7: "ISO 8859-7 (Греческий)",
            self.ISO_LATIN1T: "ISO Latin 1 T",
            self.BULGARIA: "Bulgaria",
            self.PC774: "PC774 (Эстония)",
            self.ESTONIA: "Estonia",
            self.ISO_8859_2: "ISO 8859-2 (Центр./Вост. Европа)",
            self.PC866_LAT: "PC866 (Латиница)",
            self.PC866_UKR: "PC866 (Украина)",
            self.PCAPTEC: "PCAPTEC",
            self.PC720: "PC720",
            self.PCAR864: "PCAR864",
            self.PC860: "PC860 (Португалия)",
            self.BRASCII: "BRASCII (Бразильский ASCII)",
            self.ABICOMP: "Abicomp",
            self.ROMAN8: "Roman 8",
            self.ISO_8859_1: "ISO 8859-1 (Зап. Европа)",
            self.ISO_8859_15: "ISO 8859-15 (E/€)",
            self.PC_MC: "PC_MC",
            self.PC1250: "PC1250 (Central Europe)",
            self.PC1251: "PC1251 (Кириллица Windows)",
            self.PC771: "PC771",
            self.PC437_SLOVENI: "PC437 (Словения)",
        }
        names_en = {
            self.PC437: "PC437 (US English)",
            self.PC437_GREEK: "PC437 Greek",
            self.PC850: "PC850 (Western Europe)",
            self.PC852: "PC852 (Central/Eastern Europe)",
            self.PC855: "PC855 (Cyrillic)",
            self.PC866: "PC866 (Russian Cyrillic)",
            self.PC857: "PC857 (Turkish)",
            self.PC861: "PC861 (Icelandic)",
            self.PC863: "PC863 (Canadian French)",
            self.PC865: "PC865 (Nordic)",
            self.PC858: "PC858 (w/Euro)",
            self.PC869: "PC869 (Greek 2)",
            self.MAZOWIA: "Mazowia",
            self.MJK: "MJK code",
            self.ISO_8859_7: "ISO 8859-7 (Greek)",
            self.ISO_LATIN1T: "ISO Latin 1 T",
            self.BULGARIA: "Bulgaria",
            self.PC774: "PC774 (Estonian)",
            self.ESTONIA: "Estonia",
            self.ISO_8859_2: "ISO 8859-2 (Central/Eastern Europe)",
            self.PC866_LAT: "PC866 (Latin variant)",
            self.PC866_UKR: "PC866 (Ukrainian)",
            self.PCAPTEC: "PCAPTEC",
            self.PC720: "PC720",
            self.PCAR864: "PCAR864",
            self.PC860: "PC860 (Portuguese)",
            self.BRASCII: "BRASCII (Brazilian ASCII)",
            self.ABICOMP: "Abicomp",
            self.ROMAN8: "Roman 8",
            self.ISO_8859_1: "ISO 8859-1 (Western Europe)",
            self.ISO_8859_15: "ISO 8859-15",
            self.PC_MC: "PC_MC",
            self.PC1250: "PC1250 (Central Europe)",
            self.PC1251: "PC1251 (Windows Cyrillic)",
            self.PC771: "PC771",
            self.PC437_SLOVENI: "PC437 (Slovene)",
        }
        return (
            names_ru.get(self, self.value)
            if lang == "ru"
            else names_en.get(self, self.value)
        )


class BarcodeType(str, Enum):
    EAN8 = "ean8"
    EAN13 = "ean13"
    EAN14 = "ean14"  # GTIN-14/shipping, not hardware FX-890, software/industry use!
    UPCA = "upca"
    UPCE = "upce"
    CODE39 = "code39"
    CODE93 = "code93"  # Software/industry use
    CODE128 = "code128"
    ITF = "itf"
    MSI = "msi"  # Software/industry
    PHARMACODE = "pharmacode"  # Software/industry
    CODABAR = "codabar"
    CODE11 = "code11"  # Software/industry
    STANDARD2OF5 = "standard2of5"  # Also known as industrial 2 of 5
    GS1128 = "gs1128"  # GS1-128; software emulation via Code128
    POSTNET = "postnet"
    PLESSEY = "plessey"  # Retail/legacy, software only
    TELEPEN = "telepen"  # Academic/library, software only
    TRIOPTIC = "trioptic"  # Lens marking/industry
    # FX-890 hardware natively supports only some of these! Others - for preview/software export.
    # For 2D codes (QR/DataMatrix/PDF417 etc) use a separate enum if needed

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        names_ru = {
            self.EAN8: "EAN-8",
            self.EAN13: "EAN-13",
            self.EAN14: "EAN-14 (товар/короб)",
            self.UPCA: "UPC-A",
            self.UPCE: "UPC-E",
            self.CODE39: "Code 39",
            self.CODE93: "Code 93",
            self.CODE128: "Code 128",
            self.ITF: "Interleaved 2 of 5",
            self.MSI: "MSI Plessey",
            self.PHARMACODE: "Pharmacode",
            self.CODABAR: "Codabar",
            self.CODE11: "Code 11",
            self.STANDARD2OF5: "Standard/Industrial 2 of 5",
            self.GS1128: "GS1-128 (EAN-128)",
            self.POSTNET: "POSTNET",
            self.PLESSEY: "Plessey",
            self.TELEPEN: "Telepen",
            self.TRIOPTIC: "Trioptic",
        }
        names_en = {
            self.EAN8: "EAN-8",
            self.EAN13: "EAN-13",
            self.EAN14: "EAN-14",
            self.UPCA: "UPC-A",
            self.UPCE: "UPC-E",
            self.CODE39: "Code 39",
            self.CODE93: "Code 93",
            self.CODE128: "Code 128",
            self.ITF: "Interleaved 2 of 5",
            self.MSI: "MSI",
            self.PHARMACODE: "Pharmacode",
            self.CODABAR: "Codabar",
            self.CODE11: "Code 11",
            self.STANDARD2OF5: "Standard 2 of 5",
            self.GS1128: "GS1-128",
            self.POSTNET: "POSTNET",
            self.PLESSEY: "Plessey",
            self.TELEPEN: "Telepen",
            self.TRIOPTIC: "Trioptic",
        }
        return (
            names_ru.get(self, self.value)
            if lang == "ru"
            else names_en.get(self, self.value)
        )


class Matrix2DCodeType(str, Enum):
    QR = "qr"
    DATAMATRIX = "datamatrix"
    PDF417 = "pdf417"
    # MICRO_QR = "micro_qr"  # Добавить, если появится поддержка/пакет

    def localized_name(self, lang: str = "ru") -> str:
        names = {
            "qr": {"ru": "QR код", "en": "QR code"},
            "datamatrix": {"ru": "DataMatrix", "en": "DataMatrix"},
            "pdf417": {"ru": "PDF417", "en": "PDF417"},
            # "micro_qr": {"ru": "Микро-QR", "en": "Micro QR"},
        }
        return names[self.value][lang] if lang in names[self.value] else self.value


class GraphicsMode(str, Enum):
    SINGLE_DENSITY = "single_density"
    DOUBLE_DENSITY = "double_density"
    DOUBLE_SPEED = "double_speed"
    QUAD_DENSITY = "quad_density"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class Alignment(str, Enum):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
    JUSTIFY = "justify"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class TabAlignment(str, Enum):
    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
    DECIMAL = "decimal"

    def localized_name(self, lang: str = "ru") -> str:
        return self.value


class PaperType(str, Enum):
    CONTINUOUS_TRACTOR = "continuous_tractor"
    SHEET_FEED = "sheet_feed"
    ENVELOPE = "envelope"
    CARD = "card"
    MULTIPART_FORM = "multipart_form"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        names = {
            "continuous_tractor": {
                "ru": "Непрерывная подача",
                "en": "Continuous Tractor",
            },
            "sheet_feed": {"ru": "Листовая подача", "en": "Single Sheet"},
            "envelope": {"ru": "Конверт", "en": "Envelope"},
            "card": {"ru": "Карточка", "en": "Card"},
            "multipart_form": {"ru": "Многослойная форма", "en": "Multipart Form"},
        }
        return names.get(self.value, {}).get(lang, self.value)


class PageSize(str, Enum):
    A4 = "a4"
    LETTER = "letter"
    LEGAL = "legal"
    FANFOLD_8_5 = "fanfold_8_5"
    FANFOLD_9_5 = "fanfold_9_5"
    CUSTOM = "custom"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class Color(str, Enum):
    BLACK = "black"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return "Черный" if lang == "ru" else "Black"


class Orientation(str, Enum):
    PORTRAIT = "portrait"
    LANDSCAPE = "landscape"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return (
            "Портрет"
            if self == Orientation.PORTRAIT and lang == "ru"
            else "Альбомная" if lang == "ru" else self.value.capitalize()
        )


class TableStyle(str, Enum):
    SIMPLE = "simple"
    DOUBLE = "double"
    GRID = "grid"
    MINIMAL = "minimal"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class ListType(str, Enum):
    UNORDERED_DASH = "ul_dash"
    UNORDERED_BULLET = "ul_bullet"
    ORDERED_NUMERIC = "ol_numeric"
    ORDERED_ALPHA_UPPER = "ol_alpha_upper"
    ORDERED_ALPHA_LOWER = "ol_alpha_lower"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class TextStyle(Flag):
    BOLD = auto()
    ITALIC = auto()
    UNDERLINE = auto()
    DOUBLE_STRIKE = auto()
    SUPERSCRIPT = auto()
    SUBSCRIPT = auto()
    CONDENSED = auto()
    DOUBLE_WIDTH = auto()
    DOUBLE_HEIGHT = auto()
    PROPORTIONAL = auto()

    # локализовать флаги для UI можно при необходимости
    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.name if self.name is not None else str(self)


class MarginUnits(str, Enum):
    INCHES = "inches"
    MILLIMETERS = "millimeters"
    CHARACTERS = "characters"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class PrintDirection(str, Enum):
    BIDIRECTIONAL = "bidirectional"
    UNIDIRECTIONAL = "unidirectional"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class PaperSource(str, Enum):
    AUTO = "auto"
    TRACTOR = "tractor"
    MANUAL_FEED = "manual_feed"
    SHEET_BIN1 = "sheet_bin1"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class DitheringAlgorithm(str, Enum):
    FLOYD_STEINBERG = "floyd_steinberg"
    ORDERED_BAYER = "ordered_bayer"
    THRESHOLD = "threshold"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value


class ImagePosition(str, Enum):
    INLINE = "inline"
    FLOAT_LEFT = "float_left"
    FLOAT_RIGHT = "float_right"

    def localized_name(self, lang: Literal["ru", "en"] = "ru") -> str:
        return self.value

class FileExtension(str, Enum):
    """
    Расширения файлов FX Super.

    Все расширения начинаются с префикса .fxs (FX Super)
    для унифицированного распознавания файлов приложения.
    """

    # Документы
    DOCUMENT = ".fxsd"              # FX Super Document (незашифрованный)
    DOCUMENT_ENC = ".fxsd.enc"      # FX Super Document Encrypted

    # Шаблоны
    TEMPLATE = ".fxstpl"            # FX Super Template

    # Защищённые бланки
    BLANK = ".fxsblank"             # FX Super Blank (всегда зашифрован)

    # Безопасность
    KEYSTORE = ".fxskeystore.enc"   # FX Super Keystore
    SIGNATURE = ".fxssig"           # FX Super Signature

    # Конфигурация
    CONFIG = ".fxsconfig"           # FX Super Config

    # Бэкапы
    BACKUP = ".fxsbackup"           # FX Super Backup

    # Экспорт
    EXPORT_BUNDLE = ".fxsbundle.enc"  # FX Super Bundle (зашифрованный)

    # ESC/P
    ESCP_RAW = ".escp"              # ESC/P Raw Commands
    ESCP_SCRIPT = ".escps"          # ESC/P Script


class FileType(str, Enum):
    """
    Типы файлов приложения.

    Используется для программного определения типа файла
    без привязки к конкретному расширению.
    """

    DOCUMENT = "document"
    TEMPLATE = "template"
    BLANK = "blank"
    KEYSTORE = "keystore"
    SIGNATURE = "signature"
    CONFIG = "config"
    BACKUP = "backup"
    EXPORT_BUNDLE = "bundle"
    ESCP_RAW = "escp_raw"
    ESCP_SCRIPT = "escp_script"


# MIME types для регистрации в системе
FILE_MIME_TYPES = {
    FileExtension.DOCUMENT: "application/x-fxsuper-document",
    FileExtension.DOCUMENT_ENC: "application/x-fxsuper-document-encrypted",
    FileExtension.TEMPLATE: "application/x-fxsuper-template",
    FileExtension.BLANK: "application/x-fxsuper-blank",
    FileExtension.KEYSTORE: "application/x-fxsuper-keystore",
    FileExtension.SIGNATURE: "application/x-fxsuper-signature",
    FileExtension.CONFIG: "application/x-fxsuper-config",
    FileExtension.BACKUP: "application/x-fxsuper-backup",
    FileExtension.EXPORT_BUNDLE: "application/x-fxsuper-bundle",
    FileExtension.ESCP_RAW: "application/x-escp",
    FileExtension.ESCP_SCRIPT: "text/x-escp-script",
}

# Описания для Windows File Association
FILE_DESCRIPTIONS = {
    FileExtension.DOCUMENT: "FX Super Document",
    FileExtension.DOCUMENT_ENC: "FX Super Encrypted Document",
    FileExtension.TEMPLATE: "FX Super Form Template",
    FileExtension.BLANK: "FX Super Protected Blank",
    FileExtension.KEYSTORE: "FX Super Keystore",
    FileExtension.SIGNATURE: "FX Super Digital Signature",
    FileExtension.CONFIG: "FX Super Configuration",
    FileExtension.BACKUP: "FX Super Backup Archive",
    FileExtension.EXPORT_BUNDLE: "FX Super Export Bundle",
    FileExtension.ESCP_RAW: "ESC/P Raw Commands",
    FileExtension.ESCP_SCRIPT: "ESC/P Script",
}


# === DEFAULTS ===
DEFAULT_FONT_FAMILY: Final[FontFamily] = FontFamily.DRAFT
DEFAULT_CPI: Final[CharactersPerInch] = CharactersPerInch.CPI_10
DEFAULT_PRINT_QUALITY: Final[PrintQuality] = PrintQuality.DRAFT
DEFAULT_CODEPAGE: Final[CodePage] = CodePage.PC437
DEFAULT_ALIGNMENT: Final[Alignment] = Alignment.LEFT
DEFAULT_LINE_SPACING: Final[LineSpacing] = LineSpacing.ONE_SIXTH_INCH
DEFAULT_COLOR: Final[Color] = Color.BLACK
DEFAULT_PAGE_SIZE: Final[PageSize] = PageSize.LETTER
DEFAULT_TABLE_STYLE: Final[TableStyle] = TableStyle.GRID
DEFAULT_DITHERING_ALGORITHM: Final[DitheringAlgorithm] = (
    DitheringAlgorithm.FLOYD_STEINBERG
)
DEFAULT_PRINT_DIRECTION: Final[PrintDirection] = PrintDirection.BIDIRECTIONAL
DEFAULT_MARGIN_UNITS: Final[MarginUnits] = MarginUnits.INCHES
DEFAULT_ORIENTATION: Final[Orientation] = Orientation.PORTRAIT


# === HARDWARE-AWARE VALIDATION ===
def validate_cpi_font_combination(
    cpi: CharactersPerInch,
    font: FontFamily,
) -> bool:
    if cpi == CharactersPerInch.PROPORTIONAL:
        return font.is_nlq
    if font in {FontFamily.USD, FontFamily.HSD, FontFamily.DRAFT}:
        return cpi in {CharactersPerInch.CPI_10, CharactersPerInch.CPI_12}
    return True


def validate_quality_font_combination(
    quality: PrintQuality,
    font: FontFamily,
) -> bool:
    return not (quality == PrintQuality.NLQ and not font.is_nlq)


def validate_codepage(codepage: CodePage) -> bool:
    return codepage.is_fx890_hardware


def validate_graphics_mode(mode: GraphicsMode) -> bool:
    return mode in {
        GraphicsMode.SINGLE_DENSITY,
        GraphicsMode.DOUBLE_DENSITY,
        GraphicsMode.DOUBLE_SPEED,
        GraphicsMode.QUAD_DENSITY,
    }


def validate_barcode(barcode: BarcodeType) -> bool:
    return barcode in {
        BarcodeType.EAN8,
        BarcodeType.EAN13,
        BarcodeType.UPCA,
        BarcodeType.UPCE,
        BarcodeType.CODE39,
        BarcodeType.CODE128,
        BarcodeType.POSTNET,
        BarcodeType.ITF,
        BarcodeType.CODABAR,
    }


def validate_margin(
    left: float, right: float, top: float, bottom: float, units: MarginUnits
) -> Tuple[bool, Optional[str]]:
    if units == MarginUnits.INCHES:
        margins = [left, right, top, bottom]
        if any(x < MIN_MARGIN_INCHES for x in margins):
            return False, f'Margins less than {MIN_MARGIN_INCHES}" not permitted'
    return True, None


__all__ = [
    "FontFamily",
    "CharactersPerInch",
    "PrintQuality",
    "LineSpacing",
    "CodePage",
    "BarcodeType",
    "GraphicsMode",
    "Alignment",
    "TabAlignment",
    "PaperType",
    "PageSize",
    "Color",
    "Orientation",
    "TableStyle",
    "ListType",
    "TextStyle",
    "MarginUnits",
    "PrintDirection",
    "PaperSource",
    "DitheringAlgorithm",
    "ImagePosition",
    "DEFAULT_FONT_FAMILY",
    "DEFAULT_CPI",
    "DEFAULT_PRINT_QUALITY",
    "DEFAULT_CODEPAGE",
    "DEFAULT_ALIGNMENT",
    "DEFAULT_LINE_SPACING",
    "DEFAULT_COLOR",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_TABLE_STYLE",
    "DEFAULT_DITHERING_ALGORITHM",
    "DEFAULT_PRINT_DIRECTION",
    "DEFAULT_MARGIN_UNITS",
    "DEFAULT_ORIENTATION",
    "validate_cpi_font_combination",
    "validate_quality_font_combination",
    "validate_codepage",
    "validate_graphics_mode",
    "validate_barcode",
    "validate_margin",
]
