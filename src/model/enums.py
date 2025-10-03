"""
model/enums.py

Классы перечислений для модели документа ESC/P Text Editor.

Этот модуль определяет все типобезопасные константы для структуры документа,
форматирования текста, режимов качества печати и возможностей принтера,
специфичных для матричного принтера Epson FX-890 с полной поддержкой команд ESC/P.

Перечисления предоставляют:
- Типобезопасные константы для всех настроек документа и принтера
- Генерацию команд ESC/P для связи с принтером
- Двуязычную поддержку интерфейса (английский и русский)
- Валидацию аппаратных ограничений принтера
- JSON-сериализуемые значения для сохранения документов

Пример использования:
    >>> from src.model.enums import FontFamily, TextStyle, PrintQuality
    >>>
    >>> # Выбираем шрифт и генерируем команду ESC/P
    >>> font = FontFamily.ROMAN
    >>> command = font.to_escp()  # b'\x1b\x6b\x01'
    >>>
    >>> # Комбинируем стили текста
    >>> style = TextStyle.BOLD | TextStyle.ITALIC
    >>> if TextStyle.BOLD in style:
    ...     print("Жирный шрифт активен")
    >>>
    >>> # Проверяем совместимость
    >>> from src.model.enums import validate_cpi_font_combination
    >>> if validate_cpi_font_combination(CharactersPerInch.CPI_10, font):
    ...     print("Совместимая комбинация")

См. также:
    - Руководство по ESC/P для Epson FX-890
    - document.py: Модель документа, использующая эти перечисления
    - escp_builder.py: Построитель команд ESC/P
"""

from __future__ import annotations

from enum import Enum, Flag, auto
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# =============================================================================
# КОНСТАНТЫ УРОВНЯ МОДУЛЯ
# =============================================================================

# Максимальные аппаратные возможности
MAX_MULTIPART_COPIES: int = 6
MAX_PRINT_WIDTH_INCHES: float = 8.0
MAX_PRINT_HEIGHT_INCHES_SINGLE: float = 14.3  # ✅ НОВАЯ константа
MAX_PRINT_HEIGHT_INCHES_CONTINUOUS: float = 22.0  # Для тракторной бумаги
MAX_CPI: int = 20
MIN_CPI: int = 10
MAX_LPI: int = 8
MIN_LPI: int = 6
MIN_MARGIN_INCHES: float = 0.25  # НОВОЕ в v2.0

# Константы управляющих байтов ESC/P
ESC: bytes = b"\x1b"
ESC_INIT: bytes = b"\x1b\x40"  # НОВОЕ - ESC @ (инициализация)
SI: bytes = b"\x0f"
DC2: bytes = b"\x12"
DC4: bytes = b"\x14"
SO: bytes = b"\x0e"
FF: bytes = b"\x0c"  # НОВОЕ - Form Feed
CR: bytes = b"\x0d"  # НОВОЕ - Carriage Return
LF: bytes = b"\x0a"  # НОВОЕ - Line Feed
BEL: bytes = b"\x07"  # НОВОЕ - Bell


@dataclass(frozen=True)
class CustomPageSize:
    """Пользовательский размер бумаги."""

    width_inches: float
    height_inches: float
    name: str = "Custom"

    def __post_init__(self) -> None:
        """Валидация размеров."""
        if not (0.1 <= self.width_inches <= MAX_PRINT_WIDTH_INCHES):
            raise ValueError(f"Width must be 0.1-{MAX_PRINT_WIDTH_INCHES} inches")
        # Используем CONTINUOUS для кастомных размеров (предполагаем тракторную бумагу)
        if not (0.1 <= self.height_inches <= MAX_PRINT_HEIGHT_INCHES_CONTINUOUS):
            raise ValueError(f"Height must be 0.1-{MAX_PRINT_HEIGHT_INCHES_CONTINUOUS} inches")

    @property
    def dimensions_inches(self) -> tuple[float, float]:
        return (self.width_inches, self.height_inches)

    @property
    def max_characters_10cpi(self) -> int:
        return int(self.width_inches * 10) - 2

    @property
    def is_compatible_with_tractor(self) -> bool:
        """Предполагаем, что кастомные размеры для тракторной подачи."""
        return True

    @classmethod
    def from_mm(cls, width_mm: float, height_mm: float, name: str = "Custom") -> "CustomPageSize":
        """Создает размер из миллиметров."""
        return cls(width_inches=width_mm / 25.4, height_inches=height_mm / 25.4, name=name)


# =============================================================================
# ПЕРЕЧИСЛЕНИЯ СТРУКТУРЫ ДОКУМЕНТА
# =============================================================================


class Orientation(str, Enum):
    """
    Ориентация страницы для макета документа.

    Определяет ориентацию бумаги относительно направления печати.
    Альбомный режим поворачивает текст на 90 градусов против часовой стрелки.

    Атрибуты:
        value: Строковый идентификатор для сериализации
        description_en: Описание на английском
        description_ru: Описание на русском
    """

    PORTRAIT = "portrait"
    LANDSCAPE = "landscape"

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            Orientation.PORTRAIT: "Portrait",
            Orientation.LANDSCAPE: "Landscape",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            Orientation.PORTRAIT: "Книжная",
            Orientation.LANDSCAPE: "Альбомная",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """
        Возвращает локализованное название для отображения в UI.

        Аргументы:
            lang: Код языка ("ru" или "en")

        Возвращает:
            Локализованное название ориентации
        """
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["Orientation"]:
        """
        Поиск без учёта регистра из строки.

        Аргументы:
            value: Строковое представление ориентации

        Возвращает:
            Член перечисления Orientation или None, если не найден
        """
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class Alignment(str, Enum):
    """
    Варианты выравнивания текста для абзацев и строк.

    Выравнивание реализуется программно путём вычисления отступов,
    так как FX-890 не имеет нативных команд ESC/P для выравнивания.

    Атрибуты:
        value: Строковый идентификатор для сериализации
        description_en: Описание на английском
        description_ru: Описание на русском
    """

    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
    JUSTIFY = "justify"

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            Alignment.LEFT: "Left",
            Alignment.CENTER: "Center",
            Alignment.RIGHT: "Right",
            Alignment.JUSTIFY: "Justify",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            Alignment.LEFT: "По левому краю",
            Alignment.CENTER: "По центру",
            Alignment.RIGHT: "По правому краю",
            Alignment.JUSTIFY: "По ширине",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["Alignment"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class PaperType(str, Enum):
    """
    Поддерживаемые типы бумаги для Epson FX-890.

    Разные типы бумаги имеют разные механизмы подачи и
    максимальное количество копий. Непрерывная фальцованная бумага
    с тракторной подачей — это основной режим для FX-890.

    Атрибуты:
        value: Строковый идентификатор для сериализации
        requires_manual_feed: Требуется ли ручная подача бумаги
        max_copies: Максимальное количество копий (1-6 для многослойных форм)
        description_en: Описание на английском
        description_ru: Описание на русском
    """

    CONTINUOUS_TRACTOR = "continuous_tractor"
    SHEET_FEED = "sheet_feed"
    ENVELOPE = "envelope"
    CARD = "card"
    MULTIPART_FORM = "multipart_form"

    @property
    def requires_manual_feed(self) -> bool:
        """Проверяет, требуется ли ручная подача для этого типа бумаги."""
        return self in (PaperType.ENVELOPE, PaperType.CARD)

    @property
    def max_copies(self) -> int:
        """Максимальное количество поддерживаемых копий."""
        if self == PaperType.MULTIPART_FORM:
            return MAX_MULTIPART_COPIES
        return 1

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            PaperType.CONTINUOUS_TRACTOR: "Continuous Tractor Feed",
            PaperType.SHEET_FEED: "Single Sheet Feed",
            PaperType.ENVELOPE: "Envelope",
            PaperType.CARD: "Card",
            PaperType.MULTIPART_FORM: "Multipart Form (up to 6 copies)",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            PaperType.CONTINUOUS_TRACTOR: "Непрерывная рулонная бумага",
            PaperType.SHEET_FEED: "Листовая подача",
            PaperType.ENVELOPE: "Конверт",
            PaperType.CARD: "Карточка",
            PaperType.MULTIPART_FORM: "Многослойная форма (до 6 копий)",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["PaperType"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


# =============================================================================
# ПЕРЕЧИСЛЕНИЯ ТИПОГРАФИКИ
# =============================================================================


class FontFamily(str, Enum):
    """
    Доступные семейства шрифтов для матричного принтера Epson FX-890.

    Каждый шрифт имеет разные характеристики по скорости, качеству
    и поддержке пропорционального интервала. FX-890 поддерживает как
    черновые, так и шрифты почти-типографского качества (NLQ).

    Команда ESC/P: ESC k n
    - USD/HSD/DRAFT: ESC k 0
    - ROMAN: ESC k 1
    - SANS_SERIF: ESC k 2

    Атрибуты:
        value: Строковый идентификатор для сериализации
        escp_code: Целочисленный код для команды ESC k
        description_en: Описание на английском
        description_ru: Описание на русском
        supports_proportional: Поддерживает ли шрифт пропорциональный интервал

    См. также:
        Руководство по FX-890, Раздел 4.2 "Выбор шрифта"
    """

    USD = "usd"  # Сверхбыстрый черновик
    HSD = "hsd"  # Быстрый черновик
    DRAFT = "draft"  # Стандартный черновик
    ROMAN = "roman"  # Роман (NLQ)
    SANS_SERIF = "sans"  # Без засечек (NLQ)

    @property
    def escp_code(self) -> int:
        """
        Возвращает код команды ESC k.

        Примечание: USD, HSD и DRAFT все используют код 0, но различаются режимом качества.
        """
        mapping = {
            FontFamily.USD: 0,
            FontFamily.HSD: 0,
            FontFamily.DRAFT: 0,
            FontFamily.ROMAN: 1,
            FontFamily.SANS_SERIF: 2,
        }
        return mapping[self]

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            FontFamily.USD: "Ultra Speed Draft",
            FontFamily.HSD: "High Speed Draft",
            FontFamily.DRAFT: "Draft",
            FontFamily.ROMAN: "Roman (NLQ)",
            FontFamily.SANS_SERIF: "Sans Serif (NLQ)",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            FontFamily.USD: "Сверхбыстрый черновик",
            FontFamily.HSD: "Быстрый черновик",
            FontFamily.DRAFT: "Черновик",
            FontFamily.ROMAN: "Роман (высокое качество)",
            FontFamily.SANS_SERIF: "Без засечек (высокое качество)",
        }
        return mapping[self]

    @property
    def supports_proportional(self) -> bool:
        """
        Проверяет, поддерживает ли шрифт пропорциональный интервал.

        Только семейство шрифтов ROMAN поддерживает пропорциональный интервал на FX-890.
        """
        return self == FontFamily.ROMAN

    def to_escp(self) -> bytes:
        """
        Генерирует команду ESC/P для выбора этого шрифта.

        Возвращает:
            bytes: Последовательность команды ESC k n

        Пример:
            >>> FontFamily.ROMAN.to_escp()
            b'\x1b\x6b\x01'  # ESC k 1
        """
        return b"\x1b\x6b" + bytes([self.escp_code])

    @classmethod
    def from_string(cls, value: str) -> Optional["FontFamily"]:
        """
        Поиск без учёта регистра из строки.

        Аргументы:
            value: Строковое представление семейства шрифтов

        Возвращает:
            Член перечисления FontFamily или None, если не найден

        Пример:
            >>> FontFamily.from_string("DRAFT")
            <FontFamily.DRAFT: 'draft'>
        """
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class PrintQuality(str, Enum):
    """
    Режимы качества печати, влияющие на скорость и разрешение.

    FX-890 поддерживает несколько режимов качества, обменивая скорость на качество печати.
    USD (Сверхбыстрый черновик) — самый быстрый, но низкого качества, в то время как NLQ
    (Почти типографское качество) обеспечивает лучшее качество при самой низкой скорости.

    Атрибуты:
        value: Строковый идентификатор для сериализации
        speed_cps: Символов в секунду при 10 CPI
        resolution_dpi: Кортеж (горизонтальное, вертикальное) разрешение в DPI
        recommended_use: Описание наилучшего варианта использования

    См. также:
        Руководство по FX-890, Раздел 4.1 "Режимы качества печати"
    """

    USD = "usd"  # Сверхбыстрый черновик
    HSD = "hsd"  # Быстрый черновик
    DRAFT = "draft"  # Стандартный черновик
    NLQ = "nlq"  # Почти типографское качество

    @property
    def speed_cps(self) -> int:
        """Символов в секунду при 10 CPI."""
        mapping = {
            PrintQuality.USD: 566,
            PrintQuality.HSD: 283,
            PrintQuality.DRAFT: 283,
            PrintQuality.NLQ: 94,
        }
        return mapping[self]

    @property
    def resolution_dpi(self) -> Tuple[int, int]:
        """Разрешение печати как (горизонтальное, вертикальное) в DPI."""
        mapping = {
            PrintQuality.USD: (120, 72),
            PrintQuality.HSD: (240, 144),
            PrintQuality.DRAFT: (240, 144),
            PrintQuality.NLQ: (360, 360),
        }
        return mapping[self]

    @property
    def recommended_use(self) -> str:
        """Описание рекомендуемого варианта использования."""
        mapping = {
            PrintQuality.USD: "High-volume draft printing, internal documents",
            PrintQuality.HSD: "Draft documents with improved readability",
            PrintQuality.DRAFT: "Standard draft quality for everyday use",
            PrintQuality.NLQ: "Final documents, correspondence, reports",
        }
        return mapping[self]

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            PrintQuality.USD: "Ultra Speed Draft",
            PrintQuality.HSD: "High Speed Draft",
            PrintQuality.DRAFT: "Draft",
            PrintQuality.NLQ: "Near Letter Quality",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            PrintQuality.USD: "Сверхбыстрый черновик",
            PrintQuality.HSD: "Быстрый черновик",
            PrintQuality.DRAFT: "Черновик",
            PrintQuality.NLQ: "Высокое качество",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["PrintQuality"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class CharactersPerInch(Enum):
    """
    Варианты шага символов для FX-890.

    CPI (Characters Per Inch — символов на дюйм) определяет горизонтальную плотность символов.
    Более высокие значения CPI производят более мелкий, более сжатый текст.

    Команды ESC/P:
    - 10 CPI: ESC P
    - 12 CPI: ESC M
    - 15 CPI: ESC g
    - 17.1 CPI: SI (режим сжатия с 10 CPI)
    - 20 CPI: SI + ESC M (режим сжатия с 12 CPI)
    - Пропорциональный: ESC p 1

    Атрибуты:
        value: Внутренний идентификатор
        numeric_value: Фактическое значение CPI или None для пропорционального
        escp_command: Байты команды ESC/P
        condensed: Требуется ли режим сжатия

    См. также:
        Руководство по FX-890, Раздел 4.3 "Шаг символов"
    """

    CPI_10 = "10cpi"
    CPI_12 = "12cpi"
    CPI_15 = "15cpi"
    CPI_17 = "17cpi"  # Фактически 17.1 CPI
    CPI_20 = "20cpi"
    PROPORTIONAL = "proportional"

    @property
    def numeric_value(self) -> Optional[int]:
        """Числовое значение CPI или None для пропорционального."""
        mapping = {
            CharactersPerInch.CPI_10: 10,
            CharactersPerInch.CPI_12: 12,
            CharactersPerInch.CPI_15: 15,
            CharactersPerInch.CPI_17: 17,
            CharactersPerInch.CPI_20: 20,
            CharactersPerInch.PROPORTIONAL: None,
        }
        return mapping[self]

    @property
    def condensed(self) -> bool:
        """Проверяет, требуется ли режим сжатия."""
        return self in (CharactersPerInch.CPI_17, CharactersPerInch.CPI_20)

    @property
    def escp_command(self) -> bytes:
        """Команда ESC/P для установки этого шага."""
        mapping = {
            CharactersPerInch.CPI_10: b"\x1b\x50",  # ESC P
            CharactersPerInch.CPI_12: b"\x1b\x4d",  # ESC M
            CharactersPerInch.CPI_15: b"\x1b\x67",  # ESC g
            CharactersPerInch.CPI_17: b"\x0f\x1b\x50",  # SI + ESC P
            CharactersPerInch.CPI_20: b"\x0f\x1b\x4d",  # SI + ESC M
            CharactersPerInch.PROPORTIONAL: b"\x1b\x70\x01",  # ESC p 1
        }
        return mapping[self]

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            CharactersPerInch.CPI_10: "10 CPI (Pica)",
            CharactersPerInch.CPI_12: "12 CPI (Elite)",
            CharactersPerInch.CPI_15: "15 CPI (Condensed)",
            CharactersPerInch.CPI_17: "17.1 CPI (Condensed Pica)",
            CharactersPerInch.CPI_20: "20 CPI (Condensed Elite)",
            CharactersPerInch.PROPORTIONAL: "Proportional",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            CharactersPerInch.CPI_10: "10 знаков/дюйм (Пика)",
            CharactersPerInch.CPI_12: "12 знаков/дюйм (Элит)",
            CharactersPerInch.CPI_15: "15 знаков/дюйм (Сжатый)",
            CharactersPerInch.CPI_17: "17 знаков/дюйм (Сжатый Пика)",
            CharactersPerInch.CPI_20: "20 знаков/дюйм (Сжатый Элит)",
            CharactersPerInch.PROPORTIONAL: "Пропорциональный",
        }
        return mapping[self]

    def to_escp(self) -> bytes:
        """Генерирует команду ESC/P для этого шага."""
        return self.escp_command

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["CharactersPerInch"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class LineSpacing(Enum):
    """
    Варианты межстрочного интервала для FX-890.

    Управляет вертикальным расстоянием между последовательными строками текста.
    FX-890 поддерживает фиксированные значения интервала и пользовательский интервал через ESC 3.

    Команды ESC/P:
    - 1/6": ESC 2 (по умолчанию)
    - 1/8": ESC 0
    - 7/72": ESC 1
    - Пользовательский: ESC 3 n (n/216 дюйма)

    Атрибуты:
        value: Внутренний идентификатор
        fraction: Кортеж (числитель, знаменатель) для интервала
        escp_command: Байты команды ESC/P (None для пользовательского)

    См. также:
        Руководство по FX-890, Раздел 4.4 "Межстрочный интервал"
    """

    ONE_SIXTH_INCH = "1/6"
    ONE_EIGHTH_INCH = "1/8"
    SEVEN_SEVENTYTWOTH_INCH = "7/72"
    CUSTOM = "custom"

    @property
    def fraction(self) -> Tuple[int, int]:
        """Межстрочный интервал как дробь (числитель, знаменатель)."""
        mapping = {
            LineSpacing.ONE_SIXTH_INCH: (1, 6),
            LineSpacing.ONE_EIGHTH_INCH: (1, 8),
            LineSpacing.SEVEN_SEVENTYTWOTH_INCH: (7, 72),
            LineSpacing.CUSTOM: (0, 1),  # Заглушка для пользовательского
        }
        return mapping[self]

    @property
    def escp_command(self) -> Optional[bytes]:
        """Команда ESC/P для этого интервала (None для пользовательского)."""
        mapping = {
            LineSpacing.ONE_SIXTH_INCH: b"\x1b\x32",  # ESC 2
            LineSpacing.ONE_EIGHTH_INCH: b"\x1b\x30",  # ESC 0
            LineSpacing.SEVEN_SEVENTYTWOTH_INCH: b"\x1b\x31",  # ESC 1
            LineSpacing.CUSTOM: None,  # Требует ESC 3 n с параметром
        }
        return mapping[self]

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            LineSpacing.ONE_SIXTH_INCH: "1/6 inch (6 LPI)",
            LineSpacing.ONE_EIGHTH_INCH: "1/8 inch (8 LPI)",
            LineSpacing.SEVEN_SEVENTYTWOTH_INCH: "7/72 inch",
            LineSpacing.CUSTOM: "Custom spacing",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            LineSpacing.ONE_SIXTH_INCH: "1/6 дюйма (6 строк/дюйм)",
            LineSpacing.ONE_EIGHTH_INCH: "1/8 дюйма (8 строк/дюйм)",
            LineSpacing.SEVEN_SEVENTYTWOTH_INCH: "7/72 дюйма",
            LineSpacing.CUSTOM: "Пользовательский интервал",
        }
        return mapping[self]

    def to_escp(self, custom_value: int | None = None) -> bytes:
        """
        Convert line spacing to ESC/P command.

        Args:
            custom_value: For CUSTOM mode, specify n value for ESC 3 n (1-255).
                         Represents 1/216 inch increments.

        Returns:
            ESC/P command bytes.

        Raises:
            ValueError: If custom_value is required but not provided or out of range.

        Example:
            >>> LineSpacing.ONE_SIXTH_INCH.to_escp()
            b'\\x1b2'
            >>> LineSpacing.CUSTOM.to_escp(custom_value=36)  # 36/216" = 1/6"
            b'\\x1b3$'
        """
        if self == LineSpacing.ONE_SIXTH_INCH:
            return b"\x1b\x32"  # ESC 2
        elif self == LineSpacing.ONE_EIGHTH_INCH:
            return b"\x1b\x30"  # ESC 0
        elif self == LineSpacing.SEVEN_SEVENTYTWOTH_INCH:
            return b"\x1b\x31"  # ESC 1
        elif self == LineSpacing.CUSTOM:
            if custom_value is None:
                raise ValueError("custom_value required for CUSTOM line spacing")
            if not (1 <= custom_value <= 255):
                raise ValueError(f"custom_value must be 1-255, got {custom_value}")
            return b"\x1b\x33" + bytes([custom_value])  # ESC 3 n
        else:
            return b"\x1b\x32"  # Default to 1/6"

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["LineSpacing"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class TabAlignment(Enum):
    """Tab stop alignment modes."""

    LEFT = "left"
    CENTER = "center"
    RIGHT = "right"
    DECIMAL = "decimal"


class TextStyle(Flag):
    """
    Комбинируемые стили текста с использованием битовых операций.

    TextStyle — это Flag-перечисление, позволяющее комбинировать несколько стилей
    с использованием битового ИЛИ (|). Каждый стиль соответствует специфическим командам ESC/P
    для включения и отключения стиля.

    Команды ESC/P:
    - BOLD: ESC E (вкл), ESC F (выкл)
    - ITALIC: ESC 4 (вкл), ESC 5 (выкл)
    - UNDERLINE: ESC - 1 (вкл), ESC - 0 (выкл)
    - DOUBLE_STRIKE: ESC G (вкл), ESC H (выкл)
    - SUPERSCRIPT: ESC S 0
    - SUBSCRIPT: ESC S 1
    - OUTLINE: ESC q 1
    - SHADOW: ESC q 2
    - CONDENSED: SI (вкл), DC2 (выкл)
    - DOUBLE_WIDTH: ESC W 1 (вкл), ESC W 0 (выкл)
    - DOUBLE_HEIGHT: ESC w 1 (вкл), ESC w 0 (выкл)
    - PROPORTIONAL: ESC p 1 (вкл), ESC p 0 (выкл)

    Использование:
        >>> style = TextStyle.BOLD | TextStyle.ITALIC
        >>> if TextStyle.BOLD in style:
        ...     print("Жирный активен")
        >>> for flag in TextStyle:
        ...     if flag in style:
        ...         print(flag.to_escp_on())

    См. также:
        Руководство по FX-890, Раздел 4.5 "Стилизация текста"
        validate_style_combination(): Проверка конфликтующих стилей
    """

    BOLD = auto()
    ITALIC = auto()
    UNDERLINE = auto()
    DOUBLE_STRIKE = auto()
    STRIKETHROUGH = auto()  # Программная реализация через перепечатку
    SUPERSCRIPT = auto()
    SUBSCRIPT = auto()
    OUTLINE = auto()
    SHADOW = auto()
    CONDENSED = auto()
    DOUBLE_WIDTH = auto()
    DOUBLE_HEIGHT = auto()
    PROPORTIONAL = auto()

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            TextStyle.BOLD: "Bold",
            TextStyle.ITALIC: "Italic",
            TextStyle.UNDERLINE: "Underline",
            TextStyle.DOUBLE_STRIKE: "Double Strike",
            TextStyle.STRIKETHROUGH: "Strikethrough",
            TextStyle.SUPERSCRIPT: "Superscript",
            TextStyle.SUBSCRIPT: "Subscript",
            TextStyle.OUTLINE: "Outline",
            TextStyle.SHADOW: "Shadow",
            TextStyle.CONDENSED: "Condensed",
            TextStyle.DOUBLE_WIDTH: "Double Width",
            TextStyle.DOUBLE_HEIGHT: "Double Height",
            TextStyle.PROPORTIONAL: "Proportional",
        }
        return mapping.get(self, "Unknown")

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            TextStyle.BOLD: "Жирный",
            TextStyle.ITALIC: "Курсив",
            TextStyle.UNDERLINE: "Подчёркнутый",
            TextStyle.DOUBLE_STRIKE: "Двойной удар",
            TextStyle.STRIKETHROUGH: "Зачёркнутый",
            TextStyle.SUPERSCRIPT: "Надстрочный",
            TextStyle.SUBSCRIPT: "Подстрочный",
            TextStyle.OUTLINE: "Контурный",
            TextStyle.SHADOW: "С тенью",
            TextStyle.CONDENSED: "Сжатый",
            TextStyle.DOUBLE_WIDTH: "Двойная ширина",
            TextStyle.DOUBLE_HEIGHT: "Двойная высота",
            TextStyle.PROPORTIONAL: "Пропорциональный",
        }
        return mapping.get(self, "Неизвестно")

    def to_escp_on(self) -> bytes:
        """
        Генерирует команду ESC/P для включения этого стиля.

        Возвращает:
            bytes: Последовательность команды ESC/P для активации стиля

        Вызывает исключение:
            ValueError: Если у стиля нет команды ESC/P
        """
        mapping = {
            TextStyle.BOLD: b"\x1b\x45",  # ESC E
            TextStyle.ITALIC: b"\x1b\x34",  # ESC 4
            TextStyle.UNDERLINE: b"\x1b\x2d\x01",  # ESC - 1
            TextStyle.DOUBLE_STRIKE: b"\x1b\x47",  # ESC G
            TextStyle.SUPERSCRIPT: b"\x1b\x53\x00",  # ESC S 0
            TextStyle.SUBSCRIPT: b"\x1b\x53\x01",  # ESC S 1
            TextStyle.OUTLINE: b"\x1b\x71\x01",  # ESC q 1
            TextStyle.SHADOW: b"\x1b\x71\x02",  # ESC q 2
            TextStyle.CONDENSED: b"\x0f",  # SI
            TextStyle.DOUBLE_WIDTH: b"\x1b\x57\x01",  # ESC W 1
            TextStyle.DOUBLE_HEIGHT: b"\x1b\x77\x01",  # ESC w 1
            TextStyle.PROPORTIONAL: b"\x1b\x70\x01",  # ESC p 1
        }

        if self not in mapping:
            raise ValueError(f"Style {self} has no ESC/P enable command")

        return mapping[self]

    def to_escp_off(self) -> bytes:
        """
        Генерирует команду ESC/P для отключения этого стиля.

        Возвращает:
            bytes: Последовательность команды ESC/P для деактивации стиля

        Вызывает исключение:
            ValueError: Если у стиля нет команды ESC/P
        """
        mapping = {
            TextStyle.BOLD: b"\x1b\x46",  # ESC F
            TextStyle.ITALIC: b"\x1b\x35",  # ESC 5
            TextStyle.UNDERLINE: b"\x1b\x2d\x00",  # ESC - 0
            TextStyle.DOUBLE_STRIKE: b"\x1b\x48",  # ESC H
            TextStyle.SUPERSCRIPT: b"\x1b\x54",  # ESC T
            TextStyle.SUBSCRIPT: b"\x1b\x54",  # ESC T (то же что и для надстрочного)
            TextStyle.OUTLINE: b"\x1b\x71\x00",  # ESC q 0
            TextStyle.SHADOW: b"\x1b\x71\x00",  # ESC q 0
            TextStyle.CONDENSED: b"\x12",  # DC2
            TextStyle.DOUBLE_WIDTH: b"\x1b\x57\x00",  # ESC W 0
            TextStyle.DOUBLE_HEIGHT: b"\x1b\x77\x00",  # ESC w 0
            TextStyle.PROPORTIONAL: b"\x1b\x70\x00",  # ESC p 0
        }

        if self not in mapping:
            raise ValueError(f"Style {self} has no ESC/P disable command")

        return mapping[self]

    def conflicts_with(self, other: "TextStyle") -> bool:
        """
        Проверяет, конфликтует ли этот стиль с другим.

        Некоторые стили взаимно исключающие на аппаратуре FX-890:
        - SUPERSCRIPT и SUBSCRIPT
        - PROPORTIONAL и CONDENSED
        - OUTLINE и SHADOW

        Аргументы:
            other: Другой TextStyle для проверки

        Возвращает:
            True, если стили конфликтуют, False в противном случае
        """
        conflicts = {
            TextStyle.SUPERSCRIPT: {TextStyle.SUBSCRIPT},
            TextStyle.SUBSCRIPT: {TextStyle.SUPERSCRIPT},
            TextStyle.PROPORTIONAL: {TextStyle.CONDENSED},
            TextStyle.CONDENSED: {TextStyle.PROPORTIONAL},
            TextStyle.OUTLINE: {TextStyle.SHADOW},
            TextStyle.SHADOW: {TextStyle.OUTLINE},
        }

        return other in conflicts.get(self, set())

    def is_hardware_supported(self) -> bool:
        """
        Проверяет, поддерживается ли стиль аппаратно FX-890.

        Возвращает:
            True для аппаратных стилей, False для программных

        Пример:
            >>> TextStyle.BOLD.is_hardware_supported()
            True
            >>> TextStyle.STRIKETHROUGH.is_hardware_supported()
            False  # Требует программной реализации
        """
        # STRIKETHROUGH реализуется программно через перепечатку с '-'
        return self != TextStyle.STRIKETHROUGH

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["TextStyle"]:
        """
        Поиск из строки (по имени).

        Аргументы:
            value: Имя стиля (например, "BOLD", "bold")

        Возвращает:
            Член TextStyle или None, если не найден
        """
        if not value:
            return None
        try:
            return cls[value.upper()]
        except KeyError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


# =============================================================================
# ФУНКЦИИ ВАЛИДАЦИИ
# =============================================================================


def validate_style_combination(styles: List[TextStyle]) -> Tuple[bool, Optional[str]]:
    """
    Проверяет, что комбинация стилей текста поддерживается FX-890.

    Проверяет взаимно исключающие стили и аппаратные ограничения.

    Аргументы:
        styles: Список флагов TextStyle для проверки

    Возвращает:
        Кортеж (is_valid, error_message). error_message равен None, если валидно.

    Пример:
        >>> valid, error = validate_style_combination([TextStyle.BOLD, TextStyle.ITALIC])
        >>> assert valid
        >>>
        >>> valid, error = validate_style_combination([
        ...     TextStyle.SUPERSCRIPT, TextStyle.SUBSCRIPT
        ... ])
        >>> assert not valid
        >>> assert "conflict" in error.lower()
    """
    if not styles:
        return (True, None)

    # Проверяем конфликты между всеми парами стилей
    for i, style1 in enumerate(styles):
        for style2 in styles[i + 1 :]:
            if style1.conflicts_with(style2):
                return (
                    False,
                    f"Conflict between {style1.description_en} and {style2.description_en}",
                )

    # Проверяем аппаратные ограничения
    # Пропорциональный режим несовместим со сжатым
    if TextStyle.PROPORTIONAL in styles and TextStyle.CONDENSED in styles:
        return (False, "Proportional spacing incompatible with condensed mode")

    # Контурный и с тенью взаимно исключающие
    if TextStyle.OUTLINE in styles and TextStyle.SHADOW in styles:
        return (False, "Outline and shadow styles cannot be combined")

    return (True, None)


def validate_cpi_font_combination(cpi: CharactersPerInch, font: FontFamily) -> bool:
    """
    Проверяет, доступен ли CPI для данного семейства шрифтов.

    Аппаратные ограничения FX-890:
    - Шрифт USD поддерживает только 10 и 12 CPI
    - Пропорциональный интервал доступен только со шрифтом ROMAN

    Аргументы:
        cpi: Шаг символов для проверки
        font: Семейство шрифтов для сопоставления

    Возвращает:
        True, если комбинация валидна, False в противном случае

    Пример:
        >>> validate_cpi_font_combination(CharactersPerInch.CPI_10, FontFamily.USD)
        True
        >>> validate_cpi_font_combination(CharactersPerInch.CPI_20, FontFamily.USD)
        False
    """
    # Режим USD ограничен 10 и 12 CPI
    if font == FontFamily.USD:
        return cpi in (CharactersPerInch.CPI_10, CharactersPerInch.CPI_12)

    # Пропорциональный только с ROMAN
    if cpi == CharactersPerInch.PROPORTIONAL:
        return font.supports_proportional

    # Все остальные комбинации валидны
    return True


def validate_quality_font_combination(quality: PrintQuality, font: FontFamily) -> bool:
    """
    Проверяет, доступен ли шрифт для данного режима качества печати.

    Аппаратные ограничения FX-890:
    - Качество USD поддерживает только шрифт USD
    - Качество NLQ требует шрифтов NLQ (ROMAN или SANS_SERIF)

    Аргументы:
        quality: Режим качества печати
        font: Семейство шрифтов для проверки

    Возвращает:
        True, если комбинация валидна, False в противном случае

    Пример:
        >>> validate_quality_font_combination(PrintQuality.USD, FontFamily.USD)
        True
        >>> validate_quality_font_combination(PrintQuality.USD, FontFamily.ROMAN)
        False
    """
    # Качество USD требует шрифт USD
    if quality == PrintQuality.USD:
        return font == FontFamily.USD

    # Качество NLQ требует шрифты NLQ
    if quality == PrintQuality.NLQ:
        return font in (FontFamily.ROMAN, FontFamily.SANS_SERIF)

    # Черновое качество совместимо с черновыми шрифтами
    if quality in (PrintQuality.HSD, PrintQuality.DRAFT):
        return font in (FontFamily.HSD, FontFamily.DRAFT, FontFamily.USD)

    return True


def validate_page_size_paper_type(
    page_size: PageSize, paper_type: PaperType
) -> Tuple[bool, Optional[str]]:
    """
    Проверяет совместимость размера страницы и типа бумаги.

    Аргументы:
        page_size: Размер страницы
        paper_type: Тип бумаги

    Возвращает:
        (is_valid, error_message)

    Пример:
        >>> validate_page_size_paper_type(PageSize.FANFOLD_8_5, PaperType.ENVELOPE)
        (False, "Fanfold paper incompatible with envelope feed")
    """
    # Непрерывная бумага только с тракторной подачей
    if paper_type == PaperType.CONTINUOUS_TRACTOR:
        if not page_size.is_compatible_with_tractor():
            return (False, f"{page_size} incompatible with tractor feed")

    # Конверты только с manual feed
    if paper_type == PaperType.ENVELOPE:
        if page_size in (PageSize.FANFOLD_8_5, PageSize.FANFOLD_11):
            return (False, "Fanfold paper incompatible with envelope feed")

    return (True, None)


def validate_graphics_mode_resolution(
    graphics_mode: GraphicsMode, image_width_pixels: int
) -> Tuple[bool, Optional[str]]:
    """
    Валидирует режим графики для заданной ширины изображения.

    Проверяет, что ширина изображения не превышает максимальную
    для данного режима (зависит от DPI и ширины бумаги).
    """
    max_width_inches = MAX_PRINT_WIDTH_INCHES
    dpi_h, _ = graphics_mode.resolution_dpi
    max_pixels = int(max_width_inches * dpi_h)

    if image_width_pixels > max_pixels:
        return (
            False,
            f"Image width {image_width_pixels}px exceeds maximum "
            f"{max_pixels}px for {graphics_mode} at {dpi_h} DPI",
        )

    return (True, None)


def validate_margin_values(
    left: float, right: float, top: float, bottom: float, page_size: PageSize, units: MarginUnits
) -> Tuple[bool, Optional[str]]:
    """
    Проверяет физические границы полей страницы.

    Аргументы:
        left, right, top, bottom: Значения полей
        page_size: Размер страницы
        units: Единицы измерения

    Возвращает:
        (is_valid, error_message)
    """
    # Конвертируем в дюймы для валидации
    if units == MarginUnits.MILLIMETERS:
        left, right, top, bottom = [x / 25.4 for x in (left, right, top, bottom)]
    elif units == MarginUnits.CHARACTERS:
        # Предполагаем 10 CPI
        left, right = left / 10, right / 10
        top, bottom = top / 6, bottom / 6  # 6 LPI
    elif units == MarginUnits.DECIPOINTS:
        left, right, top, bottom = [x / 720 for x in (left, right, top, bottom)]

    width, height = page_size.dimensions_inches

    # Проверяем, что поля не перекрываются
    if left + right >= width:
        return (False, f"Left + right margins ({left + right}in) exceed page width ({width}in)")

    if top + bottom >= height:
        return (False, f"Top + bottom margins ({top + bottom}in) exceed page height ({height}in)")

    # Минимальные поля 0.25" (аппаратное ограничение FX-890)
    min_margin = 0.25
    if any(m < 0 for m in (left, right, top, bottom)):
        return (False, "Margins cannot be negative")

    if any(m < min_margin for m in (left, right)):
        return (False, f"Horizontal margins must be at least {min_margin} inches")

    return (True, None)


# =============================================================================
# СЛУЖЕБНЫЕ ОТОБРАЖЕНИЯ
# =============================================================================

# Карта конфликтов стилей для быстрого поиска
STYLE_CONFLICTS: Dict[TextStyle, List[TextStyle]] = {
    TextStyle.SUPERSCRIPT: [TextStyle.SUBSCRIPT],
    TextStyle.SUBSCRIPT: [TextStyle.SUPERSCRIPT],
    TextStyle.PROPORTIONAL: [TextStyle.CONDENSED],
    TextStyle.CONDENSED: [TextStyle.PROPORTIONAL],
    TextStyle.OUTLINE: [TextStyle.SHADOW],
    TextStyle.SHADOW: [TextStyle.OUTLINE],
}

# Отображение скорости печати (символов в секунду при 10 CPI)
QUALITY_SPEED_MAP: Dict[PrintQuality, int] = {
    PrintQuality.USD: 566,
    PrintQuality.HSD: 283,
    PrintQuality.DRAFT: 283,
    PrintQuality.NLQ: 104,
}


# =============================================================================
# ПЕРЕЧИСЛЕНИЯ ВОЗМОЖНОСТЕЙ ПРИНТЕРА
# =============================================================================


class CodePage(str, Enum):
    """
    Поддерживаемые кодовые страницы символов для FX-890.

    Кодовые страницы определяют кодировку символов для не-ASCII символов.
    PC866 — это основная кодовая страница для русского кириллического текста.

    Команда ESC/P: ESC ( t (сложная; см. руководство)

    Атрибуты:
        value: Строковый идентификатор для сериализации
        escp_code: Целочисленный код для выбора кодовой страницы
        python_encoding: Имя кодека Python
        supports_cyrillic: Включает ли кодовая страница кириллицу

    См. также:
        Руководство по FX-890, Раздел 5.2 "Наборы символов"
    """

    PC866 = "pc866"
    PC437 = "pc437"
    PC850 = "pc850"
    PC852 = "pc852"
    PC858 = "pc858"
    CUSTOM = "custom"

    @property
    def is_fx890_compatible(self) -> bool:
        """
        Проверяет совместимость кодовой страницы с FX-890.

        FX-890 не поддерживает ESC ( t команду. Поддерживаются только:
        - PC437 (USA) через ESC t 0
        - PC850 (Multilingual) через ESC t 2
        - PC858 (Multilingual с Euro) через ESC t 2

        Returns:
            True если кодировка поддерживается на FX-890
        """
        return self in (
            CodePage.PC437,
            CodePage.PC850,
            CodePage.PC858,
        )

    @property
    def escp_code(self) -> int:
        """Целочисленный код для команды ESC/P кодовой страницы."""
        mapping = {
            CodePage.PC866: 17,
            CodePage.PC437: 0,
            CodePage.PC850: 2,
            CodePage.PC852: 3,
            CodePage.PC858: 13,
            CodePage.CUSTOM: 255,
        }
        return mapping[self]

    @property
    def python_encoding(self) -> str:
        """Имя кодека Python для кодирования/декодирования."""
        mapping = {
            CodePage.PC866: "cp866",
            CodePage.PC437: "cp437",
            CodePage.PC850: "cp850",
            CodePage.PC852: "cp852",
            CodePage.PC858: "cp858",
            CodePage.CUSTOM: "utf-8",  # Запасной вариант
        }
        return mapping[self]

    @property
    def supports_cyrillic(self) -> bool:
        """Проверяет, поддерживает ли кодовая страница символы кириллицы."""
        return self in (CodePage.PC866, CodePage.PC852)

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            CodePage.PC866: "PC866 (Russian Cyrillic)",
            CodePage.PC437: "PC437 (US English)",
            CodePage.PC850: "PC850 (Western European)",
            CodePage.PC852: "PC852 (Eastern European)",
            CodePage.PC858: "PC858 (Western European with Euro)",
            CodePage.CUSTOM: "Custom Code Page",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            CodePage.PC866: "PC866 (Русская кириллица)",
            CodePage.PC437: "PC437 (Английский США)",
            CodePage.PC850: "PC850 (Западноевропейская)",
            CodePage.PC852: "PC852 (Восточноевропейская)",
            CodePage.PC858: "PC858 (Западноевропейская с евро)",
            CodePage.CUSTOM: "Пользовательская кодировка",
        }
        return mapping[self]

    def to_escp_fx890(self) -> bytes:
        """
        Генерирует команду для FX-890 (ESC t вместо ESC ( t).

        FX-890 не поддерживает ESC ( t (Assign character table),
        используем ESC t n (Select character table) из диапазона 0-3.

        Маппинг кодировок на таблицы FX-890:
        - PC437 (USA) → ESC t 0
        - PC850/PC858 (Multilingual) → ESC t 2
        - PC866/PC852 (не поддерживаются) → fallback на PC437

        Returns:
            Байтовая последовательность ESC t n

        Examples:
            >>> CodePage.PC437.to_escp_fx890()
            b'\\x1b\\x74\\x00'  # ESC t 0

            >>> CodePage.PC850.to_escp_fx890()
            b'\\x1b\\x74\\x02'  # ESC t 2

            >>> CodePage.PC866.to_escp_fx890()  # Fallback на PC437
            b'\\x1b\\x74\\x00'  # ESC t 0

        References:
            FX-890 User's Guide, Section 5.2 "Character Tables"
        """
        # Маппинг кодировок на ESC t (0-3) для FX-890
        fx890_table_map = {
            CodePage.PC437: 0,  # USA standard
            CodePage.PC850: 2,  # Multilingual (Latin 1)
            CodePage.PC858: 2,  # Multilingual with Euro (совместима с PC850)
            CodePage.PC866: 0,  # Cyrillic → fallback на USA (нет поддержки)
            CodePage.PC852: 0,  # Eastern Europe → fallback на USA (нет поддержки)
            CodePage.CUSTOM: 0,  # Custom → fallback на USA
        }

        table_id = fx890_table_map.get(self, 0)
        return b"\x1b\x74" + bytes([table_id])  # ESC t n

    def to_escp(self) -> bytes:
        """
        Генерирует команду ESC/P для выбора этой кодовой страницы.

        Возвращает:
            bytes: Последовательность команды ESC ( t
        """
        # ESC ( t 0 3 0 n 0
        code = self.escp_code
        return b"\x1b\x28\x74\x00\x03\x00" + bytes([code, 0])

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["CodePage"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class Color(str, Enum):
    """
    Выбор цвета ленты для многоцветных лент.

    FX-890 поддерживает цветные ленты с командой ESC r n.
    Наиболее часто используется с 4-цветными лентами (CMYK) или черными лентами.

    Команда ESC/P: ESC r n

    Атрибуты:
        value: Строковый идентификатор для сериализации
        rgb_preview: RGB кортеж для предпросмотра цвета в UI

    Примечание:
        Поддержка цвета требует установки совместимой ленты.
        Стандартная черная лента поддерживает только BLACK.
    """

    BLACK = "black"
    RED = "red"
    YELLOW = "yellow"
    BLUE = "blue"
    MAGENTA = "magenta"
    CYAN = "cyan"

    @property
    def escp_command(self) -> bytes:
        """Команда ESC/P для выбора этого цвета."""
        mapping = {
            Color.BLACK: b"\x1b\x72\x00",  # ESC r 0
            Color.MAGENTA: b"\x1b\x72\x01",  # ESC r 1
            Color.CYAN: b"\x1b\x72\x02",  # ESC r 2
            Color.YELLOW: b"\x1b\x72\x04",  # ESC r 4
            Color.RED: b"\x1b\x72\x01",  # ESC r 1 (пурпурный)
            Color.BLUE: b"\x1b\x72\x02",  # ESC r 2 (голубой)
        }
        return mapping[self]

    @property
    def rgb_preview(self) -> Tuple[int, int, int]:
        """Значения RGB цвета для рендеринга предпросмотра на холсте."""
        mapping = {
            Color.BLACK: (0, 0, 0),
            Color.RED: (255, 0, 0),
            Color.YELLOW: (255, 255, 0),
            Color.BLUE: (0, 0, 255),
            Color.MAGENTA: (255, 0, 255),
            Color.CYAN: (0, 255, 255),
        }
        return mapping[self]

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        return self.value.capitalize()

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            Color.BLACK: "Чёрный",
            Color.RED: "Красный",
            Color.YELLOW: "Жёлтый",
            Color.BLUE: "Синий",
            Color.MAGENTA: "Пурпурный",
            Color.CYAN: "Голубой",
        }
        return mapping[self]

    def to_escp(self) -> bytes:
        """Генерирует команду ESC/P для выбора цвета."""
        return self.escp_command

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["Color"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


# =============================================================================
# ПЕРЕЧИСЛЕНИЯ ТИПОВ КОНТЕНТА
# =============================================================================


class DitheringAlgorithm(str, Enum):
    """
    Алгоритмы дизеринга изображений для графической печати.

    Дизеринг преобразует изображения в градациях серого/цветные в 1-битный
    чёрно-белый формат для печати на матричном принтере. Разные алгоритмы
    обменивают качество на скорость.

    Атрибуты:
        value: Строковый идентификатор для сериализации
        quality_rating: Рейтинг качества 1-5 (5 = лучшее)
    """

    FLOYD_STEINBERG = "floyd_steinberg"
    ATKINSON = "atkinson"
    ORDERED_BAYER = "ordered_bayer"
    THRESHOLD = "threshold"

    @property
    def quality_rating(self) -> int:
        """Рейтинг качества от 1 (низший) до 5 (высший)."""
        mapping = {
            DitheringAlgorithm.THRESHOLD: 1,
            DitheringAlgorithm.ORDERED_BAYER: 3,
            DitheringAlgorithm.ATKINSON: 4,
            DitheringAlgorithm.FLOYD_STEINBERG: 5,
        }
        return mapping[self]

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            DitheringAlgorithm.FLOYD_STEINBERG: "Floyd-Steinberg (Best Quality)",
            DitheringAlgorithm.ATKINSON: "Atkinson (Good Quality)",
            DitheringAlgorithm.ORDERED_BAYER: "Ordered/Bayer (Fast)",
            DitheringAlgorithm.THRESHOLD: "Threshold (Fastest)",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            DitheringAlgorithm.FLOYD_STEINBERG: "Флойд-Стейнберг (лучшее качество)",
            DitheringAlgorithm.ATKINSON: "Аткинсон (хорошее качество)",
            DitheringAlgorithm.ORDERED_BAYER: "Упорядоченный/Байер (быстро)",
            DitheringAlgorithm.THRESHOLD: "Пороговый (самый быстрый)",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["DitheringAlgorithm"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class BarcodeType(str, Enum):
    """
    Поддерживаемые типы штрих-кодов для встраивания в документ.

    FX-890 имеет ограниченную нативную поддержку штрих-кодов через команду ESC ( B.
    Другие типы могут быть отрендерены программно как графика.

    Атрибуты:
        value: Строковый идентификатор для сериализации
        native_escp_support: Поддерживает ли FX-890 этот тип нативно
        supports_text: Можно ли включить читаемый человеком текст
    """

    CODE39 = "code39"
    CODE128 = "code128"
    EAN8 = "ean8"
    EAN13 = "ean13"
    UPCA = "upca"
    UPCE = "upce"
    ITF = "itf"
    POSTNET = "postnet"
    QR = "qr"

    @property
    def native_escp_support(self) -> bool:
        """Проверяет, есть ли у FX-890 нативная поддержка ESC/P."""
        # Нативная поддержка FX-890 ограничена UPC, EAN, CODE39
        return self in (
            BarcodeType.CODE39,
            BarcodeType.EAN13,
            BarcodeType.EAN8,
            BarcodeType.UPCA,
            BarcodeType.UPCE,
        )

    @property
    def supports_text(self) -> bool:
        """Проверяет, поддерживает ли тип штрих-кода читаемый человеком текст."""
        return self != BarcodeType.QR

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            BarcodeType.CODE39: "Code 39",
            BarcodeType.CODE128: "Code 128",
            BarcodeType.EAN8: "EAN-8",
            BarcodeType.EAN13: "EAN-13",
            BarcodeType.UPCA: "UPC-A",
            BarcodeType.UPCE: "UPC-E",
            BarcodeType.ITF: "Interleaved 2 of 5",
            BarcodeType.POSTNET: "POSTNET",
            BarcodeType.QR: "QR Code",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            BarcodeType.CODE39: "Код 39",
            BarcodeType.CODE128: "Код 128",
            BarcodeType.EAN8: "EAN-8",
            BarcodeType.EAN13: "EAN-13",
            BarcodeType.UPCA: "UPC-A",
            BarcodeType.UPCE: "UPC-E",
            BarcodeType.ITF: "Interleaved 2 of 5",
            BarcodeType.POSTNET: "POSTNET",
            BarcodeType.QR: "QR-код",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["BarcodeType"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class TableStyle(str, Enum):
    """
    Стили границ ASCII таблиц.

    Определяет символы границ для рисования таблиц с использованием ASCII/Unicode
    символов рисования рамок, совместимых с кодировкой PC866.

    Атрибуты:
        value: Строковый идентификатор для сериализации
        border_chars: Словарь, отображающий позиции на символы
    """

    SIMPLE = "simple"
    DOUBLE = "double"
    GRID = "grid"
    MINIMAL = "minimal"

    @property
    def border_chars(self) -> Dict[str, str]:
        """
        Отображение символов границ для рендеринга таблиц.

        Возвращает:
            Словарь с ключами: 'tl', 'tr', 'bl', 'br' (углы),
            'h' (горизонтальная), 'v' (вертикальная), 'cross', 't_down',
            't_up', 't_left', 't_right' (T-соединения)
        """
        if self == TableStyle.SIMPLE:
            return {
                "tl": "+",
                "tr": "+",
                "bl": "+",
                "br": "+",
                "h": "-",
                "v": "|",
                "cross": "+",
                "t_down": "+",
                "t_up": "+",
                "t_left": "+",
                "t_right": "+",
            }
        elif self == TableStyle.DOUBLE:
            return {
                "tl": "╔",
                "tr": "╗",
                "bl": "╚",
                "br": "╝",
                "h": "═",
                "v": "║",
                "cross": "╬",
                "t_down": "╦",
                "t_up": "╩",
                "t_left": "╣",
                "t_right": "╠",
            }
        elif self == TableStyle.GRID:
            return {
                "tl": "┌",
                "tr": "┐",
                "bl": "└",
                "br": "┘",
                "h": "─",
                "v": "│",
                "cross": "┼",
                "t_down": "┬",
                "t_up": "┴",
                "t_left": "┤",
                "t_right": "├",
            }
        else:  # MINIMAL
            return {
                "tl": " ",
                "tr": " ",
                "bl": " ",
                "br": " ",
                "h": "-",
                "v": " ",
                "cross": " ",
                "t_down": " ",
                "t_up": " ",
                "t_left": " ",
                "t_right": " ",
            }

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            TableStyle.SIMPLE: "Simple ASCII (+, -, |)",
            TableStyle.DOUBLE: "Double Line (╔, ═, ║)",
            TableStyle.GRID: "Grid (┌, ─, │)",
            TableStyle.MINIMAL: "Minimal (headers only)",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            TableStyle.SIMPLE: "Простая ASCII (+, -, |)",
            TableStyle.DOUBLE: "Двойная линия (╔, ═, ║)",
            TableStyle.GRID: "Сетка (┌, ─, │)",
            TableStyle.MINIMAL: "Минимальная (только заголовки)",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["TableStyle"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class ListType(str, Enum):
    """
    Стили нумерации и маркеров списков.

    Определяет формат для упорядоченных и неупорядоченных списков в документах.

    Атрибуты:
        value: Строковый идентификатор для сериализации
    """

    UNORDERED_DASH = "ul_dash"
    UNORDERED_BULLET = "ul_bullet"
    ORDERED_NUMERIC = "ol_numeric"
    ORDERED_ALPHA_LOWER = "ol_alpha_lower"
    ORDERED_ALPHA_UPPER = "ol_alpha_upper"
    ORDERED_ROMAN_LOWER = "ol_roman_lower"
    ORDERED_ROMAN_UPPER = "ol_roman_upper"

    @property
    def is_ordered(self) -> bool:
        """Проверяет, является ли тип списка упорядоченным (нумерованным)."""
        return self.value.startswith("ol_")

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            ListType.UNORDERED_DASH: "Dash bullets (-)",
            ListType.UNORDERED_BULLET: "Bullet points (•)",
            ListType.ORDERED_NUMERIC: "Numeric (1, 2, 3)",
            ListType.ORDERED_ALPHA_LOWER: "Alphabetic lowercase (a, b, c)",
            ListType.ORDERED_ALPHA_UPPER: "Alphabetic uppercase (A, B, C)",
            ListType.ORDERED_ROMAN_LOWER: "Roman lowercase (i, ii, iii)",
            ListType.ORDERED_ROMAN_UPPER: "Roman uppercase (I, II, III)",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            ListType.UNORDERED_DASH: "Тире (-)",
            ListType.UNORDERED_BULLET: "Маркеры (•)",
            ListType.ORDERED_NUMERIC: "Цифры (1, 2, 3)",
            ListType.ORDERED_ALPHA_LOWER: "Строчные буквы (a, b, c)",
            ListType.ORDERED_ALPHA_UPPER: "Прописные буквы (A, B, C)",
            ListType.ORDERED_ROMAN_LOWER: "Римские строчные (i, ii, iii)",
            ListType.ORDERED_ROMAN_UPPER: "Римские прописные (I, II, III)",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["ListType"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class ImagePosition(str, Enum):
    """
    Режимы позиционирования изображений в потоке документа.

    Управляет взаимодействием изображений с окружающим текстом.

    Атрибуты:
        value: Строковый идентификатор для сериализации
    """

    INLINE = "inline"
    FLOAT_LEFT = "float_left"
    FLOAT_RIGHT = "float_right"

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            ImagePosition.INLINE: "Inline (breaks text flow)",
            ImagePosition.FLOAT_LEFT: "Float left (text wraps right)",
            ImagePosition.FLOAT_RIGHT: "Float right (text wraps left)",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            ImagePosition.INLINE: "Встроенное (разрывает текст)",
            ImagePosition.FLOAT_LEFT: "Слева (текст обтекает справа)",
            ImagePosition.FLOAT_RIGHT: "Справа (текст обтекает слева)",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["ImagePosition"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class PageSize(str, Enum):
    """
    Стандартные размеры страниц для печати.

    Определяет физические размеры бумаги в дюймах. Поддерживает стандартные
    форматы и пользовательские размеры через параметры.

    Атрибуты:
        value: Строковый идентификатор для сериализации
        width_inches: Ширина страницы в дюймах
        height_inches: Высота страницы в дюймах
        is_standard: Является ли размер стандартным

    Примечание:
        FX-890 поддерживает максимальную ширину 10 дюймов (тракторная подача).

    См. также:
        Руководство по FX-890, Приложение B "Спецификации бумаги"
    """

    # Международные стандарты
    A4 = "a4"
    A5 = "a5"
    LETTER = "letter"
    LEGAL = "legal"
    EXECUTIVE = "executive"

    # Тракторная бумага (US)
    FANFOLD_8_5 = "fanfold_8_5"  # 8.5×11" (216×279 мм)
    FANFOLD_9_5 = "fanfold_9_5"  # 9.5×11" (241×279 мм)
    FANFOLD_11 = "fanfold_11"  # 11×8.5" (279×216 мм)

    # Тракторная бумага (РФ/Европа)
    FANFOLD_190x305 = "fanfold_190x305"  # 190×305 мм (7.48×12")
    FANFOLD_190x152 = "fanfold_190x152"  # 190×152.5 мм (половина)
    FANFOLD_190x102 = "fanfold_190x102"  # 190×101.67 мм (треть)
    FANFOLD_240x305 = "fanfold_240x305"  # 240×305 мм (9.45×12")

    CUSTOM = "custom"

    @property
    def dimensions_inches(self) -> tuple[float, float]:
        """Размеры в дюймах."""
        mapping = {
            PageSize.A4: (8.27, 11.69),
            PageSize.A5: (5.83, 8.27),
            PageSize.LETTER: (8.5, 11.0),
            PageSize.LEGAL: (8.5, 14.0),
            PageSize.EXECUTIVE: (7.25, 10.5),
            PageSize.FANFOLD_8_5: (8.5, 11.0),
            PageSize.FANFOLD_9_5: (9.5, 11.0),  # ✅ НОВЫЙ
            PageSize.FANFOLD_11: (11.0, 8.5),
            # ✅ НОВЫЕ РФ/ЕВРОПА ФОРМАТЫ
            PageSize.FANFOLD_190x305: (7.48, 12.01),  # 190×305 мм
            PageSize.FANFOLD_190x152: (7.48, 6.00),  # 190×152.5 мм
            PageSize.FANFOLD_190x102: (7.48, 4.00),  # 190×101.67 мм
            PageSize.FANFOLD_240x305: (9.45, 12.01),  # 240×305 мм
            PageSize.CUSTOM: (0.0, 0.0),
        }
        return mapping[self]

    @property
    def is_standard(self) -> bool:
        """Проверяет, является ли размер стандартным."""
        return self != PageSize.CUSTOM

    @property
    def max_characters_10cpi(self) -> int:
        """Максимальное количество символов на строке при 10 CPI."""
        width = self.dimensions_inches[0]
        # FX-890: минимальные поля 0.13" слева + 0.13" справа = 0.26" = 2.6 символов
        usable_width = width - 0.26
        return max(1, int(usable_width * 10))  # Минимум 1 символ

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            PageSize.A4: "A4 (210 × 297 mm)",
            PageSize.A5: "A5 (148 × 210 mm)",
            PageSize.LETTER: 'Letter (8.5" × 11")',
            PageSize.LEGAL: 'Legal (8.5" × 14")',
            PageSize.EXECUTIVE: 'Executive (7.25" × 10.5")',
            PageSize.FANFOLD_8_5: 'Fanfold 8.5" (Continuous)',
            PageSize.FANFOLD_11: 'Fanfold 11" (Continuous Landscape)',
            PageSize.CUSTOM: "Custom Size",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            PageSize.A4: "A4 (210 × 297 мм)",
            PageSize.A5: "A5 (148 × 210 мм)",
            PageSize.LETTER: 'Letter (8.5" × 11")',
            PageSize.LEGAL: 'Legal (8.5" × 14")',
            PageSize.EXECUTIVE: 'Executive (7.25" × 10.5")',
            PageSize.FANFOLD_8_5: 'Фальцованная 8.5" (непрерывная)',
            PageSize.FANFOLD_11: 'Фальцованная 11" (непрерывная альбомная)',
            PageSize.CUSTOM: "Пользовательский размер",
        }
        return mapping[self]

    def is_compatible_with_tractor(self) -> bool:
        """Совместимость с тракторной подачей."""
        return self in (
            PageSize.FANFOLD_8_5,
            PageSize.FANFOLD_9_5,
            PageSize.FANFOLD_11,
            PageSize.FANFOLD_190x305,
            PageSize.FANFOLD_190x152,
            PageSize.FANFOLD_190x102,
            PageSize.FANFOLD_240x305,
            PageSize.CUSTOM,
        )

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["PageSize"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class MarginUnits(str, Enum):
    """
    Единицы измерения полей страницы.

    Определяет единицы для указания размеров полей (отступов) документа.
    FX-890 может работать с различными единицами для удобства разработчика.

    Атрибуты:
        value: Строковый идентификатор для сериализации
    """

    INCHES = "inches"
    MILLIMETERS = "millimeters"
    CHARACTERS = "characters"
    DECIPOINTS = "decipoints"

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            MarginUnits.INCHES: "Inches",
            MarginUnits.MILLIMETERS: "Millimeters",
            MarginUnits.CHARACTERS: "Characters (depends on CPI)",
            MarginUnits.DECIPOINTS: "Decipoints (1/720 inch)",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            MarginUnits.INCHES: "Дюймы",
            MarginUnits.MILLIMETERS: "Миллиметры",
            MarginUnits.CHARACTERS: "Символы (зависит от CPI)",
            MarginUnits.DECIPOINTS: "Децепоинты (1/720 дюйма)",
        }
        return mapping[self]

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["MarginUnits"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class PrintDirection(str, Enum):
    """
    Направление печати для оптимизации скорости/качества.

    FX-890 поддерживает двунаправленную печать (быстрее) и однонаправленную
    (точнее). Также можно явно указать направление для специальных случаев.

    Команда ESC/P: ESC U n

    Атрибуты:
        value: Строковый идентификатор для сериализации
        escp_code: Код для команды ESC U
    """

    BIDIRECTIONAL = "bidirectional"
    UNIDIRECTIONAL = "unidirectional"
    LEFT_TO_RIGHT = "ltr"
    RIGHT_TO_LEFT = "rtl"

    @property
    def escp_code(self) -> int:
        """Код для команды ESC U n."""
        mapping = {
            PrintDirection.BIDIRECTIONAL: 0,
            PrintDirection.UNIDIRECTIONAL: 1,
            PrintDirection.LEFT_TO_RIGHT: 0,
            PrintDirection.RIGHT_TO_LEFT: 1,
        }
        return mapping[self]

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            PrintDirection.BIDIRECTIONAL: "Bidirectional (Faster)",
            PrintDirection.UNIDIRECTIONAL: "Unidirectional (More Precise)",
            PrintDirection.LEFT_TO_RIGHT: "Left to Right",
            PrintDirection.RIGHT_TO_LEFT: "Right to Left",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            PrintDirection.BIDIRECTIONAL: "Двунаправленная (быстрее)",
            PrintDirection.UNIDIRECTIONAL: "Однонаправленная (точнее)",
            PrintDirection.LEFT_TO_RIGHT: "Слева направо",
            PrintDirection.RIGHT_TO_LEFT: "Справа налево",
        }
        return mapping[self]

    def to_escp(self) -> bytes:
        """
        Генерирует команду ESC/P для направления печати.

        Возвращает:
            bytes: Команда ESC U n
        """
        return b"\x1b\x55" + bytes([self.escp_code])

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["PrintDirection"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class PaperSource(str, Enum):
    """
    Источники подачи бумаги для FX-890.

    Определяет механизм загрузки бумаги в принтер. FX-890 поддерживает
    тракторную подачу (непрерывная) и листовую подачу через различные лотки.

    Команда ESC/P: ESC EM (select paper source)

    Атрибуты:
        value: Строковый идентификатор для сериализации
        escp_code: Код для команды ESC EM
        is_continuous: Является ли источник непрерывным

    См. также:
        Руководство по FX-890, Раздел 2.3 "Подача бумаги"
    """

    AUTO = "auto"
    TRACTOR = "tractor"
    MANUAL_FRONT = "manual_front"
    MANUAL_REAR = "manual_rear"
    SHEET_FEEDER_BIN1 = "sheet_bin1"
    SHEET_FEEDER_BIN2 = "sheet_bin2"

    @property
    def escp_code(self) -> int:
        """Код для команды выбора источника бумаги."""
        mapping = {
            PaperSource.AUTO: 0,
            PaperSource.TRACTOR: 1,
            PaperSource.MANUAL_FRONT: 2,
            PaperSource.MANUAL_REAR: 3,
            PaperSource.SHEET_FEEDER_BIN1: 4,
            PaperSource.SHEET_FEEDER_BIN2: 5,
        }
        return mapping[self]

    @property
    def is_continuous(self) -> bool:
        """Проверяет, является ли источник непрерывным."""
        return self == PaperSource.TRACTOR

    @property
    def requires_operator_intervention(self) -> bool:
        """Проверяет, требуется ли вмешательство оператора."""
        return self in (PaperSource.MANUAL_FRONT, PaperSource.MANUAL_REAR)

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            PaperSource.AUTO: "Automatic Selection",
            PaperSource.TRACTOR: "Tractor Feed (Continuous)",
            PaperSource.MANUAL_FRONT: "Manual Feed (Front)",
            PaperSource.MANUAL_REAR: "Manual Feed (Rear)",
            PaperSource.SHEET_FEEDER_BIN1: "Sheet Feeder (Bin 1)",
            PaperSource.SHEET_FEEDER_BIN2: "Sheet Feeder (Bin 2)",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            PaperSource.AUTO: "Автоматический выбор",
            PaperSource.TRACTOR: "Тракторная подача (непрерывная)",
            PaperSource.MANUAL_FRONT: "Ручная подача (передняя)",
            PaperSource.MANUAL_REAR: "Ручная подача (задняя)",
            PaperSource.SHEET_FEEDER_BIN1: "Листовой лоток 1",
            PaperSource.SHEET_FEEDER_BIN2: "Листовой лоток 2",
        }
        return mapping[self]

    def to_escp(self) -> bytes:
        """
        Генерирует команду ESC/P для выбора источника бумаги.

        Возвращает:
            bytes: Команда ESC EM n
        """
        return b"\x1b\x19" + bytes([self.escp_code])

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["PaperSource"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


class GraphicsMode(str, Enum):
    """
    Режимы растровой графики для печати изображений на FX-890.

    FX-890 поддерживает различные режимы bit-image через команды ESC K, ESC L, ESC *.
    Разные режимы обеспечивают компромисс между скоростью и разрешением.

    Команды ESC/P: ESC K, ESC L, ESC Y, ESC Z, ESC *, ESC ^

    Атрибуты:
        value: Строковый идентификатор для сериализации
        resolution_dpi: Разрешение в точках на дюйм (горизонтальное, вертикальное)
        escp_command: Команда ESC/P для режима
        pins: Количество иголок (8 или 24)

    См. также:
        Руководство по FX-890, Раздел 6 "Растровая графика"
    """

    SINGLE_DENSITY = "single_density"
    DOUBLE_DENSITY = "double_density"
    DOUBLE_SPEED = "double_speed"
    QUAD_DENSITY = "quad_density"
    CRT_I = "crt_i"
    CRT_II = "crt_ii"
    CRT_III = "crt_iii"
    TRIPLE_DENSITY = "triple_density"
    HEXADECIMAL = "hexadecimal"
    CRT_III_24PIN = "crt_iii_24pin"

    @property
    def is_fx890_compatible(self) -> bool:
        """
        Проверяет совместимость режима с Epson FX-890 (9-pin).

        FX-890 поддерживает только базовые 8-bit режимы:
        - ESC K (60 dpi single-density)
        - ESC L (120 dpi double-density)
        - ESC Y (120 dpi double-speed)
        - ESC Z (240 dpi quad-density)

        Returns:
            True если режим поддерживается на FX-890
        """
        return self in (
            GraphicsMode.SINGLE_DENSITY,
            GraphicsMode.DOUBLE_DENSITY,
            GraphicsMode.DOUBLE_SPEED,
            GraphicsMode.QUAD_DENSITY,
        )

    def to_escp_fx890(self, num_columns: int = 0) -> bytes:
        """
        Генерирует ESC/P команду, совместимую с FX-890.

        Для несовместимых режимов (ESC * m) использует fallback
        на ближайший поддерживаемый режим.

        Args:
            num_columns: Количество столбцов графических данных (0-65535)

        Returns:
            Байтовая последовательность ESC/P команды

        Examples:
            >>> # Совместимый режим
            >>> GraphicsMode.DOUBLE_DENSITY.to_escp_fx890(100)
            b'\\x1b\\x4c\\x64\\x00'

            >>> # Несовместимый режим → fallback на QUAD_DENSITY
            >>> GraphicsMode.HEXADECIMAL.to_escp_fx890(100)
            b'\\x1b\\x5a\\x64\\x00'
        """
        if not self.is_fx890_compatible:
            # Fallback на ближайший поддерживаемый режим
            fallback_map = {
                GraphicsMode.CRT_I: GraphicsMode.SINGLE_DENSITY,  # 60 dpi → ESC K
                GraphicsMode.CRT_II: GraphicsMode.DOUBLE_DENSITY,  # 120 dpi → ESC L
                GraphicsMode.CRT_III: GraphicsMode.DOUBLE_DENSITY,  # 120 dpi → ESC L
                GraphicsMode.TRIPLE_DENSITY: GraphicsMode.QUAD_DENSITY,  # 180 dpi → ESC Z (240 dpi)
                GraphicsMode.HEXADECIMAL: GraphicsMode.QUAD_DENSITY,  # 360 dpi → ESC Z (240 dpi)
                GraphicsMode.CRT_III_24PIN: GraphicsMode.QUAD_DENSITY,  # 24-pin → ESC Z
            }
            fallback = fallback_map.get(self)
            if fallback:
                return fallback.to_escp(num_columns)

        # Для совместимых режимов используем стандартную команду
        return self.to_escp(num_columns)

    @property
    def resolution_dpi(self) -> Tuple[int, int]:
        """Разрешение как (горизонтальное, вертикальное) в DPI."""
        mapping = {
            GraphicsMode.SINGLE_DENSITY: (60, 60),
            GraphicsMode.DOUBLE_DENSITY: (120, 60),
            GraphicsMode.DOUBLE_SPEED: (120, 72),
            GraphicsMode.QUAD_DENSITY: (240, 60),
            GraphicsMode.CRT_I: (60, 60),
            GraphicsMode.CRT_II: (120, 60),
            GraphicsMode.CRT_III: (120, 120),
            GraphicsMode.TRIPLE_DENSITY: (180, 180),
            GraphicsMode.HEXADECIMAL: (360, 180),
            GraphicsMode.CRT_III_24PIN: (180, 180),
        }
        return mapping[self]

    @property
    def pins(self) -> int:
        """Количество иголок (8 или 24)."""
        if self in (GraphicsMode.HEXADECIMAL, GraphicsMode.CRT_III_24PIN):
            return 24
        return 8

    @property
    def escp_command_prefix(self) -> bytes:
        """Префикс команды ESC/P (без параметров)."""
        mapping = {
            GraphicsMode.SINGLE_DENSITY: b"\x1b\x4b",
            GraphicsMode.DOUBLE_DENSITY: b"\x1b\x4c",
            GraphicsMode.DOUBLE_SPEED: b"\x1b\x59",
            GraphicsMode.QUAD_DENSITY: b"\x1b\x5a",
            GraphicsMode.CRT_I: b"\x1b\x2a\x00",
            GraphicsMode.CRT_II: b"\x1b\x2a\x01",
            GraphicsMode.CRT_III: b"\x1b\x2a\x02",
            GraphicsMode.TRIPLE_DENSITY: b"\x1b\x2a\x03",
            GraphicsMode.HEXADECIMAL: b"\x1b\x2a\x04",
            GraphicsMode.CRT_III_24PIN: b"\x1b\x2a\x06",
        }
        return mapping[self]

    @property
    def description_en(self) -> str:
        """Описание на английском для UI."""
        mapping = {
            GraphicsMode.SINGLE_DENSITY: "Single Density (60 DPI)",
            GraphicsMode.DOUBLE_DENSITY: "Double Density (120 DPI)",
            GraphicsMode.DOUBLE_SPEED: "Double Speed (120 DPI, Fast)",
            GraphicsMode.QUAD_DENSITY: "Quad Density (240 DPI)",
            GraphicsMode.CRT_I: "CRT Graphics I (60 DPI)",
            GraphicsMode.CRT_II: "CRT Graphics II (120 DPI)",
            GraphicsMode.CRT_III: "CRT Graphics III (120 DPI, Enhanced)",
            GraphicsMode.TRIPLE_DENSITY: "Triple Density (180 DPI)",
            GraphicsMode.HEXADECIMAL: "Hexadecimal (360 DPI, 24-pin)",
            GraphicsMode.CRT_III_24PIN: "CRT III 24-pin (180 DPI)",
        }
        return mapping[self]

    @property
    def description_ru(self) -> str:
        """Описание на русском для UI."""
        mapping = {
            GraphicsMode.SINGLE_DENSITY: "Одинарная плотность (60 DPI)",
            GraphicsMode.DOUBLE_DENSITY: "Двойная плотность (120 DPI)",
            GraphicsMode.DOUBLE_SPEED: "Двойная скорость (120 DPI, быстро)",
            GraphicsMode.QUAD_DENSITY: "Четверная плотность (240 DPI)",
            GraphicsMode.CRT_I: "CRT графика I (60 DPI)",
            GraphicsMode.CRT_II: "CRT графика II (120 DPI)",
            GraphicsMode.CRT_III: "CRT графика III (120 DPI, улучшенная)",
            GraphicsMode.TRIPLE_DENSITY: "Тройная плотность (180 DPI)",
            GraphicsMode.HEXADECIMAL: "Шестнадцатеричная (360 DPI, 24 иглы)",
            GraphicsMode.CRT_III_24PIN: "CRT III 24-игольная (180 DPI)",
        }
        return mapping[self]

    def to_escp(self, num_columns: int) -> bytes:
        """
        Генерирует команду ESC/P для режима графики.

        Аргументы:
            num_columns: Количество столбцов данных (0-65535)

        Возвращает:
            bytes: Команда ESC K/L/*/^ с параметрами

        Вызывает исключение:
            ValueError: Если num_columns вне диапазона
        """
        if not 0 <= num_columns <= 65535:
            raise ValueError("num_columns must be 0-65535")

        low_byte = num_columns & 0xFF
        high_byte = (num_columns >> 8) & 0xFF

        return self.escp_command_prefix + bytes([low_byte, high_byte])

    def localized_name(self, lang: str = "ru") -> str:
        """Возвращает локализованное название для отображения в UI."""
        return self.description_ru if lang == "ru" else self.description_en

    @classmethod
    def from_string(cls, value: str) -> Optional["GraphicsMode"]:
        """Поиск без учёта регистра из строки."""
        if not value:
            return None
        try:
            return cls(value.lower())
        except ValueError:
            return None

    def __str__(self) -> str:
        """Человекочитаемое представление."""
        return self.description_en


# Значения по умолчанию (расширенные)
DEFAULT_FONT_FAMILY: FontFamily = FontFamily.DRAFT
DEFAULT_CPI: CharactersPerInch = CharactersPerInch.CPI_10
DEFAULT_PRINT_QUALITY: PrintQuality = PrintQuality.DRAFT
DEFAULT_CODEPAGE: CodePage = CodePage.PC866
DEFAULT_PAPER_TYPE: PaperType = PaperType.CONTINUOUS_TRACTOR
DEFAULT_ORIENTATION: Orientation = Orientation.PORTRAIT
DEFAULT_ALIGNMENT: Alignment = Alignment.LEFT
DEFAULT_LINE_SPACING: LineSpacing = LineSpacing.ONE_SIXTH_INCH
DEFAULT_COLOR: Color = Color.BLACK
DEFAULT_PAGE_SIZE: PageSize = PageSize.LETTER  # НОВОЕ
DEFAULT_PAPER_SOURCE: PaperSource = PaperSource.AUTO  # НОВОЕ
DEFAULT_GRAPHICS_MODE: GraphicsMode = GraphicsMode.DOUBLE_DENSITY  # НОВОЕ
DEFAULT_MARGIN_UNITS: MarginUnits = MarginUnits.INCHES  # НОВОЕ
DEFAULT_PRINT_DIRECTION: PrintDirection = PrintDirection.BIDIRECTIONAL  # НОВОЕ


# Проверка согласованности констант с перечислениями
def _validate_module_constants() -> None:
    """
    Валидирует согласованность констант модуля при импорте.

    Проверяет, что значения MAX_/MIN_ констант соответствуют
    фактическим значениям в перечислениях, и что все DEFAULT
    значения являются валидными членами своих перечислений.

    Вызывает исключение:
        AssertionError: Если обнаружено несоответствие
    """
    # MAX_CPI должен соответствовать максимальному CPI
    actual_max_cpi = max(
        cpi.numeric_value for cpi in CharactersPerInch if cpi.numeric_value is not None
    )
    assert MAX_CPI == actual_max_cpi, f"MAX_CPI mismatch: {MAX_CPI} != {actual_max_cpi}"

    # Проверка DEFAULT значений (типы)
    assert isinstance(DEFAULT_FONT_FAMILY, FontFamily), "Invalid DEFAULT_FONT_FAMILY"
    assert isinstance(DEFAULT_CPI, CharactersPerInch), "Invalid DEFAULT_CPI"
    assert isinstance(DEFAULT_CODEPAGE, CodePage), "Invalid DEFAULT_CODEPAGE"
    assert isinstance(DEFAULT_PAGE_SIZE, PageSize), "Invalid DEFAULT_PAGE_SIZE"
    assert isinstance(DEFAULT_PAPER_SOURCE, PaperSource), "Invalid DEFAULT_PAPER_SOURCE"
    assert isinstance(DEFAULT_GRAPHICS_MODE, GraphicsMode), "Invalid DEFAULT_GRAPHICS_MODE"
    assert isinstance(DEFAULT_MARGIN_UNITS, MarginUnits), "Invalid DEFAULT_MARGIN_UNITS"
    assert isinstance(DEFAULT_PRINT_DIRECTION, PrintDirection), "Invalid DEFAULT_PRINT_DIRECTION"

    # Проверка совместимости DEFAULT значений
    assert validate_cpi_font_combination(
        DEFAULT_CPI, DEFAULT_FONT_FAMILY
    ), "DEFAULT_CPI incompatible with DEFAULT_FONT_FAMILY"
    assert validate_quality_font_combination(
        DEFAULT_PRINT_QUALITY, DEFAULT_FONT_FAMILY
    ), "DEFAULT_PRINT_QUALITY incompatible with DEFAULT_FONT_FAMILY"


def validate_fx890_compatibility(
    graphics_mode: GraphicsMode,
    codepage: CodePage,
) -> tuple[bool, Optional[str]]:
    """
    Валидирует совместимость с Epson FX-890.

    Args:
        graphics_mode: Режим графики
        codepage: Кодовая страница

    Returns:
        (valid, error_message) — если valid=False, error_message объясняет причину
    """
    if not graphics_mode.is_fx890_compatible:
        return (
            False,
            f"Graphics mode '{graphics_mode.value}' requires 24-pin printer. "
            f"FX-890 supports: single_density, double_density, double_speed, quad_density.",
        )

    if not codepage.is_fx890_compatible:
        return (
            False,
            f"Codepage '{codepage.value}' has limited support on FX-890. "
            f"Recommended: PC437 (USA), PC850 (Multilingual), or PC858 (Euro). "
            f"'{codepage.value}' will fallback to PC437.",
        )

    return True, None


# Вызываем валидацию при импорте модуля
_validate_module_constants()
