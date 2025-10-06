"""
Модель секции документа с коллекцией параграфов и индивидуальными настройками.

Модель Section, представляющая логическое деление документа с собственным типом разрыва,
нумерацией страниц, настройками страницы и коллекцией параграфов. Обеспечивает управление
содержимым, валидацию совместимости с ESC/P (FX-890) и интеграцию с билдерами.

Модуль: src/model/section.py
Проект: ESC/P Text Editor
Архитектура: слой модели MVC (без генерации ESC/P команд напрямую)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final

from src.model.paragraph import Paragraph
from src.model.run import Run

logger: Final = logging.getLogger(__name__)

# =============================================================================
# Константы: аппаратные ограничения FX-890
# =============================================================================

MIN_PAGE_NUMBER: Final[int] = 1  # Минимально допустимый номер страницы
MAX_PAGE_NUMBER: Final[int] = 9999  # Максимально допустимый номер страницы

MIN_PAGE_WIDTH_INCHES: Final[float] = 4.0  # Минимальная ширина бумаги (дюймы)
MAX_PAGE_WIDTH_INCHES: Final[float] = 10.0  # Максимальная ширина бумаги (дюймы)
MIN_PAGE_LENGTH_INCHES: Final[float] = 4.0  # Минимальная длина бумаги (дюймы)
MAX_PAGE_LENGTH_INCHES: Final[float] = 22.0  # Максимальная длина бумаги (дюймы)

MIN_MARGIN_INCHES: Final[float] = 0.118  # Минимальное поле (дюймы, ~3 мм)
MAX_MARGIN_INCHES: Final[float] = 8.0  # Максимальное поле (дюймы)

DEFAULT_PAGE_WIDTH_INCHES: Final[float] = 8.5  # По умолчанию: ширина US Letter
DEFAULT_PAGE_HEIGHT_INCHES: Final[float] = 11.0  # По умолчанию: высота US Letter
DEFAULT_MARGIN_INCHES: Final[float] = 0.5  # По умолчанию: поле


# =============================================================================
# Перечисления
# =============================================================================


class SectionBreak(Enum):
    """
    Типы разрывов секций (управление переходами между страницами).

    Соответствие ESC/P-командам:
    - CONTINUOUS: Без разрыва, контент идёт сплошным потоком
    - NEW_PAGE: Вставить форм-фид (FF) для начала новой страницы
    - EVEN_PAGE: Переход к следующей четной странице
    - ODD_PAGE: Переход к следующей нечетной странице
    """

    CONTINUOUS = "continuous"
    NEW_PAGE = "new_page"
    EVEN_PAGE = "even_page"
    ODD_PAGE = "odd_page"


class PageOrientation(Enum):
    """
    Ориентация страницы для разметки секции.
    Влияет на расчет печатной области/ESC/P-команды.
    """

    PORTRAIT = "portrait"
    LANDSCAPE = "landscape"


# =============================================================================
# Неизменяемые классы конфигурации
# =============================================================================


@dataclass(frozen=True, slots=True)
class Margins:
    """
    Конфигурация полей страницы для ESC/P-принтеров (в дюймах).

    Ограничения FX-890:
      - Минимальное поле: 0.118" (~3 мм)
      - Максимальное поле: 8.0" (ограничено шириной бумаги)

    Интегрируется через метод Section.get_margin_config() для builder'ов.
    Отображается на команды ESC l, ESC Q, ESC ( c.
    """

    top: float = DEFAULT_MARGIN_INCHES
    bottom: float = DEFAULT_MARGIN_INCHES
    left: float = DEFAULT_MARGIN_INCHES
    right: float = DEFAULT_MARGIN_INCHES

    def validate(self) -> None:
        """
        Проверка значений полей на соответствие FX-890.
        Выбросит ValueError, если выходит за пределы.
        """
        for name, value in [
            ("top", self.top),
            ("bottom", self.bottom),
            ("left", self.left),
            ("right", self.right),
        ]:
            if not isinstance(value, (int, float)):
                raise TypeError(f"{name} поле должно быть числом, получено: {type(value).__name__}")
            if value < MIN_MARGIN_INCHES:
                raise ValueError(
                    f'{name} поле слишком маленькое: {value:.3f}" < {MIN_MARGIN_INCHES:.3f}"'
                )
            if value > MAX_MARGIN_INCHES:
                raise ValueError(
                    f'{name} поле слишком большое: {value:.3f}" > {MAX_MARGIN_INCHES:.3f}"'
                )

    def to_dict(self) -> dict[str, float]:
        """
        Сериализация Margin в словарь (в дюймах).
        """
        return {
            "top": self.top,
            "bottom": self.bottom,
            "left": self.left,
            "right": self.right,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Margins":
        """
        Десериализация Margin из словаря с проверкой типов.
        """
        if not isinstance(data, dict):
            raise TypeError(f"Ожидался dict, получено: {type(data).__name__}")
        return Margins(
            top=float(data.get("top", DEFAULT_MARGIN_INCHES)),
            bottom=float(data.get("bottom", DEFAULT_MARGIN_INCHES)),
            left=float(data.get("left", DEFAULT_MARGIN_INCHES)),
            right=float(data.get("right", DEFAULT_MARGIN_INCHES)),
        )


@dataclass(frozen=True, slots=True)
class PageSettings:
    """
    Конфигурация страницы секции с аппаратными ограничениями FX-890.

    Ограничения:
      - ширина: от 4" до 10"
      - длина: от 4" до 22"
      - поля — как для Margins
    """

    width: float = DEFAULT_PAGE_WIDTH_INCHES
    height: float = DEFAULT_PAGE_HEIGHT_INCHES
    orientation: PageOrientation = PageOrientation.PORTRAIT
    margins: Margins = field(default_factory=Margins)

    def validate(self) -> None:
        """
        Проверка настроек страницы и полей (ширина/длина/поля).
        TypeError — если типы некорректны.
        ValueError — если значения выходят за пределы.
        """
        if not isinstance(self.width, (int, float)):
            raise TypeError(f"Ширина должна быть числом: {type(self.width).__name__}")
        if not isinstance(self.height, (int, float)):
            raise TypeError(f"Высота должна быть числом: {type(self.height).__name__}")

        if self.width < MIN_PAGE_WIDTH_INCHES:
            raise ValueError(
                f'Ширина {self.width:.2f}" меньше минимума FX-890 ({MIN_PAGE_WIDTH_INCHES:.2f}")'
            )
        if self.width > MAX_PAGE_WIDTH_INCHES:
            raise ValueError(
                f'Ширина {self.width:.2f}" больше максимума FX-890 ({MAX_PAGE_WIDTH_INCHES:.2f}")'
            )

        if self.height < MIN_PAGE_LENGTH_INCHES:
            raise ValueError(
                f'Высота {self.height:.2f}" меньше минимума FX-890 ({MIN_PAGE_LENGTH_INCHES:.2f}")'
            )
        if self.height > MAX_PAGE_LENGTH_INCHES:
            raise ValueError(
                f'Высота {self.height:.2f}" больше максимума FX-890 ({MAX_PAGE_LENGTH_INCHES:.2f}")'
            )

        if not isinstance(self.orientation, PageOrientation):
            raise TypeError(
                f"Ориентация должна быть PageOrientation: {type(self.orientation).__name__}"
            )

        if not isinstance(self.margins, Margins):
            raise TypeError(f"Поля должны быть Margins: {type(self.margins).__name__}")
        self.margins.validate()

        if self.margins.left + self.margins.right >= self.width:
            raise ValueError(
                f'Сумма горизонтальных полей ({self.margins.left:.3f}" + {self.margins.right:.3f}") '
                f'превышает ширину страницы ({self.width:.3f}")'
            )
        if self.margins.top + self.margins.bottom >= self.height:
            raise ValueError(
                f'Сумма вертикальных полей ({self.margins.top:.3f}" + {self.margins.bottom:.3f}") '
                f'превышает высоту страницы ({self.height:.3f}")'
            )

    def get_printable_width(self) -> float:
        """
        Вернуть ширину печатной области (без горизонтальных полей).
        """
        return self.width - self.margins.left - self.margins.right

    def get_printable_height(self) -> float:
        """
        Вернуть высоту печатной области (без вертикальных полей).
        """
        return self.height - self.margins.top - self.margins.bottom

    def to_dict(self) -> dict[str, Any]:
        """
        Сериализация настроек страницы в словарь.
        """
        return {
            "width": self.width,
            "height": self.height,
            "orientation": self.orientation.value,
            "margins": self.margins.to_dict(),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "PageSettings":
        """
        Восстановить PageSettings из словаря. Проверка типов и значения orientation.
        """
        if not isinstance(data, dict):
            raise TypeError(f"Ожидался dict, получено: {type(data).__name__}")

        margins_data = data.get("margins", {})
        margins = Margins.from_dict(margins_data) if margins_data else Margins()

        orientation_str = data.get("orientation", "portrait")
        try:
            orientation = PageOrientation(orientation_str)
        except ValueError as exc:
            raise ValueError(f"Недопустимое значение ориентации: {orientation_str!r}") from exc

        return PageSettings(
            width=float(data.get("width", DEFAULT_PAGE_WIDTH_INCHES)),
            height=float(data.get("height", DEFAULT_PAGE_HEIGHT_INCHES)),
            orientation=orientation,
            margins=margins,
        )


# =============================================================================
# Главная модель Section
# =============================================================================


@dataclass(slots=True)
class Section:
    """
    Секция документа: коллекция параграфов, параметры разрыва и страницы.

    Архитектурные принципы:
      - Модель не генерирует ESC/P-команды (только экспорт параметров)
      - Все параметры страницы/полей экспортируются для builder'ов
      - page_settings неизменяемый

    Атрибуты:
      paragraphs: список параграфов
      break_type: тип разрыва секции
      page_number_start: стартовый номер страницы, None — продолжать нумерацию
      page_settings: настройки страницы (размер, поля, ориентация), либо None
    """

    paragraphs: list[Paragraph] = field(default_factory=list)
    break_type: SectionBreak = SectionBreak.NEW_PAGE
    page_number_start: int | None = None
    page_settings: PageSettings | None = None

    def __post_init__(self) -> None:
        """Проверка и нормализация атрибутов при создании объекта."""
        if not isinstance(self.paragraphs, list):
            logger.warning(
                f"'paragraphs' должен быть списком, найдено: {type(self.paragraphs).__name__}"
            )
            object.__setattr__(self, "paragraphs", list(self.paragraphs) if self.paragraphs else [])

        if self.page_number_start is not None:
            if not isinstance(self.page_number_start, int):
                logger.warning(
                    f"'page_number_start' должен быть int или None, найдено: {type(self.page_number_start).__name__}. Сбрасывается в None."
                )
                object.__setattr__(self, "page_number_start", None)
            elif not (MIN_PAGE_NUMBER <= self.page_number_start <= MAX_PAGE_NUMBER):
                logger.warning(
                    f"'page_number_start' {self.page_number_start} вне диапазона [{MIN_PAGE_NUMBER}, {MAX_PAGE_NUMBER}], приводится к границе."
                )
                object.__setattr__(
                    self,
                    "page_number_start",
                    max(MIN_PAGE_NUMBER, min(self.page_number_start, MAX_PAGE_NUMBER)),
                )

        if self.page_settings is not None:
            if not isinstance(self.page_settings, PageSettings):
                logger.warning(
                    f"'page_settings' должен быть PageSettings или None, найдено: {type(self.page_settings).__name__}. Сбрасывается в None."
                )
                object.__setattr__(self, "page_settings", None)

    # =========================================================================
    # Методы управления содержимым
    # =========================================================================

    def add_paragraph(self, paragraph: Paragraph) -> None:
        """
        Добавить параграф в конец секции.

        Исключение: TypeError — если передан не Paragraph.
        """
        if not isinstance(paragraph, Paragraph):
            raise TypeError(f"Ожидался Paragraph, получено: {type(paragraph).__name__}")

        self.paragraphs.append(paragraph)
        logger.debug(f"Добавлен параграф, всего: {len(self.paragraphs)}")

    def insert_paragraph(self, index: int, paragraph: Paragraph) -> None:
        """
        Вставить параграф по заданному индексу.

        Исключения: TypeError или IndexError.
        """
        if not isinstance(paragraph, Paragraph):
            raise TypeError(f"Ожидался Paragraph, получено: {type(paragraph).__name__}")

        if not (0 <= index <= len(self.paragraphs)):
            raise IndexError(f"Индекс вставки {index} вне диапазона {len(self.paragraphs)}")

        self.paragraphs.insert(index, paragraph)
        logger.debug(f"Вставлен параграф по индексу {index}, всего: {len(self.paragraphs)}")

    def remove_paragraph(self, index: int) -> Paragraph:
        """
        Удалить и вернуть параграф по индексу.

        Исключение: IndexError — если индекс вне диапазона.
        """
        if not (0 <= index < len(self.paragraphs)):
            raise IndexError(f"Индекс удаления {index} вне диапазона {len(self.paragraphs)}")

        removed = self.paragraphs.pop(index)
        logger.debug(f"Удалён параграф по индексу {index}, остаток: {len(self.paragraphs)}")
        return removed

    def clear_paragraphs(self) -> None:
        """
        Удалить все параграфы из секции.
        """
        count = len(self.paragraphs)
        self.paragraphs.clear()
        logger.debug(f"Очищено {count} параграфов")

    def get_paragraph_count(self) -> int:
        """Вернуть число параграфов в секции."""
        return len(self.paragraphs)

    def get_text(self) -> str:
        """Вернуть текст всей секции — все параграфы через перенос строки."""
        return "\n".join(para.get_text() for para in self.paragraphs)

    # =========================================================================
    # Методы валидации
    # =========================================================================

    def validate(self) -> None:
        """
        Проверить валидность структуры секции, всех параграфов и настроек страницы.

        Исключения: ValueError/TypeError при ошибках.
        """
        for i, para in enumerate(self.paragraphs):
            if not isinstance(para, Paragraph):
                raise TypeError(
                    f"Параграф с индексом {i} не является Paragraph: {type(para).__name__}"
                )
            try:
                para.validate()
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Параграф с индексом {i} невалиден: {exc}") from exc

        if self.page_number_start is not None:
            if not isinstance(self.page_number_start, int):
                raise TypeError(
                    f"'page_number_start' должен быть int или None, найдено: {type(self.page_number_start).__name__}"
                )
            if not (MIN_PAGE_NUMBER <= self.page_number_start <= MAX_PAGE_NUMBER):
                raise ValueError(
                    f"'page_number_start' {self.page_number_start} вне диапазона [{MIN_PAGE_NUMBER}, {MAX_PAGE_NUMBER}]"
                )

        if self.page_settings is not None:
            if not isinstance(self.page_settings, PageSettings):
                raise TypeError(
                    f"'page_settings' должен быть PageSettings или None, найдено: {type(self.page_settings).__name__}"
                )
            try:
                self.page_settings.validate()
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Ошибка проверки page_settings: {exc}") from exc

        logger.debug(
            f"Секция валидна: параграфов={len(self.paragraphs)}, "
            f"break={self.break_type.value}, "
            f"start={self.page_number_start}, "
            f"page_settings={'да' if self.page_settings is not None else 'нет'}"
        )

    # =========================================================================
    # Методы экспорта настроек для ESC/P builder'ов
    # =========================================================================

    def get_page_config(self) -> dict[str, Any]:
        """
        Экспорт настроек страницы для builder (размер, ориентация, область печати).

        Возвращает словарь:
          - width_inches (ширина)
          - height_inches (длина)
          - orientation (str)
          - printable_width_inches (ширина без полей)
          - printable_height_inches (длина без полей)
        """
        if self.page_settings is None:
            default_settings = PageSettings()
            return {
                "width_inches": default_settings.width,
                "height_inches": default_settings.height,
                "orientation": default_settings.orientation.value,
                "printable_width_inches": default_settings.get_printable_width(),
                "printable_height_inches": default_settings.get_printable_height(),
            }

        return {
            "width_inches": self.page_settings.width,
            "height_inches": self.page_settings.height,
            "orientation": self.page_settings.orientation.value,
            "printable_width_inches": self.page_settings.get_printable_width(),
            "printable_height_inches": self.page_settings.get_printable_height(),
        }

    def get_margin_config(self) -> dict[str, float]:
        """
        Экспорт конфигурации полей для builder.

        Возвращает словарь:
          - top_inches
          - bottom_inches
          - left_inches
          - right_inches
        """
        if self.page_settings is None:
            default_margins = Margins()
            return {
                "top_inches": default_margins.top,
                "bottom_inches": default_margins.bottom,
                "left_inches": default_margins.left,
                "right_inches": default_margins.right,
            }

        return {
            "top_inches": self.page_settings.margins.top,
            "bottom_inches": self.page_settings.margins.bottom,
            "left_inches": self.page_settings.margins.left,
            "right_inches": self.page_settings.margins.right,
        }

    def requires_form_feed(self) -> bool:
        """
        Нужна ли команда FF (form feed) для перехода перед секцией.

        True — если break_type секции не CONTINUOUS.
        """
        return self.break_type != SectionBreak.CONTINUOUS

    # =========================================================================
    # Методы сериализации
    # =========================================================================

    def copy(self) -> "Section":
        """
        Глубокое копирование секции (параграфы копируются, page_settings — передаётся ссылкой).
        """
        return Section(
            paragraphs=[para.copy() for para in self.paragraphs],
            break_type=self.break_type,
            page_number_start=self.page_number_start,
            page_settings=self.page_settings,
        )

    def to_dict(self) -> dict[str, Any]:
        """
        Сериализация секции в dict.
        """
        return {
            "paragraphs": [para.to_dict() for para in self.paragraphs],
            "break_type": self.break_type.value,
            "page_number_start": self.page_number_start,
            "page_settings": self.page_settings.to_dict() if self.page_settings else None,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Section":
        """
        Десериализация секции из dict.
        Исключения: TypeError/ValueError при некорректных данных.
        """
        if not isinstance(data, dict):
            raise TypeError(f"Ожидался dict, получено: {type(data).__name__}")

        paragraphs_data = data.get("paragraphs", [])
        if not isinstance(paragraphs_data, list):
            raise TypeError(
                f"'paragraphs' должен быть списком, найдено: {type(paragraphs_data).__name__}"
            )

        paragraphs = [Paragraph.from_dict(para_data) for para_data in paragraphs_data]

        break_type_str = data.get("break_type", "new_page")
        try:
            break_type = SectionBreak(break_type_str)
        except ValueError as exc:
            raise ValueError(f"Недопустимый break_type: {break_type_str!r}") from exc

        page_settings_data = data.get("page_settings")
        page_settings = (
            PageSettings.from_dict(page_settings_data) if page_settings_data is not None else None
        )

        return Section(
            paragraphs=paragraphs,
            break_type=break_type,
            page_number_start=data.get("page_number_start"),
            page_settings=page_settings,
        )

    # =========================================================================
    # Dunder-методы
    # =========================================================================

    def __len__(self) -> int:
        """Возвращает число символов в тексте всех параграфов секции."""
        total = 0
        for para in self.paragraphs:
            if hasattr(para, "runs") and isinstance(para.runs, list):
                for run in para.runs:
                    if hasattr(run, "text") and isinstance(run.text, str):
                        total += len(run.text)
        return total

    def __eq__(self, other: object) -> bool:
        """
        Эквивалентность секций — сравниваются все атрибуты и параграфы.
        """
        if not isinstance(other, Section):
            return NotImplemented

        return (
            self.paragraphs == other.paragraphs
            and self.break_type == other.break_type
            and self.page_number_start == other.page_number_start
            and self.page_settings == other.page_settings
        )

    def __repr__(self) -> str:
        """
        Строковое представление секции (информативно).
        """
        return (
            f"Section(paragraphs={len(self.paragraphs)}, chars={len(self)}, "
            f"break='{self.break_type.value}', page_settings={'да' if self.page_settings is not None else 'нет'})"
        )


# =============================================================================
# Утилитные функции
# =============================================================================


def merge_sections(sections: list[Section], preserve_breaks: bool = False) -> Section:
    """
    Объединить несколько секций в одну.

    Все параграфы будут скопированы, используются параметры первой секции.
    Если preserve_breaks=True — между секциями добавляются пустые параграфы-разделители.
    Исключение: ValueError для пустого списка.
    """
    if not sections:
        raise ValueError("Нельзя объединить пустой список секций")

    result = sections[0].copy()
    result.clear_paragraphs()

    for i, section in enumerate(sections):
        for para in section.paragraphs:
            result.add_paragraph(para.copy())
        if preserve_breaks and i < len(sections) - 1:
            result.add_paragraph(Paragraph())  # Разделитель

    logger.info(f"Объединено {len(sections)} секций, итог: {len(result.paragraphs)} параграфов")
    return result


def split_section_at(section: Section, paragraph_index: int) -> tuple[Section, Section]:
    """
    Разбить секцию на две по заданному индексу параграфа.

    Первая секция получает все параметры оригинала, вторая — CONTINUOUS break_type,
    page_number_start=None, но те же page_settings.

    Исключения: ValueError при недопустимом индексе.
    """
    if not (0 < paragraph_index < len(section.paragraphs)):
        raise ValueError(
            f"Индекс разбиения {paragraph_index} вне диапазона (0, {len(section.paragraphs)})"
        )

    first = Section(
        paragraphs=[para.copy() for para in section.paragraphs[:paragraph_index]],
        break_type=section.break_type,
        page_number_start=section.page_number_start,
        page_settings=section.page_settings,
    )
    second = Section(
        paragraphs=[para.copy() for para in section.paragraphs[paragraph_index:]],
        break_type=SectionBreak.CONTINUOUS,
        page_number_start=None,
        page_settings=section.page_settings,
    )

    logger.info(
        f"Секция разбита по индексу {paragraph_index}: "
        f"{len(section.paragraphs)} параграфов → {len(first.paragraphs)} + {len(second.paragraphs)}"
    )
    return first, second
