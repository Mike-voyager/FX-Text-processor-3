"""
Document Model for ESC/P Text Editor.

This module provides the core document model that represents the entire
document structure for the FX-Text-processor-3 editor. It follows MVC
architecture and integrates with ESC/P command generation.

Author: Mike-voyager
Project: FX-Text-processor-3
License: MIT
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Union
from uuid import UUID, uuid4

from src.model.enums import (
    Alignment,
    CharactersPerInch,
    CodePage,
    FontFamily,
    LineSpacing,
    Orientation,
    PageSize,
    PaperSource,
    PaperType,
    PrintDirection,
    PrintQuality,
)

from typing import TYPE_CHECKING


# Добавить поля доступа: owner, scope ("private"/"shared"/"system"), shared_with (user_id[])
# Метод проверки доступа (is_accessible(user_id, role))


# Use TYPE_CHECKING to avoid circular imports
if TYPE_CHECKING:
    from src.model.section import Section
    from src.model.paragraph import Paragraph
    from src.model.table import Table


logger = logging.getLogger(__name__)


@dataclass
class DocumentMetadata:
    """
    Метаданные свойств документа.

    Атрибуты:
        title: Заголовок документа
        author: Автор документа
        created: Временная метка создания
        modified: Временная метка последнего изменения
        subject: Тема/описание документа
        keywords: Список ключевых слов документа
        version: Версия формата документа
    """

    title: str = ""
    author: str = ""
    created: datetime = field(default_factory=datetime.now)
    modified: datetime = field(default_factory=datetime.now)
    subject: str = ""
    keywords: List[str] = field(default_factory=list)
    version: str = "1.0"

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует метаданные в формат словаря."""
        return {
            "title": self.title,
            "author": self.author,
            "created": self.created.isoformat(),
            "modified": self.modified.isoformat(),
            "subject": self.subject,
            "keywords": self.keywords,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DocumentMetadata:
        """Создает метаданные из словаря."""
        return cls(
            title=data.get("title", ""),
            author=data.get("author", ""),
            created=datetime.fromisoformat(data.get("created", datetime.now().isoformat())),
            modified=datetime.fromisoformat(data.get("modified", datetime.now().isoformat())),
            subject=data.get("subject", ""),
            keywords=data.get("keywords", []),
            version=data.get("version", "1.0"),
        )


@dataclass
class PageSettings:
    """
    Настройки макета страницы для документа.

    Атрибуты:
        size: Размер страницы (A4, Letter и т.д.)
        orientation: Книжная или альбомная ориентация
        width_inches: Ширина страницы в дюймах
        height_inches: Высота страницы в дюймах
        margin_left_inches: Левое поле в дюймах
        margin_right_inches: Правое поле в дюймах
        margin_top_inches: Верхнее поле в дюймах
        margin_bottom_inches: Нижнее поле в дюймах
        line_spacing: Режим межстрочного интервала
        characters_per_line: Максимум символов в строке
        lines_per_page: Максимум строк на странице
    """

    size: PageSize = PageSize.LETTER
    orientation: Orientation = Orientation.PORTRAIT
    width_inches: float = 8.5
    height_inches: float = 11.0
    margin_left_inches: float = 1.0
    margin_right_inches: float = 1.0
    margin_top_inches: float = 1.0
    margin_bottom_inches: float = 1.0
    line_spacing: LineSpacing = LineSpacing.ONE_SIXTH_INCH
    characters_per_line: int = 80
    lines_per_page: int = 66

    def get_printable_width_inches(self) -> float:
        """Вычисляет печатную ширину (без полей)."""
        return self.width_inches - self.margin_left_inches - self.margin_right_inches

    def get_printable_height_inches(self) -> float:
        """Вычисляет печатную высоту (без полей)."""
        return self.height_inches - self.margin_top_inches - self.margin_bottom_inches

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует настройки страницы в словарь."""
        return {
            "size": self.size.value,
            "orientation": self.orientation.value,
            "width_inches": self.width_inches,
            "height_inches": self.height_inches,
            "margin_left_inches": self.margin_left_inches,
            "margin_right_inches": self.margin_right_inches,
            "margin_top_inches": self.margin_top_inches,
            "margin_bottom_inches": self.margin_bottom_inches,
            "line_spacing": self.line_spacing.value,
            "characters_per_line": self.characters_per_line,
            "lines_per_page": self.lines_per_page,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PageSettings:
        """Создает настройки страницы из словаря."""
        return cls(
            size=PageSize.from_string(data.get("size", "letter")) or PageSize.LETTER,
            orientation=Orientation.from_string(data.get("orientation", "portrait"))
            or Orientation.PORTRAIT,
            width_inches=data.get("width_inches", 8.5),
            height_inches=data.get("height_inches", 11.0),
            margin_left_inches=data.get("margin_left_inches", 1.0),
            margin_right_inches=data.get("margin_right_inches", 1.0),
            margin_top_inches=data.get("margin_top_inches", 1.0),
            margin_bottom_inches=data.get("margin_bottom_inches", 1.0),
            line_spacing=LineSpacing.from_string(data.get("line_spacing", "1/6"))
            or LineSpacing.ONE_SIXTH_INCH,
            characters_per_line=data.get("characters_per_line", 80),
            lines_per_page=data.get("lines_per_page", 66),
        )


@dataclass
class PrinterSettings:
    """
    Специфичные для принтера настройки для вывода ESC/P.

    Атрибуты:
        printer_name: Имя целевого принтера
        codepage: Активная кодовая страница (PC866 для русского)
        print_quality: Качество черновика или NLQ
        font_family: Семейство шрифтов (Draft, Roman, Sans Serif)
        characters_per_inch: CPI (10, 12, 15, 17, 20)
        print_direction: Двунаправленная или однонаправленная печать
        paper_type: Тип бумаги (непрерывная, листовая и т.д.)
        paper_source: Источник бумаги (тракторная, ручная, лоток)
        default_alignment: Выравнивание текста по умолчанию
    """

    printer_name: str = "Epson FX-890"
    codepage: CodePage = CodePage.PC866
    print_quality: PrintQuality = PrintQuality.DRAFT
    font_family: FontFamily = FontFamily.DRAFT
    characters_per_inch: CharactersPerInch = CharactersPerInch.CPI_10
    print_direction: PrintDirection = PrintDirection.BIDIRECTIONAL
    paper_type: PaperType = PaperType.CONTINUOUS_TRACTOR
    paper_source: PaperSource = PaperSource.AUTO
    default_alignment: Alignment = Alignment.LEFT

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует настройки принтера в словарь."""
        return {
            "printer_name": self.printer_name,
            "codepage": self.codepage.value,
            "print_quality": self.print_quality.value,
            "font_family": self.font_family.value,
            "characters_per_inch": self.characters_per_inch.value,
            "print_direction": self.print_direction.value,
            "paper_type": self.paper_type.value,
            "paper_source": self.paper_source.value,
            "default_alignment": self.default_alignment.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PrinterSettings:
        """Создает настройки принтера из словаря."""
        return cls(
            printer_name=data.get("printer_name", "Epson FX-890"),
            codepage=CodePage.from_string(data.get("codepage", "pc866")) or CodePage.PC866,
            print_quality=PrintQuality.from_string(data.get("print_quality", "draft"))
            or PrintQuality.DRAFT,
            font_family=FontFamily.from_string(data.get("font_family", "draft"))
            or FontFamily.DRAFT,
            characters_per_inch=CharactersPerInch.from_string(
                data.get("characters_per_inch", "10cpi")
            )
            or CharactersPerInch.CPI_10,
            print_direction=PrintDirection.from_string(data.get("print_direction", "bidirectional"))
            or PrintDirection.BIDIRECTIONAL,
            paper_type=PaperType.from_string(data.get("paper_type", "continuous_tractor"))
            or PaperType.CONTINUOUS_TRACTOR,
            paper_source=PaperSource.from_string(data.get("paper_source", "auto"))
            or PaperSource.AUTO,
            default_alignment=Alignment.from_string(data.get("default_alignment", "left"))
            or Alignment.LEFT,
        )


class Document:
    """
    Основная модель документа, представляющая всю структуру документа.

    Этот класс служит корнем дерева документа и управляет:
    - Метаданными документа (заголовок, автор и т.д.)
    - Настройками макета страницы
    - Конфигурацией принтера
    - Секциями, содержащими параграфы и таблицы
    - Историей отмены/повтора
    - Состоянием документа (изменён, сохранён)

    Атрибуты:
        id: Уникальный идентификатор документа
        metadata: Метаданные документа
        page_settings: Конфигурация макета страницы
        printer_settings: Конфигурация принтера ESC/P
        sections: Список секций документа
        file_path: Путь к файлу сохранённого документа
        is_modified: Состояние изменения документа

    Пример:
        >>> doc = Document()
        >>> doc.metadata.title = "Пример документа"
        >>> section = doc.add_section()
        >>> para = section.add_paragraph("Привет, мир!")
        >>> doc.save_to_file("document.json")
    """

    def __init__(
        self,
        metadata: Optional[DocumentMetadata] = None,
        page_settings: Optional[PageSettings] = None,
        printer_settings: Optional[PrinterSettings] = None,
    ):
        """
        Инициализирует новый документ.

        Аргументы:
            metadata: Метаданные документа (создаётся по умолчанию, если None)
            page_settings: Настройки макета страницы (создаётся по умолчанию, если None)
            printer_settings: Конфигурация принтера (создаётся по умолчанию, если None)
        """
        self.id: UUID = uuid4()
        self.metadata: DocumentMetadata = metadata or DocumentMetadata()
        self.page_settings: PageSettings = page_settings or PageSettings()
        self.printer_settings: PrinterSettings = printer_settings or PrinterSettings()
        self.sections: List[Any] = []  # Будет List[Section] при реализации
        self.file_path: Optional[Path] = None
        self._is_modified: bool = False

        logger.info(f"Создан новый документ с ID: {self.id}")

    @property
    def is_modified(self) -> bool:
        """Проверяет, был ли документ изменён с момента последнего сохранения."""
        return self._is_modified

    @is_modified.setter
    def is_modified(self, value: bool) -> None:
        """Устанавливает состояние изменения документа."""
        self._is_modified = value
        if value:
            self.metadata.modified = datetime.now()

    def add_section(
        self,
        name: str = "",
        index: Optional[int] = None,
    ) -> Any:  # Вернёт Section при реализации
        """
        Добавляет новую секцию в документ.

        Аргументы:
            name: Имя/заголовок секции
            index: Позиция вставки (добавляет в конец, если None)

        Возвращает:
            Созданный объект Section

        Вызывает исключения:
            IndexError: Если индекс вне границ
            NotImplementedError: Класс Section ещё не реализован
        """
        # TODO: Реализовать, когда класс Section будет готов
        raise NotImplementedError("Класс Section ещё не реализован")

    def remove_section(self, index: int) -> Any:  # Вернёт Section при реализации
        """
        Удаляет секцию из документа.

        Аргументы:
            index: Индекс секции для удаления

        Возвращает:
            Удалённый объект Section

        Вызывает исключения:
            IndexError: Если индекс вне границ
        """
        if index < 0 or index >= len(self.sections):
            raise IndexError(f"Индекс секции {index} вне диапазона [0, {len(self.sections)})")

        section = self.sections.pop(index)
        logger.debug(f"Удалена секция на индексе {index}")
        self.is_modified = True
        return section

    def get_section(self, index: int) -> Any:  # Вернёт Section при реализации
        """
        Получает секцию по индексу.

        Аргументы:
            index: Индекс секции

        Возвращает:
            Section на указанном индексе

        Вызывает исключения:
            IndexError: Если индекс вне границ
        """
        if index < 0 or index >= len(self.sections):
            raise IndexError(f"Индекс секции {index} вне диапазона [0, {len(self.sections)})")
        return self.sections[index]

    def iter_sections(self) -> Iterator[Any]:  # Вернёт Iterator[Section] при реализации
        """Итерирует по всем секциям."""
        return iter(self.sections)

    def get_text_content(self) -> str:
        """
        Получает текстовое содержимое всего документа.

        Возвращает:
            Весь текстовый контент, соединённый с разделителями секций/параграфов
        """
        # TODO: Реализовать, когда класс Section будет готов
        return ""

    def get_character_count(self) -> int:
        """Получает общее количество символов (без пробелов)."""
        return sum(len(text.replace(" ", "")) for text in self.get_text_content().split())

    def get_word_count(self) -> int:
        """Получает общее количество слов."""
        return len(self.get_text_content().split())

    def get_line_count(self) -> int:
        """Получает общее количество строк."""
        return self.get_text_content().count("\n") + 1

    def clear(self) -> None:
        """Очищает всё содержимое документа."""
        self.sections.clear()
        logger.info(f"Очищено всё содержимое документа {self.id}")
        self.is_modified = True

    def to_dict(self) -> Dict[str, Any]:
        """
        Сериализует документ в формат словаря.

        Возвращает:
            Представление словаря, подходящее для экспорта JSON
        """
        return {
            "id": str(self.id),
            "metadata": self.metadata.to_dict(),
            "page_settings": self.page_settings.to_dict(),
            "printer_settings": self.printer_settings.to_dict(),
            "sections": [],  # TODO: Сериализовать секции при реализации
            "file_path": str(self.file_path) if self.file_path else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Document:
        """
        Десериализует документ из формата словаря.

        Аргументы:
            data: Представление словаря из JSON

        Возвращает:
            Восстановленный объект Document
        """
        metadata = DocumentMetadata.from_dict(data.get("metadata", {}))
        page_settings = PageSettings.from_dict(data.get("page_settings", {}))
        printer_settings = PrinterSettings.from_dict(data.get("printer_settings", {}))

        doc = cls(
            metadata=metadata,
            page_settings=page_settings,
            printer_settings=printer_settings,
        )

        # Восстанавливаем UUID, если присутствует
        if "id" in data:
            doc.id = UUID(data["id"])

        # Восстанавливаем путь к файлу
        if data.get("file_path"):
            doc.file_path = Path(data["file_path"])

        # TODO: Восстановить секции при реализации класса Section

        doc._is_modified = False
        logger.info(f"Загружен документ {doc.id} с {len(doc.sections)} секциями")
        return doc

    def save_to_file(self, file_path: Union[str, Path]) -> None:
        """
        Сохраняет документ в файл JSON.

        Аргументы:
            file_path: Путь к целевому файлу

        Вызывает исключения:
            IOError: Если файл не может быть записан
        """
        import json

        file_path = Path(file_path)

        try:
            with file_path.open("w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)

            self.file_path = file_path
            self._is_modified = False
            logger.info(f"Документ сохранён в {file_path}")

        except Exception as e:
            logger.error(f"Не удалось сохранить документ в {file_path}: {e}")
            raise IOError(f"Невозможно сохранить документ: {e}") from e

    @classmethod
    def load_from_file(cls, file_path: Union[str, Path]) -> Document:
        """
        Загружает документ из файла JSON.

        Аргументы:
            file_path: Путь к исходному файлу

        Возвращает:
            Загруженный объект Document

        Вызывает исключения:
            IOError: Если файл не может быть прочитан
            ValueError: Если формат файла невалиден
        """
        import json

        file_path = Path(file_path)

        try:
            with file_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            doc = cls.from_dict(data)
            doc.file_path = file_path
            logger.info(f"Документ загружен из {file_path}")
            return doc

        except json.JSONDecodeError as e:
            logger.error(f"Невалидный формат JSON в {file_path}: {e}")
            raise ValueError(f"Невалидный формат документа: {e}") from e

        except Exception as e:
            logger.error(f"Не удалось загрузить документ из {file_path}: {e}")
            raise IOError(f"Невозможно загрузить документ: {e}") from e

    def __repr__(self) -> str:
        """Строковое представление для отладки."""
        return (
            f"Document(id={self.id}, title='{self.metadata.title}', "
            f"sections={len(self.sections)}, modified={self.is_modified})"
        )

    def __len__(self) -> int:
        """Возвращает количество секций."""
        return len(self.sections)


# Фабричные функции для общих типов документов


def create_blank_document(title: str = "Без названия") -> Document:
    """
    Создаёт пустой документ с настройками по умолчанию.

    Аргументы:
        title: Заголовок документа

    Возвращает:
        Новый пустой Document
    """
    doc = Document()
    doc.metadata.title = title
    # TODO: Добавить секцию, когда класс Section будет готов
    return doc


def create_letter_document(
    title: str = "Письмо",
    author: str = "",
) -> Document:
    """
    Создаёт документ, настроенный для печати письма.

    Аргументы:
        title: Заголовок документа
        author: Автор письма

    Возвращает:
        Document, настроенный для формата письма
    """
    doc = Document()
    doc.metadata.title = title
    doc.metadata.author = author

    # Настройки страницы для письма (Letter 8.5" × 11")
    doc.page_settings.size = PageSize.LETTER
    doc.page_settings.width_inches = 8.5
    doc.page_settings.height_inches = 11.0
    doc.page_settings.margin_left_inches = 1.0
    doc.page_settings.margin_right_inches = 1.0
    doc.page_settings.margin_top_inches = 1.0
    doc.page_settings.margin_bottom_inches = 1.0

    # TODO: Добавить секции, когда класс Section будет готов

    return doc


def create_form_document(
    title: str = "Форма",
    continuous: bool = True,
) -> Document:
    """
    Создаёт документ, настроенный для печати непрерывных форм.

    Аргументы:
        title: Заголовок формы
        continuous: Использовать непрерывную рулонную бумагу

    Возвращает:
        Document, настроенный для печати форм
    """
    doc = Document()
    doc.metadata.title = title

    # Настройки формы
    if continuous:
        doc.page_settings.size = PageSize.FANFOLD_8_5
        doc.printer_settings.paper_type = PaperType.CONTINUOUS_TRACTOR
        doc.printer_settings.paper_source = PaperSource.TRACTOR
    else:
        doc.page_settings.size = PageSize.LETTER
        doc.printer_settings.paper_type = PaperType.SHEET_FEED

    doc.page_settings.margin_left_inches = 0.5
    doc.page_settings.margin_right_inches = 0.5
    doc.page_settings.margin_top_inches = 0.5
    doc.page_settings.margin_bottom_inches = 0.5

    # Оптимизация для черновика
    doc.printer_settings.print_quality = PrintQuality.DRAFT
    doc.printer_settings.font_family = FontFamily.DRAFT

    # TODO: Добавить секцию, когда класс Section будет готов

    return doc
