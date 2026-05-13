"""Главный рендерер документов в ESC/P байты.

Предоставляет:
- DocumentRenderer: Обход дерева Document → ESC/P bytes
- RenderSettings: Настройки рендеринга (CPI, LPI, качество, поля)

Example:
    >>> from src.documents.printing import DocumentRenderer, RenderSettings
    >>> from src.documents.printing.text_renderer import TextRenderer
    >>> from src.documents.printing.form_renderer import FormRenderer
    >>> from src.model.document import Document
    >>> doc = Document(title="Test")
    >>> settings = RenderSettings()
    >>> renderer = DocumentRenderer(TextRenderer(), FormRenderer())
    >>> escp_data = renderer.render(doc, settings)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol

from src.escp.commands.charset import CharacterTable, set_character_table
from src.escp.commands.hardware import ESC_INIT_PRINTER
from src.escp.commands.page_control import set_left_margin, set_right_margin
from src.escp.commands.print_quality import (
    ESC_DRAFT_MODE,
    ESC_LQ_MODE,
)
from src.model.enums import (
    CharactersPerInch,
    CodePage,
    LinesPerInch,
    PaperType,
    PrintQuality,
)

if TYPE_CHECKING:
    from src.documents.constructor.field_builder import FormField
    from src.documents.types.type_schema import FormInstance
    from src.model.character_style import CharacterStyle
    from src.model.document import Document
    from src.model.paragraph import Paragraph
    from src.model.run import Run
    from src.model.section import Section
    from src.model.table import Table

logger: Final = logging.getLogger(__name__)

# ESC/P constants
ESC_RESET = ESC_INIT_PRINTER  # ESC @ - сброс принтера
FF = b"\x0c"  # Form feed - разрыв страницы
CRLF = b"\r\n"  # Carriage return + Line feed


@dataclass(frozen=True)
class Margins:
    """Поля документа в дюймах.

    Attributes:
        left: Левое поле в дюймах
        right: Правое поле в дюймах
        top: Верхнее поле в дюймах
        bottom: Нижнее поле в дюймах
    """

    left: float = 1.0
    right: float = 1.0
    top: float = 1.0
    bottom: float = 1.0


@dataclass(frozen=True)
class RenderOptions:
    """Опции рендеринга документа.

    Attributes:
        reset_printer: Отправлять ESC @ перед рендерингом
        form_feed_at_end: Добавлять FF (form feed) в конце документа
        page_breaks: Использовать разрывы страниц между секциями
    """

    reset_printer: bool = True
    form_feed_at_end: bool = True
    page_breaks: bool = True


@dataclass(frozen=True)
class RenderSettings:
    """Настройки рендеринга документа.

    Attributes:
        paper_type: Тип бумаги
        cpi: Символов на дюйм
        lpi: Строк на дюйм
        quality: Качество печати
        margins: Поля документа
        codepage: Кодовая страница
    """

    paper_type: PaperType = PaperType.CONTINUOUS_TRACTOR
    cpi: CharactersPerInch = CharactersPerInch.CPI_10
    lpi: LinesPerInch = LinesPerInch.LPI_6
    quality: PrintQuality = PrintQuality.DRAFT
    margins: Margins = field(default_factory=Margins)
    codepage: CodePage = CodePage.PC866

    def __post_init__(self) -> None:
        """Валидация настроек после создания."""
        if self.margins.left < 0 or self.margins.right < 0:
            raise ValueError("Margins must be non-negative")


def _get_character_table(codepage: CodePage) -> CharacterTable:
    """Конвертирует CodePage модели в CharacterTable ESC/P.

    Args:
        codepage: Кодовая страница из модели

    Returns:
        CharacterTable для ESC/P команд
    """
    mapping: dict[CodePage, CharacterTable] = {
        CodePage.PC437: CharacterTable.PC437,
        CodePage.PC850: CharacterTable.PC850,
        CodePage.PC860: CharacterTable.PC860,
        CodePage.PC863: CharacterTable.PC863,
        CodePage.PC865: CharacterTable.PC865,
        CodePage.PC866: CharacterTable.PC866,
        CodePage.PC852: CharacterTable.PC852,
        CodePage.PC858: CharacterTable.PC858,
    }
    return mapping.get(codepage, CharacterTable.PC866)


class TextRendererProtocol(Protocol):
    """Протокол для текстового рендерера."""

    def render_paragraph(self, paragraph: Paragraph, settings: RenderSettings) -> bytes: ...

    def render_text_run(self, run: Run, settings: RenderSettings) -> bytes: ...

    def apply_character_style(self, cmd: bytearray, style: CharacterStyle) -> None: ...


class FormRendererProtocol(Protocol):
    """Протокол для рендерера форм."""

    def render_form(self, form: FormInstance, settings: RenderSettings) -> bytes: ...

    def render_field(self, field: FormField, settings: RenderSettings) -> bytes: ...

    def render_field_border(self, field: FormField) -> bytes: ...


class DocumentRenderer:
    """Главный координатор рендеринга документов.

    Обходит дерево Document и делегирует рендеринг специализированным
    рендерерам (TextRenderer, FormRenderer).

    Attributes:
        _text_renderer: Рендерер текстовых параграфов
        _form_renderer: Рендерер форм
        _logger: Логгер
        _codepage: Кодовая страница
        _options: Опции рендеринга

    Example:
        >>> text_renderer = TextRenderer()
        >>> form_renderer = FormRenderer()
        >>> renderer = DocumentRenderer(text_renderer, form_renderer)
        >>> data = renderer.render(document, settings)
    """

    def __init__(
        self,
        text_renderer: TextRendererProtocol | None = None,
        form_renderer: FormRendererProtocol | None = None,
        codepage: CodePage = CodePage.PC866,
        options: RenderOptions | None = None,
    ) -> None:
        """Инициализирует рендерер.

        Args:
            text_renderer: Рендерер текстовых параграфов
            form_renderer: Рендерер форм
            codepage: Кодовая страница
            options: Опции рендеринга
        """
        self._text_renderer = text_renderer
        self._form_renderer = form_renderer
        self._logger = logging.getLogger(__name__)
        self._codepage = codepage
        self._options = options or RenderOptions()

    def render(self, document: Document, settings: RenderSettings | None = None) -> bytes:
        """Рендерит документ в ESC/P байты.

        Args:
            document: Документ для рендеринга
            settings: Настройки рендеринга (опционально)

        Returns:
            ESC/P байты готовые к отправке на принтер

        Example:
            >>> settings = RenderSettings(cpi=CharactersPerInch.CPI_12)
            >>> data = renderer.render(doc, settings)
        """
        settings = settings or RenderSettings()
        result = bytearray()

        # Инициализация принтера
        result.extend(self._render_init(settings))

        # Рендеринг секций
        for section in document.sections:
            result.extend(self._render_section(section, settings))

        # Завершение документа
        result.extend(self._render_finalize(settings))

        self._logger.debug(f"Rendered document: {len(result)} bytes")
        return bytes(result)

    def render_page(
        self, document: Document, page_num: int, settings: RenderSettings | None = None
    ) -> bytes:
        """Рендерит одну страницу документа.

        Args:
            document: Документ для рендеринга
            page_num: Номер страницы (0-based)
            settings: Настройки рендеринга

        Returns:
            ESC/P байты для указанной страницы

        Note:
            FX-890 не поддерживает произвольный доступ к страницам.
            Метод использует эвристику для рендеринга нужной страницы.
        """
        settings = settings or RenderSettings()
        result = bytearray()

        # Инициализация
        result.extend(self._render_init(settings))

        # Пропускаем предыдущие страницы через FF
        for _ in range(page_num):
            result.extend(FF)

        # Находим и рендерим секцию для данной страницы
        current_page = 0
        for section in document.sections:
            if current_page == page_num:
                result.extend(self._render_section(section, settings))
                break
            if section.break_type:
                current_page += 1

        return bytes(result)

    def get_page_count(self, document: Document, settings: RenderSettings | None = None) -> int:
        """Вычисляет общее количество страниц документа.

        Args:
            document: Документ для подсчёта
            settings: Настройки рендеринга (влияет на разбиение)

        Returns:
            Количество страниц

        Note:
            Точный подсчёт требует полного рендеринга.
            Метод даёт приблизительную оценку на основе разрывов секций.
        """
        if not document.sections:
            return 1

        page_count = 1
        for section in document.sections:
            if section.break_type:
                page_count += 1

        return page_count

    def _render_init(self, settings: RenderSettings) -> bytes:
        """Рендерит инициализацию принтера.

        Args:
            settings: Настройки рендеринга

        Returns:
            ESC/P команды инициализации
        """
        result = bytearray()

        # Сброс принтера
        result.extend(ESC_RESET)

        # Установка кодовой страницы
        result.extend(set_character_table(_get_character_table(settings.codepage)))

        # Установка качества печати
        if settings.quality == PrintQuality.NLQ:
            result.extend(ESC_LQ_MODE)
        else:
            result.extend(ESC_DRAFT_MODE)

        # Установка полей
        left_margin_chars = int(settings.margins.left * 10)  # 10 CPI base
        right_margin_chars = int((8.5 - settings.margins.right) * 10)
        result.extend(set_left_margin(left_margin_chars))
        result.extend(set_right_margin(right_margin_chars))

        self._logger.debug(
            f"Init: codepage={settings.codepage.value}, quality={settings.quality.value}"
        )
        return bytes(result)

    def _render_section(self, section: Section, settings: RenderSettings) -> bytes:
        """Рендерит одну секцию документа.

        Args:
            section: Секция для рендеринга
            settings: Настройки рендеринга

        Returns:
            ESC/P байты секции
        """
        result = bytearray()

        # Разрыв страницы перед секцией (кроме первой)
        if section.break_type:
            result.extend(FF)

        # Рендеринг элементов секции
        for item in section.paragraphs:
            if hasattr(item, "runs"):  # Paragraph
                if self._text_renderer:
                    result.extend(self._text_renderer.render_paragraph(item, settings))
                else:
                    # Fallback: просто текст
                    result.extend(self._render_paragraph_fallback(item, settings))
            elif hasattr(item, "rows"):  # Table
                result.extend(self._render_table_fallback(item, settings))
            else:
                self._logger.warning(f"Unknown section item type: {type(item)}")

        return bytes(result)

    def _render_paragraph_fallback(self, paragraph: Paragraph, settings: RenderSettings) -> bytes:
        """Fallback рендеринг параграфа без TextRenderer.

        Args:
            paragraph: Параграф для рендеринга
            settings: Настройки рендеринга

        Returns:
            ESC/P байты
        """
        result = bytearray()

        # Простой текст из runs
        for run in paragraph.runs:
            if hasattr(run, "text"):
                 try:
                     encoded = run.text.encode("cp866", errors="replace")
                     result.extend(encoded)
                 except TypeError:
                     result.extend(run.text.encode("ascii", errors="replace") if hasattr(run.text, "encode") else b"")

        result.extend(CRLF)
        return bytes(result)

    def _render_table_fallback(self, table: Table, settings: RenderSettings) -> bytes:
        """Fallback рендеринг таблицы.

        Args:
            table: Таблица для рендеринга
            settings: Настройки рендеринга

        Returns:
            ESC/P байты
        """
        result = bytearray()
        result.extend(b"[Table]" + CRLF)
        return bytes(result)

    def _render_finalize(self, settings: RenderSettings) -> bytes:
        """Рендерит завершение документа.

        Args:
            settings: Настройки рендеринга

        Returns:
            ESC/P команды завершения
        """
        result = bytearray()
        result.extend(FF)  # Form feed для выгрузки страницы
        return bytes(result)

    def render_to_file(
        self, document: Document, path: Path, settings: RenderSettings | None = None
    ) -> None:
        """Рендерит документ и сохраняет в файл.

        Args:
            document: Документ для рендеринга
            path: Путь к выходному файлу
            settings: Настройки рендеринга

        Raises:
            IOError: При ошибке записи файла

        Example:
            >>> renderer.render_to_file(doc, Path("output.escp"))
        """
        data = self.render(document, settings)
        path.write_bytes(data)
        self._logger.info(f"Rendered document saved to: {path}")


__all__ = ["DocumentRenderer", "RenderSettings", "RenderOptions", "Margins"]
