"""Рендерер FreeForm режима для Form Designer.

Модуль содержит FreeFormModeRenderer — адаптер/обёртку над существующим
FreeFormRenderer, расширяющую его для интеграции с Grid Canvas.

Classes:
    FreeFormModeRenderer: Адаптер рендерера с поддержкой Grid Canvas и CPI-aware rendering.

Example:
    >>> from src.gui.modes.free_form.renderer import FreeFormModeRenderer
    >>> from src.gui.renderers.free_form_renderer import FreeFormDocument
    >>> renderer = FreeFormModeRenderer(widget_id="ff_renderer")
    >>> renderer.mount(parent_frame)
    >>> renderer.render(FreeFormDocument(content="Hello World", cpi=12))

Version: 1.1
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Final, Optional

from src.documents.types.document_type import DocumentMode
from src.gui.components.base.widget import BaseWidget
from src.gui.core.commands.command import Command
from src.gui.core.commands.command_stack import CommandStack
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol
from src.gui.renderers.free_form_renderer import (
    VALID_CPI_INT,
    FreeFormDocument,
    FreeFormRenderer,
)
from src.gui.renderers.protocols import DocumentRendererProtocol, implements
from src.model.enums import CharactersPerInch

# Константы для стилей строк двойной высоты
SHADOW_ROW_BG_COLOR: Final[str] = "#e8e8e8"
DOUBLE_HEIGHT_MARKER: Final[str] = "\U0001f4cf"  # Измерительная линейка (emoji-free fallback)
DOUBLE_HEIGHT_TAG: Final[str] = "double_height_row"
ROW_MARKER_TAG: Final[str] = "double_height_marker"

# Константы для подсветки валидации
INVALID_CHAR_TAG: Final[str] = "invalid_char"
INVALID_CHAR_BG_COLOR: Final[str] = "#ff6b6b"  # Красный фон для невалидных символов


@implements(DocumentRendererProtocol)
class FreeFormModeRenderer(BaseWidget):
    """Адаптер рендерера FreeForm для интеграции с Grid Canvas.

    Оборачивает FreeFormRenderer и добавляет:
    - Интеграцию с ESC/P Grid Canvas (коллега-агент создаст его)
    - CPI-aware rendering (поддержка 10, 12, 15, 17, 20)
    - Grid snap для позиционирования курсора
    - Адаптацию к Form Designer требованиям

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        _base_renderer: Внутренний FreeFormRenderer для фактического рендеринга.
        _grid_canvas: Опциональная ссылка на Grid Canvas (None до его создания).
        _cpi: Текущее значение CPI (characters per inch).
        _command_stack: Стек команд для undo/redo.
        _on_cpi_change_callback: Callback при изменении CPI.

    Example:
        >>> renderer = FreeFormModeRenderer(widget_id="ff_renderer")
        >>> renderer.mount(parent_frame)
        >>> doc = FreeFormDocument(content="Test", cpi=12)
        >>> renderer.render(doc)
        >>> print(renderer.get_cpi())
        12
    """

    def __init__(
        self,
        widget_id: str = "free_form_mode_renderer",
        controller: Optional[ControllerProtocol] = None,
        command_stack: Optional[CommandStack] = None,
    ) -> None:
        """Инициализация FreeFormModeRenderer.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер для callbacks.
            command_stack: Опциональный CommandStack для undo/redo.

        Example:
            >>> renderer = FreeFormModeRenderer(
            ...     widget_id="my_ff_renderer",
            ...     command_stack=CommandStack(),
            ... )
        """
        super().__init__(widget_id=widget_id, controller=controller)

        # Создаём базовый рендерер
        self._base_renderer: FreeFormRenderer = FreeFormRenderer(
            widget_id=f"{widget_id}_base",
            controller=controller,
            command_stack=command_stack,
        )

        # Grid Canvas (интегрируется когда доступен)
        self._grid_canvas: Optional[tk.Widget] = None

        # CPI state
        self._cpi: int = 10

        # Command stack
        self._command_stack: Optional[CommandStack] = command_stack

        # Callbacks
        self._on_cpi_change_callback: Optional[Callable[[int], None]] = None
        self._on_content_change_callback: Optional[Callable[[str], None]] = None
        self._on_cursor_move_callback: Optional[Callable[[int, int], None]] = None

        # Grid snap state
        self._grid_snap_enabled: bool = True
        self._grid_column_width: int = 8  # Пикселей на колонку (примерно)

        # Double-height row tracking
        self._double_height_rows: set[int] = set()
        self._shadow_row_lines: set[int] = set()
        self._on_row_style_change_callback: Optional[Callable[[int, bool], None]] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Делегирует создание базовому FreeFormRenderer.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame.
        """
        # Монтируем базовый рендерер
        base_widget = self._base_renderer.mount(parent)

        # Сохраняем ссылку
        self._tk_widget = base_widget

        # Настраиваем теги для double-height строк
        self._configure_row_style_tags()

        # Настраиваем теги для валидации
        self._configure_validation_tags()

        # Настраиваем привязки событий для Grid Canvas интеграции
        self._setup_bindings()

        return base_widget

    def _configure_row_style_tags(self) -> None:
        """Настраивает теги стилей для строк с double-height символами.

        Создаёт теги:
        - double_height_row: стиль для строк с double-height
        - shadow_row: серый фон для следующей строки
        - double_height_marker: маркер в левом поле

        Example:
            >>> renderer._configure_row_style_tags()
        """
        text_widget = self._base_renderer._tk_text
        if text_widget is None:
            return

        # Тег для строки с double-height символами
        text_widget.tag_configure(
            DOUBLE_HEIGHT_TAG,
            background="#d4edda",  # Светло-зеленый фон для double-height строк
        )

        # Тег для shadow row (следующая строка после double-height)
        text_widget.tag_configure(
            "shadow_row",
            background=SHADOW_ROW_BG_COLOR,
        )

        # Тег для маркера в левом поле
        text_widget.tag_configure(
            ROW_MARKER_TAG,
            foreground="#666666",
            font=("Segoe UI", 8),
        )

    def _configure_validation_tags(self) -> None:
        """Настраивает теги для подсветки невалидных символов.

        Создаёт тег "invalid_char" с красным фоном для выделения
        символов, несовместимых с PC866.

        Example:
            >>> renderer._configure_validation_tags()
        """
        text_widget = self._base_renderer._tk_text
        if text_widget is None:
            return

        text_widget.tag_configure(
            INVALID_CHAR_TAG,
            background=INVALID_CHAR_BG_COLOR,
        )

    def validate_and_highlight(self, text: str) -> int:
        """Валидирует текст и подсвечивает невалидные символы.

        Сканирует текст, находит символы, несовместимые с PC866,
        и подсвечивает их красным фоном.

        Args:
            text: Текст для валидации и подсветки.

        Returns:
            Количество невалидных символов.

        Example:
            >>> count = renderer.validate_and_highlight("Hello — world")
            >>> print(count)  # 1 (em-dash невалиден)
        """
        from src.gui.components.codepage_validator import CodepageValidator

        text_widget = self._base_renderer._tk_text
        if text_widget is None:
            return 0

        # Сначала очищаем старые подсветки
        self.clear_validation_highlights()

        # Создаём валидатор и проверяем
        validator = CodepageValidator()
        results = validator.validate(text)

        # Подсвечиваем каждый невалидный символ
        for result in results:
            self.highlight_invalid_char(result.position, len(result.char))

        return len(results)

    def clear_validation_highlights(self) -> None:
        """Удаляет все подсветки невалидных символов.

        Удаляет тег "invalid_char" со всего текста в виджете.

        Example:
            >>> renderer.clear_validation_highlights()
        """
        text_widget = self._base_renderer._tk_text
        if text_widget is None:
            return

        try:
            text_widget.tag_remove(INVALID_CHAR_TAG, "1.0", tk.END)
        except tk.TclError:
            pass  # Игнорируем ошибки если тег не существует

    def highlight_invalid_char(self, position: int, length: int = 1) -> None:
        """Подсвечивает конкретный невалидный символ.

        Args:
            position: Позиция символа в тексте (0-indexed).
            length: Длина символа (для многобайтовых символов).

        Example:
            >>> renderer.highlight_invalid_char(6, 1)  # Подсветка символа на позиции 6
        """
        text_widget = self._base_renderer._tk_text
        if text_widget is None:
            return

        # Конвертируем 0-indexed position в tk.Text индекс "line.col"
        # Для этого нужно пройти по тексту и найти line.col
        text_content = text_widget.get("1.0", tk.END)

        # Вычисляем line и col из position
        line = 1
        col = 0
        chars_seen = 0

        for char in text_content:
            if chars_seen >= position:
                break
            if char == "\n":
                line += 1
                col = 0
            else:
                col += 1
            chars_seen += 1

        # Применяем тег к символу
        start_idx = f"{line}.{col}"
        end_idx = f"{line}.{col + length}"

        try:
            text_widget.tag_add(INVALID_CHAR_TAG, start_idx, end_idx)
        except tk.TclError:
            pass  # Игнорируем ошибки позиционирования

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Grid Canvas интеграции."""
        # Базовый рендерер уже настроил свои bindings
        # Добавляем наши специфичные
        if self._base_renderer._tk_text is not None:
            # Bind для grid snap
            self._base_renderer._tk_text.bind("<ButtonRelease-1>", self._on_grid_snap)
            self._base_renderer._tk_text.bind("<KeyRelease>", self._on_content_update)

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        # Очищаем ссылки на Grid Canvas
        self._grid_canvas = None
        self._on_cpi_change_callback = None
        self._on_content_change_callback = None

        # Демонтируем базовый рендерер
        if self._base_renderer.is_mounted():
            self._base_renderer.unmount()

    # ==========================================================================
    # GRID CANVAS INTEGRATION
    # ==========================================================================

    def mount(self, parent: Any) -> tk.Widget:
        """Монтирует рендерер в родительский контейнер.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет.
        """
        widget = super().mount(parent)

        # Устанавливаем command stack в базовый рендерер если он ещё не установлен
        if self._command_stack is not None and self._base_renderer.is_mounted():
            self._base_renderer.set_command_stack(self._command_stack)

        return widget

    def unmount(self) -> None:
        """Размонтирует рендерер и освобождает ресурсы."""
        if not self._is_mounted:
            return

        # Очистка через базовый рендерер
        if self._base_renderer.is_mounted():
            self._base_renderer.wipe_sensitive_data()

        super().unmount()

    def attach_grid_canvas(self, grid_canvas: tk.Widget) -> None:
        """Присоединяет Grid Canvas для интеграции.

        Этот метод будет вызван коллегой-агентом после создания Grid Canvas.

        Args:
            grid_canvas: Grid Canvas виджет для интеграции.

        Example:
            >>> renderer.attach_grid_canvas(grid_canvas_widget)
        """
        self._grid_canvas = grid_canvas

    def detach_grid_canvas(self) -> None:
        """Отсоединяет Grid Canvas."""
        self._grid_canvas = None

    def _on_grid_snap(self, event: tk.Event) -> None:
        """Обрабатывает grid snap для позиционирования курсора.

        Args:
            event: Событие мыши.
        """
        if not self._grid_snap_enabled or self._base_renderer._tk_text is None:
            return

        # Получаем позицию курсора
        try:
            idx = self._base_renderer._tk_text.index(tk.INSERT)
            line, col = map(int, idx.split("."))

            # Snap к ближайшей grid позиции
            snapped_col = self._snap_to_grid(col)
            if snapped_col != col:
                self._base_renderer._tk_text.mark_set(tk.INSERT, f"{line}.{snapped_col}")

            # Callback если установлен
            if self._on_cursor_move_callback is not None:
                self._on_cursor_move_callback(line, snapped_col + 1)

        except tk.TclError:
            pass  # Игнорируем ошибки позиционирования

    def _snap_to_grid(self, column: int) -> int:
        """Snap column position to grid.

        Args:
            column: Текущая колонка (0-based).

        Returns:
            Snapped column position.
        """
        if not self._grid_snap_enabled:
            return column

        # Snap к ближайшему чётному (для ESC/P alignment)
        return (column // self._grid_column_width) * self._grid_column_width

    def _on_content_update(self, event: tk.Event) -> None:  # noqa: ARG002
        """Обрабатывает обновление содержимого для Grid Canvas."""
        if self._on_content_change_callback is not None:
            content = self.get_content()
            self._on_content_change_callback(content)

    # ==========================================================================
    # MODE IDENTIFICATION
    # ==========================================================================

    def get_mode(self) -> DocumentMode:
        """Возвращает режим документа, поддерживаемый рендерером.

        Returns:
            DocumentMode.FREE_FORM — данный рендерер работает
            в режиме свободного редактирования.

        Example:
            >>> renderer.get_mode()
            <DocumentMode.FREE_FORM: 'free_form'>
        """
        return DocumentMode.FREE_FORM

    # ==========================================================================
    # CPI-AWARE RENDERING
    # ==========================================================================

    def apply_cpi(self, cpi: int) -> None:
        """Применяет CPI (characters per inch) к документу.

        Args:
            cpi: Значение CPI (10, 12, 15, 17, 20).

        Raises:
            LifecycleError: Если виджет не смонтирован.
            ValueError: Если CPI недопустимо.

        Example:
            >>> renderer.apply_cpi(12)  # Elite font
            >>> renderer.apply_cpi(17)  # Condensed
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="apply_cpi",
                message="Widget not mounted",
            )

        if cpi not in VALID_CPI_INT:
            raise ValueError(f"Invalid CPI: {cpi}. Valid values: {sorted(VALID_CPI_INT)}")

        self._cpi = cpi

        # Применяем через базовый рендерер
        self._base_renderer.apply_cpi(cpi)

        # Обновляем grid snap width в зависимости от CPI
        self._update_grid_snap_width(cpi)

        # Callback при изменении CPI
        if self._on_cpi_change_callback is not None:
            self._on_cpi_change_callback(cpi)

    def _update_grid_snap_width(self, cpi: int) -> None:
        """Обновляет ширину grid snap в зависимости от CPI.

        Args:
            cpi: Текущее значение CPI.
        """
        # Расчёт column width на основе CPI
        # 10 CPI = wider chars, 20 CPI = narrower chars
        cpi_to_width: dict[int, int] = {
            10: 12,  # Standard
            12: 10,  # Elite
            15: 8,  # Condensed
            17: 7,  # Extra condensed
            20: 6,  # Ultra condensed
        }
        self._grid_column_width = cpi_to_width.get(cpi, 10)

    def get_cpi(self) -> int:
        """Возвращает текущее значение CPI.

        Returns:
            Текущее значение CPI (10, 12, 15, 17, 20).
        """
        return self._cpi

    def set_cpi_from_enum(self, cpi_enum: CharactersPerInch) -> None:
        """Устанавливает CPI из CharactersPerInch enum.

        Args:
            cpi_enum: CharactersPerInch enum значение.

        Example:
            >>> from src.model.enums import CharactersPerInch
            >>> renderer.set_cpi_from_enum(CharactersPerInch.CPI_12)
        """
        numeric_value = cpi_enum.numeric_value
        if numeric_value is not None:
            self.apply_cpi(numeric_value)

    # ==========================================================================
    # DOCUMENT METHODS
    # ==========================================================================

    def render(self, document: FreeFormDocument) -> None:
        """Загружает содержимое документа в редактор.

        Args:
            document: Документ для отображения.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="render",
                message="Widget not mounted",
            )

        # Делегируем базовому рендереру
        self._base_renderer.render(document)

        # Синхронизируем CPI
        self._cpi = document.cpi

    def get_content(self) -> str:
        """Возвращает текущее содержимое редактора.

        Returns:
            Текстовое содержимое редактора.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_content",
                message="Widget not mounted",
            )

        return self._base_renderer.get_content()

    def set_content(self, content: str) -> None:
        """Устанавливает содержимое редактора.

        Args:
            content: Новое текстовое содержимое.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="set_content",
                message="Widget not mounted",
            )

        self._base_renderer.set_text(content)

    def get_cursor_position(self) -> tuple[int, int]:
        """Возвращает позицию курсора.

        Returns:
            Кортеж (line, column) в 1-based координатах.
        """
        return self._base_renderer.get_cursor_position()

    def set_cursor_position(self, line: int, column: int) -> None:
        """Устанавливает позицию курсора.

        Args:
            line: Строка (1-based).
            column: Столбец (1-based).
        """
        self._base_renderer.set_cursor_position(line, column)

    # ==========================================================================
    # FORMATTING METHODS
    # ==========================================================================

    def apply_format(self, tag: str, start: str, end: str) -> None:
        """Применяет форматирование к диапазону текста.

        Args:
            tag: Тег форматирования ("bold", "italic", "underline", "bold_italic").
            start: Начальная позиция ("line.col").
            end: Конечная позиция ("line.col").

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="apply_format",
                message="Widget not mounted",
            )

        self._base_renderer.apply_format(tag, start, end)

    def remove_format(self, tag: str, start: str, end: str) -> None:
        """Удаляет форматирование из диапазона текста.

        Args:
            tag: Тег форматирования для удаления.
            start: Начальная позиция.
            end: Конечная позиция.
        """
        self._base_renderer.remove_format(tag, start, end)

    def get_formatting(self) -> list[Any]:
        """Возвращает список применённого форматирования.

        Returns:
            Список FormatRange с текущими тегами.
        """
        return self._base_renderer.get_formatting()

    # ==========================================================================
    # CALLBACK SETTERS
    # ==========================================================================

    def set_on_cpi_change_callback(self, callback: Callable[[int], None]) -> None:
        """Устанавливает callback для изменения CPI.

        Args:
            callback: Функция, вызываемая при изменении CPI.
        """
        self._on_cpi_change_callback = callback

    def set_on_content_change_callback(self, callback: Callable[[str], None]) -> None:
        """Устанавливает callback для изменения содержимого.

        Args:
            callback: Функция, вызываемая при изменении текста.
        """
        self._on_content_change_callback = callback

        # Пробрасываем в базовый рендерер
        self._base_renderer.set_on_text_change_callback(callback)

    def set_on_cursor_move_callback(self, callback: Callable[[int, int], None]) -> None:
        """Устанавливает callback для движения курсора.

        Args:
            callback: Функция, вызываемая при движении курсора.
        """
        self._on_cursor_move_callback = callback

    # ==========================================================================
    # SECURITY METHODS
    # ==========================================================================

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные из редактора."""
        self._base_renderer.wipe_sensitive_data()

    def hide_content(self) -> None:
        """Скрывает содержимое редактора (session lock)."""
        self._base_renderer.hide_content()

    def restore_content(self) -> None:
        """Восстанавливает содержимое редактора (session unlock)."""
        self._base_renderer.restore_content()

    # ==========================================================================
    # PROTOCOL METHODS (DocumentRendererProtocol)
    # ==========================================================================

    def apply_command(self, command: Command) -> None:
        """Применяет команду к документу.

        Args:
            command: Команда для выполнения.
        """
        self._base_renderer.apply_command(command)

    def can_handle(self, mode: Any) -> bool:
        """Проверяет, может ли рендерер обрабатывать данный режим.

        Args:
            mode: Режим документа для проверки.

        Returns:
            True если рендерер поддерживает данный режим.
        """
        return self._base_renderer.can_handle(mode)

    def supports_formatting(self) -> bool:
        """Проверяет, поддерживает ли рендерер форматирование текста.

        Returns:
            True для FreeFormModeRenderer (CPI, bold, italic, underline).
        """
        return True

    def set_command_stack(self, stack: CommandStack) -> None:
        """Устанавливает CommandStack для undo/redo операций.

        Args:
            stack: Стек команд для данного рендерера.
        """
        self._command_stack = stack
        self._base_renderer.set_command_stack(stack)

    # ==========================================================================
    # UTILITY METHODS
    # ==========================================================================

    def get_base_renderer(self) -> FreeFormRenderer:
        """Возвращает базовый FreeFormRenderer.

        Returns:
            Внутренний FreeFormRenderer экземпляр.
        """
        return self._base_renderer

    def get_text_widget(self) -> Optional[tk.Text]:
        """Возвращает tk.Text виджет для прямого доступа.

        Returns:
            Tkinter Text widget или None если не смонтирован.
        """
        if self._base_renderer._tk_text is not None:
            return self._base_renderer._tk_text
        return None

    def set_grid_snap_enabled(self, enabled: bool) -> None:
        """Включает/отключает grid snap.

        Args:
            enabled: True для включения grid snap.
        """
        self._grid_snap_enabled = enabled

    def is_grid_snap_enabled(self) -> bool:
        """Проверяет, включён ли grid snap.

        Returns:
            True если grid snap активен.
        """
        return self._grid_snap_enabled

    # ==========================================================================
    # DOUBLE-HEIGHT ROW INDICATORS
    # ==========================================================================

    def _apply_row_styles(
        self,
        double_height_rows: set[int],
    ) -> None:
        """Применяет визуальные стили к строкам с double-height символами.

        Сканирует документ и применяет:
        - Фоновый цвет для строк с double-height
        - Shadow row effect для следующей строки
        - Маркеры в левом поле

        Args:
            double_height_rows: Множество строк (1-based) содержащих double-height символы.

        Example:
            >>> renderer._apply_row_styles({1, 3, 5})
        """
        text_widget = self._base_renderer._tk_text
        if text_widget is None:
            return

        # Очищаем предыдущие стили
        self._clear_row_styles()

        # Сохраняем текущие double-height строки
        self._double_height_rows = set(double_height_rows)

        # Применяем стили
        for row in double_height_rows:
            self._apply_row_style_for_line(row)

        # Уведомляем о изменениях
        if self._on_row_style_change_callback is not None:
            current_line = self.get_cursor_position()[0]
            is_double = current_line in self._double_height_rows
            self._on_row_style_change_callback(current_line, is_double)

    def _clear_row_styles(self) -> None:
        """Очищает все стили строк.

        Удаляет теги double_height_row, shadow_row из текстового виджета.

        Example:
            >>> renderer._clear_row_styles()
        """
        text_widget = self._base_renderer._tk_text
        if text_widget is None:
            return

        # Удаляем теги со всего документа
        for tag in (DOUBLE_HEIGHT_TAG, "shadow_row"):
            try:
                text_widget.tag_remove(tag, "1.0", tk.END)
            except tk.TclError:
                pass  # Игнорируем ошибки если тег не существует

        self._shadow_row_lines.clear()

    def _apply_row_style_for_line(self, line: int) -> None:
        """Применяет стили для конкретной строки.

        Args:
            line: Номер строки (1-based).

        Example:
            >>> renderer._apply_row_style_for_line(5)
        """
        text_widget = self._base_renderer._tk_text
        if text_widget is None:
            return

        line_str = str(line)

        # Применяем стиль double-height к текущей строке
        text_widget.tag_add(DOUBLE_HEIGHT_TAG, f"{line_str}.0", f"{line_str}.end")

        # Применяем shadow row к следующей строке
        shadow_line = line + 1
        shadow_idx = f"{shadow_line}.0"

        # Проверяем существует ли следующая строка
        try:
            text_widget.index(shadow_idx)
            text_widget.tag_add("shadow_row", shadow_idx, f"{shadow_line}.end")
            self._shadow_row_lines.add(shadow_line)
        except tk.TclError:
            pass  # Следующая строка не существует

    def update_row_styles_from_document(self, document: FreeFormDocument) -> None:
        """Обновляет стили строк на основе документа.

        Анализирует документ и находит строки с double-height форматированием.

        Args:
            document: Документ для анализа.

        Example:
            >>> renderer.update_row_styles_from_document(doc)
        """
        # Определяем строки с double-height на основе форматирования
        double_height_rows: set[int] = set()

        # Анализируем ranges форматирования
        for fmt_range in document.formatting:
            # Проверяем теги связанные с double-height
            if hasattr(fmt_range, "tag") and fmt_range.tag in (
                "double_height",
                "double_wh",
            ):
                # Определяем строки из позиции
                try:
                    start_line = int(fmt_range.start.split(".")[0])
                    end_line = int(fmt_range.end.split(".")[0])
                    for line in range(start_line, end_line + 1):
                        double_height_rows.add(line)
                except (ValueError, AttributeError):
                    pass

        self._apply_row_styles(double_height_rows)

    def is_line_double_height(self, line: int) -> bool:
        """Проверяет, содержит ли строка double-height символы.

        Args:
            line: Номер строки (1-based).

        Returns:
            True если строка содержит double-height.

        Example:
            >>> renderer.is_line_double_height(5)
            True
        """
        return line in self._double_height_rows

    def get_double_height_rows(self) -> set[int]:
        """Возвращает множество строк с double-height символами.

        Returns:
            Множество номеров строк (1-based).

        Example:
            >>> rows = renderer.get_double_height_rows()
            >>> print(rows)
            {1, 3, 5}
        """
        return self._double_height_rows.copy()

    def get_shadow_row_lines(self) -> set[int]:
        """Возвращает множество shadow row строк.

        Shadow rows - это строки следующие за double-height строками.

        Returns:
            Множество номеров shadow row строк (1-based).

        Example:
            >>> rows = renderer.get_shadow_row_lines()
            >>> print(rows)
            {2, 4, 6}
        """
        return self._shadow_row_lines.copy()

    def set_on_row_style_change_callback(
        self,
        callback: Optional[Callable[[int, bool], None]],
    ) -> None:
        """Устанавливает callback для изменения стиля строки.

        Args:
            callback: Функция, вызываемая при изменении стиля строки.
                Принимает (line: int, is_double_height: bool).

        Example:
            >>> renderer.set_on_row_style_change_callback(
            ...     lambda line, is_dh: print(f"Line {line}: double-height={is_dh}")
            ... )
        """
        self._on_row_style_change_callback = callback

    def set_line_double_height(self, line: int, is_double: bool) -> None:
        """Устанавливает или снимает double-height для строки.

        Args:
            line: Номер строки (1-based).
            is_double: True для установки double-height, False для снятия.

        Raises:
            LifecycleError: Если виджет не смонтирован.
            ValueError: Если номер строки некорректен.

        Example:
            >>> renderer.set_line_double_height(5, True)
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="set_line_double_height",
                message="Widget not mounted",
            )

        if line < 1:
            raise ValueError(f"Номер строки должен быть >= 1: {line}")

        if is_double:
            self._double_height_rows.add(line)
        else:
            self._double_height_rows.discard(line)

        # Переприменяем все стили
        self._apply_row_styles(self._double_height_rows)

    def clear_double_height_rows(self) -> None:
        """Очищает все double-height строки.

        Example:
            >>> renderer.clear_double_height_rows()
        """
        self._double_height_rows.clear()
        self._shadow_row_lines.clear()
        self._clear_row_styles()

    # ==========================================================================
    # PROTOCOL COMPLIANCE: DocumentModeRendererProtocol
    # ==========================================================================

    def supports_workflow(self) -> bool:
        """Проверяет, поддерживает ли рендерер workflow-переходы.

        FreeForm режим не поддерживает workflow переходы
        (только STRUCTURED_FORM поддерживает).

        Returns:
            False — FreeForm не требует MFA для переходов.
        """
        return False

    def get_undo_manager(self) -> Any:
        """Возвращает менеджер undo/redo операций.

        Returns:
            Экземпляр CommandStack или None если не установлен.
        """
        return self._command_stack

    def display_document(self, document: Any) -> None:
        """Отображает документ с учётом SmartEdit режима.

        Для FreeForm режима делегирует render().

        Args:
            document: Документ для отображения.
        """
        self.render(document)

    def get_editor_state(self) -> dict[str, Any]:
        """Возвращает текущее состояние редактора.

        Returns:
            Словарь с состоянием FreeForm редактора.
        """
        return {
            "mode": DocumentMode.FREE_FORM.value,
            "cpi": self._cpi,
            "command_stack_size": len(self._command_stack) if self._command_stack else 0,
        }


__all__: list[str] = [
    "FreeFormModeRenderer",
    "DOUBLE_HEIGHT_TAG",
    "ROW_MARKER_TAG",
    "SHADOW_ROW_BG_COLOR",
    "DOUBLE_HEIGHT_MARKER",
    "INVALID_CHAR_TAG",
]
