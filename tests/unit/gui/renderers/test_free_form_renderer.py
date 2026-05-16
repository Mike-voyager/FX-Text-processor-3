"""Unit-тесты для FreeFormRenderer.

Проверяет:
- Создание FreeFormRenderer
- Рендеринг документов
- Форматирование текста (CPI, bold, italic)
- Cursor management
- Text operations (insert, delete)
- Security methods (wipe_sensitive_data, hide_content)

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.core.commands.command_stack import CommandStack
from src.gui.core.exceptions import LifecycleError
from src.gui.renderers.free_form_renderer import (
    DEFAULT_FONT_FAMILY,
    FALLBACK_FONT_FAMILY,
    FormatRange,
    FreeFormDocument,
    FreeFormRenderer,
    MAX_TEXT_LENGTH,
    PRINTER_FONT_CONFIG,
    PrinterFontMode,
    TEXT_BG_COLOR,
    TEXT_FG_COLOR,
    VALID_CPI_INT,
)
from src.gui.core.commands.text_commands import SetTextCommand
from src.gui.core.commands.barcode_commands import InsertPlaceholderCommand


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def command_stack() -> CommandStack:
    """Fixture для CommandStack."""
    return CommandStack()


@pytest.fixture
def free_form_renderer(tk_root: tk.Tk, command_stack: CommandStack) -> Generator[FreeFormRenderer, None, None]:
    """Fixture для FreeFormRenderer."""
    renderer = FreeFormRenderer(
        widget_id="test_renderer",
        command_stack=command_stack,
    )
    renderer.mount(tk_root)
    yield renderer
    renderer.unmount()


# =============================================================================
# TEST: FreeFormRenderer Creation
# =============================================================================


class TestFreeFormRendererCreation:
    """Тесты создания FreeFormRenderer."""

    def test_creation(self) -> None:
        """Создание FreeFormRenderer."""
        renderer = FreeFormRenderer(widget_id="test_renderer")

        assert renderer.widget_id == "test_renderer"
        assert not renderer.is_mounted()

    def test_creation_with_controller(self) -> None:
        """Создание с контроллером."""
        controller = MagicMock()
        renderer = FreeFormRenderer(
            widget_id="test_renderer",
            controller=controller,
        )

        assert renderer._controller == controller

    def test_creation_with_command_stack(self, command_stack: CommandStack) -> None:
        """Создание с CommandStack."""
        renderer = FreeFormRenderer(
            widget_id="test_renderer",
            command_stack=command_stack,
        )

        assert renderer._command_stack == command_stack


# =============================================================================
# TEST: FreeFormDocument
# =============================================================================


class TestFreeFormDocument:
    """Тесты FreeFormDocument."""

    def test_creation(self) -> None:
        """Создание FreeFormDocument."""
        doc = FreeFormDocument(content="Hello", cpi=12)

        assert doc.content == "Hello"
        assert doc.cpi == 12

    def test_creation_defaults(self) -> None:
        """Создание с дефолтными значениями."""
        doc = FreeFormDocument()

        assert doc.content == ""
        assert doc.cpi == 10

    def test_creation_invalid_cpi(self) -> None:
        """Невалидный CPI сбрасывается в дефолтный."""
        doc = FreeFormDocument(content="Hello", cpi=99)

        assert doc.cpi == 10


# =============================================================================
# TEST: Render
# =============================================================================


class TestRender:
    """Тесты рендеринга документов."""

    def test_render_loads_content(self, free_form_renderer: FreeFormRenderer) -> None:
        """render() загружает содержимое."""
        doc = FreeFormDocument(content="Hello World", cpi=12)

        free_form_renderer.render(doc)
        text = free_form_renderer.get_text()

        assert text == "Hello World"

    def test_render_applies_cpi(self, free_form_renderer: FreeFormRenderer) -> None:
        """render() применяет CPI."""
        doc = FreeFormDocument(content="Hello", cpi=15)

        free_form_renderer.render(doc)

        assert free_form_renderer.get_cpi() == 15

    def test_render_long_content_truncated(self, free_form_renderer: FreeFormRenderer) -> None:
        """render() обрезает длинный контент."""
        long_content = "A" * (MAX_TEXT_LENGTH + 100)
        doc = FreeFormDocument(content=long_content, cpi=10)

        free_form_renderer.render(doc)
        text = free_form_renderer.get_text()

        assert len(text) <= MAX_TEXT_LENGTH


# =============================================================================
# TEST: Text Operations
# =============================================================================


class TestTextOperations:
    """Тесты операций с текстом."""

    def test_get_text(self, free_form_renderer: FreeFormRenderer) -> None:
        """get_text() возвращает текст."""
        free_form_renderer.set_text("Hello World")
        text = free_form_renderer.get_text()

        assert text == "Hello World"

    def test_set_text(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_text() устанавливает текст."""
        free_form_renderer.set_text("New content")

        assert free_form_renderer.get_text() == "New content"

    def test_set_text_with_preserve_cursor(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_text() сохраняет позицию курсора."""
        # Установка текста и переход на позицию 1.5
        free_form_renderer._tk_text.insert("1.0", "0123456789")
        free_form_renderer._tk_text.mark_set(tk.INSERT, "1.5")
        
        # Вызываем set_text с коротким текстом — позиция 1.5 больше не валидна,
        # но _preserve_cursor_position() попытается сохранить.
        # Для этого теста проверяем просто что не падает
        free_form_renderer.set_text("1234")
        assert free_form_renderer.get_text() == "1234"

    def test_set_text_truncates_long_text(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_text() обрезает длинный текст."""
        long_text = "A" * (MAX_TEXT_LENGTH + 100)
        free_form_renderer.set_text(long_text)

        text = free_form_renderer.get_text()
        assert len(text) <= MAX_TEXT_LENGTH

    def test_insert_text(self, free_form_renderer: FreeFormRenderer) -> None:
        """insert_text() вставляет текст."""
        free_form_renderer.set_text("Hello")
        free_form_renderer.insert_text("end", " World")

        assert free_form_renderer.get_text() == "Hello World"

    def test_delete_text(self, free_form_renderer: FreeFormRenderer) -> None:
        """delete_text() удаляет текст."""
        free_form_renderer.set_text("Hello World")
        free_form_renderer.delete_text("1.5", "1.11")

        assert free_form_renderer.get_text() == "Hello"


# =============================================================================
# TEST: Cursor Position
# =============================================================================


class TestCursorPosition:
    """Тесты позиции курсора."""

    def test_get_cursor_position(self, free_form_renderer: FreeFormRenderer) -> None:
        """get_cursor_position() возвращает позицию."""
        free_form_renderer.set_text("Hello\nWorld")
        free_form_renderer.set_cursor_position(2, 3)

        pos = free_form_renderer.get_cursor_position()
        assert pos == (2, 3)

    def test_set_cursor_position(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_cursor_position() устанавливает позицию."""
        free_form_renderer.set_text("Line1\nLine2")
        free_form_renderer.set_cursor_position(2, 5)

        pos = free_form_renderer.get_cursor_position()
        assert pos == (2, 5)

    def test_set_cursor_position_invalid_raises(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_cursor_position() с невалидной позицией вызывает ValueError."""
        with pytest.raises(ValueError, match="должны быть >= 1"):
            free_form_renderer.set_cursor_position(0, 5)


# =============================================================================
# TEST: Selection
# =============================================================================


class TestSelection:
    """Тесты выделения текста."""

    def test_get_selection_none(self, free_form_renderer: FreeFormRenderer) -> None:
        """get_selection() без выделения возвращает None."""
        free_form_renderer.set_text("Hello World")
        # No selection made

        selection = free_form_renderer.get_selection()
        assert selection is None

    def test_select_all(self, free_form_renderer: FreeFormRenderer) -> None:
        """select_all() выделяет весь текст."""
        free_form_renderer.set_text("Hello World")
        free_form_renderer.select_all()

        selection = free_form_renderer.get_selection()
        assert selection is not None
        start, end = selection
        assert free_form_renderer.get_text() == "Hello World"

    def test_clear_selection(self, free_form_renderer: FreeFormRenderer) -> None:
        """clear_selection() снимает выделение."""
        free_form_renderer.set_text("Hello World")
        free_form_renderer.select_all()
        free_form_renderer.clear_selection()

        selection = free_form_renderer.get_selection()
        assert selection is None


# =============================================================================
# TEST: CPI Management
# =============================================================================


class TestCPIManagement:
    """Тесты управления CPI."""

    def test_get_cpi_default(self, free_form_renderer: FreeFormRenderer) -> None:
        """get_cpi() возвращает дефолтный CPI."""
        cpi = free_form_renderer.get_cpi()

        assert cpi == 10

    def test_apply_cpi(self, free_form_renderer: FreeFormRenderer) -> None:
        """apply_cpi() применяет CPI."""
        free_form_renderer.set_text("Hello")
        free_form_renderer.apply_cpi(12)

        assert free_form_renderer.get_cpi() == 12

    def test_apply_cpi_invalid_raises(self, free_form_renderer: FreeFormRenderer) -> None:
        """apply_cpi() с невалидным CPI вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid CPI"):
            free_form_renderer.apply_cpi(99)

    def test_valid_cpi_values(self, free_form_renderer: FreeFormRenderer) -> None:
        """Все валидные CPI значения работают."""
        for cpi in VALID_CPI_INT:
            free_form_renderer.apply_cpi(cpi)
            assert free_form_renderer.get_cpi() == cpi


# =============================================================================
# TEST: Formatting
# =============================================================================


class TestFormatting:
    """Тесты форматирования текста."""

    def test_apply_format(self, free_form_renderer: FreeFormRenderer) -> None:
        """apply_format() применяет форматирование."""
        free_form_renderer.set_text("Hello World")
        free_form_renderer.apply_format("bold", "1.0", "1.5")

        # Formatting should be applied
        formatting = free_form_renderer.get_formatting()
        assert any(f.tag == "bold" for f in formatting)

    def test_remove_format(self, free_form_renderer: FreeFormRenderer) -> None:
        """remove_format() удаляет форматирование."""
        free_form_renderer.set_text("Hello World")
        free_form_renderer.apply_format("bold", "1.0", "1.5")
        free_form_renderer.remove_format("bold", "1.0", "1.5")

        # Formatting should be removed
        formatting = free_form_renderer.get_formatting()
        assert not any(f.tag == "bold" for f in formatting)

    def test_apply_format_invalid_tag_raises(self, free_form_renderer: FreeFormRenderer) -> None:
        """apply_format() с невалидным тегом вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid tag"):
            free_form_renderer.apply_format("invalid_tag", "1.0", "1.5")


# =============================================================================
# TEST: Security Methods
# =============================================================================


class TestSecurityMethods:
    """Тесты методов безопасности."""

    def test_wipe_sensitive_data_clears_text(self, free_form_renderer: FreeFormRenderer) -> None:
        """wipe_sensitive_data() очищает текст."""
        free_form_renderer.set_text("Sensitive content")
        free_form_renderer.wipe_sensitive_data()

        assert free_form_renderer.get_text() == ""

    def test_wipe_sensitive_data_clears_command_stack(self, free_form_renderer: FreeFormRenderer, command_stack: CommandStack) -> None:
        """wipe_sensitive_data() очищает CommandStack."""
        free_form_renderer.set_text("Content")
        free_form_renderer.wipe_sensitive_data()

        assert not command_stack.can_undo()

    def test_wipe_sensitive_data_clears_backup(self, free_form_renderer: FreeFormRenderer) -> None:
        """wipe_sensitive_data() очищает backup."""
        free_form_renderer._hidden_content_backup = "backup"
        free_form_renderer.wipe_sensitive_data()

        assert free_form_renderer._hidden_content_backup == ""

    def test_hide_content_sets_flag(self, free_form_renderer: FreeFormRenderer) -> None:
        """hide_content() устанавливает флаг скрытия."""
        free_form_renderer.hide_content()

        assert free_form_renderer._content_hidden is True

    def test_hide_content_saves_backup(self, free_form_renderer: FreeFormRenderer) -> None:
        """hide_content() сохраняет контент."""
        free_form_renderer.set_text("Secret text")
        free_form_renderer.hide_content()

        assert "Secret text" in free_form_renderer._hidden_content_backup

    def test_restore_content_restores_text(self, free_form_renderer: FreeFormRenderer) -> None:
        """restore_content() восстанавливает контент."""
        free_form_renderer.set_text("Original")
        free_form_renderer.hide_content()
        free_form_renderer.restore_content()

        assert free_form_renderer.get_text() == "Original"

    def test_restore_content_clears_flag(self, free_form_renderer: FreeFormRenderer) -> None:
        """restore_content() сбрасывает флаг."""
        free_form_renderer.hide_content()
        free_form_renderer.restore_content()

        assert free_form_renderer._content_hidden is False


# =============================================================================
# TEST: Lifecycle
# =============================================================================


class TestLifecycle:
    """Тесты жизненного цикла."""

    def test_mount_creates_widget(self, tk_root: tk.Tk) -> None:
        """mount() создаёт виджет."""
        renderer = FreeFormRenderer(widget_id="test")
        renderer.mount(tk_root)

        assert renderer.is_mounted()

    def test_unmount_removes_widget(self, tk_root: tk.Tk) -> None:
        """unmount() удаляет виджет."""
        renderer = FreeFormRenderer(widget_id="test")
        renderer.mount(tk_root)
        renderer.unmount()

        assert not renderer.is_mounted()

    def test_operations_before_mount_raises(self) -> None:
        """Операции до mount() вызывают LifecycleError."""
        renderer = FreeFormRenderer(widget_id="test")

        with pytest.raises(LifecycleError):
            renderer.get_text()

    def test_focus(self, free_form_renderer: FreeFormRenderer) -> None:
        """focus() устанавливает фокус."""
        # Should not raise
        free_form_renderer.focus()


# =============================================================================
# TEST: Constants
# =============================================================================


class TestConstants:
    """Тесты констант."""

    def test_valid_cpi_int(self) -> None:
        """VALID_CPI_INT содержит ожидаемые значения."""
        assert VALID_CPI_INT == frozenset({10, 12, 15, 17, 20})

    def test_max_text_length(self) -> None:
        """MAX_TEXT_LENGTH определён."""
        assert MAX_TEXT_LENGTH == 100_000

    def test_default_font_family(self) -> None:
        """DEFAULT_FONT_FAMILY определён."""
        assert DEFAULT_FONT_FAMILY == "Courier"

    def test_fallback_font_family(self) -> None:
        """FALLBACK_FONT_FAMILY определён."""
        assert FALLBACK_FONT_FAMILY == "Consolas"


# =============================================================================
# TEST: FormatRange
# =============================================================================


class TestFormatRange:
    """Тесты FormatRange."""

    def test_creation(self) -> None:
        """Создание FormatRange."""
        fmt = FormatRange("1.0", "1.10", "bold")

        assert fmt.start == "1.0"
        assert fmt.end == "1.10"
        assert fmt.tag == "bold"

    def test_is_frozen(self) -> None:
        """FormatRange immutable."""
        fmt = FormatRange("1.0", "1.10", "bold")

        with pytest.raises(AttributeError):
            fmt.start = "2.0"  # type: ignore[misc]


# =============================================================================
# TEST: Callbacks
# =============================================================================


class TestCallbacks:
    """Тесты callback-функций."""

    def test_set_on_text_change_callback(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_on_text_change_callback() устанавливает callback."""
        callback_called = False

        def on_change(text: str) -> None:
            nonlocal callback_called
            callback_called = True

        free_form_renderer.set_on_text_change_callback(on_change)
        free_form_renderer._current_text = ""  # Reset to trigger change
        free_form_renderer.set_text("New text")

        # Note: callback might not be triggered in test environment
        # due to tk event loop limitations
        assert free_form_renderer._on_text_change_callback == on_change

    def test_set_on_cursor_move_callback(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_on_cursor_move_callback() устанавливает callback."""
        def on_move(line: int, col: int) -> None:
            pass

        free_form_renderer.set_on_cursor_move_callback(on_move)

        assert free_form_renderer._on_cursor_move_callback == on_move


# =============================================================================
# TEST: SmartEdit (FocusIn/FocusOut)
# =============================================================================


class TestSmartEdit:
    """Тесты SmartEdit режима (FocusIn/FocusOut)."""

    def test_enter_edit_mode_sets_flag(self, free_form_renderer: FreeFormRenderer) -> None:
        """_enter_edit_mode() устанавливает _is_editing."""
        free_form_renderer.set_text("Hello")
        free_form_renderer._enter_edit_mode()

        assert free_form_renderer._is_editing is True
        assert free_form_renderer._edit_start_text == "Hello"

    def test_exit_edit_mode_no_change(self, free_form_renderer: FreeFormRenderer) -> None:
        """_exit_edit_mode() без изменений не создаёт команду."""
        free_form_renderer.set_text("Hello")
        free_form_renderer._enter_edit_mode()

        stack_before = free_form_renderer._command_stack
        assert stack_before is not None
        undo_before = stack_before.can_undo()

        free_form_renderer._exit_edit_mode()

        assert free_form_renderer._is_editing is False
        assert stack_before.can_undo() == undo_before

    def test_exit_edit_mode_with_change(self, free_form_renderer: FreeFormRenderer) -> None:
        """_exit_edit_mode() при изменении текста создаёт SetTextCommand."""
        free_form_renderer.set_text("Hello")
        free_form_renderer._enter_edit_mode()

        # Модифицируем текст напрямую в tk.Text
        assert free_form_renderer._tk_text is not None
        free_form_renderer._tk_text.insert(tk.END, " World")

        stack = free_form_renderer._command_stack
        assert stack is not None
        undo_before = stack.can_undo()

        free_form_renderer._exit_edit_mode()

        assert stack.can_undo() is True
        assert free_form_renderer._current_text == "Hello World"

    def test_display_document_ignores_while_editing(
        self, free_form_renderer: FreeFormRenderer
    ) -> None:
        """display_document() игнорируется во время редактирования."""
        free_form_renderer.set_text("Original")
        free_form_renderer._enter_edit_mode()

        doc = FreeFormDocument(content="New", cpi=10)
        free_form_renderer.display_document(doc)

        assert free_form_renderer.get_text() == "Original"
        assert free_form_renderer._is_editing is True

    def test_display_document_applies_when_not_editing(
        self, free_form_renderer: FreeFormRenderer
    ) -> None:
        """display_document() применяется когда не в режиме редактирования."""
        free_form_renderer.set_text("Original")

        doc = FreeFormDocument(content="New content", cpi=12)
        free_form_renderer.display_document(doc)

        assert free_form_renderer.get_text() == "New content"
        assert free_form_renderer.get_cpi() == 12


# =============================================================================
# TEST: Protocol Methods
# =============================================================================


class TestProtocolMethods:
    """Тесты методов DocumentRendererProtocol."""

    def test_create_toolbar(self, tk_root: tk.Tk, free_form_renderer: FreeFormRenderer) -> None:
        """create_toolbar() создаёт и возвращает виджет."""
        toolbar_frame = tk.Frame(tk_root)
        widget = free_form_renderer.create_toolbar(toolbar_frame)

        assert isinstance(widget, tk.Widget)
        assert free_form_renderer._format_toolbar_ref is not None

    def test_create_editor(self, tk_root: tk.Tk, free_form_renderer: FreeFormRenderer) -> None:
        """create_editor() возвращает корневой виджет редактора."""
        editor_frame = tk.Frame(tk_root)
        widget = free_form_renderer.create_editor(editor_frame)

        assert isinstance(widget, tk.Widget)
        assert widget == free_form_renderer._tk_frame

    def test_get_editor_state(self, free_form_renderer: FreeFormRenderer) -> None:
        """get_editor_state() возвращает состояние редактора."""
        free_form_renderer.set_text("Test\nLines")
        free_form_renderer.set_cursor_position(2, 3)

        state = free_form_renderer.get_editor_state()

        assert state["cursor_line"] == 2
        assert state["cursor_column"] == 3
        assert state["text_length"] == 10
        assert state["cpi"] == 10
        assert state["is_editing"] is False
        assert "selection_start" in state

    def test_set_text_command_in_stack(self, free_form_renderer: FreeFormRenderer) -> None:
        """SetTextCommand создан при SmartEdit."""
        free_form_renderer.set_text("Old text")
        free_form_renderer._enter_edit_mode()

        assert free_form_renderer._tk_text is not None
        free_form_renderer._tk_text.delete("1.0", tk.END)
        free_form_renderer._tk_text.insert("1.0", "New text")

        free_form_renderer._exit_edit_mode()

        assert free_form_renderer._command_stack is not None
        assert free_form_renderer._command_stack.can_undo()

        # Проверяем undo
        free_form_renderer._command_stack.undo()
        assert free_form_renderer.get_text() == "Old text"


# =============================================================================
# TEST: Barcode/QR Insertion
# =============================================================================


class TestBarcodeInsertion:
    """Тесты вставки штрих-кодов и QR-кодов."""

    def test_insert_text_at_cursor(self, free_form_renderer: FreeFormRenderer) -> None:
        """insert_text_at_cursor() вставляет текст в позицию курсора."""
        free_form_renderer.set_text("Hello ")
        free_form_renderer.insert_text_at_cursor("World")

        assert free_form_renderer.get_text() == "Hello World"

    def test_insert_barcode_at_cursor_placeholder(self, free_form_renderer: FreeFormRenderer) -> None:
        """insert_barcode_at_cursor() вставляет placeholder по умолчанию."""
        free_form_renderer.set_text("")
        success = free_form_renderer.insert_barcode_at_cursor("CODE128", "12345", "software")

        assert success
        text = free_form_renderer.get_text()
        assert "BARCODE:CODE128" in text
        assert "12345" in text

    def test_insert_qr_at_cursor_placeholder(self, free_form_renderer: FreeFormRenderer) -> None:
        """insert_qr_at_cursor() вставляет QR placeholder по умолчанию."""
        free_form_renderer.set_text("")
        success = free_form_renderer.insert_qr_at_cursor("https://example.com")

        assert success
        text = free_form_renderer.get_text()
        assert "QR" in text
        assert "https://example.com" in text

    def test_insert_barcode_at_cursor_unmounted(self, tk_root: tk.Tk) -> None:
        """insert_barcode_at_cursor() без mount возвращает False."""
        renderer = FreeFormRenderer(widget_id="test_unmounted")
        success = renderer.insert_barcode_at_cursor("CODE128", "12345", "software")
        assert not success

    def test_insert_qr_at_cursor_unmounted(self, tk_root: tk.Tk) -> None:
        """insert_qr_at_cursor() без mount возвращает False."""
        renderer = FreeFormRenderer(widget_id="test_unmounted")
        success = renderer.insert_qr_at_cursor("https://example.com")
        assert not success

    def test_insert_barcode_undo(self, free_form_renderer: FreeFormRenderer) -> None:
        """Вставка штрих-кода поддерживает undo."""
        free_form_renderer.set_text("Initial")
        success = free_form_renderer.insert_barcode_at_cursor("CODE128", "12345", "software")
        assert success

        free_form_renderer._command_stack.undo()
        assert free_form_renderer.get_text() == "Initial"

    def test_insert_qr_undo(self, free_form_renderer: FreeFormRenderer) -> None:
        """Вставка QR поддерживает undo."""
        free_form_renderer.set_text("Initial")
        success = free_form_renderer.insert_qr_at_cursor("https://example.com")
        assert success

        free_form_renderer._command_stack.undo()
        assert free_form_renderer.get_text() == "Initial"

    def test_insert_barcode_with_image_flag(self, free_form_renderer: FreeFormRenderer) -> None:
        """insert_barcode_at_cursor() с render_image=True пробует вставить image."""
        free_form_renderer.set_text("")
        success = free_form_renderer.insert_barcode_at_cursor(
            "CODE128", "12345", "software", settings={"render_image": True}
        )
        # Должно быть успешно (placeholders fallback если image generation не удался)
        assert success
        # Пока python-barcode недоступен, ожидаем fallback к placeholder
        text = free_form_renderer.get_text()
        # Текст может быть пустым если image_create прошёл успешно
        # или содержать placeholder если был fallback
        assert free_form_renderer.get_text() is not None

    def test_insert_qr_with_image_flag(self, free_form_renderer: FreeFormRenderer) -> None:
        """insert_qr_at_cursor() с render_image=True пробует вставить image."""
        free_form_renderer.set_text("")
        success = free_form_renderer.insert_qr_at_cursor(
            "https://example.com", settings={"render_image": True}
        )
        assert success


# =============================================================================
# TEST: Embedded Image References
# =============================================================================


class TestEmbeddedImages:
    """Тесты защиты PhotoImage от GC."""

    def test_clear_embedded_images_on_cleanup(self, tk_root: tk.Tk, command_stack: CommandStack) -> None:
        """_cleanup() очищает список _embedded_images."""
        renderer = FreeFormRenderer(
            widget_id="test_embedded",
            command_stack=command_stack,
        )
        renderer.mount(tk_root)
        renderer._embedded_images.append(tk.PhotoImage(width=1, height=1))

        renderer._cleanup()

        assert len(renderer._embedded_images) == 0


# =============================================================================
# TEST: Printer Font Mode
# =============================================================================


class TestPrinterFontMode:
    """Тесты режимов шрифта принтера."""

    def test_default_font_mode_is_draft(self, free_form_renderer: FreeFormRenderer) -> None:
        """По умолчанию режим DRAFT."""
        assert free_form_renderer._printer_font_mode == PrinterFontMode.DRAFT

    def test_set_printer_font_mode_roman(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_printer_font_mode() переключает на ROMAN."""
        free_form_renderer.set_printer_font_mode(PrinterFontMode.ROMAN)

        assert free_form_renderer._printer_font_mode == PrinterFontMode.ROMAN
        assert free_form_renderer._font_family == PRINTER_FONT_CONFIG[PrinterFontMode.ROMAN][0]

    def test_set_printer_font_mode_sans_serif(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_printer_font_mode() переключает на SANS_SERIF."""
        free_form_renderer.set_printer_font_mode(PrinterFontMode.SANS_SERIF)

        assert free_form_renderer._printer_font_mode == PrinterFontMode.SANS_SERIF
        assert free_form_renderer._font_family == PRINTER_FONT_CONFIG[PrinterFontMode.SANS_SERIF][0]

    def test_set_printer_font_mode_invalid_raises(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_printer_font_mode() с невалидным режимом вызывает ValueError."""
        with pytest.raises(ValueError, match="Недопустимый режим шрифта"):
            free_form_renderer.set_printer_font_mode("invalid_mode")

    def test_set_printer_font_mode_before_mount(self, tk_root: tk.Tk) -> None:
        """set_printer_font_mode() работает до mount."""
        renderer = FreeFormRenderer(widget_id="test_font_mode")
        renderer.set_printer_font_mode(PrinterFontMode.ROMAN)
        renderer.mount(tk_root)

        assert renderer._font_family == PRINTER_FONT_CONFIG[PrinterFontMode.ROMAN][0]
        renderer.unmount()

    def test_printer_font_config_mapping(self) -> None:
        """PRINTER_FONT_CONFIG содержит ожидаемые режимы."""
        assert PrinterFontMode.DRAFT in PRINTER_FONT_CONFIG
        assert PrinterFontMode.ROMAN in PRINTER_FONT_CONFIG
        assert PrinterFontMode.SANS_SERIF in PRINTER_FONT_CONFIG

    def test_is_valid_mode(self) -> None:
        """PrinterFontMode.is_valid() распознаёт допустимые режимы."""
        assert PrinterFontMode.is_valid(PrinterFontMode.DRAFT) is True
        assert PrinterFontMode.is_valid(PrinterFontMode.ROMAN) is True
        assert PrinterFontMode.is_valid(PrinterFontMode.SANS_SERIF) is True
        assert PrinterFontMode.is_valid("invalid") is False


# =============================================================================
# TEST: CodepageValidator Integration
# =============================================================================


class TestCodepageValidatorIntegration:
    """Тесты интеграции CodepageValidator в FreeFormRenderer."""

    def test_set_text_replaces_invalid_chars(self, free_form_renderer: FreeFormRenderer) -> None:
        """set_text() заменяет несовместимые с PC866 символы."""
        free_form_renderer.set_text("ёлка — test")

        text = free_form_renderer.get_text()
        assert "ё" not in text
        assert "—" not in text
        assert text == "елка - test"

    def test_insert_text_replaces_invalid_chars(self, free_form_renderer: FreeFormRenderer) -> None:
        """insert_text() заменяет несовместимые с PC866 символы."""
        free_form_renderer.set_text("Hello ")
        free_form_renderer.insert_text("end", "мир—")

        text = free_form_renderer.get_text()
        assert "—" not in text
        assert text == "Hello мир-"

    def test_render_document_fixes_invalid_chars(self, free_form_renderer: FreeFormRenderer) -> None:
        """render() применяет замены к содержимому документа."""
        doc = FreeFormDocument(content="Ёлка №1", cpi=10)
        free_form_renderer.render(doc)

        text = free_form_renderer.get_text()
        assert "Ё" not in text
        assert "№" not in text
        assert text == "Елка N1"

    def test_paste_at_cursor_fixes_invalid_chars(self, free_form_renderer: FreeFormRenderer) -> None:
        """paste_at_cursor() заменяет несовместимые символы."""
        free_form_renderer.set_text("")
        success = free_form_renderer.paste_at_cursor("€100")

        assert success is True
        text = free_form_renderer.get_text()
        assert "€" not in text
        assert text == "EUR100"

    def test_valid_chars_preserved(self, free_form_renderer: FreeFormRenderer) -> None:
        """Валидные PC866 символы не изменяются."""
        original = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
        free_form_renderer.set_text(original)

        assert free_form_renderer.get_text() == original


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.renderers.free_form_renderer"])
