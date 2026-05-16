"""Тесты для PrintDialog и PrintPreviewDialog.

Модуль проверяет создание диалогов, логику фильтрации принтеров,
возврат результатов и интеграцию с ESCPPreviewWidget.

Version: 1.0
"""

from __future__ import annotations

import tkinter as tk
from typing import Generator
from unittest.mock import Mock

import pytest

# Skip all tests if no display available
try:
    import tkinter as tk_test

    root_test = tk_test.Tk()
    root_test.withdraw()
    HAS_DISPLAY = True
    root_test.destroy()
except (RuntimeError, AttributeError, ImportError, OSError):
    HAS_DISPLAY = False


pytestmark = [
    pytest.mark.skipif(not HAS_DISPLAY, reason="No display available"),
    pytest.mark.gui,
]

from src.gui.dialogs.print_dialog import PrintDialog
from src.gui.dialogs.print_preview_dialog import PrintPreviewDialog
from src.gui.dialogs.print_settings import PrintDialogResult
from src.model.document import Document, DocumentMetadata
from src.printer.printer_manager import PrinterInfo
from src.services.print_queue_service import PrintPriority

# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Фикстура для создания корневого окна tkinter."""
    root = tk.Tk()
    root.withdraw()
    yield root
    try:
        root.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def sample_document() -> Document:
    """Фикстура для создания тестового документа."""
    metadata = DocumentMetadata(title="Test Document")
    doc = Document(metadata=metadata)
    doc.set_text_content("Test content")
    return doc


@pytest.fixture
def mock_printer_manager() -> Mock:
    """Фикстура для создания mock PrinterManager."""
    pm = Mock()
    pm.get_available_printers.return_value = [
        PrinterInfo(
            printer_id="cups:FX-890",
            name="FX-890 (CUPS)",
            adapter_type="cups",
            is_default=True,
        ),
        PrinterInfo(
            printer_id="win32:PDF",
            name="Microsoft Print to PDF",
            adapter_type="win32",
            is_default=False,
        ),
        PrinterInfo(
            printer_id="file:output",
            name="File Output",
            adapter_type="file",
            is_default=False,
        ),
    ]
    pm.get_available_adapters.return_value = ["cups", "win32", "file"]
    pm.get_best_printer.return_value = "cups:FX-890"
    return pm


@pytest.fixture
def mock_document_renderer() -> Mock:
    """Фикстура для создания mock DocumentRenderer."""
    renderer = Mock()
    renderer.render.return_value = b"\x1b@Test ESC/P data\x0c"
    renderer.render_page.return_value = b"\x1b@Test ESC/P data\x0c"
    renderer.get_page_count.return_value = 1
    return renderer


@pytest.fixture
def mock_print_queue() -> Mock:
    """Фикстура для создания mock PrintQueueService."""
    queue = Mock()
    return queue


# ---------------------------------------------------------------------------
# PrintDialog
# ---------------------------------------------------------------------------


class TestPrintDialog:
    """Тесты для PrintDialog."""

    def test_dialog_creation(
        self,
        tk_root: tk.Tk,
        mock_printer_manager: Mock,
        sample_document: Document,
        mock_document_renderer: Mock,
        mock_print_queue: Mock,
    ) -> None:
        """Проверяет создание диалога и наличие вкладок."""
        dialog = PrintDialog(
            parent=tk_root,
            printer_manager=mock_printer_manager,
            document=sample_document,
            document_renderer=mock_document_renderer,
            print_queue=mock_print_queue,
            theme="classic_green",
        )
        assert dialog.title() == "Print"
        tabs = dialog.notebook.tabs()
        assert len(tabs) == 4
        dialog.destroy()

    def test_printer_list_populated_on_init(
        self,
        tk_root: tk.Tk,
        mock_printer_manager: Mock,
        sample_document: Document,
        mock_document_renderer: Mock,
        mock_print_queue: Mock,
    ) -> None:
        """Проверяет, что список принтеров заполняется при инициализации."""
        dialog = PrintDialog(
            parent=tk_root,
            printer_manager=mock_printer_manager,
            document=sample_document,
            document_renderer=mock_document_renderer,
            print_queue=mock_print_queue,
        )
        assert mock_printer_manager.get_available_printers.called
        dialog.destroy()

    def test_adapter_filter_updates_printer_list(
        self,
        tk_root: tk.Tk,
        mock_printer_manager: Mock,
        sample_document: Document,
        mock_document_renderer: Mock,
        mock_print_queue: Mock,
    ) -> None:
        """Проверяет фильтрацию принтеров по адаптеру."""
        dialog = PrintDialog(
            parent=tk_root,
            printer_manager=mock_printer_manager,
            document=sample_document,
            document_renderer=mock_document_renderer,
            print_queue=mock_print_queue,
        )
        # Переключаем на адаптер cups
        dialog._settings_vars["adapter"].set("cups")
        dialog._update_printer_list()

        values = dialog.printer_combo["values"]
        assert "FX-890 (CUPS)" in values
        assert "Microsoft Print to PDF" not in values
        assert "File Output" not in values
        dialog.destroy()

    def test_all_adapters_filter(
        self,
        tk_root: tk.Tk,
        mock_printer_manager: Mock,
        sample_document: Document,
        mock_document_renderer: Mock,
        mock_print_queue: Mock,
    ) -> None:
        """Проверяет, что фильтр 'Все' показывает все принтеры."""
        dialog = PrintDialog(
            parent=tk_root,
            printer_manager=mock_printer_manager,
            document=sample_document,
            document_renderer=mock_document_renderer,
            print_queue=mock_print_queue,
        )
        dialog._settings_vars["adapter"].set("All")
        dialog._update_printer_list()

        values = dialog.printer_combo["values"]
        assert len(values) == 3
        assert "FX-890 (CUPS)" in values
        assert "Microsoft Print to PDF" in values
        assert "File Output" in values
        dialog.destroy()

    def test_print_result_contains_correct_settings(
        self,
        tk_root: tk.Tk,
        mock_printer_manager: Mock,
        sample_document: Document,
        mock_document_renderer: Mock,
        mock_print_queue: Mock,
    ) -> None:
        """Проверяет, что нажатие 'Печать' возвращает корректный PrintDialogResult."""
        dialog = PrintDialog(
            parent=tk_root,
            printer_manager=mock_printer_manager,
            document=sample_document,
            document_renderer=mock_document_renderer,
            print_queue=mock_print_queue,
        )
        # Выбираем принтер и настраиваем параметры
        dialog.printer_combo.set("FX-890 (CUPS)")
        dialog._settings_vars["copies"].set(3)
        dialog._settings_vars["priority"].set("HIGH")
        dialog._settings_vars["page_by_page"].set(True)

        result = dialog._build_result()
        assert isinstance(result, PrintDialogResult)
        assert result.settings.copies == 3
        assert result.settings.priority == PrintPriority.HIGH
        assert result.settings.page_by_page is True
        assert result.settings.printer_id == "cups:FX-890"
        assert result.settings.adapter_id == "All"
        dialog.destroy()

    def test_cancel_returns_none(
        self,
        tk_root: tk.Tk,
        mock_printer_manager: Mock,
        sample_document: Document,
        mock_document_renderer: Mock,
        mock_print_queue: Mock,
    ) -> None:
        """Проверяет, что отмена возвращает None."""
        dialog = PrintDialog(
            parent=tk_root,
            printer_manager=mock_printer_manager,
            document=sample_document,
            document_renderer=mock_document_renderer,
            print_queue=mock_print_queue,
        )
        dialog.close(result=None)
        assert dialog.get_result() is None
        dialog.destroy()

    def test_test_page_flag_set(
        self,
        tk_root: tk.Tk,
        mock_printer_manager: Mock,
        sample_document: Document,
        mock_document_renderer: Mock,
        mock_print_queue: Mock,
    ) -> None:
        """Проверяет установку флага тестовой страницы."""
        dialog = PrintDialog(
            parent=tk_root,
            printer_manager=mock_printer_manager,
            document=sample_document,
            document_renderer=mock_document_renderer,
            print_queue=mock_print_queue,
        )
        dialog.printer_combo.set("FX-890 (CUPS)")
        dialog._settings_vars["print_test_page"].set(True)

        result = dialog._build_result()
        assert result.settings.print_test_page is True
        dialog.destroy()


# ---------------------------------------------------------------------------
# PrintPreviewDialog
# ---------------------------------------------------------------------------


class TestPrintPreviewDialog:
    """Тесты для PrintPreviewDialog."""

    def test_dialog_creation(
        self,
        tk_root: tk.Tk,
        sample_document: Document,
        mock_document_renderer: Mock,
    ) -> None:
        """Проверяет создание диалога предпросмотра."""
        dialog = PrintPreviewDialog(
            parent=tk_root,
            document=sample_document,
            document_renderer=mock_document_renderer,
            theme="classic_green",
        )
        assert dialog.title() == "Print Preview"
        dialog.destroy()

    def test_close_returns_none(
        self,
        tk_root: tk.Tk,
        sample_document: Document,
        mock_document_renderer: Mock,
    ) -> None:
        """Проверяет, что закрытие preview возвращает None."""
        dialog = PrintPreviewDialog(
            parent=tk_root,
            document=sample_document,
            document_renderer=mock_document_renderer,
            theme="classic_green",
        )
        dialog.close(result=None)
        assert dialog.get_result() is None
        dialog.destroy()

    def test_print_button_returns_print(
        self,
        tk_root: tk.Tk,
        sample_document: Document,
        mock_document_renderer: Mock,
    ) -> None:
        """Проверяет, что кнопка 'Печать...' возвращает 'print'."""
        dialog = PrintPreviewDialog(
            parent=tk_root,
            document=sample_document,
            document_renderer=mock_document_renderer,
            theme="classic_green",
        )
        dialog._on_print_clicked()
        assert dialog.get_result() == "print"
        dialog.destroy()
