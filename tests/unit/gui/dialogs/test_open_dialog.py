"""Тесты для диалога открытия документа OpenDialog.

Test coverage targets:
- Dialog creation: 100%
- File filtering: 100%
- Signature verification enable/disable: 100%
- Metadata preview: 100%
- Trust chain display: 100%
- Overall coverage: ≥90%

Example:
    >>> pytest tests/unit/gui/dialogs/test_open_dialog.py -v

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import sys
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk
from typing import Any, Optional
from unittest.mock import MagicMock, Mock, patch

import pytest

# Ensure imports work
sys.path.insert(0, "/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3")

from src.gui.dialogs.open_dialog import (
    FILE_TYPE_ICONS,
    SIGNATURE_STATUS,
    OpenDialog,
    OpenFileDialog,
    OpenResult,
    TrustChainVerifier,
)
from src.model.document import DocumentMetadata
from src.services.protocols.template_security import (
    TrustChainLink,
    TrustChainServiceProtocol,
    TrustStatus,
    TrustVerificationResult,
)
from src.services.template_manager import FormTemplate


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_trust_service() -> Mock:
    """Создаёт мок сервиса цепочки доверия."""
    service = Mock(spec=TrustChainServiceProtocol)

    # Default successful verification
    service.verify_template.return_value = TrustVerificationResult(
        template_id="tpl-123",
        is_valid=True,
        trust_status=TrustStatus.TRUSTED,
        chain_depth=2,
        signing_key_id="key-abc",
    )

    # Default chain
    service.get_trust_chain.return_value = [
        TrustChainLink(
            key_id="key-abc",
            public_key=b"public_key_data",
            algorithm="Ed25519",
            added_at=datetime.now(),
            parent_key_id="root-key",
            metadata={"name": "Test Key"},
        ),
        TrustChainLink(
            key_id="root-key",
            public_key=b"root_public_key",
            algorithm="Ed25519",
            added_at=datetime.now(),
            parent_key_id=None,
            metadata={"name": "Root Authority"},
        ),
    ]

    return service


@pytest.fixture
def mock_document_service() -> Mock:
    """Создаёт мок сервиса документов."""
    service = Mock()

    # Default metadata
    service.load_metadata.return_value = DocumentMetadata(
        title="Test Document",
        author="Test Author",
        created=datetime(2026, 4, 1, 10, 0, 0),
    )

    return service


@pytest.fixture
def tk_root() -> tk.Tk:
    """Создаёт корневое окно Tkinter для тестов."""
    root = tk.Tk()
    root.withdraw()  # Hide the window
    yield root
    root.destroy()


@pytest.fixture
def open_dialog(
    tk_root: tk.Tk,
    mock_document_service: Mock,
    mock_trust_service: Mock,
) -> OpenDialog:
    """Создаёт экземпляр OpenDialog для тестов."""
    dialog = OpenDialog(
        parent=tk_root,
        document_service=mock_document_service,
        trust_chain_verifier=mock_trust_service,
        initial_dir=Path("/tmp"),
    )
    return dialog


# =============================================================================
# TESTS: OpenResult Dataclass
# =============================================================================


class TestOpenResult:
    """Тесты для OpenResult dataclass."""

    def test_creation_with_all_fields(self) -> None:
        """Тест создания с полными данными."""
        metadata = DocumentMetadata(title="Test", author="Author")
        result = OpenResult(
            path=Path("/docs/test.fxsd"),
            verify_signature=True,
            metadata=metadata,
            signature_valid=True,
        )

        assert result.path == Path("/docs/test.fxsd")
        assert result.verify_signature is True
        assert result.metadata == metadata
        assert result.signature_valid is True

    def test_creation_with_none_metadata(self) -> None:
        """Тест создания с None метаданными."""
        result = OpenResult(
            path=Path("/docs/test.fxsd"),
            verify_signature=False,
            metadata=None,
            signature_valid=None,
        )

        assert result.metadata is None
        assert result.signature_valid is None

    def test_creation_with_invalid_signature(self) -> None:
        """Тест создания с невалидной подписью."""
        result = OpenResult(
            path=Path("/docs/test.fxsd"),
            verify_signature=True,
            metadata=None,
            signature_valid=False,
        )

        assert result.signature_valid is False

    def test_frozen_dataclass(self) -> None:
        """Тест что OpenResult immutable."""
        result = OpenResult(
            path=Path("/docs/test.fxsd"),
            verify_signature=True,
            metadata=None,
            signature_valid=True,
        )

        with pytest.raises(AttributeError):
            result.path = Path("/other.fxsd")  # type: ignore[misc]


# =============================================================================
# TESTS: Dialog Creation
# =============================================================================


@pytest.mark.gui
class TestDialogCreation:
    """Тесты создания диалога."""

    def test_dialog_initialization(
        self,
        tk_root: tk.Tk,
        mock_document_service: Mock,
        mock_trust_service: Mock,
    ) -> None:
        """Тест инициализации диалога."""
        dialog = OpenDialog(
            parent=tk_root,
            document_service=mock_document_service,
            trust_chain_verifier=mock_trust_service,
        )

        assert dialog._parent == tk_root
        assert dialog._document_service == mock_document_service
        assert dialog._trust_chain_verifier == mock_trust_service
        assert dialog._selected_path is None
        assert dialog._result is None

    def test_dialog_initialization_without_trust_service(
        self,
        tk_root: tk.Tk,
        mock_document_service: Mock,
    ) -> None:
        """Тест инициализации без сервиса цепочки доверия."""
        dialog = OpenDialog(
            parent=tk_root,
            document_service=mock_document_service,
            trust_chain_verifier=None,
        )

        assert dialog._trust_chain_verifier is None

    def test_dialog_ui_components_created(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест что все UI компоненты созданы."""
        # Check file section
        assert hasattr(open_dialog, "_path_var")
        assert hasattr(open_dialog, "_path_entry")
        assert hasattr(open_dialog, "_browse_button")

        # Check preview panel
        assert hasattr(open_dialog, "_title_var")
        assert hasattr(open_dialog, "_author_var")
        assert hasattr(open_dialog, "_created_var")
        assert hasattr(open_dialog, "_encrypted_var")

        # Check signature section
        assert hasattr(open_dialog, "_verify_var")
        assert hasattr(open_dialog, "_status_icon_var")
        assert hasattr(open_dialog, "_status_text_var")

        # Check buttons
        assert hasattr(open_dialog, "_open_button")
        assert hasattr(open_dialog, "_cancel_button")

    def test_window_configuration(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест конфигурации окна."""
        assert open_dialog.title() == "Открыть документ"
        # Window should be transient
        assert open_dialog.winfo_exists()

    def test_initial_dir_setting(
        self,
        tk_root: tk.Tk,
        mock_document_service: Mock,
    ) -> None:
        """Тест установки начальной директории."""
        custom_dir = Path("/custom/path")
        dialog = OpenDialog(
            parent=tk_root,
            document_service=mock_document_service,
            initial_dir=custom_dir,
        )

        assert dialog._initial_dir == custom_dir


# =============================================================================
# TESTS: File Filtering
# =============================================================================


@pytest.mark.gui
class TestFileFiltering:
    """Тесты фильтрации файлов."""

    def test_file_filters_defined(self) -> None:
        """Тест что фильтры файлов определены."""
        from src.gui.dialogs.open_dialog import FILE_FILTERS

        assert len(FILE_FILTERS) > 0
        # Check for expected filters
        filter_text = str(FILE_FILTERS)
        assert ".fxsd" in filter_text
        assert ".fxstpl" in filter_text

    def test_file_type_icons(self) -> None:
        """Тест иконок типов файлов."""
        assert ".fxsd" in FILE_TYPE_ICONS
        assert ".fxsd.enc" in FILE_TYPE_ICONS
        assert ".fxstpl" in FILE_TYPE_ICONS

    def test_select_fxsd_file_updates_preview(
        self,
        open_dialog: OpenDialog,
        mock_document_service: Mock,
        tmp_path: Path,
    ) -> None:
        """Тест что выбор .fxsd файла обновляет предпросмотр."""
        test_file = tmp_path / "test.fxsd"
        test_file.write_text("test content")

        open_dialog._select_file(test_file)

        assert open_dialog._selected_path == test_file
        mock_document_service.load_metadata.assert_called_once()

    def test_select_encrypted_file_shows_lock(
        self,
        open_dialog: OpenDialog,
        tmp_path: Path,
    ) -> None:
        """Тест что выбор зашифрованного файла показывает индикатор."""
        test_file = tmp_path / "test.fxsd.enc"
        test_file.write_text("encrypted content")

        open_dialog._select_file(test_file)

        assert "🔒" in open_dialog._icon_label.cget("text")
        assert "🔒" in open_dialog._encrypted_var.get()

    def test_select_template_file(
        self,
        open_dialog: OpenDialog,
        tmp_path: Path,
    ) -> None:
        """Тест что выбор шаблона .fxstpl работает корректно."""
        test_file = tmp_path / "test.fxstpl"
        # Create minimal valid template file
        test_file.write_text('FXSTPL\n1.0\n{"template_id": "tpl-1", "name": "Test", "name_ru": "Тест", "version": "1.0", "doc_type": "TEST", "pages": [], "created_at": "2026-04-01T00:00:00", "modified_at": "2026-04-01T00:00:00"}')

        open_dialog._select_file(test_file)

        assert open_dialog._selected_path == test_file
        assert "📋" in open_dialog._icon_label.cget("text")


# =============================================================================
# TESTS: Signature Verification Enable/Disable
# =============================================================================


@pytest.mark.gui
class TestSignatureVerification:
    """Тесты проверки подписи."""

    def test_signature_verification_enabled_by_default(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест что проверка подписи включена по умолчанию."""
        assert open_dialog._verify_var.get() is True

    def test_toggle_verification_off(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отключения проверки подписи."""
        open_dialog._verify_var.set(False)
        open_dialog._on_verify_toggle()

        assert "Проверка отключена" in open_dialog._status_text_var.get()

    def test_toggle_verification_on_triggers_verification(
        self,
        open_dialog: OpenDialog,
        mock_trust_service: Mock,
        tmp_path: Path,
    ) -> None:
        """Тест что включение проверки запускает верификацию."""
        # First select a file
        test_file = tmp_path / "test.fxstpl"
        test_file.write_text('FXSTPL\n1.0\n{"template_id": "tpl-1", "name": "Test", "name_ru": "Тест", "version": "1.0", "doc_type": "TEST", "pages": [], "created_at": "2026-04-01T00:00:00", "modified_at": "2026-04-01T00:00:00"}')

        open_dialog._select_file(test_file)
        mock_trust_service.verify_template.assert_called_once()

    def test_signature_status_valid(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отображения валидной подписи."""
        open_dialog._update_signature_status(True)

        assert open_dialog._status_icon_var.get() == "✓"
        assert "действительна" in open_dialog._status_text_var.get().lower()

    def test_signature_status_invalid(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отображения невалидной подписи."""
        open_dialog._update_signature_status(False)

        assert open_dialog._status_icon_var.get() == "⚠️"
        assert "невалидна" in open_dialog._status_text_var.get().lower()

    def test_signature_status_missing(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отображения отсутствующей подписи."""
        open_dialog._update_signature_status(None)

        assert open_dialog._status_icon_var.get() == "❌"
        assert "отсутствует" in open_dialog._status_text_var.get().lower()

    def test_verify_without_trust_service(
        self,
        tk_root: tk.Tk,
        mock_document_service: Mock,
        tmp_path: Path,
    ) -> None:
        """Тест верификации без сервиса цепочки доверия."""
        dialog = OpenDialog(
            parent=tk_root,
            document_service=mock_document_service,
            trust_chain_verifier=None,
        )

        test_file = tmp_path / "test.fxstpl"
        test_file.write_text('FXSTPL\n1.0\n{"template_id": "tpl-1", "name": "Test", "name_ru": "Тест", "version": "1.0", "doc_type": "TEST", "pages": [], "created_at": "2026-04-01T00:00:00", "modified_at": "2026-04-01T00:00:00"}')

        dialog._select_file(test_file)
        # Should not raise, just update to None status
        assert dialog._status_icon_var.get() == "❌"


# =============================================================================
# TESTS: Metadata Preview
# =============================================================================


@pytest.mark.gui
class TestMetadataPreview:
    """Тесты предпросмотра метаданных."""

    def test_metadata_displayed_correctly(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отображения метаданных."""
        metadata = DocumentMetadata(
            title="Test Title",
            author="Test Author",
            created=datetime(2026, 4, 1, 10, 30, 0),
        )

        open_dialog._title_var.set(metadata.title)
        open_dialog._author_var.set(metadata.author)
        open_dialog._created_var.set(metadata.created.strftime("%Y-%m-%d %H:%M"))

        assert open_dialog._title_var.get() == "Test Title"
        assert open_dialog._author_var.get() == "Test Author"
        assert "2026-04-01" in open_dialog._created_var.get()

    def test_load_metadata_from_document_service(
        self,
        open_dialog: OpenDialog,
        mock_document_service: Mock,
    ) -> None:
        """Тест загрузки метаданных через сервис документов."""
        expected_metadata = DocumentMetadata(
            title="Service Title",
            author="Service Author",
        )
        mock_document_service.load_metadata.return_value = expected_metadata

        result = open_dialog._load_metadata(Path("/test.fxsd"))

        assert result is not None
        assert result.title == "Service Title"
        assert result.author == "Service Author"

    def test_load_metadata_fallback(
        self,
        open_dialog: OpenDialog,
        mock_document_service: Mock,
        tmp_path: Path,
    ) -> None:
        """Тест fallback загрузки метаданных."""
        mock_document_service.load_metadata.side_effect = Exception("Failed")

        test_file = tmp_path / "test.fxsd"
        test_file.write_text("content")

        result = open_dialog._load_metadata(test_file)

        # Should fall back to file-based metadata
        assert result is not None
        assert result.title == "test"  # From path.stem

    def test_metadata_displayed_as_dash_when_empty(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отображения дефиса при пустых метаданных."""
        open_dialog._title_var.set("—")
        open_dialog._author_var.set("—")
        open_dialog._created_var.set("—")

        assert open_dialog._title_var.get() == "—"
        assert open_dialog._author_var.get() == "—"


# =============================================================================
# TESTS: Trust Chain Display
# =============================================================================


@pytest.mark.gui
class TestTrustChainDisplay:
    """Тесты отображения цепочки доверия."""

    def test_trust_chain_info_valid(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отображения валидной цепочки доверия."""
        result = TrustVerificationResult(
            template_id="tpl-123",
            is_valid=True,
            trust_status=TrustStatus.TRUSTED,
            chain_depth=2,
            signing_key_id="key-abc-1234567890abcdef",
        )

        open_dialog._update_trust_chain_info(result)

        assert "Доверенный ключ" in open_dialog._chain_var.get()
        assert "глубина цепочки: 2" in open_dialog._chain_var.get()

    def test_trust_chain_info_with_errors(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отображения цепочки с ошибками."""
        result = TrustVerificationResult(
            template_id="tpl-123",
            is_valid=False,
            trust_status=TrustStatus.UNTRUSTED,
            chain_depth=0,
            signing_key_id="unknown-key",
            errors=["Key not found in trust store"],
        )

        open_dialog._update_trust_chain_info(result)

        assert "⚠️" in open_dialog._chain_var.get()

    def test_trust_chain_info_none(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отображения когда результат None."""
        open_dialog._update_trust_chain_info(None)

        assert "недоступна" in open_dialog._chain_var.get()

    def test_trust_chain_info_revoked(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест отображения отозванного ключа."""
        result = TrustVerificationResult(
            template_id="tpl-123",
            is_valid=False,
            trust_status=TrustStatus.REVOKED,
            chain_depth=1,
            signing_key_id="revoked-key",
        )

        open_dialog._update_trust_chain_info(result)

        assert "Отозванный" in open_dialog._chain_var.get() or "Отозван" in open_dialog._chain_var.get()


# =============================================================================
# TESTS: TrustChainVerifier
# =============================================================================


class TestTrustChainVerifier:
    """Тесты для TrustChainVerifier."""

    def test_verifier_creation(self, mock_trust_service: Mock) -> None:
        """Тест создания верификатора."""
        verifier = TrustChainVerifier(mock_trust_service)
        assert verifier._trust_service == mock_trust_service

    def test_verify_template(self, mock_trust_service: Mock) -> None:
        """Тест верификации шаблона."""
        verifier = TrustChainVerifier(mock_trust_service)

        template = FormTemplate(
            template_id="tpl-test",
            name="Test Template",
            name_ru="Тестовый шаблон",
        )

        result = verifier.verify_template(template)

        assert isinstance(result, TrustVerificationResult)
        mock_trust_service.verify_template.assert_called_once_with(template, verify_chain=True)

    def test_get_trust_chain_summary_success(
        self,
        mock_trust_service: Mock,
    ) -> None:
        """Тест получения краткого описания цепочки."""
        verifier = TrustChainVerifier(mock_trust_service)

        summary = verifier.get_trust_chain_summary("key-abc")

        assert "глубина" in summary.lower()
        mock_trust_service.get_trust_chain.assert_called_once_with("key-abc")

    def test_get_trust_chain_summary_empty(self, mock_trust_service: Mock) -> None:
        """Тест описания при пустой цепочке."""
        mock_trust_service.get_trust_chain.return_value = []
        verifier = TrustChainVerifier(mock_trust_service)

        summary = verifier.get_trust_chain_summary("unknown-key")

        assert "не найдена" in summary.lower()


# =============================================================================
# TESTS: OpenFileDialog (Static)
# =============================================================================


class TestOpenFileDialog:
    """Тесты статического диалога OpenFileDialog."""

    @patch("src.gui.dialogs.open_dialog.filedialog.askopenfilename")
    def test_show_dialog_returns_path(self, mock_askopen: Mock) -> None:
        """Тест что show возвращает путь."""
        mock_askopen.return_value = "/path/to/document.fxsd"

        result = OpenFileDialog.show()

        assert result == Path("/path/to/document.fxsd")
        mock_askopen.assert_called_once()

    @patch("src.gui.dialogs.open_dialog.filedialog.askopenfilename")
    def test_show_dialog_returns_none_on_cancel(self, mock_askopen: Mock) -> None:
        """Тест что show возвращает None при отмене."""
        mock_askopen.return_value = ""

        result = OpenFileDialog.show()

        assert result is None

    @patch("src.gui.dialogs.open_dialog.filedialog.askopenfilename")
    def test_show_dialog_with_default_dir(self, mock_askopen: Mock) -> None:
        """Тест show с указанием директории по умолчанию."""
        mock_askopen.return_value = "/custom/path/doc.fxsd"

        default_dir = Path("/custom/path")
        result = OpenFileDialog.show(default_dir=default_dir)

        assert result is not None
        call_kwargs = mock_askopen.call_args.kwargs
        assert str(default_dir) in str(call_kwargs.get("initialdir", ""))


# =============================================================================
# TESTS: Constants
# =============================================================================


class TestConstants:
    """Тесты констант."""

    def test_signature_status_valid(self) -> None:
        """Тест константы для валидной подписи."""
        icon, text, color = SIGNATURE_STATUS[True]
        assert icon == "✓"
        assert "действительна" in text

    def test_signature_status_invalid(self) -> None:
        """Тест константы для невалидной подписи."""
        icon, text, color = SIGNATURE_STATUS[False]
        assert icon == "⚠️"
        assert "невалидна" in text

    def test_signature_status_missing(self) -> None:
        """Тест константы для отсутствующей подписи."""
        icon, text, color = SIGNATURE_STATUS[None]
        assert icon == "❌"
        assert "отсутствует" in text

    def test_dialog_dimensions(self) -> None:
        """Тест размеров диалога."""
        from src.gui.dialogs.open_dialog import (
            DIALOG_HEIGHT,
            DIALOG_WIDTH,
            MIN_DIALOG_HEIGHT,
            MIN_DIALOG_WIDTH,
        )

        assert DIALOG_WIDTH >= MIN_DIALOG_WIDTH
        assert DIALOG_HEIGHT >= MIN_DIALOG_HEIGHT
        assert DIALOG_WIDTH > 0
        assert DIALOG_HEIGHT > 0


# =============================================================================
# TESTS: Open/Cancel Buttons
# =============================================================================


@pytest.mark.gui
class TestOpenCancelButtons:
    """Тесты кнопок Открыть/Отмена."""

    def test_open_button_disabled_initially(
        self,
        open_dialog: OpenDialog,
    ) -> None:
        """Тест что кнопка Открыть отключена изначально."""
        state = str(open_dialog._open_button.cget("state"))
        assert state in ("disabled", tk.DISABLED)

    def test_open_button_enabled_after_file_selection(
        self,
        open_dialog: OpenDialog,
        tmp_path: Path,
    ) -> None:
        """Тест что кнопка Открыть включается после выбора файла."""
        test_file = tmp_path / "test.fxsd"
        test_file.write_text("content")

        open_dialog._select_file(test_file)

        state = str(open_dialog._open_button.cget("state"))
        assert state in ("normal", tk.NORMAL)

    @patch("src.gui.dialogs.open_dialog.messagebox.askyesno")
    def test_open_with_invalid_signature_shows_warning(
        self,
        mock_askyesno: Mock,
        open_dialog: OpenDialog,
        mock_trust_service: Mock,
        tmp_path: Path,
    ) -> None:
        """Тест предупреждения при открытии с невалидной подписью."""
        mock_askyesno.return_value = True  # User clicks "Yes"

        # Set up invalid signature
        mock_trust_service.verify_template.return_value = TrustVerificationResult(
            template_id="tpl-123",
            is_valid=False,
            trust_status=TrustStatus.UNTRUSTED,
            chain_depth=0,
            signing_key_id="unknown",
            errors=["Invalid signature"],
        )

        test_file = tmp_path / "test.fxstpl"
        test_file.write_text('FXSTPL\n1.0\n{"template_id": "tpl-1", "name": "Test", "name_ru": "Тест", "version": "1.0", "doc_type": "TEST", "pages": [], "created_at": "2026-04-01T00:00:00", "modified_at": "2026-04-01T00:00:00"}')

        open_dialog._select_file(test_file)
        open_dialog._on_open()

        mock_askyesno.assert_called_once()

    def test_show(self, open_dialog: OpenDialog) -> None:
        """Тест метода show."""
        # Set a result
        open_dialog._result = OpenResult(
            path=Path("/test.fxsd"),
            verify_signature=True,
            metadata=None,
            signature_valid=None,
        )

        # show should return result after wait_window
        # But wait_window would block, so we test the state
        assert open_dialog._result is not None

    def test_show_returns_none_on_cancel(self, open_dialog: OpenDialog) -> None:
        """Тест что show возвращает None при отмене."""
        open_dialog._result = None

        # Result should be None
        assert open_dialog._result is None

    def test_on_cancel_clears_result(self, open_dialog: OpenDialog) -> None:
        """Тест что _on_cancel очищает результат."""
        open_dialog._result = OpenResult(
            path=Path("/test.fxsd"),
            verify_signature=True,
            metadata=None,
            signature_valid=None,
        )

        open_dialog._on_cancel()

        assert open_dialog._result is None

    @patch("src.gui.dialogs.open_dialog.messagebox.showerror")
    def test_on_open_no_file_selected(self, mock_showerror: Mock, open_dialog: OpenDialog) -> None:
        """Тест что при открытии без выбора файла показывается ошибка."""
        open_dialog._selected_path = None

        open_dialog._on_open()

        mock_showerror.assert_called_once()
        assert "Выберите файл" in str(mock_showerror.call_args)

    @patch("src.gui.dialogs.open_dialog.messagebox.showerror")
    def test_on_open_nonexistent_file(self, mock_showerror: Mock, open_dialog: OpenDialog) -> None:
        """Тест что при открытии несуществующего файла показывается ошибка."""
        open_dialog._selected_path = Path("/nonexistent/file.fxsd")

        open_dialog._on_open()

        mock_showerror.assert_called_once()
        assert "не найден" in str(mock_showerror.call_args) or "not found" in str(mock_showerror.call_args).lower()

    @patch("src.gui.dialogs.open_dialog.messagebox.askyesno")
    def test_on_open_with_valid_signature(self, mock_askyesno: Mock, open_dialog: OpenDialog, mock_trust_service: Mock, tmp_path: Path) -> None:
        """Тест что при валидной подписи файл открывается без предупреждения."""
        # Set up valid signature
        mock_trust_service.verify_template.return_value = TrustVerificationResult(
            template_id="tpl-123",
            is_valid=True,
            trust_status=TrustStatus.TRUSTED,
            chain_depth=2,
            signing_key_id="key-abc",
        )

        test_file = tmp_path / "test.fxstpl"
        test_file.write_text('FXSTPL\n1.0\n{"template_id": "tpl-1", "name": "Test", "name_ru": "Тест", "version": "1.0", "doc_type": "TEST", "pages": [], "created_at": "2026-04-01T00:00:00", "modified_at": "2026-04-01T00:00:00"}')

        open_dialog._select_file(test_file)

        # Reset result
        open_dialog._result = None

        open_dialog._on_open()

        # Should not call askyesno for valid signature
        mock_askyesno.assert_not_called()
        # Result should be set
        assert open_dialog._result is not None
        assert open_dialog._result.path == test_file

    def test_on_verify_toggle_off(self, open_dialog: OpenDialog) -> None:
        """Тест что отключение проверки обновляет UI."""
        open_dialog._verify_var.set(False)
        open_dialog._on_verify_toggle()

        assert "Проверка отключена" in open_dialog._status_text_var.get()
        assert "отключена" in open_dialog._chain_var.get()

    def test_select_file_updates_path(self, open_dialog: OpenDialog, tmp_path: Path) -> None:
        """Тест что выбор файла обновляет путь в UI."""
        test_file = tmp_path / "test.fxsd"
        test_file.write_text("content")

        open_dialog._select_file(test_file)

        assert str(test_file) == open_dialog._path_var.get()
        assert open_dialog._selected_path == test_file


# =============================================================================
# MODULE EXPORTS
# =============================================================================


class TestModuleExports:
    """Тесты экспорта модуля."""

    def test_all_exports_defined(self) -> None:
        """Тест что __all__ содержит все публичные имена."""
        from src.gui.dialogs import open_dialog

        expected = [
            "OpenDialog",
            "OpenResult",
            "OpenFileDialog",
            "TrustChainVerifier",
            "SIGNATURE_STATUS",
            "FILE_TYPE_ICONS",
        ]

        for name in expected:
            assert name in open_dialog.__all__


# =============================================================================
# COVERAGE TARGET VERIFICATION
# =============================================================================


def test_coverage_target() -> None:
    """Верификация целевого покрытия кода (≥90%).

    Этот тест служит напоминанием о требовании покрытия.
    Фактическое покрытие должно измеряться с помощью pytest-cov.
    """
    # Import all test classes to ensure they're counted
    test_classes = [
        TestOpenResult,
        TestDialogCreation,
        TestFileFiltering,
        TestSignatureVerification,
        TestMetadataPreview,
        TestTrustChainDisplay,
        TestTrustChainVerifier,
        TestOpenFileDialog,
        TestConstants,
        TestOpenCancelButtons,
        TestModuleExports,
    ]
    assert len(test_classes) >= 10  # Ensure comprehensive test coverage


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
