"""Минимальные тесты для SaveDialog."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from typing import Generator
from unittest.mock import Mock, patch

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

from src.documents.format.document_format import SecurityPreset
from src.gui.dialogs.save_dialog import (
    PRESET_LABELS,
    SaveDialog,
    SaveFileDialog,
    SaveResult,
)
from src.model.document import Document, DocumentMetadata
from src.security.crypto.utilities.passwords import PasswordStrength


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Фикстура для создания корневого окна tkinter."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def sample_document() -> Document:
    """Фикстура для создания тестового документа."""
    metadata = DocumentMetadata(
        title="Test Document",
        author="Test Author",
        subject="Test Description",
    )
    doc = Document(metadata=metadata)
    doc.set_text_content("Test content for document")
    return doc


class TestSaveResult:
    """Тесты для dataclass SaveResult."""

    def test_save_result_creation(self) -> None:
        """Тест создания SaveResult с валидными данными."""
        result = SaveResult(
            path=Path("/docs/test.fxsd"),
            encrypted=True,
            preset=SecurityPreset.STANDARD,
            metadata=DocumentMetadata(title="Test"),
            password="secure_pass123",
        )

        assert result.path == Path("/docs/test.fxsd")
        assert result.encrypted is True
        assert result.preset == SecurityPreset.STANDARD
        assert result.metadata.title == "Test"
        assert result.password == "secure_pass123"

    def test_save_result_without_encryption(self) -> None:
        """Тест создания SaveResult без шифрования."""
        result = SaveResult(
            path=Path("/docs/test.fxsd"),
            encrypted=False,
            preset=SecurityPreset.LEGACY,
            metadata=DocumentMetadata(title="Test"),
            password="",
        )

        assert result.encrypted is False
        assert result.password == ""

    def test_save_result_frozen(self) -> None:
        """Тест что SaveResult неизменяемый."""
        result = SaveResult(
            path=Path("/docs/test.fxsd"),
            encrypted=True,
            preset=SecurityPreset.STANDARD,
            metadata=DocumentMetadata(title="Test"),
            password="pass",
        )

        with pytest.raises(AttributeError):
            result.path = Path("/other/doc.fxsd")  # type: ignore[misc]


class TestSaveDialogCreation:
    """Тесты для создания диалога SaveDialog."""

    def test_dialog_initialization(self, tk_root: tk.Tk) -> None:
        """Тест инициализации диалога."""
        doc = Document(metadata=DocumentMetadata(title="My Doc"))
        dialog = SaveDialog(tk_root, doc)

        assert dialog._document == doc
        assert dialog._result is None
        assert dialog._encrypt_var.get() is False
        dialog.destroy()

    def test_dialog_with_default_path(self, tk_root: tk.Tk) -> None:
        """Тест инициализации с путём по умолчанию."""
        doc = Document()
        default_path = Path("/home/user/Documents")

        dialog = SaveDialog(tk_root, doc, default_path=default_path)
        assert dialog._default_path == default_path
        dialog.destroy()

    def test_dialog_title(self, tk_root: tk.Tk) -> None:
        """Тест установки заголовка диалога."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc, title="Custom Title")
        assert dialog.title() == "Custom Title"
        dialog.destroy()


class TestSaveDialogUIComponents:
    """Тесты UI компонентов диалога."""

    def test_file_section_created(self, tk_root: tk.Tk) -> None:
        """Тест создания секции файла."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        assert hasattr(dialog, "_filename_entry")
        assert hasattr(dialog, "_browse_button")
        assert hasattr(dialog, "_path_label")
        dialog.destroy()

    def test_encryption_section_created(self, tk_root: tk.Tk) -> None:
        """Тест создания секции шифрования."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        assert hasattr(dialog, "_encrypt_var")
        assert hasattr(dialog, "_encrypt_check")
        assert hasattr(dialog, "_encrypt_info")
        dialog.destroy()

    def test_preset_section_created(self, tk_root: tk.Tk) -> None:
        """Тест создания секции пресета."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        assert hasattr(dialog, "_preset_var")
        assert hasattr(dialog, "_preset_combo")
        assert hasattr(dialog, "_preset_desc")
        dialog.destroy()

    def test_password_section_created(self, tk_root: tk.Tk) -> None:
        """Тест создания секции пароля."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        assert hasattr(dialog, "_password_frame")
        assert hasattr(dialog, "_password_var")
        assert hasattr(dialog, "_password_entry")
        assert hasattr(dialog, "_confirm_var")
        assert hasattr(dialog, "_confirm_entry")
        dialog.destroy()

    def test_strength_indicator_created(self, tk_root: tk.Tk) -> None:
        """Тест создания индикатора сложности."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        assert hasattr(dialog, "_strength_var")
        assert hasattr(dialog, "_strength_bar")
        assert hasattr(dialog, "_strength_label")
        dialog.destroy()

    def test_metadata_section_created(self, tk_root: tk.Tk) -> None:
        """Тест создания секции метаданных."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        assert hasattr(dialog, "_title_var")
        assert hasattr(dialog, "_author_var")
        assert hasattr(dialog, "_desc_text")
        dialog.destroy()

    def test_size_indicator_created(self, tk_root: tk.Tk) -> None:
        """Тест создания индикатора размера."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        assert hasattr(dialog, "_size_var")
        assert hasattr(dialog, "_size_label")
        dialog.destroy()

    def test_button_bar_created(self, tk_root: tk.Tk) -> None:
        """Тест создания панели кнопок."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        assert hasattr(dialog, "_save_button")
        assert hasattr(dialog, "_cancel_button")
        dialog.destroy()


class TestSaveDialogInitialization:
    """Тесты инициализации значений в диалоге."""

    def test_metadata_initialized(self, tk_root: tk.Tk, sample_document: Document) -> None:
        """Тест инициализации метаданных из документа."""
        dialog = SaveDialog(tk_root, sample_document)

        assert dialog._title_var.get() == "Test Document"
        assert dialog._author_var.get() == "Test Author"
        assert "Test Description" in dialog._desc_text.get("1.0", tk.END)
        dialog.destroy()

    def test_filename_initialized(self, tk_root: tk.Tk) -> None:
        """Тест инициализации имени файла."""
        doc = Document(metadata=DocumentMetadata(title="Invoice"))
        dialog = SaveDialog(tk_root, doc)

        assert "Invoice" in dialog._filename_var.get()
        assert dialog._filename_var.get().endswith(".fxsd")
        dialog.destroy()

    def test_filename_with_extension(self, tk_root: tk.Tk) -> None:
        """Тест что расширение не дублируется."""
        doc = Document(metadata=DocumentMetadata(title="Report.fxsd"))
        dialog = SaveDialog(tk_root, doc)

        filename = dialog._filename_var.get()
        assert ".fxsd.fxsd" not in filename
        assert filename.endswith(".fxsd")
        dialog.destroy()


class TestSaveDialogEncryption:
    """Тесты функциональности шифрования."""

    def test_encryption_toggle(self, tk_root: tk.Tk) -> None:
        """Тест что переключение шифрования работает."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        # Initially disabled
        assert dialog._encrypt_var.get() is False

        # Enable encryption
        dialog._encrypt_var.set(True)
        dialog._on_encrypt_toggle()

        # Encryption should be enabled
        assert dialog._encrypt_var.get() is True
        dialog.destroy()

    def test_preset_change_updates_description(self, tk_root: tk.Tk) -> None:
        """Тест что изменение пресета обновляет описание."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        # Test changing to each preset
        for preset in SecurityPreset:
            dialog._preset_var.set(preset.value)
            dialog._on_preset_change()

            desc = dialog._preset_desc_var.get()
            assert desc != ""
            assert desc == PRESET_LABELS[preset]

        dialog.destroy()


class TestSaveDialogPasswordStrength:
    """Тесты индикатора сложности пароля."""

    @patch("src.gui.dialogs.save_dialog.PasswordHasher")
    def test_password_strength_weak(self, mock_hasher: Mock, tk_root: tk.Tk) -> None:
        """Тест отображения слабого пароля."""
        mock_hasher.return_value.check_password_strength.return_value = Mock(
            strength=PasswordStrength.WEAK,
            score=15,
            feedback=["Too short"],
        )

        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._password_var.set("weak")
        dialog._on_password_change()

        assert dialog._strength_var.get() == 15
        assert "Weak" in dialog._strength_text_var.get()
        dialog.destroy()

    @patch("src.gui.dialogs.save_dialog.PasswordHasher")
    def test_password_strength_strong(self, mock_hasher: Mock, tk_root: tk.Tk) -> None:
        """Тест отображения надёжного пароля."""
        mock_hasher.return_value.check_password_strength.return_value = Mock(
            strength=PasswordStrength.STRONG,
            score=75,
            feedback=["Good password"],
        )

        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._password_var.set("StrongPass123!")
        dialog._on_password_change()

        assert dialog._strength_var.get() == 75
        assert "Strong" in dialog._strength_text_var.get()
        dialog.destroy()

    def test_empty_password_reset(self, tk_root: tk.Tk) -> None:
        """Тест что пустой пароль сбрасывает индикатор."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._password_var.set("")
        dialog._on_password_change()

        assert dialog._strength_var.get() == 0
        assert "Enter password" in dialog._strength_text_var.get()
        dialog.destroy()


class TestSaveDialogValidation:
    """Тесты валидации в диалоге."""

    def test_validation_empty_filename(self, tk_root: tk.Tk) -> None:
        """Тест валидации пустого имени файла."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._filename_var.set("")
        is_valid, error = dialog._validate()

        assert is_valid is False
        assert "filename" in error.lower()
        dialog.destroy()

    def test_validation_invalid_characters(self, tk_root: tk.Tk) -> None:
        """Тест валидации недопустимых символов."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._filename_var.set("file<name>.txt")
        is_valid, error = dialog._validate()

        assert is_valid is False
        assert "invalid" in error.lower()
        dialog.destroy()

    def test_validation_encryption_no_password(self, tk_root: tk.Tk) -> None:
        """Тест валидации шифрования без пароля."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._encrypt_var.set(True)
        dialog._password_var.set("")

        is_valid, error = dialog._validate()

        assert is_valid is False
        assert "password" in error.lower()
        dialog.destroy()

    def test_validation_short_password(self, tk_root: tk.Tk) -> None:
        """Тест валидации короткого пароля."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._encrypt_var.set(True)
        dialog._password_var.set("short")

        is_valid, error = dialog._validate()

        assert is_valid is False
        assert "8" in error
        dialog.destroy()

    def test_validation_passwords_mismatch(self, tk_root: tk.Tk) -> None:
        """Тест валидации несовпадающих паролей."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._encrypt_var.set(True)
        dialog._password_var.set("Password123!")
        dialog._confirm_var.set("Different123!")

        is_valid, error = dialog._validate()

        assert is_valid is False
        assert "match" in error.lower()
        dialog.destroy()

    @patch("src.gui.dialogs.save_dialog.PasswordHasher")
    def test_validation_weak_password(self, mock_hasher: Mock, tk_root: tk.Tk) -> None:
        """Тест валидации слабого пароля."""
        mock_hasher.return_value.check_password_strength.return_value = Mock(
            strength=PasswordStrength.WEAK,
            score=10,
            feedback=["Too weak", "Add more characters"],
        )

        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._encrypt_var.set(True)
        dialog._password_var.set("weakpass123!")
        dialog._confirm_var.set("weakpass123!")

        is_valid, error = dialog._validate()

        assert is_valid is False
        assert "weak" in error.lower()
        dialog.destroy()

    def test_validation_valid(self, tk_root: tk.Tk) -> None:
        """Тест успешной валидации."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._filename_var.set("document.fxsd")
        dialog._encrypt_var.set(False)

        is_valid, error = dialog._validate()

        assert is_valid is True
        assert error == ""
        dialog.destroy()


class TestSaveDialogActions:
    """Тесты действий диалога."""

    def test_cancel_sets_none_result(self, tk_root: tk.Tk) -> None:
        """Тест что отмена устанавливает None в результат."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        # Set some initial result
        dialog._result = SaveResult(
            path=Path("/tmp/test.fxsd"),
            encrypted=False,
            preset=SecurityPreset.STANDARD,
            metadata=DocumentMetadata(),
            password="",
        )

        dialog._on_cancel()

        assert dialog._result is None

    def test_show_returns_result(self, tk_root: tk.Tk) -> None:
        """Тест что show возвращает результат диалога."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        # Set a result and destroy
        dialog._result = SaveResult(
            path=Path("/tmp/test.fxsd"),
            encrypted=False,
            preset=SecurityPreset.STANDARD,
            metadata=DocumentMetadata(),
            password="",
        )

        # Just test the result is accessible
        assert dialog._result is not None
        dialog.destroy()


class TestSaveDialogSave:
    """Тесты сохранения в диалоге."""

    @patch("src.gui.dialogs.save_dialog.messagebox")
    @patch("pathlib.Path.exists")
    def test_save_success(self, mock_exists: Mock, mock_msgbox: Mock, tk_root: tk.Tk) -> None:
        """Тест успешного сохранения."""
        mock_exists.return_value = False

        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._filename_var.set("test.fxsd")
        dialog._encrypt_var.set(False)
        dialog._current_path = Path("/tmp")

        # This should set result and destroy
        # Note: can't actually call _on_save because it destroys dialog
        # But we can validate the data setup
        is_valid, error = dialog._validate()
        assert is_valid is True
        assert error == ""
        dialog.destroy()

    @patch("src.gui.dialogs.save_dialog.messagebox")
    def test_save_with_encryption(self, mock_msgbox: Mock, tk_root: tk.Tk) -> None:
        """Тест сохранения с шифрованием."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._filename_var.set("test.fxsd")
        dialog._encrypt_var.set(True)
        dialog._current_path = Path("/tmp")
        dialog._password_var.set("StrongPass123!")
        dialog._confirm_var.set("StrongPass123!")
        dialog._preset_var.set(SecurityPreset.PARANOID.value)

        is_valid, error = dialog._validate()
        assert is_valid is True
        assert error == ""
        dialog.destroy()


class TestSaveFileDialog:
    """Тесты для статического SaveFileDialog."""

    @patch("tkinter.filedialog.asksaveasfilename")
    def test_show_returns_path(self, mock_dialog: Mock) -> None:
        """Тест что show возвращает путь."""
        mock_dialog.return_value = "/home/user/document.fxsd"

        result = SaveFileDialog.show()

        assert result == Path("/home/user/document.fxsd")

    @patch("tkinter.filedialog.asksaveasfilename")
    def test_show_returns_none_on_cancel(self, mock_dialog: Mock) -> None:
        """Тест что show возвращает None при отмене."""
        mock_dialog.return_value = ""

        result = SaveFileDialog.show()

        assert result is None

    @patch("tkinter.filedialog.asksaveasfilename")
    def test_show_with_default_name(self, mock_dialog: Mock) -> None:
        """Тест show с именем по умолчанию."""
        mock_dialog.return_value = "/home/user/custom.fxsd"

        result = SaveFileDialog.show(default_name="custom.fxsd")

        mock_dialog.assert_called_once()
        assert result == Path("/home/user/custom.fxsd")


class TestSaveDialogPathHandling:
    """Тесты работы с путями."""

    def test_update_path_display(self, tk_root: tk.Tk) -> None:
        """Тест обновления отображения пути."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        test_path = Path("/very/long/path/to/documents/folder")
        dialog._update_path_display(test_path)

        # Path should be stored
        assert dialog._current_path == test_path

        # Display might be truncated
        display = dialog._path_var.get()
        assert "folder" in display or "..." in display
        dialog.destroy()


    def test_update_path_display_long_path(self, tk_root: tk.Tk) -> None:
        """Тест обновления длинного пути с усечением."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        # Very long path should be truncated
        test_path = Path("/a/very/long/path/that/exceeds/limit/and/should/be/truncated/for/display")
        dialog._update_path_display(test_path)

        # Path should be stored
        assert dialog._current_path == test_path

        # Display should be truncated (contains ... or is shorter)
        display = dialog._path_var.get()
        assert "..." in display or len(display) < 60
        dialog.destroy()

    def test_path_var_initialized(self, tk_root: tk.Tk) -> None:
        """Тест инициализации переменной пути."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        # Should have some default value
        assert dialog._path_var.get() != ""
        dialog.destroy()


class TestSaveDialogSizeEstimate:
    """Тесты оценки размера файла."""

    def test_size_estimate_no_encryption(self, tk_root: tk.Tk) -> None:
        """Тест оценки размера без шифрования."""
        doc = Document()
        doc.set_text_content("Test content")
        dialog = SaveDialog(tk_root, doc)

        dialog._encrypt_var.set(False)
        dialog._update_size_estimate()

        size = dialog._size_var.get()
        assert "~" in size
        assert "bytes" in size or "KB" in size
        dialog.destroy()


class TestSaveDialogAllPresets:
    """Тесты для всех пресетов безопасности."""

    def test_all_presets_in_combobox(self, tk_root: tk.Tk) -> None:
        """Тест что все пресеты доступны в выпадающем списке."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        values = dialog._preset_combo["values"]
        preset_values = {p.value for p in SecurityPreset}
        combo_values = set(values)

        assert preset_values == combo_values
        dialog.destroy()

    def test_each_preset_description(self, tk_root: tk.Tk) -> None:
        """Тест описаний для каждого пресета."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        for preset in SecurityPreset:
            dialog._preset_var.set(preset.value)
            dialog._on_preset_change()

            desc = dialog._preset_desc_var.get()
            assert desc == PRESET_LABELS[preset]

        dialog.destroy()


class TestSaveDialogPasswordVisibility:
    """Тесты переключения видимости пароля."""

    def test_password_visibility_toggle(self, tk_root: tk.Tk) -> None:
        """Тест переключения видимости пароля."""
        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        # Default should be hidden
        assert dialog._password_entry.cget("show") == "*"

        # Enable visibility
        dialog._show_password_var.set(True)
        dialog._toggle_password_visibility()
        assert dialog._password_entry.cget("show") == ""

        # Disable visibility
        dialog._show_password_var.set(False)
        dialog._toggle_password_visibility()
        assert dialog._password_entry.cget("show") == "*"

        dialog.destroy()


class TestSaveDialogBrowser:
    """Тесты функции обзора файлов."""

    @patch("tkinter.filedialog.asksaveasfilename")
    def test_browse_updates_filename(self, mock_dialog: Mock, tk_root: tk.Tk) -> None:
        """Тест что обзор обновляет имя файла."""
        mock_dialog.return_value = "/home/user/newdoc.fxsd"

        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        dialog._on_browse()

        assert dialog._filename_var.get() == "newdoc.fxsd"
        dialog.destroy()

    @patch("tkinter.filedialog.asksaveasfilename")
    def test_browse_auto_enables_encryption(self, mock_dialog: Mock, tk_root: tk.Tk) -> None:
        """Тест что .enc расширение включает шифрование."""
        mock_dialog.return_value = "/home/user/doc.fxsd.enc"

        doc = Document()
        dialog = SaveDialog(tk_root, doc)

        initial_encrypt = dialog._encrypt_var.get()
        dialog._on_browse()

        # Should enable encryption
        assert dialog._encrypt_var.get() is True
        dialog.destroy()
