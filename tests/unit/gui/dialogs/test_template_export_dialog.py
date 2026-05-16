# -*- coding: utf-8 -*-
"""Тесты для TemplateExportDialog.

Тестирует создание диалога, привязку данных формы,
экспорт с и без подписи, оптимизацию для дискеты,
валидацию полей и возврат результата.

Version: 1.0
"""

from __future__ import annotations

import sys
import tkinter as tk
import types
from pathlib import Path
from typing import Any, Generator, cast
from unittest.mock import MagicMock, patch

import pytest

# Add src to path before importing
project_root = Path("/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3")
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Direct import from the module file to avoid __init__.py circular dependency
template_export_module = types.ModuleType("template_export_dialog")
template_export_module.__file__ = str(project_root / "src" / "gui" / "dialogs" / "template_export_dialog.py")

# Execute module
sys.modules["template_export_dialog"] = template_export_module
with open(template_export_module.__file__, "r", encoding="utf-8") as f:
    code = compile(f.read(), template_export_module.__file__, "exec")
    exec(code, template_export_module.__dict__)

TemplateExportDialog = template_export_module.TemplateExportDialog
ExportResult = template_export_module.ExportResult
COLOR_SUCCESS = template_export_module.COLOR_SUCCESS
COLOR_ERROR = template_export_module.COLOR_ERROR
COLOR_BG = template_export_module.COLOR_BG
MAX_FLOPPY_SIZE = template_export_module.MAX_FLOPPY_SIZE
TEMPLATE_CATEGORIES = template_export_module.TEMPLATE_CATEGORIES


@pytest.fixture
def root() -> Generator[tk.Widget, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield cast(tk.Widget, root)
    root.destroy()


@pytest.fixture
def sample_form_data() -> dict[str, Any]:
    """Тестовые данные формы."""
    return {
        "name": "Test Invoice",
        "doc_type": "DVN-44-K53",
        "description": "Test invoice template",
        "author": "Test User",
        "pages": [],
    }


@pytest.fixture
def mock_template_manager() -> Generator[MagicMock, None, None]:
    """Мок менеджера шаблонов."""
    manager = MagicMock()
    manager.save_template = MagicMock(return_value=Path("/tmp/test_template.fxstpl"))
    yield manager


@pytest.fixture
def dialog(
    root: tk.Widget,
    sample_form_data: dict[str, Any],
    mock_template_manager: MagicMock,
) -> Generator[TemplateExportDialog, None, None]:
    """Фикстура для диалога экспорта."""
    dialog = TemplateExportDialog(
        parent=root,
        form_data=sample_form_data,
        template_manager=mock_template_manager,
        current_user="TestUser",
    )
    yield dialog
    try:
        dialog.destroy()
    except tk.TclError:
        pass


@pytest.mark.gui
class TestTemplateExportDialogCreation:
    """Тесты создания TemplateExportDialog."""

    def test_dialog_initialization(
        self,
        root: tk.Widget,
        sample_form_data: dict[str, Any],
        mock_template_manager: MagicMock,
    ) -> None:
        """Проверка создания диалога."""
        dialog = TemplateExportDialog(
            parent=root,
            form_data=sample_form_data,
            template_manager=mock_template_manager,
        )
        assert dialog._form_data is sample_form_data
        assert dialog._template_manager is mock_template_manager
        assert dialog._result is None
        dialog.destroy()

    def test_dialog_with_current_user(
        self,
        root: tk.Widget,
        sample_form_data: dict[str, Any],
        mock_template_manager: MagicMock,
    ) -> None:
        """Проверка auto-fill автора."""
        dialog = TemplateExportDialog(
            parent=root,
            form_data=sample_form_data,
            template_manager=mock_template_manager,
            current_user="JohnDoe",
        )
        # Author should be auto-filled from current_user
        assert dialog._author_var.get() == "JohnDoe"
        dialog.destroy()

    def test_dialog_constants(self) -> None:
        """Проверка констант диалога."""
        assert MAX_FLOPPY_SIZE == 1_340_000
        assert COLOR_SUCCESS == "#28a745"
        assert COLOR_ERROR == "#dc3545"
        assert COLOR_BG == "#f8f9fa"


@pytest.mark.gui
class TestExportResultDataclass:
    """Тесты dataclass ExportResult."""

    def test_export_result_creation(self) -> None:
        """Создание ExportResult."""
        result = ExportResult(
            path=Path("/test/template.fxstpl"),
            signed=True,
            template_name="Test Template",
            version="1.0.0",
        )
        assert result.path == Path("/test/template.fxstpl")
        assert result.signed is True
        assert result.template_name == "Test Template"
        assert result.version == "1.0.0"

    def test_export_result_not_signed(self) -> None:
        """ExportResult без подписи."""
        result = ExportResult(
            path=Path("/test/template.fxstpl"),
            signed=False,
            template_name="Test Template",
            version="2.1.0",
        )
        assert result.signed is False
        assert result.version == "2.1.0"


@pytest.mark.gui
class TestTemplateExportDialogFormBinding:
    """Тесты привязки данных формы."""

    def test_name_binding(self, dialog: TemplateExportDialog) -> None:
        """Привязка названия формы."""
        # Name should be pre-filled from form_data
        assert dialog._name_var.get() == "Test Invoice"

    def test_author_binding_from_form_data(
        self,
        root: tk.Widget,
        mock_template_manager: MagicMock,
    ) -> None:
        """Привязка автора из form_data."""
        form_data = {"name": "Test", "author": "FormAuthor"}
        dialog = TemplateExportDialog(
            parent=root,
            form_data=form_data,
            template_manager=mock_template_manager,
        )
        assert dialog._author_var.get() == "FormAuthor"
        dialog.destroy()

    def test_description_binding(
        self,
        root: tk.Widget,
        sample_form_data: dict[str, Any],
        mock_template_manager: MagicMock,
    ) -> None:
        """Привязка описания."""
        dialog = TemplateExportDialog(
            parent=root,
            form_data=sample_form_data,
            template_manager=mock_template_manager,
        )
        desc = dialog._desc_text.get("1.0", tk.END).strip()
        assert desc == "Test invoice template"
        dialog.destroy()


@pytest.mark.gui
class TestTemplateExportDialogValidation:
    """Тесты валидации полей."""

    def test_validate_empty_name(self, dialog: TemplateExportDialog) -> None:
        """Валидация пустого названия."""
        dialog._name_var.set("")
        error = dialog._validate_inputs()
        assert error == "Template name is required"

    def test_validate_empty_version(self, dialog: TemplateExportDialog) -> None:
        """Валидация пустой версии."""
        dialog._name_var.set("Test")
        dialog._version_var.set("")
        error = dialog._validate_inputs()
        assert error == "Version is required"

    def test_validate_invalid_semver(self, dialog: TemplateExportDialog) -> None:
        """Валидация неверного semver."""
        dialog._name_var.set("Test")
        dialog._version_var.set("1.0")  # Invalid semver
        dialog._path_var.set("/tmp/test.fxstpl")
        error = dialog._validate_inputs()
        assert "semver" in error.lower()

    def test_validate_valid_semver(self, dialog: TemplateExportDialog) -> None:
        """Валидация корректного semver."""
        dialog._name_var.set("Test")
        dialog._version_var.set("1.2.3")
        dialog._path_var.set("/tmp/test.fxstpl")
        error = dialog._validate_inputs()
        assert error is None

    def test_validate_empty_path(self, dialog: TemplateExportDialog) -> None:
        """Валидация пустого пути."""
        dialog._name_var.set("Test")
        dialog._version_var.set("1.0.0")
        dialog._path_var.set("")
        error = dialog._validate_inputs()
        assert error == "Select a save location"


@pytest.mark.gui
class TestTemplateExportDialogSignature:
    """Тесты опции подписи."""

    def test_signature_checkbox_default(self, dialog: TemplateExportDialog) -> None:
        """Чекбокс подписи по умолчанию выключен."""
        assert dialog._sign_var.get() is False

    def test_signature_enable(self, dialog: TemplateExportDialog) -> None:
        """Включение подписи."""
        dialog.enable_signature(True)
        assert dialog._sign_var.get() is True

    def test_signature_disable(self, dialog: TemplateExportDialog) -> None:
        """Выключение подписи."""
        dialog.enable_signature(True)
        dialog.enable_signature(False)
        assert dialog._sign_var.get() is False

    def test_signature_toggle_callback(self, dialog: TemplateExportDialog) -> None:
        """Обработчик переключения подписи."""
        # Toggle on
        dialog._sign_var.set(True)
        dialog._on_sign_toggle()
        assert dialog._sign_var.get() is True

        # Toggle off
        dialog._sign_var.set(False)
        dialog._on_sign_toggle()
        assert dialog._sign_var.get() is False


@pytest.mark.gui
class TestTemplateExportDialogFloppyOptimizer:
    """Тесты оптимизации для дискеты."""

    def test_size_variables_exist(self, dialog: TemplateExportDialog) -> None:
        """Переменные размера существуют."""
        assert dialog._original_size_var is not None
        assert dialog._optimized_size_var is not None
        assert dialog._savings_var is not None

    def test_floppy_status_variable_exists(self, dialog: TemplateExportDialog) -> None:
        """Переменная статуса существует."""
        assert dialog._floppy_status_var is not None

    def test_get_estimated_size(self, dialog: TemplateExportDialog) -> None:
        """Получение оценочного размера."""
        original, optimized = dialog.get_estimated_size()
        assert isinstance(original, int)
        assert isinstance(optimized, int)
        assert original >= 0
        assert optimized >= 0


@pytest.mark.gui
class TestTemplateExportDialogCategory:
    """Тесты выбора категории."""

    def test_category_default(self, dialog: TemplateExportDialog) -> None:
        """Категория по умолчанию."""
        assert dialog._category_var.get() == "General"

    def test_category_values(self) -> None:
        """Доступные категории."""
        assert "General" in TEMPLATE_CATEGORIES
        assert "Accounting" in TEMPLATE_CATEGORIES
        assert "Logistics" in TEMPLATE_CATEGORIES


@pytest.mark.gui
class TestTemplateExportDialogButtons:
    """Тесты кнопок диалога."""

    def test_export_button_exists(self, dialog: TemplateExportDialog) -> None:
        """Кнопка Export существует."""
        assert dialog._export_btn is not None

    def test_cancel_button_closes_dialog(
        self,
        root: tk.Widget,
        sample_form_data: dict[str, Any],
        mock_template_manager: MagicMock,
    ) -> None:
        """Кнопка Cancel закрывает диалог."""
        dialog = TemplateExportDialog(
            parent=root,
            form_data=sample_form_data,
            template_manager=mock_template_manager,
        )

        # Simulate cancel
        dialog._on_cancel()

        # Check dialog is destroyed
        try:
            exists = dialog.winfo_exists()
            assert not exists, "Dialog should be destroyed"
        except tk.TclError:
            pass  # Expected - window is destroyed

    def test_cancel_sets_result_none(
        self,
        root: tk.Widget,
        sample_form_data: dict[str, Any],
        mock_template_manager: MagicMock,
    ) -> None:
        """Cancel устанавливает result в None."""
        dialog = TemplateExportDialog(
            parent=root,
            form_data=sample_form_data,
            template_manager=mock_template_manager,
        )

        # Simulate cancel
        dialog._on_cancel()

        assert dialog._result is None


@pytest.mark.gui
class TestTemplateExportDialogExportPath:
    """Тесты установки пути экспорта."""

    def test_set_export_path(self, dialog: TemplateExportDialog) -> None:
        """Установка пути экспорта."""
        test_path = Path("/test/export/template.fxstpl")
        dialog.set_export_path(test_path)
        assert dialog._path_var.get() == str(test_path)

    def test_path_variable_exists(self, dialog: TemplateExportDialog) -> None:
        """Переменная пути существует."""
        assert dialog._path_var is not None


@pytest.mark.gui
class TestTemplateExportDialogShow:
    """Тесты метода show()."""

    def test_show_returns_none_when_cancelled(
        self,
        root: tk.Widget,
        sample_form_data: dict[str, Any],
        mock_template_manager: MagicMock,
    ) -> None:
        """show() возвращает None при отмене."""
        dialog = TemplateExportDialog(
            parent=root,
            form_data=sample_form_data,
            template_manager=mock_template_manager,
        )

        # Mock wait_window to avoid blocking
        with patch.object(dialog, "wait_window"):
            dialog._on_cancel()
            result = dialog.show()

        assert result is None

    def test_show_returns_export_result(
        self,
        root: tk.Widget,
        sample_form_data: dict[str, Any],
        mock_template_manager: MagicMock,
    ) -> None:
        """show() возвращает ExportResult при успехе."""
        dialog = TemplateExportDialog(
            parent=root,
            form_data=sample_form_data,
            template_manager=mock_template_manager,
        )

        # Set up for successful export
        dialog._name_var.set("TestTemplate")
        dialog._version_var.set("1.0.0")
        dialog._path_var.set("/tmp/test.fxstpl")
        dialog._result = ExportResult(
            path=Path("/tmp/test.fxstpl"),
            signed=False,
            template_name="TestTemplate",
            version="1.0.0",
        )

        # Mock wait_window to avoid blocking
        with patch.object(dialog, "wait_window"):
            result = dialog.show()

        assert isinstance(result, ExportResult)
        assert result.template_name == "TestTemplate"
        assert result.version == "1.0.0"


@pytest.mark.gui
class TestTemplateExportDialogTemplateCreation:
    """Тесты создания объекта шаблона."""

    def test_create_template_object(self, dialog: TemplateExportDialog) -> None:
        """Создание объекта FormTemplate."""
        dialog._name_var.set("TestTemplate")
        dialog._version_var.set("1.5.0")
        dialog._author_var.set("TestAuthor")
        dialog._desc_text.insert("1.0", "Test description")

        template = dialog._create_template_object()

        assert template.name == "TestTemplate"
        assert template.version == "1.5.0"
        assert template.author == "TestAuthor"
        assert template.is_special_blank is False

    def test_create_template_with_signature(
        self,
        root: tk.Widget,
        sample_form_data: dict[str, Any],
        mock_template_manager: MagicMock,
    ) -> None:
        """Создание шаблона с включённой подписью."""
        dialog = TemplateExportDialog(
            parent=root,
            form_data=sample_form_data,
            template_manager=mock_template_manager,
        )
        dialog._name_var.set("SignedTemplate")
        dialog._version_var.set("2.0.0")
        dialog._sign_var.set(True)

        template = dialog._create_template_object()

        assert template.is_special_blank is True
        dialog.destroy()


__all__ = [
    "TestTemplateExportDialogCreation",
    "TestExportResultDataclass",
    "TestTemplateExportDialogFormBinding",
    "TestTemplateExportDialogValidation",
    "TestTemplateExportDialogSignature",
    "TestTemplateExportDialogFloppyOptimizer",
    "TestTemplateExportDialogCategory",
    "TestTemplateExportDialogButtons",
    "TestTemplateExportDialogExportPath",
    "TestTemplateExportDialogShow",
    "TestTemplateExportDialogTemplateCreation",
]
