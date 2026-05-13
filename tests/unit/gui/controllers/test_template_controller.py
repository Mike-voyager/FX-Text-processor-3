"""Тесты для template_controller модуля.

Тестирует:
- TemplateController
- on_import_template
- on_export_template

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/controllers/test_template_controller.py -v

Module: tests/unit/gui/controllers/test_template_controller.py
Version: 1.0
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

if sys.platform == "linux" and not sys.stdin.isatty():
    try:
        import tkinter as tk

        tk.Tcl().eval("info patchlevel")
    except tk.TclError:
        pytest.skip("No display available", allow_module_level=True)

from src.gui.controllers.template_controller import TemplateController
from src.services.template_manager import FormTemplate


class TestTemplateControllerImport:
    """Тесты импорта шаблона."""

    @pytest.fixture
    def mock_service(self):
        """Мок TemplateManager."""
        service = MagicMock()
        template = FormTemplate(
            template_id="tpl-123",
            name="Test",
            name_ru="Тест",
            doc_type="DVN-44-K53",
        )
        service.import_template.return_value = template
        return service

    @pytest.fixture
    def controller(self, mock_service):
        """Создаёт контроллер с мок сервисом и мок View."""
        ctrl = TemplateController(service=mock_service)
        ctrl.register_view("import_status", lambda _id, data: None)
        ctrl.register_view("export_status", lambda _id, data: None)
        return ctrl

    def test_on_import_template_with_path(self, controller, mock_service):
        """Импорт с указанием пути."""
        path = Path("/tmp/template.fxstpl")
        result = controller.on_import_template(source_path=path)
        assert result is True
        mock_service.import_template.assert_called_once_with(path)

    def test_on_import_template_opens_dialog_when_no_path(self, controller, mock_service):
        """Открывает диалог при отсутствии пути."""
        with patch(
            "src.gui.controllers.template_controller.filedialog.askopenfilename",
            return_value="/tmp/template.fxstpl",
        ):
            result = controller.on_import_template()
        assert result is True
        mock_service.import_template.assert_called_once_with(Path("/tmp/template.fxstpl"))

    def test_on_import_template_cancel_returns_false(self, controller, mock_service):
        """Возвращает False при отмене диалога."""
        with patch(
            "src.gui.controllers.template_controller.filedialog.askopenfilename",
            return_value="",
        ):
            result = controller.on_import_template()
        assert result is False
        mock_service.import_template.assert_not_called()

    def test_on_import_template_invalid_extension(self, controller, mock_service):
        """Возвращает False при неверном расширении."""
        path = Path("/tmp/template.txt")
        result = controller.on_import_template(source_path=path)
        assert result is False
        mock_service.import_template.assert_not_called()

    def test_on_import_template_file_not_found(self, controller, mock_service):
        """Обрабатывает FileNotFoundError."""
        mock_service.import_template.side_effect = FileNotFoundError("not found")
        path = Path("/tmp/template.fxstpl")
        result = controller.on_import_template(source_path=path)
        assert result is False

    def test_on_import_template_permission_error(self, controller, mock_service):
        """Обрабатывает PermissionError."""
        mock_service.import_template.side_effect = PermissionError("denied")
        path = Path("/tmp/template.fxstpl")
        result = controller.on_import_template(source_path=path)
        assert result is False

    def test_on_import_template_value_error(self, controller, mock_service):
        """Обрабатывает ValueError."""
        mock_service.import_template.side_effect = ValueError("invalid")
        path = Path("/tmp/template.fxstpl")
        result = controller.on_import_template(source_path=path)
        assert result is False


class TestTemplateControllerExport:
    """Тесты экспорта шаблона."""

    @pytest.fixture
    def mock_service(self):
        """Мок TemplateManager."""
        service = MagicMock()
        return service

    @pytest.fixture
    def controller(self, mock_service):
        """Создаёт контроллер с мок сервисом и мок View."""
        ctrl = TemplateController(service=mock_service)
        ctrl.register_view("import_status", lambda _id, data: None)
        ctrl.register_view("export_status", lambda _id, data: None)
        return ctrl

    def test_on_export_template_with_path(self, controller, mock_service):
        """Экспорт с указанием пути и ID."""
        dest = Path("/tmp/template.fxstpl")
        result = controller.on_export_template(template_id="tpl-123", dest_path=dest)
        assert result is True
        mock_service.export_template.assert_called_once_with("tpl-123", dest)

    def test_on_export_template_opens_dialog_when_no_path(self, controller, mock_service):
        """Открывает диалог при отсутствии пути."""
        with patch(
            "src.gui.controllers.template_controller.filedialog.asksaveasfilename",
            return_value="/tmp/template.fxstpl",
        ):
            result = controller.on_export_template(template_id="tpl-123")
        assert result is True
        mock_service.export_template.assert_called_once_with(
            "tpl-123", Path("/tmp/template.fxstpl")
        )

    def test_on_export_template_cancel_returns_false(self, controller, mock_service):
        """Возвращает False при отмене диалога."""
        with patch(
            "src.gui.controllers.template_controller.filedialog.asksaveasfilename",
            return_value="",
        ):
            result = controller.on_export_template(template_id="tpl-123")
        assert result is False
        mock_service.export_template.assert_not_called()

    def test_on_export_template_no_id_returns_false(self, controller, mock_service):
        """Возвращает False при отсутствии template_id."""
        result = controller.on_export_template()
        assert result is False
        mock_service.export_template.assert_not_called()

    def test_on_export_template_file_not_found(self, controller, mock_service):
        """Обрабатывает FileNotFoundError."""
        mock_service.export_template.side_effect = FileNotFoundError("not found")
        dest = Path("/tmp/template.fxstpl")
        result = controller.on_export_template(template_id="tpl-123", dest_path=dest)
        assert result is False

    def test_on_export_template_permission_error(self, controller, mock_service):
        """Обрабатывает PermissionError."""
        mock_service.export_template.side_effect = PermissionError("denied")
        dest = Path("/tmp/template.fxstpl")
        result = controller.on_export_template(template_id="tpl-123", dest_path=dest)
        assert result is False

    def test_on_export_template_value_error(self, controller, mock_service):
        """Обрабатывает ValueError."""
        mock_service.export_template.side_effect = ValueError("invalid")
        dest = Path("/tmp/template.fxstpl")
        result = controller.on_export_template(template_id="tpl-123", dest_path=dest)
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
