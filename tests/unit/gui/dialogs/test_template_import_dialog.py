# -*- coding: utf-8 -*-
"""Тесты для TemplateImportDialog.

Тестирует создание диалога импорта шаблонов,
ImportResult, TemplatePreviewPanel и валидацию.

Version: 1.0
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import MagicMock, patch

import pytest

TKINTER_AVAILABLE = False
TemplateImportDialog: Any = None
ImportResult: Any = None
TemplatePreviewPanel: Any = None
try:
    import tkinter as tk

    from src.gui.dialogs.template_import_dialog import (
        COLOR_BG,
        COLOR_ERROR,
        COLOR_SUCCESS,
        COLOR_WARNING,
        DIALOG_HEIGHT,
        DIALOG_WIDTH,
        ImportResult,
        TemplateImportDialog,
        TemplatePreviewPanel,
    )

    TKINTER_AVAILABLE = True
except (ImportError, AttributeError, OSError, RuntimeError):
    pass


pytestmark = pytest.mark.skipif(
    not TKINTER_AVAILABLE,
    reason="Tkinter недоступен",
)


class TestImportResult:
    """Тесты для ImportResult dataclass."""

    def test_success_result(self) -> None:
        """Тест создания успешного результата."""
        mock_template = MagicMock()
        mock_template.template_id = "test-123"
        result = ImportResult.success_result(
            template_id="test-123",
            template=mock_template,
        )
        assert result.success is True
        assert result.template_id == "test-123"
        assert result.template == mock_template
        assert result.error == ""

    def test_failure_result(self) -> None:
        """Тест создания результата с ошибкой."""
        result = ImportResult.failure_result("File not found")
        assert result.success is False
        assert result.error == "File not found"
        assert result.template_id == ""
        assert result.template is None

    def test_frozen(self) -> None:
        """Тест что ImportResult immutable."""
        result = ImportResult.failure_result("error")
        with pytest.raises(AttributeError):
            result.error = "new error"  # type: ignore[misc]


class TestTemplatePreviewPanel:
    """Тесты для TemplatePreviewPanel."""

    def test_constants(self) -> None:
        """Тест констант диалога."""
        assert DIALOG_WIDTH == 700
        assert DIALOG_HEIGHT == 550