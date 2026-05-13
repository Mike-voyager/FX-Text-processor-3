"""Тесты ClipboardService.

Module: tests/unit/services/test_clipboard_service.py
"""

from __future__ import annotations

from typing import List, Optional
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from src.services.clipboard_service import (
    ClipboardBackendProtocol,
    ClipboardData,
    ClipboardEntry,
    ClipboardFormat,
    ClipboardService,
    CopyResult,
    PasteResult,
)


# ---------------------------------------------------------------------------
# Моки
# ---------------------------------------------------------------------------


class MockClipboardBackend:
    """Мок системного буфера обмена."""

    def __init__(self) -> None:
        self._text: Optional[str] = None
        self._data: dict[str, bytes] = {}

    def get_text(self) -> Optional[str]:
        return self._text

    def set_text(self, text: str) -> bool:
        self._text = text
        return True

    def get_formats(self) -> List[str]:
        return list(self._data.keys())

    def get_data(self, format: str) -> Optional[bytes]:
        return self._data.get(format)

    def set_data(self, format: str, data: bytes) -> bool:
        self._data[format] = data
        return True


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture
def backend() -> MockClipboardBackend:
    """Мок бэкенда буфера обмена."""
    return MockClipboardBackend()


@pytest.fixture
def clipboard(backend: MockClipboardBackend) -> ClipboardService:
    """Сервис буфера обмена с бэкендом."""
    return ClipboardService(backend=backend, history_size=5)


@pytest.fixture
def clipboard_no_backend() -> ClipboardService:
    """Сервис буфера обмена без бэкенда."""
    return ClipboardService(backend=None, history_size=5)


# ---------------------------------------------------------------------------
# Тесты текста
# ---------------------------------------------------------------------------


class TestTextOperations:
    """Тесты операций с текстом."""

    def test_copy_text_success(self, clipboard: ClipboardService) -> None:
        """Тест успешного копирования текста."""
        result = clipboard.copy_text("Hello, World!")

        assert result.success
        assert result.content == "Hello, World!"
        assert clipboard.has_content
        assert clipboard.current_format == ClipboardFormat.TEXT

    def test_copy_text_empty(self, clipboard: ClipboardService) -> None:
        """Тест копирования пустого текста."""
        result = clipboard.copy_text("")

        assert not result.success
        assert "пустой" in (result.error or "").lower()

    def test_paste_text_success(self, clipboard: ClipboardService) -> None:
        """Тест вставки текста."""
        clipboard.copy_text("Test text")
        text = clipboard.paste_text()

        assert text == "Test text"

    def test_paste_text_empty(self, clipboard_no_backend: ClipboardService) -> None:
        """Тест вставки из пустого буфера."""
        text = clipboard_no_backend.paste_text()

        assert text is None

    def test_copy_text_with_backend(
        self,
        clipboard: ClipboardService,
        backend: MockClipboardBackend,
    ) -> None:
        """Тест синхронизации с системным буфером."""
        clipboard.copy_text("Sync test")

        assert backend.get_text() == "Sync test"

    def test_paste_text_from_backend(
        self,
        clipboard: ClipboardService,
        backend: MockClipboardBackend,
    ) -> None:
        """Тест вставки из системного буфера."""
        backend.set_text("From system")

        text = clipboard.paste_text()

        assert text == "From system"


# ---------------------------------------------------------------------------
# Тесты истории
# ---------------------------------------------------------------------------


class TestHistory:
    """Тесты истории буфера обмена."""

    def test_history_add(self, clipboard: ClipboardService) -> None:
        """Тест добавления в историю."""
        clipboard.copy_text("First")
        clipboard.copy_text("Second")
        clipboard.copy_text("Third")

        history = clipboard.get_history()

        assert len(history) == 3
        assert history[0].description == "Текст (5 символов)"

    def test_history_limit(self, clipboard: ClipboardService) -> None:
        """Тест лимита истории."""
        for i in range(10):
            clipboard.copy_text(f"Text {i}")

        history = clipboard.get_history()
        assert len(history) <= 5

    def test_history_no_duplicates(self, clipboard: ClipboardService) -> None:
        """Тест отсутствия дубликатов в истории."""
        clipboard.copy_text("Same")
        clipboard.copy_text("Same")
        clipboard.copy_text("Same")

        history = clipboard.get_history()
        descriptions = [e.description for e in history]

        assert descriptions.count("Текст (4 символа)") <= 1

    def test_history_pin(self, clipboard: ClipboardService) -> None:
        """Тест закрепления записи."""
        clipboard.copy_text("Important")
        clipboard.pin_entry(0)

        pinned = clipboard.get_pinned()

        assert len(pinned) == 1
        assert pinned[0].data.content == "Important"

    def test_history_clear(self, clipboard: ClipboardService) -> None:
        """Тест очистки истории."""
        clipboard.copy_text("Text 1")
        clipboard.copy_text("Text 2")
        clipboard.copy_text("Text 3")

        count = clipboard.clear_history()

        assert count == 3
        assert clipboard.history_count == 0

    def test_clear_all(self, clipboard: ClipboardService) -> None:
        """Тест очистки буфера и истории."""
        clipboard.copy_text("Test")
        clipboard.clear_all()

        assert not clipboard.has_content
        assert clipboard.history_count == 0


# ---------------------------------------------------------------------------
# Тесты параграфов
# ---------------------------------------------------------------------------


class TestParagraphOperations:
    """Тесты операций с параграфами."""

    def test_copy_paragraphs_empty(self, clipboard: ClipboardService) -> None:
        """Тест копирования пустого списка параграфов."""
        result = clipboard.copy_paragraphs([])

        assert not result.success
        assert "пустой" in (result.error or "").lower()

    def test_copy_paragraphs_success(self, clipboard: ClipboardService) -> None:
        """Тест успешного копирования параграфов."""
        # Создаём мок-параграфы
        para1 = MagicMock()
        para1.get_text.return_value = "First paragraph"
        para2 = MagicMock()
        para2.get_text.return_value = "Second paragraph"

        result = clipboard.copy_paragraphs([para1, para2])

        assert result.success
        assert clipboard.current_format == ClipboardFormat.PARAGRAPHS

    def test_paste_paragraphs_empty(self, clipboard: ClipboardService) -> None:
        """Тест вставки параграфов из пустого буфера."""
        paragraphs = clipboard.paste_paragraphs()

        assert paragraphs is None


# ---------------------------------------------------------------------------
# Тесты runs
# ---------------------------------------------------------------------------


class TestRunOperations:
    """Тесты операций с runs."""

    def test_copy_runs_empty(self, clipboard: ClipboardService) -> None:
        """Тест копирования пустого списка runs."""
        result = clipboard.copy_runs([])

        assert not result.success
        assert "пустой" in (result.error or "").lower()

    def test_copy_runs_success(self, clipboard: ClipboardService) -> None:
        """Тест успешного копирования runs."""
        # Создаём мок-runs
        run1 = MagicMock()
        run1.text = "First "
        run2 = MagicMock()
        run2.text = "Second"

        result = clipboard.copy_runs([run1, run2])

        assert result.success
        assert clipboard.current_format == ClipboardFormat.RUNS

    def test_paste_runs_empty(self, clipboard: ClipboardService) -> None:
        """Тест вставки runs из пустого буфера."""
        runs = clipboard.paste_runs()

        assert runs is None


# ---------------------------------------------------------------------------
# Тесты cut
# ---------------------------------------------------------------------------


class TestCutOperations:
    """Тесты операций вырезания."""

    def test_cut_text(self, clipboard: ClipboardService) -> None:
        """Тест вырезания текста."""
        result = clipboard.cut_text("Cut text")

        assert result.success
        assert result.content == "Cut text"
        assert clipboard.has_content


# ---------------------------------------------------------------------------
# Тесты свойств
# ---------------------------------------------------------------------------


class TestProperties:
    """Тесты свойств."""

    def test_has_content_false(self, clipboard: ClipboardService) -> None:
        """Тест has_content без содержимого."""
        assert not clipboard.has_content

    def test_has_content_true(self, clipboard: ClipboardService) -> None:
        """Тест has_content с содержимым."""
        clipboard.copy_text("Test")
        assert clipboard.has_content

    def test_current_format_none(self, clipboard: ClipboardService) -> None:
        """Тест current_format без содержимого."""
        assert clipboard.current_format is None

    def test_current_format_text(self, clipboard: ClipboardService) -> None:
        """Тест current_format с текстом."""
        clipboard.copy_text("Test")
        assert clipboard.current_format == ClipboardFormat.TEXT

    def test_history_count(self, clipboard: ClipboardService) -> None:
        """Тест history_count."""
        assert clipboard.history_count == 0

        clipboard.copy_text("Test 1")
        assert clipboard.history_count == 1

        clipboard.copy_text("Test 2")
        assert clipboard.history_count == 2