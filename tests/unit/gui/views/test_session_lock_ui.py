"""Тесты для SessionLockScreen (UI_SPEC 9.2).

Покрывает: создание экрана блокировки, отображение UI,
очистку credentials, обработку событий.

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

try:
    import tkinter as tk

    from src.gui.security.session_lock_screen import SessionLockScreen

    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def no_grab() -> Generator[None, None, None]:
    """Отключает grab_set для избежания deadlock в headless тестах."""
    original = tk.Widget.grab_set
    tk.Widget.grab_set = lambda self: None  # type: ignore[method-assign]
    yield
    tk.Widget.grab_set = original  # type: ignore[method-assign]


@pytest.fixture
def mock_root() -> "Generator[tk.Tk, None, None]":
    """Создание корневого окна Tkinter для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_unlock_callback() -> MagicMock:
    """Mock callback для разблокировки."""
    return MagicMock(return_value=True)


# =============================================================================
# TestSessionLockScreen
# =============================================================================


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.security
class TestSessionLockScreen:
    """Тесты UI экрана блокировки сессии."""

    def test_creation(self, mock_root: tk.Tk, mock_unlock_callback: MagicMock) -> None:
        """Проверка создания SessionLockScreen."""
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=mock_unlock_callback,
            locked_at=datetime.now(),
            trigger="manual",
        )
        assert screen._parent is mock_root
        assert screen._on_unlock is mock_unlock_callback
        screen.destroy()

    def test_show_creates_ui(
        self, mock_root: tk.Tk, mock_unlock_callback: MagicMock
    ) -> None:
        """show() создаёт UI элементы."""
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=mock_unlock_callback,
            locked_at=datetime.now(),
            trigger="manual",
        )
        screen.show()

        assert screen._mfa_form is not None
        assert screen._error_label is not None
        assert screen._locked_info_label is not None
        assert screen._trigger_info_label is not None

        screen.destroy()

    def test_locked_info_displayed(
        self, mock_root: tk.Tk, mock_unlock_callback: MagicMock
    ) -> None:
        """Отображается время блокировки."""
        now = datetime.now()
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=mock_unlock_callback,
            locked_at=now,
            trigger="manual",
        )
        screen.show()

        info_text = screen._locked_info_label.cget("text")
        assert "Locked at:" in info_text

        screen.destroy()

    def test_trigger_info_displayed(
        self, mock_root: tk.Tk, mock_unlock_callback: MagicMock
    ) -> None:
        """Отображается причина блокировки."""
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=mock_unlock_callback,
            locked_at=datetime.now(),
            trigger="auto",
        )
        screen.show()

        trigger_text = screen._trigger_info_label.cget("text")
        assert "auto" in trigger_text

        screen.destroy()

    def test_auto_lock_label(
        self, mock_root: tk.Tk, mock_unlock_callback: MagicMock
    ) -> None:
        """Отображается auto-lock информация при необходимости."""
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=mock_unlock_callback,
            locked_at=datetime.now(),
            trigger="manual",
            auto_lock_minutes=15,
        )
        screen.show()

        assert screen._auto_lock_label is not None
        label_text = screen._auto_lock_label.cget("text")
        assert "15" in label_text

        screen.destroy()

    def test_wipe_credentials(
        self, mock_root: tk.Tk, mock_unlock_callback: MagicMock
    ) -> None:
        """wipe_credentials() очищает поля MFA."""
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=mock_unlock_callback,
            locked_at=datetime.now(),
            trigger="manual",
        )
        screen.show()

        with patch.object(screen._mfa_form, "wipe_credentials") as mock_wipe:
            screen.wipe_credentials()
            mock_wipe.assert_called_once()

        screen.destroy()

    def test_on_escape_returns_break(
        self, mock_root: tk.Tk, mock_unlock_callback: MagicMock
    ) -> None:
        """ESC возвращает 'break'."""
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=mock_unlock_callback,
            locked_at=datetime.now(),
            trigger="manual",
        )
        screen.show()

        result = screen._on_escape(None)
        assert result == "break"

        screen.destroy()

    def test_on_close_attempt_does_nothing(
        self, mock_root: tk.Tk, mock_unlock_callback: MagicMock
    ) -> None:
        """Попытка закрытия игнорируется."""
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=mock_unlock_callback,
            locked_at=datetime.now(),
            trigger="manual",
        )
        screen.show()

        # Should not raise
        screen._on_close_attempt()

        screen.destroy()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
@pytest.mark.security
class TestSessionLockScreenUnlock:
    """Тесты разблокировки."""

    def test_on_mfa_submit_calls_unlock_callback(
        self, mock_root: tk.Tk, mock_unlock_callback: MagicMock
    ) -> None:
        """MFA submit вызывает on_unlock callback."""
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=mock_unlock_callback,
            locked_at=datetime.now(),
            trigger="manual",
        )
        screen.show()

        result = screen._on_mfa_submit("user", "pass", "password", "")

        mock_unlock_callback.assert_called_once()
        assert result is True

        screen.destroy()

    def test_on_mfa_submit_no_callback_shows_error(self, mock_root: tk.Tk) -> None:
        """Без callback показывается ошибка."""
        screen = SessionLockScreen(
            parent=mock_root,
            on_unlock=None,
            locked_at=datetime.now(),
            trigger="manual",
        )
        screen.show()

        result = screen._on_mfa_submit("user", "pass", "password", "")

        assert result is False
        error_text = screen._error_label.cget("text")
        assert "not configured" in error_text or error_text != ""

        screen.destroy()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestSessionLockScreen",
    "TestSessionLockScreenUnlock",
]
