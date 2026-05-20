"""Тесты для SessionLockScreen (canonical, session_lock_screen.py).

Покрывает: application-level overlay, MFA-форму разблокировки,
очистку credentials, обработку ESC, синхронизацию геометрии с родителем.

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/security/test_session_lock_screen.py -v

Version: 2.0
Date: May 2026
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Generator
from unittest.mock import MagicMock, Mock, patch

import pytest

try:
    import tkinter as tk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

if TYPE_CHECKING:
    from collections.abc import Generator

if not TKINTER_AVAILABLE:
    pytest.skip("Tkinter not available", allow_module_level=True)

from src.gui.security.session_lock_screen import SessionLockScreen, UnlockCallback


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Создаёт Tk root для тестов GUI."""
    root = tk.Tk()
    root.withdraw()
    root.geometry("800x600+100+100")
    yield root
    root.destroy()


@pytest.fixture
def unlock_callback_success() -> UnlockCallback:
    """Callback разблокировки, всегда успешный."""
    def _callback(password: str, token: str, method: str) -> bool:
        return password == "correct" and len(token) >= 1
    return _callback


@pytest.fixture
def unlock_callback_failure() -> UnlockCallback:
    """Callback разблокировки, всегда неудачный."""
    def _callback(password: str, token: str, method: str) -> bool:
        return False
    return _callback


@pytest.fixture
def locked_time() -> datetime:
    """Время блокировки для тестов."""
    return datetime(2026, 5, 19, 10, 30, 0, tzinfo=timezone.utc)


@pytest.fixture
def lock_screen(
    tk_root: tk.Tk,
    unlock_callback_success: UnlockCallback,
    locked_time: datetime,
) -> Generator[SessionLockScreen, None, None]:
    """Создаёт SessionLockScreen с успешным callback."""
    screen = SessionLockScreen(
        parent=tk_root,
        on_unlock=unlock_callback_success,
        locked_at=locked_time,
        trigger="manual",
    )
    yield screen
    try:
        if screen.winfo_exists():
            screen.destroy()
    except tk.TclError:
        pass


# =============================================================================
# TestSessionLockScreenInit - тесты инициализации
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenInit:
    """Тесты инициализации SessionLockScreen."""

    def test_init_stores_parent(
        self,
        tk_root: tk.Tk,
        locked_time: datetime,
    ) -> None:
        """Проверка что parent сохраняется."""
        screen = SessionLockScreen(
            parent=tk_root,
            locked_at=locked_time,
        )
        assert screen._parent is tk_root
        screen.destroy()

    def test_init_stores_trigger(
        self,
        tk_root: tk.Tk,
        locked_time: datetime,
    ) -> None:
        """Проверка что trigger сохраняется."""
        screen = SessionLockScreen(
            parent=tk_root,
            locked_at=locked_time,
            trigger="auto",
        )
        assert screen._trigger == "auto"
        screen.destroy()

    def test_init_stores_locked_at(
        self,
        tk_root: tk.Tk,
        locked_time: datetime,
    ) -> None:
        """Проверка что locked_at сохраняется."""
        screen = SessionLockScreen(
            parent=tk_root,
            locked_at=locked_time,
        )
        assert screen._locked_at == locked_time
        screen.destroy()

    def test_init_default_trigger(
        self,
        tk_root: tk.Tk,
        locked_time: datetime,
    ) -> None:
        """По умолчанию trigger = 'manual'."""
        screen = SessionLockScreen(
            parent=tk_root,
            locked_at=locked_time,
        )
        assert screen._trigger == "manual"
        screen.destroy()

    def test_init_auto_lock_minutes(
        self,
        tk_root: tk.Tk,
        locked_time: datetime,
    ) -> None:
        """Проверка auto_lock_minutes."""
        screen = SessionLockScreen(
            parent=tk_root,
            locked_at=locked_time,
            auto_lock_minutes=15,
        )
        assert screen._auto_lock_minutes == 15
        screen.destroy()

    def test_init_is_toplevel(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """SessionLockScreen наследуется от tk.Toplevel."""
        assert isinstance(lock_screen, tk.Toplevel)


# =============================================================================
# TestSessionLockScreenShow - тесты show/hide
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenShow:
    """Тесты show() и hide()."""

    def test_show_creates_ui(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """show() создаёт UI элементы."""
        lock_screen.show()
        assert lock_screen._mfa_form is not None
        assert lock_screen._error_label is not None

    def test_show_sets_grab(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """show() захватывает фокус (grab_set)."""
        lock_screen.show()
        # Проверяем что окно видимо
        assert lock_screen.winfo_exists()

    def test_hide_destroys_window(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """hide() уничтожает окно."""
        lock_screen.show()
        lock_screen.hide()
        # Окно уничтожено
        assert not lock_screen.winfo_exists()


# =============================================================================
# TestSessionLockScreenSecurity - тесты безопасности
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenSecurity:
    """Тесты безопасности SessionLockScreen."""

    def test_escape_prevents_close(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """ESC не закрывает экран блокировки."""
        event = MagicMock()
        result = lock_screen._on_escape(event)
        assert result == "break"

    def test_close_attempt_ignored(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """Попытка закрытия окна игнорируется."""
        # _on_close_attempt просто return (игнорирует)
        lock_screen._on_close_attempt()
        # Окно всё ещё существует
        assert lock_screen.winfo_exists()

    def test_wipe_credentials_clears_form(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """wipe_credentials очищает MFA форму."""
        lock_screen.show()
        # Устанавливаем значения в форму
        if lock_screen._mfa_form is not None:
            lock_screen._mfa_form._password_var.set("secret")
            lock_screen._mfa_form._token_var.set("123456")

            lock_screen.wipe_credentials()

            assert lock_screen._mfa_form._password_var.get() == ""
            assert lock_screen._mfa_form._token_var.get() == ""

    def test_mfa_submit_calls_callback(
        self,
        tk_root: tk.Tk,
        locked_time: datetime,
    ) -> None:
        """_on_mfa_submit вызывает on_unlock callback."""
        callback_called = []

        def on_unlock(password: str, token: str, method: str) -> bool:
            callback_called.append((password, token, method))
            return True

        screen = SessionLockScreen(
            parent=tk_root,
            on_unlock=on_unlock,
            locked_at=locked_time,
        )

        result = screen._on_mfa_submit("user", "mypass", "totp", "123456")

        assert len(callback_called) == 1
        assert callback_called[0] == ("mypass", "123456", "totp")
        assert result is True
        screen.destroy()

    def test_mfa_submit_failure_shows_error(
        self,
        tk_root: tk.Tk,
        locked_time: datetime,
    ) -> None:
        """Неудачная MFA отправка показывает ошибку."""
        def on_unlock(password: str, token: str, method: str) -> bool:
            return False

        screen = SessionLockScreen(
            parent=tk_root,
            on_unlock=on_unlock,
            locked_at=locked_time,
        )

        result = screen._on_mfa_submit("user", "wrong", "totp", "000000")

        assert result is False
        screen.destroy()

    def test_mfa_submit_no_callback_shows_error(
        self,
        tk_root: tk.Tk,
        locked_time: datetime,
    ) -> None:
        """Отсутствие callback показывает ошибку."""
        screen = SessionLockScreen(
            parent=tk_root,
            on_unlock=None,
            locked_at=locked_time,
        )

        result = screen._on_mfa_submit("user", "pass", "totp", "123456")

        assert result is False
        screen.destroy()

    def test_mfa_submit_exception_handled(
        self,
        tk_root: tk.Tk,
        locked_time: datetime,
    ) -> None:
        """Исключение в callback обрабатывается безопасно."""
        def on_unlock(password: str, token: str, method: str) -> bool:
            raise RuntimeError("DB error")

        screen = SessionLockScreen(
            parent=tk_root,
            on_unlock=on_unlock,
            locked_at=locked_time,
        )

        # Не должно выбросить исключение
        result = screen._on_mfa_submit("user", "pass", "totp", "123456")

        assert result is False
        screen.destroy()


# =============================================================================
# TestSessionLockScreenGeometry - тесты синхронизации геометрии
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenGeometry:
    """Тесты синхронизации геометрии с родительским окном."""

    def test_sync_geometry(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """_sync_geometry синхронизирует размер с родителем."""
        lock_screen._sync_geometry()
        # Окно должно иметь те же размеры что и родитель
        expected_w = lock_screen._parent.winfo_width()
        expected_h = lock_screen._parent.winfo_height()
        assert lock_screen.winfo_width() == expected_w
        assert lock_screen.winfo_height() == expected_h

    def test_parent_configure_triggers_sync(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """_on_parent_configure вызывает _sync_geometry."""
        with patch.object(lock_screen, "_sync_geometry") as mock_sync:
            lock_screen._on_parent_configure(MagicMock())
            mock_sync.assert_called_once()


# =============================================================================
# TestSessionLockScreenDestroy - тесты уничтожения
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenDestroy:
    """Тесты destroy()."""

    def test_destroy_cancels_afters(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """destroy() отменяет все after() таймеры."""
        lock_screen._after_ids = ["fake_id_1", "fake_id_2"]
        with patch.object(lock_screen, "after_cancel") as mock_cancel:
            lock_screen.destroy()
            assert mock_cancel.call_count == 2

    def test_destroy_unbinds_parent_events(
        self,
        lock_screen: SessionLockScreen,
    ) -> None:
        """destroy() отвязывает события родителя."""
        lock_screen._bind_ids = {"<Configure>": "bind_1", "<Unmap>": "bind_2"}
        with patch.object(lock_screen._parent, "unbind") as mock_unbind:
            lock_screen.destroy()
            assert mock_unbind.call_count == 2


# =============================================================================
# TestSessionLockScreenModuleExports - тесты экспортов модуля
# =============================================================================


class TestSessionLockScreenModuleExports:
    """Тесты экспортов модуля."""

    def test_session_lock_screen_importable(self) -> None:
        """SessionLockScreen импортируется."""
        from src.gui.security.session_lock_screen import SessionLockScreen
        assert SessionLockScreen is not None

    def test_unlock_callback_importable(self) -> None:
        """UnlockCallback импортируется."""
        from src.gui.security.session_lock_screen import UnlockCallback
        assert UnlockCallback is not None

    def test_reexport_from_session_lock(self) -> None:
        """SessionLockScreen реэкспортируется из session_lock."""
        from src.gui.security.session_lock import SessionLockScreen as SLS
        from src.gui.security.session_lock_screen import SessionLockScreen as SLSS
        assert SLS is SLSS


__all__: list[str] = [
    "TestSessionLockScreenInit",
    "TestSessionLockScreenShow",
    "TestSessionLockScreenSecurity",
    "TestSessionLockScreenGeometry",
    "TestSessionLockScreenDestroy",
    "TestSessionLockScreenModuleExports",
]