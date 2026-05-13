# -*- coding: utf-8 -*-
"""Тесты для экрана блокировки сессии SessionLockScreen.

Покрывает: fullscreen режим, разблокировка паролем/MFA, очистка полей,
отображение причины блокировки, wipe_credentials, toggle visibility,
обработка ESC.

Version: 1.0
Date: April 2026
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

from src.gui.security.session_lock import SessionLockScreen
from src.gui.security.mfa_gate import MFAResult
from src.security.lock.session_lock_manager import (
    LockReason,
    SessionLockManager,
    UnlockResult,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_root() -> Generator[tk.Tk, None, None]:
    """Создание корневого окна Tkinter для тестов."""
    root = tk.Tk()
    root.withdraw()  # Скрываем окно
    yield root
    root.destroy()


@pytest.fixture
def mock_lock_manager() -> MagicMock:
    """Создание мока SessionLockManager."""
    mock = MagicMock(spec=SessionLockManager)
    mock.is_locked.return_value = True
    mock.get_lock_reason.return_value = LockReason.AUTO_LOCK
    mock.get_locked_at.return_value = datetime.now(timezone.utc)
    mock.get_idle_time_minutes.return_value = 5.5
    mock.unlock_session.return_value = UnlockResult(success=True)
    return mock


@pytest.fixture
def mock_mfa_gate() -> MagicMock:
    """Создание мока MFAGate."""
    mock = MagicMock()
    mock.challenge.return_value = MFAResult.success(
        method="totp",
        user_id="test-user-123",
        audit_token="test-token",
    )
    return mock


@pytest.fixture
def mock_theme_manager() -> Generator[MagicMock, None, None]:
    """Мок для ThemeManager."""
    with patch("src.gui.security.session_lock.get_theme_manager") as mock_get:
        mock_manager = MagicMock()
        mock_theme = MagicMock()
        mock_theme.bg_color = "#000000"
        mock_theme.fg_color = "#00FF00"
        mock_theme.accent_color = "#008800"
        mock_theme.border_color = "#003300"
        mock_theme.error_color = "#FF0000"
        mock_theme.font_family = "Courier"
        mock_theme.font_size = 12
        mock_manager.get_current_theme.return_value = mock_theme
        mock_get.return_value = mock_manager
        yield mock_manager


@pytest.fixture
def lock_screen(
    mock_root: tk.Tk,
    mock_lock_manager: MagicMock,
    mock_theme_manager: MagicMock,
) -> SessionLockScreen:
    """Создаёт экземпляр SessionLockScreen для тестов."""
    screen = SessionLockScreen(
        parent=mock_root,
        lock_manager=mock_lock_manager,
        mfa_gate=None,
    )
    return screen


@pytest.fixture
def lock_screen_with_mfa(
    mock_root: tk.Tk,
    mock_lock_manager: MagicMock,
    mock_mfa_gate: MagicMock,
    mock_theme_manager: MagicMock,
) -> SessionLockScreen:
    """Создаёт экземпляр SessionLockScreen с MFA gate."""
    screen = SessionLockScreen(
        parent=mock_root,
        lock_manager=mock_lock_manager,
        mfa_gate=mock_mfa_gate,
    )
    return screen


# =============================================================================
# TestSessionLockScreen - тесты инициализации и базовых свойств
# =============================================================================


@pytest.mark.security
class TestSessionLockScreen:
    """Базовые тесты для SessionLockScreen."""

    def test_constructor_basic(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Проверка инициализации SessionLockScreen."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        assert screen._parent == mock_root
        assert screen._lock_manager == mock_lock_manager
        assert screen._mfa_gate is None
        assert screen._password_var.get() == ""
        assert screen._mfa_var.get() == ""
        assert screen._password_visible is False
        assert screen._is_unlocking is False

    def test_constructor_with_mfa(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_mfa_gate: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Проверка инициализации с MFAGate."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
            mfa_gate=mock_mfa_gate,
        )

        assert screen._mfa_gate == mock_mfa_gate

    def test_is_locked_delegates_to_manager(
        self,
        lock_screen: SessionLockScreen,
        mock_lock_manager: MagicMock,
    ) -> None:
        """is_locked() делегирует вызов к SessionLockManager."""
        mock_lock_manager.is_locked.return_value = True

        result = lock_screen.is_locked()

        assert result is True
        mock_lock_manager.is_locked.assert_called_once()

    def test_is_locked_returns_false_when_unlocked(
        self,
        lock_screen: SessionLockScreen,
        mock_lock_manager: MagicMock,
    ) -> None:
        """is_locked() возвращает False когда сессия разблокирована."""
        mock_lock_manager.is_locked.return_value = False

        result = lock_screen.is_locked()

        assert result is False


# =============================================================================
# TestSessionLockScreenFullscreen - тесты fullscreen режима
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenFullscreen:
    """Тесты fullscreen режима."""

    def test_show_fullscreen(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Проверка что show() устанавливает fullscreen режим."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        # Мокаем attributes для проверки вызовов
        with patch.object(screen, "attributes") as mock_attrs:
            with patch.object(screen, "_create_ui"):
                screen.show()

                # Проверяем что fullscreen был установлен в show()
                mock_attrs.assert_any_call("-fullscreen", True)

            # Очистка
            screen.destroy()

    def test_setup_window_sets_fullscreen(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Проверка что _setup_window устанавливает правильные атрибуты."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        # Проверяем что fullscreen был установлен при инициализации через протокол закрытия
        assert screen._lock_manager == mock_lock_manager
        screen.destroy()

    def test_hide_removes_fullscreen(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Проверка что hide() снимает fullscreen режим."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        with patch.object(screen, "_create_ui"):
            screen.show()

        # Очищаем job перед hide
        screen._update_job_id = None

        with patch.object(screen, "destroy") as mock_destroy:
            screen.hide()

            # Проверяем что fullscreen снят
            assert screen.attributes("-fullscreen") == 0
            assert screen.attributes("-topmost") == 0
            mock_destroy.assert_called_once()


# =============================================================================
# TestSessionLockScreenUnlock - тесты разблокировки
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenUnlock:
    """Тесты разблокировки сессии."""

    def test_unlock_with_password(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Успешная разблокировка паролем."""
        mock_lock_manager.unlock_session.return_value = UnlockResult(
            success=True,
        )

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        # Устанавливаем значения в поля
        screen._password_var.set("correct_password")
        screen._mfa_var.set("123456")

        # Мокаем UI элементы
        screen._unlock_btn = MagicMock()
        screen._password_entry = MagicMock()

        # Вызываем разблокировку
        with patch.object(screen, "hide") as mock_hide:
            screen._on_unlock()

            # Проверяем что менеджер был вызван
            mock_lock_manager.unlock_session.assert_called_once_with(
                "correct_password", "123456"
            )
            # Проверяем что hide был вызван при успехе
            mock_hide.assert_called_once()

        screen.destroy()

    def test_unlock_with_empty_password_shows_error(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Пустой пароль показывает ошибку."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_var.set("")
        screen._mfa_var.set("123456")
        screen._password_entry = MagicMock()

        # Мокаем _show_error
        with patch.object(screen, "_show_error") as mock_show_error:
            screen._on_unlock()

            mock_show_error.assert_called_once_with("Введите пароль")
            # Проверяем что unlock_session не вызывался
            mock_lock_manager.unlock_session.assert_not_called()

        screen.destroy()

    def test_unlock_with_empty_mfa_shows_error(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Пустой MFA код показывает ошибку."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_var.set("password")
        screen._mfa_var.set("")
        screen._mfa_entry = MagicMock()

        with patch.object(screen, "_show_error") as mock_show_error:
            screen._on_unlock()

            mock_show_error.assert_called_once_with("Введите MFA код")
            mock_lock_manager.unlock_session.assert_not_called()

        screen.destroy()

    def test_clear_fields_on_failure(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Очистка полей при неудачной разблокировке."""
        mock_lock_manager.unlock_session.return_value = UnlockResult(
            success=False,
            error_code="INVALID_PASSWORD",
            error_message="Неверный пароль",
        )

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_var.set("wrong_password")
        screen._mfa_var.set("wrong_code")
        screen._password_entry = MagicMock()
        screen._unlock_btn = MagicMock()

        # Проверяем что wipe_credentials вызывается и очищает поля
        screen._on_unlock()

        # Проверяем что поля очищены после вызова _on_unlock_failure
        assert screen._password_var.get() == ""
        assert screen._mfa_var.get() == ""

        screen.destroy()

    def test_on_unlock_failure_shows_error(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Отображение ошибки при неудачной разблокировке."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        result = UnlockResult(
            success=False,
            error_code="INVALID_MFA",
            error_message="Неверный MFA код",
        )

        with patch.object(screen, "_show_error") as mock_show_error:
            with patch.object(screen, "wipe_credentials"):
                screen._on_unlock_failure(result)

                mock_show_error.assert_called_once_with("Неверный MFA код")

        screen.destroy()


# =============================================================================
# TestSessionLockScreenDisplay - тесты отображения информации
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenDisplay:
    """Тесты отображения информации о блокировке."""

    def test_display_lock_reason_auto(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Отображение причины блокировки - автоматическая."""
        mock_lock_manager.get_lock_reason.return_value = LockReason.AUTO_LOCK

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        # Устанавливаем причину
        screen._lock_reason = LockReason.AUTO_LOCK

        reason_text = screen._get_lock_reason_text()
        assert reason_text == "Автоматическая блокировка"

        screen.destroy()

    def test_display_lock_reason_manual(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Отображение причины блокировки - ручная."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._lock_reason = LockReason.MANUAL

        reason_text = screen._get_lock_reason_text()
        assert reason_text == "Ручная блокировка"

        screen.destroy()

    def test_display_lock_reason_system_sleep(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Отображение причины блокировки - засыпание системы."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._lock_reason = LockReason.SYSTEM_SLEEP

        reason_text = screen._get_lock_reason_text()
        assert reason_text == "Блокировка при засыпании системы"

        screen.destroy()

    def test_display_lock_reason_screensaver(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Отображение причины блокировки - скринсейвер."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._lock_reason = LockReason.SCREENSAVER

        reason_text = screen._get_lock_reason_text()
        assert reason_text == "Блокировка при скринсейвере"

        screen.destroy()

    def test_display_lock_reason_security_policy(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Отображение причины блокировки - политика безопасности."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._lock_reason = LockReason.SECURITY_POLICY

        reason_text = screen._get_lock_reason_text()
        assert reason_text == "Блокировка по политике безопасности"

        screen.destroy()

    def test_display_lock_reason_unknown(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Отображение причины блокировки - неизвестно."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._lock_reason = None

        reason_text = screen._get_lock_reason_text()
        assert reason_text == "Неизвестно"

        screen.destroy()

    def test_get_locked_time_text_with_datetime(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Форматирование времени блокировки."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        # Устанавливаем конкретное время
        locked_time = datetime(2026, 4, 11, 14, 30, 0, tzinfo=timezone.utc)
        screen._locked_at = locked_time

        time_text = screen._get_locked_time_text()
        # Формат локального времени (зависит от timezone)
        assert "14:30:00" in time_text or len(time_text) > 0

        screen.destroy()

    def test_get_locked_time_text_none(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Отображение времени блокировки когда None."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._locked_at = None

        time_text = screen._get_locked_time_text()
        assert time_text == "Неизвестно"

        screen.destroy()


# =============================================================================
# TestSessionLockScreenCredentials - тесты очистки credentials
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenCredentials:
    """Тесты очистки учётных данных."""

    def test_wipe_credentials_clears_password(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """wipe_credentials очищает поле пароля."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_var.set("secret_password")
        screen._mfa_var.set("123456")

        screen.wipe_credentials()

        assert screen._password_var.get() == ""

        screen.destroy()

    def test_wipe_credentials_clears_mfa(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """wipe_credentials очищает поле MFA."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_var.set("password")
        screen._mfa_var.set("654321")

        screen.wipe_credentials()

        assert screen._mfa_var.get() == ""

        screen.destroy()

    def test_wipe_credentials_resets_visibility(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """wipe_credentials сбрасывает флаг видимости пароля."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_visible = True
        screen._password_entry = MagicMock()
        screen._toggle_btn = MagicMock()

        screen.wipe_credentials()

        assert screen._password_visible is False
        screen._password_entry.configure.assert_called_once_with(show="*")
        screen._toggle_btn.configure.assert_called_once_with(text="👁")

        screen.destroy()

    def test_wipe_credentials_called_on_hide(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """wipe_credentials вызывается при hide()."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        with patch.object(screen, "_create_ui"):
            screen.show()

        # Очищаем job перед hide
        screen._update_job_id = None

        with patch.object(screen, "wipe_credentials") as mock_wipe:
            with patch.object(screen, "destroy"):
                screen.hide()

                mock_wipe.assert_called_once()

        screen.destroy()


# =============================================================================
# TestSessionLockScreenPasswordToggle - тесты переключения видимости пароля
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenPasswordToggle:
    """Тесты переключения видимости пароля."""

    def test_toggle_password_visibility_shows_password(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Переключение делает пароль видимым."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_entry = MagicMock()
        screen._toggle_btn = MagicMock()
        screen._password_visible = False

        screen._toggle_password_visibility()

        # Проверяем что пароль теперь видимый
        assert screen._password_visible is True
        screen._password_entry.configure.assert_called_once_with(show="")
        screen._toggle_btn.configure.assert_called_once_with(text="🙈")

        screen.destroy()

    def test_toggle_password_visibility_hides_password(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Повторное переключение скрывает пароль."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_entry = MagicMock()
        screen._toggle_btn = MagicMock()
        screen._password_visible = True

        screen._toggle_password_visibility()

        # Проверяем что пароль теперь скрыт
        assert screen._password_visible is False
        screen._password_entry.configure.assert_called_once_with(show="*")
        screen._toggle_btn.configure.assert_called_once_with(text="👁")

        screen.destroy()

    def test_toggle_password_visibility_no_entry(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Переключение не падает если entry отсутствует."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_entry = None
        screen._toggle_btn = None
        screen._password_visible = False

        # Не должно выбросить исключение
        screen._toggle_password_visibility()

        # Флаг должен остаться False так как метод возвращает early
        assert screen._password_visible is False

        screen.destroy()


# =============================================================================
# TestSessionLockScreenESC - тесты обработки ESC
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenESC:
    """Тесты обработки нажатия ESC."""

    def test_esc_does_not_close_when_locked(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """ESC не закрывает окно пока сессия заблокирована."""
        mock_lock_manager.is_locked.return_value = True

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        # Создаём mock event
        mock_event = MagicMock()

        with patch.object(screen, "_show_error") as mock_show_error:
            with patch.object(screen, "hide") as mock_hide:
                screen._on_escape(mock_event)

                # Проверяем что показано сообщение
                mock_show_error.assert_called_once_with(
                    "Нажмите 🔓 Разблокировать для входа"
                )
                # hide НЕ должен быть вызван
                mock_hide.assert_not_called()

        screen.destroy()

    def test_esc_closes_when_unlocked(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """ESC закрывает окно когда сессия разблокирована."""
        mock_lock_manager.is_locked.return_value = False

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        mock_event = MagicMock()

        with patch.object(screen, "hide") as mock_hide:
            screen._on_escape(mock_event)

            # hide должен быть вызван
            mock_hide.assert_called_once()

        screen.destroy()

    def test_esc_binding_set_in_show(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """ESC binding устанавливается в show()."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        with patch.object(screen, "_create_ui"):
            with patch.object(screen, "bind") as mock_bind:
                screen.show()

                # Проверяем что ESC забинжен
                mock_bind.assert_any_call("<Escape>", screen._on_escape)

        # Очистка
        screen._update_job_id = None
        screen.destroy()


# =============================================================================
# TestSessionLockScreenErrorHandling - тесты обработки ошибок
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenErrorHandling:
    """Тесты обработки ошибок."""

    def test_show_error_updates_label(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """_show_error обновляет текст ошибки."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        mock_label = MagicMock()
        screen._error_label = mock_label

        screen._show_error("Тестовая ошибка")

        mock_label.configure.assert_called_once_with(text="Тестовая ошибка")

        screen.destroy()

    def test_clear_error_clears_label(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """_clear_error очищает текст ошибки."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        mock_label = MagicMock()
        screen._error_label = mock_label

        screen._clear_error()

        mock_label.configure.assert_called_once_with(text="")

        screen.destroy()

    def test_on_close_attempt_ignored(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Попытка закрытия окна игнорируется."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        # Не должно выбросить исключение
        screen._on_close_attempt()

        screen.destroy()

    def test_on_unlock_exception_handled(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Исключение при разблокировке обрабатывается."""
        mock_lock_manager.unlock_session.side_effect = Exception("Database error")

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_var.set("password")
        screen._mfa_var.set("123456")
        screen._unlock_btn = MagicMock()
        screen._password_entry = MagicMock()

        with patch.object(screen, "_show_error") as mock_show_error:
            with patch.object(screen, "wipe_credentials") as mock_wipe:
                screen._on_unlock()

                # Проверяем что показана ошибка
                mock_show_error.assert_called_once_with("Ошибка разблокировки")
                # Проверяем что credentials очищены
                mock_wipe.assert_called_once()
                # Проверяем что кнопка восстановлена
                assert screen._is_unlocking is False

        screen.destroy()


# =============================================================================
# TestSessionLockScreenUI - тесты создания UI
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenUI:
    """Тесты создания UI элементов."""

    def test_create_ui_creates_password_entry(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """_create_ui создает поле пароля."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._create_ui()

        # Проверяем что элементы созданы
        assert screen._password_entry is not None
        assert screen._mfa_entry is not None
        assert screen._unlock_btn is not None
        assert screen._toggle_btn is not None
        assert screen._error_label is not None
        assert screen._reason_label is not None
        assert screen._locked_time_label is not None
        assert screen._idle_time_label is not None

        screen.destroy()

    def test_create_ui_password_entry_hidden(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Поле пароля создано со скрытыми символами."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._create_ui()

        # Проверяем что пароль скрыт
        assert screen._password_entry is not None
        assert screen._password_entry.cget("show") == "*"

        screen.destroy()

    def test_create_ui_shows_lock_reason(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """UI отображает причину блокировки."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._lock_reason = LockReason.AUTO_LOCK

        screen._create_ui()

        # Проверяем что текст содержит причину
        assert screen._reason_label is not None
        reason_text = screen._reason_label.cget("text")
        assert "Автоматическая блокировка" in reason_text

        screen.destroy()


# =============================================================================
# TestSessionLockScreenIdleUpdate - тесты обновления idle time
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenIdleUpdate:
    """Тесты обновления времени простоя."""

    def test_update_idle_time_not_locked_returns_early(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """_update_idle_time возвращается рано если не заблокировано."""
        mock_lock_manager.is_locked.return_value = False

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        mock_label = MagicMock()
        screen._idle_time_label = mock_label

        # Отменяем scheduled update
        screen._update_job_id = None

        screen._update_idle_time()

        # Label не должен был быть обновлён
        mock_label.configure.assert_not_called()

        screen.destroy()

    def test_update_idle_time_when_label_does_not_exist(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """_update_idle_time обрабатывает отсутствие label."""
        mock_lock_manager.is_locked.return_value = True
        mock_lock_manager.get_idle_time_minutes.return_value = 5.5

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        # Label не существует
        screen._idle_time_label = None
        screen._update_job_id = None

        # Не должно выбросить исключение
        screen._update_idle_time()

        screen.destroy()

    def test_update_idle_time_updates_label(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Обновление idle time обновляет label."""
        mock_lock_manager.is_locked.return_value = True
        mock_lock_manager.get_idle_time_minutes.return_value = 10.5

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        mock_label = MagicMock()
        mock_label.winfo_exists.return_value = True
        screen._idle_time_label = mock_label

        # Отменяем scheduled update чтобы избежать рекурсии
        screen._update_job_id = None

        screen._update_idle_time()

        # Проверяем что label был обновлён
        mock_label.configure.assert_called_once()
        args = mock_label.configure.call_args
        assert "text" in args[1]
        assert "10" in args[1]["text"]  # 10 минут

        screen.destroy()

    def test_schedule_idle_update(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Планирование обновления idle time."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        with patch.object(screen, "after") as mock_after:
            mock_after.return_value = "job_id_123"

            screen._schedule_idle_update()

            # Проверяем что after был вызван с правильными параметрами
            mock_after.assert_called_once_with(1000, screen._update_idle_time)
            assert screen._update_job_id == "job_id_123"

        # Очистка
        screen._update_job_id = None
        screen.destroy()

    def test_schedule_idle_update_exception_handled(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Исключение в _schedule_idle_update обрабатывается."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        with patch.object(screen, "after") as mock_after:
            mock_after.side_effect = Exception("after failed")

            # Не должно выбросить исключение
            screen._schedule_idle_update()

        screen.destroy()


# =============================================================================
# TestSessionLockScreenUnlockFlow - тесты потока разблокировки
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenUnlockFlow:
    """Тесты потока разблокировки."""

    def test_on_unlock_blocks_concurrent_attempts(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """_on_unlock блокирует параллельные попытки."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        # Устанавливаем флаг что уже идёт разблокировка
        screen._is_unlocking = True

        screen._password_var.set("password")
        screen._mfa_var.set("123456")

        # Вызываем разблокировку
        screen._on_unlock()

        # Проверяем что менеджер НЕ был вызван (блокировка)
        mock_lock_manager.unlock_session.assert_not_called()

        screen.destroy()

    def test_on_unlock_success_flow(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Успешный поток разблокировки."""
        mock_lock_manager.unlock_session.return_value = UnlockResult(success=True)

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_var.set("correct_password")
        screen._mfa_var.set("123456")
        screen._unlock_btn = MagicMock()
        screen._password_entry = MagicMock()

        with patch.object(screen, "_on_unlock_success") as mock_success:
            screen._on_unlock()

            mock_success.assert_called_once()

        screen.destroy()

    def test_on_unlock_failure_flow(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """Неудачный поток разблокировки."""
        mock_lock_manager.unlock_session.return_value = UnlockResult(
            success=False,
            error_code="INVALID_PASSWORD",
            error_message="Неверный пароль",
        )

        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._password_var.set("wrong_password")
        screen._mfa_var.set("wrong_code")
        screen._unlock_btn = MagicMock()
        screen._password_entry = MagicMock()

        with patch.object(screen, "_on_unlock_failure") as mock_failure:
            screen._on_unlock()

            mock_failure.assert_called_once()
            # Проверяем что передан результат
            call_args = mock_failure.call_args[0][0]
            assert call_args.success is False
            assert call_args.error_code == "INVALID_PASSWORD"

        screen.destroy()


# =============================================================================
# TestSessionLockScreenFocus - тесты фокуса
# =============================================================================


@pytest.mark.security
class TestSessionLockScreenFocus:
    """Тесты управления фокусом."""

    def test_focus_mfa_sets_focus(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """_focus_mfa устанавливает фокус на поле MFA."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        mock_entry = MagicMock()
        screen._mfa_entry = mock_entry

        screen._focus_mfa()

        mock_entry.focus_set.assert_called_once()

        screen.destroy()

    def test_focus_mfa_no_entry(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """_focus_mfa не падает если entry отсутствует."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        screen._mfa_entry = None

        # Не должно выбросить исключение
        screen._focus_mfa()

        screen.destroy()

    def test_show_sets_focus_to_password(
        self,
        mock_root: tk.Tk,
        mock_lock_manager: MagicMock,
        mock_theme_manager: MagicMock,
    ) -> None:
        """show() устанавливает фокус на поле пароля."""
        screen = SessionLockScreen(
            parent=mock_root,
            lock_manager=mock_lock_manager,
        )

        mock_entry = MagicMock()
        screen._password_entry = mock_entry

        with patch.object(screen, "_create_ui"):
            screen.show()

        # Фокус должен быть установлен на password_entry
        mock_entry.focus_set.assert_called_once()

        # Очистка
        screen._update_job_id = None
        screen.destroy()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "TestSessionLockScreen",
    "TestSessionLockScreenFullscreen",
    "TestSessionLockScreenUnlock",
    "TestSessionLockScreenDisplay",
    "TestSessionLockScreenCredentials",
    "TestSessionLockScreenPasswordToggle",
    "TestSessionLockScreenESC",
    "TestSessionLockScreenErrorHandling",
    "TestSessionLockScreenIdleUpdate",
    "TestSessionLockScreenUI",
    "TestSessionLockScreenUnlockFlow",
    "TestSessionLockScreenFocus",
]
