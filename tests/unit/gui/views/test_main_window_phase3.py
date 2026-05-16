# -*- coding: utf-8 -*-
"""Тесты для MainWindow Phase 3 (ModeManager, AuthOverlay, HealthCheck).

Version: 1.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, PropertyMock, call, patch

import pytest

if TYPE_CHECKING:
    from collections.abc import Generator

try:
    import tkinter as tk

    from src.gui.security.mode_manager import ModeManager
    from src.gui.views.main_window import APP_NAME, MainWindow

    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False


@pytest.fixture(autouse=True)
def reset_singleton() -> Generator[None, None, None]:
    """Сброс ModeManager singleton перед каждым тестом."""
    if TKINTER_AVAILABLE:
        ModeManager.reset_instance()
    yield
    if TKINTER_AVAILABLE:
        ModeManager.reset_instance()


@pytest.fixture(autouse=True)
def no_auth_window() -> Generator[None, None, None]:
    """Отключает auth window для избежания deadlock в headless тестах."""
    with patch.object(MainWindow, "_check_session_and_auth", lambda self: None):
        yield


@pytest.fixture
def mock_controller() -> MagicMock:
    """Создание мока контроллера."""
    mock = MagicMock()
    mock.get_auth_service.return_value = MagicMock()
    mock.dispatch.return_value = None
    return mock


@pytest.fixture
def mock_health_checker() -> MagicMock:
    """Создание мока HealthChecker."""
    from src.security.monitoring.models import (
        HealthCheckReport,
        HealthCheckResult,
        HealthCheckStatus,
    )

    mock = MagicMock()
    mock.run_critical.return_value = HealthCheckReport(
        checks=[HealthCheckResult.healthy("entropy")],
        overall_status=HealthCheckStatus.HEALTHY,
    )
    mock.run_all.return_value = HealthCheckReport(
        checks=[HealthCheckResult.healthy("entropy")],
        overall_status=HealthCheckStatus.HEALTHY,
    )
    return mock


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMainWindowStartupHealthCheck:
    """Тесты Health Check при старте."""

    def test_startup_health_check_success(self, mock_controller: MagicMock) -> None:
        """Проверка успешного Health Check при старте."""
        from src.security.monitoring.models import (
            HealthCheckReport,
            HealthCheckResult,
            HealthCheckStatus,
        )

        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar") as mock_string_var,
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
            patch(
                "src.security.monitoring.health_checker.HealthChecker"
            ) as mock_health_checker_cls,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_string_var_instance = MagicMock()
            mock_string_var_instance.get.return_value = "normal"
            mock_string_var.return_value = mock_string_var_instance

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            mock_health_instance = MagicMock()
            mock_health_instance.run_critical.return_value = HealthCheckReport(
                checks=[HealthCheckResult.healthy("entropy")],
                overall_status=HealthCheckStatus.HEALTHY,
            )
            mock_health_checker_cls.return_value = mock_health_instance

            with (
                patch.object(MainWindow, "_create_menubar"),
                patch.object(MainWindow, "_create_main_layout"),
                patch.object(MainWindow, "_create_main_toolbar"),
                patch.object(MainWindow, "_show_welcome_toast"),
                patch.object(MainWindow, "_run_startup_health_check") as mock_health,
            ):

                window = MainWindow(controller=mock_controller)
                window.initialize()

                # Проверяем что initialize вызвал _run_startup_health_check
                mock_health.assert_called_once()

    def test_startup_health_check_failure(self, mock_controller: MagicMock) -> None:
        """Проверка Health Check с ошибками при старте."""
        from src.security.monitoring.models import (
            HealthCheckReport,
            HealthCheckResult,
            HealthCheckStatus,
        )

        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
            patch(
                "src.security.monitoring.health_checker.HealthChecker"
            ) as mock_health_checker_cls,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            mock_health_instance = MagicMock()
            mock_health_instance.run_critical.return_value = HealthCheckReport(
                checks=[HealthCheckResult.unhealthy("entropy", "Low entropy")],
                overall_status=HealthCheckStatus.UNHEALTHY,
            )
            mock_health_checker_cls.return_value = mock_health_instance

            # Проверяем логику _run_startup_health_check
            window = MainWindow(controller=mock_controller)
            window._root = mock_root
            window._toast_service = mock_toast_instance
            window._mode_manager = MagicMock()
            window._health_checker = mock_health_instance

            # Вызываем метод напрямую
            window._run_startup_health_check()

            # Проверяем что показан warning toast
            mock_toast_instance.show.assert_called()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMainWindowModeMenu:
    """Тесты меню режима."""

    def test_mode_menu_creation(self, mock_controller: MagicMock) -> None:
        """Проверка создания меню Mode."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar") as mock_string_var,
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
            patch("src.gui.security.mode_manager.ModeManager") as mock_mode_manager,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_string_var_instance = MagicMock()
            mock_string_var_instance.get.return_value = "normal"
            mock_string_var.return_value = mock_string_var_instance

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            mock_mode_mgr_instance = MagicMock()
            mock_mode_mgr_instance.get_current_mode.return_value = "normal"
            mock_mode_manager.return_value = mock_mode_mgr_instance

            with (
                patch.object(MainWindow, "_create_menubar") as mock_menubar,
                patch.object(MainWindow, "_create_main_layout"),
                patch.object(MainWindow, "_create_main_toolbar"),
                patch.object(MainWindow, "_show_welcome_toast"),
                patch.object(MainWindow, "_run_startup_health_check"),
            ):

                window = MainWindow(controller=mock_controller)
                window.initialize()

                # Проверяем что _mode_var создан (StringVar)
                assert window._mode_var is not None
                # Проверяем начальное значение
                assert window._mode_var.get() == "normal"


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMainWindowModeSwitching:
    """Тесты переключения режимов."""

    def test_mode_switch_to_special_show_auth_overlay(
        self, mock_controller: MagicMock, mock_health_checker: MagicMock
    ) -> None:
        """Проверка что при переходе в Special показывается AuthOverlay."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
            patch(
                "src.gui.dialogs.security_health_check_dialog.SecurityHealthCheckDialog"
            ) as mock_health_dialog,
            patch("src.gui.views.main_window.AuthOverlay") as mock_auth_overlay,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            mock_dialog_instance = MagicMock()
            mock_dialog_instance.show.return_value = True
            mock_health_dialog.return_value = mock_dialog_instance

            window = MainWindow(controller=mock_controller)
            window._root = mock_root
            window._toast_service = mock_toast_instance
            window._health_checker = mock_health_checker
            window._mode_manager = MagicMock()

            mock_auth_overlay_instance = MagicMock()
            mock_auth_overlay.return_value = mock_auth_overlay_instance

            with patch.object(window, "_show_auth_overlay") as mock_show_auth:
                # Вызываем переход в Special Mode
                window._on_mode_special()

                # Проверяем что SecurityHealthCheckDialog был создан и показан
                mock_health_dialog.assert_called_once()
                mock_dialog_instance.show.assert_called_once()
                # Проверяем что показан AuthOverlay
                mock_show_auth.assert_called_once()

    def test_mode_switch_to_special_shows_health_dialog(
        self, mock_controller: MagicMock
    ) -> None:
        """Проверка что при отмене HealthCheckDialog показывается toast."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
            patch(
                "src.gui.dialogs.security_health_check_dialog.SecurityHealthCheckDialog"
            ) as mock_dialog,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            mock_dialog_instance = MagicMock()
            mock_dialog_instance.show.return_value = False
            mock_dialog.return_value = mock_dialog_instance

            window = MainWindow(controller=mock_controller)
            window._root = mock_root
            window._mode_manager = MagicMock()
            window._toast_service = mock_toast_instance

            window._on_mode_special()

            # Проверяем что показан SecurityHealthCheckDialog
            mock_dialog.assert_called_once()
            mock_dialog_instance.show.assert_called_once()
            # Проверяем что показан toast с сообщением об отмене
            mock_toast_instance.show.assert_called_once()

    def test_mode_switch_to_normal_confirm(self, mock_controller: MagicMock) -> None:
        """Проверка перехода в Normal Mode с подтверждением."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("tkinter.messagebox.askyesno") as mock_askyesno,
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            mock_askyesno.return_value = True

            window = MainWindow(controller=mock_controller)
            window._root = mock_root
            window._mode_manager = MagicMock()
            window._mode_manager.get_current_mode.return_value = "special"
            window._mode_manager.exit_special.return_value = True
            window._toast_service = mock_toast_instance
            window._statusbar = MagicMock()

            window._on_mode_normal()

            # Проверяем что был вызван messagebox
            mock_askyesno.assert_called_once()
            # Проверяем что вызван exit_special
            window._mode_manager.exit_special.assert_called_once_with(confirm=False)


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMainWindowStatusBarModeClick:
    """Тесты клика по Mode индикатору в StatusBar."""

    def test_statusbar_mode_click_normal_to_special(
        self, mock_controller: MagicMock
    ) -> None:
        """Проверка что клик на StatusBar в Normal Mode вызывает _on_mode_special."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            window = MainWindow(controller=mock_controller)
            window._root = mock_root
            window._mode_manager = MagicMock()
            window._mode_manager.get_current_mode.return_value = "normal"
            window._toast_service = mock_toast_instance

            # Мокаем _on_mode_special
            with patch.object(window, "_on_mode_special") as mock_special:
                window._on_statusbar_mode_click()

                # Проверяем что вызван _on_mode_special
                mock_special.assert_called_once()

    def test_statusbar_mode_click_special_to_normal(
        self, mock_controller: MagicMock
    ) -> None:
        """Проверка что клик на StatusBar в Special Mode вызывает _on_mode_normal."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            window = MainWindow(controller=mock_controller)
            window._root = mock_root
            window._mode_manager = MagicMock()
            window._mode_manager.get_current_mode.return_value = "special"
            window._toast_service = mock_toast_instance

            # Мокаем _on_mode_normal
            with patch.object(window, "_on_mode_normal") as mock_normal:
                window._on_statusbar_mode_click()

                # Проверяем что вызван _on_mode_normal
                mock_normal.assert_called_once()


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMainWindowUpdateModeUI:
    """Тесты обновления UI при смене режима."""

    def test_update_mode_ui_normal(self) -> None:
        """Проверка обновления UI в Normal Mode."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar") as mock_status,
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService"),
        ):

            mock_status_instance = MagicMock()
            mock_status.return_value = mock_status_instance

            window = MainWindow()
            window._statusbar = MagicMock()
            window._mode_var = MagicMock()

            window._update_mode_ui("normal")

            # Проверяем что StatusBar обновлён
            window._statusbar.set_mode_indicator.assert_called_once_with("normal")
            # Проверяем что меню обновлено
            window._mode_var.set.assert_called_once_with("normal")

    def test_update_mode_ui_special(self) -> None:
        """Проверка обновления UI в Special Mode."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar") as mock_status,
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService"),
        ):

            mock_status_instance = MagicMock()
            mock_status.return_value = mock_status_instance

            window = MainWindow()
            window._statusbar = MagicMock()
            window._mode_var = MagicMock()

            window._update_mode_ui("special")

            # Проверяем что StatusBar обновлён
            window._statusbar.set_mode_indicator.assert_called_once_with("special")
            # Проверяем что меню обновлено
            window._mode_var.set.assert_called_once_with("special")


@pytest.mark.skipif(not TKINTER_AVAILABLE, reason="Tkinter not available")
class TestMainWindowAuthCallbacks:
    """Тесты callbacks аутентификации."""

    def test_on_auth_success_updates_ui(self, mock_controller: MagicMock) -> None:
        """Проверка что _on_auth_success обновляет UI."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            window = MainWindow(controller=mock_controller)
            window._root = mock_root
            window._toast_service = mock_toast_instance
            window._statusbar = MagicMock()
            window._mode_var = MagicMock()
            window._auth_overlay = MagicMock()

            with patch.object(window, "_update_mode_ui") as mock_update:
                window._on_auth_success()

                # Проверяем что AuthOverlay скрыт
                window._auth_overlay.hide.assert_called_once()
                # Проверяем что UI обновлен
                mock_update.assert_called_once_with("special")
                # Проверяем что показан success toast
                mock_toast_instance.show.assert_called_once()

    def test_on_auth_cancel_cleans_up(self, mock_controller: MagicMock) -> None:
        """Проверка что _on_auth_cancel очищает данные."""
        with (
            patch("tkinter.Tk") as mock_tk,
            patch("tkinter.StringVar"),
            patch("src.gui.views.main_window.MainLayout"),
            patch("src.gui.views.main_window.StatusBar"),
            patch("src.gui.views.main_window.SideBar"),
            patch("src.gui.views.main_window.CardFileTabBar"),
            patch("src.gui.views.main_window.DocumentView"),
            patch("src.gui.services.toast_service.ToastService") as mock_toast_service,
        ):

            mock_root = MagicMock()
            mock_root.winfo_exists.return_value = True
            mock_root.after = MagicMock()
            mock_tk.return_value = mock_root

            mock_toast_instance = MagicMock()
            mock_toast_service.return_value = mock_toast_instance

            window = MainWindow(controller=mock_controller)
            window._root = mock_root
            window._toast_service = mock_toast_instance
            window._mode_manager = MagicMock()
            window._auth_overlay = MagicMock()

            with patch.object(window, "_update_mode_ui") as mock_update:
                window._on_auth_cancel()

                # Проверяем что credentials очищены
                window._auth_overlay.wipe_credentials.assert_called_once()
                # Проверяем что AuthOverlay скрыт
                window._auth_overlay.hide.assert_called_once()
                # Проверяем что вызван exit_special
                window._mode_manager.exit_special.assert_called_once_with(confirm=False)
                # Проверяем что UI обновлен
                mock_update.assert_called_once_with("normal")


__all__ = [
    "TestMainWindowStartupHealthCheck",
    "TestMainWindowModeMenu",
    "TestMainWindowModeSwitching",
    "TestMainWindowStatusBarModeClick",
    "TestMainWindowUpdateModeUI",
    "TestMainWindowAuthCallbacks",
]
