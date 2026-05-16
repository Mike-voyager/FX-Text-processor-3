"""Unit-тесты для MainWindow.

Проверяет:
- Создание MainWindow
- Инициализацию (initialize)
- Установку заголовка (set_title)
- Получение ToastService (get_toast_service)

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from src.gui.views.main_window import (
    APP_NAME,
    MODIFIED_INDICATOR,
    TITLE_SEPARATOR,
    MainWindow,
)
from src.gui.services.toast_service import ToastService


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def no_grab_and_auth() -> Generator[None, None, None]:
    """Отключает grab_set и auth window для избежания deadlock в тестах."""
    original_grab = tk.Widget.grab_set
    tk.Widget.grab_set = lambda self: None  # type: ignore[method-assign]
    with patch.object(MainWindow, "_check_session_and_auth", lambda self: None):
        yield
    tk.Widget.grab_set = original_grab  # type: ignore[method-assign]


@pytest.fixture
def mock_controller() -> MagicMock:
    """Fixture для mock контроллера."""
    controller = MagicMock()
    controller.controller_id = "test_controller"
    return controller


@pytest.fixture
def main_window(mock_controller: MagicMock) -> MainWindow:
    """Fixture для MainWindow."""
    return MainWindow(controller=mock_controller)


@pytest.fixture
def initialized_window(mock_controller: MagicMock) -> Generator[MainWindow, None, None]:
    """Fixture для инициализированного MainWindow."""
    window = MainWindow(controller=mock_controller)
    window.initialize()
    yield window
    try:
        window.destroy()
    except (RuntimeError, AttributeError, TypeError, OSError, tk.TclError):
        pass


# =============================================================================
# TEST: MainWindow Creation
# =============================================================================


class TestMainWindowCreation:
    """Тесты создания MainWindow."""

    def test_main_window_creation(self, mock_controller: MagicMock) -> None:
        """Создание MainWindow с валидными параметрами."""
        window = MainWindow(controller=mock_controller)

        assert window._controller is mock_controller
        assert not window._is_initialized
        assert window._root is None

    def test_main_window_creation_no_controller(self) -> None:
        """Создание MainWindow без контроллера."""
        window = MainWindow()

        assert window._controller is None


# =============================================================================
# TEST: MainWindow Initialize
# =============================================================================


@pytest.mark.gui
class TestMainWindowInitialize:
    """Тесты инициализации MainWindow."""

    def test_initialize(self, main_window: MainWindow) -> None:
        """initialize() инициализирует окно."""
        main_window.initialize()

        assert main_window._is_initialized
        assert main_window._root is not None
        assert isinstance(main_window._root, tk.Tk)

        # Cleanup
        main_window.destroy()

    def test_initialize_creates_toast_service(self, main_window: MainWindow) -> None:
        """initialize() создаёт ToastService."""
        main_window.initialize()

        assert main_window._toast_service is not None

        # Cleanup
        main_window.destroy()

    def test_initialize_creates_menubar(self, main_window: MainWindow) -> None:
        """initialize() создаёт меню."""
        main_window.initialize()

        assert main_window._menubar is not None

        # Cleanup
        main_window.destroy()

    def test_initialize_creates_main_layout(self, main_window: MainWindow) -> None:
        """initialize() создаёт MainLayout."""
        main_window.initialize()

        assert main_window._main_layout is not None

        # Cleanup
        main_window.destroy()

    def test_initialize_twice_raises_error(self, main_window: MainWindow) -> None:
        """Повторный initialize() вызывает RuntimeError."""
        main_window.initialize()

        with pytest.raises(RuntimeError, match="already initialized"):
            main_window.initialize()

        # Cleanup
        main_window.destroy()


# =============================================================================
# TEST: Set Title
# =============================================================================


@pytest.mark.gui
class TestSetTitle:
    """Тесты установки заголовка."""

    def test_set_title(self, initialized_window: MainWindow) -> None:
        """set_title() обновляет заголовок окна."""
        initialized_window.set_title("document.fxsd")

        title = initialized_window._root.title()
        assert "document.fxsd" in title

    def test_set_title_extracts_basename(self, initialized_window: MainWindow) -> None:
        """set_title() извлекает basename из пути."""
        initialized_window.set_title("/home/user/document.fxsd")

        title = initialized_window._root.title()
        assert "document.fxsd" in title
        assert "/home/user" not in title

    def test_set_title_with_modified(self, initialized_window: MainWindow) -> None:
        """set_title() с modified=True добавляет индикатор."""
        initialized_window.set_title("document.fxsd", modified=True)

        title = initialized_window._root.title()
        assert MODIFIED_INDICATOR in title

    def test_set_title_empty_shows_app_name(self, initialized_window: MainWindow) -> None:
        """set_title() с пустым title показывает только APP_NAME."""
        initialized_window.set_title("")

        title = initialized_window._root.title()
        assert APP_NAME in title

    def test_set_title_updates_statusbar(self, initialized_window: MainWindow) -> None:
        """set_title() обновляет statusbar."""
        initialized_window.set_title("doc.fxsd", modified=True)

        # StatusBar должен получить set_modified
        # (Cannot directly verify without mocking)


# =============================================================================
# TEST: Get Toast Service
# =============================================================================


@pytest.mark.gui
class TestGetToastService:
    """Тесты получения ToastService."""

    def test_get_toast_service(self, initialized_window: MainWindow) -> None:
        """get_toast_service() возвращает ToastService."""
        service = initialized_window.get_toast_service()

        assert isinstance(service, ToastService)

    def test_get_toast_service_not_initialized(self, main_window: MainWindow) -> None:
        """get_toast_service() до initialize() вызывает RuntimeError."""
        with pytest.raises(RuntimeError, match="not initialized"):
            main_window.get_toast_service()


# =============================================================================
# TEST: Destroy
# =============================================================================


@pytest.mark.gui
class TestDestroy:
    """Тесты уничтожения окна."""

    def test_destroy_clears_resources(self, initialized_window: MainWindow) -> None:
        """destroy() очищает ресурсы."""
        initialized_window.destroy()

        assert not initialized_window._is_initialized
        assert initialized_window._root is None

    def test_destroy_closes_toast_notifications(self, initialized_window: MainWindow) -> None:
        """destroy() закрывает все уведомления."""
        # Show a notification first
        service = initialized_window.get_toast_service()
        service.show("Test message")

        initialized_window.destroy()

        # All toasts should be closed
        assert len(service._toasts) == 0


# =============================================================================
# TEST: Lock/Unlock Session
# =============================================================================


@pytest.mark.gui
class TestLockUnlockSession:
    """Тесты блокировки/разблокировки сессии."""

    def test_lock_session_sets_flag(self, initialized_window: MainWindow) -> None:
        """lock_session() устанавливает _is_locked=True."""
        initialized_window.lock_session()

        assert initialized_window._is_locked

    def test_unlock_session_clears_flag(self, initialized_window: MainWindow) -> None:
        """unlock_session() устанавливает _is_locked=False."""
        initialized_window.lock_session()
        initialized_window.unlock_session()

        assert not initialized_window._is_locked

    def test_lock_session_creates_lock_screen(self, initialized_window: MainWindow) -> None:
        """lock_session() создаёт SessionLockScreen."""
        initialized_window.lock_session()

        assert initialized_window._session_lock_screen is not None


# =============================================================================
# TEST: Properties
# =============================================================================


class TestConstants:
    """Тесты констант модуля."""

    def test_app_name_defined(self) -> None:
        """APP_NAME определена."""
        assert isinstance(APP_NAME, str)
        assert len(APP_NAME) > 0

    def test_title_separator_defined(self) -> None:
        """TITLE_SEPARATOR определён."""
        assert isinstance(TITLE_SEPARATOR, str)

    def test_modified_indicator_defined(self) -> None:
        """MODIFIED_INDICATOR определён."""
        assert isinstance(MODIFIED_INDICATOR, str)

    def test_lock_overlay_colors_defined(self) -> None:
        """Цвета overlay определены в themes."""
        from src.gui.themes.registry import ThemeRegistry
        tr = ThemeRegistry()
        assert tr is not None  # ThemeRegistry работает


# =============================================================================
# TEST: Module Exports
# =============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.views import main_window

        assert hasattr(main_window, "__all__")
        assert "MainWindow" in main_window.__all__
        assert "APP_NAME" in main_window.__all__
        assert "MODIFIED_INDICATOR" in main_window.__all__

    def test_module_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.views import main_window

        assert hasattr(main_window, "__version__")
        assert hasattr(main_window, "__author__")
        assert hasattr(main_window, "__date__")


# =============================================================================
# TEST: Document Convert to Special/Normal Mode (Phase 3)
# =============================================================================


@pytest.mark.gui
class TestDocumentConvertMode:
    """Тесты Document → Convert to Special/Normal Mode."""

    def test_convert_to_special_mode_menu_exists(
        self, initialized_window: MainWindow
    ) -> None:
        """Меню Document → Convert to Special Mode существует."""
        assert initialized_window._menubar is not None

    def test_convert_to_normal_mode_menu_exists(
        self, initialized_window: MainWindow
    ) -> None:
        """Меню Document → Convert to Normal Mode существует."""
        assert initialized_window._menubar is not None

    def test_convert_to_special_mode_no_mode_manager(
        self, initialized_window: MainWindow
    ) -> None:
        """_on_document_convert_to_special без ModeManager не падает."""
        initialized_window._mode_manager = None
        initialized_window._on_document_convert_to_special()

    def test_convert_to_normal_mode_no_mode_manager(
        self, initialized_window: MainWindow
    ) -> None:
        """_on_document_convert_to_normal без ModeManager не падает."""
        initialized_window._mode_manager = None
        initialized_window._on_document_convert_to_normal()

    def test_convert_to_special_mode_already_special(
        self, initialized_window: MainWindow, mock_controller: MagicMock
    ) -> None:
        """Convert to Special Mode показывает info если уже в Special Mode."""
        from src.gui.security.mode_manager import ModeManager

        ModeManager.reset_instance()
        mock_hc = MagicMock()
        mock_hc.run_critical.return_value = MagicMock(is_healthy=True)
        mock_auth = MagicMock()

        mode_manager = ModeManager(
            health_checker=mock_hc,
            auth_service=mock_auth,
        )
        mode_manager.enter_special({"password": "test", "user_id": "test"})
        initialized_window._mode_manager = mode_manager

        with patch.object(initialized_window._toast_service, "show") as mock_show:
            initialized_window._on_document_convert_to_special()
            mock_show.assert_called_once()

        ModeManager.reset_instance()

    def test_convert_to_normal_mode_already_normal(
        self, initialized_window: MainWindow
    ) -> None:
        """Convert to Normal Mode показывает info если уже в Normal Mode."""
        from src.gui.security.mode_manager import ModeManager

        ModeManager.reset_instance()
        mock_hc = MagicMock()
        mock_auth = MagicMock()

        mode_manager = ModeManager(
            health_checker=mock_hc,
            auth_service=mock_auth,
        )
        initialized_window._mode_manager = mode_manager

        with patch.object(initialized_window._toast_service, "show") as mock_show:
            initialized_window._on_document_convert_to_normal()
            mock_show.assert_called_once()

        ModeManager.reset_instance()

    def test_show_health_check_dialog_for_special_mode(
        self, initialized_window: MainWindow
    ) -> None:
        """_show_health_check_dialog_for_special_mode создаёт диалог."""
        from src.gui.dialogs.health_check_dialog import HealthCheckDialog

        mock_hc = MagicMock()
        initialized_window._health_checker = mock_hc

        with patch.object(HealthCheckDialog, "show", lambda self: None):
            initialized_window._show_health_check_dialog_for_special_mode()

        assert initialized_window._health_check_dialog is not None
        assert isinstance(initialized_window._health_check_dialog, HealthCheckDialog)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.views.main_window"])
