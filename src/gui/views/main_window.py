"""MainWindow для FX Text Processor 3.

Главное окно приложения, координирующее все GUI-компоненты:
- MenuBar (File, Edit, View, Security, Tools, Help)
- MainLayout (SideBar + Content area)
- CardFileTabBar (вкладки документов)
- DocumentView (область редактирования)
- StatusBar (статусная строка)
- ToastService (уведомления)
- WindowManager (управление окнами)
- Phase 3: ModeManager, AuthOverlay, HealthCheckDialog

Security:
    - wipe_sensitive_data() при закрытии
    - Session lock/unlock с overlay
    - basename-only в заголовке (не показывать полный путь)
    - Auto-close check для unsaved документов
    - Phase 3: Special Mode с MFA

Example:
    >>> from src.gui.views.main_window import MainWindow
    >>> window = MainWindow(controller=my_controller)
    >>> window.initialize()
    >>> window.run()

Version: 2.1
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox
from typing import Any, Final, Optional, cast

from src.gui.core.error_handler import GUIErrorHandler
from src.gui.core.protocols import ControllerProtocol
from src.gui.dialogs.health_check_dialog import HealthCheckDialog
from src.gui.dialogs.window_manager_dialog import WindowManagerDialog
from src.gui.layout.layout_constants import (
    DEFAULT_WINDOW_HEIGHT,
    DEFAULT_WINDOW_WIDTH,
    MIN_WINDOW_HEIGHT,
    MIN_WINDOW_WIDTH,
)
from src.gui.layout.main_layout import MainLayout
from src.gui.security.mfa_gate import MFAGate
from src.gui.security.mode_manager import ModeManager
from src.gui.services.drag_drop_service import DragDropService
from src.gui.services.notification_service import NotificationService
from src.gui.services.sync_service import SyncService
from src.gui.services.toast_service import ToastService
from src.gui.services.window_manager import WindowManager
from src.gui.views import ToastLevel
from src.gui.views.auth_overlay import AuthOverlay
from src.gui.views.card_file_tab_bar import CardFileTabBar
from src.gui.views.document_view import DocumentView
from src.gui.views.side_bar import SideBar
from src.gui.views.status_bar import StatusBar
from src.model.bookmark import BookmarkManager
from src.security.audit import AuditEventType, AuditLog
from src.security.auth.auth_service import AuthService
from src.security.auth.session import SessionManager
from src.security.monitoring.health_checker import HealthChecker
from src.services.notification_service import (
    NotificationPriority,
    NotificationType,
)

# Phase 4: Dialog imports (lazy loaded in methods to avoid circular imports)
# from src.gui.dialogs.navigation_dialogs import GotoDialog, BookmarksDialog
# from src.gui.dialogs.workflow_dialogs import PrefillDialog

# Logger for this module
logger: logging.Logger = logging.getLogger(__name__)

# Window title
APP_NAME: Final[str] = "FX Text Processor 3"
TITLE_SEPARATOR: Final[str] = " - "
MODIFIED_INDICATOR: Final[str] = "*"

# Lock overlay colors
LOCK_OVERLAY_BG: Final[str] = "#2c3e50"
LOCK_OVERLAY_FG: Final[str] = "#ecf0f1"


class MainWindow:
    """Главное окно приложения FX Text Processor 3.

    Координирует все View-компоненты и предоставляет интерфейс
    для взаимодействия с Controller.

    Attributes:
        _controller: Ссылка на контроллер приложения.
        _root: Корневое окно Tkinter.
        _toast_service: Сервис уведомлений.
        _window_manager: Менеджер окон для multi-window support.
        _main_window_id: ID главного окна в WindowManager.
        _is_initialized: Флаг инициализации UI.
        _is_locked: Флаг блокировки сессии.
        _mode_manager: Phase 3: ModeManager для Normal/Special режимов.
        _auth_overlay: Phase 3: Overlay для MFA аутентификации.
        _health_check_dialog: Phase 3: Диалог Health Check.
        _mode_var: Phase 3: StringVar для меню Mode.

    Structure:
        ```
        +-----------------------------------+
        | MenuBar                           |
        +-----------------------------------+
        | [MainToolbar]                     |
        +-----------------------------------+
        | [SideBar] | [CardFileTabBar]      |
        |           |-----------------------|
        |           | [DocumentView]        |
        |           |                       |
        +-----------------------------------+
        | [StatusBar]                       |
        +-----------------------------------+
        ```

    Example:
        >>> window = MainWindow(controller=ctrl)
        >>> window.initialize()
        >>> window.set_title("document.fxsd", modified=True)
        >>> window.run()
    """

    def __init__(
        self,
        controller: Optional[ControllerProtocol] = None,
        audit_log: Optional["AuditLog"] = None,
    ) -> None:
        """Инициализация MainWindow.

        Args:
            controller: Опциональный контроллер для callbacks.
            audit_log: Опциональный AuditLog для аудита событий.

        Example:
            >>> window = MainWindow(controller=my_controller)
        """
        self._controller: Optional[ControllerProtocol] = controller
        self._root: Optional[tk.Tk] = None
        self._toast_service: Optional[ToastService] = None
        self._notification_service: Optional[NotificationService] = None
        self._sync_service: Optional[SyncService] = None
        self._drag_drop_service: Optional[DragDropService] = None
        self._audit_log: Optional["AuditLog"] = audit_log

        # Component references
        self._menubar: Optional[tk.Menu] = None
        self._main_toolbar: Optional[Any] = None
        self._main_layout: Optional[MainLayout] = None
        self._sidebar: Optional[SideBar] = None
        self._cardfile_tabbar: Optional[CardFileTabBar] = None
        self._document_view: Optional[DocumentView] = None
        self._statusbar: Optional[StatusBar] = None

        # Lock overlay
        self._lock_overlay: Optional[tk.Frame] = None
        self._lock_frame: Optional[tk.Frame] = None

        # State
        self._is_initialized: bool = False
        self._is_locked: bool = False
        self._current_title: str = ""
        self._is_modified: bool = False

        # Phase 3: Security UI components (initialized in initialize())
        self._mode_manager: Optional[ModeManager] = None
        self._auth_overlay: Optional[AuthOverlay] = None
        self._health_check_dialog: Optional[HealthCheckDialog] = None
        self._mode_var: Optional[tk.StringVar] = None
        self._health_checker: Optional[HealthChecker] = None

        # Phase 4: Error handling
        self._error_handler: GUIErrorHandler = GUIErrorHandler()

        # Phase 4: Bookmark manager (lazy initialized per document)
        self._bookmark_manager: Optional[BookmarkManager] = None

        # Phase 6: Barcode/QR render mode
        self._barcode_render_var: Optional[tk.StringVar] = None
        self._barcode_render_menu: Optional[tk.Menu] = None

        # Phase 7: Workflow Simple Mode
        self._workflow_simple_mode: bool = False
        self._workflow_simple_var: Optional[tk.BooleanVar] = None

        # Window Manager for multi-window support
        self._window_manager: Optional[WindowManager] = None
        self._main_window_id: Optional[str] = None

        # Session Manager for authentication
        self._session_manager: Optional[SessionManager] = None
        self._current_session_id: Optional[str] = None

        # New window counter for multi-window support
        self._new_window_counter: int = 0

    def initialize(self) -> None:
        """Инициализирует UI компоненты окна.

        Создаёт root window, menu bar, основной layout
        и все дочерние компоненты.

        Phase 3:
            - Инициализирует ModeManager
            - Запускает Startup Health Check

        Raises:
            RuntimeError: Если окно уже инициализировано.

        Example:
            >>> window = MainWindow(controller=ctrl)
            >>> window.initialize()
        """
        if self._is_initialized:
            raise RuntimeError("MainWindow уже инициализирован")

        # Create root window
        self._root = tk.Tk()
        self._root.title(APP_NAME)
        self._root.geometry(f"{DEFAULT_WINDOW_WIDTH}x{DEFAULT_WINDOW_HEIGHT}")
        self._root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)

        # Configure grid
        self._root.rowconfigure(2, weight=1)  # Main content expands (row 2 after toolbar)
        self._root.columnconfigure(0, weight=1)

        # Initialize ToastService
        self._toast_service = ToastService(self._root)

        # Initialize WindowManager
        self._window_manager = WindowManager(self._root)

        # Register main window
        self._main_window_id = self._window_manager.register_window(
            self._root, APP_NAME, is_modal=False
        )
        self._window_manager.set_main_window_id(self._main_window_id)

        # Phase 7: Initialize SyncService for inter-window synchronization
        self._sync_service = SyncService(self._window_manager)

        # Phase 7: Initialize NotificationService with WindowManager integration
        self._notification_service = NotificationService(self._root, self._window_manager)

        # Phase 7: Initialize DragDropService with sync support
        self._drag_drop_service = DragDropService(
            self._root, self._window_manager, self._sync_service
        )

        # Phase 3: Initialize ModeManager and mode_var
        self._mode_manager = ModeManager(
            health_checker=self._health_checker,
            auth_service=self._get_auth_service(),
        )
        self._mode_var = tk.StringVar(value="normal")

        # Create menu bar
        self._create_menubar()

        # Create main toolbar
        self._create_main_toolbar()

        # Setup toolbar commands
        self._setup_toolbar_commands()

        # Create main layout
        self._create_main_layout()

        # Configure window close handler
        self._root.protocol("WM_DELETE_WINDOW", self._on_window_close)

        self._is_initialized = True

        # Show welcome toast
        self._show_welcome_toast()

        # Phase 3: Startup Health Check
        self._run_startup_health_check()

        # Check session and show AuthWindow if needed
        self._check_session_and_auth()

    def run(self) -> None:
        """Запускает главный цикл обработки событий.

        Блокирует выполнение до закрытия окна.

        Example:
            >>> window.initialize()
            >>> window.run()  # Blocks until window closed
        """
        if not self._is_initialized or self._root is None:
            raise RuntimeError("MainWindow не инициализирован. Вызовите initialize() сначала.")

        self._root.mainloop()

    def destroy(self) -> None:
        """Корректно закрывает окно с очисткой sensitive данных.

        Security:
            - Вызывает wipe_sensitive_data() для очистки данных
            - Уничтожает все виджеты
            - Останавливает mainloop если он запущен
            - Phase 3: Очищает AuthOverlay credentials
            - Unregisters main window from WindowManager

        Example:
            >>> window.destroy()  # Graceful shutdown with wipe
        """
        # Wipe sensitive data
        self._wipe_sensitive_data()

        # Phase 3: Cleanup AuthOverlay
        if self._auth_overlay is not None:
            self._auth_overlay.wipe_credentials()
            self._auth_overlay = None

        # Phase 3: Cleanup HealthCheckDialog
        if self._health_check_dialog is not None:
            self._health_check_dialog.destroy()
            self._health_check_dialog = None

        # Close all toast notifications
        if self._toast_service is not None:
            self._toast_service.close_all()

        # Cleanup NotificationService
        if self._notification_service is not None:
            self._notification_service.dismiss_all()
            self._notification_service = None

        # Destroy lock overlay if present
        if self._lock_overlay is not None:
            self._lock_overlay.destroy()
            self._lock_overlay = None

        # Unregister main window from WindowManager
        if self._window_manager is not None and self._main_window_id is not None:
            self._window_manager.unregister_window(self._main_window_id)
            self._main_window_id = None

        # Unmount and destroy components
        if self._main_layout is not None:
            self._main_layout.unmount()
            self._main_layout = None

        # Phase 7: Cleanup DragDropService
        if self._drag_drop_service is not None:
            self._drag_drop_service = None

        # Phase 7: Cleanup SyncService (clear handlers)
        if self._sync_service is not None:
            self._sync_service.clear_handlers()
            self._sync_service = None

        # Phase 7: Cleanup NotificationService
        if self._notification_service is not None:
            self._notification_service.close_all_toasts()
            self._notification_service = None

        # Destroy root window
        if self._root is not None:
            self._root.destroy()
            self._root = None

        self._is_initialized = False
        self._is_locked = False

    def get_toast_service(self) -> ToastService:
        """Возвращает сервис уведомлений.

        Returns:
            ToastService для показа уведомлений.

        Raises:
            RuntimeError: Если окно не инициализировано.

        Example:
            >>> toast = window.get_toast_service()
            >>> toast.show("Document saved", ToastLevel.SUCCESS)
        """
        if self._toast_service is None:
            raise RuntimeError("MainWindow не инициализирован")
        return self._toast_service

    def notify(self, message: str, category: str, priority: NotificationPriority) -> str:
        """Показать уведомление пользователю.

        Args:
            message: Текст уведомления.
            category: Категория уведомления (info, success, warning, error).
            priority: Приоритет уведомления.

        Returns:
            ID созданного уведомления.

        Example:
            >>> window.notify("Файл сохранён", "success", NotificationPriority.NORMAL)
            'uuid-string'
        """
        if self._notification_service is None:
            raise RuntimeError("MainWindow не инициализирован")

        # Map category to NotificationType
        type_mapping = {
            "info": NotificationType.INFO,
            "success": NotificationType.SUCCESS,
            "warning": NotificationType.WARNING,
            "error": NotificationType.ERROR,
        }
        notif_type = type_mapping.get(category.lower(), NotificationType.INFO)

        # Map NotificationPriority to ToastLevel for toast display
        toast_mapping = {
            NotificationPriority.LOW: ToastLevel.INFO,
            NotificationPriority.NORMAL: ToastLevel.INFO,
            NotificationPriority.HIGH: ToastLevel.WARNING,
            NotificationPriority.CRITICAL: ToastLevel.ERROR,
        }
        toast_level = toast_mapping.get(priority, ToastLevel.INFO)

        # Show via NotificationService
        result = self._notification_service.show(
            title=category.capitalize(),
            message=message,
            type=notif_type,
            priority=priority,
        )

        # Also show toast for immediate visual feedback
        if self._toast_service is not None and result.success:
            self._toast_service.show(message, toast_level)

        return str(result.notification_id) if result.notification_id else ""

    def get_root(self) -> Optional[tk.Tk]:
        """Возвращает корневое окно Tkinter.

        Returns:
            Корневое окно или None если не инициализировано.
        """
        return self._root

    def get_theme(self) -> str:
        """Возвращает текущую тему оформления.

        Returns:
            Идентификатор темы (default: "classic_green").
        """
        return "classic_green"

    def add_document(self, document: Any) -> None:
        """Добавляет документ в UI (вкладку).

        Args:
            document: Модель документа с атрибутами id и metadata.

        Note:
            Вызывается из AppController после создания документа.
        """
        if self._cardfile_tabbar is None:
            return

        from src.documents.types.document_type import DocumentMode

        doc_id = str(getattr(document, "id", str(id(document))))

        # Get title from metadata
        metadata = getattr(document, "metadata", None)
        title_str: str = "Без названия"
        if metadata is not None:
            doc_title = getattr(metadata, "title", None)
            if doc_title is not None:
                title_str = str(doc_title)

        # Get mode from document
        mode = getattr(document, "mode", DocumentMode.FREE_FORM)
        if mode is None:
            mode = DocumentMode.FREE_FORM

        self._cardfile_tabbar.add_tab(document_id=doc_id, title=title_str, mode=mode)

    def remove_document(self, doc_id: str) -> None:
        """Удаляет документ из UI (вкладку).

        Args:
            doc_id: Идентификатор документа для удаления.
        """
        if self._cardfile_tabbar is None:
            return

        self._cardfile_tabbar.close_tab(doc_id)

    def set_document(self, document: Any) -> None:
        """Устанавливает текущий документ для отображения.

        Args:
            document: Модель документа.

        Note:
            Передаёт документ в DocumentView для рендеринга.
        """
        if self._document_view is None:
            return

        from src.documents.types.document_type import DocumentMode

        # Create a protocol-compatible document wrapper
        class DocumentWrapper:
            """Обертка для документа, реализующая DocumentProtocol.

            Адаптирует Document model для работы с DocumentView,
            извлекая текст из секций и параграфов.

            Attributes:
                id: Уникальный идентификатор документа.
                mode: Режим документа (всегда FREE_FORM).

            Example:
                >>> wrapper = DocumentWrapper(document)
                >>> content = wrapper.get_content()
                >>> cpi = wrapper.get_cpi()
            """

            def __init__(self, doc: Any) -> None:
                """Инициализация DocumentWrapper.

                Args:
                    doc: Исходный документ model.
                """
                self._doc = doc
                doc_id = getattr(doc, "id", str(id(doc)))
                self.id = str(doc_id)  # Ensure it's a string
                # Document model doesn't have mode, default to FREE_FORM
                self.mode = DocumentMode.FREE_FORM

            def get_content(self) -> str:
                """Извлекает текст из секций документа.

                Returns:
                    Текст из всех параграфов секций, объединенный через \n.
                """
                # Get text from all sections/paragraphs
                sections = getattr(self._doc, "sections", [])
                if not sections:
                    return ""

                content_parts = []
                for section in sections:
                    paragraphs = getattr(section, "paragraphs", [])
                    for para in paragraphs:
                        # Paragraph has get_text() method, not text attribute
                        if hasattr(para, "get_text"):
                            text = para.get_text()
                        else:
                            text = str(para)
                        content_parts.append(text)

                return "\n".join(content_parts)

            def get_cpi(self) -> int:
                """Возвращает CPI из настроек принтера.

                Returns:
                    Количество символов на дюйм (CPI), по умолчанию 10.
                """
                settings = getattr(self._doc, "printer_settings", None)
                if settings:
                    cpi_enum = getattr(settings, "characters_per_inch", None)
                    if cpi_enum:
                        # Extract number from enum like CharactersPerInch.CPI_10
                        cpi_name = str(cpi_enum.name)  # e.g., "CPI_10"
                        if cpi_name.startswith("CPI_"):
                            try:
                                return int(cpi_name.split("_")[1])
                            except (ValueError, IndexError):
                                pass
                return 10  # Default CPI

        wrapped = DocumentWrapper(document)
        self._document_view.set_document(wrapped)

    def lock_session(self) -> None:
        """Блокирует сессию (screen lock).

        Security:
            - Скрывает DocumentView
            - Показывает lock overlay с запросом аутентификации
            - Вызывает wipe_sensitive_data() для очистки
            - Закрывает все вспомогательные окна через WindowManager

        Example:
            >>> window.lock_session()  # Session locked
        """
        if self._is_locked or self._root is None:
            return

        self._is_locked = True

        # Close all auxiliary windows (dialogs, etc.)
        if self._window_manager is not None:
            self._window_manager.close_all_except_main()

        # Wipe sensitive data
        self._wipe_sensitive_data()

        # Hide document content
        if self._document_view is not None:
            self._document_view.hide_content()

        # Show lock overlay
        self._show_lock_overlay()

        # Show notification
        if self._toast_service is not None:
            self._toast_service.show("Сессия заблокирована", ToastLevel.INFO)

        # Log to audit
        if self._audit_log:
            user_id = self._get_current_user_id()
            if user_id:
                try:
                    self._audit_log.log_event(
                        AuditEventType.SESSION_LOCKED, details={"user_id": user_id}
                    )
                except Exception as e:
                    logger.error("Failed to log session lock: %s", e)

    def unlock_session(self) -> None:
        """Разблокирует сессию.

        Восстанавливает отображение документа после аутентификации.

        Raises:
            RuntimeError: Если сессия не была заблокирована.

        Example:
            >>> # After successful authentication
            >>> window.unlock_session()
        """
        if not self._is_locked:
            return

        self._is_locked = False

        # Hide lock overlay
        self._hide_lock_overlay()

        # Restore document content
        if self._document_view is not None:
            self._document_view.restore_content()

        # Show notification
        if self._toast_service is not None:
            self._toast_service.show("Сессия разблокирована", ToastLevel.SUCCESS)

        # Log to audit
        if self._audit_log:
            user_id = self._get_current_user_id()
            if user_id:
                try:
                    self._audit_log.log_event(
                        AuditEventType.APP_UNLOCKED, details={"user_id": user_id}
                    )
                except Exception as e:
                    logger.error("Failed to log session unlock: %s", e)

    # =============================================================================
    # PHASE 3: SECURITY UI METHODS
    # =============================================================================

    def _check_session_and_auth(self) -> None:
        """Проверяет сессию и показывает AuthWindow если нужно."""
        if not self._current_session_id:
            self._show_auth_window()

    def _show_auth_window(self) -> None:
        """Показывает окно аутентификации."""
        if self._root is None:
            return
        from src.gui.security.auth_window import AuthWindow

        auth_window = AuthWindow(
            parent=self._root,
            auth_service=self._get_auth_service(),
            on_auth_success=self._on_startup_auth_success,
            on_cancel=self._on_startup_auth_cancel,
        )
        auth_window.show()

    def _on_startup_auth_success(self, user_id: str) -> None:
        """Обработчик успешной аутентификации."""
        if self._session_manager:
            token_bundle = self._session_manager.issue(user_id=user_id)
            self._current_session_id = token_bundle.session_id
        self._update_ui_for_authenticated_user(user_id)

    def _on_startup_auth_cancel(self) -> None:
        """Обработчик отмены аутентификации."""
        if self._root is not None and messagebox.askyesno("Выход", "Выйти из приложения?"):
            self._root.destroy()

    def _update_ui_for_authenticated_user(self, user_id: str) -> None:
        """Обновляет UI после аутентификации."""
        if self._root is not None:
            self._root.title(f"{APP_NAME} - User: {user_id}")
        if self._toast_service:
            self._toast_service.show(f"Добро пожаловать, {user_id}!", ToastLevel.SUCCESS)

    def _run_startup_health_check(self) -> None:
        """Запускает Health Check при старте.

        Если critical failures:
        - Показывает warning Toast
        - Блокирует Special Mode
        """
        if self._root is None or self._mode_manager is None:
            return

        # Create HealthChecker if not exists
        if self._health_checker is None:
            self._health_checker = HealthChecker(version="3.0.0")

        try:
            # Run critical checks
            report = self._health_checker.run_critical()

            if not report.is_healthy:
                # Show warning toast
                if self._toast_service is not None:
                    self._toast_service.show(
                        "⚠️ Security Health Check failed. Special Mode disabled.",
                        ToastLevel.WARNING,
                    )
                # Disable Special Mode
                self._mode_manager.disable_special_mode(
                    reason=f"Critical health check failures: {report.unhealthy_count}"
                )
            else:
                # Health check passed
                if self._toast_service is not None:
                    self._toast_service.show(
                        "🔒 Security Health Check passed",
                        ToastLevel.SUCCESS,
                    )

        except Exception as exc:
            # Log error and disable Special Mode on error
            if self._toast_service is not None:
                self._toast_service.show(
                    "⚠️ Health Check error. Special Mode disabled.",
                    ToastLevel.WARNING,
                )
            if self._mode_manager is not None:
                self._mode_manager.disable_special_mode(reason=f"Health check error: {exc}")

    def _on_mode_special(self) -> None:
        """Обработчик входа в Special Mode.

        Flow:
        1. Проверить can_enter_special()
        2. Если нельзя:
           - Показать HealthCheckDialog
           - Return
        3. Показать AuthOverlay
        4. При успехе auth:
           - Переключить режим
           - Обновить StatusBar
           - Обновить Menu
        """
        if self._mode_manager is None:
            return

        # Step 1: Check if can enter Special Mode
        can_enter, reason = self._mode_manager.can_enter_special()

        if not can_enter:
            # Step 2: Show HealthCheckDialog
            if self._root is not None:
                self._health_check_dialog = HealthCheckDialog(
                    parent=self._root,  # type: ignore[arg-type]
                    health_checker=self._health_checker,
                )
                self._health_check_dialog.show()

                # Check if user wants to retry after fixing issues
                if self._health_check_dialog.has_critical_failures():
                    if self._toast_service is not None:
                        self._toast_service.show(
                            "⚠️ Critical failures detected. Special Mode unavailable.",
                            ToastLevel.WARNING,
                        )
                    return
            return

        # Step 3: Show AuthOverlay
        self._show_auth_overlay()

    def _on_mode_normal(self) -> None:
        """Обработчик выхода в Normal Mode.

        Flow:
        1. Confirm dialog: "Exit Special Mode?"
        2. Если да:
           - mode_manager.exit_special()
           - Обновить StatusBar
           - Обновить Menu
        """
        if self._mode_manager is None:
            return

        # Step 1: Confirm dialog
        if self._root is None:
            return

        response = messagebox.askyesno(
            "Exit Special Mode",
            "Are you sure you want to exit Special Mode?\nSome features may become unavailable.",
            icon="question",
        )

        if not response:
            return

        # Step 2: Exit Special Mode
        success = self._mode_manager.exit_special(confirm=False)

        if success:
            # Update UI
            self._update_mode_ui("normal")

            if self._toast_service is not None:
                self._toast_service.show(
                    "Returned to Normal Mode",
                    ToastLevel.INFO,
                )

    def _on_tools_health_check(self) -> None:
        """Обработчик Tools → Health Check."""
        if self._root is None:
            return

        # Create HealthChecker if not exists
        if self._health_checker is None:
            self._health_checker = HealthChecker(version="3.0.0")

        self._health_check_dialog = HealthCheckDialog(
            parent=self._root,  # type: ignore[arg-type]
            health_checker=self._health_checker,
        )
        self._health_check_dialog.show()

    def _on_statusbar_mode_click(self) -> None:
        """Обработчик клика на Mode индикатор в StatusBar.

        Если Normal → вызвать _on_mode_special()
        Если Special → вызвать _on_mode_normal()
        """
        if self._mode_manager is None:
            return

        current_mode = self._mode_manager.get_current_mode()

        if current_mode == ModeManager.MODE_NORMAL:
            self._on_mode_special()
        else:
            self._on_mode_normal()

    def _show_auth_overlay(self) -> None:
        """Показывает AuthOverlay для входа в Special Mode."""
        if self._root is None:
            return

        if self._auth_overlay is None:
            self._auth_overlay = AuthOverlay(
                parent=self._root,  # type: ignore[arg-type]
                widget_id="auth_overlay",
                controller=self._controller,
                auth_service=self._get_auth_service(),
                on_auth_success=self._on_auth_success,
                on_cancel=self._on_auth_cancel,
            )
            self._auth_overlay.mount(self._root)

        self._auth_overlay.show()

    def _on_auth_success(self) -> None:
        """Callback при успешной аутентификации.

        Steps:
        1. Hide AuthOverlay
        2. mode_manager.enter_special()
        3. Update StatusBar: set_mode_indicator("special")
        4. Update Menu: _mode_var.set("special")
        5. Show success Toast
        """
        # Step 1: Hide AuthOverlay
        if self._auth_overlay is not None:
            self._auth_overlay.hide()

        # Step 2: Enter Special Mode
        # Note: AuthOverlay already performed MFA authentication
        # ModeManager handles state internally, we just update UI

        # Step 3 & 4: Update UI
        self._update_mode_ui("special")

        # Step 5: Show success toast
        if self._toast_service is not None:
            self._toast_service.show(
                "🔓 Special Mode activated",
                ToastLevel.SUCCESS,
            )

    def _on_auth_cancel(self) -> None:
        """Callback при отмене аутентификации.

        Security:
            - Скрывает AuthOverlay
            - Очищает credentials
            - Возвращает в Normal Mode
        """
        # Hide AuthOverlay and wipe credentials
        if self._auth_overlay is not None:
            self._auth_overlay.wipe_credentials()
            self._auth_overlay.hide()

        # Ensure we're in Normal Mode
        if self._mode_manager is not None:
            self._mode_manager.exit_special(confirm=False)

        # Update UI
        self._update_mode_ui("normal")

        if self._toast_service is not None:
            self._toast_service.show(
                "Authentication cancelled",
                ToastLevel.INFO,
            )

    def _get_auth_service(self) -> Optional[AuthService]:
        """Возвращает AuthService из контроллера или создаёт новый.

        Returns:
            AuthService instance или None.
        """
        # Try to get from controller first
        if self._controller is not None:
            try:
                auth_service = getattr(self._controller, "get_auth_service", None)
                if auth_service is not None:
                    result = auth_service()
                    if isinstance(result, AuthService):
                        return result
            except Exception as _exc:
                # Log error but continue - AuthOverlay will handle gracefully
                self._error_handler.handle_silent(
                    _exc,
                    {"operation": "_get_auth_service", "controller": "get_auth_service"},
                )

        # Return None - AuthOverlay will handle gracefully
        return None

    def _get_auth_controller(self) -> Any:
        """Возвращает AuthController из контроллера.

        Returns:
            AuthController instance или None.
        """
        if self._controller is not None:
            try:
                # Try common attribute names
                auth_ctrl = getattr(self._controller, "auth_controller", None)
                if auth_ctrl is not None:
                    return auth_ctrl
                # Try the controller itself if it has verify methods
                if hasattr(self._controller, "verify_totp"):
                    return self._controller
            except Exception as e:
                logger.debug("Failed to get auth controller: %s", e)
        return None

    def _get_current_user_id(self) -> Optional[str]:
        """Возвращает ID текущего пользователя.

        Returns:
            User ID или None если не аутентифицирован.
        """
        auth_controller = self._get_auth_controller()
        if auth_controller is not None:
            try:
                user_id = auth_controller.get_current_user()
                if isinstance(user_id, str):
                    return user_id
            except Exception as e:
                logger.debug("Failed to get current user: %s", e)
        return None

    def _update_mode_ui(self, mode: str) -> None:
        """Обновляет UI при смене режима.

        Args:
            mode: Новый режим ("normal" или "special").

        Updates:
        - StatusBar: set_mode_indicator()
        - Menu: _mode_var.set()
        - Toast: показать уведомление (опционально)
        """
        # Update StatusBar
        if self._statusbar is not None:
            self._statusbar.set_mode_indicator(mode)

        # Update Menu
        if self._mode_var is not None:
            self._mode_var.set(mode)

    # =============================================================================
    # PRIVATE METHODS
    # =============================================================================

    def _create_menubar(self) -> None:
        """Создаёт меню бар с пунктами File, Edit, View, Security, Tools, Help."""
        if self._root is None:
            return

        self._menubar = tk.Menu(self._root)
        self._root.config(menu=self._menubar)

        # File menu
        file_menu = tk.Menu(self._menubar, tearoff=0)
        file_menu.add_command(label="New", command=self._on_file_new, accelerator="Ctrl+N")
        file_menu.add_command(label="Open...", command=self._on_file_open, accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Save", command=self._on_file_save, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As...", command=self._on_file_save_as)
        file_menu.add_separator()
        file_menu.add_command(label="Print...", command=self._on_file_print, accelerator="Ctrl+P")
        file_menu.add_separator()
        # Phase 3: Document → Convert to Special/Normal Mode
        file_menu.add_command(
            label="Convert to Special Mode...",
            command=self._on_document_convert_to_special,
        )
        file_menu.add_command(
            label="Convert to Normal Mode...",
            command=self._on_document_convert_to_normal,
        )
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_window_close, accelerator="Alt+F4")
        self._menubar.add_cascade(label="File", menu=file_menu)

        # Edit menu
        edit_menu = tk.Menu(self._menubar, tearoff=0)
        edit_menu.add_command(label="Undo", command=self._on_edit_undo, accelerator="Ctrl+Z")
        edit_menu.add_command(label="Redo", command=self._on_edit_redo, accelerator="Ctrl+Y")
        edit_menu.add_separator()
        edit_menu.add_command(label="Cut", command=self._on_edit_cut, accelerator="Ctrl+X")
        edit_menu.add_command(label="Copy", command=self._on_edit_copy, accelerator="Ctrl+C")
        edit_menu.add_command(label="Paste", command=self._on_edit_paste, accelerator="Ctrl+V")
        edit_menu.add_separator()
        edit_menu.add_command(label="Find...", command=self._on_edit_find, accelerator="Ctrl+F")
        edit_menu.add_separator()
        edit_menu.add_command(label="Go to...", command=self._on_goto, accelerator="Ctrl+G")
        edit_menu.add_command(label="Bookmarks", command=self._on_bookmarks, accelerator="Ctrl+B")
        edit_menu.add_separator()
        edit_menu.add_command(label="Prefill from Previous", command=self._on_prefill)
        self._menubar.add_cascade(label="Edit", menu=edit_menu)

        # Insert menu
        insert_menu = tk.Menu(self._menubar, tearoff=0)
        insert_menu.add_command(
            label="📊 Barcode...", command=self._on_insert_barcode, accelerator="Ctrl+Shift+B"
        )
        insert_menu.add_command(
            label="🔳 QR Code...", command=self._on_insert_qr, accelerator="Ctrl+Shift+Q"
        )
        insert_menu.add_separator()
        insert_menu.add_command(label="Special Character...", command=self._on_insert_special)
        self._menubar.add_cascade(label="Insert", menu=insert_menu)

        # View menu
        view_menu = tk.Menu(self._menubar, tearoff=0)
        view_menu.add_command(label="Toggle Sidebar", command=self._on_view_toggle_sidebar)
        view_menu.add_command(label="Toggle StatusBar", command=self._on_view_toggle_statusbar)
        view_menu.add_separator()
        view_menu.add_command(label="Zoom In", command=self._on_view_zoom_in, accelerator="Ctrl++")
        view_menu.add_command(
            label="Zoom Out", command=self._on_view_zoom_out, accelerator="Ctrl+-"
        )
        view_menu.add_command(label="Reset Zoom", command=self._on_view_zoom_reset)
        view_menu.add_separator()
        # Barcode Render Mode submenu (Phase 6)
        self._barcode_render_menu = tk.Menu(view_menu, tearoff=0)
        self._barcode_render_var = tk.StringVar(value="placeholder")
        self._barcode_render_menu.add_radiobutton(
            label="📊 Real (render actual barcodes)",
            variable=self._barcode_render_var,
            value="real",
            command=self._on_view_barcode_render_mode_changed,
        )
        self._barcode_render_menu.add_radiobutton(
            label="⬜ Placeholder (fast, rectangles)",
            variable=self._barcode_render_var,
            value="placeholder",
            command=self._on_view_barcode_render_mode_changed,
        )
        view_menu.add_cascade(label="Barcode Render Mode", menu=self._barcode_render_menu)
        view_menu.add_separator()
        # Window management submenu (Phase 7)
        window_menu = tk.Menu(view_menu, tearoff=0)
        window_menu.add_command(label="Список окон", command=self._on_window_list)
        window_menu.add_separator()
        window_menu.add_command(label="Свернуть все", command=self._on_window_minimize_all)
        window_menu.add_command(label="Восстановить все", command=self._on_window_restore_all)
        view_menu.add_cascade(label="Окна", menu=window_menu)
        view_menu.add_separator()
        # Workflow submenu with Simple Mode toggle
        self._workflow_simple_var = tk.BooleanVar(value=self._workflow_simple_mode)
        workflow_menu = tk.Menu(view_menu, tearoff=0)
        workflow_menu.add_checkbutton(
            label="Simple Mode",
            variable=self._workflow_simple_var,
            command=self._on_view_workflow_simple_mode,
        )
        view_menu.add_cascade(label="Approval Workflow", menu=workflow_menu)
        view_menu.add_separator()
        self._menubar.add_cascade(label="View", menu=view_menu)

        # Phase 7: Notifications menu
        notifications_menu = tk.Menu(self._menubar, tearoff=0)
        notifications_menu.add_command(label="История", command=self._on_view_notifications)
        notifications_menu.add_command(
            label="Отметить все прочитанными", command=self._on_notifications_mark_all_read
        )
        self._menubar.add_cascade(label="Уведомления", menu=notifications_menu)

        # Security menu
        security_menu = tk.Menu(self._menubar, tearoff=0)
        security_menu.add_command(label="Lock Session", command=self._on_security_lock)
        security_menu.add_separator()
        security_menu.add_command(
            label="Change Password...", command=self._on_security_change_password
        )
        security_menu.add_command(label="Health Check...", command=self._on_security_health_check)
        security_menu.add_separator()
        security_menu.add_command(label="Резервные коды", command=self._on_security_backup_codes)
        security_menu.add_command(
            label="Профиль безопасности", command=self._on_security_crypto_profile
        )
        security_menu.add_command(
            label="Настройки автоблокировки", command=self._on_security_auto_lock_settings
        )
        self._menubar.add_cascade(label="Security", menu=security_menu)

        # Phase 3: Tools menu with Mode submenu
        tools_menu = tk.Menu(self._menubar, tearoff=0)

        # Mode submenu - only if _mode_var is initialized
        if self._mode_var is not None:
            mode_menu = tk.Menu(tools_menu, tearoff=0)
            mode_menu.add_radiobutton(
                label="🟢 Normal Mode",
                variable=self._mode_var,
                value="normal",
                command=self._on_mode_normal,
            )
            mode_menu.add_radiobutton(
                label="🔴 Special Mode...",
                variable=self._mode_var,
                value="special",
                command=self._on_mode_special,
            )
            tools_menu.add_cascade(label="Mode", menu=mode_menu)
            tools_menu.add_separator()
        tools_menu.add_command(
            label="Health Check...",
            command=self._on_tools_health_check,
        )
        self._menubar.add_cascade(label="Tools", menu=tools_menu)

        # Phase 7: Window menu
        window_menu = tk.Menu(self._menubar, tearoff=0)
        window_menu.add_command(
            label="New Window", command=self._on_new_window, accelerator="Ctrl+N"
        )
        window_menu.add_command(
            label="Window Manager...",
            command=self._on_window_manager,
        )
        window_menu.add_separator()
        window_menu.add_command(
            label="Minimize All",
            command=self._on_window_minimize_all,
        )
        window_menu.add_command(
            label="Close All Except Main",
            command=self._on_window_close_all_except_main,
        )
        self._menubar.add_cascade(label="Window", menu=window_menu)

        # Help menu
        help_menu = tk.Menu(self._menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._on_help_about)
        self._menubar.add_cascade(label="Help", menu=help_menu)

        # Bind keyboard shortcuts
        self._bind_shortcuts()

    def _on_window_manager(self) -> None:
        """Open Window Manager dialog."""
        if self._window_manager is None or self._sync_service is None or self._root is None:
            return

        dialog = WindowManagerDialog(
            parent=self._root,
            window_manager=self._window_manager,
            sync_service=self._sync_service,
        )
        dialog.show()

    def _on_new_window(self) -> None:
        """Create new document window."""
        MAX_WINDOWS = 50
        WARNING_THRESHOLD = 40  # 80% of limit

        if self._window_manager is None or self._root is None or self._sync_service is None:
            return

        current_count = self._window_manager.get_window_count()

        # Warning at 80%
        if WARNING_THRESHOLD <= current_count < MAX_WINDOWS:
            result = messagebox.askyesno(
                "Предупреждение",
                f"Открыто окон: {current_count}/{MAX_WINDOWS}\nПриближается лимит. Продолжить?",
                parent=self._root,
            )
            if not result:
                return

        # Block at 100%
        if current_count >= MAX_WINDOWS:
            messagebox.showerror(
                "Лимит окон",
                f"Достигнут максимум окон ({MAX_WINDOWS}).\nЗакройте неиспользуемые окна.",
                parent=self._root,
            )
            return

        self._new_window_counter += 1

        # Create Toplevel
        new_window = tk.Toplevel(self._root)
        new_window.title(f"Untitled {self._new_window_counter}")
        new_window.geometry("800x600")

        # Register in WindowManager
        window_id = self._window_manager.register_window(
            new_window,
            title=f"Untitled {self._new_window_counter}",
            is_modal=False,
        )

        # Basic UI elements
        self._setup_new_window_ui(new_window, window_id)

        # Bind close event
        new_window.protocol(
            "WM_DELETE_WINDOW", lambda: self._on_new_window_close(window_id, new_window)
        )

        # Broadcast window list changed
        self._sync_service.broadcast(
            source_window_id=window_id,
            data_type="window_list_changed",
            data={"action": "created", "window_id": window_id},
        )

    def _setup_new_window_ui(self, window: tk.Toplevel, window_id: str) -> None:
        """Setup basic UI for new window."""
        # Menu bar
        menubar = tk.Menu(window)
        window.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Close", command=window.destroy, accelerator="Ctrl+W")

        # Window menu
        window_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Window", menu=window_menu)
        window_menu.add_command(label="Window Manager...", command=self._on_window_manager)

        # Main content area (placeholder for DocumentView)
        content_frame = tk.Frame(window, bg="#f8f9fa")
        content_frame.pack(fill=tk.BOTH, expand=True)

        placeholder = tk.Label(
            content_frame,
            text="Document View\n(Phase 8-9)",
            bg="#f8f9fa",
            fg="#666666",
            font=("Helvetica", 14),
        )
        placeholder.pack(expand=True)

        # Status bar
        status_bar = tk.Label(
            window,
            text=f"Window: {window_id}",
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Bind Ctrl+W
        window.bind("<Control-w>", lambda e: window.destroy())

    def _on_new_window_close(self, window_id: str, window: tk.Toplevel) -> None:
        """Handle new window close."""
        try:
            if self._window_manager is not None:
                self._window_manager.unregister_window(window_id)
        except KeyError:
            pass

        # Broadcast window list changed
        if self._sync_service is not None:
            self._sync_service.broadcast(
                source_window_id=window_id,
                data_type="window_list_changed",
                data={"action": "closed", "window_id": window_id},
            )

        window.destroy()

    def _on_window_close_all_except_main(self) -> None:
        """Callback: Window → Close All Except Main."""
        if self._window_manager is not None:
            count = self._window_manager.close_all_except_main()
            if self._toast_service is not None:
                self._toast_service.show(f"Закрыто окон: {count}", ToastLevel.INFO)

    def _create_main_toolbar(self) -> None:
        """Создаёт главную панель инструментов."""
        from src.gui.components.composite.main_toolbar import MainToolbar

        if self._root is None:
            return

        self._main_toolbar = MainToolbar(
            widget_id="main_toolbar",
            controller=self._controller,
        )
        toolbar_frame = self._main_toolbar.mount(self._root)
        toolbar_frame.grid(row=1, column=0, sticky="ew")

    def _update_toolbar_state(self, has_document: bool = False, is_modified: bool = False) -> None:
        """Обновляет состояние кнопок тулбара."""
        if self._main_toolbar:
            self._main_toolbar.set_button_enabled("save", has_document and is_modified)
            self._main_toolbar.set_button_enabled("print", has_document)

    def _setup_toolbar_commands(self) -> None:
        """Настраивает команды для кнопок тулбара."""
        if self._controller is not None and hasattr(self._controller, "subscribe"):
            self._controller.subscribe(
                "document_changed",
                lambda data: self._update_toolbar_state(
                    data.get("has_document", False), data.get("is_modified", False)
                ),
            )

    def _bind_shortcuts(self) -> None:
        """Привязывает клавиатурные shortcuts."""
        if self._root is None:
            return

        # File shortcuts
        self._root.bind("<Control-n>", lambda e: self._on_file_new())
        self._root.bind("<Control-o>", lambda e: self._on_file_open())
        self._root.bind("<Control-s>", lambda e: self._on_file_save())
        self._root.bind("<Control-p>", lambda e: self._on_file_print())

        # Edit shortcuts
        self._root.bind("<Control-z>", lambda e: self._on_edit_undo())
        self._root.bind("<Control-y>", lambda e: self._on_edit_redo())
        self._root.bind("<Control-f>", lambda e: self._on_edit_find())

        # View shortcuts
        self._root.bind("<Control-plus>", lambda e: self._on_view_zoom_in())
        self._root.bind("<Control-minus>", lambda e: self._on_view_zoom_out())
        self._root.bind("<Control-0>", lambda e: self._on_view_zoom_reset())

        # Navigation shortcuts (Phase 4)
        self._root.bind("<Control-g>", lambda e: self._on_goto())
        self._root.bind("<Control-b>", lambda e: self._on_bookmarks())

        # Insert shortcuts (Phase 6)
        self._root.bind("<Control-Shift-B>", lambda e: self._on_insert_barcode())
        self._root.bind("<Control-Shift-Q>", lambda e: self._on_insert_qr())

    def _create_main_layout(self) -> None:
        """Создаёт основной layout с SideBar, Content и StatusBar."""
        if self._root is None:
            return

        # Create main layout
        self._main_layout = MainLayout(
            widget_id="main_layout",
            controller=self._controller,
            root=self._root,
            sidebar_toggle_callback=self._on_sidebar_toggled,
        )
        main_widget = self._main_layout.mount(self._root)
        main_widget.grid(row=2, column=0, sticky="nsew")

        # Create and set sidebar (Phase 7: with sync_service)
        self._sidebar = SideBar(
            widget_id="sidebar",
            controller=self._controller,
            on_section_select=self._on_section_selected,
            on_tree_select=self._on_tree_item_selected,
            sync_service=self._sync_service,
        )
        self._sidebar.mount(self._root)
        self._main_layout.set_sidebar(self._sidebar.widget)

        # Create content area (frame with TabBar + DocumentView)
        content_frame = tk.Frame(self._root)
        content_frame.rowconfigure(1, weight=1)  # DocumentView expands
        content_frame.columnconfigure(0, weight=1)

        # Create card file tab bar
        self._cardfile_tabbar = CardFileTabBar(
            widget_id="cardfile_tabbar",
            controller=self._controller,
            on_new_tab=self._on_new_tab,
            on_tab_close=self._on_tab_close,
            on_tab_activate=self._on_tab_activate,
        )
        self._cardfile_tabbar.mount(content_frame)
        self._cardfile_tabbar.widget.grid(row=0, column=0, sticky="ew")

        # Create document view
        self._document_view = DocumentView(
            widget_id="document_view",
            controller=self._controller,
        )
        self._document_view.mount(content_frame)
        self._document_view.widget.grid(row=1, column=0, sticky="nsew")

        self._main_layout.set_content(content_frame)

        # Create and set status bar
        self._statusbar = StatusBar(
            widget_id="statusbar",
            controller=self._controller,
            mode_callback=self._on_statusbar_mode_click,
        )
        self._statusbar.mount(self._root)
        self._main_layout.set_statusbar(self._statusbar.widget)

    def _show_lock_overlay(self) -> None:
        """Показывает overlay блокировки сессии.

        UI_SPEC 9.2: Session Lock Screen
        - Background: #2c3e50 (dark blue-gray)
        - Center panel with:
          - Lock icon
          - Title: "Сеанс заблокирован"
          - Time of lock
          - Duration since lock
          - MFA method selection
          - Input field (adaptive based on method)
          - Unlock button
        - Countdown timer for auto-lock
        """
        if self._root is None:
            return

        from datetime import datetime

        # Store lock time
        self._lock_time: datetime = datetime.now()

        # Create overlay frame covering entire window
        self._lock_overlay = tk.Frame(
            self._root,
            bg=LOCK_OVERLAY_BG,
        )
        self._lock_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._lock_overlay.lift()

        # Center panel with fixed width for consistent appearance
        self._lock_frame = tk.Frame(
            self._lock_overlay,
            bg=LOCK_OVERLAY_BG,
            width=400,
            height=500,
        )
        self._lock_frame.place(relx=0.5, rely=0.5, anchor="center")
        self._lock_frame.pack_propagate(False)

        # Lock icon (emoji)
        lock_label = tk.Label(
            self._lock_frame,
            text="🔒",
            font=("TkDefaultFont", 72),
            bg=LOCK_OVERLAY_BG,
            fg=LOCK_OVERLAY_FG,
        )
        lock_label.pack(pady=(20, 10))

        # Title
        title_label = tk.Label(
            self._lock_frame,
            text="Сеанс заблокирован",
            font=("TkDefaultFont", 16, "bold"),
            bg=LOCK_OVERLAY_BG,
            fg=LOCK_OVERLAY_FG,
        )
        title_label.pack(pady=(0, 10))

        # Time of lock
        time_str = self._lock_time.strftime("%H:%M:%S")
        self._lock_time_label = tk.Label(
            self._lock_frame,
            text=f"Время блокировки: {time_str}",
            font=("TkDefaultFont", 10),
            bg=LOCK_OVERLAY_BG,
            fg="#bdc3c7",
        )
        self._lock_time_label.pack(pady=(0, 5))

        # Duration since lock (will be updated)
        self._lock_duration_label = tk.Label(
            self._lock_frame,
            text="Продолжительность: 00:00",
            font=("TkDefaultFont", 10),
            bg=LOCK_OVERLAY_BG,
            fg="#bdc3c7",
        )
        self._lock_duration_label.pack(pady=(0, 15))

        # Separator
        separator = tk.Frame(self._lock_frame, height=1, bg="#34495e")
        separator.pack(fill=tk.X, padx=30, pady=10)

        # MFA Method selection label
        method_label = tk.Label(
            self._lock_frame,
            text="Способ разблокировки:",
            font=("TkDefaultFont", 11),
            bg=LOCK_OVERLAY_BG,
            fg=LOCK_OVERLAY_FG,
        )
        method_label.pack(anchor=tk.W, padx=30, pady=(10, 5))

        # MFA Method selection frame
        self._mfa_method_var = tk.StringVar(value="password")
        self._mfa_method_frame = tk.Frame(self._lock_frame, bg=LOCK_OVERLAY_BG)
        self._mfa_method_frame.pack(fill=tk.X, padx=30, pady=5)

        # Password option
        self._create_mfa_radio(
            parent=self._mfa_method_frame,
            value="password",
            text="🔑 Пароль",
        )

        # FIDO2 option
        self._create_mfa_radio(
            parent=self._mfa_method_frame,
            value="fido2",
            text="🔐 FIDO2 ключ",
        )

        # TOTP option
        self._create_mfa_radio(
            parent=self._mfa_method_frame,
            value="totp",
            text="📱 TOTP код",
        )

        # Backup code option
        self._create_mfa_radio(
            parent=self._mfa_method_frame,
            value="backup_code",
            text="📝 Резервный код",
        )

        # Input frame
        self._mfa_input_frame = tk.Frame(self._lock_frame, bg=LOCK_OVERLAY_BG)
        self._mfa_input_frame.pack(fill=tk.X, padx=30, pady=10)

        # Input field label
        self._mfa_input_label = tk.Label(
            self._mfa_input_frame,
            text="Пароль:",
            font=("TkDefaultFont", 10),
            bg=LOCK_OVERLAY_BG,
            fg=LOCK_OVERLAY_FG,
            width=15,
            anchor=tk.E,
        )
        self._mfa_input_label.pack(side=tk.LEFT, padx=(0, 10))

        # Input field (adaptive based on method)
        self._mfa_input_var = tk.StringVar()
        self._mfa_input_entry = tk.Entry(
            self._mfa_input_frame,
            textvariable=self._mfa_input_var,
            font=("TkDefaultFont", 12),
            width=20,
            show="*",
        )
        self._mfa_input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Bind method change to update input field
        self._mfa_method_var.trace_add("write", self._on_mfa_method_changed)

        # Error message label
        self._lock_error_label = tk.Label(
            self._lock_frame,
            text="",
            font=("TkDefaultFont", 10),
            bg=LOCK_OVERLAY_BG,
            fg="#e74c3c",
            wraplength=340,
        )
        self._lock_error_label.pack(pady=5)

        # Unlock button
        self._unlock_btn = tk.Button(
            self._lock_frame,
            text="🔓 Разблокировать",
            font=("TkDefaultFont", 12),
            command=self._on_unlock_clicked,
            width=20,
            bg="#27ae60",
            fg="white",
            activebackground="#2ecc71",
            activeforeground="white",
        )
        self._unlock_btn.pack(pady=15)

        # Auto-lock countdown (if configured)
        self._auto_lock_countdown_label = tk.Label(
            self._lock_frame,
            text="",
            font=("TkDefaultFont", 9),
            bg=LOCK_OVERLAY_BG,
            fg="#95a5a6",
        )
        self._auto_lock_countdown_label.pack(pady=(5, 0))

        # Start duration update timer
        self._update_lock_duration()

        # Set focus to input field
        self._mfa_input_entry.focus_set()

    def _create_mfa_radio(self, parent: tk.Widget, value: str, text: str) -> None:
        """Создаёт радиокнопку для выбора MFA метода.

        Args:
            parent: Родительский виджет.
            value: Значение радиокнопки.
            text: Текст радиокнопки.
        """
        radio = tk.Radiobutton(
            parent,
            text=text,
            variable=self._mfa_method_var,
            value=value,
            font=("TkDefaultFont", 10),
            bg=LOCK_OVERLAY_BG,
            fg=LOCK_OVERLAY_FG,
            selectcolor="#34495e",
            activebackground=LOCK_OVERLAY_BG,
            activeforeground=LOCK_OVERLAY_FG,
        )
        radio.pack(anchor=tk.W, pady=2)

    def _on_mfa_method_changed(self, *args: Any) -> None:
        """Обрабатывает изменение метода MFA.

        Адаптирует поле ввода в зависимости от выбранного метода.
        """
        if not hasattr(self, '_mfa_method_var'):
            return

        method = self._mfa_method_var.get()

        # Update input label based on method
        labels: dict[str, str] = {
            "password": "Пароль:",
            "fido2": "PIN (опционально):",
            "totp": "TOTP код:",
            "backup_code": "Резервный код:",
        }

        if self._mfa_input_label is not None:
            self._mfa_input_label.config(text=labels.get(method, "Код:"))

        # Update input field show/hide
        if self._mfa_input_entry is not None:
            if method == "password":
                self._mfa_input_entry.config(show="*")
            else:
                self._mfa_input_entry.config(show="")

        # Clear input and error
        if self._mfa_input_var is not None:
            self._mfa_input_var.set("")

        if self._lock_error_label is not None:
            self._lock_error_label.config(text="")

    def _update_lock_duration(self) -> None:
        """Обновляет отображение продолжительности блокировки."""
        if not self._is_locked or self._lock_overlay is None:
            return

        from datetime import datetime

        if hasattr(self, '_lock_time') and self._lock_time is not None:
            duration = datetime.now() - self._lock_time
            minutes, seconds = divmod(int(duration.total_seconds()), 60)
            hours, minutes = divmod(minutes, 60)

            if hours > 0:
                duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            else:
                duration_str = f"{minutes:02d}:{seconds:02d}"

            if self._lock_duration_label is not None:
                self._lock_duration_label.config(
                    text=f"Продолжительность: {duration_str}"
                )

        # Schedule next update (every second)
        if self._lock_overlay is not None:
            self._lock_overlay.after(1000, self._update_lock_duration)

    def _hide_lock_overlay(self) -> None:
        """Скрывает overlay блокировки."""
        if self._lock_overlay is not None:
            self._lock_overlay.destroy()
            self._lock_overlay = None
            self._lock_frame = None

    def _wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные из памяти.

        Security:
            - Вызывает wipe на DocumentView
            - Очищает внутренние ссылки
        """
        if self._document_view is not None:
            self._document_view.wipe_sensitive_data()

        # Clear title references that may contain paths
        self._current_title = ""

    def _on_window_close(self) -> None:
        """Обработчик закрытия окна.

        Security:
            - Проверяет наличие несохранённых документов
            - Запрашивает подтверждение если есть unsaved changes
        """
        # Check for unsaved documents
        if self._is_modified:
            response = messagebox.askyesnocancel(
                APP_NAME,
                "У вас есть несохранённые изменения.\nСохранить перед выходом?",
                icon="warning",
            )
            if response is True:  # Yes - save and exit
                self._on_file_save()
                self.destroy()
            elif response is False:  # No - exit without saving
                self.destroy()
            # else: Cancel - don't close
        else:
            self.destroy()

    def _on_unlock_clicked(self) -> None:
        """Обработчик клика по кнопке разблокировки с MFA.

        Security:
            - Требует MFA верификацию перед разблокировкой
            - Использует выбранный метод из UI_SPEC 9.2
            - Интеграция с AuthController для реальной проверки
            - CRITICAL-001: Не разблокирует без валидного MFA
        """
        if not self._is_locked:
            return

        # Get selected MFA method and input
        if not hasattr(self, '_mfa_method_var') or self._mfa_method_var is None:
            if self._toast_service is not None:
                self._toast_service.show(
                    "UI ошибка: не выбран метод MFA",
                    ToastLevel.ERROR,
                )
            return

        selected_method = self._mfa_method_var.get()
        credential = self._mfa_input_var.get() if hasattr(self, '_mfa_input_var') else ""

        # Validate input
        if not credential.strip() and selected_method != "fido2":
            if self._lock_error_label is not None:
                self._lock_error_label.config(text="Введите учётные данные для разблокировки")
            return

        # Get auth controller and user ID
        auth_controller = self._get_auth_controller()
        user_id = self._get_current_user_id()

        if auth_controller is None or user_id is None:
            # If no auth configured, show error (security requirement)
            if self._lock_error_label is not None:
                self._lock_error_label.config(text="Система аутентификации недоступна")
            return

        # Disable unlock button during verification
        if self._unlock_btn is not None:
            self._unlock_btn.config(state=tk.DISABLED, text="Проверка...")

        try:
            # Attempt verification with selected method
            verified = False
            error_message = ""

            if selected_method == "password":
                # Use password verification via auth_controller
                verified = self._verify_password(auth_controller, user_id, credential)
                if not verified:
                    error_message = "Неверный пароль"
            elif selected_method == "fido2":
                # FIDO2 verification
                verified = self._verify_fido2(auth_controller, user_id, credential)
                if not verified:
                    error_message = "FIDO2 верификация не удалась"
            elif selected_method == "totp":
                # TOTP verification
                verified = self._verify_totp(auth_controller, user_id, credential)
                if not verified:
                    error_message = "Неверный TOTP код"
            elif selected_method == "backup_code":
                # Backup code verification
                verified = self._verify_backup_code(auth_controller, user_id, credential)
                if not verified:
                    error_message = "Неверный резервный код"

            if verified:
                logger.info("MFA verified via %s, unlocking session for user %s", selected_method, user_id)
                self.unlock_session()
            else:
                logger.warning("MFA verification failed via %s for user %s", selected_method, user_id)
                if self._lock_error_label is not None:
                    self._lock_error_label.config(text=error_message)
                # Clear input for security
                if self._mfa_input_var is not None:
                    self._mfa_input_var.set("")

        except Exception as e:
            logger.error("MFA challenge failed: %s", e)
            if self._lock_error_label is not None:
                self._lock_error_label.config(text="Ошибка аутентификации")
        finally:
            # Re-enable unlock button
            if self._unlock_btn is not None:
                self._unlock_btn.config(state=tk.NORMAL, text="🔓 Разблокировать")

    def _verify_password(self, auth_controller: Any, user_id: str, password: str) -> bool:
        """Проверяет пароль.

        Args:
            auth_controller: Контроллер аутентификации.
            user_id: ID пользователя.
            password: Пароль для проверки.

        Returns:
            True если пароль верный.
        """
        try:
            if hasattr(auth_controller, 'verify_password'):
                return bool(auth_controller.verify_password(user_id, password))
            return False
        except Exception as e:
            logger.error("Password verification failed: %s", e)
            return False

    def _verify_fido2(self, auth_controller: Any, user_id: str, pin: str) -> bool:
        """Проверяет FIDO2 ключ.

        Args:
            auth_controller: Контроллер аутентификации.
            user_id: ID пользователя.
            pin: PIN для FIDO2 (опционально).

        Returns:
            True если FIDO2 верификация прошла.
        """
        try:
            if hasattr(auth_controller, 'verify_fido2'):
                return bool(auth_controller.verify_fido2(user_id, pin))
            # Fallback: try generic verify method
            if hasattr(auth_controller, 'verify_mfa'):
                return bool(auth_controller.verify_mfa(user_id, "fido2", ""))
            return False
        except Exception as e:
            logger.error("FIDO2 verification failed: %s", e)
            return False

    def _verify_totp(self, auth_controller: Any, user_id: str, code: str) -> bool:
        """Проверяет TOTP код.

        Args:
            auth_controller: Контроллер аутентификации.
            user_id: ID пользователя.
            code: TOTP код.

        Returns:
            True если код верный.
        """
        try:
            if hasattr(auth_controller, 'verify_totp'):
                return bool(auth_controller.verify_totp(user_id, code))
            return False
        except Exception as e:
            logger.error("TOTP verification failed: %s", e)
            return False

    def _verify_backup_code(self, auth_controller: Any, user_id: str, code: str) -> bool:
        """Проверяет резервный код.

        Args:
            auth_controller: Контроллер аутентификации.
            user_id: ID пользователя.
            code: Резервный код.

        Returns:
            True если код верный.
        """
        try:
            if hasattr(auth_controller, 'verify_backup_code'):
                return bool(auth_controller.verify_backup_code(user_id, code))
            return False
        except Exception as e:
            logger.error("Backup code verification failed: %s", e)
            return False

    def _show_welcome_toast(self) -> None:
        """Показывает приветственное уведомление."""
        if self._toast_service is not None:
            self._toast_service.show(
                f"Добро пожаловать в {APP_NAME}",
                ToastLevel.INFO,
            )

    # =============================================================================
    # MENU CALLBACKS (STUBS)
    # =============================================================================

    def _on_document_convert_to_special(self) -> None:
        """Callback: File → Convert to Special Mode.

        Конвертирует документ в Special Mode (защищённый режим).
        Требует успешного Health Check и MFA верификации.

        Flow:
        1. Проверить can_enter_special() через ModeManager
        2. Если Health Check не пройден — показать HealthCheckDialog
        3. Показать AuthOverlay для MFA верификации
        4. При успехе — обновить UI и установить Special Mode
        """
        if self._mode_manager is None:
            return

        can_enter, reason = self._mode_manager.can_enter_special()

        if not can_enter:
            if reason == "health_check_failed":
                self._show_health_check_dialog_for_special_mode()
            elif reason == "disabled":
                messagebox.showwarning(
                    "Special Mode недоступен",
                    "Special Mode отключён из-за проблем безопасности.\n"
                    "Запустите Tools → Health Check для диагностики.",
                    parent=self._root,
                )
            elif reason == "already_special":
                messagebox.showinfo(
                    "Special Mode",
                    "Документ уже в Special Mode.",
                    parent=self._root,
                )
            else:
                messagebox.showwarning(
                    "Special Mode",
                    f"Невозможно войти в Special Mode: {reason}",
                    parent=self._root,
                )
            return

        self._show_auth_overlay()

    def _on_document_convert_to_normal(self) -> None:
        """Callback: File → Convert to Normal Mode.

        Конвертирует документ из Special Mode в Normal Mode.
        Требует подтверждения пользователя.

        Flow:
        1. Проверить что currently в Special Mode
        2. Показать диалог подтверждения с предупреждением
        3. При подтверждении — сохранить копию (опционально) и выйти в Normal Mode
        """
        if self._mode_manager is None:
            return

        current_mode = self._mode_manager.get_current_mode()
        if current_mode != ModeManager.MODE_SPECIAL:
            messagebox.showinfo(
                "Normal Mode",
                "Документ уже в Normal Mode.",
                parent=self._root,
            )
            return

        response = messagebox.askyesnocancel(
            "Конвертация в Normal Mode",
            "⚠️ ВНИМАНИЕ: Документ выйдет из защищённого режима.\n\n"
            "В Special Mode документ защищён от несанкционированного доступа.\n"
            "Продолжить?",
            icon="warning",
            parent=self._root,
        )

        if response is None:
            return

        if response:
            if self._toast_service is not None:
                self._toast_service.show(
                    "Создание резервной копии...",
                    ToastLevel.INFO,
                )

        success = self._mode_manager.exit_special(confirm=False)

        if success:
            self._update_mode_ui("normal")
            if self._toast_service is not None:
                self._toast_service.show(
                    "Документ конвертирован в Normal Mode",
                    ToastLevel.SUCCESS,
                )

    def _show_health_check_dialog_for_special_mode(self) -> None:
        """Показывает HealthCheckDialog для Special Mode."""
        if self._root is None:
            return

        if self._health_checker is None:
            self._health_checker = HealthChecker(version="3.0.0")

        self._health_check_dialog = HealthCheckDialog(
            parent=self._root,
            health_checker=self._health_checker,
        )
        self._health_check_dialog.show()

    def _on_file_new(self) -> None:
        """Callback: File -> New."""
        if self._controller is not None:
            self._controller.dispatch("file_new")
        elif self._toast_service is not None:
            self._toast_service.show("Создание нового документа", ToastLevel.INFO)

    def _on_file_open(self) -> None:
        """Callback: File -> Open."""
        if self._controller is not None:
            self._controller.dispatch("file_open")
        elif self._toast_service is not None:
            self._toast_service.show("Открытие документа", ToastLevel.INFO)

    def _on_file_save(self) -> None:
        """Callback: File -> Save."""
        if self._controller is not None:
            self._controller.dispatch("file_save")
        elif self._toast_service is not None:
            self._toast_service.show("Сохранение документа", ToastLevel.INFO)

    def _on_file_save_as(self) -> None:
        """Callback: File -> Save As."""
        if self._controller is not None:
            self._controller.dispatch("file_save_as")
        elif self._toast_service is not None:
            self._toast_service.show("Сохранение документа как...", ToastLevel.INFO)

    def _on_file_print(self) -> None:
        """Callback: File -> Print."""
        if self._controller is not None:
            self._controller.dispatch("file_print")
        elif self._toast_service is not None:
            self._toast_service.show("Печать документа", ToastLevel.INFO)

    def _on_edit_undo(self) -> None:
        """Callback: Edit -> Undo."""
        if self._controller is not None:
            self._controller.dispatch("edit_undo")

    def _on_edit_redo(self) -> None:
        """Callback: Edit -> Redo."""
        if self._controller is not None:
            self._controller.dispatch("edit_redo")

    def _on_edit_cut(self) -> None:
        """Callback: Edit -> Cut."""
        if self._controller is not None:
            self._controller.dispatch("edit_cut")

    def _on_edit_copy(self) -> None:
        """Callback: Edit -> Copy."""
        if self._controller is not None:
            self._controller.dispatch("edit_copy")

    def _on_edit_paste(self) -> None:
        """Callback: Edit -> Paste."""
        if self._controller is not None:
            self._controller.dispatch("edit_paste")

    def _on_edit_find(self) -> None:
        """Callback: Edit -> Find."""
        if self._controller is not None:
            self._controller.dispatch("edit_find")

    def _on_view_toggle_sidebar(self) -> None:
        """Callback: View -> Toggle Sidebar."""
        if self._main_layout is not None:
            self._main_layout.toggle_sidebar()

    def _on_view_toggle_statusbar(self) -> None:
        """Callback: View -> Toggle StatusBar."""
        if self._statusbar is not None:
            if self._statusbar.is_visible():
                self._statusbar.hide()
            else:
                self._statusbar.show()

    def _on_view_zoom_in(self) -> None:
        """Callback: View -> Zoom In."""
        if self._controller is not None:
            self._controller.dispatch("view_zoom_in")

    def _on_view_zoom_out(self) -> None:
        """Callback: View -> Zoom Out."""
        if self._controller is not None:
            self._controller.dispatch("view_zoom_out")

    def _on_view_zoom_reset(self) -> None:
        """Callback: View -> Reset Zoom."""
        if self._controller is not None:
            self._controller.dispatch("view_zoom_reset")

    def _on_view_workflow_simple_mode(self) -> None:
        """Callback: View -> Approval Workflow -> Simple Mode.

        Переключает между упрощённым (DRAFT ↔ SIGNED) и полным workflow.
        """
        if self._workflow_simple_var is not None:
            self._workflow_simple_mode = self._workflow_simple_var.get()

            # Dispatch event to controller to update workflow indicator
            if self._controller is not None:
                self._controller.dispatch(
                    "workflow_mode_changed",
                    simple_mode=self._workflow_simple_mode,
                )

            # Show toast notification
            if self._toast_service is not None:
                mode_text = "упрощённый" if self._workflow_simple_mode else "полный"
                self._toast_service.show(
                    f"Режим workflow: {mode_text}",
                    ToastLevel.INFO,
                )

    def is_workflow_simple_mode(self) -> bool:
        """Возвращает текущий режим workflow.

        Returns:
            True если включен Simple Mode (только DRAFT ↔ SIGNED).
        """
        return self._workflow_simple_mode

    def _on_view_notifications(self) -> None:
        """Callback: Уведомления → История.

        Показывает диалог истории уведомлений.
        """
        if self._notification_service is None:
            return

        # Get notification history (Phase 7 API)
        notifications = self._notification_service.get_history()
        count = len(notifications)

        if count == 0:
            if self._toast_service is not None:
                self._toast_service.show("Нет уведомлений в истории", ToastLevel.INFO)
            return

        # Build notification list for display
        lines = [f"Уведомлений в истории: {count}\n"]
        for n in notifications[:10]:  # Show first 10
            # Map priority to emoji
            if n.priority.value >= 4:
                status = "🔴"
            elif n.priority.value >= 3:
                status = "⚠️"
            else:
                status = "ℹ️"
            read_status = "✓" if n.read else "○"
            lines.append(f"{status} [{read_status}] [{n.category.upper()}] {n.message}")

        if count > 10:
            lines.append(f"\n... и ещё {count - 10} уведомлений")

        message = "\n".join(lines)
        messagebox.showinfo("История уведомлений", message, parent=self._root)

    def _on_notifications_mark_all_read(self) -> None:
        """Callback: Уведомления → Отметить все прочитанными."""
        if self._notification_service is None:
            return

        self._notification_service.mark_all_as_read()
        if self._toast_service is not None:
            self._toast_service.show("Все уведомления отмечены прочитанными", ToastLevel.SUCCESS)

    def _on_security_lock(self) -> None:
        """Callback: Security -> Lock Session."""
        self.lock_session()

    def _on_security_change_password(self) -> None:
        """Callback: Security -> Change Password."""
        if self._controller is not None:
            self._controller.dispatch("security_change_password")

    def _on_security_health_check(self) -> None:
        """Callback: Security -> Health Check."""
        self._on_tools_health_check()

    def _on_security_backup_codes(self) -> None:
        """Callback: Security -> Резервные коды."""
        if self._root is None:
            return

        user_id = self._get_current_user_id()
        if user_id is None:
            if self._toast_service is not None:
                self._toast_service.show(
                    "Требуется аутентификация",
                    ToastLevel.WARNING,
                )
            return

        from src.gui.dialogs.backup_codes_dialog import BackupCodesDialog

        dialog = BackupCodesDialog(
            parent=self._root,
            user_id=user_id,
        )
        dialog.show()

    def _on_security_crypto_profile(self) -> None:
        """Callback: Security -> Профиль безопасности."""
        if self._root is None:
            return

        from src.gui.dialogs.crypto_profile_dialog import (
            CryptoProfileDialog,
            ProfileSelectionResult,
        )
        from src.security.crypto.service.profiles import CryptoProfile

        # TODO: Get current profile from service
        dialog = CryptoProfileDialog(
            parent=self._root,
            current_profile=CryptoProfile.STANDARD,
        )
        result = dialog.show()
        if result is not None and isinstance(result, ProfileSelectionResult):
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Выбран профиль: {result.profile.label()}",
                    ToastLevel.SUCCESS,
                )

    def _on_security_auto_lock_settings(self) -> None:
        """Callback: Security -> Настройки автоблокировки."""
        if self._root is None:
            return

        from src.gui.dialogs.auto_lock_settings_dialog import (
            AutoLockSettingsDialog,
            AutoLockSettingsResult,
        )
        from src.security.lock.session_lock_manager import LockConfig

        # TODO: Get current config from service
        config = LockConfig(auto_lock_minutes=15)
        dialog = AutoLockSettingsDialog(
            parent=self._root,
            current_config=config,
        )
        result = dialog.show()
        if result is not None and isinstance(result, AutoLockSettingsResult):
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Таймаут: {result.config.auto_lock_minutes} мин",
                    ToastLevel.SUCCESS,
                )

    def _on_help_about(self) -> None:
        """Callback: Help -> About."""
        messagebox.showinfo(
            f"О {APP_NAME}",
            f"{APP_NAME}\n"
            f"Version: 3.0.0\n"
            f"Enterprise WYSIWYG editor for Epson FX-890\n"
            f"with Zero Trust cryptography",
        )

    # =============================================================================
    # SIDEBAR CALLBACKS
    # =============================================================================

    def _on_sidebar_toggled(self, visible: bool) -> None:
        """Callback при переключении sidebar.

        Args:
            visible: True если sidebar стал видимым.
        """
        pass  # Can be used to update menu checkbox

    def _on_section_selected(self, section_id: str) -> None:
        """Callback при выборе секции в sidebar.

        Args:
            section_id: Идентификатор выбранной секции.
        """
        if self._controller is not None:
            self._controller.dispatch("section_selected", section_id=section_id)

    def _on_tree_item_selected(self, item_id: str) -> None:
        """Callback при выборе элемента в дереве.

        Args:
            item_id: Идентификатор выбранного элемента.
        """
        if self._controller is not None:
            self._controller.dispatch("tree_item_selected", item_id=item_id)

    # =============================================================================
    # TABBAR CALLBACKS
    # =============================================================================

    def _on_new_tab(self) -> None:
        """Callback при создании новой вкладки."""
        if self._controller is not None:
            self._controller.dispatch("tab_new")

    def _on_tab_close(self, document_id: str) -> bool:
        """Callback при закрытии вкладки.

        Args:
            document_id: Идентификатор документа.

        Returns:
            True если вкладку можно закрыть.
        """
        if self._controller is not None:
            result = self._controller.dispatch("tab_close", document_id=document_id)
            return bool(result) if result is not None else True
        return True

    def _on_tab_activate(self, document_id: str) -> None:
        """Callback при активации вкладки.

        Args:
            document_id: Идентификатор активированного документа.
        """
        if self._controller is not None:
            self._controller.dispatch("tab_activate", document_id=document_id)
        # Document is set via controller dispatch or handled separately
        # Note: DocumentView.set_document expects DocumentProtocol, not str

    # =============================================================================
    # PHASE 4: NAVIGATION DIALOG HANDLERS
    # =============================================================================

    def _on_goto(self) -> None:
        """Callback: Edit -> Go to...

        Открывает диалог перехода к позиции в документе
        и выполняет навигацию при подтверждении.

        Example:
            >>> window._on_goto()  # Показывает диалог "Перейти к"
        """
        if self._root is None or self._document_view is None:
            return

        from src.gui.dialogs.navigation_dialogs import BookmarkItem, GotoDialog

        # Get document info
        total_pages = self._document_view.get_total_pages()
        current_page = self._document_view.get_current_page()

        # Prepare bookmarks list
        bookmarks: list[BookmarkItem] = []
        if self._bookmark_manager is not None:
            for bm in self._bookmark_manager.get_all_bookmarks():
                # Convert paragraph index to approximate page
                lines_per_page = 66
                page = (bm.paragraph_index // lines_per_page) + 1
                bookmarks.append(
                    BookmarkItem(
                        id=bm.name,
                        name=bm.name,
                        page=page,
                        line=bm.run_index + 1,
                        description=f"Параграф {bm.paragraph_index + 1}",
                    )
                )

        dialog = GotoDialog(
            cast(tk.Widget, self._root),
            total_pages=total_pages,
            current_page=current_page,
            bookmarks=bookmarks if bookmarks else None,
        )
        result = dialog.show()

        if result:
            try:
                self._document_view.goto_page(result["page"], result.get("line"))
                if self._toast_service is not None:
                    self._toast_service.show(
                        f"Переход к странице {result['page']}",
                        ToastLevel.INFO,
                    )
            except Exception as e:
                logger.error("Failed to navigate: %s", e)
                messagebox.showerror("Ошибка", f"Не удалось выполнить переход: {e}")

    def _on_bookmarks(self) -> None:
        """Callback: Edit -> Bookmarks

        Открывает диалог управления закладками с возможностью
        перехода к выбранной позиции.

        Example:
            >>> window._on_bookmarks()  # Показывает диалог "Закладки"
        """
        if self._root is None or self._document_view is None:
            return

        from uuid import UUID

        from src.gui.dialogs.navigation_dialogs import BookmarksDialog

        # Ensure bookmark manager exists
        if self._bookmark_manager is None:
            # Create new bookmark manager for current document
            doc_id = self._document_view.current_document_id
            if doc_id:
                try:
                    uuid = UUID(doc_id)
                except ValueError:
                    uuid = UUID(int=0)  # Fallback
                self._bookmark_manager = BookmarkManager(uuid)
            else:
                messagebox.showwarning(
                    "Закладки",
                    "Откройте документ для работы с закладками",
                )
                return

        current_page = self._document_view.get_current_page()

        # Store document_view reference for lambda
        document_view = self._document_view

        dialog = BookmarksDialog(
            cast(tk.Widget, self._root),
            bookmark_manager=self._bookmark_manager,
            current_page=current_page,
            on_goto=lambda page, line: document_view.goto_page(page, line),
        )
        result = dialog.show()

        if result and result.get("action") == "goto":
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Переход к странице {result['page']}",
                    ToastLevel.INFO,
                )

    def _on_prefill(self) -> None:
        """Callback: Edit -> Prefill from Previous

        Открывает диалог автозаполнения для копирования значений
        из предыдущих документов.

        Example:
            >>> window._on_prefill()  # Показывает диалог "Автозаполнение"
        """
        if self._root is None or self._document_view is None:
            return

        from src.documents.types.document_type import DocumentMode
        from src.gui.dialogs.workflow_dialogs import PrefillDialog

        # Check if we have a structured form document
        if self._document_view.current_mode != DocumentMode.STRUCTURED_FORM:
            messagebox.showinfo(
                "Автозаполнение",
                "Автозаполнение доступно только для структурированных форм",
            )
            return

        # Get current field or use first available
        form_fields = self._document_view.get_form_fields()
        if not form_fields:
            messagebox.showwarning(
                "Автозаполнение",
                "Нет доступных полей для автозаполнения",
            )
            return

        # Use first field or current focused field
        field_id = next(iter(form_fields.keys()))
        field = form_fields[field_id]

        # Get field info
        field_label_obj = getattr(field, "_field_def", None)
        if field_label_obj:
            field_label_str = getattr(field_label_obj, "label", field_id)
        else:
            field_label_str = field_id

        current_value = getattr(field, "get_value", lambda: "")()

        dialog = PrefillDialog(
            cast(tk.Widget, self._root),
            field_id=field_id,
            field_label=field_label_str if field_label_str else field_id,
            current_value=current_value,
            on_select=lambda value: field.set_value(value) if hasattr(field, "set_value") else None,
        )
        result = dialog.show()

        if result:
            # Apply to field
            if hasattr(field, "set_value"):
                field.set_value(result)
                if self._toast_service is not None:
                    self._toast_service.show(
                        f"Поле '{field_label_str}' заполнено автоматически",
                        ToastLevel.SUCCESS,
                    )

            # Dispatch event for controller to handle bulk prefill
            if self._controller is not None:
                self._controller.dispatch(
                    "prefill_field",
                    field_id=field_id,
                    value=result,
                )

    def _apply_prefill(self, result: dict[str, Any]) -> None:
        """Применяет результаты автозаполнения к полям формы.

        Args:
            result: Словарь с результатами автозаполнения.

        Example:
            >>> window._apply_prefill({
            ...     "customer_name": "ООО Ромашка",
            ...     "inn": "1234567890",
            ... })
        """
        if self._document_view is None:
            return

        applied = 0
        failed = 0

        for field_id, value in result.items():
            success = self._document_view.set_form_field_value(field_id, value)
            if success:
                applied += 1
            else:
                failed += 1

        if self._toast_service is not None:
            if applied > 0:
                self._toast_service.show(
                    f"Заполнено полей: {applied}",
                    ToastLevel.SUCCESS,
                )
            if failed > 0:
                self._toast_service.show(
                    f"Не удалось заполнить: {failed} полей",
                    ToastLevel.WARNING,
                )

    def _on_view_barcode_render_mode_changed(self) -> None:
        """Обработчик изменения режима рендеринга штрих-кодов (View → Barcode Render Mode)."""
        mode = self._barcode_render_var.get() if self._barcode_render_var else "placeholder"
        logger.info(f"Barcode render mode changed to: {mode}")
        if self._toast_service:
            self._toast_service.show(
                f"Режим рендеринга штрих-кодов: {'Реальный' if mode == 'real' else 'Placeholder'}",
                ToastLevel.INFO,
            )

    def _on_window_list(self) -> None:
        """Callback: View → Window → Список окон.

        Показывает список всех открытых окон.
        """
        if self._window_manager is None or self._toast_service is None:
            return

        windows = self._window_manager.get_window_list()
        if not windows:
            self._toast_service.show("Нет открытых окон", ToastLevel.INFO)
            return

        # Build window list message
        window_names = []
        for w in windows:
            status = "[свёрнуто]" if w.is_minimized else ""
            marker = "✓" if self._window_manager.is_main_window(w.window_id) else " "
            window_names.append(f"{marker} {w.title} {status}")

        message = "Открытые окна:\n" + "\n".join(window_names)
        messagebox.showinfo("Список окон", message, parent=self._root)

    def _on_window_minimize_all(self) -> None:
        """Callback: View → Window → Свернуть все.

        Сворачивает все окна приложения.
        """
        if self._window_manager is None:
            return

        count = self._window_manager.minimize_all()
        if self._toast_service is not None:
            self._toast_service.show(f"Свёрнуто окон: {count}", ToastLevel.INFO)

    def _on_window_restore_all(self) -> None:
        """Callback: View → Window → Восстановить все.

        Восстанавливает все свёрнутые окна.
        """
        if self._window_manager is None:
            return

        count = self._window_manager.restore_all()
        if self._toast_service is not None:
            self._toast_service.show(f"Восстановлено окон: {count}", ToastLevel.INFO)

    def _on_insert_barcode(self) -> None:
        """Handler для вставки штрих-кода (Insert → Barcode).

        Phase 6: Открывает диалог выбора типа штрих-кода.
        """
        logger.info("Insert Barcode menu triggered")
        # TODO: Integrate with BarcodeController in Phase 6
        messagebox.showinfo(
            "Вставка штрих-кода",
            "📊 Диалог выбора штрих-кода\n\n"
            "Будет реализовано в Phase 6:\n"
            "- Выбор типа (CODE128, EAN13, etc)\n"
            "- Режим Hardware/Software\n"
            "- Предпросмотр",
            parent=self._root,
        )

    def _on_insert_qr(self) -> None:
        """Handler для вставки QR-кода (Insert → QR Code).

        Phase 6: Открывает диалог настроек QR.
        """
        logger.info("Insert QR menu triggered")
        # TODO: Integrate with BarcodeController in Phase 6
        messagebox.showinfo(
            "Вставка QR-кода",
            "🔳 Диалог настроек QR\n\n"
            "Будет реализовано в Phase 6:\n"
            "- Настройка уровня коррекции\n"
            "- Выбор версии QR\n"
            "- Предпросмотр и экспорт",
            parent=self._root,
        )

    def _on_insert_special(self) -> None:
        """Handler для вставки спецсимвола (Insert → Special Character).

        Phase 6: Placeholder для будущей реализации.
        """
        logger.info("Insert Special Character menu triggered")
        messagebox.showinfo(
            "Специальные символы",
            "Вставка специальных символов ESC/P\n\nБудет реализовано в следующей версии.",
            parent=self._root,
        )

    # =============================================================================
    # NOTIFICATION SERVICE CALLBACKS
    # =============================================================================

    def _on_notification_received(self, notification: Any) -> None:
        """Callback при получении нового уведомления.

        Обновляет индикатор уведомлений в StatusBar и показывает toast.

        Args:
            notification: Объект уведомления.
        """
        # Update StatusBar badge count
        if self._statusbar is not None and self._notification_service is not None:
            count = self._notification_service.count()
            self._statusbar.set_notification_count(count)

        # Show toast based on notification type
        if self._toast_service is not None:
            from src.services.notification_service import NotificationType

            toast_mapping = {
                NotificationType.INFO: ToastLevel.INFO,
                NotificationType.SUCCESS: ToastLevel.SUCCESS,
                NotificationType.WARNING: ToastLevel.WARNING,
                NotificationType.ERROR: ToastLevel.ERROR,
                NotificationType.PROGRESS: ToastLevel.INFO,
            }
            level = toast_mapping.get(notification.type, ToastLevel.INFO)
            self._toast_service.show(notification.message, level)

    def _on_notification_dismissed(self, notification_id: Any, action: Optional[str]) -> None:
        """Callback при закрытии уведомления.

        Обновляет индикатор уведомлений в StatusBar.

        Args:
            notification_id: ID закрытого уведомления.
            action: Выбранное действие (если есть).
        """
        # Update StatusBar badge count
        if self._statusbar is not None and self._notification_service is not None:
            count = self._notification_service.count()
            self._statusbar.set_notification_count(count)

    # =============================================================================
    # SERVICE ACCESS PROPERTIES
    # =============================================================================

    @property
    def window_manager(self) -> WindowManager:
        """Returns WindowManager for window management.

        Returns:
            WindowManager instance.

        Raises:
            RuntimeError: If MainWindow not initialized.
        """
        if self._window_manager is None:
            raise RuntimeError("MainWindow not initialized")
        return self._window_manager

    @property
    def sync_service(self) -> SyncService:
        """Returns SyncService for inter-window synchronization.

        Returns:
            SyncService instance.

        Raises:
            RuntimeError: If MainWindow not initialized.
        """
        if self._sync_service is None:
            raise RuntimeError("MainWindow not initialized")
        return self._sync_service

    @property
    def notification_service(self) -> NotificationService:
        """Returns NotificationService for notifications.

        Returns:
            NotificationService instance.

        Raises:
            RuntimeError: If MainWindow not initialized.
        """
        if self._notification_service is None:
            raise RuntimeError("MainWindow not initialized")
        return self._notification_service


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "MainWindow",
    "APP_NAME",
    "LOCK_OVERLAY_BG",
    "LOCK_OVERLAY_FG",
]
