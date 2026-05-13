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
from typing import TYPE_CHECKING, Any, Final, Optional, cast

if TYPE_CHECKING:
    from src.controller.workflow_controller import WorkflowController
    from src.gui.controllers.barcode_controller import BarcodeController
    from src.gui.security.mfa_gate import MFAGate

from src.gui.components.sync.window_sync_indicator import (
    TitleBarSyncDecorator,
)
from src.gui.core.commands.text_commands import InsertTextCommand
from src.gui.core.error_handler import GUIErrorHandler
from src.gui.core.protocols import ControllerProtocol
from src.gui.dialogs.navigation_dialogs import BookmarksDialog, GotoDialog
from src.gui.dialogs.special_character_dialog import (
    SpecialCharacterDialog,
    SpecialCharResult,
)
from src.gui.layout.layout_constants import (
    DEFAULT_WINDOW_HEIGHT,
    DEFAULT_WINDOW_WIDTH,
    MIN_WINDOW_HEIGHT,
    MIN_WINDOW_WIDTH,
)
from src.gui.layout.main_layout import MainLayout
from src.gui.security.mode_manager import ModeManager
from src.gui.security.session_lock_screen import SessionLockScreen
from src.gui.services.drag_drop_service import DragDropService
from src.gui.services.key_bindings import KeyBindingsService
from src.gui.services.notification_service import (
    CATEGORY_SECURITY,
    CATEGORY_SYSTEM,
    CATEGORY_WORKFLOW,
    NotificationPriority,
    NotificationService,
)
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
from src.model.document import Document
from src.security.audit import AuditEventType, AuditLog
from src.security.auth.auth_service import AuthService
from src.security.auth.session import SessionManager
from src.security.monitoring.health_checker import HealthChecker

# Phase 4: Dialog imports (lazy loaded in methods to avoid circular imports)
# from src.gui.dialogs.workflow_dialogs import PrefillDialog

# Logger for this module
logger: logging.Logger = logging.getLogger(__name__)

# Window title
APP_NAME: Final[str] = "FX Text Processor 3"
TITLE_SEPARATOR: Final[str] = " - "
MODIFIED_INDICATOR: Final[str] = "*"


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
        toast_service: Optional[ToastService] = None,
        window_manager: Optional[WindowManager] = None,
        sync_service: Optional[SyncService] = None,
        notification_service: Optional[NotificationService] = None,
        drag_drop_service: Optional[DragDropService] = None,
        mode_manager: Optional[ModeManager] = None,
        workflow_state_manager: Optional[Any] = None,
        controller: Optional[ControllerProtocol] = None,
        audit_log: Optional["AuditLog"] = None,
        workflow_controller: Optional["WorkflowController"] = None,
        mfa_gate: Optional["MFAGate"] = None,
    ) -> None:
        """Инициализация MainWindow.

        Args:
            toast_service: Опциональный сервис уведомлений.
            window_manager: Опциональный менеджер окон.
            sync_service: Опциональный сервис синхронизации.
            notification_service: Опциональный сервис нотификаций.
            drag_drop_service: Опциональный сервис drag-and-drop.
            mode_manager: Опциональный ModeManager.
            workflow_state_manager: Опциональный WorkflowStateManager.
            controller: Опциональный контроллер для callbacks.
            audit_log: Опциональный AuditLog для аудита событий.
            workflow_controller: Контроллер workflow для WorkflowStateManager.
            mfa_gate: MFA gate для WorkflowStateManager.

        Example:
            >>> window = MainWindow(controller=my_controller)
        """
        self._controller: Optional[ControllerProtocol] = controller
        self._workflow_controller: Optional["WorkflowController"] = workflow_controller
        self._mfa_gate: Optional["MFAGate"] = mfa_gate
        self._toast_service: Optional[ToastService] = toast_service
        self._window_manager: Optional[WindowManager] = window_manager
        self._sync_service: Optional[SyncService] = sync_service
        self._notification_service: Optional[NotificationService] = notification_service
        self._drag_drop_service: Optional[DragDropService] = drag_drop_service
        self._mode_manager: Optional[ModeManager] = mode_manager
        self._workflow_state_manager: Optional[Any] = workflow_state_manager
        self._root: Optional[tk.Tk] = None
        self._audit_log: Optional["AuditLog"] = audit_log
        # Barcode controller
        self._barcode_controller: Optional[BarcodeController] = None

        # Component references
        self._menubar: Optional[tk.Menu] = None
        self._main_toolbar: Optional[Any] = None
        self._main_layout: Optional[MainLayout] = None
        self._sidebar: Optional[SideBar] = None
        self._cardfile_tabbar: Optional[CardFileTabBar] = None
        self._document_view: Optional[DocumentView] = None
        self._statusbar: Optional[StatusBar] = None

        # Multi-window support: DocumentView for new windows (Toplevel instances)
        self._new_window_doc_views: dict[str, Any] = {}

        # Multi-window support: stores DocumentView for new Toplevel windows
        # Key: window_id from WindowManager, Value: DocumentView instance
        self._new_window_document_views: dict[str, Any] = {}

        # Session lock screen (Toplevel)
        self._session_lock_screen: Optional[SessionLockScreen] = None

        # Auto-lock
        self._auto_lock_timer_id: Optional[str] = None
        self._auto_lock_minutes: int = 15  # Default 15 min
        self._last_activity_time: float = 0.0

        # State
        self._is_initialized: bool = False
        self._is_locked: bool = False
        self._current_title: str = ""
        self._is_modified: bool = False

        self._auth_overlay: Optional[AuthOverlay] = None
        self._health_check_dialog: Optional[Any] = None
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

        self._main_window_id: Optional[str] = None

        # Session Manager for authentication
        self._session_manager: Optional[SessionManager] = None
        self._current_session_id: Optional[str] = None

        # Auth services for session lock (injected from AppController)
        self._password_service: Optional[Any] = None
        self._mfa_manager: Optional[Any] = None

        # New window counter for multi-window support
        self._new_window_counter: int = 0

        # KeyBindingsService
        self._key_bindings: Optional[KeyBindingsService] = None

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

        # Wire DI-injected services that need root or each other
        if self._window_manager is not None:
            self._main_window_id = self._window_manager.register_window(
                self._root, APP_NAME, is_modal=False
            )
            self._window_manager.set_main_window_id(self._main_window_id)
        # ToastService has no set_root method (root is set via constructor)
        # SyncService, NotificationService, DragDropService, ModeManager,
        # WorkflowStateManager already have their dependencies externally.

        # Configure grid
        self._root.rowconfigure(2, weight=1)  # Main content expands (row 2 after toolbar)
        self._root.columnconfigure(0, weight=1)

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

        self._key_bindings = KeyBindingsService()

        # Show welcome toast
        self._show_welcome_toast()

        # Phase 3: Startup Health Check
        self._run_startup_health_check()

        # Check session and show AuthWindow if needed
        self._check_session_and_auth()

        # Initialize auto-lock timer
        import time

        self._last_activity_time = time.time()
        self._bind_activity_events()
        self._schedule_auto_lock_check()

        self._is_initialized = True

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
            self._toast_service = None

        # Cleanup NotificationService
        if self._notification_service is not None:
            self._notification_service.dismiss_all()
            self._notification_service = None

        # Destroy session lock screen if present
        if self._session_lock_screen is not None:
            try:
                self._session_lock_screen.wipe_credentials()
                self._session_lock_screen.destroy()
            except (tk.TclError, AttributeError, RuntimeError) as e:
                logger.debug("Session lock screen cleanup error (non-critical): %s", e)
            self._session_lock_screen = None

        # Cancel auto-lock timer
        if self._auto_lock_timer_id is not None and self._root is not None:
            try:
                self._root.after_cancel(self._auto_lock_timer_id)
            except (tk.TclError, ValueError) as e:
                logger.debug("Auto-lock timer cancel error (non-critical): %s", e)
            self._auto_lock_timer_id = None

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

        # Map category to GUI NotificationService category
        category_mapping = {
            "info": CATEGORY_SYSTEM,
            "success": CATEGORY_WORKFLOW,
            "warning": CATEGORY_SYSTEM,
            "error": CATEGORY_SECURITY,
        }
        notif_category = category_mapping.get(category.lower(), CATEGORY_SYSTEM)

        # Map NotificationPriority to ToastLevel for toast display
        toast_mapping = {
            NotificationPriority.LOW: ToastLevel.INFO,
            NotificationPriority.NORMAL: ToastLevel.INFO,
            NotificationPriority.HIGH: ToastLevel.WARNING,
            NotificationPriority.CRITICAL: ToastLevel.ERROR,
        }
        toast_level = toast_mapping.get(priority, ToastLevel.INFO)

        # Show via NotificationService (GUI version returns UUID string)
        notification_id = self._notification_service.notify(
            message=message,
            category=notif_category,
            priority=priority,
        )

        # Also show toast for immediate visual feedback
        if self._toast_service is not None:
            self._toast_service.show(message, toast_level)

        return notification_id

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

        # Update tab indicators based on document state
        is_encrypted = getattr(document, "is_encrypted", False)
        is_readonly = getattr(document, "is_readonly", False)
        is_modified = getattr(document, "is_modified", False)
        self._cardfile_tabbar.set_tab_encrypted(doc_id, bool(is_encrypted))
        self._cardfile_tabbar.set_tab_readonly(doc_id, bool(is_readonly))
        self._cardfile_tabbar.set_tab_modified(doc_id, bool(is_modified))

    def remove_document(self, doc_id: str) -> None:
        """Удаляет документ из UI (вкладку).

        Args:
            doc_id: Идентификатор документа для удаления.
        """
        if self._cardfile_tabbar is None:
            return

        self._cardfile_tabbar.close_tab(doc_id)

    def set_document_modified(self, doc_id: str, modified: bool) -> None:
        """Устанавливает индикатор изменений для вкладки документа.

        Args:
            doc_id: Идентификатор документа.
            modified: True если документ изменён.
        """
        if self._cardfile_tabbar is None:
            return

        self._cardfile_tabbar.set_tab_modified(doc_id, modified)

    def set_title(self, title: str, modified: bool = False) -> None:
        """Устанавливает заголовок окна с индикатором изменений.

        Сохраняет «чистый» заголовок для последующего использования
        TitleBarSyncDecorator.

        Args:
            title: Базовый заголовок (имя документа).
            modified: True если документ изменён (префикс "*").
        """
        self._current_title = title
        prefix = MODIFIED_INDICATOR if modified else ""
        full_title = f"{prefix}{title}{TITLE_SEPARATOR}{APP_NAME}"
        if self._root is not None:
            self._root.title(full_title)

    def update_window_sync_status(self, status: str) -> None:
        """Обновляет глобальный индикатор синхронизации в заголовке окна.

        Args:
            status: Статус из :class:`SyncStatus`.
        """
        if self._root is None:
            return
        TitleBarSyncDecorator.update_title(self._root, status)

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

    def lock_session(self, trigger: str = "manual") -> None:
        """Блокирует сессию (screen lock).

        Security:
            - Закрывает все auxiliary windows через WindowManager
            - Wipe sensitive data
            - Hide DocumentView
            - Создаёт полноэкранный SessionLockScreen

        Args:
            trigger: Причина блокировки ("manual", "auto", etc.).

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

        # Create and show fullscreen lock screen
        from datetime import datetime

        now = datetime.now()
        self._session_lock_screen = SessionLockScreen(
            parent=self._root,
            on_unlock=self._on_unlock_attempt,
            locked_at=now,
            trigger=trigger,
            auto_lock_minutes=self._auto_lock_minutes,
            password_service=self._password_service,
            mfa_manager=self._mfa_manager,
        )
        self._session_lock_screen.show()

        # Show notification
        if self._toast_service is not None:
            self._toast_service.show("Сессия заблокирована", ToastLevel.INFO)

        # Log to audit
        if self._audit_log:
            user_id = self._get_current_user_id()
            if user_id:
                try:
                    self._audit_log.log_event(
                        AuditEventType.SESSION_LOCKED,
                        details={"user_id": user_id, "trigger": trigger},
                    )
                except Exception as e:
                    logging.exception("Failed to log session lock: %s", e)

    def unlock_session(self) -> None:
        """Разблокирует сессию.

        Восстанавливает отображение документа после аутентификации.

        Example:
            >>> # After successful authentication
            >>> window.unlock_session()
        """
        if not self._is_locked:
            return

        self._is_locked = False

        # Destroy lock screen
        if self._session_lock_screen is not None:
            try:
                self._session_lock_screen.wipe_credentials()
                self._session_lock_screen.destroy()
            except (tk.TclError, AttributeError, RuntimeError) as e:
                logger.debug("Session lock screen cleanup error (non-critical): %s", e)
            self._session_lock_screen = None

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
                    logging.exception("Failed to log session unlock: %s", e)

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
        if self._toast_service is not None:
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

        except (KeyError, AttributeError, tk.TclError) as exc:
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
        1. Показать SecurityHealthCheckDialog
        2. Если не пройден — return
        3. Показать AuthOverlay
        4. При успехе auth:
           - Переключить режим
           - Обновить StatusBar
           - Обновить Menu
        """
        if self._mode_manager is None or self._root is None:
            return

        # Step 1: Show SecurityHealthCheckDialog
        from src.gui.dialogs.security_health_check_dialog import (
            SecurityHealthCheckDialog,
        )

        dialog = SecurityHealthCheckDialog(
            parent=cast(tk.Widget, self._root),
            health_checker=self._health_checker,
        )
        passed = dialog.show()
        if not passed:
            if self._toast_service is not None:
                self._toast_service.show(
                    "Special Mode entry cancelled",
                    ToastLevel.INFO,
                )
            return

        # Step 2: Show AuthOverlay
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

        from src.gui.dialogs.health_check_dialog import HealthCheckDialog

        self._health_check_dialog = HealthCheckDialog(
            parent=self._root,
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
            except (AttributeError, KeyError, tk.TclError) as _exc:
                # Log error but continue - AuthOverlay will handle gracefully
                self._error_handler.handle_silent(
                    _exc,
                    {
                        "operation": "_get_auth_service",
                        "controller": "get_auth_service",
                    },
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
            except (AttributeError, KeyError, tk.TclError) as e:
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
            except (AttributeError, KeyError, tk.TclError) as e:
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

        # Format menu
        format_menu = tk.Menu(self._menubar, tearoff=0)
        format_menu.add_command(
            label="Page Setup...",
            command=self._on_page_setup,
            accelerator="Ctrl+Shift+P",
        )
        self._menubar.add_cascade(label="Format", menu=format_menu)

        # Insert menu
        insert_menu = tk.Menu(self._menubar, tearoff=0)
        insert_menu.add_command(
            label="📊 Barcode...",
            command=self._on_insert_barcode,
            accelerator="Ctrl+Shift+B",
        )
        insert_menu.add_command(
            label="🔳 QR Code...",
            command=self._on_insert_qr,
            accelerator="Ctrl+Shift+Q",
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
        view_menu.add_command(label="Go To...", command=self._on_goto, accelerator="Ctrl+G")
        view_menu.add_command(label="Bookmarks", command=self._on_bookmarks, accelerator="Ctrl+B")
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
            label="Отметить все прочитанными",
            command=self._on_notifications_mark_all_read,
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
            label="Настройки автоблокировки",
            command=self._on_security_auto_lock_settings,
        )
        security_menu.add_separator()
        security_menu.add_command(
            label="Integrity Check...", command=self._on_security_integrity_check
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

        # Bind keyboard shortcuts via KeyBindingsService
        self._setup_key_bindings()

    def _on_window_manager(self) -> None:
        """Open Window Manager dialog."""
        if self._window_manager is None or self._sync_service is None or self._root is None:
            return

        from src.gui.dialogs.window_manager_dialog import WindowManagerDialog

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
        """Настраивает базовый UI для нового окна с интегрированным DocumentView.

        Создаёт структуру меню и основной контент area с полноценным
        DocumentView для редактирования документов в новом окне.

        Args:
            window: Корневой Toplevel для нового окна.
            window_id: Уникальный ID окна из WindowManager.

        Note:
            Использует None для statusbar, так как новые окна не имеют
            StatusBar. DocumentView корректно обрабатывает отсутствие
            statusbar благодаря optional parameter в конструкторе.
        """
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

        # Main content area with DocumentView
        content_frame = tk.Frame(window, bg="#f8f9fa")
        content_frame.pack(fill=tk.BOTH, expand=True)

        # Create document view with StatusBar reference (None for new window context)
        # Store in both window._document_view (dynamic attribute) and registry for type safety
        doc_view = DocumentView(
            widget_id="document_view",
            controller=self._controller,
            on_paper_setup=self._on_paper_setup,
            statusbar=None,
        )

        # Store in registry with window_id as key
        self._new_window_doc_views[window_id] = doc_view

        doc_view.mount(content_frame)
        doc_view.widget.pack(fill=tk.BOTH, expand=True)

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
        """Handle new window close.

        Security:
            - Очищает sensitive данные из DocumentView
            - Unregisters window от WindowManager
            - Broadcasts closure event through SyncService
        """
        try:
            if self._window_manager is not None:
                self._window_manager.unregister_window(window_id)
        except KeyError:
            pass

        # Wipe sensitive data from window's DocumentView before destruction
        # Get from registry by window_id for type safety
        doc_view = self._new_window_doc_views.get(window_id)
        if doc_view is not None:
            try:
                doc_view.wipe_sensitive_data()
            except (tk.TclError, AttributeError, RuntimeError) as e:
                logger.debug(
                    "Failed to wipe DocumentView for window %s (non-critical): %s",
                    window_id,
                    e,
                )

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

    def _setup_key_bindings(self) -> None:
        """Настраивает клавиатурные shortcuts через KeyBindingsService."""
        if self._root is None or self._key_bindings is None:
            return

        # File
        self._key_bindings.register("Ctrl+N", self._on_file_new)
        self._key_bindings.register("Ctrl+O", self._on_file_open)
        self._key_bindings.register("Ctrl+S", self._on_file_save)
        self._key_bindings.register("Ctrl+P", self._on_file_print)

        # Edit
        self._key_bindings.register("Ctrl+Z", self._on_edit_undo)
        self._key_bindings.register("Ctrl+Y", self._on_edit_redo)
        self._key_bindings.register("Ctrl+X", self._on_edit_cut)
        self._key_bindings.register("Ctrl+C", self._on_edit_copy)
        self._key_bindings.register("Ctrl+V", self._on_edit_paste)
        self._key_bindings.register("Ctrl+F", self._on_edit_find)

        # View / Zoom
        self._key_bindings.register("Ctrl++", self._on_view_zoom_in)
        self._key_bindings.register("Ctrl+-", self._on_view_zoom_out)
        self._key_bindings.register("Ctrl+0", self._on_view_zoom_reset)

        # Navigation
        self._key_bindings.register("Ctrl+G", self._on_goto)
        self._key_bindings.register("Ctrl+B", self._on_bookmarks)

        # Insert (Phase 6)
        self._key_bindings.register("Ctrl+Shift+B", self._on_insert_barcode)
        self._key_bindings.register("Ctrl+Shift+Q", self._on_insert_qr)

        # Глобальный обработчик для dispatch
        self._root.bind_all("<Key>", self._on_key_event)

    def _on_key_event(self, event: tk.Event) -> None:
        """Прокси-обработчик tk.Key для KeyBindingsService.dispatch()."""
        if self._key_bindings is not None:
            self._key_bindings.dispatch(event)

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
        self._sidebar.mount(cast(tk.Widget, self._root))
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
            sync_service=self._sync_service,
        )
        self._cardfile_tabbar.mount(content_frame)
        self._cardfile_tabbar.widget.grid(row=0, column=0, sticky="ew")

        # Create and set status bar FIRST (so DocumentView can reference it)
        self._statusbar = StatusBar(
            widget_id="statusbar",
            controller=self._controller,
            mode_callback=self._on_statusbar_mode_click,
            paper_callback=self._on_page_setup,
        )
        self._statusbar.mount(self._root)
        self._main_layout.set_statusbar(self._statusbar.widget)

        # Create document view with StatusBar reference
        self._document_view = DocumentView(
            widget_id="document_view",
            controller=self._controller,
            on_paper_setup=self._on_paper_setup,
            statusbar=self._statusbar,
        )
        self._document_view.mount(content_frame)
        self._document_view.widget.grid(row=1, column=0, sticky="nsew")
        # Set workflow state manager
        self._document_view.set_workflow_state_manager(self._workflow_state_manager)

        # Initialize BarcodeController (lazy import to avoid circular import)
        from src.gui.controllers.barcode_controller import BarcodeController

        self._barcode_controller = BarcodeController(
            parent=cast(tk.Widget, self._root),
            view=self._document_view,
        )

        # Create initial empty document so the text area is visible on startup
        self._initialize_empty_document()

        self._main_layout.set_content(content_frame)

    def _initialize_empty_document(self) -> None:
        """Создаёт начальный пустой документ и отображает его в DocumentView.

        Вызывается в конце initialize() чтобы область редактирования
        была видна сразу после запуска приложения, а не пустым placeholder.
        """
        if self._document_view is None:
            return

        # Use a proper model Document; set_document() handles the DocumentWrapper
        # that provides DocumentProtocol (str id, mode, get_content, get_cpi).
        self.set_document(Document())

    def _on_unlock_attempt(self, password: str, mfa_token: str, method: str) -> bool:
        """Callback для проверки credentials при разблокировке.

        Security:
            - НЕ логирует password/token.
            - Использует AuthController для верификации.

        Args:
            password: Введённый пароль.
            mfa_token: Введённый MFA токен.
            method: Выбранный метод MFA ("totp", "backup", "fido2").

        Returns:
            True если аутентификация успешна.
        """
        auth_controller = self._get_auth_controller()
        user_id = self._get_current_user_id()

        if auth_controller is None or user_id is None:
            return False

        try:
            # Verify password
            if not hasattr(auth_controller, "verify_password"):
                return False
            if not bool(auth_controller.verify_password(user_id, password)):
                return False

            # Verify MFA based on method
            if method == "totp":
                if not hasattr(auth_controller, "verify_totp"):
                    return False
                return bool(auth_controller.verify_totp(user_id, mfa_token))
            elif method == "backup":
                if not hasattr(auth_controller, "verify_backup_code"):
                    return False
                return bool(auth_controller.verify_backup_code(user_id, mfa_token))
            elif method == "fido2":
                if hasattr(auth_controller, "verify_fido2"):
                    return bool(auth_controller.verify_fido2(user_id, ""))
                return False
            else:
                return False

        except (AttributeError, ValueError, TypeError, RuntimeError):
            # Don't expose internal details
            return False

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

    def _schedule_auto_lock_check(self) -> None:
        """Планирует проверку неактивности для автоматической блокировки.

        Вызывается периодически (каждую минуту) через after().
        Если время неактивности превышает auto_lock_minutes —
        вызывает lock_session(trigger="auto").
        """
        if self._root is None:
            return

        if self._is_locked:
            # Don't schedule next check if already locked
            return

        import time

        elapsed = time.time() - self._last_activity_time
        inactive_minutes = int(elapsed / 60)

        if inactive_minutes >= self._auto_lock_minutes and self._auto_lock_minutes > 0:
            self.lock_session(trigger="auto")
            return

        # Schedule next check in 60 seconds
        self._auto_lock_timer_id = str(self._root.after(60000, self._schedule_auto_lock_check))

    def _reset_activity_timer(self, _event: Any) -> None:
        """Сбрасывает таймер неактивности при любом событии.

        Args:
            _event: Событие Tkinter (не используется).
        """
        import time

        self._last_activity_time = time.time()

    def _bind_activity_events(self) -> None:
        """Привязывает обработчики событий активности к root.

        Сбрасывает таймер неактивности при любом key/mouse event.
        """
        if self._root is None:
            return

        events = [
            "<Key>",
            "<KeyRelease>",
            "<Button>",
            "<ButtonRelease>",
            "<Motion>",
            "<MouseWheel>",
        ]
        for event in events:
            self._root.bind(event, self._reset_activity_timer)

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

        Конвертирует документ в Special Mode.
        Требует ConfirmDialog, MFA через MFAGate и обновления индикатора вкладки.
        """
        if self._mode_manager is None or self._root is None:
            return

        if self._mode_manager.is_special():
            logger.info("Document already in Special Mode")
            if self._toast_service is not None:
                self._toast_service.show("Документ уже в Special Mode", ToastLevel.INFO)
            return

        response = messagebox.askyesno(
            "Convert to Special Mode",
            "Convert to Special Mode? This requires MFA.",
            parent=self._root,
        )
        if not response:
            return

        self._run_conversion_with_mfa("special")

    def _on_document_convert_to_normal(self) -> None:
        """Callback: File → Convert to Normal Mode.

        Конвертирует документ из Special Mode в Normal Mode.
        Требует ConfirmDialog, MFA через MFAGate и обновления индикатора вкладки.
        """
        if self._mode_manager is None or self._root is None:
            return

        if not self._mode_manager.is_special():
            logger.info("Document already in Normal Mode")
            if self._toast_service is not None:
                self._toast_service.show("Документ уже в Normal Mode", ToastLevel.INFO)
            return

        response = messagebox.askyesno(
            "Convert to Normal Mode",
            "Convert to Normal Mode? This requires MFA.",
            parent=self._root,
        )
        if not response:
            return

        self._run_conversion_with_mfa("normal")

    def _run_conversion_with_mfa(self, target_mode: str) -> None:
        """Выполняет MFA challenge и конвертацию документа.

        Args:
            target_mode: Целевой режим ('special' или 'normal').
        """
        if self._root is None:
            return

        auth_controller = self._get_auth_controller()
        if auth_controller is None:
            messagebox.showerror(
                "Ошибка аутентификации",
                "Auth controller не доступен.",
                parent=self._root,
            )
            return

        from src.gui.security.mfa_gate import MFAGate

        gate = MFAGate(auth_service=auth_controller, audit_log=self._audit_log)
        result = gate.execute(
            parent=cast(tk.Widget, self._root),
            operation=lambda: self._perform_document_conversion(target_mode),
            operation_name=f"Convert to {target_mode.capitalize()} Mode",
            requires_mfa=True,
        )
        if result is None:
            if self._toast_service is not None:
                self._toast_service.show("MFA верификация отменена", ToastLevel.INFO)

    def _perform_document_conversion(self, target_mode: str) -> bool:
        """Выполняет конвертацию документа и обновляет UI.

        Args:
            target_mode: Целевой режим ('special' или 'normal').

        Returns:
            True при успехе.
        """
        if self._controller is not None:
            try:
                self._controller.dispatch("document_convert", mode=target_mode)
            except Exception as exc:
                logger.error("Document conversion dispatch failed: %s", exc)

        # Update tab indicator
        if self._cardfile_tabbar is not None:
            active_tab = self._cardfile_tabbar.get_active_tab()
            if active_tab is not None:
                self._cardfile_tabbar.set_tab_special(active_tab, target_mode == "special")

        # Update global mode UI
        self._update_mode_ui(target_mode)

        if self._toast_service is not None:
            msg = (
                "Документ конвертирован в Special Mode"
                if target_mode == "special"
                else "Документ конвертирован в Normal Mode"
            )
            self._toast_service.show(msg, ToastLevel.SUCCESS)

        return True

    def _show_health_check_dialog_for_special_mode(self) -> None:
        """Показывает HealthCheckDialog для Special Mode."""
        if self._root is None:
            return

        if self._health_checker is None:
            self._health_checker = HealthChecker(version="3.0.0")

        from src.gui.dialogs.health_check_dialog import HealthCheckDialog

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

    def _on_page_setup(self) -> None:
        """Callback: Format -> Page Setup (и double-click на Paper в StatusBar)."""
        self._on_paper_setup()

    def _on_paper_setup(self) -> None:
        """Callback: открытие диалога настройки бумаги из PaperToolbar.

        Передаётся в DocumentView как on_paper_setup callback.
        """
        from src.gui.dialogs.paper_setup import PaperSetupDialog

        if self._root is None:
            return
        dialog = PaperSetupDialog(parent=self._root)
        dialog.show()

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

    def set_workflow_state_manager(self, manager: Any) -> None:
        """Устанавливает WorkflowStateManager для интеграции с Simple Mode.

        Args:
            manager: Экземпляр WorkflowStateManager или совместимый объект.
        """
        self._workflow_state_manager = manager

    def set_password_service(self, password_service: Any) -> None:
        """Устанавливает сервис паролей для session lock.

        Args:
            password_service: PasswordService или совместимый объект.
        """
        self._password_service = password_service

    def set_mfa_manager(self, mfa_manager: Any) -> None:
        """Устанавливает MFA-менеджер для session lock.

        Args:
            mfa_manager: SecondFactorManager или совместимый объект.
        """
        self._mfa_manager = mfa_manager

    def _on_view_workflow_simple_mode(self) -> None:
        """Callback: View -> Approval Workflow -> Simple Mode.

        Переключает между упрощённым (DRAFT ↔ SIGNED) и полным workflow.
        Обновляет StatusBar timeline и синхронизирует WorkflowStateManager.
        """
        if self._workflow_simple_var is not None:
            simple = self._workflow_simple_var.get()
            self._workflow_simple_mode = simple

            # Синхронизируем WorkflowStateManager
            if self._workflow_state_manager is not None:
                if hasattr(self._workflow_state_manager, "set_simple_mode"):
                    self._workflow_state_manager.set_simple_mode(simple)

            # Обновляем StatusBar timeline если visible
            if self._statusbar is not None:
                self._statusbar.set_simple_mode(simple)

            # Dispatch event to controller
            if self._controller is not None:
                self._controller.dispatch(
                    "workflow_mode_changed",
                    simple_mode=simple,
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
        messagebox.showinfo("История уведомлений", message, parent=self._root)  # type: ignore[arg-type]

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

    def _on_security_integrity_check(self) -> None:
        """Проверка целостности приложения.

        Создаёт экземпляры AppIntegrityChecker и ConfigIntegrityChecker
        и отображает IntegrityDialog с результатами.
        """
        from src.gui.dialogs.integrity_dialog import (
            IntegrityDialog,  # lazy: avoid circular import
        )

        if self._root is None:
            return

        from pathlib import Path

        from src.security.integrity import AppIntegrityChecker, ConfigIntegrityChecker

        # Стандартные пути (могут отсутствовать в dev-режиме)
        app_checker: Optional[AppIntegrityChecker] = None
        config_checker: Optional[ConfigIntegrityChecker] = None
        try:
            reference_path = Path(".app-hash")
            if reference_path.exists():
                app_checker = AppIntegrityChecker(reference_path)
        except (FileNotFoundError, PermissionError, OSError, ValueError) as e:
            logger.debug("App integrity check skipped (dev mode): %s", e)

        try:
            config_path = Path("config.fxsconfig")
            if config_path.exists():
                config_checker = ConfigIntegrityChecker(config_path)
        except (FileNotFoundError, PermissionError, OSError, ValueError) as e:
            logger.debug("Config integrity check skipped (dev mode): %s", e)

        dialog = IntegrityDialog(
            parent=self._root,
            app_checker=app_checker,
            config_checker=config_checker,
        )
        dialog.show()

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

        from src.gui.dialogs.navigation_dialogs import BookmarkItem

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
        if self._toast_service is not None:
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
        messagebox.showinfo("Список окон", message, parent=self._root)  # type: ignore[arg-type]

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

        Открывает диалог выбора типа штрих-кода и вставляет выбранный штрих-код в документ.
        """
        logger.info("Insert Barcode menu triggered")
        if self._root is None or self._barcode_controller is None:
            return
        self._barcode_controller.show_barcode_dialog()

    def _on_insert_qr(self) -> None:
        """Handler для вставки QR-кода (Insert → QR Code).

        Открывает диалог QR-кода и вставляет QR-код в документ.
        """
        logger.info("Insert QR menu triggered")
        if self._root is None or self._barcode_controller is None:
            return
        self._barcode_controller.show_qr_dialog()

    def _on_insert_special(self) -> None:
        """Handler для вставки спецсимвола (Insert → Special Character).

        Открывает диалог выбора специального символа и вставляет
        выбранный символ в текущую позицию курсора.
        """
        logger.info("Insert Special Character menu triggered")

        if self._root is None or self._document_view is None:
            return

        renderer = self._document_view._free_form_renderer
        if renderer is None:
            logger.warning("Special character insertion not available: FreeForm renderer missing")
            if self._toast_service is not None:
                self._toast_service.show(
                    "Вставка спецсимволов доступна только в режиме FreeForm",
                    ToastLevel.WARNING,
                )
            return

        dialog = SpecialCharacterDialog(parent=cast(tk.Widget, self._root))
        result: Optional[SpecialCharResult] = dialog.show()

        if result is None:
            return

        try:
            line, col = renderer.get_cursor_position()
        except Exception as e:
            logger.error("Failed to get cursor position: %s", e)
            messagebox.showerror(
                "Ошибка",
                "Не удалось определить позицию курсора.",
                parent=self._root,
            )
            return

        try:
            assert renderer._tk_text is not None
            assert renderer._command_stack is not None

            position = f"{line}.{col - 1}"
            cmd = InsertTextCommand(renderer._tk_text, result.char, position)
            renderer._command_stack.execute(cmd)

            if self._toast_service is not None:
                self._toast_service.show("Символ вставлен", ToastLevel.SUCCESS)
        except Exception as e:
            logger.error("Error inserting special character: %s", e)
            messagebox.showerror(
                "Ошибка",
                f"Не удалось вставить символ: {str(e)}",
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
]
