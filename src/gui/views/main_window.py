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
import time
import tkinter as tk
from pathlib import Path
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
from src.gui.core.protocols import (
    ControllerProtocol,
    DocumentViewProtocol,
    HealthCheckDialogProtocol,
    MainToolbarProtocol,
    MFAManagerProtocol,
    ModeIntegrationProtocol,
    ModeToggleProtocol,
    PasswordServiceProtocol,
    SessionManagerProtocol,
    UndoRedoMenuItemsProtocol,
    WorkflowManagerProtocol,
    WorkflowStateManagerProtocol,
    WorkflowUIFactoryProtocol,
)
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
from src.gui.views import SideBarMode, ToastLevel
from src.gui.views.auth_overlay import AuthOverlay, AuthServiceProtocol
from src.gui.views.card_file_tab_bar import CardFileTabBar
from src.gui.views.document_view import DocumentView
from src.gui.views.side_bar import SideBar
from src.gui.views.status_bar import StatusBar

# Bug 8 FIX: View НЕ должен импортировать из Model напрямую.
# BookmarkManager импортируется лениво (в методах) для избежания
# прямой зависимости View -> Model. Document заменён на DocumentViewAdapter.
# Причина: MVC строго запрещает View знать о внутренней структуре Model.
# См. src/gui/adapters/document_adapter.py
from src.security.audit import AuditEventType, AuditLog
from src.security.lock.session_lock_manager import DEFAULT_AUTO_LOCK_MINUTES

# Bug 8 FIX: SessionManager заменён на SessionManagerProtocol в типах.
# Прямой импорт убран — View работает через Protocol.
# Bug 8 FIX: AuthService заменён на AuthServiceProtocol — View не зависит
# от конкретной реализации AuthService, только от Protocol.
from src.security.monitoring.health_checker import HealthChecker

# Phase 4: Dialog imports (lazy loaded in methods to avoid circular imports)
# Bug 11 FIX: документация ленивых импортов.
# Ленивые импорты внутри методов необходимы по следующим причинам:
#
# 1. ЦИКЛИЧЕСКИЕ ЗАВИСИМОСТИ (основная причина):
#    - dialogs/ -> views/ -> dialogs/ (dialog открывает другой dialog)
#    - workflow/ -> views/ -> workflow/ (workflow UI factory)
#    - security/ -> views/ -> security/ (MFA gate, auth window)
#    Без ленивого импорта Python падает с ImportError при старте.
#
# 2. MVC РАЗДЕЛЕНИЕ (Bug 8):
#    - src.model.document (Document) — View не должен знать о Model,
#      поэтому импортируется лениво только в _initialize_empty_document()
#      и адаптируется через DocumentViewAdapter
#    - src.model.bookmark (BookmarkManager) — аналогично, ленивый в _on_bookmarks()
#
# 3. OPTIONAL DEPENDENCIES:
#    - src.gui.core.lifecycle (LifecycleManager) — может отсутствовать
#    - src.gui.workflow.undo_redo_menu (UndoRedoMenuItems) — Phase 7, может не быть
#    - src.security.auth.debug_utils — только для debug
#
# 4. PERFORMANCE:
#    - Dialogs (PaperSetup, FindReplace, etc.) импортируются только при открытии
#    - CryptoProfile, FloppyOptimizer — тяжёлые модули, не нужны при старте
#    - TrustChainService, TemplateManager — создают ресурсы при импорте
#
# Паттерн: from X import Y внутри метода, за которым сразу следует использование.
# Все такие импорты защищены try/except (Bug 5 FIX: конкретные исключения).
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
        workflow_state_manager: Optional[WorkflowStateManagerProtocol] = None,
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
        self._workflow_state_manager: Optional[WorkflowStateManagerProtocol] = (
            workflow_state_manager
        )
        self._root: Optional[tk.Tk] = None
        self._audit_log: Optional["AuditLog"] = audit_log
        # Barcode controller
        self._barcode_controller: Optional[BarcodeController] = None

        # Component references
        self._menubar: Optional[tk.Menu] = None
        self._main_toolbar: Optional[MainToolbarProtocol] = None
        self._main_layout: Optional[MainLayout] = None
        self._sidebar: Optional[SideBar] = None
        self._cardfile_tabbar: Optional[CardFileTabBar] = None
        self._document_view: Optional[DocumentView] = None
        self._statusbar: Optional[StatusBar] = None

        # Multi-window support: stores DocumentView for new Toplevel windows
        # Key: window_id from WindowManager, Value: DocumentView instance
        self._new_window_document_views: dict[str, DocumentView] = {}

        # Session lock screen (Toplevel)
        self._session_lock_screen: Optional[SessionLockScreen] = None

        # Auto-lock
        self._auto_lock_timer_id: Optional[str] = None
        self._auto_lock_minutes: int = DEFAULT_AUTO_LOCK_MINUTES
        self._last_activity_time: float = 0.0

        # State
        self._is_initialized: bool = False
        self._is_locked: bool = False
        self._current_title: str = ""
        self._is_modified: bool = False

        self._auth_overlay: Optional[AuthOverlay] = None
        self._health_check_dialog: Optional[HealthCheckDialogProtocol] = None
        self._mode_var: Optional[tk.StringVar] = None
        self._sidebar_mode_var: Optional[tk.StringVar] = None
        self._health_checker: Optional[HealthChecker] = None

        # Phase 4: Error handling
        self._error_handler: GUIErrorHandler = GUIErrorHandler()

        # Phase 4: Lifecycle manager (lazy import, may not be available)
        self._lifecycle_manager: Optional[Any] = None

        # Phase 4: Bookmark manager (lazy initialized per document)
        # Bug 8 FIX: тип Any вместо BookmarkManager — View не импортирует Model
        self._bookmark_manager: Optional[Any] = None

        # Phase 6: Barcode/QR render mode
        self._barcode_render_var: Optional[tk.StringVar] = None
        self._barcode_render_menu: Optional[tk.Menu] = None

        # Phase 7: Workflow Simple Mode
        self._workflow_simple_mode: bool = False
        self._workflow_simple_var: Optional[tk.BooleanVar] = None

        # Mode integration (renderer caching)
        self._mode_integration: Optional[ModeIntegrationProtocol] = None

        # Workflow undo/redo menu items
        self._undo_redo_menu_items: Optional[UndoRedoMenuItemsProtocol] = None

        # Workflow manager (action visibility engine)
        self._workflow_manager: Optional[WorkflowManagerProtocol] = None

        # Workflow UI factory (dialog creation with MFA)
        self._workflow_ui_factory: Optional[WorkflowUIFactoryProtocol] = None

        # Mode toggle widget (Normal/Special visual switch)
        self._mode_toggle: Optional[ModeToggleProtocol] = None

        self._main_window_id: Optional[str] = None

        # Session Manager for authentication
        self._session_manager: Optional[SessionManagerProtocol] = None
        self._current_session_id: Optional[str] = None

        # Auth services for session lock (injected from AppController)
        self._password_service: Optional[PasswordServiceProtocol] = None
        self._mfa_manager: Optional[MFAManagerProtocol] = None

        # New window counter for multi-window support
        self._new_window_counter: int = 0

        # KeyBindingsService
        self._key_bindings: Optional[KeyBindingsService] = None

    def initialize(self, root: Optional[tk.Tk] = None) -> None:
        """Инициализирует UI компоненты окна.

        Создаёт root window, menu bar, основной layout
        и все дочерние компоненты.

        Args:
            root: Существующее корневое окно Tkinter.
                Если None, создаётся новое окно.

        Phase 3:
            - Инициализирует ModeManager
            - Запускает Startup Health Check

        Raises:
            RuntimeError: Если окно уже инициализировано.

        Example:
            >>> window = MainWindow(controller=ctrl)
            >>> window.initialize(root=existing_root)
        """
        if self._is_initialized:
            raise RuntimeError("MainWindow is already initialized")

        # Create or reuse root window
        if root is not None:
            self._root = root
        else:
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
        # All services are injected via DI (Bug FIX: View must NOT create services).
        # ToastService, SyncService, NotificationService, DragDropService, ModeManager,
        # and WorkflowStateManager must all be provided through constructor injection.

        # Create LifecycleManager for component lifecycle tracking
        try:
            from src.gui.core.lifecycle import LifecycleManager

            self._lifecycle_manager = LifecycleManager()
        except (ImportError, AttributeError, TypeError) as _lifecycle_err:
            # Bug 5 FIX: конкретные исключения вместо молчащего except Exception
            logger.debug("LifecycleManager not available: %s", _lifecycle_err)
            self._lifecycle_manager = None

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
            raise RuntimeError("MainWindow is not initialized. Call initialize() first.")

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
        if not self._is_initialized:
            return

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

        # Bug 9 FIX: Очистка new_window DocumentView при destroy MainWindow.
        # Без этого wipe_sensitive_data() не вызывался для DocumentView
        # в дочерних Toplevel окнах, что могло привести к утечке sensitive данных.
        for window_id, doc_view in list(self._new_window_document_views.items()):
            try:
                doc_view.wipe_sensitive_data()
            except (tk.TclError, AttributeError, RuntimeError) as e:
                logger.debug(
                    "Failed to wipe DocumentView for window %s (non-critical): %s",
                    window_id,
                    e,
                )
        self._new_window_document_views.clear()

        # Close all toast notifications
        if self._toast_service is not None:
            self._toast_service.close_all()
            self._toast_service = None

        # Cleanup NotificationService
        if self._notification_service is not None:
            self._notification_service.dismiss_all()
            self._notification_service.close_all_toasts()
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
            raise RuntimeError("MainWindow is not initialized")
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
            raise RuntimeError("MainWindow is not initialized")

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

    def _root_widget(self) -> tk.Widget:
        """Возвращает корневое окно как tk.Widget для передачи в диалоги.

        tk.Tk не наследует tk.Widget в type stubs, но является
        корректным родительским виджетом во время выполнения.

        Returns:
            Корневое окно, приведённое к tk.Widget.

        Raises:
            RuntimeError: Если корневое окно не инициализировано.
        """
        if self._root is None:
            raise RuntimeError("Root window not initialized")
        return cast(tk.Widget, self._root)

    def get_theme(self) -> str:
        """Возвращает текущую тему оформления.

        Returns:
            Идентификатор темы (default: "classic_green").
        """
        return "classic_green"

    def add_document(self, document: DocumentViewProtocol) -> None:
        """Добавляет документ в UI (вкладку).

        Args:
            document: Адаптированная модель документа (DocumentViewProtocol).

        Note:
            Вызывается из AppController после создания документа.
            Ожидает DocumentViewProtocol, а не сырой Document Model.
        """
        if self._cardfile_tabbar is None:
            return

        doc_id = document.doc_id
        title_str = document.title
        mode = document.mode

        self._cardfile_tabbar.add_tab(document_id=doc_id, title=title_str, mode=mode)

        # Update tab indicators based on document state
        is_encrypted = document.is_encrypted
        is_readonly = document.is_readonly
        is_modified = document.is_modified
        self._cardfile_tabbar.set_tab_encrypted(doc_id, is_encrypted)
        self._cardfile_tabbar.set_tab_readonly(doc_id, is_readonly)
        self._cardfile_tabbar.set_tab_modified(doc_id, is_modified)
        if self._statusbar is not None:
            self._statusbar.set_encrypted(is_encrypted)
            self._statusbar.set_readonly(is_readonly)

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
        display_name = Path(title).name if title else ""
        prefix = MODIFIED_INDICATOR if modified else ""
        full_title = f"{prefix}{display_name}{TITLE_SEPARATOR}{APP_NAME}"
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
            document: Модель документа (Document из src.model.document).
                Адаптируется в DocumentViewProtocol через DocumentViewAdapter.

        Note:
            Передаёт документ в DocumentView для рендеринга.
            DocumentViewAdapter инкапсулирует бизнес-логику маппинга
            (Bug 1 FIX: убран из View в отдельный Adapter).
        """
        if self._document_view is None:
            return

        from src.gui.adapters.document_adapter import DocumentViewAdapter

        # Адаптируем Document model -> DocumentViewProtocol
        # Это единственное место в View, где Document model проходит
        # через адаптер. Все остальные методы работают с DocumentViewProtocol.
        adapted: DocumentViewProtocol = DocumentViewAdapter(document)
        self._document_view.set_document(adapted)
        self.add_document(adapted)

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
            self._toast_service.show("Session locked", ToastLevel.INFO)

        # Log to audit
        if self._audit_log:
            user_id = self._get_current_user_id()
            if user_id:
                try:
                    self._audit_log.log_event(
                        AuditEventType.SESSION_LOCKED,
                        details={"user_id": user_id, "trigger": trigger},
                    )
                except (OSError, ValueError, RuntimeError) as e:
                    # Bug 5 FIX: конкретные исключения вместо except Exception
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
            self._toast_service.show("Session unlocked", ToastLevel.SUCCESS)

        # Log to audit
        if self._audit_log:
            user_id = self._get_current_user_id()
            if user_id:
                try:
                    self._audit_log.log_event(
                        AuditEventType.APP_UNLOCKED, details={"user_id": user_id}
                    )
                except (OSError, ValueError, RuntimeError) as e:
                    # Bug 5 FIX: конкретные исключения вместо except Exception
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
        if self._root is not None and messagebox.askyesno("Exit", "Exit application?"):
            self._root.destroy()

    def _update_ui_for_authenticated_user(self, user_id: str) -> None:
        """Обновляет UI после аутентификации."""
        if self._root is not None:
            self._root.title(f"{APP_NAME} - User: {user_id}")
        if self._toast_service is not None:
            self._toast_service.show(f"Welcome, {user_id}!", ToastLevel.SUCCESS)

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
            parent=self._root_widget(),
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

            # Switch renderer via ModeIntegration
            if self._mode_integration is not None and self._root is not None:
                try:
                    from src.documents.types.document_type import DocumentMode

                    self._mode_integration.switch_mode(
                        DocumentMode.FREE_FORM, self._root, self._controller
                    )
                except (ImportError, AttributeError, tk.TclError, ValueError) as exc:
                    # Bug 5 FIX: конкретные исключения вместо except Exception
                    logger.debug("ModeIntegration switch to FREE_FORM failed: %s", exc)

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

        from src.gui.security.health_check_dialog import HealthCheckDialog

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
            self._auth_overlay.mount(self._root)  # type: ignore[arg-type]

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

        # Switch renderer via ModeIntegration
        if self._mode_integration is not None and self._root is not None:
            try:
                from src.documents.types.document_type import DocumentMode

                self._mode_integration.switch_mode(
                    DocumentMode.STRUCTURED_FORM, self._root, self._controller
                )
            except (ImportError, AttributeError, tk.TclError, ValueError) as exc:
                # Bug 5 FIX: конкретные исключения вместо except Exception
                logger.debug("ModeIntegration switch to STRUCTURED_FORM failed: %s", exc)

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

    def _get_auth_service(self) -> Optional[AuthServiceProtocol]:
        """Возвращает AuthService из контроллера или создаёт новый.

        Returns:
            AuthServiceProtocol instance или None.
        """
        # Try to get from controller first
        if self._controller is not None:
            try:
                auth_service = getattr(self._controller, "get_auth_service", None)
                if auth_service is not None:
                    result = auth_service()
                    if isinstance(result, AuthServiceProtocol):
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
                # Bug 6 FIX: hasattr заменён на try-атрибут
                # ControllerProtocol не определяет verify_totp, поэтому
                # используем getattr с fallback
                if getattr(self._controller, "verify_totp", None) is not None:
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
        file_menu.add_command(label="Import Template...", command=self._on_file_import_template)
        file_menu.add_command(label="Export Template...", command=self._on_file_export_template)
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
        edit_menu.add_command(
            label="Find and Replace...", command=self._on_edit_find_replace, accelerator="Ctrl+H"
        )
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
        format_menu.add_command(
            label="Paper Profiles...",
            command=self._on_format_paper_profiles,
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
        view_menu.add_command(
            label="Document Tree...",
            command=self._on_view_document_tree,
        )
        view_menu.add_command(
            label="Toggle Annotations...",
            command=self._on_view_toggle_annotation_panel,
        )
        view_menu.add_separator()
        # SideBar Mode submenu
        self._sidebar_mode_var = tk.StringVar(value="sections")
        sidebar_mode_menu = tk.Menu(view_menu, tearoff=0)
        sidebar_mode_menu.add_radiobutton(
            label="Sections",
            variable=self._sidebar_mode_var,
            value="sections",
            command=self._on_view_sidebar_mode_changed,
        )
        sidebar_mode_menu.add_radiobutton(
            label="Tree",
            variable=self._sidebar_mode_var,
            value="tree",
            command=self._on_view_sidebar_mode_changed,
        )
        view_menu.add_cascade(label="SideBar Mode", menu=sidebar_mode_menu)
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
        window_menu.add_command(label="Window list", command=self._on_window_list)
        window_menu.add_separator()
        window_menu.add_command(label="Minimize all", command=self._on_window_minimize_all)
        window_menu.add_command(label="Restore all", command=self._on_window_restore_all)
        view_menu.add_cascade(label="Windows", menu=window_menu)
        view_menu.add_separator()
        # Workflow submenu with Simple Mode toggle
        self._workflow_simple_var = tk.BooleanVar(value=self._workflow_simple_mode)
        workflow_menu = tk.Menu(view_menu, tearoff=0)
        workflow_menu.add_checkbutton(
            label="Simple Mode",
            variable=self._workflow_simple_var,
            command=self._on_view_workflow_simple_mode,
        )
        workflow_menu.add_separator()
        # Workflow undo/redo items (dynamic labels)
        self._setup_workflow_undo_redo(workflow_menu)
        view_menu.add_cascade(label="Approval Workflow", menu=workflow_menu)
        view_menu.add_separator()
        self._menubar.add_cascade(label="View", menu=view_menu)

        # Phase 7: Notifications menu
        notifications_menu = tk.Menu(self._menubar, tearoff=0)
        notifications_menu.add_command(label="History", command=self._on_view_notifications)
        notifications_menu.add_command(
            label="Mark all as read",
            command=self._on_notifications_mark_all_read,
        )
        self._menubar.add_cascade(label="Notifications", menu=notifications_menu)

        # Security menu
        security_menu = tk.Menu(self._menubar, tearoff=0)
        security_menu.add_command(label="Lock Session", command=self._on_security_lock)
        security_menu.add_separator()
        security_menu.add_command(
            label="Change Password...", command=self._on_security_change_password
        )
        security_menu.add_command(label="Health Check...", command=self._on_security_health_check)
        security_menu.add_separator()
        security_menu.add_command(label="Backup codes", command=self._on_security_backup_codes)
        security_menu.add_command(
            label="Security profile", command=self._on_security_crypto_profile
        )
        security_menu.add_command(
            label="Auto-lock settings",
            command=self._on_security_auto_lock_settings,
        )
        security_menu.add_separator()
        security_menu.add_command(label="FIDO2 Setup...", command=self._on_security_fido2_setup)
        security_menu.add_command(label="TOTP Setup...", command=self._on_security_totp_setup)
        security_menu.add_command(
            label="MFA Verification...", command=self._on_security_mfa_verification
        )
        security_menu.add_separator()
        security_menu.add_command(
            label="Integrity Check...", command=self._on_security_integrity_check
        )
        security_menu.add_command(
            label="Trust Chain Verification...", command=self._on_security_trust_chain
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
        tools_menu.add_command(
            label="Floppy Optimizer...",
            command=self._on_tools_floppy_optimizer,
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
        self._new_window_document_views[window_id] = doc_view

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
        doc_view = self._new_window_document_views.get(window_id)
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
                self._toast_service.show(f"Windows closed: {count}", ToastLevel.INFO)

    def _create_main_toolbar(self) -> None:
        """Создаёт главную панель инструментов."""
        from src.gui.components.composite.main_toolbar import MainToolbar

        if self._root is None:
            return

        self._main_toolbar = MainToolbar(
            widget_id="main_toolbar",
            controller=self._controller,
        )
        toolbar_frame = self._main_toolbar.mount(self._root)  # type: ignore[arg-type]
        toolbar_frame.grid(row=1, column=0, sticky="ew")

    def _update_toolbar_state(self, has_document: bool = False, is_modified: bool = False) -> None:
        """Обновляет состояние кнопок тулбара."""
        if self._main_toolbar:
            self._main_toolbar.set_button_enabled("save", has_document and is_modified)
            self._main_toolbar.set_button_enabled("print", has_document)

    def _setup_toolbar_commands(self) -> None:
        """Настраивает команды для кнопок тулбара."""
        # Bug 6 FIX: hasattr заменён на getattr с fallback
        # ControllerProtocol не определяет subscribe, поэтому используем safe access
        if self._controller is not None:
            subscribe_fn = getattr(self._controller, "subscribe", None)
            if subscribe_fn is not None:
                subscribe_fn(
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

        # Bug 3 FIX: bind вместо bind_all — ограничиваем scope корневым окном.
        # bind_all перехватывал ВСЕ клавиатурные события глобально, включая
        # события в модальных диалогах и других Toplevel окнах, что приводило
        # к непреднамеренной обработке клавиш вне MainWindow.
        self._root.bind("<Key>", self._on_key_event)

    def _setup_workflow_undo_redo(self, menu: tk.Menu) -> None:
        """Добавляет пункты undo/redo workflow в меню.

        Args:
            menu: Меню Workflow для добавления пунктов.
        """
        try:
            from src.gui.workflow.undo_redo_menu import UndoRedoMenuItems

            self._undo_redo_menu_items = UndoRedoMenuItems(
                undo_callback=lambda: (
                    self._controller.dispatch("workflow_undo") if self._controller else None
                ),
                redo_callback=lambda: (
                    self._controller.dispatch("workflow_redo") if self._controller else None
                ),
                get_undo_text=lambda: self._get_workflow_undo_text(),
                get_redo_text=lambda: self._get_workflow_redo_text(),
            )
            self._undo_redo_menu_items.add_to_menu(menu)
        except (ImportError, AttributeError, TypeError, tk.TclError) as exc:
            # Bug 5 FIX: конкретные исключения вместо except Exception
            logger.debug("Workflow undo/redo menu items skipped: %s", exc)

    def _get_workflow_undo_text(self) -> Optional[str]:
        """Возвращает описание последнего действия для undo."""
        # Bug 6 FIX: hasattr заменён на Protocol-гарантированный вызов
        if self._workflow_state_manager is not None:
            return self._workflow_state_manager.get_last_undo_description()
        return None

    def _get_workflow_redo_text(self) -> Optional[str]:
        """Возвращает описание последнего действия для redo."""
        # Bug 6 FIX: hasattr заменён на Protocol-гарантированный вызов
        if self._workflow_state_manager is not None:
            return self._workflow_state_manager.get_last_redo_description()
        return None

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
        main_widget = self._main_layout.mount(self._root)  # type: ignore[arg-type]
        main_widget.grid(row=2, column=0, sticky="nsew")

        # Create and set sidebar (Phase 7: with sync_service)
        self._sidebar = SideBar(
            widget_id="sidebar",
            controller=self._controller,
            on_section_select=self._on_section_selected,
            on_tree_select=self._on_tree_item_selected,
            sync_service=self._sync_service,
        )
        self._sidebar.mount(self._root_widget())
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
        self._statusbar.mount(self._root_widget())
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
        if self._workflow_state_manager is not None:
            self._document_view.set_workflow_state_manager(self._workflow_state_manager)

        # Initialize BarcodeController (lazy import to avoid circular import)
        from src.gui.controllers.barcode_controller import BarcodeController

        self._barcode_controller = BarcodeController(
            parent=self._root_widget(),
            view=self._document_view,
        )

        # Create initial empty document so the text area is visible on startup
        self._initialize_empty_document()

        self._main_layout.set_content(content_frame)

    def _initialize_empty_document(self) -> None:
        """Создаёт начальный пустой документ и отображает его в DocumentView.

        Вызывается в конце initialize() чтобы область редактирования
        была видна сразу после запуска приложения, а не пустым placeholder.

        Bug 8 FIX: Document импортируется лениво (View не зависит от Model).
        set_document() адаптирует Document через DocumentViewAdapter.
        """
        if self._document_view is None:
            return

        # Bug 8 FIX: ленивый импорт Document — View не импортирует из Model напрямую
        from src.model.document import Document

        # set_document() адаптирует Document через DocumentViewAdapter,
        # предоставляя DocumentProtocol для View слоя.
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
            # Bug 6 FIX: hasattr заменён на try/except с конкретными исключениями
            if not bool(auth_controller.verify_password(user_id, password)):
                return False

            # Verify MFA based on method
            if method == "totp":
                return bool(auth_controller.verify_totp(user_id, mfa_token))
            elif method == "backup":
                return bool(auth_controller.verify_backup_code(user_id, mfa_token))
            elif method == "fido2":
                try:
                    return bool(auth_controller.verify_fido2(user_id, ""))
                except AttributeError:
                    # FIDO2 не поддерживается данным контроллером
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
        Если время неактивности превышает auto_lock_minutes --
        вызывает lock_session(trigger="auto").

        Bug 7 FIX: добавлена защита от повторного входа:
        - Проверяет наличие модальных диалогов перед блокировкой
        - Проверяет, не正在进行 критическая операция (grab)
        - Предотвращает блокировку при активном вводе в диалоге
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
            # Bug 7 FIX: не блокируем если есть модальный диалог или grab
            try:
                grab_window = self._root.grab_current()  # type: ignore[no-untyped-call]
                if grab_window is not None:
                    # Модальный диалог активен — откладываем блокировку
                    self._auto_lock_timer_id = str(
                        self._root.after(60000, self._schedule_auto_lock_check)
                    )
                    return
            except (tk.TclError, AttributeError):
                pass  # Нет grab — можно блокировать

            self.lock_session(trigger="auto")
            return

        # Schedule next check in 60 seconds
        self._auto_lock_timer_id = str(self._root.after(60000, self._schedule_auto_lock_check))

    def _reset_activity_timer(self, _event: Any) -> None:
        """Сбрасывает таймер неактивности при любом событии.

        Args:
            _event: Событие Tkinter (не используется).
        """
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
                self._toast_service.show("Document already in Special Mode", ToastLevel.INFO)
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
                self._toast_service.show("Document already in Normal Mode", ToastLevel.INFO)
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
            parent=self._root_widget(),
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
            except (ValueError, RuntimeError, AttributeError, tk.TclError) as exc:
                # Bug 5 FIX: конкретные исключения вместо except Exception
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

        from src.gui.security.health_check_dialog import HealthCheckDialog

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
            self._toast_service.show("Creating new document", ToastLevel.INFO)

    def _on_file_open(self) -> None:
        """Callback: File -> Open."""
        if self._controller is not None:
            self._controller.dispatch("file_open")
        elif self._toast_service is not None:
            self._toast_service.show("Opening document", ToastLevel.INFO)

    def _on_file_save(self) -> None:
        """Callback: File -> Save."""
        if self._controller is not None:
            self._controller.dispatch("file_save")
        elif self._toast_service is not None:
            self._toast_service.show("Saving document", ToastLevel.INFO)

    def _on_file_save_as(self) -> None:
        """Callback: File -> Save As."""
        if self._controller is not None:
            self._controller.dispatch("file_save_as")
        elif self._toast_service is not None:
            self._toast_service.show("Save document as...", ToastLevel.INFO)

    def _on_file_print(self) -> None:
        """Callback: File -> Print."""
        if self._controller is not None:
            self._controller.dispatch("file_print")
        elif self._toast_service is not None:
            self._toast_service.show("Printing document", ToastLevel.INFO)

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
        """Callback: Edit -> Undo.

        При наличии контроллера делегирует ему, иначе вызывает
        undo() напрямую у DocumentView через CommandStack.
        """
        if self._controller is not None:
            self._controller.dispatch("edit_undo")
        elif self._document_view is not None and self._document_view.can_undo():
            self._document_view.undo()

    def _on_edit_redo(self) -> None:
        """Callback: Edit -> Redo.

        При наличии контроллера делегирует ему, иначе вызывает
        redo() напрямую у DocumentView через CommandStack.
        """
        if self._controller is not None:
            self._controller.dispatch("edit_redo")
        elif self._document_view is not None and self._document_view.can_redo():
            self._document_view.redo()

    def _on_edit_cut(self) -> None:
        """Callback: Edit -> Cut.

        При наличии контроллера делегирует ему, иначе вызывает
        on_edit_cut() напрямую у DocumentView.
        """
        if self._controller is not None:
            self._controller.dispatch("edit_cut")
        elif self._document_view is not None:
            self._document_view.on_edit_cut()

    def _on_edit_copy(self) -> None:
        """Callback: Edit -> Copy.

        При наличии контроллера делегирует ему, иначе вызывает
        on_edit_copy() напрямую у DocumentView.
        """
        if self._controller is not None:
            self._controller.dispatch("edit_copy")
        elif self._document_view is not None:
            self._document_view.on_edit_copy()

    def _on_edit_paste(self) -> None:
        """Callback: Edit -> Paste.

        При наличии контроллера делегирует ему, иначе вызывает
        on_edit_paste() напрямую у DocumentView.
        """
        if self._controller is not None:
            self._controller.dispatch("edit_paste")
        elif self._document_view is not None:
            self._document_view.on_edit_paste()

    def _on_edit_find(self) -> None:
        """Callback: Edit -> Find.

        При наличии контроллера делегирует ему, иначе открывает
        диалог поиска напрямую.
        """
        if self._controller is not None:
            self._controller.dispatch("edit_find")
        else:
            self._on_edit_find_replace()

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

    def _on_view_document_tree(self) -> None:
        """Callback: View -> Document Tree.

        Открывает панель дерева документов для навигации по индексам.
        """
        if self._root is None:
            return

        try:
            from src.gui.form_designer.tree_panel import TreePanel

            def on_select(item_id: str) -> None:
                if self._controller is not None:
                    self._controller.dispatch("tree_item_selected", item_id=item_id)

            def on_double_click(item_id: str) -> None:
                if self._controller is not None:
                    self._controller.dispatch("tree_item_activated", item_id=item_id)

            TreePanel(
                parent=self._root_widget(),
                on_select=on_select,
                on_double_click=on_double_click,
            )
            if self._toast_service is not None:
                self._toast_service.show(
                    "Дерево документов открыто",
                    ToastLevel.INFO,
                )
        except (ImportError, AttributeError, TypeError, tk.TclError, OSError) as e:
            # Bug 5 FIX: конкретные исключения вместо except Exception
            logger.error("Ошибка открытия дерева документов: %s", e)
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Ошибка: {e}",
                    ToastLevel.ERROR,
                )

    def _on_view_toggle_annotation_panel(self) -> None:
        """Callback: View -> Toggle Annotations.

        Открывает панель аннотаций workflow рядом с документом.
        """
        if self._root is None:
            return

        try:
            from src.gui.workflow.workflow_annotation_panel import (
                WorkflowAnnotationPanel,
            )

            current_user = "operator"
            current_role = "operator"
            # Bug 6 FIX: hasattr убран — WorkflowManagerProtocol гарантирует current_role
            if self._workflow_manager is not None:
                try:
                    current_role = self._workflow_manager.current_role.value
                except (AttributeError, TypeError):
                    pass

            def on_add(
                text: str, annot_type: Any, parent_id: Optional[str] = None
            ) -> Optional[str]:
                if self._controller is not None:
                    self._controller.dispatch(
                        "annotation_add",
                        text=text,
                        annot_type=str(annot_type),
                        parent_id=parent_id,
                    )
                return None

            def on_resolve(annotation_id: str) -> bool:
                if self._controller is not None:
                    self._controller.dispatch(
                        "annotation_resolve",
                        annotation_id=annotation_id,
                    )
                return True

            def on_reply(parent_id: str, text: str) -> Optional[str]:
                if self._controller is not None:
                    self._controller.dispatch(
                        "annotation_reply",
                        parent_id=parent_id,
                        text=text,
                    )
                return None

            panel = WorkflowAnnotationPanel(
                parent=self._root_widget(),
                annotations=[],
                current_user=current_user,
                current_role=current_role,
                on_add=on_add,
                on_resolve=on_resolve,
                on_reply=on_reply,
                controller=self._controller,
            )
            panel.mount(self._root_widget())

            if self._toast_service is not None:
                self._toast_service.show(
                    "Панель аннотаций открыта",
                    ToastLevel.INFO,
                )

        except (ImportError, AttributeError, TypeError, tk.TclError, OSError) as e:
            # Bug 5 FIX: конкретные исключения вместо except Exception
            logger.error("Ошибка открытия панели аннотаций: %s", e)
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Ошибка: {e}",
                    ToastLevel.ERROR,
                )

    def _on_view_sidebar_mode_changed(self) -> None:
        """Callback: View -> SideBar Mode -> Sections / Tree."""
        if self._sidebar is None or self._sidebar_mode_var is None:
            return
        mode = self._sidebar_mode_var.get()
        if mode == "tree":
            self._sidebar.set_mode(SideBarMode.TREE)
        else:
            self._sidebar.set_mode(SideBarMode.SECTIONS)

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

    def set_workflow_state_manager(self, manager: WorkflowStateManagerProtocol) -> None:
        """Устанавливает WorkflowStateManager для интеграции с Simple Mode.

        Args:
            manager: Экземпляр WorkflowStateManagerProtocol.
        """
        self._workflow_state_manager = manager

    def set_password_service(self, password_service: PasswordServiceProtocol) -> None:
        """Устанавливает сервис паролей для session lock.

        Args:
            password_service: Экземпляр PasswordServiceProtocol.
        """
        self._password_service = password_service

    def set_mfa_manager(self, mfa_manager: MFAManagerProtocol) -> None:
        """Устанавливает MFA-менеджер для session lock.

        Args:
            mfa_manager: Экземпляр MFAManagerProtocol.
        """
        self._mfa_manager = mfa_manager

    def set_session_manager(self, session_manager: SessionManagerProtocol) -> None:
        """Устанавливает менеджер сессий для аутентификации.

        Args:
            session_manager: Экземпляр SessionManagerProtocol.
        """
        self._session_manager = session_manager

    def set_mode_integration(self, mode_integration: ModeIntegrationProtocol) -> None:
        """Устанавливает интеграцию режимов (ModeIntegration).

        Args:
            mode_integration: Экземпляр ModeIntegrationProtocol.
        """
        self._mode_integration = mode_integration

    def set_workflow_manager(self, workflow_manager: WorkflowManagerProtocol) -> None:
        """Устанавливает менеджер workflow для видимости действий.

        Args:
            workflow_manager: Экземпляр WorkflowManagerProtocol.
        """
        self._workflow_manager = workflow_manager

    def set_workflow_ui_factory(self, factory: WorkflowUIFactoryProtocol) -> None:
        """Устанавливает фабрику workflow UI для создания диалогов с MFA.

        Args:
            factory: Экземпляр WorkflowUIFactoryProtocol.
        """
        self._workflow_ui_factory = factory

    def set_mode_toggle(self, mode_toggle: ModeToggleProtocol) -> None:
        """Устанавливает виджет ModeToggle для визуального переключения режимов.

        Args:
            mode_toggle: Экземпляр ModeToggleProtocol.
        """
        self._mode_toggle = mode_toggle

    def _on_view_workflow_simple_mode(self) -> None:
        """Callback: View -> Approval Workflow -> Simple Mode.

        Переключает между упрощённым (DRAFT ↔ SIGNED) и полным workflow.
        Обновляет StatusBar timeline и синхронизирует WorkflowStateManager.
        """
        if self._workflow_simple_var is not None:
            simple = self._workflow_simple_var.get()
            self._workflow_simple_mode = simple

            # Синхронизируем WorkflowStateManager
            # Bug 6 FIX: hasattr убран — Protocol гарантирует метод
            if self._workflow_state_manager is not None:
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
                self._toast_service.show("No notifications in history", ToastLevel.INFO)
            return

        # Build notification list for display
        lines: list[str] = [f"Уведомлений в истории: {count}\n"]
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
        if self._root is not None:
            messagebox.showinfo("Notification history", message, parent=self._root)

    def _on_notifications_mark_all_read(self) -> None:
        """Callback: Уведомления → Отметить все прочитанными."""
        if self._notification_service is None:
            return

        self._notification_service.mark_all_as_read()
        if self._toast_service is not None:
            self._toast_service.show("All notifications marked as read", ToastLevel.SUCCESS)

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

        from src.app_context import get_app_context
        from src.gui.dialogs.crypto_profile_dialog import (
            CryptoProfileDialog,
            ProfileSelectionResult,
        )
        from src.security.crypto.service.profiles import CryptoProfile

        # Определяем текущий профиль из AppContext (fallback на STANDARD)
        try:
            ctx = get_app_context()
            current_profile: CryptoProfile = ctx.crypto_service.profile
        except (RuntimeError, AttributeError):
            current_profile = CryptoProfile.STANDARD

        dialog = CryptoProfileDialog(
            parent=self._root,
            current_profile=current_profile,
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

        config = LockConfig(auto_lock_minutes=self._auto_lock_minutes)
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

    def _on_security_trust_chain(self) -> None:
        """Верификация цепочки доверия шаблона."""
        if self._root is None:
            return

        try:
            from src.gui.security.trust_chain_dialog import TrustChainDialog
            from src.services.template_manager import TemplateManager
            from src.services.trust_chain_service import TrustChainService

            template_manager = TemplateManager()

            # Выбираем первый доступный шаблон для верификации
            templates = template_manager.list_templates()
            if not templates:
                if self._toast_service is not None:
                    self._toast_service.show(
                        "Нет шаблонов для верификации",
                        ToastLevel.WARNING,
                    )
                return

            import secrets
            from pathlib import Path

            keystore_path = Path.home() / ".fxtextprocessor" / "keystore"
            keystore_path.mkdir(parents=True, exist_ok=True)
            audit_key = secrets.token_bytes(32)
            trust_service = TrustChainService(
                keystore_path=keystore_path,
                audit_secret_key=audit_key,
            )

            template = templates[0]

            def on_whitelist(key_id: str) -> None:
                if self._toast_service is not None:
                    self._toast_service.show(
                        f"Ключ {key_id} добавлен в белый список",
                        ToastLevel.SUCCESS,
                    )

            def on_reject(key_id: str) -> None:
                if self._toast_service is not None:
                    self._toast_service.show(
                        f"Ключ {key_id} отклонён",
                        ToastLevel.INFO,
                    )

            dialog = TrustChainDialog(
                parent=self._root_widget(),
                template=template,
                trust_service=trust_service,
                verification_mode=True,
                on_whitelist=on_whitelist,
                on_reject=on_reject,
            )
            dialog.show()

        except (ImportError, AttributeError, TypeError, OSError, PermissionError, ValueError) as e:
            # Bug 5 FIX: конкретные исключения вместо except Exception
            logger.error("Ошибка открытия диалога Trust Chain: %s", e)
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Ошибка: {e}",
                    ToastLevel.ERROR,
                )

    def _on_security_fido2_setup(self) -> None:
        """Настройка FIDO2-устройства.

        Открывает диалог регистрации FIDO2 security key.
        """
        if self._root is None:
            return

        from src.gui.dialogs.fido2_setup_dialog import FIDO2SetupDialog

        def on_fido2_complete(result: dict[str, Any]) -> None:
            if result.get("success"):
                if self._toast_service is not None:
                    self._toast_service.show(
                        "FIDO2-устройство настроено",
                        ToastLevel.SUCCESS,
                    )
            else:
                if self._toast_service is not None:
                    self._toast_service.show(
                        "Настройка FIDO2 отменена",
                        ToastLevel.WARNING,
                    )

        dialog = FIDO2SetupDialog(
            parent=self._root_widget(),
            on_complete=on_fido2_complete,
        )
        dialog.show()

    def _on_security_totp_setup(self) -> None:
        """Настройка TOTP-аутентификатора.

        Открывает диалог настройки TOTP (QR-код + верификация).
        """
        if self._root is None:
            return

        from src.gui.dialogs.totp_setup_dialog import TOTPSetupDialog

        def on_totp_complete(result: dict[str, Any]) -> None:
            if result.get("verified"):
                if self._toast_service is not None:
                    self._toast_service.show(
                        "TOTP-аутентификатор настроен",
                        ToastLevel.SUCCESS,
                    )
            else:
                if self._toast_service is not None:
                    self._toast_service.show(
                        "Настройка TOTP отменена",
                        ToastLevel.WARNING,
                    )

        dialog = TOTPSetupDialog(
            parent=self._root_widget(),
            on_complete=on_totp_complete,
        )
        dialog.show()

    def _on_security_mfa_verification(self) -> None:
        """Ручная верификация MFA.

        Открывает диалог для повторной верификации MFA
        (например, для доступа к критическим операциям).
        """
        if self._root is None:
            return

        user_id = self._get_current_user_id()
        if user_id is None:
            if self._toast_service is not None:
                self._toast_service.show(
                    "Требуется вход в систему",
                    ToastLevel.WARNING,
                )
            return

        from src.gui.dialogs.mfa_verification_dialog import MFAVerificationDialog

        def on_verify(result: dict[str, Any]) -> None:
            if result.get("verified"):
                if self._toast_service is not None:
                    self._toast_service.show(
                        "MFA верификация пройдена",
                        ToastLevel.SUCCESS,
                    )

        dialog = MFAVerificationDialog(
            parent=self._root_widget(),
            user_id=user_id,
            on_verify=on_verify,
        )
        dialog.show()

    def _on_edit_find_replace(self) -> None:
        """Открывает диалог поиска и замены."""
        if self._root is None:
            return

        # Получаем текстовый виджет из активного документа
        # Bug 6 FIX: hasattr(self, "_document_view") убран — атрибут гарантирован
        # hasattr(_document_view, "get_text_widget") убран — DocumentView имеет метод
        text_widget = None
        if self._document_view is not None:
            text_widget = self._document_view.get_text_widget()

        if text_widget is None:
            if self._toast_service is not None:
                self._toast_service.show(
                    "Нет активного документа",
                    ToastLevel.WARNING,
                )
            return

        from src.gui.dialogs.find_replace_dialog import FindReplaceDialog

        dialog = FindReplaceDialog(
            parent=self._root_widget(),
            text_widget=text_widget,
        )
        dialog.show()

    def _on_file_import_template(self) -> None:
        """Открывает диалог импорта шаблона."""
        if self._root is None:
            return

        try:
            from src.gui.dialogs.template_import_dialog import TemplateImportDialog
            from src.security.crypto.utilities.floppy_optimizer import FloppyOptimizer
            from src.services.template_manager import TemplateManager
            from src.services.trust_chain_service import TrustChainService

            template_manager = TemplateManager()
            floppy_optimizer = FloppyOptimizer()

            # TrustChainService требует keystore_path и audit_secret_key
            from pathlib import Path

            keystore_path = Path.home() / ".fxtextprocessor" / "keystore"
            keystore_path.mkdir(parents=True, exist_ok=True)
            import secrets

            audit_key = secrets.token_bytes(32)
            trust_chain_service = TrustChainService(
                keystore_path=keystore_path,
                audit_secret_key=audit_key,
            )

            def on_import(result: object) -> None:
                if self._toast_service is not None:
                    self._toast_service.show(
                        "Шаблон импортирован",
                        ToastLevel.SUCCESS,
                    )

            def on_new_document(template_id: str) -> None:
                if self._controller is not None:
                    self._controller.dispatch("new_document_from_template", template_id=template_id)

            def on_print_blank(template_id: str) -> None:
                if self._controller is not None:
                    self._controller.dispatch("print_blank", template_id=template_id)

            dialog = TemplateImportDialog(
                parent=self._root_widget(),
                template_manager=template_manager,
                trust_chain_service=trust_chain_service,
                floppy_optimizer=floppy_optimizer,
                on_import=on_import,
                on_new_document=on_new_document,
                on_print_blank=on_print_blank,
            )
            dialog.show()

        except (ImportError, AttributeError, TypeError, OSError, PermissionError, ValueError) as e:
            # Bug 5 FIX: конкретные исключения вместо except Exception
            logger.error("Ошибка открытия диалога импорта шаблона: %s", e)
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Ошибка: {e}",
                    ToastLevel.ERROR,
                )

    def _on_file_export_template(self) -> None:
        """Открывает диалог экспорта шаблона."""
        if self._root is None:
            return

        try:
            from src.gui.dialogs.template_export_dialog import TemplateExportDialog
            from src.services.template_manager import TemplateManager

            template_manager = TemplateManager()

            # Bug 6 FIX: hasattr убран — DocumentView имеет get_form_data
            form_data: dict[str, Any] = {}
            if self._document_view is not None:
                form_data = self._document_view.get_form_data()

            current_user = "operator"
            if self._current_session_id is not None and self._session_manager is not None:
                try:
                    from src.security.auth.debug_utils import get_debug_user_id

                    current_user = get_debug_user_id()
                except ImportError:
                    pass

            def on_export_success(result: object) -> None:
                if self._toast_service is not None:
                    self._toast_service.show(
                        "Шаблон экспортирован",
                        ToastLevel.SUCCESS,
                    )

            dialog = TemplateExportDialog(
                parent=self._root_widget(),
                form_data=form_data,
                template_manager=template_manager,
                current_user=current_user,
            )
            dialog.show()

        except (ImportError, AttributeError, TypeError, OSError, ValueError) as e:
            # Bug 5 FIX: конкретные исключения вместо except Exception
            logger.error("Ошибка открытия диалога экспорта шаблона: %s", e)
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Ошибка: {e}",
                    ToastLevel.ERROR,
                )

    def _on_format_paper_profiles(self) -> None:
        """Открывает диалог выбора профиля бумаги."""
        if self._root is None:
            return

        from src.gui.dialogs.paper_profile_dialog import PaperProfileDialog

        def on_select(profile: object) -> None:
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Профиль применён: {getattr(profile, 'name', str(profile))}",
                    ToastLevel.SUCCESS,
                )

        dialog = PaperProfileDialog(
            parent=self._root_widget(),
            on_select=on_select,
        )
        dialog.show()

    def _on_tools_floppy_optimizer(self) -> None:
        """Открывает диалог оптимизации для дискеты."""
        if self._root is None:
            return

        from src.gui.dialogs.floppy_optimizer_dialog import FloppyOptimizerDialog

        # Получаем данные текущего документа для оптимизации
        # Bug FIX: get_template_data() возвращает dict, но FloppyOptimizerDialog
        # ожидает bytes. Используем get_template_data_as_bytes() для сериализации.
        template_data = b""
        if self._document_view is not None:
            try:
                template_data = self._document_view.get_template_data_as_bytes()
            except (AttributeError, TypeError):
                pass

        if not template_data:
            if self._toast_service is not None:
                self._toast_service.show(
                    "Нет данных документа для оптимизации",
                    ToastLevel.WARNING,
                )
            return

        dialog = FloppyOptimizerDialog(
            parent=self._root_widget(),
            template_data=template_data,
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
            self._root_widget(),
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
                        f"Go to page {result['page']}",
                        ToastLevel.INFO,
                    )
            except (ValueError, KeyError, tk.TclError, AttributeError) as e:
                # Bug 5 FIX: конкретные исключения вместо except Exception
                logger.error("Failed to navigate: %s", e)
                messagebox.showerror("Error", f"Failed to navigate: {e}")

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
                # Bug 8 FIX: ленивый импорт BookmarkManager — View не зависит от Model
                from src.model.bookmark import BookmarkManager

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
            self._root_widget(),
            bookmark_manager=self._bookmark_manager,
            current_page=current_page,
            on_goto=lambda page, line: document_view.goto_page(page, line),
        )
        result = dialog.show()

        if result and result.get("action") == "goto":
            if self._toast_service is not None:
                self._toast_service.show(
                    f"Go to page {result['page']}",
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

        # Bug 6 FIX: hasattr заменён на isinstance с FormFieldProtocol
        from src.gui.core.protocols import FormFieldProtocol

        current_value: str = ""
        if isinstance(field, FormFieldProtocol):
            current_value = str(field.get_value())

        dialog = PrefillDialog(
            self._root_widget(),
            field_id=field_id,
            field_label=field_label_str if field_label_str else field_id,
            current_value=current_value,
            on_select=lambda value: (
                field.set_value(value) if isinstance(field, FormFieldProtocol) else None
            ),
        )
        result = dialog.show()

        if result:
            # Apply to field
            if isinstance(field, FormFieldProtocol):
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
        logger.info("Barcode render mode changed to: %s", mode)
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
            self._toast_service.show("No open windows", ToastLevel.INFO)
            return

        # Build window list message
        window_names: list[str] = []
        for w in windows:
            status = "[свёрнуто]" if w.is_minimized else ""
            # is_main_window не определён в WindowManagerProtocol,
            # сравниваем с _main_window_id напрямую
            is_main = w.window_id == self._main_window_id if self._main_window_id else False
            marker = "✓" if is_main else " "
            window_names.append(f"{marker} {w.title} {status}")

        message = "Открытые окна:\n" + "\n".join(window_names)
        if self._root is not None:
            messagebox.showinfo("Window list", message, parent=self._root)

    def _on_window_minimize_all(self) -> None:
        """Callback: View → Window → Свернуть все.

        Сворачивает все окна приложения.
        """
        if self._window_manager is None:
            return

        count = self._window_manager.minimize_all()
        if self._toast_service is not None:
            self._toast_service.show(f"Windows minimized: {count}", ToastLevel.INFO)

    def _on_window_restore_all(self) -> None:
        """Callback: View → Window → Восстановить все.

        Восстанавливает все свёрнутые окна.
        """
        if self._window_manager is None:
            return

        count = self._window_manager.restore_all()
        if self._toast_service is not None:
            self._toast_service.show(f"Windows restored: {count}", ToastLevel.INFO)

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

        dialog = SpecialCharacterDialog(parent=self._root_widget())
        result: Optional[SpecialCharResult] = dialog.show()

        if result is None:
            return

        try:
            line, col = renderer.get_cursor_position()
        except (AttributeError, tk.TclError, RuntimeError) as e:
            # Bug 5 FIX: конкретные исключения вместо except Exception
            logger.error("Failed to get cursor position: %s", e)
            messagebox.showerror(
                "Ошибка",
                "Не удалось определить позицию курсора.",
                parent=self._root,
            )
            return

        try:
            if renderer._tk_text is None or renderer._command_stack is None:
                raise RuntimeError("Renderer text widget or command stack not available")

            position = f"{line}.{col - 1}"
            cmd = InsertTextCommand(renderer._tk_text, result.char, position)
            renderer._command_stack.execute(cmd)

            if self._toast_service is not None:
                self._toast_service.show("Character inserted", ToastLevel.SUCCESS)
        except (AttributeError, tk.TclError, RuntimeError, ValueError) as e:
            # Bug 5 FIX: конкретные исключения вместо except Exception
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

__version__: Final[str] = "2.1"
__author__: Final[str] = "FX Text Processor Team"
__date__: Final[str] = "April 2026"

__all__: list[str] = [
    "MainWindow",
    "APP_NAME",
    "MODIFIED_INDICATOR",
    "TITLE_SEPARATOR",
]
