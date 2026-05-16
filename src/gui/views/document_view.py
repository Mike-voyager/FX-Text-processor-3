"""DocumentView для FX Text Processor 3.

Полная реализация для Фазы 2 — интегрирует все компоненты:
- Ruler: линейка с метками символов
- FormatToolbar: панель форматирования (CPI, bold, italic, etc.)
- FreeFormRenderer: WYSIWYG редактор свободной формы
- Navigator: панель навигации по документу
- CommandStack: undo/redo система

Security:
    - Sanitization входных данных
    - Wipe методы для очистки sensitive данных
    - Session lock support (hide_content/restore_content)

Example:
    >>> doc_view = DocumentView(widget_id="doc_view", controller=ctrl)
    >>> doc_view.mount(parent_frame)
    >>> doc_view.show_placeholder("Select a document to edit")
    >>> doc_view.set_document(document)  # Document model
    >>> doc_view.switch_mode(DocumentMode.FREE_FORM)
    >>> doc_view.undo()
    >>> doc_view.wipe_sensitive_data()

Version: 2.0 (Phase 2)
Date: April 2026
"""

from __future__ import annotations

__version__ = "2.0"
__author__ = "FX Text Processor Team"
__date__ = "April 2026"

import logging
import tkinter as tk
from typing import Any, Callable, Final, Optional, Protocol, cast, runtime_checkable

from src.documents.constructor.form_status import FormStatus
from src.documents.printing.document_renderer import DocumentRenderer
from src.documents.types.document_type import DocumentMode
from src.gui.components.base.widget import BaseWidget
from src.gui.components.escp_preview_widget import ESCPPreviewWidget
from src.gui.components.format_toolbar import FormatToolbar
from src.gui.components.navigator import Navigator
from src.gui.components.paper_toolbar import PaperToolbar
from src.gui.components.paper_visualization import CodepageStatusWidget
from src.gui.components.ruler import Ruler
from src.gui.core.commands.command import Command
from src.gui.core.commands.command_stack import CommandStack
from src.gui.form_designer.designer_tab import DesignerTab
from src.gui.layout.layout_constants import PADDING_LARGE, PADDING_NORMAL
from src.gui.renderers.factory import RendererFactory
from src.gui.renderers.free_form_renderer import FreeFormDocument, FreeFormRenderer
from src.gui.renderers.protocols import DocumentRendererProtocol
from src.gui.renderers.structured_form_renderer import (
    StructuredFormDocument,
    StructuredFormRenderer,
)
from src.gui.themes import ThemeRegistry
from src.services.clipboard_service import ClipboardService, PyperclipBackend

logger = logging.getLogger(__name__)


def _theme_color(key: str) -> str:
    """Возвращает цвет из текущей темы.

    Args:
        key: Идентификатор цвета.

    Returns:
        Color в формате HEX.
    """
    try:
        return ThemeRegistry.get_instance().get_current().get_color(key)
    except (AttributeError, KeyError):
        return "#f5f5f5"


# Placeholder icon (document emoji)
PLACEHOLDER_ICON: Final[str] = "📄"

# Default placeholder message
DEFAULT_PLACEHOLDER_MESSAGE: Final[str] = "No document open"

# Maximum length for document_id (security: prevent DoS)
MAX_DOCUMENT_ID_LENGTH: Final[int] = 100

# Colors
PLACEHOLDER_BG: Final[str] = "#f5f5f5"
PLACEHOLDER_FG: Final[str] = "#888888"
PLACEHOLDER_ICON_SIZE: Final[int] = 48


# Document model protocol
@runtime_checkable
class DocumentProtocol(Protocol):
    """Протокол для Document модели."""

    @property
    def id(self) -> str:
        """ID документа."""
        ...

    @property
    def mode(self) -> DocumentMode:
        """Режим документа."""
        ...

    def get_content(self) -> str:
        """Возвращает содержимое документа."""
        ...

    def get_cpi(self) -> int:
        """Возвращает CPI документа."""
        ...


class DocumentView(BaseWidget):
    """DocumentView с полной интеграцией компонентов Phase 2.

    Реализует DocumentViewProtocol, предоставляя интерфейс для
    отображения и редактирования документов.

    Layout:
        ┌───────────────────────────────┐
        │ [Ruler]                       │
        ├───────────────────────────────┤
        │ [FormatToolbar]               │
        ├───────────────────────────────┤
        │                               │
        │ [FreeFormRenderer]            │
        │ (Text widget + scrollbars)    │
        │                               │
        ├───────────────────────────────┤
        │ [Navigator]                   │
        └───────────────────────────────┘

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        command_stack: Стек команд для undo/redo.

    Component Integration:
        - FormatToolbar.on_cpi_change -> FreeFormRenderer.apply_cpi
        - FormatToolbar.on_format_toggle -> FreeFormRenderer.apply_format
        - FreeFormRenderer.on_text_change -> DocumentView._on_text_changed
        - FreeFormRenderer.on_cursor_move -> Navigator.set_position
        - Navigator.on_goto_line -> FreeFormRenderer.set_cursor_position
        - Ruler.on_click -> FreeFormRenderer.set_cursor_position

    Security Attributes:
        _sensitive_fields: Список полей с sensitive данными для wipe
        _content_hidden: Флаг скрытия контента (session lock)

    Example:
        >>> doc_view = DocumentView(widget_id="doc_view", controller=ctrl)
        >>> doc_view.mount(parent_frame)
        >>> doc_view.set_document(free_form_doc)
        >>> doc_view.undo()
        >>> doc_view.wipe_sensitive_data()
    """

    def __init__(
        self,
        widget_id: str = "document_view",
        controller: Optional[Any] = None,
        on_paper_setup: Optional[Callable[[], None]] = None,
        statusbar: Optional[Any] = None,
    ) -> None:
        """Инициализация DocumentView.

        Args:
            widget_id: Уникальный идентификатор виджета (default: "document_view").
            controller: Опциональная ссылка на контроллер для callbacks.
            on_paper_setup: Callback для открытия диалога настройки бумаги.
            statusbar: Опциональная ссылка на StatusBar для workflow обновлений.

        Example:
            >>> doc_view = DocumentView(controller=my_controller)
        """
        super().__init__(widget_id=widget_id, controller=controller)

        # Callback для настройки бумаги
        self._on_paper_setup: Optional[Callable[[], None]] = on_paper_setup

        # StatusBar reference for workflow timeline updates
        self._statusbar: Optional[Any] = statusbar

        # Document state
        self._current_document: Optional[DocumentProtocol] = None
        self._current_document_id: Optional[str] = None
        self._current_mode: DocumentMode = DocumentMode.FREE_FORM
        self._placeholder_visible: bool = True

        # CommandStack для undo/redo
        self._command_stack: CommandStack = CommandStack()

        # Phase 2: Clipboard service
        self._clipboard_service: ClipboardService = ClipboardService(
            backend=PyperclipBackend(),
            history_size=20,
        )

        # Phase 2: Component references (initialized in _create_tk_widget)
        self._paper_toolbar: Optional[PaperToolbar] = None
        self._ruler: Optional[Ruler] = None
        self._format_toolbar: Optional[FormatToolbar] = None
        self._navigator: Optional[Navigator] = None

        # Phase 2: Preview mode
        self._document_renderer: DocumentRenderer = DocumentRenderer()
        self._preview_widget: Optional[ESCPPreviewWidget] = None

        # Phase 4: Strategy Pattern - unified renderer interface
        self._current_renderer: Optional[DocumentRendererProtocol[Any, Any]] = None
        # Alias for protocol compliance
        self._renderer: Optional[DocumentRendererProtocol[Any, Any]] = None
        self._renderer_factory: RendererFactory = RendererFactory()

        # Phase 4: Workflow state manager for toolbar integration
        self._workflow_state_manager: Optional[Any] = None

        # Mode state for protocol compliance
        self._mode: Optional[DocumentMode] = None

        # Phase 5: Form Designer
        self._designer_tab: Optional[DesignerTab] = None

        # Mode tabs frame (for Document/Designer/Preview)
        self._tk_mode_tabs_frame: Optional[tk.Frame] = None
        self._mode_tab_buttons: dict[str, tk.Button] = {}

        # Security: Session lock state
        self._content_hidden: bool = False
        self._hidden_content_backup: Optional[str] = None

        # Widget references (initialized in _create_tk_widget)
        self._tk_frame: Optional[tk.Frame] = None
        self._tk_placeholder_frame: Optional[tk.Frame] = None
        self._tk_icon_label: Optional[tk.Label] = None
        self._tk_message_label: Optional[tk.Label] = None
        self._tk_content_frame: Optional[tk.Frame] = None

        # Sub-frames for layout
        self._tk_paper_toolbar_frame: Optional[tk.Frame] = None
        self._tk_ruler_frame: Optional[tk.Frame] = None
        self._tk_toolbar_frame: Optional[tk.Frame] = None
        self._tk_renderer_frame: Optional[tk.Frame] = None
        self._tk_navigator_frame: Optional[tk.Frame] = None
        self._tk_field_palette_frame: Optional[tk.Frame] = None
        self._tk_codepage_status_frame: Optional[tk.Frame] = None

        # Codepage status widget
        self._codepage_status: Optional[CodepageStatusWidget] = None

        # Saved document state for mode switching
        self._saved_state: dict[str, Any] = {}

    @property
    def _free_form_renderer(self) -> Optional[FreeFormRenderer]:
        """Backward compatibility property for FREE_FORM renderer.

        Returns:
            FreeFormRenderer если текущий режим FREE_FORM, иначе None.
        """
        if self._current_mode == DocumentMode.FREE_FORM:
            if self._current_renderer is not None:
                return self._current_renderer  # type: ignore[return-value]
        return None

    @property
    def _structured_renderer(self) -> Optional[StructuredFormRenderer]:
        """Backward compatibility property for STRUCTURED_FORM renderer.

        Returns:
            StructuredFormRenderer если текущий режим STRUCTURED_FORM, иначе None.
        """
        if self._current_mode == DocumentMode.STRUCTURED_FORM:
            if self._current_renderer is not None:
                return self._current_renderer  # type: ignore[return-value]
        return None

    @property
    def widget(self) -> tk.Widget:
        """Возвращает tkinter widget для размещения.

        Returns:
            Корневой Frame DocumentView.

        Raises:
            RuntimeError: Если виджет не смонтирован.
        """
        if self._tk_frame is None:
            raise RuntimeError("DocumentView is not mounted")
        return self._tk_frame

    @property
    def current_document_id(self) -> Optional[str]:
        """ID текущего документа.

        Returns:
            Строковый ID документа или None если документ не открыт.
        """
        return self._current_document_id

    @property
    def current_mode(self) -> DocumentMode:
        """Текущий режим документа.

        Returns:
            Режим документа (FREE_FORM или STRUCTURED_FORM).
        """
        return self._current_mode

    @property
    def is_placeholder_visible(self) -> bool:
        """Видимость placeholder.

        Returns:
            True если placeholder отображается.
        """
        return self._placeholder_visible

    @property
    def command_stack(self) -> CommandStack:
        """Возвращает CommandStack для undo/redo.

        Returns:
            Экземпляр CommandStack.
        """
        return self._command_stack

    def show(self) -> None:
        """Показывает компонент."""
        if self._tk_frame is not None:
            self._tk_frame.pack(fill="both", expand=True)

    def hide(self) -> None:
        """Скрывает компонент."""
        if self._tk_frame is not None:
            self._tk_frame.pack_forget()

    def is_visible(self) -> bool:
        """Проверяет видимость компонента.

        Returns:
            True если виджет отображается.
        """
        if self._tk_frame is None:
            return False
        return self._tk_frame.winfo_viewable() == 1

    def show_placeholder(self, message: str = DEFAULT_PLACEHOLDER_MESSAGE) -> None:
        """Показывает placeholder content.

        Отображает иконку документа и сообщение в центре View.
        Используется когда нет открытого документа.

        Args:
            message: Текст сообщения для отображения (default: "No document open").

        Security:
            Сообщение обрезается до 200 символов для предотвращения
            UI-based DoS атак.

        Example:
            >>> doc_view.show_placeholder("Select a document from sidebar")
            >>> doc_view.show_placeholder()  # Default message
        """
        # Security: truncate long messages
        safe_message = message[:200] if message else DEFAULT_PLACEHOLDER_MESSAGE

        self._placeholder_visible = True

        # Update label if mounted
        if self._tk_message_label is not None:
            self._tk_message_label.config(text=safe_message)

        # Show placeholder frame, hide content
        if self._tk_placeholder_frame is not None:
            self._tk_placeholder_frame.pack(fill="both", expand=True)

        # Hide content frame
        if self._tk_content_frame is not None:
            self._tk_content_frame.pack_forget()

    def hide_placeholder(self) -> None:
        """Скрывает placeholder и показывает content frame."""
        self._placeholder_visible = False

        if self._tk_placeholder_frame is not None:
            self._tk_placeholder_frame.pack_forget()

        if self._tk_content_frame is not None:
            self._tk_content_frame.pack(fill="both", expand=True)
            try:
                self._tk_content_frame.lift()  # Bring to front
            except tk.TclError:
                pass
            self._tk_content_frame.update_idletasks()

    def set_document(self, document: DocumentProtocol) -> None:
        """Устанавливает текущий документ.

        Определяет режим документа, переключает режим отображения
        и загружает содержимое в соответствующий рендерер.

        Args:
            document: Модель документа (Document или FreeFormDocument).

        Security:
            - document.id санитизируется (max 100 chars)
            - Проверка на недопустимые символы

        Raises:
            ValueError: Если document.id пустой или содержит
                недопустимые символы.
            TypeError: Если document не поддерживает DocumentProtocol.

        Example:
            >>> doc = FreeFormDocument(content="Hello", cpi=12)
            >>> doc_view.set_document(doc)
            >>> # Переключается в FREE_FORM mode, рендерит документ
        """
        if not isinstance(document, DocumentProtocol):
            raise TypeError(
                f"document must support DocumentProtocol, got {type(document).__name__}"
            )

        # Security: sanitize document_id
        doc_id = getattr(document, "id", str(id(document)))
        sanitized_id = self._sanitize_document_id(doc_id)

        # Wipe previous document if switching to a different one
        if (
            self._current_document is not None
            and self._current_document_id is not None
            and self._current_document_id != sanitized_id
        ):
            self.wipe_sensitive_data()

        self._current_document = document
        self._current_document_id = sanitized_id

        # Determine mode from document
        try:
            mode = document.mode
        except AttributeError:
            # Default to FREE_FORM if mode not specified
            mode = DocumentMode.FREE_FORM

        # Hide placeholder, show content FIRST
        self.hide_placeholder()

        # Force content frame update
        if self._tk_content_frame is not None:
            self._tk_content_frame.update_idletasks()

        # Switch to appropriate mode (after content is visible)
        self.switch_mode(mode)

        # Render document content based on mode
        if mode == DocumentMode.FREE_FORM:
            self._render_free_form_document(document)
        elif mode == DocumentMode.STRUCTURED_FORM:
            self._render_structured_document(document)
            # Sync StatusBar with document workflow status if available
            self._sync_statusbar_workflow_from_document(document)

    def switch_mode(self, mode: DocumentMode) -> None:
        """Переключает режим отображения документа.

        Использует Strategy Pattern через RendererFactory для создания
        и переключения между рендерерами. Настраивает UI под режим
        через renderer.create_toolbar() и renderer.create_editor().

        Args:
            mode: Режим документа (FREE_FORM или STRUCTURED_FORM).

        Example:
            >>> doc_view.switch_mode(DocumentMode.FREE_FORM)
            >>> doc_view.switch_mode(DocumentMode.STRUCTURED_FORM)
        """
        if self._current_mode == mode and self._current_renderer is not None:
            return  # Already in this mode with active renderer

        # Save current state before switching
        self._save_current_state()

        # Cleanup current renderer
        self._cleanup_current_renderer()

        # Update mode
        self._current_mode = mode
        self._mode = mode

        # Create new renderer via factory
        self._renderer = self._create_renderer_for_mode(mode)
        self._current_renderer = self._renderer

        # Rebuild UI using renderer-based Strategy Pattern
        self._rebuild_ui()

        # Render current document if available
        if self._current_document is not None:
            self._render_current_document()

        # Notify controller
        if self._controller is not None:
            self._controller.dispatch("document_mode_changed", mode=mode)

        # Update StatusBar workflow visibility
        if self._statusbar is not None:
            self._statusbar.set_document_mode(mode)
            # For structured form, try to sync current workflow status
            if mode == DocumentMode.STRUCTURED_FORM:
                self._sync_statusbar_workflow()

    def _rebuild_ui(self) -> None:
        """Перестраивает UI для текущего рендерера.

        Strategy Pattern: вызывает renderer.create_toolbar() и
        renderer.create_editor() для создания mode-specific UI.
        Очищает предыдущий toolbar перед созданием нового.

        Mode-specific visibility:
            - FREE_FORM: FormatToolbar visible, WorkflowToolbar hidden
            - STRUCTURED_FORM: WorkflowToolbar visible, FormatToolbar hidden
            - Ruler visible для обоих режимов
        """
        if self._current_renderer is None:
            return

        # Clear toolbar frame
        if self._tk_toolbar_frame is not None:
            for child in self._tk_toolbar_frame.winfo_children():
                child.destroy()
            self._format_toolbar = None

            toolbar_widget: Optional[tk.Widget] = None

            if self._current_mode == DocumentMode.FREE_FORM:
                # FREE_FORM: создаём FormatToolbar
                self._format_toolbar = FormatToolbar(
                    widget_id="format_toolbar",
                    on_cpi_change=self._on_cpi_changed,
                    on_format_toggle=self._on_format_toggled,
                )
                toolbar_widget = self._format_toolbar.mount(self._tk_toolbar_frame)
                toolbar_widget.pack(fill=tk.BOTH, expand=True)
            elif self._current_mode == DocumentMode.STRUCTURED_FORM:
                # STRUCTURED_FORM: создаём WorkflowToolbar через renderer
                if hasattr(self._current_renderer, "create_toolbar"):
                    toolbar_widget = self._current_renderer.create_toolbar(
                        self._tk_toolbar_frame,
                    )
                    if toolbar_widget is not None:
                        toolbar_widget.pack(fill=tk.BOTH, expand=True)

        # Renderer frame: factory уже смонтировала renderer,
        # поэтому вызываем renderer.show() для отображения вместо manual pack.
        if self._tk_renderer_frame is not None:
            if hasattr(self._current_renderer, "create_editor"):
                self._current_renderer.create_editor(
                    self._tk_renderer_frame,
                )
            if hasattr(self._current_renderer, "show"):
                self._current_renderer.show()

        # Setup renderer callbacks
        if hasattr(self._current_renderer, "set_on_text_change_callback"):
            self._current_renderer.set_on_text_change_callback(
                self._on_text_changed,
            )
        if hasattr(self._current_renderer, "set_on_field_change_callback"):
            self._current_renderer.set_on_field_change_callback(
                self._on_field_changed,
            )
        if hasattr(self._current_renderer, "set_on_cursor_move_callback"):
            self._current_renderer.set_on_cursor_move_callback(
                self._on_cursor_moved,
            )

        # Ensure Ruler is visible for both modes
        self._show_ruler(True)

        # Show navigator only for FREE_FORM (structured has own navigation)
        if self._tk_navigator_frame is not None:
            if self._current_mode == DocumentMode.FREE_FORM:
                self._tk_navigator_frame.pack(fill=tk.X, side=tk.BOTTOM)
            else:
                self._tk_navigator_frame.pack_forget()

    def _cleanup_current_renderer(self) -> None:
        """Очищает текущий рендерер перед переключением."""
        if self._current_renderer is not None:
            try:
                self._current_renderer.wipe_sensitive_data()
                self._current_renderer.unmount()
            except (AttributeError, RuntimeError) as e:
                logger.debug("Renderer cleanup error (non-critical): %s", e)
            self._current_renderer = None
            self._renderer = None

    def _create_renderer_for_mode(self, mode: DocumentMode) -> DocumentRendererProtocol[Any, Any]:
        """Создаёт renderer для указанного режима документа.

        Args:
            mode: Режим документа для которого создаётся рендерер.

        Returns:
            Экземпляр рендерера, реализующий DocumentRendererProtocol.

        Raises:
            RuntimeError: Если renderer frame не инициализирован.
        """
        if self._tk_renderer_frame is None:
            raise RuntimeError("Renderer frame not initialized")

        renderer = self._renderer_factory.create(
            mode=mode,
            parent=self._tk_renderer_frame,
            controller=self._controller,
            command_stack=self._command_stack,
            workflow_state_manager=self._workflow_state_manager,
        )

        # Set document if available
        if self._current_document is not None and hasattr(renderer, "set_document"):
            renderer.set_document(self._current_document)

        # Wire WorkflowToolbar callbacks to WorkflowStateManager if available
        if (
            mode == DocumentMode.STRUCTURED_FORM
            and self._workflow_state_manager is not None
            and hasattr(renderer, "_workflow_toolbar")
        ):
            toolbar = getattr(renderer, "_workflow_toolbar", None)
            if toolbar is not None:
                toolbar.on_action(self._on_workflow_action)

        return renderer  # type: ignore[no-any-return]

    def _on_workflow_action(self, action: str) -> None:
        """Обработчик действий WorkflowToolbar, связанный с WorkflowStateManager.

        Args:
            action: Имя действия workflow.
        """
        if self._workflow_state_manager is None:
            logger.debug("Workflow action %s ignored: no state manager", action)
            # Still update StatusBar for role/status changes that don't require state manager
            self._update_statusbar_for_action(action)
            return
        # Dispatch to workflow state manager if it supports direct action mapping,
        # otherwise fall back to controller dispatch.
        try:
            if hasattr(self._workflow_state_manager, "request_transition_by_action"):
                from uuid import UUID

                doc_id = self._current_document_id
                if doc_id:
                    self._workflow_state_manager.request_transition_by_action(
                        UUID(doc_id) if isinstance(doc_id, str) else doc_id,
                        action,
                    )
            elif self._controller is not None:
                self._controller.dispatch("workflow_action", workflow_action=action)
            # Update StatusBar timeline and role after workflow action
            self._update_statusbar_for_action(action)
        except (ValueError, AttributeError, RuntimeError) as e:
            logger.warning("Workflow action %s failed: %s", action, e)

    def _update_statusbar_for_action(self, action: str) -> None:
        """Обновляет StatusBar timeline и role badge на основе workflow действия.

        Args:
            action: Имя действия workflow.
        """
        if self._statusbar is None:
            return

        # Map action names to FormStatus
        action_to_status: dict[str, FormStatus] = {
            "save_draft": FormStatus.DRAFT,
            "fill_fields": FormStatus.DRAFT,
            "submit_for_validation": FormStatus.FILLED,
            "validate": FormStatus.VALIDATED,
            "approve": FormStatus.APPROVED,
            "sign": FormStatus.SIGNED,
            "print": FormStatus.PRINTED,
            "archive": FormStatus.ARCHIVED,
            "reject": FormStatus.REJECTED,
        }

        if action in action_to_status:
            status = action_to_status[action]
            self._statusbar.set_workflow_status(status)
            self._statusbar.set_workflow_timeline(status)

        # Map role switch actions to WorkflowRole
        from src.gui.workflow.role_badge import WorkflowRole

        action_to_role: dict[str, WorkflowRole] = {
            "switch_to_operator": WorkflowRole.OPERATOR,
            "switch_to_editor": WorkflowRole.EDITOR,
            "switch_to_supervisor": WorkflowRole.SUPERVISOR,
            "switch_to_signatory": WorkflowRole.SIGNATORY,
        }

        if action in action_to_role:
            self._statusbar.set_role_badge(action_to_role[action])

    def _sync_statusbar_workflow(self) -> None:
        """Синхронизирует StatusBar workflow indicators с текущим состоянием."""
        if self._statusbar is None:
            return
        if self._current_mode != DocumentMode.STRUCTURED_FORM:
            return

        # Try to get status from workflow state manager or current document
        if self._current_document is not None:
            self._sync_statusbar_workflow_from_document(self._current_document)
        elif self._workflow_state_manager is not None and self._current_document_id:
            try:
                if hasattr(self._workflow_state_manager, "workflow_controller"):
                    wc = self._workflow_state_manager.workflow_controller
                    from uuid import UUID

                    doc_uuid = (
                        UUID(self._current_document_id)
                        if isinstance(self._current_document_id, str)
                        else self._current_document_id
                    )
                    if hasattr(wc, "get_current_state"):
                        status = wc.get_current_state(doc_uuid)
                        self._statusbar.set_workflow_status(status)
                        self._statusbar.set_workflow_timeline(status)
                    if hasattr(wc, "current_role"):
                        role = wc.current_role
                        self._statusbar.set_role_badge(role)
            except Exception as e:
                logger.debug("Failed to sync StatusBar workflow: %s", e)

    def _sync_statusbar_workflow_from_document(self, document: DocumentProtocol) -> None:
        """Синхронизирует StatusBar с workflow статусом документа.

        Args:
            document: Документ для получения статуса.
        """
        if self._statusbar is None:
            return

        # Try to extract status from document
        status_attr = getattr(document, "status", None)
        if status_attr is not None:
            try:
                if isinstance(status_attr, FormStatus):
                    status = status_attr
                elif isinstance(status_attr, str):
                    status = FormStatus(status_attr)
                else:
                    return
                self._statusbar.set_workflow_status(status)
                self._statusbar.set_workflow_timeline(status)
            except (ValueError, TypeError):
                logger.debug("Document status not a valid FormStatus: %s", status_attr)

        # Try to extract role from document
        role_attr = getattr(document, "role", None)
        if role_attr is not None:
            try:
                from src.gui.workflow.role_badge import WorkflowRole

                if isinstance(role_attr, WorkflowRole):
                    self._statusbar.set_role_badge(role_attr)
                elif isinstance(role_attr, str):
                    self._statusbar.set_role_badge(WorkflowRole(role_attr))
            except (ValueError, TypeError):
                logger.debug("Document role not a valid WorkflowRole: %s", role_attr)

    def set_workflow_state_manager(self, manager: Any) -> None:
        """Устанавливает WorkflowStateManager для интеграции с WorkflowToolbar.

        Args:
            manager: Экземпляр WorkflowStateManager или совместимый объект.
        """
        self._workflow_state_manager = manager

    def _save_current_state(self) -> None:
        """Сохраняет состояние текущего документа перед переключением режима.

        Сохраняет позицию скролла, позицию курсора и выделение
        из текстового виджета текущего рендерера в ``self._saved_state``.
        """
        self._saved_state.clear()
        renderer: Any = self._current_renderer
        if renderer is None:
            return
        text_widget: Optional[tk.Text] = None
        if hasattr(renderer, "_tk_text"):
            text_widget = cast(Optional[tk.Text], getattr(renderer, "_tk_text", None))
        if text_widget is not None:
            try:
                self._saved_state["yview"] = text_widget.yview()
                self._saved_state["xview"] = text_widget.xview()
                self._saved_state["cursor"] = str(text_widget.index(tk.INSERT))
                try:
                    sel_start = str(text_widget.index(tk.SEL_FIRST))
                    sel_end = str(text_widget.index(tk.SEL_LAST))
                    self._saved_state["selection"] = (sel_start, sel_end)
                except tk.TclError:
                    self._saved_state["selection"] = None
            except tk.TclError as e:
                logger.debug("State save interrupted: %s", e)

    def _setup_mode_specific_ui(self) -> None:
        """Настраивает UI в зависимости от режима.

        .. deprecated::
            Используйте _rebuild_ui() для renderer-based UI creation.

        Configure UI components based on document mode:
        - FREE_FORM: format toolbar visible, ruler visible, field palette hidden
        - STRUCTURED_FORM: format toolbar hidden, ruler visible, field palette visible
        """
        if self._mode == DocumentMode.FREE_FORM:
            self._show_format_toolbar(True)
            self._show_ruler(True)
            self._set_field_palette_visible(False)
        elif self._mode == DocumentMode.STRUCTURED_FORM:
            self._show_format_toolbar(True)  # WorkflowToolbar в этом фрейме
            self._show_ruler(True)
            self._set_field_palette_visible(True)

    def _show_format_toolbar(self, show: bool) -> None:
        """Показывает или скрывает панель форматирования.

        Args:
            show: True для показа, False для скрытия.
        """
        if self._tk_toolbar_frame is None:
            return

        if show:
            self._tk_toolbar_frame.pack(fill=tk.X, side=tk.TOP)
        else:
            self._tk_toolbar_frame.pack_forget()

    def _show_ruler(self, show: bool) -> None:
        """Показывает или скрывает линейку.

        Args:
            show: True для показа, False для скрытия.
        """
        if self._ruler is None or self._tk_ruler_frame is None:
            return

        if show:
            self._tk_ruler_frame.pack(fill=tk.X, side=tk.TOP)
        else:
            self._tk_ruler_frame.pack_forget()

    def _set_field_palette_visible(self, show: bool) -> None:
        """Показывает или скрывает палитру полей формы.

        Args:
            show: True для показа, False для скрытия.
        """
        if self._tk_field_palette_frame is None:
            return
        if show:
            self._tk_field_palette_frame.pack(fill=tk.Y, side=tk.RIGHT)
        else:
            self._tk_field_palette_frame.pack_forget()

    def set_renderer(self, renderer: DocumentRendererProtocol[Any, Any]) -> None:
        """Устанавливает renderer с проверкой протокола.

        Args:
            renderer: Рендерер, реализующий DocumentRendererProtocol.

        Raises:
            TypeError: Если renderer не реализует DocumentRendererProtocol.
        """
        # Check protocol compliance using hasattr for runtime checking
        required_methods = [
            "render",
            "get_content",
            "wipe_sensitive_data",
            "can_handle",
        ]
        for method in required_methods:
            if not hasattr(renderer, method):
                raise TypeError(
                    f"Renderer must implement DocumentRendererProtocol, missing method: {method}"
                )

        self._renderer = renderer
        self._current_renderer = renderer

    def _render_current_document(self) -> None:
        """Рендерит текущий документ в активном рендерере."""
        if self._current_renderer is None or self._current_document is None:
            return

        document = self._current_document

        if self._current_mode == DocumentMode.FREE_FORM:
            if isinstance(document, FreeFormDocument):
                self._current_renderer.render(document)
            else:
                # Convert to FreeFormDocument
                content = getattr(document, "content", "")
                cpi = getattr(document, "cpi", 10)
                free_doc = FreeFormDocument(content=content, cpi=cpi)
                self._current_renderer.render(free_doc)

        elif self._current_mode == DocumentMode.STRUCTURED_FORM:
            if isinstance(document, StructuredFormDocument):
                self._current_renderer.render(document)
            else:
                self.show_placeholder("Structured Form requires StructuredFormDocument")

    def _show_free_form_renderer(self) -> None:
        """Показывает FreeFormRenderer (backward compatibility).

        DEPRECATED: Используйте switch_mode(DocumentMode.FREE_FORM).
        """
        self.switch_mode(DocumentMode.FREE_FORM)

    def _show_structured_form_renderer(self) -> None:
        """Показывает StructuredFormRenderer (backward compatibility).

        DEPRECATED: Используйте switch_mode(DocumentMode.STRUCTURED_FORM).
        """
        self.switch_mode(DocumentMode.STRUCTURED_FORM)

    # =====================================================================
    # PHASE 5: FORM DESIGNER MODE
    # =====================================================================

    def _create_mode_tabs(self) -> None:
        """Создаёт табы Document/Designer/Preview.

        Creates tab bar above content area for mode switching:
        [Document] [Designer] [Preview]
        """
        if self._tk_content_frame is None:
            return

        self._tk_mode_tabs_frame = tk.Frame(
            self._tk_content_frame,
            bg=_theme_color("bg"),
            height=28,
        )
        self._tk_mode_tabs_frame.pack(fill=tk.X, side=tk.TOP)
        self._tk_mode_tabs_frame.pack_propagate(False)

        # Document tab (default)
        doc_btn = tk.Button(
            self._tk_mode_tabs_frame,
            text="📄 Document",
            relief=tk.SUNKEN,
            bg=_theme_color("accent"),
            command=self.switch_to_document_mode,
        )
        doc_btn.pack(side=tk.LEFT, padx=2, pady=2)
        self._mode_tab_buttons["document"] = doc_btn

        # Designer tab
        designer_btn = tk.Button(
            self._tk_mode_tabs_frame,
            text="🎨 Designer",
            relief=tk.RAISED,
            bg=_theme_color("bg"),
            command=self.switch_to_designer_mode,
        )
        designer_btn.pack(side=tk.LEFT, padx=2, pady=2)
        self._mode_tab_buttons["designer"] = designer_btn

        # Preview tab
        preview_btn = tk.Button(
            self._tk_mode_tabs_frame,
            text="👁 Preview",
            relief=tk.RAISED,
            bg=_theme_color("bg"),
            command=self.switch_to_preview_mode,
        )
        preview_btn.pack(side=tk.LEFT, padx=2, pady=2)
        self._mode_tab_buttons["preview"] = preview_btn

    def switch_to_designer_mode(self) -> None:
        """Переключает в режим дизайнера."""
        # Hide other renderers
        self._hide_all_renderers()

        # Update tab buttons
        self._update_tab_button_state("designer")

        # Show DesignerTab
        if self._designer_tab is None and self._tk_content_frame is not None:
            self._designer_tab = DesignerTab(
                parent=self._tk_content_frame,
                document=self._get_current_document(),
                controller=self._controller,
            )
            self._designer_tab.mount(self._tk_content_frame)

        if self._designer_tab is not None and hasattr(self._designer_tab, "show"):
            self._designer_tab.show()

    def switch_to_document_mode(self) -> None:
        """Переключает в режим документа."""
        # Hide DesignerTab
        if self._designer_tab is not None and hasattr(self._designer_tab, "hide"):
            self._designer_tab.hide()

        # Update tab buttons
        self._update_tab_button_state("document")

        # Show appropriate renderer (FreeForm or StructuredForm)
        if self._current_mode == DocumentMode.FREE_FORM:
            self._show_free_form_renderer()
        elif self._current_mode == DocumentMode.STRUCTURED_FORM:
            self._show_structured_form_renderer()

    def switch_to_preview_mode(self) -> None:
        """Переключает в режим предпросмотра ESC/P.

        Показывает рендеренный ESC/P вывод документа.
        """
        # Hide all renderers
        self._hide_all_renderers()

        # Update tab buttons
        self._update_tab_button_state("preview")

        # Create preview widget if needed
        if self._preview_widget is None and self._tk_content_frame is not None:
            self._preview_widget = ESCPPreviewWidget(
                parent=self._tk_content_frame,
                document_renderer=self._document_renderer,
            )

        if self._preview_widget is not None:
            # Get current document and show in preview
            document = self._get_current_document()
            if document:
                self._preview_widget.show_document(document)
            else:
                self._preview_widget.clear()

            self._preview_widget.pack(fill=tk.BOTH, expand=True)
            if self._tk_content_frame is not None:
                self._tk_content_frame.pack_propagate(False)

    def _hide_all_renderers(self) -> None:
        """Скрывает все рендереры."""
        if self._free_form_renderer is not None:
            self._free_form_renderer.hide()
        if self._structured_renderer is not None:
            self._structured_renderer.hide()
        if self._designer_tab is not None and hasattr(self._designer_tab, "hide"):
            self._designer_tab.hide()
        if self._preview_widget is not None:
            self._preview_widget.grid_forget()

        # Hide placeholder if showing
        if self._tk_placeholder_frame is not None:
            self._tk_placeholder_frame.pack_forget()

    def _update_tab_button_state(self, active_tab: str) -> None:
        """Обновляет состояние кнопок табов.

        Args:
            active_tab: Активный таб ("document", "designer", "preview").
        """
        for tab_name, btn in self._mode_tab_buttons.items():
            if tab_name == active_tab:
                btn.config(relief=tk.SUNKEN, bg=_theme_color("accent"))
            else:
                btn.config(relief=tk.RAISED, bg=_theme_color("bg"))

    def _get_current_document(self) -> Optional[Any]:
        """Возвращает текущий документ.

        Returns:
            Текущий документ или None.
        """
        return self._current_document

    def _show_structured_renderer(self, document: StructuredFormDocument) -> None:
        """Показывает StructuredFormRenderer и рендерит документ.

        Args:
            document: StructuredFormDocument для рендеринга.
        """
        if self._tk_frame is None:
            return

        self._placeholder_visible = False

        # Create structured renderer if needed using RendererFactory
        if self._current_renderer is None or not self._current_renderer.can_handle(
            DocumentMode.STRUCTURED_FORM
        ):
            # Safely get mode_manager from controller
            mode_manager = None
            if self._controller is not None and hasattr(self._controller, "mode_manager"):
                mode_manager = self._controller.mode_manager

            self._current_renderer = self._renderer_factory.create(
                mode=DocumentMode.STRUCTURED_FORM,
                parent=self._tk_frame,
                controller=self._controller,
                command_stack=self._command_stack,
                mode_manager=mode_manager,
            )

        # Hide other renderers (via placeholder visibility)
        if self._tk_placeholder_frame is not None:
            self._tk_placeholder_frame.pack_forget()

        # Show structured renderer
        if self._current_renderer is not None:
            self._current_renderer.render(document)

        # Update document ID
        self._current_document_id = document.form_id

    def _render_free_form_document(self, document: DocumentProtocol) -> None:
        """Рендерит документ в FreeFormRenderer.

        Args:
            document: Документ для рендеринга.
        """
        if self._current_renderer is None:
            return

        try:
            content = document.get_content()
            cpi = document.get_cpi()
        except AttributeError:
            # Fallback for simple objects
            content = getattr(document, "content", "")
            cpi = getattr(document, "cpi", 10)

        free_form_doc = FreeFormDocument(content=content, cpi=cpi)
        self._current_renderer.render(free_form_doc)

        # Update ruler CPI (backward compat)
        if self._ruler is not None:
            self._ruler.set_cpi(cpi)

        # Update navigator
        lines = content.count("\n") + 1 if content else 1
        if self._navigator is not None:
            self._navigator.set_total_lines(lines)
            self._navigator.set_position(1, 1)

    def _render_structured_document(self, document: DocumentProtocol) -> None:
        """Рендерит документ в StructuredFormRenderer.

        Args:
            document: Документ для рендеринга.
        """
        if isinstance(document, StructuredFormDocument):
            self._show_structured_renderer(document)
        else:
            # Fallback: create StructuredFormDocument from simple data
            structured_doc = StructuredFormDocument(
                form_id=getattr(document, "id", "unknown"),
                pages=[],
            )
            self._show_structured_renderer(structured_doc)

    def clear_document(self) -> None:
        """Очищает текущий документ.

        Сбрасывает document_id и возвращается к placeholder.
        Вызывается при закрытии документа или переключении вкладок.

        Security:
            НЕ выполняет wipe sensitive данных — для этого
            используйте wipe_sensitive_data().

        Example:
            >>> doc_view.clear_document()
            >>> # Показывает placeholder "No document open"
        """
        self._current_document = None
        self._current_document_id = None
        self._current_mode = DocumentMode.FREE_FORM

        # Clear renderers
        if self._free_form_renderer is not None:
            self._free_form_renderer.set_text("")

        # Clear command history
        self._command_stack.clear()

        # Show placeholder
        self.show_placeholder(DEFAULT_PLACEHOLDER_MESSAGE)

    def hide_content(self) -> None:
        """Скрывает содержимое редактора (session lock). Делегирует рендереру.

        Устанавливает флаг скрытия и вызывает hide_content()
        на текущем рендерере.
        """
        self._content_hidden = True
        if self._current_renderer is not None:
            self._current_renderer.hide_content()
        if self._tk_message_label is not None:
            try:
                self._hidden_content_backup = self._tk_message_label.cget("text")
            except tk.TclError:
                self._hidden_content_backup = DEFAULT_PLACEHOLDER_MESSAGE
        else:
            self._hidden_content_backup = DEFAULT_PLACEHOLDER_MESSAGE

    def restore_content(self) -> None:
        """Восстанавливает содержимое редактора (session unlock).

        Сбрасывает флаг скрытия и вызывает restore_content()
        на текущем рендерере.
        """
        self._content_hidden = False
        self._hidden_content_backup = None
        if self._current_renderer is not None:
            self._current_renderer.restore_content()

    def _clear_internal_references(self) -> None:
        """Очищает внутренние ссылки на данные документа.

        Security: используется wipe_sensitive_data.
        """
        self._current_document = None
        self._current_document_id = None
        self._hidden_content_backup = None

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные из редактора и внутренних ссылок.

        Делегирует очистку текущему рендереру и очищает
        внутренние ссылки на документ.
        """
        self._clear_internal_references()
        if self._current_renderer is not None:
            self._current_renderer.wipe_sensitive_data()
        self.show_placeholder(DEFAULT_PLACEHOLDER_MESSAGE)

    # =====================================================================
    # UNDO/REDO METHODS
    # =====================================================================

    def execute_command(self, cmd: Command) -> None:
        """Выполняет команду через Controller (Вариант B слоения).

        Проксирует вызов в controller.execute_command() если доступен,
        иначе выполняет напрямую через внутренний CommandStack.

        Args:
            cmd: Команда для выполнения.

        Example:
            >>> doc_view.execute_command(InsertTextCommand(widget, "Hello", "1.0"))
        """
        if self._controller is not None and hasattr(self._controller, "execute_command"):
            self._controller.execute_command(cmd)
        else:
            self._command_stack.execute(cmd)

    def undo(self) -> None:
        """Отменяет последнее действие.

        Вызывает controller.on_undo() если доступен, иначе
        напрямую CommandStack.undo().

        Example:
            >>> doc_view.undo()
        """
        if self._controller is not None and hasattr(self._controller, "on_undo"):
            self._controller.on_undo()
        elif self._command_stack.can_undo():
            self._command_stack.undo()

    def redo(self) -> None:
        """Повторяет отменённое действие.

        Вызывает controller.on_redo() если доступен, иначе
        напрямую CommandStack.redo().

        Example:
            >>> doc_view.redo()
        """
        if self._controller is not None and hasattr(self._controller, "on_redo"):
            self._controller.on_redo()
        elif self._command_stack.can_redo():
            self._command_stack.redo()

    def can_undo(self) -> bool:
        """Проверяет, есть ли команды для отмены.

        Returns:
            True если есть команды для отмены.
        """
        return self._command_stack.can_undo()

    def can_redo(self) -> bool:
        """Проверяет, есть ли команды для повтора.

        Returns:
            True если есть команды для повтора.
        """
        return self._command_stack.can_redo()

    def get_undo_description(self) -> Optional[str]:
        """Возвращает описание команды для отмены.

        Returns:
            Описание команды или None если undo недоступен.

        Example:
            >>> desc = doc_view.get_undo_description()
            >>> # "Insert 'Hello' at 1.0"
        """
        return self._command_stack.get_undo_description()

    def get_redo_description(self) -> Optional[str]:
        """Возвращает описание команды для повтора.

        Returns:
            Описание команды или None если redo недоступен.
        """
        return self._command_stack.get_redo_description()

    # =====================================================================
    # BARCODE / QR INSERTION (BarcodeViewProtocol)
    # =====================================================================

    def insert_barcode_at_cursor(
        self,
        barcode_type: str,
        data: str,
        mode: str,
        settings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Вставляет штрих-код в позицию курсора через текущий рендерер.

        Проксирует вызов к текущему рендереру, если он поддерживает метод
        insert_barcode_at_cursor. Иначе возвращает False.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные для кодирования.
            mode: Режим ("hardware"/"software").
            settings: Дополнительные настройки.

        Returns:
            True если вставка успешна.
        """
        renderer: Any = self._current_renderer
        if renderer is not None and hasattr(renderer, "insert_barcode_at_cursor"):
            result: Any = renderer.insert_barcode_at_cursor(
                barcode_type=barcode_type,
                data=data,
                mode=mode,
                settings=settings,
            )
            return bool(result)
        return False

    def insert_qr_at_cursor(
        self,
        data: str,
        settings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Вставляет QR-код в позицию курсора через текущий рендерер.

        Проксирует вызов к текущему рендереру, если он поддерживает метод
        insert_qr_at_cursor. Иначе возвращает False.

        Args:
            data: Данные для кодирования.
            settings: Дополнительные настройки.

        Returns:
            True если вставка успешна.
        """
        renderer: Any = self._current_renderer
        if renderer is not None and hasattr(renderer, "insert_qr_at_cursor"):
            result: Any = renderer.insert_qr_at_cursor(
                data=data,
                settings=settings,
            )
            return bool(result)
        return False

    def get_cursor_position(self) -> tuple[int, int]:
        """Возвращает текущую позицию курсора.

        Проксирует вызов к текущему рендереру, если он поддерживает метод
        get_cursor_position. Иначе возвращает (1, 1).

        Returns:
            Кортеж (line, column) в 1-based координатах.
        """
        renderer: Any = self._current_renderer
        if renderer is not None and hasattr(renderer, "get_cursor_position"):
            result: Any = renderer.get_cursor_position()
            return cast(tuple[int, int], result)
        return (1, 1)

    # =====================================================================
    # MENU BAR CALLBACKS
    # =====================================================================

    def on_edit_undo(self) -> None:
        """Callback для Edit → Undo.

        Example:
            >>> menu.add_command(label="Undo", command=doc_view.on_edit_undo)
        """
        self.undo()

    def on_edit_redo(self) -> None:
        """Callback для Edit → Redo.

        Example:
            >>> menu.add_command(label="Redo", command=doc_view.on_edit_redo)
        """
        self.redo()

    def on_edit_cut(self) -> None:
        """Callback для Edit → Cut.

        Вырезает выделенный текст в буфер обмена через ClipboardService.
        """
        if self._free_form_renderer is not None and self._current_mode == DocumentMode.FREE_FORM:
            text = self._free_form_renderer.cut_selection()
            if text:
                # Конвертируем document_id в UUID если возможно
                from uuid import UUID

                doc_uuid: UUID | None = None
                if self._current_document_id:
                    try:
                        doc_uuid = UUID(self._current_document_id)
                    except ValueError:
                        pass
                self._clipboard_service.cut_text(
                    text,
                    source_document_id=doc_uuid,
                )

    def on_edit_copy(self) -> None:
        """Callback для Edit → Copy.

        Копирует выделенный текст в буфер обмена через ClipboardService.
        """
        if self._free_form_renderer is not None and self._current_mode == DocumentMode.FREE_FORM:
            text = self._free_form_renderer.copy_selection()
            if text:
                # Конвертируем document_id в UUID если возможно
                from uuid import UUID

                doc_uuid: UUID | None = None
                if self._current_document_id:
                    try:
                        doc_uuid = UUID(self._current_document_id)
                    except ValueError:
                        pass
                self._clipboard_service.copy_text(
                    text,
                    source_document_id=doc_uuid,
                )

    def on_edit_paste(self) -> None:
        """Callback для Edit → Paste.

        Вставляет текст из буфера обмена через ClipboardService.
        """
        if self._free_form_renderer is not None and self._current_mode == DocumentMode.FREE_FORM:
            text = self._clipboard_service.paste_text()
            if text:
                self._free_form_renderer.paste_at_cursor(text)

    def on_edit_select_all(self) -> None:
        """Callback для Edit → Select All."""
        if self._free_form_renderer is not None and self._current_mode == DocumentMode.FREE_FORM:
            self._free_form_renderer.select_all()

    # =====================================================================
    # COMPONENT CALLBACK BINDINGS
    # =====================================================================

    def _on_cpi_changed(self, cpi: int) -> None:
        """Обработчик изменения CPI из FormatToolbar.

        Args:
            cpi: Новое значение CPI.
        """
        # Forward to current renderer if it supports CPI
        if (
            self._current_renderer is not None
            and self._current_mode == DocumentMode.FREE_FORM
            and hasattr(self._current_renderer, "apply_cpi")
        ):
            self._current_renderer.apply_cpi(cpi)

        if self._ruler is not None:
            self._ruler.set_cpi(cpi)

        # Propagate to controller
        if self._controller is not None:
            self._controller.dispatch("cpi_changed", cpi=cpi)

    def _on_format_toggled(self, format_type: str, active: bool) -> None:
        """Обработчик переключения формата из FormatToolbar.

        Args:
            format_type: Тип форматирования (bold, italic, etc.).
            active: True если формат активирован.
        """
        if self._current_renderer is None:
            return

        if (
            self._current_mode == DocumentMode.FREE_FORM
            and hasattr(self._current_renderer, "get_selection")
            and hasattr(self._current_renderer, "apply_format")
            and hasattr(self._current_renderer, "remove_format")
            and hasattr(self._current_renderer, "get_cursor_position")
        ):
            # Get current selection or cursor position
            selection = self._current_renderer.get_selection()

            if selection is not None:
                start, end = selection
                if active:
                    self._current_renderer.apply_format(format_type, start, end)
                else:
                    self._current_renderer.remove_format(format_type, start, end)
            else:
                # No selection - apply to word under cursor (simplified)
                line, col = self._current_renderer.get_cursor_position()
                start = f"{line}.{col - 1}"
                end = f"{line}.{col}"
                if active:
                    self._current_renderer.apply_format(format_type, start, end)

        # Propagate to controller
        if self._controller is not None:
            self._controller.dispatch(
                "format_toggled",
                format_type=format_type,
                active=active,
            )

    def _on_text_changed(self, text: str) -> None:
        """Обработчик изменения текста из FreeFormRenderer.

        Args:
            text: Новое текстовое содержимое.
        """
        # Update navigator line count
        lines = text.count("\n") + 1 if text else 1
        if self._navigator is not None:
            self._navigator.set_total_lines(lines)

        # Update codepage status
        if self._codepage_status is not None:
            self._codepage_status.validate_text(text)

        # Propagate to controller
        if self._controller is not None:
            self._controller.dispatch("text_changed", text=text)
            # Notify tab bar that document is modified
            if self._current_document_id is not None:
                self._controller.dispatch(
                    "document_modified",
                    document_id=self._current_document_id,
                    modified=True,
                )

    def _on_field_changed(self, field_id: str, value: Any) -> None:
        """Обработчик изменения поля из StructuredFormRenderer.

        Args:
            field_id: Идентификатор изменённого поля.
            value: Новое значение поля.
        """
        # Propagate to controller
        if self._controller is not None:
            self._controller.dispatch("field_changed", field_id=field_id, value=value)
            # Notify tab bar that document is modified
            if self._current_document_id is not None:
                self._controller.dispatch(
                    "document_modified",
                    document_id=self._current_document_id,
                    modified=True,
                )

    def _on_cursor_moved(self, line: int, column: int) -> None:
        """Обработчик движения курсора из FreeFormRenderer.

        Args:
            line: Номер строки (1-based).
            column: Номер колонки (1-based).
        """
        # Update navigator position
        if self._navigator is not None:
            self._navigator.set_position(line, column)

            # Обратная связь double-height: подсвечиваем shadow row
            if (
                self._current_renderer is not None
                and self._current_mode == DocumentMode.FREE_FORM
                and hasattr(self._current_renderer, "is_line_double_height")
            ):
                is_dh = self._current_renderer.is_line_double_height(line)
                self._navigator.set_double_height_indicator(is_dh)

        # Propagate to controller
        if self._controller is not None:
            self._controller.dispatch(
                "cursor_moved",
                line=line,
                column=column,
            )

    def _on_navigator_goto_line(self, line: int) -> None:
        """Обработчик перехода к строке из Navigator.

        Args:
            line: Номер строки для перехода.
        """
        if (
            self._current_renderer is not None
            and self._current_mode == DocumentMode.FREE_FORM
            and hasattr(self._current_renderer, "set_cursor_position")
        ):
            self._current_renderer.set_cursor_position(line, 1)

    def _on_navigator_goto_start(self) -> None:
        """Обработчик перехода в начало документа."""
        if (
            self._current_renderer is not None
            and self._current_mode == DocumentMode.FREE_FORM
            and hasattr(self._current_renderer, "set_cursor_position")
        ):
            self._current_renderer.set_cursor_position(1, 1)

    def _on_navigator_goto_end(self) -> None:
        """Обработчик перехода в конец документа."""
        if (
            self._current_renderer is not None
            and self._current_mode == DocumentMode.FREE_FORM
            and hasattr(self._current_renderer, "get_text")
            and hasattr(self._current_renderer, "set_cursor_position")
        ):
            # Go to end of text
            text = self._current_renderer.get_text()
            lines = text.count("\n") + 1 if text else 1
            last_line_len = len(text.split("\n")[-1]) if text else 1
            self._current_renderer.set_cursor_position(lines, max(1, last_line_len))

    def _on_ruler_clicked(self, position: int) -> None:
        """Обработчик клика по линейке.

        Args:
            position: Позиция в символах.
        """
        if (
            self._current_renderer is not None
            and self._current_mode == DocumentMode.FREE_FORM
            and hasattr(self._current_renderer, "get_cursor_position")
            and hasattr(self._current_renderer, "set_cursor_position")
        ):
            line, _ = self._current_renderer.get_cursor_position()
            self._current_renderer.set_cursor_position(line, position + 1)

    # =====================================================================
    # TK WIDGET CREATION
    # =====================================================================

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет с компонентами Phase 2.

        Layout:
            ┌───────────────────────────────┐
            │ [Ruler]                       │
            ├───────────────────────────────┤
            │ [FormatToolbar]               │
            ├───────────────────────────────┤
            │                               │
            │ [FreeFormRenderer]            │
            │                               │
            ├───────────────────────────────┤
            │ [Navigator]                   │
            └───────────────────────────────┘

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame DocumentView.
        """
        # Root frame
        self._tk_frame = tk.Frame(parent, bg=_theme_color("bg"))

        # Placeholder frame (shown when no document)
        self._tk_placeholder_frame = tk.Frame(
            self._tk_frame,
            bg=_theme_color("bg"),
        )

        # Icon label (large document emoji)
        self._tk_icon_label = tk.Label(
            self._tk_placeholder_frame,
            text=PLACEHOLDER_ICON,
            font=("TkDefaultFont", PLACEHOLDER_ICON_SIZE),
            bg=_theme_color("bg"),
            fg=_theme_color("fg"),
        )
        self._tk_icon_label.pack(pady=(PADDING_LARGE * 4, PADDING_NORMAL))

        # Message label
        self._tk_message_label = tk.Label(
            self._tk_placeholder_frame,
            text=DEFAULT_PLACEHOLDER_MESSAGE,
            font=("TkDefaultFont", 12),
            bg=_theme_color("bg"),
            fg=_theme_color("fg"),
        )
        self._tk_message_label.pack(pady=PADDING_NORMAL)

        # Content frame (shown when document is open)
        self._tk_content_frame = tk.Frame(self._tk_frame, bg=_theme_color("bg"))

        # Create Phase 2 components (mode-agnostic)
        self._create_paper_toolbar(self._tk_content_frame)
        self._create_ruler(self._tk_content_frame)
        self._create_empty_toolbar_frame(self._tk_content_frame)
        self._create_empty_renderer_frame(self._tk_content_frame)
        self._create_field_palette_frame(self._tk_content_frame)
        self._create_navigator(self._tk_content_frame)
        self._create_codepage_status(self._tk_content_frame)

        # Create Phase 5 mode tabs
        self._create_mode_tabs()

        # Layout content frame components
        self._layout_content_frame()

        # Initially show placeholder
        self._tk_placeholder_frame.pack(fill="both", expand=True)

        return self._tk_frame

    def _create_empty_toolbar_frame(self, parent: tk.Frame) -> None:
        """Создаёт пустой фрейм для toolbar (renderer-based creation).

        Args:
            parent: Родительский фрейм.
        """
        self._tk_toolbar_frame = tk.Frame(parent, height=35, bg=_theme_color("bg"))

    def _create_empty_renderer_frame(self, parent: tk.Frame) -> None:
        """Создаёт пустой фрейм для renderer (renderer-based creation).

        Args:
            parent: Родительский фрейм.
        """
        self._tk_renderer_frame = tk.Frame(parent, bg=_theme_color("bg"))

    def _create_paper_toolbar(self, parent: tk.Frame) -> None:
        """Создаёт PaperToolbar компонент.

        Args:
            parent: Родительский фрейм.
        """
        self._tk_paper_toolbar_frame = tk.Frame(parent, height=30, bg=_theme_color("bg"))
        self._paper_toolbar = PaperToolbar(
            widget_id="paper_toolbar",
            controller=self._controller,
        )
        toolbar_widget = self._paper_toolbar.mount(self._tk_paper_toolbar_frame)
        toolbar_widget.pack(fill=tk.BOTH, expand=True)

    def _create_ruler(self, parent: tk.Frame) -> None:
        """Создаёт Ruler компонент.

        Args:
            parent: Родительский фрейм.
        """
        self._tk_ruler_frame = tk.Frame(parent, height=25, bg=_theme_color("bg"))
        self._ruler = Ruler(
            widget_id="doc_ruler",
            controller=self._controller,
            on_click=self._on_ruler_clicked,
            initial_cpi=10,
            initial_width_chars=80,
        )
        ruler_widget = self._ruler.mount(self._tk_ruler_frame)
        ruler_widget.pack(fill=tk.BOTH, expand=True)

    def _create_format_toolbar(self, parent: tk.Frame) -> None:
        """Создаёт FormatToolbar компонент (backward compatibility).

        .. deprecated::
            Используйте renderer.create_toolbar() через _rebuild_ui().

        Args:
            parent: Родительский фрейм.
        """
        self._tk_toolbar_frame = tk.Frame(parent, height=35, bg=_theme_color("bg"))
        self._format_toolbar = FormatToolbar(
            widget_id="format_toolbar",
            on_cpi_change=self._on_cpi_changed,
            on_format_toggle=self._on_format_toggled,
        )
        toolbar_widget = self._format_toolbar.mount(self._tk_toolbar_frame)
        toolbar_widget.pack(fill=tk.BOTH, expand=True)

    def _create_free_form_renderer(self, parent: tk.Frame) -> None:
        """Создаёт FreeFormRenderer компонент (Phase 4 Strategy Pattern).

        .. deprecated::
            Используйте renderer.create_editor() через _rebuild_ui().

        Args:
            parent: Родительский фрейм.
        """
        self._tk_renderer_frame = tk.Frame(parent, bg=_theme_color("bg"))

        # Use RendererFactory for Strategy Pattern
        self._current_renderer = self._renderer_factory.create(
            mode=DocumentMode.FREE_FORM,
            parent=self._tk_renderer_frame,
            controller=self._controller,
            command_stack=self._command_stack,
            widget_id="free_form_renderer",
        )
        # Note: Renderer is shown via show() method when needed

        # Set up callbacks (if renderer supports them)
        if hasattr(self._current_renderer, "set_on_text_change_callback"):
            self._current_renderer.set_on_text_change_callback(self._on_text_changed)
        if hasattr(self._current_renderer, "set_on_cursor_move_callback"):
            self._current_renderer.set_on_cursor_move_callback(self._on_cursor_moved)

    def _create_field_palette_frame(self, parent: tk.Frame) -> None:
        """Создаёт фрейм для палитры полей формы.

        Args:
            parent: Родительский фрейм.
        """
        self._tk_field_palette_frame = tk.Frame(parent, width=180, bg=_theme_color("bg"))

    def _create_navigator(self, parent: tk.Frame) -> None:
        """Создаёт Navigator компонент.

        Args:
            parent: Родительский фрейм.
        """
        self._tk_navigator_frame = tk.Frame(parent, height=28, bg=_theme_color("bg"))
        self._navigator = Navigator(
            widget_id="doc_navigator",
            controller=self._controller,
            on_goto_line=self._on_navigator_goto_line,
            on_goto_start=self._on_navigator_goto_start,
            on_goto_end=self._on_navigator_goto_end,
            initial_line=1,
            initial_column=1,
            initial_total_lines=1,
        )
        if (
            self._current_renderer is not None
            and hasattr(self._current_renderer, "highlight_line")
            and hasattr(self._navigator, "set_on_highlight_line_callback")
        ):
            self._navigator.set_on_highlight_line_callback(self._current_renderer.highlight_line)
        navigator_widget = self._navigator.mount(self._tk_navigator_frame)
        navigator_widget.pack(fill=tk.BOTH, expand=True)

    def _create_codepage_status(self, parent: tk.Frame) -> None:
        """Создаёт CodepageStatusWidget.

        Args:
            parent: Родительский фрейм.
        """
        self._tk_codepage_status_frame = tk.Frame(parent, height=24, bg=_theme_color("bg"))
        self._codepage_status = CodepageStatusWidget(
            widget_id="codepage_status",
            controller=self._controller,
        )
        status_widget = self._codepage_status.mount(self._tk_codepage_status_frame)
        status_widget.pack(fill=tk.X, expand=False)

    def _layout_content_frame(self) -> None:
        """Располагает компоненты в content frame."""
        if self._tk_paper_toolbar_frame is not None:
            self._tk_paper_toolbar_frame.pack(fill=tk.X, side=tk.TOP)
            self._tk_paper_toolbar_frame.pack_propagate(False)

        if self._tk_ruler_frame is not None:
            self._tk_ruler_frame.pack(fill=tk.X, side=tk.TOP)
            self._tk_ruler_frame.pack_propagate(False)

        if self._tk_toolbar_frame is not None:
            self._tk_toolbar_frame.pack(fill=tk.X, side=tk.TOP)
            self._tk_toolbar_frame.pack_propagate(False)

        if self._tk_renderer_frame is not None:
            self._tk_renderer_frame.pack(fill=tk.BOTH, expand=True, side=tk.TOP)

        if self._tk_field_palette_frame is not None:
            self._tk_field_palette_frame.pack(fill=tk.Y, side=tk.RIGHT)
            self._tk_field_palette_frame.pack_propagate(False)

        if self._tk_codepage_status_frame is not None:
            self._tk_codepage_status_frame.pack(fill=tk.X, side=tk.BOTTOM)
            self._tk_codepage_status_frame.pack_propagate(False)

        if self._tk_navigator_frame is not None:
            self._tk_navigator_frame.pack(fill=tk.X, side=tk.BOTTOM)
            self._tk_navigator_frame.pack_propagate(False)

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Tkinter виджета."""
        if self._tk_frame is not None:
            # Intercept built-in tk.Text <<Undo>> / <<Redo>> events
            self._tk_frame.bind("<<Undo>>", lambda e: (self.on_edit_undo(), "break")[1])  # type: ignore[func-returns-value]
            self._tk_frame.bind("<<Redo>>", lambda e: (self.on_edit_redo(), "break")[1])  # type: ignore[func-returns-value]
            # Keyboard shortcuts for undo/redo
            self._tk_frame.bind("<Control-z>", lambda e: self.on_edit_undo())
            self._tk_frame.bind("<Control-y>", lambda e: self.on_edit_redo())
            self._tk_frame.bind("<Control-Shift-Z>", lambda e: self.on_edit_redo())

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием.

        Security:
            Очищает все ссылки на виджеты и sensitive данные.
        """
        # Cleanup components
        if self._paper_toolbar is not None:
            self._paper_toolbar.unmount()
            self._paper_toolbar = None

        if self._ruler is not None:
            self._ruler.unmount()
            self._ruler = None

        if self._format_toolbar is not None:
            self._format_toolbar.unmount()
            self._format_toolbar = None

        if self._current_renderer is not None:
            self._current_renderer.unmount()
            self._current_renderer = None

        if self._navigator is not None:
            self._navigator.unmount()
            self._navigator = None

        if self._codepage_status is not None:
            self._codepage_status.unmount()
            self._codepage_status = None

        if self._designer_tab is not None:
            self._designer_tab.unmount()
            self._designer_tab = None

        # Clear widget references
        self._tk_icon_label = None
        self._tk_message_label = None
        self._tk_placeholder_frame = None
        self._tk_content_frame = None
        self._tk_paper_toolbar_frame = None
        self._tk_ruler_frame = None
        self._tk_toolbar_frame = None
        self._tk_renderer_frame = None
        self._tk_navigator_frame = None
        self._tk_field_palette_frame = None
        self._tk_codepage_status_frame = None
        self._tk_frame = None

        # Clear state
        self._current_document = None
        self._current_document_id = None
        self._hidden_content_backup = None
        self._saved_state.clear()

        # Clear command stack
        self._command_stack.clear()

    def _sanitize_document_id(self, document_id: str) -> str:
        """Санитизирует document_id для security.

        Args:
            document_id: Исходный ID документа.

        Returns:
            Санитизированный ID (max 100 chars).

        Raises:
            ValueError: Если document_id пустой или None.
        """
        if not document_id:
            raise ValueError("document_id cannot be empty")

        # Truncate to max length
        sanitized = document_id[:MAX_DOCUMENT_ID_LENGTH]

        # Basic sanitization: remove control characters
        # Note: Keep unicode for international document IDs
        sanitized = "".join(char for char in sanitized if char.isprintable())

        return sanitized

    # =====================================================================
    # NAVIGATION METHODS (Phase 4)
    # =====================================================================

    def goto_page(self, page: int, line: Optional[int] = None) -> None:
        """Переходит к указанной странице и строке.

        Args:
            page: Номер страницы (1-based).
            line: Номер строки внутри страницы (1-based, опционально).

        Example:
            >>> doc_view.goto_page(5)  # Переход к странице 5
            >>> doc_view.goto_page(3, 10)  # Переход к странице 3, строке 10
        """
        if self._current_renderer is None:
            return

        # Calculate actual line in document
        lines_per_page = 66  # Standard lines per page
        target_line = (page - 1) * lines_per_page + 1

        if line is not None and line > 0:
            target_line += line - 1

        # Navigate to line
        if self._current_mode == DocumentMode.FREE_FORM:
            if hasattr(self._current_renderer, "set_cursor_position"):
                self._current_renderer.set_cursor_position(target_line, 1)
        elif self._current_mode == DocumentMode.STRUCTURED_FORM:
            # For structured form, use page navigation
            if hasattr(self._current_renderer, "goto_page"):
                self._current_renderer.goto_page(page, line)

        # Update navigator
        if self._navigator is not None:
            self._navigator.set_position(target_line, 1)

    def get_total_pages(self) -> int:
        """Возвращает общее количество страниц в документе.

        Returns:
            Общее количество страниц (минимум 1).

        Example:
            >>> total = doc_view.get_total_pages()
            >>> print(f"Document has {total} pages")
        """
        if self._current_renderer is None:
            return 1

        lines_per_page = 66  # Standard lines per page

        if self._current_mode == DocumentMode.FREE_FORM:
            if hasattr(self._current_renderer, "get_text"):
                text = self._current_renderer.get_text()
                total_lines = text.count("\n") + 1 if text else 1
                return max(1, (total_lines + lines_per_page - 1) // lines_per_page)
        elif self._current_mode == DocumentMode.STRUCTURED_FORM:
            if hasattr(self._current_renderer, "get_total_pages"):
                return cast(int, self._current_renderer.get_total_pages())

        return 1

    def get_current_page(self) -> int:
        """Возвращает текущий номер страницы.

        Returns:
            Текущая страница (1-based).

        Example:
            >>> current = doc_view.get_current_page()
            >>> print(f"Currently on page {current}")
        """
        if self._current_renderer is None:
            return 1

        lines_per_page = 66  # Standard lines per page

        if self._current_mode == DocumentMode.FREE_FORM:
            if hasattr(self._current_renderer, "get_cursor_position"):
                line, _ = self._current_renderer.get_cursor_position()
                return max(1, ((cast(int, line) - 1) // lines_per_page) + 1)

        return 1

    def get_form_fields(self) -> dict[str, Any]:
        """Возвращает словарь полей формы (для STRUCTURED_FORM).

        Returns:
            Словарь {field_id: FormField} или пустой словарь.

        Example:
            >>> fields = doc_view.get_form_fields()
            >>> for field_id, field in fields.items():
            ...     print(f"{field_id}: {field.get_value()}")
        """
        if self._current_mode == DocumentMode.STRUCTURED_FORM:
            if self._current_renderer is not None and hasattr(
                self._current_renderer, "get_form_fields"
            ):
                return cast(dict[str, Any], self._current_renderer.get_form_fields())
        return {}

    def set_form_field_value(self, field_id: str, value: Any) -> bool:
        """Устанавливает значение поля формы.

        Args:
            field_id: Идентификатор поля.
            value: Новое значение.

        Returns:
            True если поле найдено и значение установлено.

        Example:
            >>> success = doc_view.set_form_field_value("customer_name", "ООО Ромашка")
            >>> if not success:
            ...     print("Поле not found")
        """
        if self._current_mode != DocumentMode.STRUCTURED_FORM:
            return False

        if self._current_renderer is not None and hasattr(
            self._current_renderer, "get_form_fields"
        ):
            fields = cast(dict[str, Any], self._current_renderer.get_form_fields())
            if field_id in fields:
                field = fields[field_id]
                if hasattr(field, "set_value"):
                    field.set_value(value)
                    return True
        return False

    def apply_prefill_values(self, values: dict[str, Any]) -> dict[str, bool]:
        """Применяет значения автозаполнения к полям формы.

        Args:
            values: Словарь {field_id: value} для заполнения.

        Returns:
            Словарь {field_id: success} с результатами.

        Example:
            >>> results = doc_view.apply_prefill_values({
            ...     "customer_name": "ООО Ромашка",
            ...     "inn": "1234567890",
            ... })
            >>> for field_id, ok in results.items():
            ...     status = "✓" if ok else "✗"
            ...     print(f"{field_id}: {status}")
        """
        results: dict[str, bool] = {}
        for field_id, value in values.items():
            results[field_id] = self.set_form_field_value(field_id, value)
        return results


# Module exports
__all__: list[str] = [
    "DocumentView",
    "DocumentProtocol",
    "PLACEHOLDER_ICON",
    "DEFAULT_PLACEHOLDER_MESSAGE",
    "MAX_DOCUMENT_ID_LENGTH",
]
