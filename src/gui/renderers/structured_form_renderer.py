"""StructuredFormRenderer для FX Text Processor 3.

Реализует WYSIWYG редактор для структурированных форм с multi-page support.
- Multi-page с разными paper types
- Sidebar с thumbnails страниц
- Header/Footer global/per-page
- Command pattern для undo/redo
- Drag-drop reorder страниц

Example:
    >>> renderer = StructuredFormRenderer(
    ...     parent=root,
    ...     controller=my_controller,
    ...     mode_manager=mode_manager,
    ... )
    >>> renderer.mount(parent_frame)
    >>> doc = StructuredFormDocument(form_id="test", pages=[...])
    >>> renderer.render(doc)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Final, Optional

from src.documents.constructor.form_constructor import ValidationReport
from src.documents.constructor.form_status import FormStatus, FormStatusManager
from src.documents.types.document_type import DocumentMode
from src.documents.types.type_schema import FieldDefinition, FieldType
from src.gui.components.base.widget import BaseWidget
from src.gui.components.factories.form_field_factory import create_form_field
from src.gui.core.commands.command import Command
from src.gui.core.commands.command_stack import CommandStack
from src.gui.core.error_handler import GUIErrorHandler
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol, FormFieldProtocol
from src.gui.dialogs.reject_dialog import RejectDialog
from src.gui.dialogs.role_switch_dialog import RoleSwitchDialog
from src.gui.modes.structured_form.widgets import (
    AutocompleteEntry,
    DateEntry,
    NumberEntry,
    TableField,
    create_inline_widget,
)
from src.gui.modes.structured_form.widgets.base_field import BaseField
from src.gui.renderers.form_canvas import FormCanvas, FormFieldWidget
from src.gui.renderers.protocols import implements
from src.gui.security.mode_manager import ModeManager
from src.gui.services.autocomplete_service import AutocompleteServiceGui
from src.gui.workflow.workflow_toolbar import WorkflowToolbar
from src.model.enums import FontFamily
from src.services.paper_format_service import PaperFormatService, PaperProfile

logger: Final = logging.getLogger(__name__)

# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class HeaderFooterConfig:
    """Конфигурация колонтитула.

    Attributes:
        left_text: Текст слева.
        center_text: Текст по центру.
        right_text: Текст справа.
        font_family: Шрифт.
        cpi: Characters per inch.

    Note:
        Placeholders: {page}, {total_pages}, {date}, {time}, {document_index}
    """

    left_text: str = ""
    center_text: str = ""
    right_text: str = ""
    font_family: FontFamily = FontFamily.ROMAN
    cpi: int = 10

    def render(self, page_number: int, total_pages: int, document_index: str) -> str:
        """Рендерит текст колонтитула с подстановкой placeholders.

        Args:
            page_number: Номер текущей страницы.
            total_pages: Общее количество страниц.
            document_index: Индекс документа.

        Returns:
            Отрендеренный текст.
        """
        now = datetime.now()
        placeholders = {
            "{page}": str(page_number),
            "{total_pages}": str(total_pages),
            "{date}": now.strftime("%d.%m.%Y"),
            "{time}": now.strftime("%H:%M"),
            "{document_index}": document_index,
        }

        result = f"{self.left_text} {self.center_text} {self.right_text}"
        for placeholder, value in placeholders.items():
            result = result.replace(placeholder, value)
        return result


@dataclass
class PageData:
    """Данные страницы формы.

    Attributes:
        profile: Профиль бумаги.
        fields: Список определений полей на странице.
        header: Конфигурация верхнего колонтитула.
        footer: Конфигурация нижнего колонтитула.
    """

    profile: PaperProfile
    fields: list[FieldDefinition] = field(default_factory=list)
    header: Optional[HeaderFooterConfig] = None
    footer: Optional[HeaderFooterConfig] = None


@dataclass
class FormPage:
    """Страница формы.

    Attributes:
        index: Индекс страницы (0-based).
        profile: Профиль бумаги.
        fields: Список виджетов полей.
        canvas: Canvas для отрисовки.
        header: Конфигурация верхнего колонтитула.
        footer: Конфигурация нижнего колонтитула.
        inline_frame: Фрейм для inline-режима (альтернатива canvas).
        inline_field_defs: Определения полей для inline-режима.
    """

    index: int
    profile: PaperProfile
    fields: list[FormFieldWidget] = field(default_factory=list)
    canvas: Optional[FormCanvas] = None
    header: Optional[HeaderFooterConfig] = None
    footer: Optional[HeaderFooterConfig] = None
    inline_frame: Optional[tk.Frame] = None
    inline_field_defs: list[FieldDefinition] = field(default_factory=list)


@dataclass
class StructuredFormDocument:
    """Модель документа структурированной формы.

    Attributes:
        form_id: Уникальный идентификатор формы.
        pages: Список страниц.
        status: Статус формы.
        document_index: Индекс документа.
    """

    form_id: str
    pages: list[PageData] = field(default_factory=list)
    status: FormStatus = FormStatus.DRAFT
    document_index: str = ""

    @property
    def id(self) -> str:
        return self.form_id


# =============================================================================
# STRUCTURED FORM RENDERER
# =============================================================================


@implements(Any)
class StructuredFormRenderer(BaseWidget):
    """Renderer для STRUCTURED_FORM с multi-page support.

    Features:
    - Multi-page с разными paper types
    - Sidebar с thumbnails страниц
    - Header/Footer global/per-page
    - Command pattern для undo/redo
    - Drag-drop reorder страниц
    - MFA workflow transitions

    Example:
        >>> renderer = StructuredFormRenderer(
        ...     parent=root,
        ...     controller=controller,
        ...     mode_manager=mode_manager,
        ... )
        >>> renderer.mount(parent)
        >>> renderer.render(document)
    """

    # Constants
    SIDEBAR_WIDTH: Final[int] = 150
    HEADER_HEIGHT: Final[int] = 40
    FOOTER_HEIGHT: Final[int] = 40

    def __init__(
        self,
        parent: tk.Widget,
        controller: Optional[ControllerProtocol] = None,
        mode_manager: Optional[ModeManager] = None,
        workflow_manager: Optional[Any] = None,
        mfa_gate: Optional[Any] = None,
    ) -> None:
        """Инициализация StructuredFormRenderer.

        Args:
            parent: Родительский Tkinter виджет.
            controller: Опциональная ссылка на контроллер.
            mode_manager: ModeManager для MFA workflow.
            workflow_manager: Менеджер workflow для управления видимостью действий.
            mfa_gate: MFAGate для MFA-gated transitions.
        """
        super().__init__(
            widget_id="structured_form_renderer",
            controller=controller,
        )

        self._parent: tk.Widget = parent
        self._mode_manager: Optional[ModeManager] = mode_manager
        self._workflow_manager: Optional[Any] = workflow_manager
        self._mfa_gate: Optional[Any] = mfa_gate

        # Multi-page support
        self._pages: list[FormPage] = []
        self._current_page_index: int = 0

        # Sidebar with thumbnails
        self._page_sidebar: Optional[tk.Frame] = None
        self._sidebar_canvas: Optional[tk.Canvas] = None
        self._sidebar_scrollbar: Optional[tk.Scrollbar] = None
        self._thumbnail_frames: list[Optional[tk.Frame]] = []  # None for not-yet-created
        self._visible_thumbnail_range: tuple[int, int] = (0, 0)
        self._thumbnails_per_viewport: int = 5  # Approximate visible count
        self._thumbnail_scroll_binding: Optional[str] = None
        self._scroll_update_pending: bool = False
        self._scroll_update_after_id: Optional[str] = None

        # Main content area
        self._content_frame: Optional[tk.Frame] = None
        self._current_canvas: Optional[FormCanvas] = None

        # Header/Footer
        self._header_scope: str = "global"  # "global" или "per_page"
        self._footer_scope: str = "global"
        self._global_header: Optional[HeaderFooterConfig] = None
        self._global_footer: Optional[HeaderFooterConfig] = None

        # Workflow
        self._form_status: FormStatus = FormStatus.DRAFT
        self._form_id: Optional[str] = None
        self._document_index: str = ""

        # Command stack for undo/redo
        self._command_stack: CommandStack = CommandStack()

        # Status manager
        self._status_manager: FormStatusManager = FormStatusManager(require_mfa=True)

        # Callbacks
        self._on_page_change_callback: Optional[Callable[[int], None]] = None
        self._on_field_select_callback: Optional[Callable[[Optional[str]], None]] = None
        self._on_field_change_callback: Optional[Callable[[str, Any], None]] = None

        # Error handler
        self._error_handler: GUIErrorHandler = GUIErrorHandler()

        # Autocomplete service for FormField integration
        self._autocomplete_gui: Optional[AutocompleteServiceGui] = None

        # Inline mode support
        self._use_inline_mode: bool = True
        self._inline_frames: list[Optional[tk.Frame]] = []
        self._inline_fields: dict[str, BaseField] = {}  # page_{index}_{field_id} -> BaseField
        self._current_inline_frame: Optional[tk.Frame] = None

        # Tk widgets (initialized in _create_tk_widget)
        self._tk_frame: Optional[tk.Frame] = None
        self._header_frame: Optional[tk.Frame] = None
        self._footer_frame: Optional[tk.Frame] = None
        self._canvas_frame: Optional[tk.Frame] = None

        # Workflow toolbar
        self._workflow_toolbar: Optional[WorkflowToolbar] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame.
        """
        # Main frame with sidebar and content
        self._tk_frame = tk.Frame(parent, bg="#f0f0f0")

        # Left sidebar for page thumbnails
        self._page_sidebar = tk.Frame(
            self._tk_frame,
            width=self.SIDEBAR_WIDTH,
            bg="#e8e8e8",
            relief=tk.RIDGE,
            bd=1,
        )
        self._page_sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=1, pady=1)
        self._page_sidebar.pack_propagate(False)

        # Sidebar header
        sidebar_header = tk.Label(
            self._page_sidebar,
            text="Pages",
            bg="#d0d0d0",
            font=("Arial", 10, "bold"),
        )
        sidebar_header.pack(fill=tk.X, pady=(0, 2))

        # Sidebar canvas for thumbnails with scrollbar
        self._sidebar_canvas = tk.Canvas(
            self._page_sidebar,
            bg="#e8e8e8",
            highlightthickness=0,
        )
        self._sidebar_canvas.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self._sidebar_canvas.bind(
            "<Destroy>",
            lambda _e: self._cancel_scroll_update(),
            add=True,
        )

        # Add scrollbar for lazy loading
        self._sidebar_scrollbar = tk.Scrollbar(
            self._page_sidebar, orient=tk.VERTICAL, command=self._sidebar_canvas.yview
        )
        self._sidebar_canvas.configure(yscrollcommand=self._sidebar_scrollbar.set)
        self._sidebar_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind scroll events for lazy loading
        def on_canvas_scroll(*args: Any) -> Any:
            """Handle scroll and update thumbnails lazily."""
            if self._sidebar_canvas is None:
                return None
            result = self._sidebar_canvas.yview(*args)
            # Schedule thumbnail update after scroll
            self._update_sidebar_after_scroll()
            return result

        def on_mousewheel(event: tk.Event) -> None:
            """Handle mousewheel for smooth scrolling."""
            if self._sidebar_canvas:
                delta = -1 if event.delta > 0 else 1
                self._sidebar_canvas.yview_scroll(delta, "units")
                self._update_sidebar_after_scroll()

        # Replace scrollbar command to intercept scroll
        self._sidebar_scrollbar.config(command=on_canvas_scroll)
        self._sidebar_canvas.bind("<MouseWheel>", on_mousewheel)

        # Add page button
        add_btn = tk.Button(
            self._page_sidebar,
            text="+ Add",
            command=self._on_add_page_click,
        )
        add_btn.pack(fill=tk.X, padx=2, pady=2)

        # Main content area
        content_container = tk.Frame(self._tk_frame, bg="#ffffff")
        content_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=1, pady=1)

        # Header frame
        self._header_frame = tk.Frame(
            content_container,
            height=self.HEADER_HEIGHT,
            bg="#f8f8f8",
            relief=tk.GROOVE,
            bd=1,
        )
        self._header_frame.pack(fill=tk.X, side=tk.TOP)
        self._header_frame.pack_propagate(False)

        # Canvas frame (middle)
        self._canvas_frame = tk.Frame(content_container, bg="#ffffff")
        self._canvas_frame.pack(fill=tk.BOTH, expand=True)

        # Footer frame
        self._footer_frame = tk.Frame(
            content_container,
            height=self.FOOTER_HEIGHT,
            bg="#f8f8f8",
            relief=tk.GROOVE,
            bd=1,
        )
        self._footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self._footer_frame.pack_propagate(False)

        # Header/Footer labels
        self._header_label = tk.Label(
            self._header_frame,
            text="",
            bg="#f8f8f8",
            font=("Courier", 9),
        )
        self._header_label.pack(expand=True)

        self._footer_label = tk.Label(
            self._footer_frame,
            text="",
            bg="#f8f8f8",
            font=("Courier", 9),
        )
        self._footer_label.pack(expand=True)

        # Initialize autocomplete service for FormField integration
        self._autocomplete_gui = AutocompleteServiceGui()

        return self._tk_frame

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Tkinter виджета."""
        # Drag-drop для sidebar будет настроен при создании thumbnails
        pass

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        # Clear all pages
        for page in self._pages:
            if page.canvas is not None:
                page.canvas.unmount()
            if page.inline_frame is not None:
                page.inline_frame.destroy()
            page.fields.clear()
        self._pages.clear()

        # Clear inline state
        self._inline_frames.clear()
        self._inline_fields.clear()
        self._current_inline_frame = None

        # Clear command stack
        self._command_stack.clear()

        # Clear callbacks
        self._on_page_change_callback = None
        self._on_field_select_callback = None

        # Reset state
        self._current_page_index = 0
        self._current_canvas = None

    @staticmethod
    def _get_field_key(page_index: int, field_id: str) -> str:
        """Возвращает уникальный ключ для поля с учётом страницы.

        Args:
            page_index: Индекс страницы.
            field_id: Идентификатор поля.

        Returns:
            Уникальный ключ в формате ``page_{index}_{field_id}``.
        """
        return f"page_{page_index}_{field_id}"

    @staticmethod
    def _field_id_from_key(key: str) -> str:
        """Извлекает field_id из ключа поля.

        Args:
            key: Ключ в формате ``page_{index}_{field_id}``.

        Returns:
            Идентификатор поля.
        """
        parts = key.split("_", 2)
        return parts[2] if len(parts) >= 3 else key

    # =============================================================================
    # PUBLIC API
    # =============================================================================

    def render(self, document: StructuredFormDocument) -> None:
        """Рендерит документ формы.

        Args:
            document: StructuredFormDocument с pages и fields.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="render",
                message="Widget not mounted",
            )

        self._form_id = document.form_id
        self._form_status = document.status
        self._document_index = document.document_index

        # Clear existing pages
        self._clear_pages()
        self._inline_fields.clear()

        # Create pages
        for i, page_data in enumerate(document.pages):
            self._create_page_from_data(page_data, i)

        # Show first page
        if self._pages:
            self._show_page(0)

        # Update sidebar
        self._update_sidebar()

    def add_page(
        self,
        profile: Optional[PaperProfile] = None,
        index: Optional[int] = None,
    ) -> int:
        """Добавляет новую страницу.

        Args:
            profile: Профиль бумаги (default: first favorite).
            index: Позиция вставки (default: в конец).

        Returns:
            Индекс созданной страницы.
        """
        if profile is None:
            # Get default from PaperFormatService
            service = PaperFormatService()
            profile = service.get_profile("a4_portrait") or service.get_default_profile()

        page = FormPage(
            index=index if index is not None else len(self._pages),
            profile=profile,
            fields=[],
            canvas=None,
        )

        if index is None:
            self._pages.append(page)
        else:
            self._pages.insert(index, page)
            self._renumber_pages()

        # Create canvas or inline frame for page
        if self._use_inline_mode:
            self._create_inline_frame_for_page(page, [])
        else:
            self._create_canvas_for_page(page)

        self._update_sidebar()

        return page.index

    def remove_page(self, index: int) -> bool:
        """Удаляет страницу.

        Args:
            index: Индекс страницы для удаления.

        Returns:
            True если удалена успешно.
        """
        if len(self._pages) <= 1:
            # Don't remove last page
            return False

        if 0 <= index < len(self._pages):
            page = self._pages[index]
            if page.canvas is not None:
                page.canvas.unmount()
            if page.inline_frame is not None:
                page.inline_frame.destroy()
                if page.inline_frame in self._inline_frames:
                    self._inline_frames.remove(page.inline_frame)

            del self._pages[index]
            self._renumber_pages()
            self._update_sidebar()

            # Show adjacent page
            new_index = min(index, len(self._pages) - 1)
            if new_index >= 0:
                self._show_page(new_index)

            return True
        return False

    def set_page_paper(self, page_index: int, profile: PaperProfile) -> None:
        """Меняет paper type для страницы.

        Args:
            page_index: Индекс страницы.
            profile: Новый профиль бумаги.
        """
        if 0 <= page_index < len(self._pages):
            page = self._pages[page_index]
            page.profile = profile

            # Recreate canvas with new profile
            if page.canvas is not None:
                page.canvas.unmount()
            page.canvas = self._create_canvas_for_page(page)

            # Update if current page
            if page_index == self._current_page_index:
                self._show_page(page_index)

            self._update_sidebar_thumbnail(page_index)

    def duplicate_page(self, index: int) -> int:
        """Дублирует страницу с FormField integration.

        Args:
            index: Индекс страницы для дублирования.

        Returns:
            Индекс новой страницы.
        """
        if not (0 <= index < len(self._pages)):
            return -1

        source_page = self._pages[index]

        # Create new page with same profile and fields
        new_page = FormPage(
            index=len(self._pages),
            profile=source_page.profile,
            fields=[],  # Fields will be copied separately
            canvas=None,
            header=source_page.header,
            footer=source_page.footer,
        )

        if self._use_inline_mode:
            # Duplicate inline frame with same field definitions
            self._create_inline_frame_for_page(new_page, list(source_page.inline_field_defs))
        else:
            # Create canvas first (needed for FormField placement)
            self._create_canvas_for_page(new_page)

            # Copy fields from source page with FormField creation
            for field_widget in source_page.fields:
                # Create new field widget for positioning
                new_field = self._create_field_widget(
                    field_widget.field_def,
                    field_widget.position.col,
                    field_widget.position.row,
                )
                new_page.fields.append(new_field)

                # Create and place FormField on the new page's canvas
                self._create_and_place_form_field(
                    new_page,
                    new_field,
                    field_widget.field_def,
                    field_widget.position.col,
                    field_widget.position.row,
                )

        self._pages.insert(index + 1, new_page)
        self._renumber_pages()

        self._update_sidebar()

        return new_page.index

    def reorder_pages(self, from_index: int, to_index: int) -> None:
        """Меняет порядок страниц (drag-drop).

        Args:
            from_index: Исходный индекс.
            to_index: Целевой индекс.
        """
        if not (0 <= from_index < len(self._pages)):
            return
        if not (0 <= to_index < len(self._pages)):
            return
        if from_index == to_index:
            return

        # Move page
        page = self._pages.pop(from_index)
        self._pages.insert(to_index, page)

        self._renumber_pages()
        self._update_sidebar()

        # Show moved page
        self._show_page(to_index)

    def configure_header_footer(
        self,
        scope: str,
        header: Optional[HeaderFooterConfig] = None,
        footer: Optional[HeaderFooterConfig] = None,
        page_index: Optional[int] = None,
    ) -> None:
        """Настраивает колонтитулы.

        Args:
            scope: "global" для всех страниц, "per_page" для конкретной.
            header: Конфигурация верхнего колонтитула.
            footer: Конфигурация нижнего колонтитула.
            page_index: Индекс страницы (для per_page scope).
        """
        if scope == "global":
            if header is not None:
                self._global_header = header
                self._header_scope = "global"
            if footer is not None:
                self._global_footer = footer
                self._footer_scope = "global"
        elif scope == "per_page" and page_index is not None:
            if 0 <= page_index < len(self._pages):
                page = self._pages[page_index]
                if header is not None:
                    page.header = header
                if footer is not None:
                    page.footer = footer

        # Refresh current page header/footer
        self._update_header_footer()

    def create_field(
        self,
        field_def: FieldDefinition,
        page_index: Optional[int] = None,
    ) -> Optional[FormFieldWidget]:
        """Создаёт поле на Canvas с FormField integration.

        Args:
            field_def: Определение поля.
            page_index: Страница (default: текущая).

        Returns:
            Созданный виджет поля или None.
        """
        page_idx = page_index if page_index is not None else self._current_page_index

        if not (0 <= page_idx < len(self._pages)):
            return None

        page = self._pages[page_idx]
        if page.canvas is None:
            return None

        # Calculate center position
        cols = page.canvas._cols if hasattr(page.canvas, "_cols") else 80
        rows = page.canvas._rows if hasattr(page.canvas, "_rows") else 66

        col = cols // 4
        row = rows // 4

        # Create FormFieldWidget for positioning metadata
        field_widget = self._create_field_widget(field_def, col, row)
        page.fields.append(field_widget)

        # Create FormField (composite widget) and place on canvas
        self._create_and_place_form_field(page, field_widget, field_def, col, row)

        return field_widget

    def select_field(self, field_id: str) -> None:
        """Выделяет поле.

        Args:
            field_id: ID поля для выделения.
        """
        for page in self._pages:
            if page.canvas is not None:
                page.canvas.select_field(field_id)

        if self._on_field_select_callback is not None:
            self._on_field_select_callback(field_id)

    def move_field(
        self,
        field_id: str,
        new_x: int,
        new_y: int,
        new_page: Optional[int] = None,
    ) -> bool:
        """Перемещает поле.

        Args:
            field_id: ID поля.
            new_x: Новая колонка.
            new_y: Новая строка.
            new_page: Новая страница (опционально).

        Returns:
            True если перемещение успешно.
        """
        # Find the field and its current page
        source_page: Optional[FormPage] = None
        field_widget: Optional[FormFieldWidget] = None
        field_index: int = -1

        for page in self._pages:
            for i, fld in enumerate(page.fields):
                if fld.field_id == field_id:
                    source_page = page
                    field_widget = fld
                    field_index = i
                    break
            if source_page is not None:
                break

        if source_page is None or field_widget is None:
            return False

        # Validate position on target page
        target_page_index = new_page if new_page is not None else source_page.index
        if not (0 <= target_page_index < len(self._pages)):
            return False

        target_page = self._pages[target_page_index]
        if target_page.canvas is None:
            return False

        # Validate position on target canvas
        is_valid, _ = target_page.canvas.validate_field_position(
            field_id,
            new_x,
            new_y,
            field_widget.position.width,
            field_widget.position.height,
        )
        if not is_valid:
            return False

        # If moving to different page
        if target_page_index != source_page.index:
            # Remove from source page
            if source_page.canvas is not None:
                source_page.canvas.remove_field(field_id)
            source_page.fields.pop(field_index)

            # Update field position
            from src.gui.renderers.form_canvas import FieldPosition

            field_widget.position = FieldPosition(
                col=new_x,
                row=new_y,
                width=field_widget.position.width,
                height=field_widget.position.height,
            )

            # Add to target page
            target_page.fields.append(field_widget)
            target_page.canvas.create_field(
                field_widget.field_def,
                new_x,
                new_y,
            )

            # Switch to target page if needed
            if target_page_index != self._current_page_index:
                self._show_page(target_page_index)
        else:
            # Same page move - use canvas move_field
            if source_page.canvas is not None:
                if not source_page.canvas.move_field(field_id, new_x, new_y):
                    return False

        return True

    def delete_field(self, field_id: str) -> bool:
        """Удаляет поле.

        Args:
            field_id: ID поля для удаления.

        Returns:
            True если удалено успешно.
        """
        for page in self._pages:
            for i, fld in enumerate(page.fields):
                if fld.field_id == field_id:
                    if page.canvas is not None:
                        page.canvas.remove_field(field_id)
                    page.fields.pop(i)
                    return True
        return False

    def get_form_data(self) -> dict[str, Any]:
        """Возвращает данные всех полей.

        Returns:
            Словарь с данными полей.
        """
        data: dict[str, Any] = {}

        if self._use_inline_mode:
            for field_key, widget in self._inline_fields.items():
                field_id = self._field_id_from_key(field_key)
                try:
                    data[field_id] = widget.get_value()
                except Exception as e:
                    data[field_id] = None
                    logger.warning(f"Failed to get value for field {field_id}: {e}")
            return data

        for page in self._pages:
            if page.canvas is None:
                continue

            # Получаем виджеты полей из canvas
            field_widgets = page.canvas.get_field_widgets()
            for field_id, widget in field_widgets.items():
                try:
                    if hasattr(widget, "get_value"):
                        data[field_id] = widget.get_value()
                    else:
                        data[field_id] = None
                        logger.warning(f"Widget for field {field_id} has no get_value method")
                except Exception as e:
                    data[field_id] = None
                    logger.warning(f"Failed to get value for field {field_id}: {e}")

        return data

    def validate_form(self) -> ValidationReport:
        """Валидирует всю форму.

        Проверяет:
        - Дубликаты field_id между страницами
        - Перекрытие полей на каждой странице (только canvas mode)
        - Выход полей за границы страницы (только canvas mode)
        - Валидацию каждого поля через widget.validate()

        Returns:
            Отчёт о валидации с ошибками полей.
        """
        report = ValidationReport()

        if self._use_inline_mode:
            for field_key, widget in self._inline_fields.items():
                field_id = self._field_id_from_key(field_key)
                try:
                    is_valid = widget.validate()
                    if not is_valid:
                        error_msg = getattr(widget, "_error_message", None)
                        if error_msg:
                            report.add_field_error(field_id, str(error_msg))
                except Exception as e:
                    report.add_field_error(field_id, f"Ошибка валидации: {e}")
                    logger.warning(f"Validation failed for field {field_id}: {e}")
            return report

        # Track all field IDs across pages
        all_field_ids: dict[str, int] = {}

        # Validate each page
        for page in self._pages:
            if page.canvas is None:
                continue

            page_index = page.index
            fields = list(page.fields)

            # Check for field overlaps on this page
            for i, field1 in enumerate(fields):
                # Check for duplicate field IDs across pages
                if field1.field_id in all_field_ids:
                    other_page = all_field_ids[field1.field_id]
                    report.add_form_error(
                        f"Поле {field1.field_id} дублируется на страницах "
                        f"{other_page + 1} и {page_index + 1}"
                    )
                else:
                    all_field_ids[field1.field_id] = page_index

                # Check for overlaps
                for field2 in fields[i + 1 :]:
                    if self._fields_overlap(field1, field2):
                        report.add_form_error(
                            f"Перекрытие полей {field1.field_id} и {field2.field_id} "
                            f"на странице {page_index + 1}"
                        )

                # Check bounds
                if page.canvas is not None:
                    is_valid, error = page.canvas.validate_field_position(
                        field1.field_id,
                        field1.position.col,
                        field1.position.row,
                        field1.position.width,
                        field1.position.height,
                    )
                    if not is_valid:
                        report.add_field_error(field1.field_id, f"Выход за границы: {error}")

            # Validate field widgets (if they have validate method)
            field_widgets = page.canvas.get_field_widgets()
            for field_id, widget in field_widgets.items():
                try:
                    if hasattr(widget, "validate"):
                        is_valid = widget.validate()
                        if not is_valid:
                            error_msg = getattr(widget, "_error_message", None)
                            if error_msg:
                                report.add_field_error(field_id, str(error_msg))
                except Exception as e:
                    report.add_field_error(field_id, f"Ошибка валидации: {e}")
                    logger.warning(f"Validation failed for field {field_id}: {e}")

        return report

    def highlight_validation_errors(self, report: ValidationReport) -> None:
        """Подсвечивает поля с ошибками на Canvas / inline widgets и FormField.

        Args:
            report: Отчёт о валидации с ошибками.
        """
        # Clear previous errors
        if self._use_inline_mode:
            for widget in self._inline_fields.values():
                widget.set_error(None)
        else:
            for page in self._pages:
                if page.canvas is not None:
                    page.canvas.clear_all_errors()

        # Highlight field errors
        for field_id, error_messages in report.field_errors.items():
            error_msg = "; ".join(error_messages)

            if self._use_inline_mode:
                # Find the field widget across all pages using field key
                found = False
                for field_key, field_widget in self._inline_fields.items():
                    if self._field_id_from_key(field_key) == field_id:
                        field_widget.set_error(error_msg)
                        found = True
                        break
                if found:
                    continue

            # Canvas mode

            # Find field and highlight (canvas mode)
            for page in self._pages:
                if page.canvas is not None:
                    # Highlight on canvas
                    if page.canvas.highlight_field_error(field_id, error_msg):
                        # Also set error on FormField if available
                        field_widgets = page.canvas.get_field_widgets()
                        if field_id in field_widgets:
                            widget = field_widgets[field_id]
                            if isinstance(widget, FormFieldProtocol):
                                widget.set_error(error_msg)
                        break

    def clear_validation_errors(self) -> None:
        """Убирает подсветку ошибок со всех полей, включая FormField."""
        if self._use_inline_mode:
            for widget in self._inline_fields.values():
                widget.set_error(None)
            return

        for page in self._pages:
            if page.canvas is not None:
                page.canvas.clear_all_errors()

                # Clear FormField errors
                field_widgets = page.canvas.get_field_widgets()
                for widget in field_widgets.values():
                    if isinstance(widget, FormFieldProtocol):
                        widget.clear_error()

    def transition_status(
        self,
        new_status: FormStatus,
        mfa_credentials: Optional[dict[str, str]] = None,
    ) -> bool:
        """Переход workflow status с MFA.

        Args:
            new_status: Новый статус.
            mfa_credentials: MFA credentials (password, totp, etc.).

        Returns:
            True если переход успешен.
        """
        # Check if MFA required
        if self._status_manager._is_mfa_required(self._form_status, new_status):
            if mfa_credentials is None:
                return False

            # Verify MFA through mode_manager
            if self._mode_manager is not None:
                if not self._mode_manager.is_special():
                    # Try to enter special mode
                    if not self._mode_manager.enter_special(mfa_credentials):
                        return False

        try:
            doc = StructuredFormDocument(
                form_id=self._form_id or "",
                status=self._form_status,
                pages=[],
                document_index=self._document_index,
            )
            self._status_manager.transition(
                doc,
                new_status,
                mfa=mfa_credentials is not None,
            )
            self._form_status = new_status
            return True
        except Exception as e:
            self._error_handler.handle_silent(
                e,
                {
                    "operation": "transition_status",
                    "form_id": self._form_id,
                    "from_status": self._form_status,
                    "to_status": new_status,
                },
            )
            return False

    def undo(self) -> bool:
        """Undo последнего действия.

        Returns:
            True если undo выполнен.
        """
        if self._command_stack.can_undo():
            self._command_stack.undo()
            return True
        return False

    def redo(self) -> bool:
        """Redo отменённого действия.

        Returns:
            True если redo выполнен.
        """
        if self._command_stack.can_redo():
            self._command_stack.redo()
            return True
        return False

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные, включая FormField widgets."""
        if self._use_inline_mode:
            for widget in self._inline_fields.values():
                if hasattr(widget, "wipe_sensitive_data"):
                    widget.wipe_sensitive_data()
        else:
            for page in self._pages:
                # Clear FormField widgets data
                if page.canvas is not None:
                    field_widgets = page.canvas.get_field_widgets()
                    for widget in field_widgets.values():
                        if isinstance(widget, FormFieldProtocol):
                            widget.wipe_sensitive_data()

                # Clear legacy field data
                for fld in page.fields:
                    if hasattr(fld, "wipe_sensitive_data"):
                        fld.wipe_sensitive_data()

        # Clear command history
        self._command_stack.clear()

        # Clear autocomplete cache if available
        if self._autocomplete_gui is not None:
            self._autocomplete_gui.invalidate_cache()

    # ==========================================================================
    # PROTOCOL METHODS (DocumentRendererProtocol)
    # ==========================================================================

    def set_field_value(self, field_id: str, value: Any) -> None:
        """Устанавливает значение конкретного поля.

        Args:
            field_id: Идентификатор поля.
            value: Новое значение.
        """
        if self._use_inline_mode:
            for field_key, inline_widget in self._inline_fields.items():
                if self._field_id_from_key(field_key) == field_id:
                    inline_widget.set_value(value)
                    return
            return

        # Canvas mode: set via canvas
        for page in self._pages:
            if page.canvas is not None:
                field_widgets = page.canvas.get_field_widgets()
                canvas_widget: Any = field_widgets.get(field_id)
                if canvas_widget is not None and hasattr(canvas_widget, "set_value"):
                    canvas_widget.set_value(value)
                    break

    def get_field_value(self, field_id: str) -> Any:
        """Возвращает значение конкретного поля.

        Args:
            field_id: Идентификатор поля.

        Returns:
            Текущее значение поля или None.
        """
        if self._use_inline_mode:
            for field_key, inline_widget in self._inline_fields.items():
                if self._field_id_from_key(field_key) == field_id:
                    return inline_widget.get_value()
            return None

        # Canvas mode: get via canvas
        for page in self._pages:
            if page.canvas is not None:
                field_widgets = page.canvas.get_field_widgets()
                canvas_widget: Any = field_widgets.get(field_id)
                if canvas_widget is not None and hasattr(canvas_widget, "get_value"):
                    return canvas_widget.get_value()
        return None

    def get_content(self) -> StructuredFormDocument:
        """Возвращает текущее содержимое формы.

        Returns:
            StructuredFormDocument с текущими данными.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_content",
                message="Widget not mounted",
            )

        # Convert FormPage list to PageData list
        page_data_list: list[PageData] = []
        for page in self._pages:
            pd = PageData(
                profile=page.profile,
                fields=[fld.field_def for fld in page.fields],
            )
            page_data_list.append(pd)

        # Build current document from pages
        return StructuredFormDocument(
            form_id=self._form_id or "",
            pages=page_data_list,
            status=self._form_status or FormStatus.DRAFT,
            document_index=self._document_index or "",
        )

    def apply_command(self, command: Command) -> None:
        """Применяет команду к документу.

        Args:
            command: Команда для выполнения.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="apply_command",
                message="Widget not mounted",
            )

        if self._command_stack is not None:
            self._command_stack.execute(command)
        else:
            command.execute()

    def can_handle(self, mode: DocumentMode) -> bool:
        """Проверяет, может ли рендерер обрабатывать данный режим.

        Args:
            mode: Режим документа для проверки.

        Returns:
            True если рендерер поддерживает данный режим.
        """
        return mode == DocumentMode.STRUCTURED_FORM

    def supports_formatting(self) -> bool:
        """Проверяет, поддерживает ли рендерер форматирование текста.

        Returns:
            False для StructuredFormRenderer (форматирование на уровне полей).
        """
        return False

    def set_command_stack(self, stack: CommandStack) -> None:
        """Устанавливает CommandStack для undo/redo операций.

        Args:
            stack: Стек команд для данного рендерера.
        """
        self._command_stack = stack

    def hide_content(self) -> None:
        """Скрывает содержимое редактора (session lock).

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="hide_content",
                message="Widget not mounted",
            )

        # Hide main content areas
        if self._canvas_frame is not None:
            self._canvas_frame.pack_forget()
        if self._page_sidebar is not None:
            self._page_sidebar.pack_forget()
        if self._header_frame is not None:
            self._header_frame.pack_forget()
        if self._footer_frame is not None:
            self._footer_frame.pack_forget()

    def restore_content(self) -> None:
        """Восстанавливает содержимое редактора (session unlock).

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="restore_content",
                message="Widget not mounted",
            )

        # Restore main content areas - re-pack in correct order
        if self._header_frame is not None:
            self._header_frame.pack(fill=tk.X, side=tk.TOP)
        if self._canvas_frame is not None:
            self._canvas_frame.pack(fill=tk.BOTH, expand=True)
        if self._footer_frame is not None:
            self._footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        if self._page_sidebar is not None:
            self._page_sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=1, pady=1)

    def set_on_page_change_callback(self, callback: Callable[[int], None]) -> None:
        """Устанавливает callback для смены страницы.

        Args:
            callback: Функция(index: int) -> None.
        """
        self._on_page_change_callback = callback

    def set_on_field_select_callback(
        self,
        callback: Callable[[Optional[str]], None],
    ) -> None:
        """Устанавливает callback для выбора поля.

        Args:
            callback: Функция(field_id: Optional[str]) -> None.
        """
        self._on_field_select_callback = callback

    # =============================================================================
    # PRIVATE METHODS
    # =============================================================================

    def _create_page_from_data(self, page_data: PageData, index: int) -> FormPage:
        """Создаёт страницу из данных.

        Args:
            page_data: Данные страницы.
            index: Индекс страницы.

        Returns:
            Созданная страница.
        """
        page = FormPage(
            index=index,
            profile=page_data.profile,
            fields=[],
            canvas=None,
            header=page_data.header,
            footer=page_data.footer,
        )

        self._pages.append(page)

        if self._use_inline_mode:
            self._create_inline_frame_for_page(page, page_data.fields)
        else:
            # Create canvas for legacy mode
            self._create_canvas_for_page(page)

        return page

    def _create_inline_frame_for_page(
        self,
        page: FormPage,
        field_defs: list[FieldDefinition],
    ) -> None:
        """Создаёт inline-фрейм для страницы с BaseField виджетами.

        Args:
            page: Страница формы.
            field_defs: Список определений полей для отображения.
        """
        if self._canvas_frame is None:
            return

        inline_frame = tk.Frame(self._canvas_frame, bg="#ffffff")
        page.inline_frame = inline_frame
        page.inline_field_defs = list(field_defs)
        self._inline_frames.append(inline_frame)

        for field_def in field_defs:
            field_type = field_def.field_type
            widget = create_inline_widget(
                field_type=field_type,
                parent=inline_frame,
                field_def=field_def,
                document_index=self._document_index,
                on_change=self._on_field_changed,
                autocomplete_service=self._autocomplete_gui,
            )
            widget.pack(fill=tk.X, pady=2, padx=4)
            field_key = self._get_field_key(page.index, field_def.field_id)
            self._inline_fields[field_key] = widget

    def _show_page(self, index: int) -> None:
        """Показывает страницу.

        Args:
            index: Индекс страницы.
        """
        if not (0 <= index < len(self._pages)):
            return

        self._current_page_index = index
        page = self._pages[index]

        if self._use_inline_mode:
            # Hide current inline frame
            if self._current_inline_frame is not None:
                self._current_inline_frame.pack_forget()

            # Show new inline frame
            if page.inline_frame is not None:
                page.inline_frame.pack(fill=tk.BOTH, expand=True)
                self._current_inline_frame = page.inline_frame
        else:
            # Hide current canvas
            if self._current_canvas is not None:
                if self._current_canvas._tk_widget is not None:
                    self._current_canvas._tk_widget.pack_forget()

            # Show new canvas
            if page.canvas is not None:
                if page.canvas._is_mounted:
                    # Already mounted, just pack it
                    if page.canvas._tk_widget is not None:
                        page.canvas._tk_widget.pack(fill=tk.BOTH, expand=True)
                else:
                    if self._canvas_frame is not None:
                        page.canvas.mount(self._canvas_frame)
                    if page.canvas._tk_widget is not None:
                        page.canvas._tk_widget.pack(fill=tk.BOTH, expand=True)
                self._current_canvas = page.canvas

        # Update header/footer
        self._update_header_footer()

        # Update sidebar selection
        self._update_sidebar_selection()

        # Notify callback
        if self._on_page_change_callback is not None:
            self._on_page_change_callback(index)

    def _create_canvas_for_page(self, page: FormPage) -> FormCanvas:
        """Создаёт Canvas для страницы.

        Args:
            page: Страница.

        Returns:
            Созданный Canvas.
        """
        canvas = FormCanvas(
            widget_id=f"form_canvas_page_{page.index}",
            controller=self._controller,
            profile=page.profile,
            zoom=1.0,
            show_grid=True,
            show_margins=True,
            snap_to_grid=True,
            on_field_select=self._on_field_select_callback,
        )
        # Mount canvas to the canvas frame
        if self._canvas_frame is not None:
            canvas.mount(self._canvas_frame)
        page.canvas = canvas
        return canvas

    def _create_field_widget(
        self,
        field_def: FieldDefinition,
        col: int,
        row: int,
    ) -> FormFieldWidget:
        """Создаёт виджет поля.

        Args:
            field_def: Определение поля.
            col: Колонка.
            row: Строка.

        Returns:
            Созданный виджет поля.
        """
        from src.gui.renderers.form_canvas import FieldPosition

        return FormFieldWidget(
            field_id=field_def.field_id,
            field_def=field_def,
            position=FieldPosition(col=col, row=row, width=1, height=1),
        )

    def _create_and_place_form_field(
        self,
        page: FormPage,
        field_widget: FormFieldWidget,
        field_def: FieldDefinition,
        col: int,
        row: int,
    ) -> Optional[Any]:
        """Создаёт FormField и размещает его на Canvas.

        Использует новые виджеты из structured_form.widgets по FieldType:
        - TEXT_INPUT → AutocompleteEntry
        - NUMBER_INPUT, CURRENCY → NumberEntry
        - DATE_INPUT → DateEntry
        - TABLE → TableField
        - DROPDOWN → tk.OptionMenu (fallback через FormField)

        Args:
            page: Страница формы.
            field_widget: Виджет поля для позиционирования.
            field_def: Определение поля.
            col: Колонка для размещения.
            row: Строка для размещения.

        Returns:
            Созданный FormField или None.
        """
        if page.canvas is None:
            return None

        if not isinstance(page.canvas._tk_widget, tk.Canvas):
            return None

        canvas = page.canvas._tk_widget

        # Calculate pixel position and size
        cell_width = page.canvas._cell_width
        cell_height = page.canvas._cell_height
        x = col * cell_width
        y = row * cell_height

        # Calculate size based on field definition
        width_chars = getattr(field_def, "width_chars", 20)
        height_lines = getattr(field_def, "height_lines", 1)

        # Calculate pixel dimensions
        width_px = max(150, width_chars * 8)  # Minimum 150px, ~8px per char
        height_px = max(60, height_lines * 24)  # Minimum 60px, ~24px per line

        # Create container frame for field widget
        container = tk.Frame(canvas, bg="#ffffff", relief=tk.RIDGE, bd=1)

        # Choose widget based on FieldType
        field_type = field_def.field_type
        inner_widget: Optional[Any] = None

        if field_type == FieldType.TEXT_INPUT:
            # Use new AutocompleteEntry if autocomplete_source present,
            # otherwise fallback to FormField text input
            if field_def.autocomplete_source and self._autocomplete_gui is not None:
                inner_widget = AutocompleteEntry(
                    parent=container,
                    field_id=field_def.field_id,
                    document_index=self._document_index,
                    label=field_def.label,
                    on_change=self._on_field_changed,
                    autocomplete_service=self._autocomplete_gui,
                )
            else:
                inner_widget = create_form_field(
                    parent=container,
                    field_def=field_def,
                    document_index=self._document_index,
                    autocomplete_service=None,
                    on_change=self._on_field_changed,
                    on_validate=self._on_field_validated,
                )

        elif field_type in (FieldType.NUMBER_INPUT, FieldType.CURRENCY):
            # NumberEntry with min/max and decimal places from field_def
            decimal_places = 2  # default
            if field_type == FieldType.CURRENCY:
                decimal_places = 2
            inner_widget = NumberEntry(
                parent=container,
                field_id=field_def.field_id,
                label=field_def.label,
                min_value=field_def.min_value,
                max_value=field_def.max_value,
                decimal_places=decimal_places,
                on_change=self._on_field_changed,
            )

        elif field_type == FieldType.DATE_INPUT:
            inner_widget = DateEntry(
                parent=container,
                field_id=field_def.field_id,
                label=field_def.label,
                on_change=self._on_field_changed,
            )

        elif field_type == FieldType.TABLE:
            # TableField with columns from table_schema
            columns: list[str] = []
            if field_def.table_schema is not None:
                columns = [col.header for col in field_def.table_schema.columns]
            inner_widget = TableField(
                parent=container,
                field_id=field_def.field_id,
                columns=columns,
                rows=field_def.table_schema.min_rows if field_def.table_schema else 1,
                on_change=self._on_field_changed,
                label=field_def.label,
            )

        elif field_type == FieldType.DROPDOWN:
            options = list(field_def.options) if field_def.options else []
            inner_widget = self._create_option_menu_field(container, field_def, options)

        else:
            # Fallback to legacy FormField for all other types
            core_service = (
                self._autocomplete_gui._core_service if self._autocomplete_gui is not None else None
            )
            inner_widget = create_form_field(
                parent=container,
                field_def=field_def,
                document_index=self._document_index,
                autocomplete_service=core_service,
                on_change=self._on_field_changed,
                on_validate=self._on_field_validated,
            )

        if inner_widget is not None:
            # Pack the widget into the container
            if isinstance(inner_widget, BaseField):
                inner_widget.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
            elif isinstance(inner_widget, FormFieldProtocol):
                inner_widget.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Place container on canvas using create_window
        canvas.create_window(
            x,
            y,
            window=container,
            anchor=tk.NW,
            width=width_px,
            height=height_px if field_type != FieldType.TABLE else max(height_px, 150),
            tags=(f"field_{field_def.field_id}",),
        )

        # Store reference in canvas for value retrieval
        page.canvas.set_field_widget(field_def.field_id, inner_widget)

        return inner_widget

    def _create_option_menu_field(
        self,
        parent: tk.Widget,
        field_def: FieldDefinition,
        options: list[str],
    ) -> BaseField:
        """Создаёт inline DROPDOWN виджет на базе OptionMenu.

        Args:
            parent: Родительский виджет.
            field_def: Определение поля.
            options: Список опций.

        Returns:
            BaseField с OptionMenu.
        """

        class DropdownField(BaseField):
            """Inline DROPDOWN на основе tk.OptionMenu."""

            def _create_content(self) -> None:
                """Создаёт OptionMenu внутри BaseField."""
                self._var: tk.StringVar = tk.StringVar(value=options[0] if options else "")
                self._option_menu = tk.OptionMenu(self, self._var, *options)
                self._option_menu.pack(fill=tk.X)
                self._option_menu.bind("<Configure>", self._on_select)

            def _on_select(self, event: tk.Event[Any]) -> None:
                """Обработчик выбора опции."""
                _ = event
                self.set_value(self._var.get())

            def get_value(self) -> Any:
                """Возвращает текущее значение."""
                return self._var.get()

            def set_value(self, value: Any) -> None:
                """Устанавливает значение OptionMenu."""
                str_value = str(value) if value is not None else ""
                if str_value in options:
                    self._var.set(str_value)
                super().set_value(str_value)

            def validate(self) -> bool:
                """Валидирует значение DROPDOWN."""
                value = self.get_value()
                if value not in options:
                    self.set_error(f"Недопустимое значение: {value}")
                    return False
                return super().validate()

            def focus(self) -> None:
                """Устанавливает фокус на OptionMenu."""
                self._option_menu.focus_set()

        return DropdownField(
            parent=parent,
            field_id=field_def.field_id,
            label=field_def.label,
            on_change=self._on_field_changed,
        )

    def _on_field_changed(self, field_id: str, value: Any) -> None:
        """Callback при изменении значения поля.

        Args:
            field_id: Идентификатор поля.
            value: Новое значение.
        """
        # Trigger validation on change if needed
        logger.debug(f"Field {field_id} changed to: {value}")

        # Propagate to external callback
        if self._on_field_change_callback is not None:
            self._on_field_change_callback(field_id, value)

    def set_on_field_change_callback(self, callback: Callable[[str, Any], None]) -> None:
        """Устанавливает callback при изменении поля.

        Args:
            callback: Функция обратного вызова (field_id, value).
        """
        self._on_field_change_callback = callback

    def _on_field_validated(
        self,
        field_id: str,
        is_valid: bool,
        error: Optional[str],
    ) -> None:
        """Callback при валидации поля.

        Args:
            field_id: Идентификатор поля.
            is_valid: Флаг валидности.
            error: Сообщение об ошибке.
        """
        # Log validation result
        if not is_valid and error:
            logger.warning(f"Field {field_id} validation failed: {error}")

    def _renumber_pages(self) -> None:
        """Пересчитывает индексы страниц."""
        for i, page in enumerate(self._pages):
            page.index = i

    def _get_visible_page_range(self) -> range:
        """Возвращает диапазон видимых страниц в sidebar.

        Returns:
            range с индексами видимых страниц (с буфером для smooth scrolling).
        """
        if self._sidebar_canvas is None:
            return range(0)

        if not self._pages:
            return range(0)

        # Get scroll position
        yview = self._sidebar_canvas.yview()
        if yview == (0.0, 1.0):  # All visible
            return range(len(self._pages))

        # Calculate visible range based on scroll position
        total = len(self._pages)
        start = int(yview[0] * total)
        end = min(int(yview[1] * total) + 1, total)

        # Add buffer for smooth scrolling
        buffer = 2
        return range(max(0, start - buffer), min(total, end + buffer))

    def _update_sidebar(self) -> None:
        """Обновляет sidebar с lazy loading.

        Создаёт только видимые thumbnails с буфером для smooth scrolling.
        Остальные thumbnails создаются on-demand при скролле.
        """
        if self._sidebar_canvas is None:
            return

        if not self._pages:
            # Clear everything if no pages
            for widget in self._thumbnail_frames:
                if widget is not None:
                    widget.destroy()
            self._thumbnail_frames.clear()
            self._sidebar_canvas.delete("all")
            return

        visible_range = self._get_visible_page_range()
        self._visible_thumbnail_range = (visible_range.start, visible_range.stop)

        # Ensure list is right size - preserve existing thumbnails
        while len(self._thumbnail_frames) < len(self._pages):
            self._thumbnail_frames.append(None)
        while len(self._thumbnail_frames) > len(self._pages):
            old = self._thumbnail_frames.pop()
            if old is not None:
                old.destroy()

        # Destroy thumbnails outside visible range (memory optimization)
        thumbnail_height = 80
        for i in range(len(self._thumbnail_frames)):
            if i not in visible_range and self._thumbnail_frames[i] is not None:
                self._thumbnail_frames[i].destroy()  # type: ignore[union-attr]
                self._thumbnail_frames[i] = None

        # Clear canvas and recreate visible thumbnails
        self._sidebar_canvas.delete("all")

        # Create/update visible thumbnails
        y_offset = 5
        for i in visible_range:
            if i >= len(self._pages):
                break

            if self._thumbnail_frames[i] is None:
                # LAZY CREATE
                self._thumbnail_frames[i] = self._create_thumbnail(
                    i, self._pages[i], thumbnail_height
                )

            # Position thumbnail in canvas
            frame = self._thumbnail_frames[i]
            if frame is not None:
                self._sidebar_canvas.create_window(
                    5,
                    y_offset,
                    window=frame,
                    anchor="nw",
                    width=130,
                    height=thumbnail_height,
                )
            y_offset += thumbnail_height + 5

        # Update scroll region for all pages (virtual height)
        total_height = len(self._pages) * (thumbnail_height + 5) + 10
        self._sidebar_canvas.config(scrollregion=(0, 0, 150, total_height))

        # Setup scroll binding for lazy loading on scroll
        self._setup_lazy_scroll_binding()

    def _create_thumbnail(
        self,
        index: int,
        page: FormPage,
        height: int,
    ) -> tk.Frame:
        """Создаёт thumbnail для страницы.

        Args:
            index: Индекс страницы.
            page: Страница.
            height: Высота thumbnail.

        Returns:
            Frame с thumbnail.
        """
        frame = tk.Frame(
            self._sidebar_canvas,
            bg="#ffffff",
            relief=tk.RAISED,
            bd=1,
            width=120,
            height=height,
        )
        frame.pack_propagate(False)

        # Page number label
        label = tk.Label(
            frame,
            text=f"Pg. {index + 1}",
            bg="#ffffff",
            font=("Arial", 8),
        )
        label.pack(side=tk.BOTTOM, fill=tk.X)

        # Paper type label
        paper_label = tk.Label(
            frame,
            text=page.profile.name,
            bg="#f0f0f0",
            font=("Arial", 7),
            wraplength=110,
        )
        paper_label.pack(side=tk.TOP, fill=tk.X)

        # Canvas for preview
        preview = tk.Canvas(
            frame,
            bg="white",
            highlightthickness=0,
            width=100,
            height=height - 30,
        )
        preview.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)

        # Draw simple page representation
        aspect = page.profile.height_mm / page.profile.width_mm
        pw = 90
        ph = int(pw * aspect)
        if ph > height - 35:
            ph = height - 35
            pw = int(ph / aspect)

        x1 = (100 - pw) // 2
        y1 = (height - 35 - ph) // 2
        preview.create_rectangle(
            x1,
            y1,
            x1 + pw,
            y1 + ph,
            outline="#000000",
            fill="#ffffff",
            width=1,
        )

        # Click binding - use function factories to avoid lambda inference issues
        def make_click_handler(idx: int) -> Callable[[tk.Event], None]:
            def handler(event: tk.Event) -> None:
                _ = event
                self._on_thumbnail_click(idx)

            return handler

        frame.bind("<Button-1>", make_click_handler(index))
        preview.bind("<Button-1>", make_click_handler(index))
        label.bind("<Button-1>", make_click_handler(index))
        paper_label.bind("<Button-1>", make_click_handler(index))

        # Context menu - use function factories to avoid lambda inference issues
        def make_duplicate_cmd(idx: int) -> Callable[[], None]:
            def cmd() -> None:
                self.duplicate_page(idx)

            return cmd

        def make_remove_cmd(idx: int) -> Callable[[], None]:
            def cmd() -> None:
                self.remove_page(idx)

            return cmd

        def make_move_up_cmd(idx: int) -> Callable[[], None]:
            def cmd() -> None:
                self._move_page_up(idx)

            return cmd

        def make_move_down_cmd(idx: int) -> Callable[[], None]:
            def cmd() -> None:
                self._move_page_down(idx)

            return cmd

        menu = tk.Menu(frame, tearoff=0)
        menu.add_command(label="Duplicate", command=make_duplicate_cmd(index))
        menu.add_command(label="Delete", command=make_remove_cmd(index))
        menu.add_separator()
        menu.add_command(label="Up", command=make_move_up_cmd(index))
        menu.add_command(label="Down", command=make_move_down_cmd(index))

        def show_menu(event: tk.Event) -> None:
            menu.post(event.x_root, event.y_root)

        frame.bind("<Button-3>", show_menu)
        preview.bind("<Button-3>", show_menu)

        # Place in canvas
        if self._sidebar_canvas is not None:
            y_pos = index * (height + 5) + 5
            self._sidebar_canvas.create_window(
                5,
                y_pos,
                anchor=tk.NW,
                window=frame,
                width=130,
                height=height,
            )

        return frame

    def _cancel_scroll_update(self) -> None:
        """Отменяет pending after() для обновления sidebar."""
        if self._scroll_update_after_id is not None and self._sidebar_canvas is not None:
            try:
                self._sidebar_canvas.after_cancel(self._scroll_update_after_id)
            except tk.TclError:
                pass
            self._scroll_update_after_id = None
        self._scroll_update_pending = False

    def _update_sidebar_after_scroll(self) -> None:
        """Обновляет sidebar после скролла с debounce.

        Использует debounce для smooth 60fps scrolling.
        """
        if self._scroll_update_pending:
            return

        self._scroll_update_pending = True

        def do_update() -> None:
            self._scroll_update_pending = False
            self._scroll_update_after_id = None
            old_range = self._visible_thumbnail_range
            new_range = self._get_visible_page_range()

            if new_range.start != old_range[0] or new_range.stop != old_range[1]:
                self._update_sidebar()

        # Debounce: wait for scroll to settle
        if self._sidebar_canvas:
            self._scroll_update_after_id = self._sidebar_canvas.after(50, do_update)

    def _setup_lazy_scroll_binding(self) -> None:
        """Настраивает binding для lazy loading при скролле sidebar."""
        if self._sidebar_canvas is None:
            return

        # Remove old binding if exists
        if self._thumbnail_scroll_binding is not None:
            self._sidebar_canvas.unbind("<Configure>", self._thumbnail_scroll_binding)

        # Add binding for scroll/resize events
        def on_scroll_or_resize(event: tk.Event) -> None:
            _ = event
            # Check if visible range changed
            old_range = self._visible_thumbnail_range
            new_range = self._get_visible_page_range()

            if new_range.start != old_range[0] or new_range.stop != old_range[1]:
                # Update sidebar to create/destroy thumbnails as needed
                self._update_sidebar()

        self._thumbnail_scroll_binding = self._sidebar_canvas.bind(
            "<Configure>", on_scroll_or_resize
        )

        # Also bind to scroll commands
        def on_yscroll(*args: Any) -> None:
            if self._sidebar_canvas is None:
                return
            # Original yview behavior
            self._sidebar_canvas.yview(*args)
            # Check if we need to update thumbnails
            old_range = self._visible_thumbnail_range
            new_range = self._get_visible_page_range()
            if new_range.start != old_range[0] or new_range.stop != old_range[1]:
                self._update_sidebar()

        # Note: yscrollcommand is set on scrollbar, not canvas
        # We rely on Configure event which fires on scroll

    def _update_sidebar_thumbnail(self, index: int) -> None:
        """Обновляет только один thumbnail, не все.

        Args:
            index: Индекс страницы.

        Note:
            Оптимизировано: пересоздаёт только один thumbnail,
            а не все как в предыдущей реализации.
        """
        if index < 0 or index >= len(self._pages):
            return

        # Ensure list is right size
        while len(self._thumbnail_frames) < len(self._pages):
            self._thumbnail_frames.append(None)

        # Only recreate if exists
        if index < len(self._thumbnail_frames) and self._thumbnail_frames[index] is not None:
            self._thumbnail_frames[index].destroy()  # type: ignore[union-attr]
            self._thumbnail_frames[index] = None

        # Only create if in visible range
        visible_range = self._get_visible_page_range()
        if index in visible_range:
            thumbnail_height = 80
            self._thumbnail_frames[index] = self._create_thumbnail(
                index, self._pages[index], thumbnail_height
            )
            # Reposition all visible thumbnails
            self._update_sidebar_layout()

    def _update_sidebar_layout(self) -> None:
        """Перерисовывает layout видимых thumbnails без их пересоздания.

        Вызывается когда меняется порядок страниц или размер,
        но сами thumbnails не нужно пересоздавать.
        """
        if self._sidebar_canvas is None:
            return

        # Clear canvas but keep widget references
        self._sidebar_canvas.delete("all")

        # Reposition visible thumbnails
        thumbnail_height = 80
        y_offset = 5
        visible_range = self._get_visible_page_range()

        for i in visible_range:
            if i >= len(self._thumbnail_frames):
                break
            frame = self._thumbnail_frames[i]
            if frame is not None:
                self._sidebar_canvas.create_window(
                    5,
                    y_offset,
                    window=frame,
                    anchor="nw",
                    width=130,
                    height=thumbnail_height,
                )
            y_offset += thumbnail_height + 5

        # Update scroll region
        total_height = len(self._pages) * (thumbnail_height + 5) + 10
        self._sidebar_canvas.config(scrollregion=(0, 0, 150, total_height))

    def _update_sidebar_selection(self) -> None:
        """Обновляет выделение в sidebar."""
        for i, frame in enumerate(self._thumbnail_frames):
            if frame is None:
                continue
            if i == self._current_page_index:
                frame.config(bg="#3498db", relief=tk.SUNKEN)
                for child in frame.winfo_children():
                    if isinstance(child, tk.Label):
                        child.config(bg="#3498db", fg="white")
            else:
                frame.config(bg="#ffffff", relief=tk.RAISED)
                for child in frame.winfo_children():
                    if isinstance(child, tk.Label):
                        child.config(bg="#ffffff", fg="black")

    def _update_header_footer(self) -> None:
        """Обновляет отображение колонтитулов."""
        if not (0 <= self._current_page_index < len(self._pages)):
            return

        page = self._pages[self._current_page_index]

        # Header
        if self._header_scope == "global" and self._global_header is not None:
            header_text = self._global_header.render(
                self._current_page_index + 1,
                len(self._pages),
                self._document_index,
            )
        elif page.header is not None:
            header_text = page.header.render(
                self._current_page_index + 1,
                len(self._pages),
                self._document_index,
            )
        else:
            header_text = ""

        if self._header_label is not None:
            self._header_label.config(text=header_text)

        # Footer
        if self._footer_scope == "global" and self._global_footer is not None:
            footer_text = self._global_footer.render(
                self._current_page_index + 1,
                len(self._pages),
                self._document_index,
            )
        elif page.footer is not None:
            footer_text = page.footer.render(
                self._current_page_index + 1,
                len(self._pages),
                self._document_index,
            )
        else:
            footer_text = ""

        if self._footer_label is not None:
            self._footer_label.config(text=footer_text)

    def _clear_pages(self) -> None:
        """Очищает все страницы и inline-виджеты."""
        for page in self._pages:
            if page.canvas is not None:
                page.canvas.unmount()
            if page.inline_frame is not None:
                page.inline_frame.destroy()
        self._pages.clear()
        self._inline_frames.clear()
        self._inline_fields.clear()
        self._current_inline_frame = None

    def _on_thumbnail_click(self, index: int) -> None:
        """Обработчик клика по thumbnail.

        Args:
            index: Индекс страницы.
        """
        self._show_page(index)

    def _on_add_page_click(self) -> None:
        """Обработчик клика по кнопке добавления страницы."""
        self.add_page()

    def _move_page_up(self, index: int) -> None:
        """Перемещает страницу вверх.

        Args:
            index: Индекс страницы.
        """
        if index > 0:
            self.reorder_pages(index, index - 1)

    def _move_page_down(self, index: int) -> None:
        """Перемещает страницу вниз.

        Args:
            index: Индекс страницы.
        """
        if index < len(self._pages) - 1:
            self.reorder_pages(index, index + 1)

    # =============================================================================
    # PROPERTIES
    # =============================================================================

    @property
    def current_page(self) -> Optional[FormPage]:
        """Возвращает текущую страницу."""
        if 0 <= self._current_page_index < len(self._pages):
            return self._pages[self._current_page_index]
        return None

    @property
    def page_count(self) -> int:
        """Возвращает количество страниц."""
        return len(self._pages)

    @property
    def form_status(self) -> FormStatus:
        """Возвращает статус формы."""
        return self._form_status

    def _fields_overlap(
        self,
        field1: FormFieldWidget,
        field2: FormFieldWidget,
    ) -> bool:
        """Проверяет перекрытие двух полей.

        Args:
            field1: Первое поле.
            field2: Второе поле.

        Returns:
            True если поля перекрываются.
        """
        p1 = field1.position
        p2 = field2.position

        return (
            p1.col < p2.col + p2.width
            and p1.col + p1.width > p2.col
            and p1.row < p2.row + p2.height
            and p1.row + p1.height > p2.row
        )

    def show(self) -> None:
        """Показывает рендерер.

        Example:
            >>> renderer.show()
        """
        if self._tk_widget is not None:
            self._tk_widget.pack(fill=tk.BOTH, expand=True)

    def hide(self) -> None:
        """Скрывает рендерер.

        Example:
            >>> renderer.hide()
        """
        if self._tk_widget is not None:
            self._tk_widget.pack_forget()

    # =============================================================================
    # PROTOCOL METHODS (DocumentRendererProtocol)
    # =============================================================================

    def display_document(self, document: StructuredFormDocument) -> None:
        """Отображает документ (alias для render с SmartEdit-aware проверкой).

        Args:
            document: Документ для отображения.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        self.render(document)

    def create_toolbar(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт toolbar для STRUCTURED_FORM режима.

        Создаёт WorkflowToolbar с кнопками для workflow операций
        и настраивает видимость по текущему состоянию формы.

        Args:
            parent: Родительский виджет.

        Returns:
            WorkflowToolbar widget.

        Raises:
            ValueError: Если parent is None.
        """
        if parent is None:
            raise ValueError("parent cannot be None")

        self._workflow_toolbar = WorkflowToolbar(parent)
        self._workflow_toolbar.on_action(self._on_workflow_action)

        # Обновить видимость по текущей роли и состоянию
        if self._workflow_manager is not None:
            actions = self._workflow_manager.get_visible_actions(
                self._workflow_manager.current_role,
                self._form_status,
            )
            self._workflow_toolbar.set_available_actions(actions)
        else:
            # По умолчанию показываем save_draft
            self._workflow_toolbar.set_available_actions({"save_draft"})

        return self._workflow_toolbar

    def _on_workflow_action(self, action: str) -> None:
        """Обработчик действий WorkflowToolbar.

        Args:
            action: Имя действия (save_draft, validate, approve, sign, reject,
                switch_role, fill_fields, submit_for_validation, view_comments,
                print, archive, switch_to_editor, switch_to_operator,
                switch_to_supervisor, switch_to_signatory).
        """
        if action == "save_draft":
            if self._controller is not None:
                self._controller.dispatch("save_draft", form_id=self._form_id)

        elif action == "fill_fields":
            # Placeholder: логика заполнения полей реализуется на уровне контроллера
            logger.info("Action fill_fields triggered")

        elif action == "submit_for_validation":
            self._transition_status(FormStatus.FILLED)

        elif action == "validate":
            self._transition_status(FormStatus.VALIDATED)

        elif action == "approve":
            self._transition_status(FormStatus.APPROVED)

        elif action == "sign":
            self._transition_status(FormStatus.SIGNED)

        elif action == "reject":
            self._show_reject_dialog()

        elif action == "view_comments":
            # Placeholder: открытие панели комментариев
            logger.info("Action view_comments triggered")

        elif action == "print":
            if self._controller is not None:
                self._controller.dispatch("print", form_id=self._form_id)

        elif action == "archive":
            self._transition_status(FormStatus.ARCHIVED)

        elif action == "switch_role":
            self._show_role_switch_dialog()

        elif action in (
            "switch_to_editor",
            "switch_to_operator",
            "switch_to_supervisor",
            "switch_to_signatory",
        ):
            role_map = {
                "switch_to_editor": "editor",
                "switch_to_operator": "operator",
                "switch_to_supervisor": "supervisor",
                "switch_to_signatory": "signatory",
            }
            from src.controller.workflow_controller import WorkflowRole

            new_role = WorkflowRole(role_map[action])
            if self._workflow_manager is not None:
                self._workflow_manager.set_role(new_role)

            # Обновить toolbar после смены роли
            if self._workflow_toolbar is not None and self._workflow_manager is not None:
                actions = self._workflow_manager.get_visible_actions(
                    self._workflow_manager.current_role,
                    self._form_status,
                )
                self._workflow_toolbar.set_available_actions(actions)

            if self._controller is not None:
                self._controller.dispatch("role_switched", role=new_role.value)

    def _transition_status(self, new_status: FormStatus) -> None:
        """Выполняет переход статуса через MFAGate если доступен.

        Args:
            new_status: Целевой статус формы.
        """
        if self._mfa_gate is not None:
            try:
                self._mfa_gate.execute(
                    parent=self._tk_frame,
                    operation=lambda: self._do_transition(new_status),
                    operation_name=f"Переход в {new_status.value}",
                    requires_mfa=True,
                )
            except Exception as e:
                logger.warning(f"MFA transition failed: {e}")
        else:
            self._do_transition(new_status)

    def _do_transition(self, new_status: FormStatus) -> None:
        """Выполняет переход статуса через FormStatusManager.

        Args:
            new_status: Целевой статус формы.
        """
        try:
            doc = StructuredFormDocument(
                form_id=self._form_id or "",
                status=self._form_status,
                pages=[],
                document_index=self._document_index,
            )
            self._status_manager.transition(doc, new_status, mfa=False)
            self._form_status = new_status

            # Обновить toolbar
            if self._workflow_toolbar is not None and self._workflow_manager is not None:
                actions = self._workflow_manager.get_visible_actions(
                    self._workflow_manager.current_role,
                    self._form_status,
                )
                self._workflow_toolbar.set_available_actions(actions)

            # Уведомить контроллер
            if self._controller is not None:
                self._controller.dispatch(
                    "form_status_changed",
                    form_id=self._form_id,
                    new_status=new_status.value,
                )

        except Exception as e:
            self._error_handler.handle_silent(
                e,
                {
                    "operation": "transition_status",
                    "form_id": self._form_id,
                    "from_status": self._form_status,
                    "to_status": new_status,
                },
            )

    def _show_reject_dialog(self) -> None:
        """Показывает диалог отклонения формы."""
        if self._tk_frame is None:
            return
        current_role = (
            self._workflow_manager.current_role if self._workflow_manager is not None else None
        )
        dialog = RejectDialog(
            parent=self._tk_frame,
            current_status=self._form_status,
            current_role=current_role,
            on_reject=self._on_reject_confirmed,
        )
        result = dialog.show()
        if result is not None:
            target_status = result.get("target_status")
            if isinstance(target_status, FormStatus):
                self._do_transition(target_status)

    def _on_reject_confirmed(
        self,
        status: FormStatus,
        reason: str,
        mfa_credentials: Optional[dict[str, str]],
    ) -> None:
        """Callback при подтверждении отклонения.

        Args:
            status: Выбранный целевой статус.
            reason: Причина отклонения.
            mfa_credentials: MFA credentials (опционально).
        """
        self._do_transition(status)

    def _show_role_switch_dialog(self) -> None:
        """Показывает диалог смены роли."""
        if self._tk_frame is None:
            return
        from src.controller.workflow_controller import WorkflowRole

        dialog = RoleSwitchDialog(
            parent=self._tk_frame,
            current_role=WorkflowRole.OPERATOR,
            on_role_selected=self._on_role_selected,
        )
        result = dialog.show()
        if result is not None:
            new_role, free_mode, requires_mfa = result
            if self._controller is not None:
                self._controller.dispatch(
                    "role_switched",
                    role=new_role.value,
                    free_mode=free_mode,
                )

    def _on_role_selected(self, role: Any, free_mode: bool) -> None:
        """Callback при выборе роли.

        Обновляет роль в WorkflowManager и пересчитывает видимость кнопок toolbar.

        Args:
            role: Выбранная роль.
            free_mode: Режим свободного переключения.
        """
        # Обновить роль в менеджере workflow
        if self._workflow_manager is not None:
            self._workflow_manager.set_role(role)

        # Обновить видимость кнопок toolbar
        if self._workflow_toolbar is not None and self._workflow_manager is not None:
            actions = self._workflow_manager.get_visible_actions(
                self._workflow_manager.current_role,
                self._form_status,
            )
            self._workflow_toolbar.set_available_actions(actions)

        if self._controller is not None:
            self._controller.dispatch(
                "role_switched",
                role=getattr(role, "value", str(role)),
                free_mode=free_mode,
            )

    def create_editor(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт редактор в указанном parent.

        Если рендерер ещё не смонтирован, выполняет mount.

        Args:
            parent: Родительский виджет.

        Returns:
            Корневой виджет редактора.

        Raises:
            ValueError: Если parent is None.
        """
        if parent is None:
            raise ValueError("parent cannot be None")

        if not self._is_mounted:
            self.mount(parent)

        if self._tk_frame is None:
            raise RuntimeError("Editor widget not created after mount")

        return self._tk_frame

    def get_editor_state(self) -> dict[str, Any]:
        """Возвращает текущее состояние редактора.

        Returns:
            Словарь с current_page, page_count, form_status, form_id.

        Raises:
            LifecycleError: Если рендерер не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_editor_state",
                message="Widget not mounted",
            )

        return {
            "current_page": self._current_page_index,
            "page_count": len(self._pages),
            "form_status": self._form_status.name,
            "form_id": self._form_id,
        }

    def supports_workflow(self) -> bool:
        """Проверяет, поддерживает ли рендерер workflow-переходы.

        Returns:
            True для StructuredFormRenderer (MFA workflow transitions).
        """
        return True

    def get_undo_manager(self) -> Any:
        """Возвращает менеджер undo/redo операций.

        Returns:
            CommandStack для данного рендерера.
        """
        return self._command_stack


# =============================================================================
# MODULE EXPORTS
# =============================================================================


__all__: list[str] = [
    "StructuredFormRenderer",
    "StructuredFormDocument",
    "FormPage",
    "PageData",
    "HeaderFooterConfig",
]
