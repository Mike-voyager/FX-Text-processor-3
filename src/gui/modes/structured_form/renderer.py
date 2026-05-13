"""StructuredFormModeRenderer — адаптер для рендеринга структурированных форм.

Реализует интеграцию StructuredFormRenderer с ESC/P Grid Canvas:
- Field snap-to-grid placement
- Workflow state visualization
- Grid snap toggle
- Theme support

Example:
    >>> renderer = StructuredFormModeRenderer(
    ...     parent=root,
    ...     controller=controller,
    ...     mode_manager=mode_manager,
    ... )
    >>> renderer.mount(parent_frame)
    >>> renderer.render(document)
    >>> content = renderer.get_content()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from typing import TYPE_CHECKING, Any, Callable, Final, Optional

from src.documents.constructor.form_constructor import ValidationReport
from src.documents.constructor.form_status import FormStatus
from src.documents.types.type_schema import FieldDefinition
from src.gui.core.commands.command import Command
from src.gui.core.commands.command_stack import CommandStack
from src.gui.components.base.widget import BaseWidget
from src.gui.core.error_handler import GUIErrorHandler
from src.gui.core.exceptions import LifecycleError
from src.gui.core.protocols import ControllerProtocol
from src.gui.modes.structured_form.workflow.form_workflow_bar import FormWorkflowBar
from src.gui.security.mode_manager import ModeManager

if TYPE_CHECKING:
    from src.gui.renderers.structured_form_renderer import StructuredFormRenderer

# Import types after TYPE_CHECKING block to avoid circular imports
from src.gui.renderers.structured_form_renderer import (
    StructuredFormDocument,
)

logger: Final = logging.getLogger(__name__)


class StructuredFormModeRenderer(BaseWidget):
    """Адаптер для StructuredFormRenderer с Grid Canvas интеграцией.

    Особенности:
    - Интеграция с ESC/P Grid Canvas (FormCanvas)
    - Field snap-to-grid placement
    - Workflow state visualization через FormWorkflowBar
    - Theme support
    - MFA-gated workflow transitions

    Attributes:
        _inner_renderer: Базовый StructuredFormRenderer.
        _workflow_bar: Панель отображения статуса workflow.
        _snap_to_grid: Флаг привязки к сетке.
        _command_stack: Стек команд для undo/redo.

    Example:
        >>> renderer = StructuredFormModeRenderer(
        ...     parent=root,
        ...     controller=controller,
        ...     mode_manager=mode_manager,
        ... )
        >>> renderer.mount(parent_frame)
        >>> doc = StructuredFormDocument(form_id="test", pages=[...])
        >>> renderer.render(doc)
        >>> is_valid = renderer.validate()
    """

    # UI Constants
    WORKFLOW_BAR_HEIGHT: Final[int] = 80
    TOOLBAR_HEIGHT: Final[int] = 40

    def __init__(
        self,
        parent: tk.Widget,
        controller: Optional[ControllerProtocol] = None,
        mode_manager: Optional[ModeManager] = None,
        snap_to_grid: bool = True,
    ) -> None:
        """Инициализация StructuredFormModeRenderer.

        Args:
            parent: Родительский Tkinter виджет.
            controller: Опциональная ссылка на контроллер для callbacks.
            mode_manager: ModeManager для MFA workflow.
            snap_to_grid: Включить привязку к сетке по умолчанию.
        """
        super().__init__(
            widget_id="structured_form_mode_renderer",
            controller=controller,
        )

        self._parent: tk.Widget = parent
        self._mode_manager: Optional[ModeManager] = mode_manager
        self._snap_to_grid: bool = snap_to_grid

        # Внутренний рендерер
        self._inner_renderer: Optional[StructuredFormRenderer] = None

        # UI компоненты
        self._main_frame: Optional[tk.Frame] = None
        self._workflow_bar: Optional[FormWorkflowBar] = None
        self._renderer_frame: Optional[tk.Frame] = None

        # Callbacks
        self._on_field_select_callback: Optional[Callable[[Optional[str]], None]] = None
        self._on_page_change_callback: Optional[Callable[[int], None]] = None
        self._on_status_change_callback: Optional[Callable[[FormStatus, FormStatus], None]] = None

        # Command stack
        self._command_stack: CommandStack = CommandStack()

        # Error handler
        self._error_handler: GUIErrorHandler = GUIErrorHandler()

        # Current document
        self._current_document: Optional[StructuredFormDocument] = None
        self._current_status: FormStatus = FormStatus.DRAFT

    def _create_inner_renderer(self) -> Any:
        """Лениво создаёт внутренний StructuredFormRenderer."""
        # Import here to avoid circular import
        from src.gui.renderers.structured_form_renderer import StructuredFormRenderer

        if self._renderer_frame is None:
            raise AssertionError("Renderer frame must be created first")
        return StructuredFormRenderer(
            parent=self._renderer_frame,
            controller=self._controller,
            mode_manager=self._mode_manager,
        )

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame.
        """
        # Главный контейнер
        self._main_frame = tk.Frame(parent, bg="#f5f5f5")

        # Панель workflow (вверху)
        self._workflow_bar = FormWorkflowBar(
            parent=self._main_frame,
            current_status=self._current_status,
            on_transition=self._on_workflow_transition,
            mode_manager=self._mode_manager,
        )
        self._workflow_bar.mount(self._main_frame)
        if self._workflow_bar._tk_widget is not None:
            self._workflow_bar._tk_widget.pack(
                fill=tk.X,
                side=tk.TOP,
                padx=2,
                pady=2,
            )

        # Контейнер для рендерера
        self._renderer_frame = tk.Frame(
            self._main_frame,
            bg="#ffffff",
            relief=tk.SUNKEN,
            bd=1,
        )
        self._renderer_frame.pack(
            fill=tk.BOTH,
            expand=True,
            side=tk.TOP,
            padx=2,
            pady=2,
        )

        # Создаём внутренний рендерер
        self._inner_renderer = self._create_inner_renderer()
        self._inner_renderer.mount(self._renderer_frame)
        if self._inner_renderer._tk_widget is not None:
            self._inner_renderer._tk_widget.pack(fill=tk.BOTH, expand=True)

        # Настраиваем callbacks
        self._setup_renderer_callbacks()

        return self._main_frame

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Tkinter виджета."""
        # Базовая настройка - дополнительные bindings можно добавить здесь
        pass

    def _setup_renderer_callbacks(self) -> None:
        """Настраивает callbacks для внутреннего рендерера."""
        if self._inner_renderer is None:
            return

        # Callback выбора поля
        if self._on_field_select_callback is not None:
            self._inner_renderer.set_on_field_select_callback(self._on_field_select_callback)

        # Callback смены страницы
        if self._on_page_change_callback is not None:
            self._inner_renderer.set_on_page_change_callback(self._on_page_change_callback)

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        # Очищаем workflow bar
        if self._workflow_bar is not None:
            self._workflow_bar.wipe_sensitive_data()
            self._workflow_bar.unmount()
            self._workflow_bar = None

        # Очищаем внутренний рендерер
        if self._inner_renderer is not None:
            self._inner_renderer.wipe_sensitive_data()
            self._inner_renderer.unmount()
            self._inner_renderer = None

        # Очищаем callbacks
        self._on_field_select_callback = None
        self._on_page_change_callback = None
        self._on_status_change_callback = None

        # Очищаем command stack
        self._command_stack.clear()

        # Сбрасываем ссылки
        self._current_document = None

    def _on_workflow_transition(
        self,
        old_status: FormStatus,
        new_status: FormStatus,
    ) -> None:
        """Обработчик перехода workflow status.

        Args:
            old_status: Предыдущий статус.
            new_status: Новый статус.
        """
        self._current_status = new_status

        # Уведомляем callback
        if self._on_status_change_callback is not None:
            self._on_status_change_callback(old_status, new_status)

        # Обновляем document status если есть документ
        if self._current_document is not None:
            self._current_document = StructuredFormDocument(
                form_id=self._current_document.form_id,
                pages=self._current_document.pages,
                status=new_status,
                document_index=self._current_document.document_index,
            )

        logger.debug(f"Workflow transition: {old_status.value} -> {new_status.value}")

    # ==========================================================================
    # PUBLIC API
    # ==========================================================================

    def mount(self, parent: Any) -> tk.Widget:
        """Монтирует виджет в родительский контейнер.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Tkinter виджет.

        Raises:
            LifecycleError: Если виджет уже смонтирован.
        """
        return super().mount(parent)

    def unmount(self) -> None:
        """Демонтирует виджет и освобождает ресурсы."""
        super().unmount()

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
                message="Виджет не смонтирован",
            )

        self._current_document = document
        self._current_status = document.status

        # Обновляем workflow bar
        if self._workflow_bar is not None:
            self._workflow_bar.set_status(document.status)

        # Рендерим через внутренний рендерер
        if self._inner_renderer is not None:
            self._inner_renderer.render(document)

    def get_content(self) -> StructuredFormDocument:
        """Возвращает текущее содержимое формы.

        Returns:
            StructuredFormDocument с текущими данными.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="get_content",
                message="Виджет не смонтирован",
            )

        if self._inner_renderer is not None:
            return self._inner_renderer.get_content()

        # Return empty document if no inner renderer
        return StructuredFormDocument(
            form_id="",
            pages=[],
            status=FormStatus.DRAFT,
            document_index="",
        )

    def validate(self) -> ValidationReport:
        """Валидирует всю форму.

        Returns:
            Отчёт о валидации с ошибками полей.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="validate",
                message="Виджет не смонтирован",
            )

        if self._inner_renderer is not None:
            return self._inner_renderer.validate_form()

        return ValidationReport()

    def apply_command(self, command: Command) -> None:
        """Применяет команду к документу.

        Args:
            command: Команда для выполнения.

        Raises:
            LifecycleError: Если виджет не смонтирован.
        """
        if not self._is_mounted:
            raise LifecycleError(
                widget_id=self._widget_id,
                operation="apply_command",
                message="Виджет не смонтирован",
            )

        if self._inner_renderer is not None:
            self._inner_renderer.apply_command(command)
        else:
            self._command_stack.execute(command)

    def undo(self) -> bool:
        """Undo последнего действия.

        Returns:
            True если undo выполнен.
        """
        if self._inner_renderer is not None:
            return self._inner_renderer.undo()
        if self._command_stack.can_undo():
            self._command_stack.undo()
            return True
        return False

    def redo(self) -> bool:
        """Redo отменённого действия.

        Returns:
            True если redo выполнен.
        """
        if self._inner_renderer is not None:
            return self._inner_renderer.redo()
        if self._command_stack.can_redo():
            self._command_stack.redo()
            return True
        return False

    def set_snap_to_grid(self, enabled: bool) -> None:
        """Устанавливает флаг привязки к сетке.

        Args:
            enabled: True для включения snap-to-grid.
        """
        self._snap_to_grid = enabled

        # Обновляем все canvas в inner renderer
        if self._inner_renderer is not None:
            for page in self._inner_renderer._pages:
                if page.canvas is not None:
                    page.canvas._snap_to_grid = enabled

    def get_snap_to_grid(self) -> bool:
        """Возвращает текущее состояние привязки к сетке.

        Returns:
            True если snap-to-grid включён.
        """
        return self._snap_to_grid

    def create_field(
        self,
        field_def: FieldDefinition,
        page_index: Optional[int] = None,
    ) -> Optional[Any]:
        """Создаёт поле на Canvas.

        Args:
            field_def: Определение поля.
            page_index: Страница (default: текущая).

        Returns:
            Созданный виджет поля или None.
        """
        if self._inner_renderer is None:
            return None
        return self._inner_renderer.create_field(field_def, page_index)

    def select_field(self, field_id: str) -> None:
        """Выделяет поле.

        Args:
            field_id: ID поля для выделения.
        """
        if self._inner_renderer is not None:
            self._inner_renderer.select_field(field_id)

    def delete_field(self, field_id: str) -> bool:
        """Удаляет поле.

        Args:
            field_id: ID поля для удаления.

        Returns:
            True если удалено успешно.
        """
        if self._inner_renderer is not None:
            return self._inner_renderer.delete_field(field_id)
        return False

    def get_form_data(self) -> dict[str, Any]:
        """Возвращает данные всех полей.

        Returns:
            Словарь с данными полей.
        """
        if self._inner_renderer is not None:
            return self._inner_renderer.get_form_data()
        return {}

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
        if self._workflow_bar is not None:
            return self._workflow_bar.request_transition(new_status, mfa_credentials)
        return False

    def get_current_status(self) -> FormStatus:
        """Возвращает текущий workflow status.

        Returns:
            Текущий статус формы.
        """
        return self._current_status

    def set_on_field_select_callback(
        self,
        callback: Callable[[Optional[str]], None],
    ) -> None:
        """Устанавливает callback для выбора поля.

        Args:
            callback: Функция(field_id: Optional[str]) -> None.
        """
        self._on_field_select_callback = callback
        self._setup_renderer_callbacks()

    def set_on_page_change_callback(
        self,
        callback: Callable[[int], None],
    ) -> None:
        """Устанавливает callback для смены страницы.

        Args:
            callback: Функция(index: int) -> None.
        """
        self._on_page_change_callback = callback
        self._setup_renderer_callbacks()

    def set_on_status_change_callback(
        self,
        callback: Callable[[FormStatus, FormStatus], None],
    ) -> None:
        """Устанавливает callback для изменения статуса.

        Args:
            callback: Функция(old_status: FormStatus, new_status: FormStatus) -> None.
        """
        self._on_status_change_callback = callback

    def highlight_validation_errors(self, report: ValidationReport) -> None:
        """Подсвечивает поля с ошибками.

        Args:
            report: Отчёт о валидации с ошибками.
        """
        if self._inner_renderer is not None:
            self._inner_renderer.highlight_validation_errors(report)

    def clear_validation_errors(self) -> None:
        """Убирает подсветку ошибок со всех полей."""
        if self._inner_renderer is not None:
            self._inner_renderer.clear_validation_errors()

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные."""
        super()._cleanup()
        if self._inner_renderer is not None:
            self._inner_renderer.wipe_sensitive_data()

    def hide_content(self) -> None:
        """Скрывает содержимое редактора (session lock)."""
        if self._inner_renderer is not None:
            self._inner_renderer.hide_content()

    def restore_content(self) -> None:
        """Восстанавливает содержимое редактора (session unlock)."""
        if self._inner_renderer is not None:
            self._inner_renderer.restore_content()

    def add_page(self, profile: Optional[Any] = None, index: Optional[int] = None) -> int:
        """Добавляет новую страницу.

        Args:
            profile: Профиль бумаги (default: first favorite).
            index: Позиция вставки (default: в конец).

        Returns:
            Индекс созданной страницы.
        """
        if self._inner_renderer is not None:
            return self._inner_renderer.add_page(profile, index)
        return -1

    def remove_page(self, index: int) -> bool:
        """Удаляет страницу.

        Args:
            index: Индекс страницы для удаления.

        Returns:
            True если удалена успешно.
        """
        if self._inner_renderer is not None:
            return self._inner_renderer.remove_page(index)
        return False

    def duplicate_page(self, index: int) -> int:
        """Дублирует страницу.

        Args:
            index: Индекс страницы для дублирования.

        Returns:
            Индекс новой страницы.
        """
        if self._inner_renderer is not None:
            return self._inner_renderer.duplicate_page(index)
        return -1

    def get_current_page(self) -> int:
        """Возвращает индекс текущей страницы.

        Returns:
            Индекс текущей страницы (0-based).
        """
        if self._inner_renderer is not None:
            return self._inner_renderer._current_page_index
        return 0

    def set_current_page(self, index: int) -> None:
        """Устанавливает текущую страницу.

        Args:
            index: Индекс страницы для отображения.
        """
        if self._inner_renderer is not None:
            self._inner_renderer._show_page(index)
