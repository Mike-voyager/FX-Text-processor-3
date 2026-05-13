"""StructuredFormToolbar — панель инструментов для StructuredForm mode.

Предоставляет:
- Field type palette (compact icons)
- Workflow state indicator
- Validation toggle button
- Grid snap toggle
- Role indicator

Example:
    >>> from src.gui.modes.structured_form.toolbar import StructuredFormToolbar
    >>> toolbar = StructuredFormToolbar(
    ...     parent=root,
    ...     controller=controller,
    ...     mode_manager=mode_manager,
    ... )
    >>> toolbar.mount(parent_frame)
    >>> toolbar.set_role(WorkflowRole.EDITOR)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Final, Optional

from src.documents.constructor.form_status import FormStatus
from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol
from src.gui.workflow.role_badge import WorkflowRole

if TYPE_CHECKING:
    from src.gui.security.mode_manager import ModeManager

logger: Final = logging.getLogger(__name__)


class FieldType(str, Enum):
    """Типы полей для палитры.

    Attributes:
        TEXT: Текстовое поле.
        NUMBER: Числовое поле.
        DATE: Поле даты.
        CHECKBOX: Чекбокс.
        SELECT: Выпадающий список.
        TEXTAREA: Многострочный текст.
        BARCODE: Штрихкод.
        SIGNATURE: Подпись.
    """

    TEXT = "text"
    NUMBER = "number"
    DATE = "date"
    CHECKBOX = "checkbox"
    SELECT = "select"
    TEXTAREA = "textarea"
    BARCODE = "barcode"
    SIGNATURE = "signature"

    @property
    def icon(self) -> str:
        """Возвращает иконку для типа поля."""
        icons: dict[FieldType, str] = {
            FieldType.TEXT: "T",
            FieldType.NUMBER: "#",
            FieldType.DATE: "D",
            FieldType.CHECKBOX: "☐",
            FieldType.SELECT: "▼",
            FieldType.TEXTAREA: "¶",
            FieldType.BARCODE: "|||",
            FieldType.SIGNATURE: "✍",
        }
        return icons.get(self, "?")

    @property
    def localized_name(self) -> str:
        """Возвращает локализованное название типа поля."""
        names: dict[FieldType, str] = {
            FieldType.TEXT: "Текст",
            FieldType.NUMBER: "Число",
            FieldType.DATE: "Дата",
            FieldType.CHECKBOX: "Флаг",
            FieldType.SELECT: "Список",
            FieldType.TEXTAREA: "Текст (многостр.)",
            FieldType.BARCODE: "Штрихкод",
            FieldType.SIGNATURE: "Подпись",
        }
        return names.get(self, self.value)


class StructuredFormToolbar(BaseWidget):
    """Панель инструментов для StructuredForm mode.

    Features:
    - Field type palette с compact icons
    - Workflow state indicator (DRAFT → FILLED → VALIDATED → SIGNED)
    - Validation toggle button
    - Grid snap toggle для полей
    - Role indicator (OPERATOR/EDITOR/SUPERVISOR/SIGNATORY)
    - Theme support

    Example:
        >>> toolbar = StructuredFormToolbar(
        ...     parent=root,
        ...     controller=controller,
        ...     mode_manager=mode_manager,
        ... )
        >>> toolbar.mount(parent_frame)
        >>> toolbar.set_role(WorkflowRole.EDITOR)
    """

    # UI Constants
    BUTTON_SIZE: Final[int] = 28
    BUTTON_PAD: Final[int] = 2
    SECTION_PAD: Final[int] = 10

    # Theme colors
    BG_COLOR: Final[str] = "#f0f0f0"
    BUTTON_BG: Final[str] = "#ffffff"
    BUTTON_ACTIVE_BG: Final[str] = "#e0e0e0"
    TOGGLE_ON_BG: Final[str] = "#3498db"
    TOGGLE_ON_FG: Final[str] = "#ffffff"

    ROLE_COLORS: Final[dict[WorkflowRole, str]] = {
        WorkflowRole.OPERATOR: "#3498db",  # Синий
        WorkflowRole.EDITOR: "#2ecc71",  # Зелёный
        WorkflowRole.SUPERVISOR: "#f39c12",  # Оранжевый
        WorkflowRole.SIGNATORY: "#e74c3c",  # Красный
    }

    def __init__(
        self,
        parent: tk.Widget,
        controller: Optional[ControllerProtocol] = None,
        mode_manager: Optional[ModeManager] = None,
        on_field_add: Optional[Callable[[FieldType], None]] = None,
        on_validate_toggle: Optional[Callable[[bool], None]] = None,
        on_snap_toggle: Optional[Callable[[bool], None]] = None,
        on_role_change: Optional[Callable[[WorkflowRole], None]] = None,
    ) -> None:
        """Инициализация StructuredFormToolbar.

        Args:
            parent: Родительский Tkinter виджет.
            controller: Опциональная ссылка на контроллер для callbacks.
            mode_manager: ModeManager для MFA проверок.
            on_field_add: Callback при добавлении поля (тип поля).
            on_validate_toggle: Callback переключения валидации (enabled).
            on_snap_toggle: Callback переключения snap-to-grid (enabled).
            on_role_change: Callback смены роли (новая роль).
        """
        super().__init__(
            widget_id="structured_form_toolbar",
            controller=controller,
        )

        self._parent: tk.Widget = parent
        self._mode_manager: Optional[ModeManager] = mode_manager

        # Callbacks
        self._on_field_add: Optional[Callable[[FieldType], None]] = on_field_add
        self._on_validate_toggle: Optional[Callable[[bool], None]] = on_validate_toggle
        self._on_snap_toggle: Optional[Callable[[bool], None]] = on_snap_toggle
        self._on_role_change: Optional[Callable[[WorkflowRole], None]] = on_role_change

        # State
        self._current_role: WorkflowRole = WorkflowRole.OPERATOR
        self._current_status: FormStatus = FormStatus.DRAFT
        self._validation_enabled: bool = True
        self._snap_to_grid: bool = True

        # UI components
        self._main_frame: Optional[tk.Frame] = None
        self._field_buttons: dict[FieldType, tk.Button] = {}
        self._status_labels: dict[FormStatus, tk.Label] = {}
        self._validate_btn: Optional[tk.Button] = None
        self._snap_btn: Optional[tk.Button] = None
        self._role_indicator: Optional[tk.Frame] = None
        self._role_label: Optional[tk.Label] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame.
        """
        self._main_frame = tk.Frame(
            parent,
            bg=self.BG_COLOR,
            relief=tk.RAISED,
            bd=1,
            padx=5,
            pady=5,
        )

        # Секция 1: Field type palette
        self._create_field_palette()

        # Разделитель
        separator1 = tk.Frame(
            self._main_frame,
            width=2,
            height=self.BUTTON_SIZE + 4,
            bg="#cccccc",
        )
        separator1.pack(side=tk.LEFT, padx=self.SECTION_PAD, fill=tk.Y)

        # Секция 2: Workflow state indicator
        self._create_workflow_indicator()

        # Разделитель
        separator2 = tk.Frame(
            self._main_frame,
            width=2,
            height=self.BUTTON_SIZE + 4,
            bg="#cccccc",
        )
        separator2.pack(side=tk.LEFT, padx=self.SECTION_PAD, fill=tk.Y)

        # Секция 3: Toggle buttons
        self._create_toggle_buttons()

        # Разделитель
        separator3 = tk.Frame(
            self._main_frame,
            width=2,
            height=self.BUTTON_SIZE + 4,
            bg="#cccccc",
        )
        separator3.pack(side=tk.LEFT, padx=self.SECTION_PAD, fill=tk.Y)

        # Секция 4: Role indicator
        self._create_role_indicator()

        return self._main_frame

    def _create_field_palette(self) -> None:
        """Создаёт палитру типов полей с compact icons."""
        palette_frame = tk.Frame(self._main_frame, bg=self.BG_COLOR)
        palette_frame.pack(side=tk.LEFT, fill=tk.Y)

        # Заголовок
        header = tk.Label(
            palette_frame,
            text="Поля:",
            bg=self.BG_COLOR,
            font=("TkDefaultFont", 8),
            fg="#666666",
        )
        header.pack(side=tk.TOP, anchor=tk.W, pady=(0, 2))

        # Кнопки типов полей
        btn_frame = tk.Frame(palette_frame, bg=self.BG_COLOR)
        btn_frame.pack(side=tk.TOP, fill=tk.X)

        def _make_field_callback(ft: FieldType) -> Callable[[], None]:
            return lambda: self._on_field_type_click(ft)

        for field_type in FieldType:
            btn = tk.Button(
                btn_frame,
                text=field_type.icon,
                width=2,
                height=1,
                bg=self.BUTTON_BG,
                activebackground=self.BUTTON_ACTIVE_BG,
                relief=tk.RAISED,
                bd=1,
                font=("TkDefaultFont", 10, "bold"),
                cursor="hand2",
                command=_make_field_callback(field_type),
            )
            btn.pack(side=tk.LEFT, padx=self.BUTTON_PAD)
            self._field_buttons[field_type] = btn

            # Tooltip
            self._create_tooltip(btn, field_type.localized_name)

    def _create_workflow_indicator(self) -> None:
        """Создаёт индикатор состояния workflow."""
        workflow_frame = tk.Frame(self._main_frame, bg=self.BG_COLOR)
        workflow_frame.pack(side=tk.LEFT, fill=tk.Y)

        # Заголовок
        header = tk.Label(
            workflow_frame,
            text="Статус:",
            bg=self.BG_COLOR,
            font=("TkDefaultFont", 8),
            fg="#666666",
        )
        header.pack(side=tk.TOP, anchor=tk.W, pady=(0, 2))

        # Цепочка статусов
        chain_frame = tk.Frame(workflow_frame, bg=self.BG_COLOR)
        chain_frame.pack(side=tk.TOP, fill=tk.X)

        # Основные статусы для отображения
        display_statuses = [
            FormStatus.DRAFT,
            FormStatus.FILLED,
            FormStatus.VALIDATED,
            FormStatus.SIGNED,
        ]

        status_colors: dict[FormStatus, str] = {
            FormStatus.DRAFT: "#95a5a6",
            FormStatus.FILLED: "#3498db",
            FormStatus.VALIDATED: "#f39c12",
            FormStatus.SIGNED: "#27ae60",
        }

        for i, status in enumerate(display_statuses):
            # Статус label
            label = tk.Label(
                chain_frame,
                text=status.localized_name,
                bg=status_colors.get(status, "#95a5a6")
                if status == self._current_status
                else "#ecf0f1",
                fg="white" if status == self._current_status else "#7f8c8d",
                font=("TkDefaultFont", 8, "bold" if status == self._current_status else "normal"),
                padx=6,
                pady=2,
                relief=tk.RAISED if status == self._current_status else tk.FLAT,
                borderwidth=1,
            )
            label.pack(side=tk.LEFT, padx=1)
            self._status_labels[status] = label

            # Стрелка (кроме последнего)
            if i < len(display_statuses) - 1:
                arrow = tk.Label(
                    chain_frame,
                    text="→",
                    font=("TkDefaultFont", 8),
                    fg="#bdc3c7",
                    bg=self.BG_COLOR,
                )
                arrow.pack(side=tk.LEFT)

    def _create_toggle_buttons(self) -> None:
        """Создаёт кнопки переключателей."""
        toggle_frame = tk.Frame(self._main_frame, bg=self.BG_COLOR)
        toggle_frame.pack(side=tk.LEFT, fill=tk.Y)

        # Grid snap toggle
        self._snap_btn = tk.Button(
            toggle_frame,
            text="⧉ Сетка",
            bg=self.TOGGLE_ON_BG if self._snap_to_grid else self.BUTTON_BG,
            fg=self.TOGGLE_ON_FG if self._snap_to_grid else "#000000",
            activebackground=self.BUTTON_ACTIVE_BG,
            relief=tk.RAISED,
            bd=1,
            font=("TkDefaultFont", 8),
            cursor="hand2",
            command=self._on_snap_toggle_click,
        )
        self._snap_btn.pack(side=tk.LEFT, padx=self.BUTTON_PAD)

        # Validation toggle
        self._validate_btn = tk.Button(
            toggle_frame,
            text="✓ Валидация",
            bg=self.TOGGLE_ON_BG if self._validation_enabled else self.BUTTON_BG,
            fg=self.TOGGLE_ON_FG if self._validation_enabled else "#000000",
            activebackground=self.BUTTON_ACTIVE_BG,
            relief=tk.RAISED,
            bd=1,
            font=("TkDefaultFont", 8),
            cursor="hand2",
            command=self._on_validate_toggle_click,
        )
        self._validate_btn.pack(side=tk.LEFT, padx=self.BUTTON_PAD)

    def _create_role_indicator(self) -> None:
        """Создаёт индикатор текущей роли."""
        role_frame = tk.Frame(self._main_frame, bg=self.BG_COLOR)
        role_frame.pack(side=tk.RIGHT, fill=tk.Y)

        # Заголовок
        header = tk.Label(
            role_frame,
            text="Роль:",
            bg=self.BG_COLOR,
            font=("TkDefaultFont", 8),
            fg="#666666",
        )
        header.pack(side=tk.TOP, anchor=tk.W, pady=(0, 2))

        # Индикатор роли
        self._role_indicator = tk.Frame(
            role_frame,
            bg=self.ROLE_COLORS[self._current_role],
            relief=tk.RAISED,
            bd=1,
            padx=8,
            pady=4,
        )
        self._role_indicator.pack(side=tk.TOP)

        # Label с названием роли
        self._role_label = tk.Label(
            self._role_indicator,
            text=self._get_role_display_name(self._current_role),
            bg=self.ROLE_COLORS[self._current_role],
            fg="white",
            font=("TkDefaultFont", 9, "bold"),
            cursor="hand2",
        )
        self._role_label.pack()

        def _on_role_label_click(event: tk.Event) -> None:
            self._on_role_click()

        self._role_label.bind("<Button-1>", _on_role_label_click)

    def _create_tooltip(self, widget: tk.Widget, text: str) -> None:
        """Создаёт tooltip для виджета.

        Args:
            widget: Виджет для tooltip.
            text: Текст tooltip.
        """
        tooltip: Optional[tk.Toplevel] = None

        def on_enter(event: tk.Event) -> None:
            nonlocal tooltip
            x = widget.winfo_rootx() + widget.winfo_width() // 2
            y = widget.winfo_rooty() + widget.winfo_height()

            tooltip = tk.Toplevel(widget)
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{x}+{y}")

            label = tk.Label(
                tooltip,
                text=text,
                bg="#ffffcc",
                relief=tk.SOLID,
                bd=1,
                font=("TkDefaultFont", 8),
                padx=4,
                pady=2,
            )
            label.pack()

        def on_leave(event: tk.Event) -> None:
            nonlocal tooltip
            if tooltip is not None:
                tooltip.destroy()
                tooltip = None

        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def _get_role_display_name(self, role: WorkflowRole) -> str:
        """Возвращает отображаемое название роли.

        Args:
            role: Роль для отображения.

        Returns:
            Локализованное название роли.
        """
        names: dict[WorkflowRole, str] = {
            WorkflowRole.OPERATOR: "Оператор",
            WorkflowRole.EDITOR: "Редактор",
            WorkflowRole.SUPERVISOR: "Супервизор",
            WorkflowRole.SIGNATORY: "Подписант",
        }
        return names.get(role, role.value)

    def _on_field_type_click(self, field_type: FieldType) -> None:
        """Обработчик нажатия на тип поля.

        Args:
            field_type: Выбранный тип поля.
        """
        logger.debug(f"Field type selected: {field_type.value}")
        if self._on_field_add is not None:
            self._on_field_add(field_type)

    def _on_validate_toggle_click(self) -> None:
        """Обработчик переключения валидации."""
        self._validation_enabled = not self._validation_enabled

        # Обновляем кнопку
        if self._validate_btn is not None:
            self._validate_btn.config(
                bg=self.TOGGLE_ON_BG if self._validation_enabled else self.BUTTON_BG,
                fg=self.TOGGLE_ON_FG if self._validation_enabled else "#000000",
            )

        logger.debug(f"Validation toggled: {self._validation_enabled}")

        # Вызываем callback
        if self._on_validate_toggle is not None:
            self._on_validate_toggle(self._validation_enabled)

    def _on_snap_toggle_click(self) -> None:
        """Обработчик переключения snap-to-grid."""
        self._snap_to_grid = not self._snap_to_grid

        # Обновляем кнопку
        if self._snap_btn is not None:
            self._snap_btn.config(
                bg=self.TOGGLE_ON_BG if self._snap_to_grid else self.BUTTON_BG,
                fg=self.TOGGLE_ON_FG if self._snap_to_grid else "#000000",
            )

        logger.debug(f"Snap-to-grid toggled: {self._snap_to_grid}")

        # Вызываем callback
        if self._on_snap_toggle is not None:
            self._on_snap_toggle(self._snap_to_grid)

    def _on_role_click(self) -> None:
        """Обработчик клика на индикатор роли (смена роли)."""
        # Cycle through roles: OPERATOR -> EDITOR -> SUPERVISOR -> SIGNATORY -> OPERATOR
        role_order = [
            WorkflowRole.OPERATOR,
            WorkflowRole.EDITOR,
            WorkflowRole.SUPERVISOR,
            WorkflowRole.SIGNATORY,
        ]

        current_index = role_order.index(self._current_role)
        next_index = (current_index + 1) % len(role_order)
        new_role = role_order[next_index]

        self.set_role(new_role)

    def _setup_bindings(self) -> None:
        """Настраивает event bindings для Tkinter виджета."""
        # Базовая настройка
        pass

    def _cleanup(self) -> None:
        """Выполняет очистку ресурсов перед демонтированием."""
        self._field_buttons.clear()
        self._status_labels.clear()
        self._validate_btn = None
        self._snap_btn = None
        self._role_indicator = None
        self._role_label = None

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

    def set_role(self, role: WorkflowRole) -> None:
        """Устанавливает текущую роль.

        Args:
            role: Новая роль.
        """
        old_role = self._current_role
        self._current_role = role

        # Обновляем UI
        if self._role_indicator is not None and self._role_label is not None:
            color = self.ROLE_COLORS.get(role, "#95a5a6")
            self._role_indicator.config(bg=color)
            self._role_label.config(
                bg=color,
                text=self._get_role_display_name(role),
            )

        logger.debug(f"Role changed: {old_role.value} -> {role.value}")

        # Вызываем callback
        if self._on_role_change is not None:
            self._on_role_change(role)

    def get_role(self) -> WorkflowRole:
        """Возвращает текущую роль.

        Returns:
            Текущая роль пользователя.
        """
        return self._current_role

    def set_status(self, status: FormStatus) -> None:
        """Устанавливает текущий workflow status.

        Args:
            status: Новый статус формы.
        """
        self._current_status = status

        # Обновляем UI
        status_colors: dict[FormStatus, str] = {
            FormStatus.DRAFT: "#95a5a6",
            FormStatus.FILLED: "#3498db",
            FormStatus.VALIDATED: "#f39c12",
            FormStatus.SIGNED: "#27ae60",
        }

        display_statuses = [
            FormStatus.DRAFT,
            FormStatus.FILLED,
            FormStatus.VALIDATED,
            FormStatus.SIGNED,
        ]

        for s in display_statuses:
            label = self._status_labels.get(s)
            if label is not None:
                is_current = s == status
                color = status_colors.get(s, "#95a5a6") if is_current else "#ecf0f1"
                label.config(
                    bg=color,
                    fg="white" if is_current else "#7f8c8d",
                    font=("TkDefaultFont", 8, "bold" if is_current else "normal"),
                    relief=tk.RAISED if is_current else tk.FLAT,
                )

    def get_status(self) -> FormStatus:
        """Возвращает текущий workflow status.

        Returns:
            Текущий статус формы.
        """
        return self._current_status

    def set_snap_to_grid(self, enabled: bool) -> None:
        """Устанавливает состояние snap-to-grid.

        Args:
            enabled: True для включения.
        """
        if self._snap_to_grid != enabled:
            self._snap_to_grid = enabled

            # Обновляем кнопку
            if self._snap_btn is not None:
                self._snap_btn.config(
                    bg=self.TOGGLE_ON_BG if enabled else self.BUTTON_BG,
                    fg=self.TOGGLE_ON_FG if enabled else "#000000",
                )

    def get_snap_to_grid(self) -> bool:
        """Возвращает состояние snap-to-grid.

        Returns:
            True если snap-to-grid включён.
        """
        return self._snap_to_grid

    def set_validation_enabled(self, enabled: bool) -> None:
        """Устанавливает состояние валидации.

        Args:
            enabled: True для включения.
        """
        if self._validation_enabled != enabled:
            self._validation_enabled = enabled

            # Обновляем кнопку
            if self._validate_btn is not None:
                self._validate_btn.config(
                    bg=self.TOGGLE_ON_BG if enabled else self.BUTTON_BG,
                    fg=self.TOGGLE_ON_FG if enabled else "#000000",
                )

    def get_validation_enabled(self) -> bool:
        """Возвращает состояние валидации.

        Returns:
            True если валидация включена.
        """
        return self._validation_enabled

    def enable_field_type(self, field_type: FieldType, enabled: bool = True) -> None:
        """Включает или отключает кнопку типа поля.

        Args:
            field_type: Тип поля.
            enabled: True для включения, False для отключения.
        """
        btn = self._field_buttons.get(field_type)
        if btn is not None:
            btn.config(state=tk.NORMAL if enabled else tk.DISABLED)

    def set_on_field_add_callback(self, callback: Callable[[FieldType], None]) -> None:
        """Устанавливает callback для добавления поля.

        Args:
            callback: Функция(field_type: FieldType) -> None.
        """
        self._on_field_add = callback

    def set_on_validate_toggle_callback(
        self,
        callback: Callable[[bool], None],
    ) -> None:
        """Устанавливает callback для переключения валидации.

        Args:
            callback: Функция(enabled: bool) -> None.
        """
        self._on_validate_toggle = callback

    def set_on_snap_toggle_callback(self, callback: Callable[[bool], None]) -> None:
        """Устанавливает callback для переключения snap-to-grid.

        Args:
            callback: Функция(enabled: bool) -> None.
        """
        self._on_snap_toggle = callback

    def set_on_role_change_callback(
        self,
        callback: Callable[[WorkflowRole], None],
    ) -> None:
        """Устанавливает callback для смены роли.

        Args:
            callback: Функция(role: WorkflowRole) -> None.
        """
        self._on_role_change = callback
