"""RoleBadge — виджет отображения роли пользователя.

Предоставляет:
- Отображение текущей роли с иконкой и цветом
- Dropdown для смены роли
- Предупреждение о необходимости MFA

Colorа ролей:
    OPERATOR — синий (#3498db)
    EDITOR — зелёный (#2ecc71)
    SUPERVISOR — оранжевый (#f39c12)
    SIGNATORY — красный (#e74c3c)

Example:
    >>> from src.gui.security.mode_manager import ModeManager
    >>> mode_manager = ModeManager()
    >>> badge = RoleBadge(
    ...     parent=frame,
    ...     current_role=WorkflowRole.OPERATOR,
    ...     on_role_change=on_role_change,
    ...     mode_manager=mode_manager,
    ... )
    >>> badge.set_role(WorkflowRole.EDITOR)
    >>> badge.requires_mfa_for_role(WorkflowRole.SIGNATORY)
    True

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from enum import Enum
from typing import TYPE_CHECKING, Callable, Final, Optional

from src.gui.components.base.widget import BaseWidget

if TYPE_CHECKING:
    from src.gui.security.mode_manager import ModeManager


class WorkflowRole(Enum):
    """Роли внутри single-operator workflow.

    Attributes:
        OPERATOR: Оператор — заполнение формы.
        EDITOR: Редактор — редактирование/проверка.
        SUPERVISOR: Супервайзер — согласование.
        SIGNATORY: Подписант — подписание.
    """

    OPERATOR = "operator"
    EDITOR = "editor"
    SUPERVISOR = "supervisor"
    SIGNATORY = "signatory"


class RoleBadge(BaseWidget):
    """Виджет отображения текущей роли с возможностью смены.

    Отображает иконку, название роли и цветовой индикатор.
    Поддерживает dropdown для смены роли и показывает предупреждение,
    если для роли требуется MFA.

    Attributes:
        ROLE_COLORS: Colorа для каждой роли.
        ROLE_ICONS: Иконки для каждой роли.
        ROLE_NAMES: Локализованные названия ролей.

    Example:
        >>> badge = RoleBadge(
        ...     parent=frame,
        ...     current_role=WorkflowRole.OPERATOR,
        ...     on_role_change=on_role_change,
        ...     mode_manager=mode_manager,
        ... )
        >>> badge.mount(parent)
    """

    @property
    def widget(self) -> tk.Widget:
        """Возвращает tkinter widget для размещения.

        Returns:
            Корневой Frame бейджа.

        Raises:
            RuntimeError: Если виджет не смонтирован.
        """
        if self._main_frame is None:
            raise RuntimeError("RoleBadge not mounted")
        return self._main_frame

    # Colorа ролей (синий, зелёный, оранжевый, красный)
    ROLE_COLORS: Final[dict[WorkflowRole, str]] = {
        WorkflowRole.OPERATOR: "#3498db",  # Синий
        WorkflowRole.EDITOR: "#2ecc71",  # Зелёный
        WorkflowRole.SUPERVISOR: "#f39c12",  # Оранжевый
        WorkflowRole.SIGNATORY: "#e74c3c",  # Красный
    }

    # Иконки ролей
    ROLE_ICONS: Final[dict[WorkflowRole, str]] = {
        WorkflowRole.OPERATOR: "👤",
        WorkflowRole.EDITOR: "✏️",
        WorkflowRole.SUPERVISOR: "👁️",
        WorkflowRole.SIGNATORY: "🔏",
    }

    # Локализованные названия ролей
    ROLE_NAMES: Final[dict[WorkflowRole, str]] = {
        WorkflowRole.OPERATOR: "Оператор",
        WorkflowRole.EDITOR: "Редактор",
        WorkflowRole.SUPERVISOR: "Супервайзер",
        WorkflowRole.SIGNATORY: "Подписант",
    }

    # MFA требуется для привилегированных ролей
    PRIVILEGED_ROLES: Final[set[WorkflowRole]] = {
        WorkflowRole.SUPERVISOR,
        WorkflowRole.SIGNATORY,
    }

    def __init__(
        self,
        parent: tk.Widget,
        current_role: WorkflowRole = WorkflowRole.OPERATOR,
        on_role_change: Optional[Callable[[WorkflowRole], None]] = None,
        mode_manager: Optional["ModeManager"] = None,
    ) -> None:
        """Инициализация бейджа роли.

        Args:
            parent: Родительский Tkinter виджет.
            current_role: Начальная роль (по умолчанию OPERATOR).
            on_role_change: Callback при смене роли.
            mode_manager: ModeManager для проверки MFA.
        """
        super().__init__(widget_id="role_badge", controller=None)

        self._parent: tk.Widget = parent
        self._current_role: WorkflowRole = current_role
        self._on_role_change: Optional[Callable[[WorkflowRole], None]] = on_role_change
        self._mode_manager: Optional["ModeManager"] = mode_manager

        # Tk widgets
        self._main_frame: Optional[tk.Frame] = None
        self._icon_label: Optional[tk.Label] = None
        self._role_label: Optional[tk.Label] = None
        self._mfa_warning: Optional[tk.Label] = None
        self._dropdown_button: Optional[tk.Button] = None
        self._menu: Optional[tk.Menu] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter виджет бейджа роли.

        Args:
            parent: Родительский виджет.

        Returns:
            Созданный фрейм с бейджем роли.
        """
        self._main_frame = tk.Frame(parent, padx=5, pady=2)

        # Icon
        self._icon_label = tk.Label(
            self._main_frame,
            text=self.ROLE_ICONS[self._current_role],
            font=("TkDefaultFont", 12),
        )
        self._icon_label.pack(side=tk.LEFT, padx=(0, 5))

        # Role name
        role_color = self.ROLE_COLORS[self._current_role]
        self._role_label = tk.Label(
            self._main_frame,
            text=self.ROLE_NAMES[self._current_role],
            bg=role_color,
            fg="white",
            font=("TkDefaultFont", 9, "bold"),
            padx=10,
            pady=3,
            relief=tk.RAISED,
            borderwidth=1,
        )
        self._role_label.pack(side=tk.LEFT)

        # MFA warning indicator
        self._mfa_warning = tk.Label(
            self._main_frame,
            text="🔒",
            font=("TkDefaultFont", 10),
        )
        self._update_mfa_warning()

        # Dropdown button
        self._dropdown_button = tk.Button(
            self._main_frame,
            text="▼",
            font=("TkDefaultFont", 8),
            padx=3,
            pady=1,
            command=self._show_dropdown,
        )
        self._dropdown_button.pack(side=tk.LEFT, padx=(5, 0))

        return self._main_frame

    def _update_display(self) -> None:
        """Обновляет отображение бейджа при смене роли."""
        if self._icon_label is not None:
            self._icon_label.config(text=self.ROLE_ICONS[self._current_role])

        if self._role_label is not None:
            role_color = self.ROLE_COLORS[self._current_role]
            self._role_label.config(
                text=self.ROLE_NAMES[self._current_role],
                bg=role_color,
            )

        self._update_mfa_warning()

    def _update_mfa_warning(self) -> None:
        """Обновляет индикатор предупреждения MFA."""
        if self._mfa_warning is None:
            return

        if self._requires_mfa(self._current_role):
            self._mfa_warning.pack(side=tk.LEFT, padx=(5, 0))
        else:
            self._mfa_warning.pack_forget()

    def _requires_mfa(self, role: WorkflowRole) -> bool:
        """Проверяет, требуется ли MFA для роли.

        Args:
            role: Роль для проверки.

        Returns:
            True если для роли требуется MFA.
        """
        return role in self.PRIVILEGED_ROLES

    def _show_dropdown(self) -> None:
        """Показывает dropdown меню для выбора роли."""
        if self._menu is None:
            self._menu = tk.Menu(self._parent, tearoff=0)
            for role in WorkflowRole:
                mfa_indicator = " 🔒" if self._requires_mfa(role) else ""

                def make_handler(r: WorkflowRole = role) -> Callable[[], None]:
                    return lambda: self._on_role_selected(r)

                self._menu.add_command(
                    label=f"{self.ROLE_ICONS[role]} {self.ROLE_NAMES[role]}{mfa_indicator}",
                    command=make_handler(role),
                )

        if self._dropdown_button is not None:
            self._menu.post(
                self._dropdown_button.winfo_rootx(),
                self._dropdown_button.winfo_rooty() + self._dropdown_button.winfo_height(),
            )

    def _on_role_selected(self, role: WorkflowRole) -> None:
        """Обработчик выбора роли из dropdown.

        Args:
            role: Выбранная роль.
        """
        self._current_role = role
        self._update_display()

        if self._on_role_change is not None:
            self._on_role_change(role)

    def set_role(self, role: WorkflowRole) -> None:
        """Устанавливает текущую роль.

        Args:
            role: Новая роль.
        """
        self._current_role = role
        self._update_display()

    def get_role(self) -> WorkflowRole:
        """Возвращает текущую роль.

        Returns:
            Текущая роль.
        """
        return self._current_role

    def get_role_color(self) -> str:
        """Возвращает цвет текущей роли.

        Returns:
            HEX цвет роли.
        """
        return self.ROLE_COLORS[self._current_role]

    def _cleanup(self) -> None:
        """Очищает ресурсы перед демонтированием."""
        self._on_role_change = None
        self._mode_manager = None
        if self._menu is not None:
            try:
                self._menu.destroy()
            except tk.TclError:
                pass
            self._menu = None
        super()._cleanup()


__all__: list[str] = [
    "RoleBadge",
    "WorkflowRole",
]
