# -*- coding: utf-8 -*-
"""Панель workflow для форм со статусами и переходами.

Предоставляет:
- FormWorkflowBar: панель отображения статуса и переходов

UI:
    [DRAFT] → [FILLED] → [VALIDATED] → [SIGNED] → [PRINTED] → [ARCHIVED]
      Gray      Blue        Orange        Green       Purple     Dark

Example:
    >>> bar = FormWorkflowBar(
    ...     parent=frame,
    ...     current_status=FormStatus.DRAFT,
    ...     on_transition=on_status_change,
    ...     mode_manager=ModeManager(),
    ... )
    >>> bar.request_transition(FormStatus.FILLED)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any, Callable, Final, Optional

from src.documents.constructor.form_status import FormStatus
from src.gui.components.base.widget import BaseWidget
from src.gui.security.mode_manager import ModeManager


class FormWorkflowBar(BaseWidget):
    """Панель workflow для форм со статусами и переходами.

    Отображает цепочку статусов и кнопки для разрешённых переходов.
    Поддерживает MFA-gated переходы для критичных операций.

    Attributes:
        STATUS_COLORS: Colorа для каждого статуса.
        STATUS_ORDER: Порядок статусов в цепочке.

    Example:
        >>> bar = FormWorkflowBar(
        ...     parent=frame,
        ...     current_status=FormStatus.DRAFT,
        ...     on_transition=on_status_change,
        ... )
        >>> bar.set_status(FormStatus.FILLED)
    """

    # Status colors
    STATUS_COLORS: Final[dict[FormStatus, str]] = {
        FormStatus.DRAFT: "#95a5a6",  # Gray
        FormStatus.FILLED: "#3498db",  # Blue
        FormStatus.VALIDATED: "#f39c12",  # Orange
        FormStatus.SIGNED: "#27ae60",  # Green
        FormStatus.PRINTED: "#9b59b6",  # Purple
        FormStatus.ARCHIVED: "#2c3e50",  # Dark blue
        FormStatus.REJECTED: "#e74c3c",  # Red
    }

    STATUS_ORDER: Final[list[FormStatus]] = [
        FormStatus.DRAFT,
        FormStatus.FILLED,
        FormStatus.VALIDATED,
        FormStatus.SIGNED,
        FormStatus.PRINTED,
        FormStatus.ARCHIVED,
    ]

    def __init__(
        self,
        parent: tk.Widget,
        current_status: FormStatus = FormStatus.DRAFT,
        on_transition: Optional[Callable[[FormStatus, FormStatus], None]] = None,
        mode_manager: Optional[ModeManager] = None,
    ) -> None:
        """Инициализация панели workflow.

        Args:
            parent: Родительский Tkinter виджет.
            current_status: Начальный статус формы.
            on_transition: Callback при изменении статуса.
            mode_manager: ModeManager для MFA проверок.
        """
        super().__init__(widget_id="form_workflow_bar", controller=None)

        self._parent: tk.Widget = parent
        self._current_status: FormStatus = current_status
        self._on_transition: Optional[Callable[[FormStatus, FormStatus], None]] = on_transition
        self._mode_manager: Optional[ModeManager] = mode_manager

        # Status chain display
        self._status_labels: dict[FormStatus, tk.Label] = {}
        self._status_arrows: list[tk.Label] = []

        # Transition buttons
        self._transition_buttons: list[tk.Button] = []
        self._transition_frame: Optional[tk.Frame] = None

        # Main frames
        self._main_frame: Optional[tk.Frame] = None
        self._status_frame: Optional[tk.Widget] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter виджет панели workflow.

        Args:
            parent: Родительский виджет.

        Returns:
            Созданный фрейм с панелью workflow.
        """
        self._main_frame = tk.Frame(parent, padx=10, pady=10)

        # Create status chain
        status_frame = self._create_status_indicator()
        self._status_frame = status_frame
        status_frame.pack(fill=tk.X, pady=(0, 10))

        # Create transition buttons
        transition_frame = self._create_transition_buttons()
        self._transition_frame = transition_frame  # type: ignore[assignment]
        transition_frame.pack(fill=tk.X)

        return self._main_frame

    def _create_status_indicator(self) -> tk.Widget:
        """Создаёт индикатор текущего статуса.

        Returns:
            Фрейм с цепочкой статусов.

        UI:
            [DRAFT] → [FILLED] → [VALIDATED] → [SIGNED] → [PRINTED] → [ARCHIVED]
        """
        if self._main_frame is None:
            raise RuntimeError("Main frame not created")

        frame = tk.Frame(self._main_frame)

        for i, status in enumerate(self.STATUS_ORDER):
            # Status label
            color = self.STATUS_COLORS[status]
            is_current = status == self._current_status

            label = tk.Label(
                frame,
                text=status.localized_name,
                bg=color if is_current else "#ecf0f1",
                fg="white" if is_current else "#7f8c8d",
                font=("TkDefaultFont", 9, "bold" if is_current else "normal"),
                padx=10,
                pady=5,
                relief=tk.RAISED if is_current else tk.FLAT,
                borderwidth=2 if is_current else 1,
            )
            label.pack(side=tk.LEFT, padx=2)
            self._status_labels[status] = label

            # Arrow (except for last item)
            if i < len(self.STATUS_ORDER) - 1:
                arrow = tk.Label(
                    frame,
                    text="→",
                    font=("TkDefaultFont", 10),
                    fg="#bdc3c7",
                )
                arrow.pack(side=tk.LEFT)
                self._status_arrows.append(arrow)

        return frame

    def _create_transition_buttons(self) -> tk.Widget:
        """Создаёт кнопки переходов.

        Returns:
            Фрейм с кнопками для разрешённых переходов.
        """
        if self._main_frame is None:
            raise RuntimeError("Main frame not created")

        frame = tk.Frame(self._main_frame)

        allowed = self.get_allowed_transitions()

        for status in allowed:
            btn_text = self._get_transition_button_text(status)
            btn_color = self.STATUS_COLORS[status]

            target_status: FormStatus = status  # для closure
            btn = tk.Button(
                frame,
                text=btn_text,
                bg=btn_color,
                fg="white",
                font=("TkDefaultFont", 9, "bold"),
                padx=15,
                pady=5,
                command=lambda s=target_status: self._on_transition_button_click(s),  # type: ignore[misc]
            )
            btn.pack(side=tk.LEFT, padx=5)
            self._transition_buttons.append(btn)

        # Add reject button if applicable
        if FormStatus.REJECTED in self._get_allowed_transitions_internal():
            _reject_status: FormStatus = FormStatus.REJECTED
            reject_btn = tk.Button(
                frame,
                text="Reject",
                bg=self.STATUS_COLORS[FormStatus.REJECTED],
                fg="white",
                font=("TkDefaultFont", 9, "bold"),
                padx=15,
                pady=5,
                command=lambda: self._on_transition_button_click(_reject_status),
            )
            reject_btn.pack(side=tk.LEFT, padx=5)
            self._transition_buttons.append(reject_btn)

        # If no transitions available, show message
        if not allowed and FormStatus.REJECTED not in self._get_allowed_transitions_internal():
            msg = tk.Label(
                frame,
                text="No available transitions",
                fg="#7f8c8d",
                font=("TkDefaultFont", 9, "italic"),
            )
            msg.pack(side=tk.LEFT, padx=5)

        return frame

    def _get_transition_button_text(self, new_status: FormStatus) -> str:
        """Возвращает текст кнопки перехода.

        Args:
            new_status: Целевой статус.

        Returns:
            Текст для кнопки перехода.
        """
        texts: dict[FormStatus, str] = {
            FormStatus.DRAFT: "Rework",
            FormStatus.FILLED: "Fill",
            FormStatus.VALIDATED: "Validate",
            FormStatus.SIGNED: "Sign",
            FormStatus.PRINTED: "Print",
            FormStatus.ARCHIVED: "Archive",
            FormStatus.REJECTED: "Reject",
        }
        return texts.get(new_status, new_status.localized_name)

    def _on_transition_button_click(self, new_status: FormStatus) -> None:
        """Обработчик нажатия кнопки перехода.

        Args:
            new_status: Целевой статус.
        """
        self.request_transition(new_status)

    def set_status(self, status: FormStatus) -> None:
        """Устанавливает текущий статус.

        Args:
            status: Новый статус формы.
        """
        old_status = self._current_status
        self._current_status = status
        self._update_display()

        if self._on_transition is not None:
            self._on_transition(old_status, status)

    def get_current_status(self) -> FormStatus:
        """Возвращает текущий статус.

        Returns:
            Текущий статус формы.
        """
        return self._current_status

    def get_allowed_transitions(self) -> list[FormStatus]:
        """Возвращает разрешённые переходы.

        Rules:
            - DRAFT → [FILLED]
            - FILLED → [VALIDATED, REJECTED]
            - VALIDATED → [SIGNED, REJECTED]
            - SIGNED → [PRINTED]
            - PRINTED → [ARCHIVED]
            - REJECTED → [DRAFT]

        Returns:
            Список допустимых целевых статусов (без REJECTED).
        """
        return self._get_allowed_transitions_internal()

    def _get_allowed_transitions_internal(self) -> list[FormStatus]:
        """Внутренний метод для получения разрешённых переходов."""
        transitions: dict[FormStatus, list[FormStatus]] = {
            FormStatus.DRAFT: [FormStatus.FILLED],
            FormStatus.FILLED: [FormStatus.VALIDATED, FormStatus.REJECTED],
            FormStatus.VALIDATED: [FormStatus.SIGNED, FormStatus.REJECTED],
            FormStatus.SIGNED: [FormStatus.PRINTED],
            FormStatus.PRINTED: [FormStatus.ARCHIVED],
            FormStatus.REJECTED: [FormStatus.DRAFT],
            FormStatus.ARCHIVED: [],
        }
        return transitions.get(self._current_status, [])

    def can_transition_to(self, new_status: FormStatus) -> bool:
        """Проверяет возможность перехода.

        Args:
            new_status: Целевой статус.

        Returns:
            True если переход разрешён.
        """
        return new_status in self.get_allowed_transitions()

    def request_transition(
        self,
        new_status: FormStatus,
        mfa_credentials: Optional[dict[str, str]] = None,
    ) -> bool:
        """Запрашивает переход статуса.

        Args:
            new_status: Целевой статус.
            mfa_credentials: MFA credentials (required for certain transitions).

        Returns:
            True если переход успешен.
        """
        if not self.can_transition_to(new_status):
            return False

        # Check if MFA required
        if self._is_mfa_required(new_status) and not mfa_credentials:
            # Show MFA dialog
            return self._show_mfa_dialog(new_status)

        # Execute transition
        self.set_status(new_status)
        return True

    def _is_mfa_required(self, new_status: FormStatus) -> bool:
        """Проверяет требование MFA для перехода.

        Args:
            new_status: Целевой статус.

        Returns:
            True если требуется MFA.

        MFA required for:
            - VALIDATED→SIGNED
            - SIGNED→PRINTED
            - PRINTED→ARCHIVED
        """
        mfa_transitions: set[tuple[FormStatus, FormStatus]] = {
            (FormStatus.VALIDATED, FormStatus.SIGNED),
            (FormStatus.SIGNED, FormStatus.PRINTED),
            (FormStatus.PRINTED, FormStatus.ARCHIVED),
        }
        return (self._current_status, new_status) in mfa_transitions

    def _show_mfa_dialog(self, target_status: FormStatus) -> bool:
        """Показывает улучшенный MFA диалог с выбором метода.

        Args:
            target_status: Целевой статус.

        Returns:
            True если MFA пройден и переход выполнен.
        """
        dialog = tk.Toplevel(self._parent)
        dialog.title("🔒 Подтверждение MFA")
        dialog.geometry("350x280")
        dialog.transient(self._parent.winfo_toplevel())
        try:
            dialog.grab_set()
        except tk.TclError:
            pass
        dialog.resizable(False, False)

        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (350 // 2)
        y = (dialog.winfo_screenheight() // 2) - (280 // 2)
        dialog.geometry(f"350x280+{x}+{y}")

        result = {"success": False}
        selected_method = tk.StringVar(value="totp")

        # Header
        header_frame = tk.Frame(dialog, bg="#2c3e50", padx=10, pady=10)
        header_frame.pack(fill=tk.X)
        transition_text = (
            f"Transition: {self._current_status.localized_name} → {target_status.localized_name}"
        )
        tk.Label(
            header_frame,
            text=transition_text,
            fg="white",
            bg="#2c3e50",
            font=("TkDefaultFont", 10, "bold"),
        ).pack()
        tk.Label(
            header_frame,
            text="Multi-factor authentication required",
            fg="#ecf0f1",
            bg="#2c3e50",
            font=("TkDefaultFont", 9),
        ).pack()

        # Method selection
        method_frame = tk.LabelFrame(dialog, text="Select method", padx=10, pady=10)
        method_frame.pack(fill=tk.X, padx=10, pady=10)

        methods = [
            ("fido2", "🔐 FIDO2 Security Key", "Коснитесь ключа для подтверждения"),
            ("totp", "📱 TOTP Authenticator", "Введите 6-значный код"),
            ("backup", "🔑 Резервный код", "Введите одноразовый код"),
        ]

        for method, label, _desc in methods:
            rb = tk.Radiobutton(
                method_frame,
                text=label,
                variable=selected_method,
                value=method,
                font=("TkDefaultFont", 9),
                anchor=tk.W,
            )
            rb.pack(fill=tk.X, pady=2)

        # Dynamic input frame
        input_frame = tk.Frame(dialog, padx=20, pady=5)
        input_frame.pack(fill=tk.X)

        input_label = tk.Label(input_frame, text="TOTP Code:", font=("TkDefaultFont", 9))
        input_label.pack(side=tk.LEFT)

        input_entry = tk.Entry(input_frame, width=15, font=("TkDefaultFont", 10))
        input_entry.pack(side=tk.LEFT, padx=5)
        input_entry.focus_set()

        status_label = tk.Label(dialog, text="", fg="red", font=("TkDefaultFont", 9))
        status_label.pack()

        def update_input_field(*args: Any) -> None:
            """Обновляет поле ввода при смене метода."""
            method = selected_method.get()
            input_entry.delete(0, tk.END)

            if method == "fido2":
                input_label.config(text="Status:")
                input_entry.config(state="readonly")
                input_entry.insert(0, "Waiting for touch...")
                # В реальности здесь был бы вызов FIDO2 API
            elif method == "totp":
                input_label.config(text="TOTP code:")
                input_entry.config(state="normal", show="")
            elif method == "backup":
                input_label.config(text="Code:")
                input_entry.config(state="normal", show="*")

        selected_method.trace_add("write", update_input_field)

        def on_confirm() -> None:
            """Обработчик подтверждения."""
            method = selected_method.get()
            token = input_entry.get()

            # Валидация
            if method == "fido2":
                # Симуляция FIDO2
                success = True
            elif method == "totp":
                if len(token) != 6 or not token.isdigit():
                    status_label.config(text="❌ TOTP must be 6 digits")
                    return
                success = True  # Симуляция
            elif method == "backup":
                if len(token) < 8:
                    status_label.config(text="❌ Code too short")
                    return
                success = True  # Симуляция

            if success:
                result["success"] = True
                dialog.destroy()
                self.set_status(target_status)

        def on_cancel() -> None:
            """Обработчик отмены."""
            result["success"] = False
            dialog.destroy()

        # Buttons
        btn_frame = tk.Frame(dialog, pady=15)
        btn_frame.pack()
        tk.Button(
            btn_frame,
            text="✓ Confirm",
            command=on_confirm,
            bg="#27ae60",
            fg="white",
            font=("TkDefaultFont", 9, "bold"),
            padx=15,
        ).pack(side=tk.LEFT, padx=5)
        tk.Button(
            btn_frame,
            text="✗ Cancel",
            command=on_cancel,
            font=("TkDefaultFont", 9),
            padx=15,
        ).pack(side=tk.LEFT, padx=5)

        # Initial update
        update_input_field()

        dialog.wait_window()
        return result["success"]

    def _update_display(self) -> None:
        """Обновляет отображение статуса и кнопок."""
        # Update status labels
        for status, label in self._status_labels.items():
            color = self.STATUS_COLORS[status]
            is_current = status == self._current_status

            label.config(
                bg=color if is_current else "#ecf0f1",
                fg="white" if is_current else "#7f8c8d",
                font=("TkDefaultFont", 9, "bold" if is_current else "normal"),
                relief=tk.RAISED if is_current else tk.FLAT,
                borderwidth=2 if is_current else 1,
            )

        # Clear and recreate transition buttons
        if self._transition_frame is not None:
            for widget in self._transition_frame.winfo_children():
                widget.destroy()
            self._transition_buttons.clear()

            allowed = self.get_allowed_transitions()

            for _status in allowed:
                btn_text = self._get_transition_button_text(_status)
                btn_color = self.STATUS_COLORS[_status]
                _target_status: FormStatus = _status

                btn = tk.Button(
                    self._transition_frame,
                    text=btn_text,
                    bg=btn_color,
                    fg="white",
                    font=("TkDefaultFont", 9, "bold"),
                    padx=15,
                    pady=5,
                    command=lambda s=_target_status: self._on_transition_button_click(s),  # type: ignore[misc]
                )
                btn.pack(side=tk.LEFT, padx=5)
                self._transition_buttons.append(btn)

            # Add reject button if applicable
            if FormStatus.REJECTED in self._get_allowed_transitions_internal():
                _reject_status: FormStatus = FormStatus.REJECTED
                reject_btn = tk.Button(
                    self._transition_frame,
                    text="Reject",
                    bg=self.STATUS_COLORS[FormStatus.REJECTED],
                    fg="white",
                    font=("TkDefaultFont", 9, "bold"),
                    padx=15,
                    pady=5,
                    command=lambda: self._on_transition_button_click(_reject_status),
                )
                reject_btn.pack(side=tk.LEFT, padx=5)
                self._transition_buttons.append(reject_btn)

            # If no transitions available, show message
            if not allowed and FormStatus.REJECTED not in self._get_allowed_transitions_internal():
                msg = tk.Label(
                    self._transition_frame,
                    text="No available transitions",
                    fg="#7f8c8d",
                    font=("TkDefaultFont", 9, "italic"),
                )
                msg.pack(side=tk.LEFT, padx=5)

    def wipe_sensitive_data(self) -> None:
        """Очищает sensitive данные.

        Security:
            Очищает все внутренние ссылки и callback'и.
        """
        self._on_transition = None
        self._mode_manager = None

    def _cleanup(self) -> None:
        """Очищает ресурсы перед демонтированием."""
        self._status_labels.clear()
        self._status_arrows.clear()
        self._transition_buttons.clear()
        super()._cleanup()


__all__: list[str] = [
    "FormWorkflowBar",
]
