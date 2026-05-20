"""Диалоги подтверждения для FX Text Processor 3.

Предоставляет модальные диалоги для критических операций:
- SaveChangesDialog: подтверждение сохранения изменений перед закрытием
- ConfirmDialog: универсальный диалог подтверждения с выбором

Все диалогы наследуют BaseDialog для единообразного модального поведения.

Example:
    >>> result = SaveChangesDialog.show(parent=root)
    >>> if result.choice == "yes":
    ...     document.save()

Version: 1.0
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from tkinter import messagebox
from typing import Optional

from src.gui.dialogs.base_dialog import BaseDialog

# =============================================================================
# RESULT DATA CLASS
# =============================================================================


@dataclass(frozen=True)
class ConfirmResult:
    """Результат диалога подтверждения.

    Attributes:
        choice: Выбор пользователя ('yes', 'no', 'cancel').

    Example:
        >>> result = ConfirmResult(choice="yes")
        >>> assert result.choice == "yes"
    """

    choice: str


# =============================================================================
# SAVE CHANGES DIALOG
# =============================================================================


class SaveChangesDialog(BaseDialog):
    """Модальный диалог подтверждения сохранения изменений.

    Предлагает пользователю сохранить, не сохранить или отменить
    закрытие документа. Соответствует стандартному паттерну
    «Save changes? / Don't save / Cancel».

    Attributes:
        _result_data: Результат выбора пользователя.

    Example:
        >>> dialog = SaveChangesDialog(parent=root)
        >>> result = dialog.show()
        >>> if result and result.choice == "yes":
        ...     document.save()
    """

    def __init__(
        self,
        parent: tk.Misc,
        document_name: str = "",
    ) -> None:
        """Инициализация диалога подтверждения сохранения.

        Args:
            parent: Родительский виджет.
            document_name: Имя документа для отображения в заголовке.
        """
        super().__init__(parent, title="Сохранить изменения?", modal=True)

        self._document_name: str = document_name
        self._result_data: Optional[ConfirmResult] = None

        self._create_ui()

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс диалога."""
        self.geometry("400x180")
        self.resizable(False, False)

        # Основной фрейм
        main_frame = tk.Frame(self, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Текст сообщения
        doc_text = f" '{self._document_name}'" if self._document_name else ""
        message = (
            f"Документ{doc_text} был изменён.\n"
            "Сохранить изменения перед закрытием?"
        )

        msg_label = tk.Label(
            main_frame,
            text=message,
            font=("TkDefaultFont", 10),
            justify=tk.LEFT,
            wraplength=350,
        )
        msg_label.pack(anchor=tk.W, pady=(0, 20))

        # Кнопки
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(fill=tk.X)

        # Spacer
        tk.Frame(btn_frame).pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Cancel
        cancel_btn = tk.Button(
            btn_frame,
            text="Отмена",
            width=10,
            command=self._on_cancel,
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Don't save
        nosave_btn = tk.Button(
            btn_frame,
            text="Не сохранять",
            width=12,
            command=self._on_no,
        )
        nosave_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Save
        save_btn = tk.Button(
            btn_frame,
            text="Сохранить",
            width=10,
            command=self._on_yes,
        )
        save_btn.pack(side=tk.RIGHT)

    def _on_yes(self) -> None:
        """Обработчик кнопки «Сохранить»."""
        self._result_data = ConfirmResult(choice="yes")
        self.close(self._result_data)

    def _on_no(self) -> None:
        """Обработчик кнопки «Не сохранять»."""
        self._result_data = ConfirmResult(choice="no")
        self.close(self._result_data)

    def _on_cancel(self) -> None:
        """Обработчик кнопки «Отмена»."""
        self._result_data = ConfirmResult(choice="cancel")
        self.close(self._result_data)

    def show(self) -> Optional[ConfirmResult]:
        """Показывает диалог модально и возвращает результат.

        Returns:
            ConfirmResult с выбором пользователя или None.
        """
        super().show()
        return self._result_data

    @staticmethod
    def show_static(parent: Optional[tk.Misc] = None) -> str:
        """Статический метод для быстрого вызова через messagebox.

        Используется для обратной совместимости. Предпочтительный
        способ — создание экземпляра диалога и вызов show().

        Args:
            parent: Родительский виджет (опционально).

        Returns:
            'yes', 'no', или 'cancel'.
        """
        result = messagebox.askyesnocancel(
            "Сохранить изменения?",
            "Документ был изменён. Сохранить перед закрытием?",
            icon="warning",
            parent=parent,  # type: ignore[arg-type]
        )
        if result is None:
            return "cancel"
        return "yes" if result else "no"


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "SaveChangesDialog",
    "ConfirmResult",
]
