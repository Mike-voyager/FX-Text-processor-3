"""Диалог цифровой подписи для FX Text Processor 3.

Позволяет выбрать алгоритм подписи, подписать документ,
а также проверить существующую подпись.

Architecture:
    Dialog (View) → MainController (Controller) → CryptoService.sign_document()

Example:
    >>> from src.gui.dialogs.digital_signature_dialog import DigitalSignatureDialog
    >>> result = DigitalSignatureDialog.show_dialog(parent, document_id="doc-1")
    >>> if result:
    ...     print(result.algorithm, result.signature_hex[:16])

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import ttk, messagebox
from dataclasses import dataclass
from typing import Optional, Final

from src.gui.dialogs.base_dialog import BaseDialog
from src.security.crypto.core.registry import AlgorithmRegistry

logger: Final = logging.getLogger(__name__)

DIALOG_WIDTH: Final[int] = 480
DIALOG_HEIGHT: Final[int] = 320


@dataclass(frozen=True)
class DigitalSignatureResult:
    """Результат диалога цифровой подписи."""

    action: str  # "sign" или "verify"
    algorithm: str
    signature_hex: Optional[str] = None


class DigitalSignatureDialog(BaseDialog):
    """Модальный диалог управления цифровой подписью.

    Attributes:
        _document_id: ID активного документа.
        _action_var: Выбранное действие (sign/verify).
        _algorithm_var: Выбранный алгоритм.
        _algo_list: Список доступных алгоритмов подписи.
    """

    def __init__(
        self,
        parent: tk.Widget,
        document_id: Optional[str] = None,
        default_algorithm: str = "Ed25519",
    ) -> None:
        """Инициализация диалога цифровой подписи.

        Args:
            parent: Родительский виджет.
            document_id: ID документа для подписи/верификации.
            default_algorithm: Алгоритм по умолчанию.
        """
        super().__init__(parent, title="Цифровая подпись", modal=True)

        self._document_id = document_id
        self._action_var = tk.StringVar(master=self, value="sign")
        self._algorithm_var = tk.StringVar(master=self, value=default_algorithm)
        self._algo_list: list[str] = self._get_signature_algorithms()

        self._create_ui()
        self._setup_window()

    def _get_signature_algorithms(self) -> list[str]:
        """Возвращает список доступных алгоритмов подписи.

        Returns:
            Список ID алгоритмов.
        """
        try:
            registry = AlgorithmRegistry.get_instance()
            # Get all algorithms from the registry
            algorithms = []
            for algo_id in registry.list_ids():
                meta = registry.get_metadata(algo_id)
                if meta and meta.category == "signature":
                    algorithms.append(algo_id)
            return algorithms if algorithms else ["Ed25519", "Ed448", "RSA-PSS-2048", "RSA-PSS-4096"]
        except Exception:
            # Fallback if registry not available
            return ["Ed25519", "Ed448", "RSA-PSS-2048", "RSA-PSS-4096"]

    def _setup_window(self) -> None:
        """Настройка геометрии окна."""
        self.resizable(False, False)
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self._center_window()

    def _create_ui(self) -> None:
        """Создаёт элементы интерфейса."""
        frame = ttk.Frame(self, padding=15)
        frame.pack(fill="both", expand=True)

        # Action selection
        action_frame = ttk.LabelFrame(frame, text="Действие", padding=10)
        action_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)

        ttk.Radiobutton(action_frame, text="Подписать документ", variable=self._action_var, value="sign").pack(
            side="left", padx=10
        )
        ttk.Radiobutton(
            action_frame, text="Проверить подпись", variable=self._action_var, value="verify"
        ).pack(side="left", padx=10)

        # Algorithm selection
        ttk.Label(frame, text="Алгоритм подписи:").grid(row=1, column=0, sticky="w", pady=8)
        algo_combo = ttk.Combobox(
            frame,
            textvariable=self._algorithm_var,
            values=self._algo_list,
            state="readonly",
            width=30,
        )
        algo_combo.grid(row=1, column=1, sticky="ew", pady=8)

        # Info
        info_frame = ttk.LabelFrame(frame, text="Информация", padding=10)
        info_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)

        info_text = (
            "Ed25519 — быстрый, компактный (64 байт)\n"
            "RSA-PSS-4096 — классический, длинный ключ\n"
            "ML-DSA-65 — постквантовый (требует liboqs)"
        )
        ttk.Label(info_frame, text=info_text, justify="left").pack(anchor="w")

        # Document ID display
        if self._document_id:
            ttk.Label(frame, text=f"Документ: {self._document_id}").grid(
                row=3, column=0, columnspan=2, sticky="w", pady=5
            )

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=15)

        ttk.Button(btn_frame, text="Выполнить", command=self._on_execute, width=14).pack(
            side="left", padx=5
        )
        ttk.Button(btn_frame, text="Отмена", command=self._on_cancel, width=12).pack(side="left", padx=5)

        frame.columnconfigure(1, weight=1)

    def _on_execute(self) -> None:
        """Выполняет действие (подпись или верификацию)."""
        action = self._action_var.get()
        algorithm = self._algorithm_var.get()

        if not algorithm:
            messagebox.showwarning("Предупреждение", "Выберите алгоритм подписи", parent=self)
            return

        result = DigitalSignatureResult(action=action, algorithm=algorithm)
        self.close(result=result)

    def _on_cancel(self) -> None:
        """Отменяет и закрывает диалог."""
        self.close(result=None)

    def get_result(self) -> Optional[DigitalSignatureResult]:
        """Возвращает результат диалога.

        Returns:
            DigitalSignatureResult или None.
        """
        result = super().get_result()
        if isinstance(result, DigitalSignatureResult):
            return result
        return None

    @classmethod
    def show_dialog(
        cls,
        parent: tk.Widget,
        document_id: Optional[str] = None,
        default_algorithm: str = "Ed25519",
    ) -> Optional[DigitalSignatureResult]:
        """Показывает диалог и возвращает результат.

        Args:
            parent: Родительский виджет.
            document_id: ID документа.
            default_algorithm: Алгоритм по умолчанию.

        Returns:
            DigitalSignatureResult или None.
        """
        dialog = cls(parent=parent, document_id=document_id, default_algorithm=default_algorithm)
        dialog.wait_window()
        return dialog.get_result()
