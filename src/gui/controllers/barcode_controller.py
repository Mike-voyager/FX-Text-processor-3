"""Контроллер для работы со штрих-кодами и QR-кодами.

Связывает GUI диалоги с сервисным слоем BarcodeService.
Обрабатывает выбор типа, настройки и вставку штрих-кодов.

Example:
    >>> from src.gui.controllers.barcode_controller import BarcodeController
    >>> controller = BarcodeController(parent_view)
    >>> controller.show_barcode_dialog()  # Открывает диалог выбора
    >>> controller.show_qr_dialog()         # Открывает диалог QR

Module: src/gui/controllers/barcode_controller.py
Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import messagebox
from typing import Any, Callable, Final, Optional, Protocol

from src.gui.dialogs.barcode_dialog import (
    BarcodeConflictDialog,
    BarcodeMode,
    BarcodeSelectionResult,
    BarcodeSettings,
    BarcodeSettingsPanel,
    BarcodeTypeSelector,
)
from src.gui.dialogs.qr_code_dialog import QRCodeResult, QRCodeSettingsDialog
from src.model.enums import BarcodeType

logger: Final = logging.getLogger(__name__)


# =============================================================================
# PROTOCOLS
# =============================================================================


class BarcodeViewProtocol(Protocol):
    """Протокол для View, поддерживающего вставку штрих-кодов."""

    def insert_barcode_at_cursor(
        self,
        barcode_type: str,
        data: str,
        mode: str,
        settings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Вставляет штрих-код в позицию курсора.

        Args:
            barcode_type: Тип штрих-кода.
            data: Данные для кодирования.
            mode: Режим ("hardware" или "software").
            settings: Дополнительные настройки.

        Returns:
            True если вставка успешна.
        """
        ...

    def insert_qr_at_cursor(
        self,
        data: str,
        settings: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Вставляет QR-код в позицию курсора.

        Args:
            data: Данные для кодирования.
            settings: Настройки QR-кода.

        Returns:
            True если вставка успешна.
        """
        ...

    def get_cursor_position(self) -> tuple[int, int]:
        """Возвращает текущую позицию курсора.

        Returns:
            Кортеж (line, column).
        """
        ...


# =============================================================================
# CONTROLLER
# =============================================================================


class BarcodeController:
    """Контроллер для управления штрих-кодами и QR-кодами.

    Управляет flow от открытия диалога до вставки в документ.
    Интегрируется с BarcodeService для валидации и генерации.

    Attributes:
        _parent: Родительский виджет для диалогов.
        _view: View для вставки штрих-кодов.
        _on_insert_callback: Callback после успешной вставки.

    Example:
        >>> controller = BarcodeController(parent_view=main_window)
        >>> controller.show_barcode_dialog()
    """

    def __init__(
        self,
        parent: tk.Widget,
        view: Optional[BarcodeViewProtocol] = None,
        on_insert: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        """Инициализация контроллера.

        Args:
            parent: Родительский виджет для диалогов.
            view: View для вставки штрих-кодов.
            on_insert: Callback после вставки (type, data).
        """
        self._parent: tk.Widget = parent
        self._view: Optional[BarcodeViewProtocol] = view
        self._on_insert_callback: Optional[Callable[[str, str], None]] = on_insert

        # Default settings
        self._last_barcode_settings: BarcodeSettings = BarcodeSettings()
        self._last_qr_settings: Optional[dict[str, Any]] = None

    def show_barcode_dialog(
        self,
        default_type: str = "",
        default_mode: BarcodeMode = BarcodeMode.SOFTWARE,
    ) -> Optional[BarcodeSelectionResult]:
        """Показывает диалог выбора типа штрих-кода.

        Args:
            default_type: Тип по умолчанию.
            default_mode: Режим по умолчанию.

        Returns:
            Результат выбора или None.
        """
        try:
            dialog = BarcodeTypeSelector(
                parent=self._parent,
                current_type=default_type,
                current_mode=default_mode,
            )
            result = dialog.show()

            if result:
                logger.info(f"Barcode selected: {result.barcode_type}, mode: {result.mode.name}")

                # Check for hardware/software conflict
                if self._check_hardware_conflict(result):
                    return self._handle_conflict(result)

                # Insert into document
                self._insert_barcode(result)

            return result

        except (OSError, ValueError) as e:
            logger.error(f"Error showing barcode dialog: {e}")
            messagebox.showerror(
                "Ошибка",
                f"Не удалось открыть диалог штрих-кода:\n{e}",
                parent=self._parent,
            )
            return None

    def show_barcode_settings_dialog(
        self,
        current_settings: Optional[BarcodeSettings] = None,
    ) -> Optional[BarcodeSettings]:
        """Показывает диалог настроек штрих-кода.

        Args:
            current_settings: Текущие настройки.

        Returns:
            Новые настройки или None.
        """
        settings = current_settings or self._last_barcode_settings

        # Create a dialog with settings panel
        dialog = tk.Toplevel(self._parent)
        dialog.title("⚙️ Настройки штрих-кода")
        dialog.geometry("400x400")
        dialog.transient(self._parent)  # type: ignore[call-overload]
        dialog.grab_set()

        # Settings panel
        panel = BarcodeSettingsPanel(dialog)  # type: ignore[arg-type]
        panel.set_settings(settings)
        panel.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Result
        result: Optional[BarcodeSettings] = None

        def on_ok() -> None:
            nonlocal result
            result = panel.get_settings()
            self._last_barcode_settings = result
            dialog.destroy()

        def on_cancel() -> None:
            dialog.destroy()

        # Buttons
        btn_frame = tk.Frame(dialog)
        btn_frame.pack(fill=tk.X, padx=20, pady=10)

        tk.Button(btn_frame, text="Отмена", command=on_cancel).pack(side=tk.RIGHT)
        tk.Button(btn_frame, text="OK", command=on_ok).pack(side=tk.RIGHT, padx=(0, 10))

        dialog.wait_window()
        return result

    def show_qr_dialog(
        self,
        default_data: str = "",
    ) -> Optional[QRCodeResult]:
        """Показывает диалог настроек QR-кода.

        Args:
            default_data: Данные по умолчанию.

        Returns:
            Результат настроек или None.
        """
        try:
            dialog = QRCodeSettingsDialog(
                parent=self._parent,
                default_data=default_data,
                default_settings=self._dict_to_qr_settings(self._last_qr_settings)
                if self._last_qr_settings
                else None,
            )
            result = dialog.show()

            if result:
                logger.info("QR code configured, inserting")
                self._last_qr_settings = self._qr_settings_to_dict(result.settings)
                self._insert_qr(result)

            return result

        except (OSError, ValueError) as e:
            logger.error(f"Error showing QR dialog: {e}")
            messagebox.showerror(
                "Ошибка",
                f"Не удалось открыть диалог QR:\n{e}",
                parent=self._parent,
            )
            return None

    def _check_hardware_conflict(
        self,
        result: BarcodeSelectionResult,
    ) -> bool:
        """Проверяет конфликт hardware/software.

        Args:
            result: Результат выбора.

        Returns:
            True если есть конфликт.
        """
        # Hardware types supported by FX-890
        hardware_types = {
            BarcodeType.EAN13.value,
            BarcodeType.EAN8.value,
            BarcodeType.CODE39.value,
            BarcodeType.CODE128.value,
            BarcodeType.UPCA.value,
        }

        barcode_type = result.barcode_type.lower()
        if result.mode == BarcodeMode.HARDWARE and barcode_type not in hardware_types:
            return True
        return False

    def _handle_conflict(
        self,
        result: BarcodeSelectionResult,
    ) -> Optional[BarcodeSelectionResult]:
        """Обрабатывает конфликт типа с помощью диалога.

        Args:
            result: Текущий результат с конфликтом.

        Returns:
            Исправленный результат или None.
        """
        hardware_types = {
            BarcodeType.EAN13.value,
            BarcodeType.EAN8.value,
            BarcodeType.CODE39.value,
            BarcodeType.CODE128.value,
        }

        barcode_type = result.barcode_type.lower()
        suggested = next(
            (t for t in hardware_types if t != barcode_type),
            BarcodeType.CODE128.value,
        )

        dialog = BarcodeConflictDialog(
            parent=self._parent,
            barcode_type=result.barcode_type,
            reason=f"{result.barcode_type} не поддерживается в Hardware mode",
            suggested_type=suggested,
        )

        success, choice = dialog.show()

        if not success:
            return None

        if choice == "software":
            # Switch to software mode
            return BarcodeSelectionResult(
                barcode_type=result.barcode_type,
                mode=BarcodeMode.SOFTWARE,
                data=result.data,
            )
        elif choice == "switch":
            # Switch to suggested type
            return BarcodeSelectionResult(
                barcode_type=suggested,
                mode=BarcodeMode.HARDWARE,
                data=result.data,
            )

        return None

    def _insert_barcode(self, result: BarcodeSelectionResult) -> bool:
        """Вставляет штрих-код в документ.

        Args:
            result: Результат выбора.

        Returns:
            True если вставка успешна.
        """
        try:
            mode_str = "hardware" if result.mode == BarcodeMode.HARDWARE else "software"

            settings = {
                "width_mm": self._last_barcode_settings.width_mm,
                "height_mm": self._last_barcode_settings.height_mm,
                "dpi": self._last_barcode_settings.dpi,
                "show_text": self._last_barcode_settings.show_text,
            }

            if self._view:
                success = self._view.insert_barcode_at_cursor(
                    barcode_type=result.barcode_type,
                    data=result.data,
                    mode=mode_str,
                    settings=settings,
                )
            else:
                # Fallback: just log
                logger.info(
                    f"Would insert barcode: {result.barcode_type}={result.data} in {mode_str} mode"
                )
                success = True

            if success and self._on_insert_callback:
                self._on_insert_callback(result.barcode_type, result.data)

            return success

        except (OSError, ValueError) as e:
            logger.error(f"Error inserting barcode: {e}")
            messagebox.showerror(
                "Ошибка",
                f"Не удалось вставить штрих-код:\n{e}",
                parent=self._parent,
            )
            return False

    def _insert_qr(self, result: QRCodeResult) -> bool:
        """Вставляет QR-код в документ.

        Args:
            result: Результат настроек.

        Returns:
            True если вставка успешна.
        """
        try:
            settings = {
                "error_correction": result.settings.error_correction,
                "version": result.settings.version,
                "box_size": result.settings.box_size,
                "border": result.settings.border,
            }

            if self._view:
                success = self._view.insert_qr_at_cursor(
                    data=result.settings.data,
                    settings=settings,
                )
            else:
                # Fallback: just log
                logger.info(f"Would insert QR: {result.settings.data[:50]}...")
                success = True

            if success and self._on_insert_callback:
                self._on_insert_callback("QR", result.settings.data)

            return success

        except (OSError, ValueError) as e:
            logger.error(f"Error inserting QR: {e}")
            messagebox.showerror(
                "Ошибка",
                f"Не удалось вставить QR-код:\n{e}",
                parent=self._parent,
            )
            return False

    def _dict_to_qr_settings(
        self,
        data: dict[str, Any],
    ) -> Optional[Any]:
        """Конвертирует dict в QRCodeSettings.

        Args:
            data: Словарь с настройками.

        Returns:
            QRCodeSettings или None.
        """
        try:
            from src.gui.dialogs.qr_code_dialog import QRCodeSettings

            return QRCodeSettings(
                data=data.get("data", ""),
                error_correction=data.get("error_correction", "M"),
                version=data.get("version", "auto"),
                box_size=data.get("box_size", 4),
                border=data.get("border", 4),
            )
        except (TypeError, ValueError):
            return None

    def _qr_settings_to_dict(
        self,
        settings: Any,
    ) -> dict[str, Any]:
        """Конвертирует QRCodeSettings в dict.

        Args:
            settings: Настройки QR.

        Returns:
            Словарь с настройками.
        """
        return {
            "data": settings.data,
            "error_correction": settings.error_correction,
            "version": settings.version,
            "box_size": settings.box_size,
            "border": settings.border,
        }

    def get_last_barcode_settings(self) -> BarcodeSettings:
        """Возвращает последние настройки штрих-кода.

        Returns:
            Последние настройки.
        """
        return self._last_barcode_settings

    def set_last_barcode_settings(self, settings: BarcodeSettings) -> None:
        """Устанавливает последние настройки штрих-кода.

        Args:
            settings: Новые настройки.
        """
        self._last_barcode_settings = settings


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================


def validate_barcode_data(barcode_type: str, data: str) -> tuple[bool, str]:
    """Валидирует данные для штрих-кода.

    Args:
        barcode_type: Тип штрих-кода.
        data: Данные для кодирования.

    Returns:
        Кортеж (valid, message).
    """
    if not data:
        return False, "Данные не могут быть пустыми"

    bt = barcode_type.lower()

    # EAN-13 validation
    if bt == BarcodeType.EAN13.value:
        if not data.isdigit():
            return False, "EAN-13 требует только цифры"
        if len(data) != 13:
            return False, f"EAN-13 требует ровно 13 цифр (получено {len(data)})"

    # EAN-8 validation
    elif bt == BarcodeType.EAN8.value:
        if not data.isdigit():
            return False, "EAN-8 требует только цифры"
        if len(data) != 8:
            return False, f"EAN-8 требует ровно 8 цифр (получено {len(data)})"

    # CODE39 validation
    elif bt == BarcodeType.CODE39.value:
        valid_chars = set("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%")
        invalid = set(data.upper()) - valid_chars
        if invalid:
            return False, f"CODE39 не поддерживает символы: {''.join(invalid)}"

    # UPC validation
    elif bt == BarcodeType.UPCA.value:
        if not data.isdigit():
            return False, "UPC требует только цифры"
        if len(data) != 12:
            return False, f"UPC-A требует ровно 12 цифр (получено {len(data)})"

    return True, ""


def format_barcode_data(barcode_type: str, data: str) -> str:
    """Форматирует данные для штрих-кода.

    Args:
        barcode_type: Тип штрих-кода.
        data: Исходные данные.

    Returns:
        Отформатированные данные.
    """
    bt = barcode_type.lower()

    # Remove spaces for numeric codes
    if bt in {BarcodeType.EAN13.value, BarcodeType.EAN8.value, BarcodeType.UPCA.value}:
        return data.replace(" ", "").replace("-", "")

    # Uppercase for CODE39
    if bt == BarcodeType.CODE39.value:
        return data.upper()

    return data
