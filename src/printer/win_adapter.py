"""Windows адаптер принтера.

Интеграция с Windows Print Spooler через Win32 API.
Использует pywin32 для доступа к принтеру.

Module: src/printer/win_adapter.py
"""

from __future__ import annotations

import logging
from typing import List, Optional

from src.printer.base_adapter import BasePrinterAdapter, PrinterInfo
from src.printer.protocol import (
    PrinterCapabilities,
    PrinterStatus,
)

logger = logging.getLogger(__name__)

# Флаг для проверки доступности Windows API
try:
    import win32print

    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False
    win32print = None


# ---------------------------------------------------------------------------
# Windows адаптер
# ---------------------------------------------------------------------------


class WinPrinterAdapter(BasePrinterAdapter):
    """Windows адаптер принтера.

    Интеграция с Windows Print Spooler через Win32 API.
    Требует pywin32.
    """

    def __init__(self, printer_name: Optional[str] = None) -> None:
        """Инициализирует Windows адаптер."""
        self._printer_name = printer_name
        self._printer_handle = None

        printer_info = self._get_printer_info(printer_name)
        super().__init__(printer_info)

        if not WIN32_AVAILABLE:
            logger.warning("pywin32 не установлен. Windows принтеры недоступны.")

    def _get_printer_info(self, printer_name: Optional[str]) -> PrinterInfo:
        """Получает информацию о принтере."""
        if not WIN32_AVAILABLE:
            return PrinterInfo(
                name=printer_name or "default",
                model="Unknown",
                connection_type="win32",
                is_online=False,
            )

        try:
            if not printer_name:
                printer_name = win32print.GetDefaultPrinter()

            handle = win32print.OpenPrinter(printer_name)
            info = win32print.GetPrinter(handle, 2)
            win32print.ClosePrinter(handle)

            return PrinterInfo(
                name=printer_name,
                model=info.get("pDriverName", "Unknown"),
                connection_type="win32",
                port=info.get("pPortName", ""),
                is_online=True,
            )

        except (OSError, TypeError, ValueError) as exc:
            logger.error("Ошибка получения информации о принтере: %s", exc)
            return PrinterInfo(
                name=printer_name or "default",
                connection_type="win32",
                is_online=False,
            )

    def get_name(self) -> str:
        """Возвращает имя принтера."""
        return self._printer_name or "default"

    def get_capabilities(self) -> PrinterCapabilities:
        """Возвращает возможности принтера."""
        return PrinterCapabilities(
            name=self._printer_info.name,
            model=self._printer_info.model,
            supports_escp=True,
            max_width=136,
            max_lines=66,
        )

    def is_available(self) -> bool:
        """Проверяет доступность принтера."""
        if not WIN32_AVAILABLE:
            return False

        try:
            handle = win32print.OpenPrinter(self.get_name())
            win32print.ClosePrinter(handle)
            return True
        except (OSError, TypeError, ValueError) as exc:
            logger.debug("Failed to check printer availability: %s", exc)
            return False

    def _send_data(self, data: bytes) -> bool:
        """Отправляет данные на принтер."""
        if not WIN32_AVAILABLE:
            self._set_error("pywin32 не установлен")
            return False

        try:
            handle = win32print.OpenPrinter(self.get_name())

            win32print.StartDocPrinter(handle, 1, ("ESC/P Document", None, "RAW"))

            try:
                win32print.StartPagePrinter(handle)
                win32print.WritePrinter(handle, data)
                win32print.EndPagePrinter(handle)
            finally:
                win32print.EndDocPrinter(handle)
                win32print.ClosePrinter(handle)

            logger.info("Данные отправлены на принтер %s", self.get_name())
            return True

        except (OSError, TypeError, ValueError) as exc:
            self._set_error(f"Ошибка отправки: {exc}")
            return False

    def _get_printer_status(self) -> PrinterStatus:
        """Возвращает статус принтера."""
        if not WIN32_AVAILABLE:
            return PrinterStatus.UNKNOWN

        try:
            handle = win32print.OpenPrinter(self.get_name())
            info = win32print.GetPrinter(handle, 2)
            win32print.ClosePrinter(handle)

            status = info.get("Status", 0)

            if status & 0x00000080:  # OFFLINE
                return PrinterStatus.OFFLINE
            if status & 0x00000002:  # ERROR
                return PrinterStatus.ERROR
            if status & 0x00000008:  # PAPER_JAM
                return PrinterStatus.PAPER_JAM
            if status & 0x00000010:  # PAPER_OUT
                return PrinterStatus.OUT_OF_PAPER

            return PrinterStatus.READY

        except (OSError, TypeError, ValueError) as exc:
            logger.debug("Failed to get printer status: %s", exc)
            return PrinterStatus.UNKNOWN

    @staticmethod
    def discover_printers() -> List[PrinterInfo]:
        """Обнаруживает принтеры через Win32 API."""
        printers: List[PrinterInfo] = []

        if not WIN32_AVAILABLE:
            return printers

        try:
            printer_enum = win32print.EnumPrinters(
                win32print.PRINTER_ENUM_LOCAL | win32print.PRINTER_ENUM_CONNECTIONS,
                None,
                2,
            )

            for printer in printer_enum:
                name = printer.get("pPrinterName", "Unknown")
                model = printer.get("pDriverName", "Unknown")

                printers.append(
                    PrinterInfo(
                        name=name,
                        model=model,
                        connection_type="win32",
                        is_online=True,
                    )
                )

            logger.info("Обнаружено %d принтеров Windows", len(printers))

        except (OSError, TypeError, ValueError) as exc:
            logger.error("Ошибка обнаружения принтеров: %s", exc)

        return printers


__all__ = [
    "WinPrinterAdapter",
    "WIN32_AVAILABLE",
]
