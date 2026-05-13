"""Модуль принтера для FX Text Processor 3.

Transport layer для печати на Epson FX-890 через различные бэкенды:
- CUPS (Linux/Unix)
- Win32 API (Windows)
- File (все платформы, fallback)

Architecture:
    PrinterManager
        → CupsAdapter | WindowsAdapter | FileAdapter
        → Transport layer → Printer hardware

Example:
    >>> from src.printer import PrinterManager
    >>> manager = PrinterManager()
    >>> printers = manager.get_available_printers()
    >>> result = manager.print(b"data", "printer_id")
"""

from src.printer.cups_adapter import CupsAdapter, CupsAdapterError
from src.printer.file_adapter import FileAdapter, FileAdapterError
from src.printer.printer_manager import PrinterManager, PrinterManagerError
from src.printer.printer_protocol import (
    PrinterInfo,
    PrinterProtocol,
    PrinterStatus,
    PrintJobStatus,
    PrintResult,
)
from src.printer.windows_adapter import WindowsAdapter, WindowsAdapterError

__all__ = [
    # Protocol
    "PrinterProtocol",
    # Data classes
    "PrinterInfo",
    "PrinterStatus",
    "PrintResult",
    "PrintJobStatus",
    # Adapters
    "CupsAdapter",
    "CupsAdapterError",
    "WindowsAdapter",
    "WindowsAdapterError",
    "FileAdapter",
    "FileAdapterError",
    # Manager
    "PrinterManager",
    "PrinterManagerError",
]
