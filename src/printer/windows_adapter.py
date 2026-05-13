"""Windows адаптер для печати через Win32 API.

Использует ctypes для вызова функций Windows API:
- OpenPrinter, ClosePrinter
- StartDocPrinter, EndDocPrinter
- StartPagePrinter, EndPagePrinter
- WritePrinter

Поддерживает raw режим для ESC/P данных.
"""

from __future__ import annotations

import logging
import platform
import struct
from datetime import datetime
from typing import Any, ClassVar, List, Optional, Tuple

from src.printer.printer_protocol import (
    PrinterInfo,
    PrinterProtocol,
    PrinterState,
    PrinterStatus,
    PrintJobStatus,
    PrintOptions,
    PrintResult,
)

# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------


class WindowsAdapterError(Exception):
    """Базовая ошибка Windows адаптера."""

    pass


class Win32NotAvailableError(WindowsAdapterError):
    """Win32 API не доступна (не Windows)."""

    pass


class Win32PrintError(WindowsAdapterError):
    """Ошибка при печати через Win32 API."""

    pass


class Win32PrinterNotFoundError(WindowsAdapterError):
    """Принтер не найден."""

    pass


# -----------------------------------------------------------------------------
# Windows API Constants
# -----------------------------------------------------------------------------

# Статусы принтера
PRINTER_STATUS_PAUSED = 0x00000001
PRINTER_STATUS_ERROR = 0x00000002
PRINTER_STATUS_OFFLINE = 0x00000080
PRINTER_STATUS_PRINTING = 0x00000400
PRINTER_STATUS_PROCESSING = 0x00004000

PRINTER_ATTRIBUTE_DEFAULT = 0x00000004


# -----------------------------------------------------------------------------
# Windows Adapter
# -----------------------------------------------------------------------------


class WindowsAdapter:
    """Адаптер печати через Win32 API (Windows).

    Использует ctypes для прямого вызова Windows API функций.
    Поддерживает raw печать для ESC/P данных.

    Attributes:
        _logger: Логгер
        _winspool: Модуль winspool.drv
        _kernel32: Модуль kernel32.dll

    Example:
        >>> adapter = WindowsAdapter()
        >>> if adapter.is_available():
        ...     printers = adapter.get_printers()
        ...     result = adapter.print_data(b"ESC/P data", "FX-890")
    """

    def __init__(self) -> None:
        """Инициализирует Windows адаптер.

        Загружает необходимые DLL если доступны.
        """
        self._logger = logging.getLogger(__name__)
        self._winspool: Optional[Any] = None
        self._kernel32: Optional[Any] = None
        self._load_win32_apis()

    def _load_win32_apis(self) -> None:
        """Загружает Win32 API через ctypes."""
        if platform.system() != "Windows":
            return

        try:
            import ctypes as _ctypes

            # Загружаем winspool.drv
            self._winspool = _ctypes.WinDLL("winspool.drv")  # type: ignore[attr-defined]
            self._kernel32 = _ctypes.WinDLL("kernel32.dll")  # type: ignore[attr-defined]

            self._logger.debug("Win32 API loaded successfully")

        except Exception as e:
            self._logger.warning(f"Failed to load Win32 API: {e}")

    def is_available(self) -> bool:
        """Проверяет доступность Win32 API.

        Returns:
            True если Windows и winspool.drv загружен
        """
        if platform.system() != "Windows":
            return False
        return self._winspool is not None

    def get_adapter_name(self) -> str:
        """Возвращает имя адаптера.

        Returns:
            "win32"
        """
        return "win32"

    def _assert_win32_available(self) -> Tuple[Any, Any]:
        """Проверяет доступность Win32 API и возвращает модули.

        Returns:
            Кортеж (winspool, kernel32)

        Raises:
            Win32NotAvailableError: Если Win32 API не доступен
        """
        if not self.is_available():
            raise Win32NotAvailableError("Win32 API не доступен")
        assert self._winspool is not None
        assert self._kernel32 is not None
        return self._winspool, self._kernel32

    def get_printers(self) -> List[PrinterInfo]:
        """Возвращает список Windows принтеров.

        Использует EnumPrinters из winspool.drv.

        Returns:
            Список PrinterInfo объектов

        Raises:
            Win32NotAvailableError: Если Win32 API не доступен
        """
        import ctypes
        from ctypes import wintypes

        winspool, kernel32 = self._assert_win32_available()
        printers: List[PrinterInfo] = []

        # Константы
        PRINTER_ENUM_LOCAL = 0x00000002
        PRINTER_ENUM_CONNECTIONS = 0x00000001
        LEVEL = 2

        pcb_needed = wintypes.DWORD(0)
        pc_returned = wintypes.DWORD(0)

        # Первый вызов для получения размера буфера
        winspool.EnumPrintersW(
            PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
            None,
            LEVEL,
            None,
            0,
            ctypes.byref(pcb_needed),
            ctypes.byref(pc_returned),
        )

        if pcb_needed.value == 0:
            return printers

        # Выделяем буфер
        buffer = ctypes.create_string_buffer(pcb_needed.value)

        # Второй вызов для получения данных
        result = winspool.EnumPrintersW(
            PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS,
            None,
            LEVEL,
            buffer,
            pcb_needed.value,
            ctypes.byref(pcb_needed),
            ctypes.byref(pc_returned),
        )

        if result == 0:
            error = kernel32.GetLastError()
            self._logger.warning(f"EnumPrinters failed: {error}")
            return printers

        # Определяем структуру PRINTER_INFO_2
        class PRINTER_INFO_2_STRUCT(ctypes.Structure):
            _fields_: ClassVar[List[Tuple[str, Any]]] = [
                ("pServerName", wintypes.LPWSTR),
                ("pPrinterName", wintypes.LPWSTR),
                ("pShareName", wintypes.LPWSTR),
                ("pPortName", wintypes.LPWSTR),
                ("pDriverName", wintypes.LPWSTR),
                ("pComment", wintypes.LPWSTR),
                ("pLocation", wintypes.LPWSTR),
                ("pDevMode", wintypes.LPVOID),
                ("pSepFile", wintypes.LPWSTR),
                ("pPrintProcessor", wintypes.LPWSTR),
                ("pDatatype", wintypes.LPWSTR),
                ("pParameters", wintypes.LPWSTR),
                ("pSecurityDescriptor", wintypes.LPVOID),
                ("Attributes", wintypes.DWORD),
                ("Priority", wintypes.DWORD),
                ("DefaultPriority", wintypes.DWORD),
                ("StartTime", wintypes.DWORD),
                ("UntilTime", wintypes.DWORD),
                ("Status", wintypes.DWORD),
                ("cJobs", wintypes.DWORD),
                ("AveragePPM", wintypes.DWORD),
            ]

        # Читаем данные принтеров
        pInfo = ctypes.cast(buffer, ctypes.POINTER(PRINTER_INFO_2_STRUCT))

        for i in range(pc_returned.value):
            info = pInfo[i]

            # Определяем доступность по статусу
            is_available = (info.Status & PRINTER_STATUS_OFFLINE) == 0
            is_available = is_available and (info.Status & PRINTER_STATUS_ERROR) == 0

            # Проверяем является ли принтер по умолчанию
            is_default = (info.Attributes & PRINTER_ATTRIBUTE_DEFAULT) != 0

            printer = PrinterInfo(
                printer_id=f"win32:{info.pPrinterName}",
                name=info.pPrinterName,
                adapter_type="win32",
                is_default=is_default,
                is_available=is_available,
                location=info.pLocation,
                description=info.pComment,
            )
            printers.append(printer)

        return printers

    def get_default_printer(self) -> Optional[str]:
        """Возвращает имя принтера по умолчанию.

        Returns:
            Имя принтера или None
        """
        import ctypes
        from ctypes import wintypes

        winspool, kernel32 = self._assert_win32_available()

        # Буфер для имени
        buffer_size = wintypes.DWORD(256)
        buffer = ctypes.create_unicode_buffer(256)

        result = winspool.GetDefaultPrinterW(
            buffer,
            ctypes.byref(buffer_size),
        )

        if result:
            return buffer.value

        return None

    def get_status(self, printer_name: str) -> PrinterStatus:
        """Возвращает статус Windows принтера.

        Args:
            printer_name: Имя принтера

        Returns:
            PrinterStatus объект

        Raises:
            Win32NotAvailableError: Если Win32 API не доступен
        """
        import ctypes
        from ctypes import wintypes

        winspool, kernel32 = self._assert_win32_available()

        # Открываем принтер
        phPrinter = wintypes.HANDLE()
        result = winspool.OpenPrinterW(
            printer_name,
            ctypes.byref(phPrinter),
            None,
        )

        if result == 0:
            error = kernel32.GetLastError()
            return PrinterStatus(
                state=PrinterState.UNKNOWN,
                message=f"Не удалось открыть принтер: {error}",
                is_accepting_jobs=False,
            )

        try:
            # Получаем информацию о принтере
            pcb_needed = wintypes.DWORD(0)

            winspool.GetPrinterW(
                phPrinter,
                2,
                None,
                0,
                ctypes.byref(pcb_needed),
            )

            if pcb_needed.value > 0:
                buffer = ctypes.create_string_buffer(pcb_needed.value)

                result = winspool.GetPrinterW(
                    phPrinter,
                    2,
                    buffer,
                    pcb_needed.value,
                    ctypes.byref(pcb_needed),
                )

                if result:
                    # Парсим статус - оффсеты в структуре PRINTER_INFO_2
                    # Status находится по оффсету ~52 байта
                    status_offset = 52
                    status = struct.unpack_from("I", buffer, status_offset)[0]

                    # Определяем состояние
                    state = PrinterState.IDLE
                    message = "Принтер готов"
                    is_accepting = True

                    if status & PRINTER_STATUS_PRINTING:
                        state = PrinterState.PRINTING
                        message = "Идёт печать"
                    elif status & PRINTER_STATUS_PAUSED:
                        state = PrinterState.PAUSED
                        message = "Принтер приостановлен"
                        is_accepting = False
                    elif status & PRINTER_STATUS_ERROR:
                        state = PrinterState.ERROR
                        message = "Ошибка принтера"
                        is_accepting = False
                    elif status & PRINTER_STATUS_OFFLINE:
                        state = PrinterState.OFFLINE
                        message = "Принтер отключён"
                        is_accepting = False

                    # cJobs находится после Status
                    jobs_offset = status_offset + 4
                    job_count = struct.unpack_from("I", buffer, jobs_offset)[0]

                    return PrinterStatus(
                        state=state,
                        message=message,
                        job_count=job_count,
                        is_accepting_jobs=is_accepting,
                    )

        finally:
            winspool.ClosePrinter(phPrinter)

        return PrinterStatus(
            state=PrinterState.UNKNOWN,
            message="Не удалось получить статус",
            is_accepting_jobs=False,
        )

    def print_data(
        self,
        data: bytes,
        printer_name: str,
        job_name: str = "FX-Document",
        options: Optional[PrintOptions] = None,
    ) -> PrintResult:
        """Печатает данные через Win32 API.

        Args:
            data: ESC/P данные для печати
            printer_name: Имя Windows принтера
            job_name: Имя задания
            options: Опции печати

        Returns:
            PrintResult с результатом

        Raises:
            Win32NotAvailableError: Если Win32 API не доступен
            Win32PrintError: При ошибке печати
        """
        import ctypes
        from ctypes import wintypes

        winspool, kernel32 = self._assert_win32_available()
        opts = options or PrintOptions()

        # Открываем принтер
        phPrinter = wintypes.HANDLE()
        result = winspool.OpenPrinterW(
            printer_name,
            ctypes.byref(phPrinter),
            None,
        )

        if result == 0:
            error = kernel32.GetLastError()
            raise Win32PrintError(f"Не удалось открыть принтер: {error}")

        try:
            # Создаём DOC_INFO_1
            class DOC_INFO_1_STRUCT(ctypes.Structure):
                _fields_: ClassVar[List[Tuple[str, Any]]] = [
                    ("pDocName", wintypes.LPWSTR),
                    ("pOutputFile", wintypes.LPWSTR),
                    ("pDatatype", wintypes.LPWSTR),
                ]

            # Тип данных: RAW для ESC/P
            data_type = "RAW" if opts.raw_mode else "TEXT"

            doc_info = DOC_INFO_1_STRUCT()
            doc_info.pDocName = job_name
            doc_info.pOutputFile = None
            doc_info.pDatatype = data_type

            # Начинаем документ
            job_id = winspool.StartDocPrinterW(
                phPrinter,
                1,
                ctypes.byref(doc_info),
            )

            if job_id == 0:
                error = kernel32.GetLastError()
                raise Win32PrintError(f"StartDocPrinter failed: {error}")

            try:
                # Пишем данные
                written = wintypes.DWORD(0)

                result = winspool.WritePrinter(
                    phPrinter,
                    data,
                    len(data),
                    ctypes.byref(written),
                )

                if result == 0:
                    error = kernel32.GetLastError()
                    raise Win32PrintError(f"WritePrinter failed: {error}")

                self._logger.info(f"Written {written.value} bytes to printer")

            finally:
                # Завершаем документ
                winspool.EndDocPrinter(phPrinter)

            return PrintResult(
                success=True,
                job_id=str(job_id),
                status=PrintJobStatus.COMPLETED,
                message="Документ успешно напечатан",
                bytes_transferred=written.value if written.value > 0 else len(data),
                timestamp=datetime.now(),
            )

        finally:
            winspool.ClosePrinter(phPrinter)


# Type checking
if __name__ == "__main__":
    from src.printer.printer_protocol import PrinterProtocol

    adapter: PrinterProtocol = WindowsAdapter()
    print(f"Win32 available: {adapter.is_available()}")
