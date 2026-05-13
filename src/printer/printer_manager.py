"""Менеджер принтеров для FX Text Processor 3.

Автоматически определяет доступные адаптеры и управляет
их жизненным циклом. Предоставляет единый интерфейс
для печати через любой доступный адаптер.

Architecture:
    PrinterManager
        ├─ CupsAdapter (Linux/Unix)
        ├─ WindowsAdapter (Windows)
        └─ FileAdapter (Fallback, все платформы)
"""

from __future__ import annotations

import logging
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type

from src.printer.printer_protocol import (
    PrinterInfo,
    PrinterProtocol,
    PrinterStatus,
    PrintJobStatus,
    PrintOptions,
    PrintResult,
)

# -----------------------------------------------------------------------------
# Exceptions
# -----------------------------------------------------------------------------


class PrinterManagerError(Exception):
    """Базовая ошибка менеджера принтеров."""

    pass


class PrinterNotFoundError(PrinterManagerError):
    """Принтер не найден."""

    pass


class AdapterNotAvailableError(PrinterManagerError):
    """Адаптер не доступен."""

    pass


class PrintError(PrinterManagerError):
    """Ошибка при печати."""

    pass


# -----------------------------------------------------------------------------
# Adapter Registration
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class AdapterInfo:
    """Информация о зарегистрированном адаптере.

    Attributes:
        adapter_id: Уникальный ID адаптера
        adapter_class: Класс адаптера
        adapter_instance: Экземпляр адаптера (или None)
        is_available: Доступен ли адаптер
        priority: Приоритет (ниже = выше приоритет)
    """

    adapter_id: str
    adapter_class: Type[PrinterProtocol]
    adapter_instance: Optional[PrinterProtocol]
    is_available: bool
    priority: int = 100


# -----------------------------------------------------------------------------
# Printer Manager
# -----------------------------------------------------------------------------


class PrinterManager:
    """Менеджер принтеров с автоматическим определением адаптеров.

    Отвечает за:
    - Авто-определение доступных адаптеров (CUPS, Win32, File)
    - Управление приоритетами адаптеров
    - Маршрутизацию запросов печати
    - Агрегацию информации о принтерах

    Attributes:
        _adapters: Словарь зарегистрированных адаптеров
        _logger: Логгер
        _default_output_dir: Директория для файлового вывода

    Example:
        >>> manager = PrinterManager()
        >>> printers = manager.get_available_printers()
        >>> result = manager.print(b"data", "cups:FX-890")
    """

    # Приоритеты адаптеров (ниже = выше приоритет)
    PRIORITY_CUPS = 10
    PRIORITY_WIN32 = 10
    PRIORITY_FILE = 100  # Fallback

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        auto_detect: bool = True,
    ) -> None:
        """Инициализирует менеджер принтеров.

        Args:
            output_dir: Директория для файлового вывода
            auto_detect: Автоматически определять адаптеры
        """
        self._logger = logging.getLogger(__name__)
        self._adapters: Dict[str, AdapterInfo] = {}
        self._default_output_dir = output_dir or Path("./output")

        if auto_detect:
            self._detect_adapters()

    def _detect_adapters(self) -> None:
        """Автоматически определяет доступные адаптеры.

        Определяет адаптеры в порядке:
        1. CUPS (Linux/Unix)
        2. Win32 (Windows)
        3. File (всегда)
        """
        self._logger.info("Detecting printer adapters...")

        # CUPS на Linux/macOS
        if platform.system() in ("Linux", "Darwin"):
            try:
                from src.printer.cups_adapter import CupsAdapter

                adapter = CupsAdapter()
                if adapter.is_available():
                    self._register_adapter(
                        "cups",
                        CupsAdapter,
                        adapter,
                        priority=self.PRIORITY_CUPS,
                    )
                    self._logger.info("CUPS adapter registered")
                else:
                    self._logger.debug("CUPS not available")
            except ImportError as e:
                self._logger.debug(f"CUPS import error: {e}")
            except Exception as e:
                self._logger.warning(f"CUPS adapter error: {e}")

        # Win32 на Windows
        if platform.system() == "Windows":
            try:
                from src.printer.windows_adapter import WindowsAdapter

                win_adapter = WindowsAdapter()
                if win_adapter.is_available():
                    self._register_adapter(
                        "win32",
                        WindowsAdapter,
                        win_adapter,
                        priority=self.PRIORITY_WIN32,
                    )
                    self._logger.info("Windows adapter registered")
                else:
                    self._logger.debug("Win32 API not available")
            except ImportError as e:
                self._logger.debug(f"Win32 import error: {e}")
            except Exception as e:
                self._logger.warning(f"Windows adapter error: {e}")

        # File adapter (всегда доступен)
        try:
            from src.printer.file_adapter import FileAdapter

            file_adapter = FileAdapter(self._default_output_dir)
            self._register_adapter(
                "file",
                FileAdapter,
                file_adapter,
                priority=self.PRIORITY_FILE,
            )
            self._logger.info("File adapter registered")
        except Exception as e:
            self._logger.error(f"File adapter error: {e}")

    def _register_adapter(
        self,
        adapter_id: str,
        adapter_class: Type[PrinterProtocol],
        adapter_instance: Optional[PrinterProtocol] = None,
        priority: int = 100,
    ) -> None:
        """Регистрирует адаптер.

        Args:
            adapter_id: Уникальный ID адаптера
            adapter_class: Класс адаптера
            adapter_instance: Экземпляр (или создаётся при запросе)
            priority: Приоритет адаптера
        """
        is_available = adapter_instance.is_available() if adapter_instance else False

        info = AdapterInfo(
            adapter_id=adapter_id,
            adapter_class=adapter_class,
            adapter_instance=adapter_instance,
            is_available=is_available,
            priority=priority,
        )

        self._adapters[adapter_id] = info
        self._logger.debug(f"Registered adapter: {adapter_id} (priority={priority})")

    def get_adapter(self, adapter_id: str) -> PrinterProtocol:
        """Возвращает адаптер по ID.

        Args:
            adapter_id: ID адаптера (cups/win32/file)

        Returns:
            Экземпляр адаптера

        Raises:
            AdapterNotAvailableError: Если адаптер не найден
        """
        info = self._adapters.get(adapter_id)
        if not info:
            raise AdapterNotAvailableError(f"Адаптер не найден: {adapter_id}")

        # Создаём экземпляр если нужно
        if info.adapter_instance is None:
            try:
                instance = info.adapter_class()
                if instance.is_available():
                    # Обновляем информацию
                    new_info = AdapterInfo(
                        adapter_id=info.adapter_id,
                        adapter_class=info.adapter_class,
                        adapter_instance=instance,
                        is_available=True,
                        priority=info.priority,
                    )
                    self._adapters[adapter_id] = new_info
                    return instance
                else:
                    raise AdapterNotAvailableError(f"Адаптер не доступен: {adapter_id}")
            except Exception as e:
                raise AdapterNotAvailableError(f"Ошибка создания адаптера {adapter_id}: {e}")

        return info.adapter_instance

    def get_available_adapters(self) -> List[str]:
        """Возвращает список доступных адаптеров.

        Returns:
            Список ID адаптеров
        """
        return [info.adapter_id for info in self._adapters.values() if info.is_available]

    def get_available_printers(self) -> List[PrinterInfo]:
        """Возвращает список всех доступных принтеров.

        Агрегирует принтеры от всех доступных адаптеров.

        Returns:
            Список PrinterInfo объектов
        """
        printers: List[PrinterInfo] = []

        # Сортируем адаптеры по приоритету
        sorted_adapters = sorted(
            self._adapters.values(),
            key=lambda x: x.priority,
        )

        for info in sorted_adapters:
            if not info.is_available:
                continue

            try:
                adapter = self.get_adapter(info.adapter_id)
                adapter_printers = adapter.get_printers()
                printers.extend(adapter_printers)
            except Exception as e:
                self._logger.warning(f"Error getting printers from {info.adapter_id}: {e}")

        return printers

    def get_printer_info(self, printer_id: str) -> PrinterInfo:
        """Возвращает информацию о принтере.

        Args:
            printer_id: ID принтера (adapter:name)

        Returns:
            PrinterInfo

        Raises:
            PrinterNotFoundError: Если принтер не найден
        """
        # Парсим ID
        if ":" not in printer_id:
            raise PrinterNotFoundError(f"Неверный формат ID принтера: {printer_id}")

        adapter_id, name = printer_id.split(":", 1)

        try:
            adapter = self.get_adapter(adapter_id)
            printers = adapter.get_printers()

            for printer in printers:
                if printer.printer_id == printer_id or printer.name == name:
                    return printer

        except Exception as e:
            self._logger.error(f"Error getting printer info: {e}")

        raise PrinterNotFoundError(f"Принтер не найден: {printer_id}")

    def get_status(self, printer_id: str) -> PrinterStatus:
        """Возвращает статус принтера.

        Args:
            printer_id: ID принтера (adapter:name)

        Returns:
            PrinterStatus

        Raises:
            PrinterNotFoundError: Если принтер не найден
        """
        if ":" not in printer_id:
            raise PrinterNotFoundError(f"Неверный формат ID: {printer_id}")

        adapter_id, name = printer_id.split(":", 1)

        try:
            adapter = self.get_adapter(adapter_id)
            return adapter.get_status(name)
        except Exception as e:
            self._logger.error(f"Error getting status: {e}")
            raise PrinterNotFoundError(f"Ошибка получения статуса: {e}")

    def print(
        self,
        data: bytes,
        printer_id: str,
        job_name: str = "FX-Document",
        options: Optional[PrintOptions] = None,
    ) -> PrintResult:
        """Печатает данные на указанный принтер.

        Args:
            data: ESC/P данные
            printer_id: ID принтера (adapter:name)
            job_name: Имя задания
            options: Опции печати

        Returns:
            PrintResult

        Raises:
            PrinterNotFoundError: Если принтер не найден
            PrintError: При ошибке печати
        """
        if ":" not in printer_id:
            raise PrinterNotFoundError(f"Неверный формат ID: {printer_id}")

        adapter_id, name = printer_id.split(":", 1)

        self._logger.info(f"Printing to {printer_id}, {len(data)} bytes")

        try:
            adapter = self.get_adapter(adapter_id)
            return adapter.print_data(
                data=data,
                printer_name=name,
                job_name=job_name,
                options=options,
            )
        except Exception as e:
            self._logger.error(f"Print error: {e}")
            raise PrintError(f"Ошибка печати: {e}") from e

    def print_with_fallback(
        self,
        data: bytes,
        preferred_printer: Optional[str] = None,
        job_name: str = "FX-Document",
        options: Optional[PrintOptions] = None,
    ) -> Tuple[PrintResult, str]:
        """Печатает с автоматическим fallback на доступные адаптеры.

        Args:
            data: ESC/P данные
            preferred_printer: Предпочтительный принтер
            job_name: Имя задания
            options: Опции печати

        Returns:
            Кортеж (PrintResult, printer_id)
        """
        # Сначала пробуем предпочтительный
        if preferred_printer:
            try:
                result = self.print(data, preferred_printer, job_name, options)
                if result.success:
                    return result, preferred_printer
            except Exception as e:
                self._logger.warning(f"Preferred printer failed: {e}")

        # Перебираем все доступные принтеры
        printers = self.get_available_printers()

        for printer_info in printers:
            if printer_info.printer_id == preferred_printer:
                continue  # Уже пробовали

            try:
                result = self.print(data, printer_info.printer_id, job_name, options)
                if result.success:
                    return result, printer_info.printer_id
            except Exception as e:
                self._logger.warning(f"Printer {printer_info.printer_id} failed: {e}")

        # Ничего не сработало
        return PrintResult(
            success=False,
            status=PrintJobStatus.FAILED,
            message="Не удалось напечатать на доступных принтерах",
        ), ""

    def get_best_adapter(self) -> Optional[str]:
        """Возвращает лучший доступный адаптер.

        Returns:
            ID адаптера или None
        """
        sorted_adapters = sorted(
            self._adapters.values(),
            key=lambda x: x.priority,
        )

        for info in sorted_adapters:
            if info.is_available:
                return info.adapter_id

        return None

    def get_best_printer(self) -> Optional[str]:
        """Возвращает ID лучшего доступного принтера.

        Returns:
            printer_id или None
        """
        printers = self.get_available_printers()

        if not printers:
            return None

        # Сначала ищем принтер по умолчанию
        for printer in printers:
            if printer.is_default and printer.is_available:
                return printer.printer_id

        # Берём первый доступный
        for printer in printers:
            if printer.is_available:
                return printer.printer_id

        return None

    def get_adapter_info(self) -> List[Tuple[str, bool, int]]:
        """Возвращает информацию о зарегистрированных адаптерах.

        Returns:
            Список (adapter_id, is_available, priority)
        """
        return [
            (info.adapter_id, info.is_available, info.priority) for info in self._adapters.values()
        ]


# -----------------------------------------------------------------------------
# Factory Functions
# -----------------------------------------------------------------------------


def create_printer_manager(
    output_dir: Optional[Path] = None,
    auto_detect: bool = True,
) -> PrinterManager:
    """Фабричная функция для создания PrinterManager.

    Args:
        output_dir: Директория для файлового вывода
        auto_detect: Авто-определение адаптеров

    Returns:
        Настроенный PrinterManager
    """
    return PrinterManager(
        output_dir=output_dir,
        auto_detect=auto_detect,
    )


# -----------------------------------------------------------------------------
# Exports
# -----------------------------------------------------------------------------

__all__ = [
    "PrinterManager",
    "create_printer_manager",
    "PrinterManagerError",
    "PrinterNotFoundError",
    "AdapterNotAvailableError",
    "PrintError",
    "AdapterInfo",
]
