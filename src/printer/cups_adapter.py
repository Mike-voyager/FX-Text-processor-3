"""CUPS адаптер для печати на Linux/Unix системах.

Использует subprocess для вызова команд lp/lpr или
pycups если доступен. Предпочитает raw режим для ESC/P.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

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


class CupsAdapterError(Exception):
    """Базовая ошибка CUPS адаптера."""

    pass


class CupsNotAvailableError(CupsAdapterError):
    """CUPS не доступен на системе."""

    pass


class CupsPrintError(CupsAdapterError):
    """Ошибка при печати через CUPS."""

    pass


class CupsPrinterNotFoundError(CupsAdapterError):
    """Принтер не найден в CUPS."""

    pass


# -----------------------------------------------------------------------------
# CUPS Adapter
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class CupsPrinterOptions:
    """Опции CUPS принтера.

    Attributes:
        device_uri: URI устройства
        ppd_name: Имя PPD файла
        state_reasons: Причины состояния
    """

    device_uri: Optional[str] = None
    ppd_name: Optional[str] = None
    state_reasons: Tuple[str, ...] = ()


class CupsAdapter:
    """Адаптер печати через CUPS (Common Unix Printing System).

    Поддерживает печать в raw режиме для ESC/P данных.
    Требует установленного CUPS и доступных lp/lpr команд.

    Attributes:
        _logger: Логгер для диагностики
        _lp_path: Путь к команде lp
        _lpstat_path: Путь к команде lpstat
        _lpoptions_path: Путь к команде lpoptions

    Example:
        >>> adapter = CupsAdapter()
        >>> if adapter.is_available():
        ...     printers = adapter.get_printers()
        ...     result = adapter.print_data(b"ESC/P data", "FX-890")
    """

    # Коды выхода CUPS
    EXIT_OK = 0
    EXIT_PRINTER_NOT_FOUND = 1

    def __init__(self) -> None:
        """Инициализирует CUPS адаптер.

        Определяет пути к командам CUPS при инициализации.
        """
        self._logger = logging.getLogger(__name__)
        self._lp_path: Optional[str] = None
        self._lpstat_path: Optional[str] = None
        self._lpoptions_path: Optional[str] = None
        self._cups_printers: Dict[str, CupsPrinterOptions] = {}

        self._detect_cups_commands()

    def _detect_cups_commands(self) -> None:
        """Определяет пути к командам CUPS."""
        self._lp_path = shutil.which("lp")
        self._lpstat_path = shutil.which("lpstat")
        self._lpoptions_path = shutil.which("lpoptions")

        if self._lp_path:
            self._logger.debug(f"Found lp command: {self._lp_path}")
        if self._lpstat_path:
            self._logger.debug(f"Found lpstat command: {self._lpstat_path}")

    def is_available(self) -> bool:
        """Проверяет доступность CUPS.

        Returns:
            True если команды lp и lpstat доступны
        """
        return self._lp_path is not None and self._lpstat_path is not None

    def get_adapter_name(self) -> str:
        """Возвращает имя адаптера.

        Returns:
            "cups"
        """
        return "cups"

    def get_printers(self) -> List[PrinterInfo]:
        """Возвращает список CUPS принтеров.

        Использует lpstat -p -d для получения списка.

        Returns:
            Список PrinterInfo объектов

        Raises:
            CupsNotAvailableError: Если CUPS не доступен
        """
        if not self.is_available():
            raise CupsNotAvailableError("CUPS команды не найдены")

        printers: List[PrinterInfo] = []
        default_printer: Optional[str] = None

        try:
            # Получаем принтер по умолчанию
            assert self._lpstat_path is not None
            result = subprocess.run(
                [self._lpstat_path, "-d"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "system default destination" in result.stdout:
                parts = result.stdout.strip().split(":")
                if len(parts) > 1:
                    default_printer = parts[1].strip()

            # Получаем список принтеров
            assert self._lpstat_path is not None
            result = subprocess.run(
                [self._lpstat_path, "-p", "-l"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                self._logger.warning(f"lpstat failed: {result.stderr}")
                return printers

            # Парсим вывод lpstat
            current_printer: Optional[str] = None
            current_info: Dict[str, Any] = {}

            for line in result.stdout.split("\n"):
                line = line.strip()

                # Новый принтер: "printer PRINTER_NAME is ..."
                if line.startswith("printer "):
                    # Сохраняем предыдущий
                    if current_printer:
                        printer = self._create_printer_info(
                            current_printer,
                            current_info,
                            default_printer,
                        )
                        printers.append(printer)

                    # Парсим имя принтера
                    parts = line.split()
                    if len(parts) >= 2:
                        current_printer = parts[1]
                        current_info = {"status_line": line}

                # Дополнительная информация
                elif line.startswith("Description:"):
                    current_info["description"] = line.split(":", 1)[1].strip()
                elif line.startswith("Location:"):
                    current_info["location"] = line.split(":", 1)[1].strip()
                elif line.startswith("Interface:"):
                    current_info["interface"] = line.split(":", 1)[1].strip()
                elif line.startswith("URI:"):
                    current_info["uri"] = line.split(":", 1)[1].strip()

            # Сохраняем последний
            if current_printer:
                printer = self._create_printer_info(
                    current_printer,
                    current_info,
                    default_printer,
                )
                printers.append(printer)

        except subprocess.TimeoutExpired:
            self._logger.warning("lpstat timeout")
        except Exception as e:
            self._logger.error(f"Error getting printers: {e}")

        return printers

    def _create_printer_info(
        self,
        name: str,
        info: Dict[str, Any],
        default_printer: Optional[str],
    ) -> PrinterInfo:
        """Создает PrinterInfo из данных lpstat.

        Args:
            name: Имя принтера
            info: Словарь с дополнительной информацией
            default_printer: Имя принтера по умолчанию

        Returns:
            PrinterInfo объект
        """
        status_line = info.get("status_line", "")
        is_available = "idle" in status_line.lower() or "printing" in status_line.lower()

        return PrinterInfo(
            printer_id=f"cups:{name}",
            name=name,
            adapter_type="cups",
            is_default=(name == default_printer),
            is_available=is_available,
            location=info.get("location"),
            description=info.get("description"),
        )

    def get_status(self, printer_name: str) -> PrinterStatus:
        """Возвращает статус CUPS принтера.

        Args:
            printer_name: Имя принтера (без префикса cups:)

        Returns:
            PrinterStatus объект

        Raises:
            CupsNotAvailableError: Если CUPS не доступен
        """
        if not self.is_available():
            raise CupsNotAvailableError("CUPS команды не найдены")

        try:
            # Получаем статус через lpstat
            assert self._lpstat_path is not None
            result = subprocess.run(
                [self._lpstat_path, "-p", printer_name],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return PrinterStatus(
                    state=PrinterState.UNKNOWN,
                    message=f"Ошибка получения статуса: {result.stderr}",
                    is_accepting_jobs=False,
                )

            # Парсим статус
            output = result.stdout.lower()
            state = PrinterState.UNKNOWN
            message = "Статус неизвестен"
            is_accepting = True

            if "idle" in output:
                state = PrinterState.IDLE
                message = "Принтер готов к работе"
            elif "printing" in output or "processing" in output:
                state = PrinterState.PRINTING
                message = "Идёт печать"
            elif "paused" in output or "disabled" in output:
                state = PrinterState.PAUSED
                message = "Принтер приостановлен"
                is_accepting = False
            elif "error" in output or "stopped" in output:
                state = PrinterState.ERROR
                message = "Ошибка принтера"
                is_accepting = False

            # Проверяем очередь
            assert self._lpstat_path is not None
            queue_result = subprocess.run(
                [self._lpstat_path, "-o", printer_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            job_count = len([line for line in queue_result.stdout.split("\n") if line.strip()])

            return PrinterStatus(
                state=state,
                message=message,
                job_count=job_count,
                is_accepting_jobs=is_accepting,
            )

        except subprocess.TimeoutExpired:
            return PrinterStatus(
                state=PrinterState.OFFLINE,
                message="Таймаут при получении статуса",
                is_accepting_jobs=False,
            )
        except Exception as e:
            self._logger.error(f"Error getting printer status: {e}")
            return PrinterStatus(
                state=PrinterState.UNKNOWN,
                message=f"Ошибка: {e}",
                is_accepting_jobs=False,
            )

    def print_data(
        self,
        data: bytes,
        printer_name: str,
        job_name: str = "FX-Document",
        options: Optional[PrintOptions] = None,
    ) -> PrintResult:
        """Печатает данные через CUPS.

        Использует lp с опцией -o raw для ESC/P данных.

        Args:
            data: ESC/P данные для печати
            printer_name: Имя CUPS принтера
            job_name: Имя задания
            options: Опции печати

        Returns:
            PrintResult с результатом операции

        Raises:
            CupsNotAvailableError: Если CUPS не доступен
            CupsPrintError: При ошибке печати
        """
        if not self.is_available():
            raise CupsNotAvailableError("CUPS команды не найдены")

        opts = options or PrintOptions()

        try:
            # Формируем аргументы для lp
            assert self._lp_path is not None
            cmd: List[str] = [
                self._lp_path,
                "-d",
                printer_name,
                "-t",
                job_name,
            ]

            # Добавляем опции
            if opts.copies > 1:
                cmd.extend(["-n", str(opts.copies)])

            # Raw режим для ESC/P
            if opts.raw_mode:
                cmd.extend(["-o", "raw"])

            # Медиа
            if opts.media:
                cmd.extend(["-o", f"media={opts.media}"])

            # Ориентация
            if opts.orientation:
                cmd.extend(["-o", f"orientation-requested={opts.orientation}"])

            # Двусторонняя печать (если поддерживается)
            if opts.duplex:
                cmd.extend(["-o", "sides=two-sided-long-edge"])

            # Пользовательские опции
            for key, value in opts.custom_options.items():
                cmd.extend(["-o", f"{key}={value}"])

            # Выполняем команду
            assert self._lp_path is not None
            self._logger.debug(f"Executing: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                input=data,
                capture_output=True,
                timeout=60,
            )

            if result.returncode != 0:
                error_msg = (
                    result.stderr.decode("utf-8", errors="replace")
                    if result.stderr
                    else "Unknown error"
                )
                self._logger.error(f"lp failed: {error_msg}")
                return PrintResult(
                    success=False,
                    status=PrintJobStatus.FAILED,
                    message=f"Ошибка CUPS: {error_msg}",
                    bytes_transferred=0,
                )

            # Парсим ID задания
            job_id: Optional[str] = None
            stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
            if "request id is" in stdout.lower():
                parts = stdout.split()
                for i, part in enumerate(parts):
                    if part.lower() == "is" and i + 1 < len(parts):
                        job_id = parts[i + 1].rstrip(".")
                        break

            self._logger.info(f"Print job submitted: {job_id}")

            return PrintResult(
                success=True,
                job_id=job_id,
                status=PrintJobStatus.PROCESSING,
                message=f"Задание отправлено: {job_id}",
                bytes_transferred=len(data),
                timestamp=datetime.now(),
            )

        except subprocess.TimeoutExpired:
            return PrintResult(
                success=False,
                status=PrintJobStatus.FAILED,
                message="Таймаут при отправке на печать",
                bytes_transferred=0,
            )
        except Exception as e:
            self._logger.error(f"Error printing: {e}")
            return PrintResult(
                success=False,
                status=PrintJobStatus.FAILED,
                message=f"Ошибка печати: {e}",
                bytes_transferred=0,
            )

    def cancel_job(self, job_id: str) -> bool:
        """Отменяет задание печати.

        Args:
            job_id: ID задания

        Returns:
            True если задание отменено
        """
        cancel_path = shutil.which("cancel")
        if not cancel_path:
            return False

        try:
            result = subprocess.run(
                [cancel_path, job_id],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception as e:
            self._logger.error(f"Error cancelling job: {e}")
            return False


# Проверка типов: CupsAdapter реализует PrinterProtocol
if __name__ == "__main__":
    # Type checking
    adapter: PrinterProtocol = CupsAdapter()
    print(f"CUPS available: {adapter.is_available()}")
