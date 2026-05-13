"""Файловый адаптер для печати.

Сохраняет ESC/P данные в файлы .escp для тестирования и отладки.
Работает на всех платформах как fallback адаптер.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional

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


class FileAdapterError(Exception):
    """Базовая ошибка файлового адаптера."""

    pass


class FilePrintError(FileAdapterError):
    """Ошибка при сохранении в файл."""

    pass


class FileNotWritableError(FileAdapterError):
    """Невозможно записать в директорию."""

    pass


# -----------------------------------------------------------------------------
# File Adapter
# -----------------------------------------------------------------------------


class FileAdapter:
    """Адаптер печати в файл.

    Сохраняет ESC/P данные в файлы с расширением .escp.
    Полезен для тестирования, отладки и экспорта.

    Attributes:
        _output_dir: Директория для сохранения файлов
        _logger: Логгер
        _file_counter: Счётчик для генерации имён файлов

    Example:
        >>> adapter = FileAdapter(Path("./output"))
        >>> result = adapter.print_data(b"ESC/P data", "test_printer")
        >>> print(f"Saved to: {result.message}")
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        filename_pattern: str = "fx_doc_{timestamp}_{counter}.escp",
    ) -> None:
        """Инициализирует файловый адаптер.

        Args:
            output_dir: Директория для сохранения (default: ./output)
            filename_pattern: Шаблон для имён файлов

        Raises:
            FileNotWritableError: Если директория не доступна для записи
        """
        self._logger = logging.getLogger(__name__)
        self._file_counter: int = 0
        self._filename_pattern = filename_pattern

        # Директория по умолчанию
        if output_dir is None:
            output_dir = Path("./output")

        self._output_dir: Path = Path(output_dir).resolve()

        # Создаём директорию если нужно
        try:
            self._output_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError, TypeError) as e:
            raise FileNotWritableError(f"Не удалось создать директорию {self._output_dir}: {e}")

        # Проверяем доступность на запись
        if not self._is_writable(self._output_dir):
            raise FileNotWritableError(f"Директория не доступна для записи: {self._output_dir}")

        self._logger.debug(f"FileAdapter initialized with output: {self._output_dir}")

    def _is_writable(self, path: Path) -> bool:
        """Проверяет возможность записи в директорию.

        Args:
            path: Путь к директории

        Returns:
            True если можно записывать
        """
        try:
            test_file = path / ".write_test"
            test_file.write_text("")
            test_file.unlink()
            return True
        except (OSError, PermissionError, TypeError):
            return False

    def _generate_filename(self, job_name: str) -> str:
        """Генерирует имя файла по шаблону.

        Args:
            job_name: Имя задания

        Returns:
            Имя файла
        """
        self._file_counter += 1
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Очищаем job_name для использования в имени файла
        safe_name = "".join(c for c in job_name if c.isalnum() or c in "_-").rstrip()
        safe_name = safe_name[:50]  # Ограничиваем длину

        filename = self._filename_pattern.format(
            timestamp=timestamp,
            counter=self._file_counter,
            job_name=safe_name or "unnamed",
        )

        return filename

    def is_available(self) -> bool:
        """Проверяет доступность адаптера.

        Returns:
            True если директория доступна для записи
        """
        return self._output_dir.exists() and self._is_writable(self._output_dir)

    def get_adapter_name(self) -> str:
        """Возвращает имя адаптера.

        Returns:
            "file"
        """
        return "file"

    def get_printers(self) -> List[PrinterInfo]:
        """Возвращает виртуальный "принтер" для файлового вывода.

        Returns:
            Список с одним виртуальным принтером
        """
        return [
            PrinterInfo(
                printer_id="file:escp_output",
                name="Сохранить в файл (.escp)",
                adapter_type="file",
                is_default=False,
                is_available=self.is_available(),
                location=str(self._output_dir),
                description="Сохранение ESC/P данных в файл",
            )
        ]

    def get_status(self, printer_name: str) -> PrinterStatus:
        """Возвращает статус файлового адаптера.

        Args:
            printer_name: Игнорируется (виртуальный принтер)

        Returns:
            PrinterStatus
        """
        if not self.is_available():
            return PrinterStatus(
                state=PrinterState.ERROR,
                message="Директория не доступна для записи",
                is_accepting_jobs=False,
            )

        # Подсчитываем файлы в директории
        try:
            file_count = len(list(self._output_dir.glob("*.escp")))
        except (OSError, PermissionError, TypeError, ValueError):
            file_count = 0

        return PrinterStatus(
            state=PrinterState.IDLE,
            message=f"Готов к сохранению. Файлов: {file_count}",
            job_count=0,
            is_accepting_jobs=True,
        )

    def print_data(
        self,
        data: bytes,
        printer_name: str = "file",
        job_name: str = "FX-Document",
        options: Optional[PrintOptions] = None,
    ) -> PrintResult:
        """Сохраняет данные в файл.

        Args:
            data: ESC/P данные для сохранения
            printer_name: Игнорируется
            job_name: Имя задания (используется в имени файла)
            options: Опции (copies игнорируется)

        Returns:
            PrintResult с путём к файлу

        Raises:
            FilePrintError: При ошибке записи
        """
        if not self.is_available():
            return PrintResult(
                success=False,
                status=PrintJobStatus.FAILED,
                message="Директория не доступна для записи",
                bytes_transferred=0,
            )

        try:
            # Генерируем имя файла
            filename = self._generate_filename(job_name)
            filepath = self._output_dir / filename

            # Записываем данные
            filepath.write_bytes(data)

            self._logger.info(f"Saved ESC/P data to: {filepath}")

            return PrintResult(
                success=True,
                job_id=str(filepath),
                status=PrintJobStatus.COMPLETED,
                message=f"Сохранено: {filepath.name}",
                bytes_transferred=len(data),
                timestamp=datetime.now(),
            )

        except (OSError, PermissionError, TypeError, ValueError) as e:
            self._logger.error(f"Error saving file: {e}")
            return PrintResult(
                success=False,
                status=PrintJobStatus.FAILED,
                message=f"Ошибка сохранения: {e}",
                bytes_transferred=0,
            )

    def get_output_dir(self) -> Path:
        """Возвращает директорию для вывода.

        Returns:
            Путь к директории
        """
        return self._output_dir

    def list_saved_files(self) -> List[Path]:
        """Возвращает список сохранённых файлов.

        Returns:
            Список путей к .escp файлам
        """
        try:
            return sorted(self._output_dir.glob("*.escp"), key=lambda p: p.stat().st_mtime)
        except (OSError, PermissionError, TypeError, ValueError) as e:
            self._logger.error(f"Error listing files: {e}")
            return []

    def clear_output_dir(self, confirm: bool = False) -> int:
        """Очищает директорию от .escp файлов.

        Args:
            confirm: Подтверждение операции

        Returns:
            Количество удалённых файлов
        """
        if not confirm:
            self._logger.warning("Use confirm=True to clear output directory")
            return 0

        count = 0
        try:
            for filepath in self._output_dir.glob("*.escp"):
                filepath.unlink()
                count += 1
            self._logger.info(f"Cleared {count} files from {self._output_dir}")
        except (OSError, PermissionError, TypeError, ValueError) as e:
            self._logger.error(f"Error clearing directory: {e}")

        return count


# Compatibility with print_controller.py
class FilePrinterAdapter:
    """Адаптер для совместимости с PrinterAdapterProtocol.

    Используется в print_controller.py для обратной совместимости.

    Example:
        >>> adapter = FilePrinterAdapter(Path("./output"))
        >>> adapter.print_data(b"data", "Test Job", copies=1)
    """

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        """Инициализирует адаптер.

        Args:
            output_dir: Директория для сохранения
        """
        self._adapter = FileAdapter(output_dir)
        self._logger = logging.getLogger(__name__)

    def get_name(self) -> str:
        """Возвращает имя адаптера."""
        return "file"

    def is_available(self) -> bool:
        """Проверяет доступность."""
        return self._adapter.is_available()

    def print_data(self, data: bytes, job_name: str, copies: int = 1) -> bool:
        """Печатает данные.

        Args:
            data: Данные для печати
            job_name: Имя задания
            copies: Игнорируется

        Returns:
            True если успешно
        """
        try:
            result = self._adapter.print_data(
                data=data,
                printer_name="file",
                job_name=job_name,
            )
            return result.success
        except (OSError, PermissionError, TypeError, ValueError) as e:
            self._logger.error(f"Print error: {e}")
            return False

    @staticmethod
    def discover_printers() -> List[PrinterInfo]:
        """Обнаруживает принтеры.

        Returns:
            Список принтеров
        """
        adapter = FileAdapter()
        return adapter.get_printers()


# Type checking
if __name__ == "__main__":
    from src.printer.printer_protocol import PrinterProtocol

    adapter: PrinterProtocol = FileAdapter()
    print(f"File adapter available: {adapter.is_available()}")
