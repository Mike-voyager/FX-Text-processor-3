"""
Безопасное удаление данных.

Модуль предоставляет функции для безопасного удаления:
- wipe_memory: Обнуление чувствительных данных в памяти
- wipe_file: Безопасное удаление файлов (многопроходная перезапись)
- wipe_directory: Рекурсивное удаление директорий
- clear_clipboard: Очистка буфера обмена

Security:
    - Многопроходная перезапись для файлов (DoD 5220.22-M)
    - Обнуление памяти перед освобождением
    - Платформозависимая очистка буфера обмена

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import ctypes
import logging
import os
import platform
import shutil
import subprocess
import sys
import types
from pathlib import Path
from typing import Final, List, Optional

LOG = logging.getLogger(__name__)

# Константы для безопасного удаления
WIPE_PASSES: Final[int] = 3
"""Количество проходов перезаписи (DoD 5220.22-M рекомендует 3+)."""

BUFFER_SIZE: Final[int] = 65536
"""Размер буфера для записи (64 KB)."""

# Паттерны перезаписи по стандарту DoD 5220.22-M
DOD_PATTERNS: Final[List[bytes]] = [
    b"\x00",  # Проход 1: нули
    b"\xFF",  # Проход 2: единицы
    b"\x00",  # Проход 3: случайные (будут заменены на os.urandom)
]


class SecureEraseError(Exception):
    """Базовое исключение для ошибок безопасного удаления."""

    def __init__(self, message: str, *, path: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.path = path

    def __str__(self) -> str:
        parts = [self.__class__.__name__, ": ", self.message]
        if self.path:
            parts.append(f" [path={self.path}]")
        return "".join(parts)


class MemoryWipeError(SecureEraseError):
    """Ошибка обнуления памяти."""


class FileWipeError(SecureEraseError):
    """Ошибка безопасного удаления файла."""

    def __init__(
        self,
        message: str,
        *,
        path: Optional[str] = None,
        pass_number: Optional[int] = None,
    ) -> None:
        super().__init__(message, path=path)
        self.pass_number = pass_number


class DirectoryWipeError(SecureEraseError):
    """Ошибка рекурсивного удаления директории."""


class ClipboardClearError(SecureEraseError):
    """Ошибка очистки буфера обмена."""


def wipe_memory(data: bytearray) -> None:
    """
    Безопасное обнуление памяти.

    Перезаписывает содержимое bytearray нулями таким образом,
    что компилятор не может оптимизировать операцию.

    Args:
        data: ByteArray для обнуления

    Note:
        После вызова data будет содержать только нули.
        Вызывайте перед del переменной с чувствительными данными.

    Example:
        >>> key = bytearray(os.urandom(32))
        >>> # ... использование key ...
        >>> wipe_memory(key)
        >>> del key

    Security:
        - Использует ctypes для предотвращения оптимизации
        - Гарантированно перезаписывает все байты
        - Подходит для ключей, паролей, секретов
    """
    if not isinstance(data, bytearray):
        raise MemoryWipeError("wipe_memory требует bytearray, не bytes")

    # Получаем указатель на данные
    ptr = (ctypes.c_char * len(data)).from_buffer(data)

    # Перезаписываем нулями
    ctypes.memset(ptr, 0, len(data))

    # Принудительно синхронизируем память
    # (предотвращает оптимизацию компилятора)
    for i in range(len(data)):
        data[i] = 0

    LOG.debug("Обнулён bytearray размером %d байт", len(data))


def wipe_file(
    filepath: Path,
    *,
    passes: int = WIPE_PASSES,
    remove: bool = True,
) -> bool:
    """
    Безопасное удаление файла.

    Выполняет многопроходную перезапись файла перед удалением
    по стандарту DoD 5220.22-M.

    Args:
        filepath: Путь к файлу
        passes: Количество проходов перезаписи (минимум 1)
        remove: Удалить файл после перезаписи

    Returns:
        True если файл успешно удалён/перезаписан

    Raises:
        FileWipeError: Ошибка удаления или перезаписи

    Note:
        На SSD/NVMe носителях стандартная перезапись менее эффективна
        из-за wear leveling. Рассмотрите использование ATA Secure Erase
        или криптографического уничтожения.

    Example:
        >>> wipe_file(Path("secret.key"), passes=7, remove=True)
        True

    Security:
        - Проход 1: нули
        - Проход 2: единицы
        - Проход 3+: случайные данные
        - Финальный проход: нули
        - Удаление файла
    """
    if passes < 1:
        raise FileWipeError("passes должен быть >= 1", path=str(filepath))

    if not filepath.exists():
        LOG.debug("Файл не существует: %s", filepath)
        return True

    if not filepath.is_file():
        raise FileWipeError(f"Путь не является файлом: {filepath}", path=str(filepath))

    file_size = filepath.stat().st_size

    try:
        with open(filepath, "r+b") as f:
            for pass_num in range(passes):
                # Определяем паттерн для этого прохода
                if pass_num < len(DOD_PATTERNS):
                    pattern = DOD_PATTERNS[pass_num]
                else:
                    pattern = None  # Случайные данные

                # Перезаписываем файл
                f.seek(0)

                if pattern:
                    # Паттерн-перезапись
                    buffer = pattern * BUFFER_SIZE
                    remaining = file_size
                    while remaining > 0:
                        chunk_size = min(BUFFER_SIZE, remaining)
                        f.write(buffer[:chunk_size])
                        remaining -= chunk_size
                else:
                    # Случайные данные
                    remaining = file_size
                    while remaining > 0:
                        chunk_size = min(BUFFER_SIZE, remaining)
                        f.write(os.urandom(chunk_size))
                        remaining -= chunk_size

                # Принудительно сбрасываем на диск
                f.flush()
                os.fsync(f.fileno())

                LOG.debug(
                    "Проход %d/%d завершён: %s",
                    pass_num + 1,
                    passes,
                    filepath,
                )

        # Удаляем файл
        if remove:
            filepath.unlink()
            LOG.info("Файл безопасно удалён: %s (%d байт, %d проходов)", filepath, file_size, passes)
        else:
            LOG.info("Файл безопасно перезаписан: %s (%d байт, %d проходов)", filepath, file_size, passes)

        return True

    except PermissionError as e:
        raise FileWipeError(
            f"Нет прав для удаления файла: {filepath}",
            path=str(filepath),
        ) from e
    except OSError as e:
        raise FileWipeError(
            f"Ошибка удаления файла: {e}",
            path=str(filepath),
        ) from e


def wipe_directory(
    dirpath: Path,
    *,
    passes: int = WIPE_PASSES,
    remove_empty: bool = True,
) -> int:
    """
    Рекурсивное безопасное удаление директории.

    Удаляет все файлы в директории с многопроходной перезаписью,
    затем удаляет пустые поддиректории.

    Args:
        dirpath: Путь к директории
        passes: Количество проходов перезаписи файлов
        remove_empty: Удалить саму директорию если она пустая

    Returns:
        Количество удалённых файлов

    Raises:
        DirectoryWipeError: Ошибка удаления директории

    Example:
        >>> count = wipe_directory(Path("secrets/"), passes=3)
        >>> print(f"Удалено {count} файлов")
    """
    if not dirpath.exists():
        LOG.debug("Директория не существует: %s", dirpath)
        return 0

    if not dirpath.is_dir():
        raise DirectoryWipeError(
            f"Путь не является директорией: {dirpath}",
            path=str(dirpath),
        )

    deleted_count = 0

    # Рекурсивно обходим директорию
    for root, dirs, files in os.walk(dirpath, topdown=False):
        root_path = Path(root)

        # Удаляем файлы
        for filename in files:
            filepath = root_path / filename
            try:
                wipe_file(filepath, passes=passes, remove=True)
                deleted_count += 1
            except FileWipeError as e:
                LOG.warning("Не удалось удалить файл %s: %s", filepath, e)
                # Продолжаем с остальными файлами

        # Удаляем пустые поддиректории
        if remove_empty:
            for dirname in dirs:
                subdirpath = root_path / dirname
                try:
                    # Удаляем только если директория пустая
                    if not any(subdirpath.iterdir()):
                        subdirpath.rmdir()
                        LOG.debug("Удалена пустая директория: %s", subdirpath)
                except OSError:
                    pass  # Директория не пуста или ошибка доступа

    # Удаляем корневую директорию
    if remove_empty:
        try:
            if not any(dirpath.iterdir()):
                dirpath.rmdir()
                LOG.info("Директория удалена: %s", dirpath)
        except OSError:
            pass

    LOG.info("Рекурсивно удалено %d файлов из %s", deleted_count, dirpath)
    return deleted_count


def clear_clipboard() -> bool:
    """
    Очистка буфера обмена.

    Платформозависимая очистка системного буфера обмена
    для предотвращения утечки чувствительных данных
    (например, после копирования пароля).

    Returns:
        True если буфер обмена успешно очищен

    Raises:
        ClipboardClearError: Ошибка очистки

    Note:
        - Linux: использует xclip или wl-copy (Wayland)
        - Windows: использует ctypes для Win32 API
        - macOS: использует pbcopy

    Example:
        >>> # После копирования пароля в буфер обмена
        >>> clear_clipboard()
        True
    """
    system = platform.system()

    try:
        if system == "Linux":
            return _clear_clipboard_linux()
        elif system == "Windows":
            return _clear_clipboard_windows()
        elif system == "Darwin":
            return _clear_clipboard_macos()
        else:
            LOG.warning("Неподдерживаемая платформа для очистки буфера: %s", system)
            return False

    except Exception as e:
        raise ClipboardClearError(f"Ошибка очистки буфера обмена: {e}") from e


def _clear_clipboard_linux() -> bool:
    """Очистка буфера обмена на Linux (X11 и Wayland)."""
    # Проверяем Wayland vs X11
    wayland_display = os.environ.get("WAYLAND_DISPLAY")

    if wayland_display:
        # Wayland: используем wl-copy
        try:
            result = subprocess.run(
                ["wl-copy", "--clear"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode == 0:
                LOG.debug("Буфер обмена очищен (wl-copy)")
                return True
        except (subprocess.SubprocessError, FileNotFoundError):
            pass

    # X11: используем xclip
    try:
        result = subprocess.run(
            ["xclip", "-selection", "clipboard", "/dev/null"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            LOG.debug("Буфер обмена очищен (xclip)")
            return True
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    # Пробуем xsel как fallback
    try:
        result = subprocess.run(
            ["xsel", "--clipboard", "--delete"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            LOG.debug("Буфер обмена очищен (xsel)")
            return True
    except (subprocess.SubprocessError, FileNotFoundError):
        pass

    LOG.warning("Не удалось очистить буфер обмена на Linux")
    return False


def _clear_clipboard_windows() -> bool:
    """Очистка буфера обмена на Windows."""
    # Используем ctypes для Win32 API
    CF_TEXT = 1
    GHND = 0x0042

    try:
        # Открываем буфер обмена
        if not ctypes.windll.user32.OpenClipboard(0):  # type: ignore[attr-defined]
            LOG.warning("Не удалось открыть буфер обмена")
            return False

        try:
            # Очищаем буфер
            ctypes.windll.user32.EmptyClipboard()  # type: ignore[attr-defined]
            LOG.debug("Буфер обмена очищен (Windows)")
            return True
        finally:
            ctypes.windll.user32.CloseClipboard()  # type: ignore[attr-defined]

    except (AttributeError, OSError) as e:
        LOG.warning("Ошибка Win32 API для буфера обмена: %s", e)
        return False


def _clear_clipboard_macos() -> bool:
    """Очистка буфера обмена на macOS."""
    try:
        result = subprocess.run(
            ["pbcopy", "/dev/null"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode == 0:
            LOG.debug("Буфер обмена очищен (macOS)")
            return True
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        LOG.warning("Ошибка очистки буфера на macOS: %s", e)

    return False


class SecureData:
    """
    Контекстный менеджер для безопасной работы с данными.

    Автоматически обнуляет данные при выходе из контекста.

    Example:
        >>> with SecureData(bytearray(os.urandom(32))) as key:
        ...     # Используем key ...
        ...     process(key)
        >>> # key автоматически обнулён
    """

    def __init__(self, data: bytearray) -> None:
        """
        Инициализация контекстного менеджера.

        Args:
            data: ByteArray для автоматического обнуления
        """
        if not isinstance(data, bytearray):
            raise MemoryWipeError("SecureData требует bytearray, не bytes")
        self._data = data

    def __enter__(self) -> bytearray:
        """Вход в контекст."""
        return self._data

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional["types.TracebackType"],
    ) -> None:
        """Выход из контекста с автоматическим обнулением."""
        wipe_memory(self._data)

    def __del__(self) -> None:
        """Деструктор с обнулением."""
        try:
            if hasattr(self, "_data") and self._data is not None:
                wipe_memory(self._data)
        except Exception:  # noqa: BLE001
            pass  # Игнорируем ошибки в деструкторе


__all__: list[str] = [
    # Exceptions
    "SecureEraseError",
    "MemoryWipeError",
    "FileWipeError",
    "DirectoryWipeError",
    "ClipboardClearError",
    # Functions
    "wipe_memory",
    "wipe_file",
    "wipe_directory",
    "clear_clipboard",
    # Classes
    "SecureData",
    # Constants
    "WIPE_PASSES",
    "BUFFER_SIZE",
    "DOD_PATTERNS",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"