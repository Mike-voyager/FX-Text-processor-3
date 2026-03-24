"""
Проверка целостности бинарника приложения.

AppIntegrityChecker вычисляет и проверяет SHA3-256 хеш
исполняемого файла приложения при запуске.

Security:
    - SHA3-256 для хеширования (устойчив к коллизиям)
    - Предотвращение несанкционированных модификаций
    - Zero Trust: проверка при каждом запуске

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from pathlib import Path
from typing import Final, Optional

from src.security.integrity.exceptions import IntegrityCheckError
from src.security.integrity.models import (
    IntegrityCheckResult,
    IntegrityCheckType,
)

LOG = logging.getLogger(__name__)

# Размер буфера для чтения файла (64 KB)
HASH_BUFFER_SIZE: Final[int] = 65536

# Имя файла с ожидаемым хешем
HASH_FILE_NAME: Final[str] = ".app-hash"


class AppIntegrityChecker:
    """
    Проверка целостности бинарника приложения.

    Вычисляет SHA3-256 хеш исполняемого файла и сравнивает
    с сохранённым ожидаемым хешем. Поддерживает:
    - Python скрипты (.py)
    - Компилированные executables (.exe, бинарники)
    - PyInstaller bundles

    Attributes:
        expected_hash: Ожидаемый хеш приложения (hex)
        app_path: Путь к исполняемому файлу
        hash_algorithm: Алгоритм хеширования (sha3-256)

    Example:
        >>> checker = AppIntegrityChecker()
        >>> result = checker.check_integrity()
        >>> if result.passed:
        ...     print("Приложение не модифицировано")
        ... else:
        ...     print(f"Нарушение целостности: {result.error_message}")
    """

    __slots__ = ("_expected_hash", "_app_path", "_hash_file_path")

    def __init__(
        self,
        expected_hash: Optional[str] = None,
        app_path: Optional[Path] = None,
        hash_file_path: Optional[Path] = None,
    ) -> None:
        """
        Инициализация проверяющего.

        Args:
            expected_hash: Ожидаемый хеш (hex строка). Если None, читается
                           из файла или из переменной окружения APP_HASH.
            app_path: Путь к исполняемому файлу. Если None, определяется
                     автоматически (sys.executable или __file__).
            hash_file_path: Путь к файлу с хешем. Если None, ищется
                           рядом с исполняемым файлом.

        Raises:
            IntegrityCheckError: Не удалось определить путь к приложению
        """
        self._app_path = app_path or self._detect_app_path()
        self._hash_file_path = hash_file_path or self._detect_hash_file()
        self._expected_hash = expected_hash or self._load_expected_hash()

    @staticmethod
    def _detect_app_path() -> Path:
        """
        Автоматическое определение пути к приложению.

        Returns:
            Путь к исполняемому файлу

        Raises:
            IntegrityCheckError: Не удалось определить путь
        """
        # PyInstaller / cx_Freeze bundle
        if getattr(sys, "frozen", False):
            # frozen=True если запущен как executable
            app_path = Path(sys.executable)
            LOG.debug("Detected frozen app: %s", app_path)
            return app_path

        # Python скрипт
        if sys.argv and sys.argv[0]:
            app_path = Path(sys.argv[0]).resolve()
            if app_path.exists():
                LOG.debug("Detected Python script: %s", app_path)
                return app_path

        # Fallback: текущий исполняемый файл Python
        if sys.executable:
            app_path = Path(sys.executable)
            LOG.debug("Using Python executable: %s", app_path)
            return app_path

        raise IntegrityCheckError(
            "Не удалось определить путь к приложению",
            context={"sys_argv": str(sys.argv), "sys_executable": str(sys.executable)},
        )

    def _detect_hash_file(self) -> Optional[Path]:
        """
        Поиск файла с ожидаемым хешем.

        Returns:
            Путь к файлу с хешем или None
        """
        # Ищем файл рядом с исполняемым
        hash_file = self._app_path.parent / HASH_FILE_NAME
        if hash_file.exists():
            return hash_file

        # Ищем в текущей директории
        hash_file = Path.cwd() / HASH_FILE_NAME
        if hash_file.exists():
            return hash_file

        return None

    def _load_expected_hash(self) -> Optional[str]:
        """
        Загрузка ожидаемого хеша из источника.

        Приоритет:
        1. Переменная окружения APP_HASH
        2. Файл .app-hash
        3. Встроенный хеш (для PyInstaller)

        Returns:
            Ожидаемый хеш (hex) или None
        """
        # 1. Переменная окружения
        env_hash = os.environ.get("APP_HASH")
        if env_hash:
            LOG.debug("Loaded hash from environment: %s...", env_hash[:16])
            return env_hash.lower().strip()

        # 2. Файл с хешем
        if self._hash_file_path and self._hash_file_path.exists():
            try:
                hash_content = self._hash_file_path.read_text(encoding="utf-8").strip()
                # Формат: <hash>  или  <hash>  <filename>
                expected = hash_content.split()[0].lower()
                LOG.debug("Loaded hash from file: %s...", expected[:16])
                return expected
            except OSError as e:
                LOG.warning("Не удалось прочитать файл хеша: %s", e)

        # 3. Встроенный хеш (для PyInstaller)
        if getattr(sys, "frozen", False):
            # PyInstaller добавляет __file__ к executable
            builtin_hash = getattr(sys, "_MEIAPP_HASH", None)
            if isinstance(builtin_hash, str):
                result: str = builtin_hash.lower()
                LOG.debug("Loaded builtin hash: %s...", result[:16])
                return result

        return None

    def compute_hash(self) -> str:
        """
        Вычисление SHA3-256 хеша приложения.

        Returns:
            Хеш в hex формате (64 символа)

        Raises:
            IntegrityCheckError: Файл не найден или ошибка чтения
        """
        if not self._app_path.exists():
            raise IntegrityCheckError(
                f"Файл приложения не найден: {self._app_path}",
                file_path=str(self._app_path),
            )

        try:
            hasher = hashlib.sha3_256()

            with open(self._app_path, "rb") as f:
                while chunk := f.read(HASH_BUFFER_SIZE):
                    hasher.update(chunk)

            computed_hash = hasher.hexdigest()
            LOG.debug("Computed hash: %s for %s", computed_hash[:16], self._app_path)
            return computed_hash

        except PermissionError as e:
            raise IntegrityCheckError(
                f"Нет прав для чтения файла: {self._app_path}",
                file_path=str(self._app_path),
            ) from e
        except OSError as e:
            raise IntegrityCheckError(
                f"Ошибка чтения файла: {e}",
                file_path=str(self._app_path),
            ) from e

    def check_integrity(
        self,
        expected_hash: Optional[str] = None,
    ) -> IntegrityCheckResult:
        """
        Проверка целостности приложения.

        Вычисляет текущий хеш и сравнивает с ожидаемым.

        Args:
            expected_hash: Переопределить ожидаемый хеш.
                          Если None, используется сохранённый.

        Returns:
            IntegrityCheckResult с результатом проверки

        Example:
            >>> result = checker.check_integrity()
            >>> result.passed
            True
            >>> result.actual_hash[:16]
            'a1b2c3d4e5f6...'
        """
        # Определяем ожидаемый хеш
        expected = expected_hash or self._expected_hash

        if expected is None:
            LOG.warning("Ожидаемый хеш не задан — пропуск проверки")
            return IntegrityCheckResult(
                check_type=IntegrityCheckType.APP_BINARY,
                passed=True,
                file_path=str(self._app_path),
                algorithm="sha3-256",
                warnings=["Ожидаемый хеш не задан — проверка пропущена"],
            )

        # Вычисляем фактический хеш
        try:
            actual_hash = self.compute_hash()
        except IntegrityCheckError as e:
            return IntegrityCheckResult(
                check_type=IntegrityCheckType.APP_BINARY,
                passed=False,
                file_path=str(self._app_path),
                algorithm="sha3-256",
                error_message=e.message,
            )

        # Сравниваем хеши
        expected_clean = expected.lower().strip()
        actual_clean = actual_hash.lower().strip()

        if expected_clean == actual_clean:
            LOG.info("Целостность приложения подтверждена")
            return IntegrityCheckResult(
                check_type=IntegrityCheckType.APP_BINARY,
                passed=True,
                expected_hash=expected_clean,
                actual_hash=actual_clean,
                file_path=str(self._app_path),
                algorithm="sha3-256",
            )

        # Нарушение целостности
        LOG.error(
            "Нарушение целостности! Expected: %s..., Actual: %s...",
            expected_clean[:16],
            actual_clean[:16],
        )
        return IntegrityCheckResult(
            check_type=IntegrityCheckType.APP_BINARY,
            passed=False,
            expected_hash=expected_clean,
            actual_hash=actual_clean,
            file_path=str(self._app_path),
            algorithm="sha3-256",
            error_message="Хеш приложения не совпадает с ожидаемым",
        )

    @property
    def app_path(self) -> Path:
        """Путь к исполняемому файлу."""
        return self._app_path

    @property
    def expected_hash(self) -> Optional[str]:
        """Ожидаемый хеш (если задан)."""
        return self._expected_hash

    @property
    def hash_file_path(self) -> Optional[Path]:
        """Путь к файлу с хешем."""
        return self._hash_file_path

    def save_current_hash(self, output_path: Optional[Path] = None) -> Path:
        """
        Сохранение текущего хеша в файл.

        Используется для генерации файла хеша при сборке.

        Args:
            output_path: Путь для сохранения. По умолчанию .app-hash
                         рядом с исполняемым файлом.

        Returns:
            Путь к созданному файлу

        Raises:
            IntegrityCheckError: Ошибка записи файла
        """
        current_hash = self.compute_hash()
        save_path = output_path or (self._app_path.parent / HASH_FILE_NAME)

        try:
            save_path.write_text(f"{current_hash}  {self._app_path.name}\n", encoding="utf-8")
            LOG.info("Хеш сохранён в %s", save_path)
            return save_path
        except OSError as e:
            raise IntegrityCheckError(
                f"Ошибка записи файла хеша: {e}",
                file_path=str(save_path),
            ) from e

    def __repr__(self) -> str:
        return (
            f"AppIntegrityChecker("
            f"app_path={self._app_path!r}, "
            f"has_expected_hash={self._expected_hash is not None})"
        )


__all__: list[str] = [
    "AppIntegrityChecker",
    "HASH_BUFFER_SIZE",
    "HASH_FILE_NAME",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"