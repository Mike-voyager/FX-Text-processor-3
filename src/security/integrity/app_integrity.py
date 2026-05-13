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
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Optional

from src.security.integrity.exceptions import IntegrityCheckError
from src.security.integrity.models import IntegrityCheckResult

LOG = logging.getLogger(__name__)

# Размер буфера для чтения файла (64 KB)
HASH_BUFFER_SIZE: Final[int] = 65536


@dataclass(frozen=True)
class AppHashRegistry:
    """Реестр зарегистрированного хеша приложения.

    Содержит эталонный хеш и метаданные для верификации.

    Attributes:
        hash_value: Эталонный хеш в hex формате
        algorithm: Алгоритм хеширования
        file_name: Имя файла приложения
        registration_time: Время регистрации
    """

    hash_value: str
    algorithm: str
    file_name: str
    registration_time: str


class AppIntegrityChecker:
    """Проверка целостности бинарного файла приложения.

    Вычисляет SHA3-256 хеш исполняемого файла и сравнивает
    с сохранённым ожидаемым хешем. Поддерживает:
    - Python скрипты (.py)
    - Компилированные executables (.exe, бинарники)
    - PyInstaller bundles

    Attributes:
        expected_hash: Ожидаемый хеш приложения (hex)
        app_path: Путь к исполняемому файлу
        hash_algorithm: Алгоритм хеширования (SHA3-256)

    Example:
        >>> checker = AppIntegrityChecker(Path("/app/.app-hash"))
        >>> result = checker.verify()
        >>> if result.valid:
        ...     print("Приложение не модифицировано")
        ... else:
        ...     print(f"Нарушение целостности: {result.reason}")
    """

    __slots__ = ("_reference_path", "_algorithm", "_app_path")

    def __init__(
        self,
        reference_hash_path: Path,
        algorithm: str = "SHA3-256",
    ) -> None:
        """Инициализация проверяющего.

        Args:
            reference_hash_path: Путь к файлу с эталонным hash
            algorithm: Алгоритм hash (SHA3-256, SHA-256, etc.)

        Raises:
            IntegrityCheckError: Некорректные параметры
        """
        self._reference_path = reference_hash_path
        self._algorithm = algorithm.upper()
        self._app_path = self._detect_app_path()

        # Проверяем поддержку алгоритма
        if self._algorithm not in (
            "SHA3-256",
            "SHA-256",
            "SHA3-512",
            "SHA-512",
            "BLAKE2b",
        ):
            raise IntegrityCheckError(
                f"Неподдерживаемый алгоритм хеширования: {algorithm}",
                context={
                    "supported": [
                        "SHA3-256",
                        "SHA-256",
                        "SHA3-512",
                        "SHA-512",
                        "BLAKE2b",
                    ]
                },
            )

    def _detect_app_path(self) -> Path:
        """Автоматическое определение пути к приложению.

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

    def _compute_hash(self, file_path: Path) -> str:
        """Вычисление hash файла.

        Использует hashlib для SHA3-256, чтение блоками для больших файлов.

        Args:
            file_path: Путь к файлу для хеширования

        Returns:
            Хеш в hex формате

        Raises:
            IntegrityCheckError: Ошибка чтения или хеширования
        """
        if not file_path.exists():
            raise IntegrityCheckError(
                f"Файл не найден: {file_path}",
                file_path=str(file_path),
            )

        try:
            # Выбираем алгоритм
            if self._algorithm == "SHA3-256":
                hasher = hashlib.sha3_256()
            elif self._algorithm == "SHA-256":
                hasher = hashlib.sha256()
            elif self._algorithm == "SHA3-512":
                hasher = hashlib.sha3_512()
            elif self._algorithm == "SHA-512":
                hasher = hashlib.sha512()
            elif self._algorithm == "BLAKE2b":
                hasher = hashlib.blake2b()
            else:
                hasher = hashlib.sha3_256()  # Fallback

            # Читаем файл блоками
            with open(file_path, "rb") as f:
                while chunk := f.read(HASH_BUFFER_SIZE):
                    hasher.update(chunk)

            computed_hash = hasher.hexdigest()
            LOG.debug("Computed hash for %s: %s...", file_path, computed_hash[:16])
            return computed_hash

        except PermissionError as e:
            raise IntegrityCheckError(
                f"Нет прав для чтения файла: {file_path}",
                file_path=str(file_path),
            ) from e
        except OSError as e:
            raise IntegrityCheckError(
                f"Ошибка чтения файла: {e}",
                file_path=str(file_path),
            ) from e

    def _load_expected_hash(self) -> Optional[str]:
        """Загрузка ожидаемого хеша из реестра.

        Returns:
            Ожидаемый хеш (hex) или None

        Raises:
            IntegrityCheckError: Ошибка чтения файла
        """
        if not self._reference_path.exists():
            LOG.warning("Файл с эталонным хешем не найден: %s", self._reference_path)
            return None

        try:
            hash_content = self._reference_path.read_text(encoding="utf-8").strip()
            # Формат: <hash>  или  <hash>  <filename>
            expected = hash_content.split()[0].lower()
            LOG.debug("Loaded expected hash from file: %s...", expected[:16])
            return expected
        except OSError as e:
            raise IntegrityCheckError(
                f"Не удалось прочитать файл хеша: {e}",
                file_path=str(self._reference_path),
            ) from e

    def verify(self) -> IntegrityCheckResult:
        """Проверка hash текущего исполняемого файла.

        Получает путь к текущему исполняемому файлу, вычисляет hash
        и сравнивает с эталонным.

        Returns:
            IntegrityCheckResult с результатом проверки
        """
        # Загружаем ожидаемый хеш
        expected_hash = self._load_expected_hash()

        if expected_hash is None:
            LOG.warning("Эталонный хеш не задан — проверка пропущена")
            return IntegrityCheckResult(
                valid=True,
                reason="Проверка пропущена: эталонный хеш не задан",
                expected_hash=None,
                actual_hash=None,
                warnings=["Эталонный хеш не задан — проверка целостности пропущена"],
                metadata={
                    "file_path": str(self._app_path),
                    "algorithm": self._algorithm,
                },
            )

        # Вычисляем фактический хеш
        try:
            actual_hash = self._compute_hash(self._app_path)
        except IntegrityCheckError as e:
            return IntegrityCheckResult(
                valid=False,
                reason="Ошибка вычисления хеша",
                expected_hash=expected_hash,
                actual_hash=None,
                error_message=e.message,
                metadata={
                    "file_path": str(self._app_path),
                    "algorithm": self._algorithm,
                },
            )

        # Сравниваем хеши
        expected_clean = expected_hash.lower().strip()
        actual_clean = actual_hash.lower().strip()

        if expected_clean == actual_clean:
            LOG.info("Целостность приложения подтверждена: %s", self._app_path)
            return IntegrityCheckResult(
                valid=True,
                reason="Хеш совпадает — целостность подтверждена",
                expected_hash=expected_clean,
                actual_hash=actual_clean,
                metadata={
                    "file_path": str(self._app_path),
                    "algorithm": self._algorithm,
                    "reference_file": str(self._reference_path),
                },
            )

        # Нарушение целостности
        LOG.error(
            "Нарушение целостности! Expected: %s..., Actual: %s...",
            expected_clean[:16],
            actual_clean[:16],
        )
        return IntegrityCheckResult(
            valid=False,
            reason="Нарушение целостности: хеш не совпадает",
            expected_hash=expected_clean,
            actual_hash=actual_clean,
            error_message="Хеш приложения не совпадает с ожидаемым — возможно, файл был изменён",
            metadata={
                "file_path": str(self._app_path),
                "algorithm": self._algorithm,
                "reference_file": str(self._reference_path),
            },
        )

    def register_hash(self) -> None:
        """Регистрация текущего hash как эталонного.

        Вычисляет hash, сохраняет в reference_hash_path.
        Используется при сборке или первоначальной настройке.

        Raises:
            IntegrityCheckError: Ошибка записи файла
        """
        # Вычисляем текущий хеш
        current_hash = self._compute_hash(self._app_path)

        # Создаём директорию если нужно
        self._reference_path.parent.mkdir(parents=True, exist_ok=True)

        # Сохраняем хеш
        try:
            # Формат: <hash>  <filename>
            content = f"{current_hash}  {self._app_path.name}\n"
            self._reference_path.write_text(content, encoding="utf-8")
            LOG.info("Хеш зарегистрирован: %s", self._reference_path)
        except OSError as e:
            raise IntegrityCheckError(
                f"Ошибка записи файла хеша: {e}",
                file_path=str(self._reference_path),
            ) from e

    @property
    def reference_path(self) -> Path:
        """Путь к файлу с эталонным хешем."""
        return self._reference_path

    @property
    def app_path(self) -> Path:
        """Путь к исполняемому файлу приложения."""
        return self._app_path

    @property
    def algorithm(self) -> str:
        """Алгоритм хеширования."""
        return self._algorithm

    def __repr__(self) -> str:
        return (
            f"AppIntegrityChecker("
            f"app_path={self._app_path!r}, "
            f"reference_path={self._reference_path!r}, "
            f"algorithm={self._algorithm!r})"
        )


__all__: list[str] = [
    "AppIntegrityChecker",
    "AppHashRegistry",
    "HASH_BUFFER_SIZE",
]

__version__ = "1.0.0"
__author__ = "FX Text Processor Team"
__date__ = "2026-03-23"
