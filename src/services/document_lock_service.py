"""Сервис блокировки документов.

Защита от одновременного редактирования документов разными процессами.
Использует файлы блокировок (lock files) с информацией о владельце.

Module: src/services/document_lock_service.py
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------

LOCK_EXTENSION = ".lock"
LOCK_TIMEOUT_SECONDS = 300  # 5 минут - после этого считаем блокировку устаревшей


# ---------------------------------------------------------------------------
# Модели данных
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LockInfo:
    """Информация о блокировке файла.

    Attrs:
        owner_id: Идентификатор владельца (session_id)
        owner_name: Имя владельца (optional)
        locked_at: Время блокировки
        file_path: Путь к заблокированному файлу
        lock_file_path: Путь к файлу блокировки
        hostname: Имя хоста (optional)
        pid: ID процесса (optional)
    """

    owner_id: str
    owner_name: str = ""
    locked_at: datetime = field(default_factory=datetime.now)
    file_path: Path = field(default_factory=lambda: Path(""))
    lock_file_path: Path = field(default_factory=lambda: Path(""))
    hostname: str = ""
    pid: int = 0


@dataclass(frozen=True)
class LockResult:
    """Результат операции блокировки.

    Attrs:
        success: True при успехе
        lock_info: Информация о блокировке (если успешна)
        error: Сообщение об ошибке или None
        existing_lock: Информация о существующей блокировке (если есть)
    """

    success: bool
    lock_info: Optional[LockInfo] = None
    error: Optional[str] = None
    existing_lock: Optional[LockInfo] = None


# ---------------------------------------------------------------------------
# DocumentLockService
# ---------------------------------------------------------------------------


class DocumentLockService:
    """Сервис блокировки документов.

    Управляет файлами блокировок для защиты от одновременного редактирования:
    - Создание/удаление файлов блокировок
    - Проверка на устаревшие блокировки
    - Информация о владельце блокировки

    Пример:
        >>> service = DocumentLockService(owner_id="session-123")
        >>> result = service.try_lock(Path("document.fxsd"))
        >>> if result.success:
        ...     # Работаем с документом
        ...     service.release_lock(Path("document.fxsd"))
    """

    def __init__(
        self,
        owner_id: Optional[str] = None,
        owner_name: str = "",
        lock_dir: Optional[Path] = None,
        timeout_seconds: int = LOCK_TIMEOUT_SECONDS,
    ) -> None:
        """Инициализирует сервис блокировок.

        Args:
            owner_id: Идентификатор владельца (optional, генерируется)
            owner_name: Имя владельца для отображения
            lock_dir: Директория для файлов блокировок (optional)
            timeout_seconds: Таймаут устаревания блокировки
        """
        self._owner_id = owner_id or str(uuid4())
        self._owner_name = owner_name
        self._lock_dir = lock_dir
        self._timeout = timeout_seconds

        # Кэш активных блокировок
        self._locks: Dict[Path, LockInfo] = {}

        # Информация о процессе
        self._hostname = self._get_hostname()
        self._pid = os.getpid()

    # ---------- Основные операции ----------

    def try_lock(self, file_path: Path) -> LockResult:
        """Пытается захватить блокировку файла.

        Args:
            file_path: Путь к файлу

        Returns:
            LockResult с результатом операции
        """
        lock_file = self._get_lock_file_path(file_path)

        # Проверяем существующую блокировку
        existing = self._read_lock_file(lock_file)
        if existing:
            # Проверяем, не устарела ли блокировка
            if self._is_lock_expired(existing):
                logger.info("Удаляем устаревшую блокировку: %s", lock_file)
                self._delete_lock_file(lock_file)
            elif existing.owner_id == self._owner_id:
                # Наша блокировка - обновляем
                return self._create_lock(file_path, lock_file)
            else:
                # Блокировка другого владельца
                return LockResult(
                    success=False,
                    error="Файл заблокирован другим пользователем",
                    existing_lock=existing,
                )

        # Создаём новую блокировку
        return self._create_lock(file_path, lock_file)

    def release_lock(self, file_path: Path) -> bool:
        """Освобождает блокировку файла.

        Args:
            file_path: Путь к файлу

        Returns:
            True если блокировка освобождена
        """
        lock_file = self._get_lock_file_path(file_path)

        # Проверяем, наша ли блокировка
        existing = self._read_lock_file(lock_file)
        if not existing:
            # Блокировки нет
            return False

        if existing.owner_id != self._owner_id:
            logger.warning("Попытка освободить чужую блокировку: %s", lock_file)
            return False

        # Удаляем файл блокировки
        success = self._delete_lock_file(lock_file)

        # Удаляем из кэша
        if file_path in self._locks:
            del self._locks[file_path]

        if success:
            logger.debug("Блокировка освобождена: %s", file_path)

        return success

    def is_locked(self, file_path: Path) -> bool:
        """Проверяет, заблокирован ли файл.

        Args:
            file_path: Путь к файлу

        Returns:
            True если файл заблокирован
        """
        lock_file = self._get_lock_file_path(file_path)
        existing = self._read_lock_file(lock_file)

        if not existing:
            return False

        # Проверяем устаревание
        if self._is_lock_expired(existing):
            self._delete_lock_file(lock_file)
            return False

        return True

    def get_lock_info(self, file_path: Path) -> Optional[LockInfo]:
        """Возвращает информацию о блокировке файла.

        Args:
            file_path: Путь к файлу

        Returns:
            LockInfo или None если не заблокирован
        """
        lock_file = self._get_lock_file_path(file_path)
        return self._read_lock_file(lock_file)

    # ---------- Массовые операции ----------

    def release_all(self) -> int:
        """Освобождает все блокировки текущего владельца.

        Returns:
            Количество освобождённых блокировок
        """
        count = 0
        for file_path in list(self._locks.keys()):
            if self.release_lock(file_path):
                count += 1
        return count

    def get_all_locks(self) -> Dict[Path, LockInfo]:
        """Возвращает все активные блокировки текущего владельца.

        Returns:
            Словарь {путь_файла: информация_о_блокировке}
        """
        return dict(self._locks)

    # ---------- Утилиты ----------

    def set_owner_id(self, owner_id: str) -> None:
        """Устанавливает идентификатор владельца.

        Args:
            owner_id: Новый идентификатор
        """
        self._owner_id = owner_id

    def set_owner_name(self, owner_name: str) -> None:
        """Устанавливает имя владельца.

        Args:
            owner_name: Имя владельца
        """
        self._owner_name = owner_name

    # ---------- Внутренние методы ----------

    def _get_lock_file_path(self, file_path: Path) -> Path:
        """Возвращает путь к файлу блокировки.

        Args:
            file_path: Путь к файлу

        Returns:
            Путь к файлу блокировки
        """
        if self._lock_dir:
            # Используем отдельную директорию
            return self._lock_dir / f"{file_path.name}{LOCK_EXTENSION}"
        else:
            # Рядом с файлом
            return file_path.with_suffix(file_path.suffix + LOCK_EXTENSION)

    def _create_lock(self, file_path: Path, lock_file: Path) -> LockResult:
        """Создаёт файл блокировки.

        Args:
            file_path: Путь к файлу
            lock_file: Путь к файлу блокировки

        Returns:
            LockResult
        """
        lock_info = LockInfo(
            owner_id=self._owner_id,
            owner_name=self._owner_name,
            locked_at=datetime.now(),
            file_path=file_path,
            lock_file_path=lock_file,
            hostname=self._hostname,
            pid=self._pid,
        )

        try:
            # Создаём директорию если нужно
            lock_file.parent.mkdir(parents=True, exist_ok=True)

            # Записываем информацию о блокировке
            data = self._lock_info_to_dict(lock_info)
            lock_file.write_text(json.dumps(data, ensure_ascii=False, indent=2))

            # Добавляем в кэш
            self._locks[file_path] = lock_info

            logger.debug("Создана блокировка: %s", lock_file)
            return LockResult(success=True, lock_info=lock_info)

        except (OSError, PermissionError, TypeError, ValueError) as exc:
            error = f"Ошибка создания блокировки: {exc}"
            logger.error(error)
            return LockResult(success=False, error=error)

    def _delete_lock_file(self, lock_file: Path) -> bool:
        """Удаляет файл блокировки.

        Args:
            lock_file: Путь к файлу блокировки

        Returns:
            True если удалено успешно
        """
        try:
            if lock_file.exists():
                lock_file.unlink()
            return True
        except (OSError, PermissionError, TypeError, ValueError) as exc:
            logger.warning("Ошибка удаления файла блокировки: %s", exc)
            return False

    def _read_lock_file(self, lock_file: Path) -> Optional[LockInfo]:
        """Читает информацию из файла блокировки.

        Args:
            lock_file: Путь к файлу блокировки

        Returns:
            LockInfo или None
        """
        if not lock_file.exists():
            return None

        try:
            data = json.loads(lock_file.read_text())
            return self._dict_to_lock_info(data)
        except (OSError, PermissionError, TypeError, json.JSONDecodeError, ValueError) as exc:
            logger.warning("Ошибка чтения файла блокировки: %s", exc)
            return None

    def _is_lock_expired(self, lock_info: LockInfo) -> bool:
        """Проверяет, устарела ли блокировка.

        Args:
            lock_info: Информация о блокировке

        Returns:
            True если блокировка устарела
        """
        now = datetime.now()
        delta = (now - lock_info.locked_at).total_seconds()
        return delta > self._timeout

    def _lock_info_to_dict(self, lock_info: LockInfo) -> Dict[str, Any]:
        """Конвертирует LockInfo в словарь.

        Args:
            lock_info: Информация о блокировке

        Returns:
            Словарь для сериализации
        """
        return {
            "owner_id": lock_info.owner_id,
            "owner_name": lock_info.owner_name,
            "locked_at": lock_info.locked_at.isoformat(),
            "file_path": str(lock_info.file_path),
            "lock_file_path": str(lock_info.lock_file_path),
            "hostname": lock_info.hostname,
            "pid": lock_info.pid,
        }

    def _dict_to_lock_info(self, data: Dict[str, Any]) -> LockInfo:
        """Конвертирует словарь в LockInfo.

        Args:
            data: Словарь из файла

        Returns:
            LockInfo
        """
        return LockInfo(
            owner_id=data.get("owner_id", ""),
            owner_name=data.get("owner_name", ""),
            locked_at=datetime.fromisoformat(data.get("locked_at", datetime.now().isoformat())),
            file_path=Path(data.get("file_path", "")),
            lock_file_path=Path(data.get("lock_file_path", "")),
            hostname=data.get("hostname", ""),
            pid=data.get("pid", 0),
        )

    def _get_hostname(self) -> str:
        """Получает имя хоста.

        Returns:
            Имя хоста или пустую строку
        """
        import socket

        try:
            return socket.gethostname()
        except (OSError, socket.error) as e:
            logger.debug("Failed to get hostname: %s", e)
            return ""


__all__ = [
    "DocumentLockService",
    "LockInfo",
    "LockResult",
    "LOCK_EXTENSION",
    "LOCK_TIMEOUT_SECONDS",
]
