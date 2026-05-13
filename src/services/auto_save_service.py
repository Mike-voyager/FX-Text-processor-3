"""Сервис автосохранения.

Управляет таймером автосохранения для открытых документов.
Интегрируется с DocumentManagerService для сохранения изменённых документов.

Module: src/services/auto_save_service.py
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Optional, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from src.services.document_manager_service import DocumentManagerService

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Протоколы
# ---------------------------------------------------------------------------


class AutoSaveCallback(Protocol):
    """Протокол callback для автосохранения."""

    def __call__(self, document_id: UUID, path: Path) -> None:
        """Вызывается после автосохранения.

        Args:
            document_id: ID сохранённого документа
            path: Путь сохранения
        """
        ...


class AutoSaveErrorCallback(Protocol):
    """Протокол callback для ошибок автосохранения."""

    def __call__(self, document_id: UUID, error: str) -> None:
        """Вызывается при ошибке автосохранения.

        Args:
            document_id: ID документа
            error: Описание ошибки
        """
        ...


# ---------------------------------------------------------------------------
# Результаты операций
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AutoSaveStats:
    """Статистика автосохранения.

    Attrs:
        total_saves: Общее количество сохранений
        successful_saves: Успешные сохранения
        failed_saves: Неудачные сохранения
        last_save_time: Время последнего сохранения
        last_save_path: Путь последнего сохранения
    """

    total_saves: int = 0
    successful_saves: int = 0
    failed_saves: int = 0
    last_save_time: Optional[datetime] = None
    last_save_path: Optional[Path] = None


@dataclass
class AutoSaveConfig:
    """Конфигурация автосохранения.

    Attrs:
        enabled: Включено ли автосохранение
        interval_seconds: Интервал в секундах (по умолчанию 300 = 5 минут)
        save_modified_only: Сохранять только изменённые документы
        backup_enabled: Создавать резервные копии
        backup_suffix: Суффикс для резервных копий
    """

    enabled: bool = True
    interval_seconds: int = 300  # 5 минут
    save_modified_only: bool = True
    backup_enabled: bool = True
    backup_suffix: str = ".bak"


# ---------------------------------------------------------------------------
# AutoSaveService
# ---------------------------------------------------------------------------


class AutoSaveService:
    """Сервис автоматического сохранения документов.

    Запускает таймер для периодического сохранения изменённых документов.
    Интегрируется с DocumentManagerService.

    Пример:
        >>> from src.services.auto_save_service import AutoSaveService
        >>> auto_save = AutoSaveService(document_manager)
        >>> auto_save.start()
        >>> # ... работа с документами ...
        >>> auto_save.stop()
    """

    def __init__(
        self,
        document_manager: "DocumentManagerService",
        config: Optional[AutoSaveConfig] = None,
        on_save: Optional[AutoSaveCallback] = None,
        on_error: Optional[AutoSaveErrorCallback] = None,
    ) -> None:
        """Инициализирует сервис автосохранения.

        Args:
            document_manager: Менеджер документов
            config: Конфигурация (optional, используется по умолчанию)
            on_save: Callback при успешном сохранении
            on_error: Callback при ошибке сохранения
        """
        self._manager = document_manager
        self._config = config or AutoSaveConfig()
        self._on_save = on_save
        self._on_error = on_error

        # Состояние
        self._timer: Optional[threading.Timer] = None
        self._running = False
        self._lock = threading.Lock()
        self._stats = AutoSaveStats()
        self._document_stats: Dict[UUID, AutoSaveStats] = {}

    # ---------- Управление таймером ----------

    def start(self) -> None:
        """Запускает таймер автосохранения."""
        with self._lock:
            if self._running:
                logger.warning("Автосохранение уже запущено")
                return

            if not self._config.enabled:
                logger.info("Автосохранение отключено в конфигурации")
                return

            self._running = True
            self._schedule_next()
            logger.info(
                "Автосохранение запущено (интервал: %d сек)",
                self._config.interval_seconds,
            )

    def stop(self) -> None:
        """Останавливает таймер автосохранения."""
        with self._lock:
            if not self._running:
                return

            self._running = False
            if self._timer:
                self._timer.cancel()
                self._timer = None

            logger.info("Автосохранение остановлено")

    def restart(self) -> None:
        """Перезапускает таймер с новой конфигурацией."""
        self.stop()
        self.start()

    def is_running(self) -> bool:
        """Проверяет, запущено ли автосохранение."""
        return self._running

    # ---------- Конфигурация ----------

    def get_config(self) -> AutoSaveConfig:
        """Возвращает текущую конфигурацию."""
        return self._config

    def set_config(self, config: AutoSaveConfig) -> None:
        """Устанавливает новую конфигурацию и перезапускает.

        Args:
            config: Новая конфигурация
        """
        self._config = config
        if self._running:
            self.restart()

    def set_interval(self, seconds: int) -> None:
        """Устанавливает интервал автосохранения.

        Args:
            seconds: Интервал в секундах (минимум 10)
        """
        self._config.interval_seconds = max(10, seconds)
        if self._running:
            self.restart()

    def enable(self) -> None:
        """Включает автосохранение."""
        self._config.enabled = True
        if not self._running:
            self.start()

    def disable(self) -> None:
        """Выключает автосохранение."""
        self._config.enabled = False
        self.stop()

    # ---------- Сохранение ----------

    def save_all_modified(self) -> Dict[UUID, bool]:
        """Сохраняет все изменённые документы.

        Returns:
            Словарь {document_id: success}
        """
        results: Dict[UUID, bool] = {}
        modified_docs = list(self._manager.modified_documents)

        for doc in modified_docs:
            if doc.id is None:
                continue

            doc_id = doc.id
            path = self._manager.get_document_path(doc_id)

            if path is None:
                # Документ не сохранён, пропускаем
                logger.debug("Документ %s не имеет пути, пропускаем", doc_id)
                results[doc_id] = False
                continue

            success = self._save_document(doc_id, path)
            results[doc_id] = success

        return results

    def _save_document(self, document_id: UUID, path: Path) -> bool:
        """Сохраняет один документ.

        Args:
            document_id: ID документа
            path: Путь сохранения

        Returns:
            True при успехе
        """
        # Создаём резервную копию если включено
        if self._config.backup_enabled and path.exists():
            self._create_backup(path)

        # Сохраняем через менеджер
        result = self._manager.save(document_id, path)

        # Обновляем статистику
        self._update_stats(document_id, result.success)

        if result.success:
            # Вызываем callback
            if self._on_save:
                try:
                    self._on_save(document_id, path)
                except Exception as exc:
                    logger.error("Ошибка callback on_save: %s", exc)
            logger.debug("Автосохранение: %s -> %s", document_id, path)
        else:
            # Вызываем callback ошибки
            if self._on_error:
                try:
                    self._on_error(document_id, result.error or "Unknown error")
                except Exception as exc:
                    logger.error("Ошибка callback on_error: %s", exc)
            logger.error("Ошибка автосохранения %s: %s", document_id, result.error)

        return result.success

    def _create_backup(self, path: Path) -> None:
        """Создаёт резервную копию файла.

        Args:
            path: Путь к файлу
        """
        try:
            import shutil

            backup_path = path.with_suffix(path.suffix + self._config.backup_suffix)
            shutil.copy2(path, backup_path)
            logger.debug("Создана резервная копия: %s", backup_path)

        except Exception as exc:
            logger.warning("Не удалось создать резервную копию: %s", exc)

    def _update_stats(self, document_id: UUID, success: bool) -> None:
        """Обновляет статистику сохранения.

        Args:
            document_id: ID документа
            success: Успешность сохранения
        """
        # Обновляем общую статистику
        total = self._stats.total_saves + 1
        successful = self._stats.successful_saves + (1 if success else 0)
        failed = self._stats.failed_saves + (0 if success else 1)

        self._stats = AutoSaveStats(
            total_saves=total,
            successful_saves=successful,
            failed_saves=failed,
            last_save_time=datetime.now(),
            last_save_path=self._manager.get_document_path(document_id),
        )

        # Обновляем статистику документа
        doc_stats = self._document_stats.get(document_id, AutoSaveStats())
        doc_total = doc_stats.total_saves + 1
        doc_successful = doc_stats.successful_saves + (1 if success else 0)
        doc_failed = doc_stats.failed_saves + (0 if success else 1)

        self._document_stats[document_id] = AutoSaveStats(
            total_saves=doc_total,
            successful_saves=doc_successful,
            failed_saves=doc_failed,
            last_save_time=datetime.now(),
            last_save_path=self._manager.get_document_path(document_id),
        )

    # ---------- Таймер ----------

    def _schedule_next(self) -> None:
        """Планирует следующий запуск автосохранения."""
        if not self._running:
            return

        self._timer = threading.Timer(
            self._config.interval_seconds,
            self._auto_save_callback,
        )
        self._timer.daemon = True
        self._timer.start()

    def _auto_save_callback(self) -> None:
        """Callback таймера для автосохранения."""
        if not self._running:
            return

        try:
            # Сохраняем изменённые документы
            self.save_all_modified()

        except Exception as exc:
            logger.error("Ошибка автосохранения: %s", exc, exc_info=True)

        finally:
            # Планируем следующий запуск
            with self._lock:
                if self._running:
                    self._schedule_next()

    # ---------- Статистика ----------

    def get_stats(self) -> AutoSaveStats:
        """Возвращает общую статистику автосохранения."""
        return self._stats

    def get_document_stats(self, document_id: UUID) -> Optional[AutoSaveStats]:
        """Возвращает статистику для конкретного документа.

        Args:
            document_id: ID документа

        Returns:
            Статистика или None
        """
        return self._document_stats.get(document_id)

    def reset_stats(self) -> None:
        """Сбрасывает статистику."""
        self._stats = AutoSaveStats()
        self._document_stats.clear()


__all__ = [
    "AutoSaveService",
    "AutoSaveConfig",
    "AutoSaveStats",
    "AutoSaveCallback",
    "AutoSaveErrorCallback",
]
