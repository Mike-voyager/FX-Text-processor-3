"""Сервис автоматической блокировки сессии для FX Text Processor 3.

Предоставляет фоновый сервис для автоматической блокировки сессии
по таймауту бездействия пользователя.

Architecture:
    - Background thread для мониторинга
    - Thread-safe через Event и Timer
    - Graceful shutdown через stop()
    - Интеграция с SessionLockManager

Example:
    >>> from src.security.lock import SessionLockManager, AutoLockService
    >>> lock_manager = SessionLockManager(auth_controller)
    >>> auto_lock = AutoLockService(lock_manager, check_interval_seconds=60.0)
    >>> auto_lock.start()
    >>> # При активности пользователя:
    >>> auto_lock.on_user_activity()
    >>> # При завершении:
    >>> auto_lock.stop()
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, List, Optional, Protocol

if TYPE_CHECKING:
    from src.security.lock.session_lock_manager import (
        SessionLockManager,
    )


logger = logging.getLogger(__name__)


class AutoLockState(Enum):
    """Состояние сервиса автоблокировки."""

    STOPPED = "stopped"
    RUNNING = "running"
    PAUSED = "paused"
    LOCKING = "locking"


class AutoLockError(Exception):
    """Базовое исключение для ошибок автоблокировки."""

    pass


class ServiceAlreadyRunningError(AutoLockError):
    """Сервис уже запущен."""

    pass


class ServiceNotRunningError(AutoLockError):
    """Сервис не запущен."""

    pass


class ActivityListener(Protocol):
    """Протокол слушателя активности пользователя."""

    def on_activity_detected(self, timestamp: float) -> None:
        """Вызывается при обнаружении активности.

        Args:
            timestamp: Время активности (unix timestamp)
        """
        ...


@dataclass
class AutoLockStats:
    """Статистика автоблокировки.

    Attributes:
        start_time: Время запуска сервиса
        check_count: Количество выполненных проверок
        lock_count: Количество автоблокировок
        last_check_time: Время последней проверки
        last_lock_time: Время последней блокировки
    """

    start_time: Optional[float] = None
    check_count: int = 0
    lock_count: int = 0
    last_check_time: Optional[float] = None
    last_lock_time: Optional[float] = None


class AutoLockService:
    """Сервис автоматической блокировки по таймауту.

    Запускает фоновый поток, который периодически проверяет
    время бездействия пользователя и блокирует сессию при
    превышении порога.

    Attributes:
        _lock_manager: Менеджер блокировки сессии
        _interval: Интервал проверки в секундах
        _timer: Таймер для следующей проверки
        _running: Флаг состояния сервиса
        _state: Текущее состояние сервиса
        _lock: Блокировка для thread-safety
        _pause_event: Событие для паузы
        _activity_listeners: Слушатели активности
        _stats: Статистика сервиса

    Thread Safety:
        Все операции thread-safe через threading.Lock.

    Example:
        >>> service = AutoLockService(lock_manager, check_interval_seconds=60.0)
        >>> service.start()
        >>> # В UI thread:
        >>> root.bind("<KeyPress>", lambda e: service.on_user_activity())
    """

    MIN_INTERVAL: float = 5.0  # Минимальный интервал проверки (сек)
    MAX_INTERVAL: float = 600.0  # Максимальный интервал проверки (сек)

    def __init__(
        self,
        lock_manager: "SessionLockManager",
        check_interval_seconds: float = 60.0,
    ) -> None:
        """Инициализация сервиса автоблокировки.

        Args:
            lock_manager: Менеджер блокировки сессии
            check_interval_seconds: Интервал проверки в секундах (минимум 5)

        Raises:
            ValueError: Если интервал вне допустимого диапазона
        """
        if not (self.MIN_INTERVAL <= check_interval_seconds <= self.MAX_INTERVAL):
            raise ValueError(
                f"Интервал должен быть между {self.MIN_INTERVAL} и {self.MAX_INTERVAL} секунд"
            )

        self._lock_manager = lock_manager
        self._interval = check_interval_seconds
        self._timer: Optional[threading.Timer] = None
        self._running = False
        self._state = AutoLockState.STOPPED

        self._lock = threading.Lock()
        self._pause_event = threading.Event()
        self._pause_event.set()  # По умолчанию не на паузе

        self._activity_listeners: List[ActivityListener] = []
        self._stats = AutoLockStats()

        logger.debug("AutoLockService initialized (interval=%.1fs)", check_interval_seconds)

    # === Управление слушателями активности ===

    def add_activity_listener(self, listener: ActivityListener) -> None:
        """Добавить слушателя активности.

        Args:
            listener: Объект, реализующий ActivityListener
        """
        with self._lock:
            self._activity_listeners.append(listener)
            logger.debug("Activity listener added")

    def remove_activity_listener(self, listener: ActivityListener) -> None:
        """Удалить слушателя активности.

        Args:
            listener: Объект для удаления
        """
        with self._lock:
            if listener in self._activity_listeners:
                self._activity_listeners.remove(listener)
                logger.debug("Activity listener removed")

    def _notify_activity_listeners(self) -> None:
        """Уведомить слушателей об активности."""
        timestamp = time.time()
        for listener in self._activity_listeners:
            try:
                listener.on_activity_detected(timestamp)
            except Exception as e:
                logger.warning("Activity listener failed: %s", e)

    # === Жизненный цикл сервиса ===

    def start(self) -> None:
        """Запуск сервиса авто-блокировки.

        Raises:
            ServiceAlreadyRunningError: Если сервис уже запущен
        """
        with self._lock:
            if self._running:
                raise ServiceAlreadyRunningError("Сервис уже запущен")

            self._running = True
            self._state = AutoLockState.RUNNING
            self._stats.start_time = time.time()

            logger.info("AutoLockService started (interval=%.1fs)", self._interval)

        self._schedule_check()

    def stop(self) -> None:
        """Остановка сервиса.

        Отменяет таймер и останавливает фоновый поток.
        Блокирует до завершения текущей операции.
        """
        with self._lock:
            if not self._running:
                return

            self._running = False
            self._state = AutoLockState.STOPPED

            if self._timer:
                self._timer.cancel()
                self._timer = None

            logger.info("AutoLockService stopped")

    def pause(self) -> None:
        """Приостановка сервиса (без остановки).

        Проверки продолжают выполняться, но блокировка не происходит.
        Полезно для режимов презентации или фоновых операций.
        """
        with self._lock:
            if self._state == AutoLockState.RUNNING:
                self._state = AutoLockState.PAUSED
                self._pause_event.clear()
                logger.info("AutoLockService paused")

    def resume(self) -> None:
        """Возобновление сервиса после паузы."""
        with self._lock:
            if self._state == AutoLockState.PAUSED:
                self._state = AutoLockState.RUNNING
                self._pause_event.set()
                # Сбрасываем время активности
                self._lock_manager.update_activity()
                logger.info("AutoLockService resumed")

    def is_running(self) -> bool:
        """Проверяет, запущен ли сервис.

        Returns:
            True если сервис запущен
        """
        with self._lock:
            return self._running

    def is_paused(self) -> bool:
        """Проверяет, на паузе ли сервис.

        Returns:
            True если сервис на паузе
        """
        with self._lock:
            return self._state == AutoLockState.PAUSED

    def get_state(self) -> AutoLockState:
        """Возвращает текущее состояние сервиса.

        Returns:
            Текущее состояние
        """
        with self._lock:
            return self._state

    # === Планирование проверок ===

    def _schedule_check(self) -> None:
        """Планирование следующей проверки.

        Создаёт таймер для выполнения _check_and_lock через interval секунд.
        """
        with self._lock:
            if not self._running:
                return

            # Отменяем предыдущий таймер если есть
            if self._timer:
                self._timer.cancel()

            self._timer = threading.Timer(self._interval, self._check_and_lock)
            self._timer.daemon = True
            self._timer.name = "AutoLockTimer"
            self._timer.start()

    def _check_and_lock(self) -> None:
        """Проверка времени бездействия и блокировка.

        Вызывается по таймеру. Проверяет idle time и блокирует сессию
        при необходимости.
        """
        try:
            with self._lock:
                if not self._running:
                    return

                # Ждём если на паузе
                self._pause_event.wait()

                if not self._running:
                    return

                # Проверяем конфигурацию
                config = self._lock_manager.get_config()
                if not config.enabled:
                    self._schedule_check()
                    return

                # Обновляем статистику
                self._stats.check_count += 1
                self._stats.last_check_time = time.time()

            # Проверяем idle time (вне блокировки для избежания deadlock)
            idle_minutes = self._lock_manager.get_idle_time_minutes()
            threshold = config.auto_lock_minutes

            logger.debug(
                "Auto-lock check: idle=%.1f min, threshold=%d min",
                idle_minutes,
                threshold,
            )

            if idle_minutes >= threshold:
                # Авто-блокировка
                self._perform_auto_lock()
            else:
                # Продолжаем наблюдение
                self._schedule_check()

        except Exception as e:
            logger.error("Error in auto-lock check: %s", e)
            # Продолжаем работу даже при ошибке
            self._schedule_check()

    def _perform_auto_lock(self) -> None:
        """Выполняет автоматическую блокировку."""
        with self._lock:
            if self._state != AutoLockState.RUNNING:
                return

            self._state = AutoLockState.LOCKING

        try:
            from src.security.lock.session_lock_manager import LockReason

            self._lock_manager.lock_session(reason=LockReason.AUTO_LOCK.value)

            with self._lock:
                self._stats.lock_count += 1
                self._stats.last_lock_time = time.time()

            logger.info("Session auto-locked due to inactivity")

        except Exception as e:
            logger.error("Auto-lock failed: %s", e)
        finally:
            with self._lock:
                if self._running:
                    self._state = AutoLockState.RUNNING
                    self._schedule_check()

    # === Обработка активности ===

    def on_user_activity(self) -> None:
        """Вызывается при активности пользователя.

        Обновляет время последней активности в SessionLockManager
        и уведомляет слушателей.
        """
        # Обновляем активность
        self._lock_manager.update_activity()

        # Уведомляем слушателей
        self._notify_activity_listeners()

    def force_check(self) -> bool:
        """Принудительная проверка бездействия.

        Returns:
            True если выполнена блокировка
        """
        with self._lock:
            if not self._running:
                return False

        # Выполняем проверку немедленно
        self._check_and_lock()
        return self._lock_manager.is_locked()

    # === Управление интервалом ===

    def get_interval(self) -> float:
        """Возвращает текущий интервал проверки.

        Returns:
            Интервал в секундах
        """
        with self._lock:
            return self._interval

    def set_interval(self, interval_seconds: float) -> None:
        """Изменяет интервал проверки.

        Args:
            interval_seconds: Новый интервал в секундах

        Raises:
            ValueError: Если интервал вне допустимого диапазона
        """
        if not (self.MIN_INTERVAL <= interval_seconds <= self.MAX_INTERVAL):
            raise ValueError(
                f"Интервал должен быть между {self.MIN_INTERVAL} и {self.MAX_INTERVAL} секунд"
            )

        with self._lock:
            old_interval = self._interval
            self._interval = interval_seconds

            # Перепланируем если запущено
            if self._running:
                self._schedule_check()

        logger.info("Auto-lock interval changed: %.1f -> %.1f", old_interval, interval_seconds)

    # === Статистика ===

    def get_stats(self) -> AutoLockStats:
        """Возвращает статистику сервиса.

        Returns:
            Копия статистики
        """
        with self._lock:
            return AutoLockStats(
                start_time=self._stats.start_time,
                check_count=self._stats.check_count,
                lock_count=self._stats.lock_count,
                last_check_time=self._stats.last_check_time,
                last_lock_time=self._stats.last_lock_time,
            )

    def reset_stats(self) -> None:
        """Сбрасывает статистику сервиса."""
        with self._lock:
            self._stats = AutoLockStats(
                start_time=self._stats.start_time  # Сохраняем время запуска
            )
            logger.debug("AutoLockService stats reset")

    def get_uptime_seconds(self) -> float:
        """Возвращает время работы сервиса.

        Returns:
            Количество секунд с момента запуска
        """
        with self._lock:
            if self._stats.start_time is None:
                return 0.0
            return time.time() - self._stats.start_time

    # === Контекстный менеджер ===

    def __enter__(self) -> "AutoLockService":
        """Вход в контекст — запуск сервиса."""
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Выход из контекста — остановка сервиса."""
        self.stop()

    # === Служебные методы ===

    def __repr__(self) -> str:
        """Строковое представление."""
        with self._lock:
            return (
                f"AutoLockService("
                f"state={self._state.value}, "
                f"interval={self._interval}s, "
                f"checks={self._stats.check_count}, "
                f"locks={self._stats.lock_count})"
            )
