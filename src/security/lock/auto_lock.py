"""
Автоматическая блокировка по таймауту неактивности.

AutoLockService запускает фоновый поток для мониторинга
неактивности пользователя и автоматической блокировки.

Features:
    - Фоновый мониторинг неактивности
    - Настраиваемый таймаут
    - Grace period с предупреждением
    - Платформозависимое определение неактивности системы

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import logging
import platform
import subprocess
import threading
import time
import types
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from src.security.lock.models import LockConfig, LockReason
from src.security.lock.session_lock import SessionLockManager

LOG = logging.getLogger(__name__)

# Интервал проверки неактивности (секунды)
DEFAULT_CHECK_INTERVAL = 10

# Время предупреждения до блокировки (секунды)
DEFAULT_WARNING_SECONDS = 30


@dataclass
class AutoLockService:
    """
    Сервис автоматической блокировки по таймауту.

    Запускает фоновый поток для мониторинга неактивности
    и автоматической блокировки сессии.

    Attributes:
        lock_manager: SessionLockManager для блокировки
        check_interval: Интервал проверки в секундах
        warning_seconds: Время предупреждения до блокировки
        on_warning: Callback для предупреждения о блокировке

    Thread Safety:
        - Безопасен для многопоточной среды
        - Корректно останавливается при shutdown

    Example:
        >>> manager = SessionLockManager(config=LockConfig(idle_timeout_seconds=300))
        >>> auto_lock = AutoLockService(lock_manager=manager)
        >>> auto_lock.start()
        >>> # Фоновый мониторинг запущен
        >>> auto_lock.stop()
    """

    lock_manager: SessionLockManager
    check_interval: int = DEFAULT_CHECK_INTERVAL
    warning_seconds: int = DEFAULT_WARNING_SECONDS
    on_warning: Optional[Callable[[int], None]] = None

    # Внутреннее состояние
    _thread: Optional[threading.Thread] = field(default=None, init=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _warning_sent: bool = field(default=False, init=False)
    _last_system_idle: int = field(default=0, init=False)

    @property
    def is_running(self) -> bool:
        """Сервис запущен."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def config(self) -> LockConfig:
        """Конфигурация блокировки."""
        return self.lock_manager.config

    # --------------------------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------------------------

    def start(self) -> None:
        """
        Запустить фоновый мониторинг.

        Raises:
            RuntimeError: Сервис уже запущен

        Example:
            >>> auto_lock.start()
        """
        if self.is_running:
            raise RuntimeError("AutoLockService is already running")

        if not self.config.is_idle_timeout_enabled:
            LOG.info("Idle timeout disabled, AutoLockService not started")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="AutoLockThread",
            daemon=True,
        )
        self._thread.start()
        LOG.info(
            "AutoLockService started: timeout=%ds, check_interval=%ds",
            self.config.idle_timeout_seconds,
            self.check_interval,
        )

    def stop(self) -> None:
        """
        Остановить фоновый мониторинг.

        Example:
            >>> auto_lock.stop()
        """
        if not self.is_running:
            return

        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.check_interval + 5)
            self._thread = None

        LOG.info("AutoLockService stopped")

    # --------------------------------------------------------------------------
    # Monitoring Loop
    # --------------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        """Основной цикл мониторинга."""
        LOG.debug("AutoLock monitoring loop started")

        while not self._stop_event.wait(timeout=self.check_interval):
            try:
                self._check_idle_timeout()
            except Exception as e:
                LOG.error("Error in auto-lock check: %s", e)

        LOG.debug("AutoLock monitoring loop stopped")

    def _check_idle_timeout(self) -> None:
        """Проверка таймаута неактивности."""
        # Если уже заблокирован, пропускаем
        if self.lock_manager.is_locked:
            return

        # Получаем время неактивности
        idle_seconds = self._get_idle_seconds()
        timeout = self.config.idle_timeout_seconds

        # Сбрасываем предупреждение при активности
        if idle_seconds < timeout - self.warning_seconds:
            self._warning_sent = False

        # Проверяем предупреждение
        if idle_seconds >= timeout - self.warning_seconds and not self._warning_sent:
            remaining = timeout - idle_seconds
            LOG.info("Auto-lock warning: %d seconds remaining", remaining)
            self._send_warning(remaining)
            self._warning_sent = True

        # Проверяем таймаут
        if idle_seconds >= timeout:
            LOG.warning(
                "Idle timeout reached: %d seconds >= %d seconds",
                idle_seconds,
                timeout,
            )
            self._perform_lock(idle_seconds)

    def _get_idle_seconds(self) -> int:
        """
        Получить время неактивности системы.

        Использует платформозависимые методы:
        - Linux: xprintidle (X11)
        - Windows: ctypes + GetLastInputInfo
        - macOS: ioreg или AppleScript

        Returns:
            Время неактивности в секундах
        """
        # Приоритет: неактивность приложения (через lock_manager)
        app_idle = self.lock_manager.idle_seconds

        # Пытаемся получить системную неактивность
        system_idle = self._get_system_idle_seconds()

        # Берём максимум из двух значений
        return max(app_idle, system_idle)

    def _get_system_idle_seconds(self) -> int:
        """
        Получить системное время неактивности.

        Returns:
            Время неактивности системы в секундах
        """
        system = platform.system()

        try:
            if system == "Linux":
                return self._get_linux_idle_seconds()
            elif system == "Windows":
                return self._get_windows_idle_seconds()
            elif system == "Darwin":
                return self._get_macos_idle_seconds()
        except Exception as e:
            LOG.debug("Failed to get system idle time: %s", e)

        return 0

    def _get_linux_idle_seconds(self) -> int:
        """
        Получить время неактивности на Linux (X11).

        Использует xprintidle для получения времени в миллисекундах.
        """
        try:
            result = subprocess.run(
                ["xprintidle"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                idle_ms = int(result.stdout.strip())
                return idle_ms // 1000
        except (subprocess.SubprocessError, FileNotFoundError, ValueError):
            pass

        return 0

    def _get_windows_idle_seconds(self) -> int:
        """
        Получить время неактивности на Windows.

        Использует GetLastInputInfo через ctypes.
        """
        import ctypes

        try:
            # Структура LASTINPUTINFO
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", ctypes.c_uint),
                    ("dwTime", ctypes.c_uint),
                ]

            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)

            if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):  # type: ignore[attr-defined]
                # Получаем текущее время с запуска системы
                millis = ctypes.windll.kernel32.GetTickCount64()  # type: ignore[attr-defined]
                idle_ms = millis - lii.dwTime
                return int(idle_ms // 1000)
        except (AttributeError, OSError):
            pass

        return 0

    def _get_macos_idle_seconds(self) -> int:
        """
        Получить время неактивности на macOS.

        Использует ioreg для получения HID idle time.
        """
        try:
            result = subprocess.run(
                ["ioreg", "-c", "IOHIDSystem"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Парсим "HIDIdleTime" = <число>
                for line in result.stdout.split("\n"):
                    if "HIDIdleTime" in line:
                        # Формат: "HIDIdleTime" = <number>
                        import re

                        match = re.search(r"=\s*(\d+)", line)
                        if match:
                            idle_ns = int(match.group(1))
                            return idle_ns // 1_000_000_000
        except (subprocess.SubprocessError, FileNotFoundError, ValueError):
            pass

        return 0

    # --------------------------------------------------------------------------
    # Actions
    # --------------------------------------------------------------------------

    def _send_warning(self, remaining_seconds: int) -> None:
        """
        Отправить предупреждение о блокировке.

        Args:
            remaining_seconds: Оставшееся время до блокировки
        """
        if self.on_warning:
            try:
                self.on_warning(remaining_seconds)
            except Exception as e:
                LOG.warning("Warning callback failed: %s", e)

    def _perform_lock(self, idle_seconds: int) -> None:
        """
        Выполнить автоматическую блокировку.

        Args:
            idle_seconds: Время неактивности
        """
        try:
            self.lock_manager.lock(
                reason=LockReason.IDLE_TIMEOUT,
                metadata={
                    "idle_seconds": idle_seconds,
                    "timeout_config": self.config.idle_timeout_seconds,
                    "auto_lock": True,
                },
            )
        except Exception as e:
            LOG.error("Auto-lock failed: %s", e)

    # --------------------------------------------------------------------------
    # Context Manager
    # --------------------------------------------------------------------------

    def __enter__(self) -> "AutoLockService":
        """Запустить сервис при входе в контекст."""
        self.start()
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional["types.TracebackType"],
    ) -> None:
        """Остановить сервис при выходе из контекста."""
        self.stop()

    def __repr__(self) -> str:
        return (
            f"AutoLockService("
            f"running={self.is_running}, "
            f"timeout={self.config.idle_timeout_seconds}s)"
        )


__all__: list[str] = [
    "AutoLockService",
    "DEFAULT_CHECK_INTERVAL",
    "DEFAULT_WARNING_SECONDS",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"