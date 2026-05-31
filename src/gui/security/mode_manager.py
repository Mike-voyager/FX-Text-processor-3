# -*- coding: utf-8 -*-
"""
ModeManager — управление Normal/Special режимами работы приложения.

ModeManager реализует конечный автомат для переключения между режимами:
- NORMAL: стандартный режим работы без MFA
- SPECIAL: расширенный режим с требованием MFA

Интеграция с HealthChecker позволяет автоматически блокировать Special Mode
при критических проблемах безопасности.

Thread Safety:
    Все операции потокобезопасны через threading.Lock.

Example:
    >>> from src.gui.security.mode_manager import ModeManager
    >>> from src.security.monitoring.health_checker import HealthChecker
    >>> from src.security.auth.auth_service import AuthService
    >>> manager = ModeManager(health_checker=hc, auth_service=auth)
    >>> manager.get_current_mode()
    'normal'
    >>> can_enter, reason = manager.can_enter_special()
    >>> if can_enter:
    ...     success = manager.enter_special({"password": "...", "totp": "123456"})

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Callable, Optional

from src.security.monitoring.health_checker import HealthChecker
from src.security.monitoring.models import HealthCheckReport

LOG = logging.getLogger(__name__)

# Тип для callback функций
ModeChangeCallback = Callable[[str, str], None]


class ModeManager:
    """Singleton управление Normal/Special режимами.

    Управляет состоянием приложения и переходами между режимами.
    Требует MFA для входа в Special Mode.

    Attributes:
        MODE_NORMAL: Идентификатор нормального режима.
        MODE_SPECIAL: Идентификатор специального режима.

    Thread Safety:
        Все публичные методы потокобезопасны.

    Example:
        >>> manager = ModeManager()
        >>> manager.is_normal()
        True
        >>> manager.enter_special({"password": "secret", "totp": "123456"})
        True
        >>> manager.is_special()
        True
    """

    MODE_NORMAL: str = "normal"
    """🟢 Без MFA."""

    MODE_SPECIAL: str = "special"
    """🔴 С MFA."""

    _instance: Optional["ModeManager"] = None
    _instance_lock: threading.Lock = threading.Lock()

    def __new__(
        cls,
        health_checker: Optional[HealthChecker] = None,
        auth_service: Optional[Any] = None,
    ) -> "ModeManager":
        """Создание или получение singleton экземпляра.

        Args:
            health_checker: Опциональный HealthChecker для проверок.
            auth_service: Опциональный AuthService для MFA.

        Returns:
            Singleton экземпляр ModeManager.
        """
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    instance = super().__new__(cls)
                    cls._instance = instance
        return cls._instance

    def __init__(
        self,
        health_checker: Optional[HealthChecker] = None,
        auth_service: Optional[Any] = None,
    ) -> None:
        """Инициализация ModeManager.

        Args:
            health_checker: HealthChecker для проверки состояния системы.
            auth_service: AuthService для верификации MFA.
        """
        # Инициализируем только один раз (singleton pattern)
        if hasattr(self, "_initialized"):
            return

        self._lock: threading.Lock = threading.Lock()
        self._current_mode: str = self.MODE_NORMAL
        self._health_checker: Optional[HealthChecker] = health_checker
        self._auth_service: Optional[Any] = auth_service
        self._callbacks: list[ModeChangeCallback] = []
        self._special_mode_disabled: bool = False
        self._disable_reason: str = ""

        self._initialized: bool = True
        LOG.debug("ModeManager initialized in NORMAL mode")

    # --------------------------------------------------------------------------
    # Core methods
    # --------------------------------------------------------------------------

    def get_current_mode(self) -> str:
        """Получить текущий режим работы.

        Returns:
            MODE_NORMAL или MODE_SPECIAL.
        """
        with self._lock:
            return self._current_mode

    def is_normal(self) -> bool:
        """Проверить, находится ли система в Normal Mode.

        Returns:
            True если текущий режим — Normal.
        """
        with self._lock:
            return self._current_mode == self.MODE_NORMAL

    def is_special(self) -> bool:
        """Проверить, находится ли система в Special Mode.

        Returns:
            True если текущий режим — Special.
        """
        with self._lock:
            return self._current_mode == self.MODE_SPECIAL

    # --------------------------------------------------------------------------
    # Transition checks
    # --------------------------------------------------------------------------

    def can_enter_special(self) -> tuple[bool, str]:
        """Проверка перед входом в Special Mode.

        Проверяет:
        1. Не находимся ли уже в Special Mode
        2. Не отключён ли Special Mode
        3. Проходят ли health checks

        Returns:
            Кортеж (can_enter: bool, reason: str).
            Возможные reason:
            - "ok": можно входить
            - "already_special": уже в Special Mode
            - "disabled": Special Mode отключён
            - "health_check_failed": не пройдены health checks
        """
        with self._lock:
            if self._current_mode == self.MODE_SPECIAL:
                return False, "already_special"

            if self._special_mode_disabled:
                return False, "disabled"

        # Проверка health check вне lock для избежания deadlock
        if self._health_checker is not None:
            report = self._health_checker.run_critical()
            if not report.is_healthy:
                LOG.warning(
                    "Cannot enter Special Mode: health check failed (%s)",
                    report.overall_status.value,
                )
                return False, "health_check_failed"

        return True, "ok"

    def can_exit_special(self) -> tuple[bool, str]:
        """Проверка перед выходом из Special Mode.

        Returns:
            Кортеж (can_exit: bool, reason: str).
            Возможные reason:
            - "ok": можно выходить
            - "already_normal": уже в Normal Mode
        """
        with self._lock:
            if self._current_mode == self.MODE_NORMAL:
                return False, "already_normal"
            return True, "ok"

    # --------------------------------------------------------------------------
    # Transitions
    # --------------------------------------------------------------------------

    def enter_special(self, mfa_credentials: dict[str, str]) -> bool:
        """Вход в Special Mode с MFA.

        Steps:
            1. Проверить can_enter_special()
            2. Верифицировать MFA через auth_service
            3. Переключить режим
            4. Вызвать callbacks

        Args:
            mfa_credentials: Словарь с учётными данными MFA.
                Ожидаемые ключи: "password", "totp"|"fido2"|"backupcode".

        Returns:
            True при успешном входе в Special Mode.

        Security:
            Не логирует credentials. Логирует только результат и user_id.
        """
        # Шаг 1: Проверка возможности входа
        can_enter, reason = self.can_enter_special()
        if not can_enter:
            LOG.warning("Cannot enter Special Mode: %s", reason)
            return False

        # Шаг 2: Проверка наличия auth_service
        if self._auth_service is None:
            LOG.error("Cannot enter Special Mode: auth_service not configured")
            return False

        # Шаг 3: MFA верификация
        password = mfa_credentials.get("password", "")
        user_id = mfa_credentials.get("user_id", "operator")

        # Определяем тип второго фактора
        factor_type: Optional[str] = None
        factor_credential: Optional[str] = None

        if "totp" in mfa_credentials:
            factor_type = "totp"
            factor_credential = mfa_credentials["totp"]
        elif "fido2" in mfa_credentials:
            factor_type = "fido2"
            factor_credential = mfa_credentials["fido2"]
        elif "backupcode" in mfa_credentials:
            factor_type = "backupcode"
            factor_credential = mfa_credentials["backupcode"]

        try:
            result = self._auth_service.authenticate(
                user_id=user_id,
                password=password,
                factor_type=factor_type,
                factor_credential=factor_credential,
            )

            if not result.success:
                LOG.warning(
                    "MFA authentication failed for user=%s: %s",
                    user_id,
                    result.failure_reason,
                )
                return False

        except (ValueError, TypeError, AttributeError, RuntimeError) as exc:
            LOG.error("MFA authentication error: %s", exc)
            return False

        # Шаг 4: Переключение режима
        with self._lock:
            old_mode = self._current_mode
            self._current_mode = self.MODE_SPECIAL
            LOG.info(
                "Mode changed: %s -> %s (user=%s)",
                old_mode,
                self.MODE_SPECIAL,
                user_id,
            )

        # Шаг 5: Уведомление подписчиков
        self._notify_mode_change(old_mode, self.MODE_SPECIAL)

        return True

    def exit_special(self, confirm: bool = True) -> bool:
        """Выход в Normal Mode.

        Args:
            confirm: Если True — не требует подтверждения (для тестов).

        Returns:
            True при успешном выходе из Special Mode.

        Note:
            При confirm=False можно добавить дополнительные проверки
            (например, наличие несохранённых данных).
        """
        # Проверка возможности выхода
        can_exit, reason = self.can_exit_special()
        if not can_exit:
            LOG.debug("Cannot exit Special Mode: %s", reason)
            return False

        with self._lock:
            old_mode = self._current_mode
            self._current_mode = self.MODE_NORMAL
            LOG.info("Mode changed: %s -> %s", old_mode, self.MODE_NORMAL)

        self._notify_mode_change(old_mode, self.MODE_NORMAL)

        return True

    # --------------------------------------------------------------------------
    # Observer pattern
    # --------------------------------------------------------------------------

    def on_mode_change(self, callback: ModeChangeCallback) -> None:
        """Подписка на изменение режима.

        Args:
            callback: Функция(old_mode: str, new_mode: str) -> None.

        Example:
            >>> def on_change(old: str, new: str) -> None:
            ...     print(f"Mode changed: {old} -> {new}")
            >>> manager.on_mode_change(on_change)
        """
        with self._lock:
            self._callbacks.append(callback)
            LOG.debug("Mode change callback registered (total: %d)", len(self._callbacks))

    def _notify_mode_change(self, old_mode: str, new_mode: str) -> None:
        """Уведомление подписчиков об изменении режима.

        Args:
            old_mode: Предыдущий режим.
            new_mode: Новый режим.

        Note:
            Callbacks вызываются вне lock для предотвращения deadlock.
            Исключения в callback'ах не прерывают цепочку уведомлений.
        """
        with self._lock:
            callbacks = self._callbacks.copy()

        for callback in callbacks:
            try:
                callback(old_mode, new_mode)
            except (ValueError, TypeError, AttributeError, RuntimeError) as exc:
                LOG.warning("Mode change callback failed: %s", exc)

    # --------------------------------------------------------------------------
    # Health Check integration
    # --------------------------------------------------------------------------

    def check_health_status(self) -> Optional[HealthCheckReport]:
        """Проверка Health Check для Special Mode.

        Returns:
            HealthCheckReport если HealthChecker настроен, иначе None.
        """
        if self._health_checker is None:
            LOG.debug("HealthChecker not configured")
            return None

        return self._health_checker.run_critical()

    def disable_special_mode(self, reason: str = "") -> None:
        """Отключить Special Mode (при critical Health Check).

        Если текущий режим Special — принудительно выходит в Normal.

        Args:
            reason: Причина отключения (для логирования).
        """
        with self._lock:
            self._special_mode_disabled = True
            self._disable_reason = reason

            was_special = self._current_mode == self.MODE_SPECIAL

            if was_special:
                self._current_mode = self.MODE_NORMAL
                LOG.warning(
                    "Special Mode disabled%s, forced exit to Normal",
                    f": {reason}" if reason else "",
                )
            else:
                LOG.warning(
                    "Special Mode disabled%s",
                    f": {reason}" if reason else "",
                )

        # Уведомление вне lock
        if was_special:
            self._notify_mode_change(self.MODE_SPECIAL, self.MODE_NORMAL)

    def enable_special_mode(self) -> None:
        """Включить Special Mode.

        Снимает флаг отключения, установленный disable_special_mode().
        Не переключает режим автоматически.
        """
        with self._lock:
            was_disabled = self._special_mode_disabled
            self._special_mode_disabled = False
            self._disable_reason = ""

        if was_disabled:
            LOG.info("Special Mode enabled")

    def is_special_mode_disabled(self) -> bool:
        """Проверить, отключён ли Special Mode.

        Returns:
            True если Special Mode отключён.
        """
        with self._lock:
            return self._special_mode_disabled

    # --------------------------------------------------------------------------
    # Utility
    # --------------------------------------------------------------------------

    def force_mode(self, mode: str) -> None:
        """Принудительно переключает режим без MFA проверки.

        Используется после успешной MFA верификации через UI
        (MFAGate / ModeToggle), когда повторная проверка не нужна.

        Args:
            mode: Целевой режим (MODE_NORMAL или MODE_SPECIAL).

        Security:
            Вызывающий код ОБЯЗАН убедиться, что MFA пройдена
            перед вызовом этого метода.
        """
        if mode not in (self.MODE_NORMAL, self.MODE_SPECIAL):
            LOG.warning("Invalid mode for force_mode: %s", mode)
            return

        with self._lock:
            old_mode = self._current_mode
            if old_mode == mode:
                return
            self._current_mode = mode
            LOG.info("Mode force-changed: %s -> %s", old_mode, mode)

        self._notify_mode_change(old_mode, mode)

    def reset(self) -> None:
        """Сброс состояния (для тестирования).

        Возвращает менеджер в начальное состояние:
        - режим Normal
        - Special Mode включён
        - очищены callbacks
        """
        with self._lock:
            old_mode = self._current_mode
            self._current_mode = self.MODE_NORMAL
            self._special_mode_disabled = False
            self._disable_reason = ""
            self._callbacks.clear()

        if old_mode != self.MODE_NORMAL:
            self._notify_mode_change(old_mode, self.MODE_NORMAL)

        LOG.debug("ModeManager reset to initial state")

    @classmethod
    def reset_instance(cls) -> None:
        """Сброс singleton экземпляра (для тестирования).

        Warning:
            Использовать только в тестах! Нарушает singleton контракт.
        """
        with cls._instance_lock:
            cls._instance = None
        LOG.debug("ModeManager singleton instance reset")


__all__: list[str] = [
    "ModeManager",
    "ModeChangeCallback",
]
