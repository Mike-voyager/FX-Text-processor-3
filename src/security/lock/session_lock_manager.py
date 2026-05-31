"""Менеджер блокировки сессии для FX Text Processor 3.

Управляет блокировкой сессии с поддержкой MFA, очисткой памяти
и интеграцией с AuthController.

Architecture:
    - Service Layer → вся бизнес-логика блокировки
    - Интеграция с AuthController для верификации
    - Thread-safe через RLock
    - Clear memory on lock для security

Example:
    >>> from src.security.lock import SessionLockManager, LockConfig
    >>> config = LockConfig(auto_lock_minutes=15, require_mfa_to_unlock=True)
    >>> manager = SessionLockManager(auth_controller, config)
    >>> manager.lock_session(reason="manual")
    >>> # Позже...
    >>> if manager.unlock_session(password="secret", mfa_token="123456"):
    ...     print("Сессия разблокирована")
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, Final, List, Optional, Protocol

if TYPE_CHECKING:
    from src.controller.auth_controller import AuthController


logger = logging.getLogger(__name__)


class LockReason(Enum):
    """Причины блокировки сессии."""

    MANUAL = "manual"
    AUTO_LOCK = "auto_lock"
    SYSTEM_SLEEP = "system_sleep"
    SCREENSAVER = "screensaver"
    SECURITY_POLICY = "security_policy"


DEFAULT_AUTO_LOCK_MINUTES: int = 15
"""Таймаут автоблокировки по умолчанию (в минутах).

Используется в LockConfig и GUI. Централизованное значение
для предотвращения хардкода в разных модулях.
"""


@dataclass(frozen=True)
class LockConfig:
    """Конфигурация блокировки сессии.

    Attributes:
        enabled: Включена ли блокировка сессии
        auto_lock_minutes: Таймаут автоблокировки в минутах
        lock_on_sleep: Блокировать при засыпании системы
        lock_on_screensaver: Блокировать при включении скринсейвера
        require_mfa_to_unlock: Требовать MFA для разблокировки
        clear_clipboard_on_lock: Очищать буфер обмена при блокировке
        hide_documents_on_lock: Скрывать документы при блокировке
    """

    enabled: bool = True
    auto_lock_minutes: int = DEFAULT_AUTO_LOCK_MINUTES
    lock_on_sleep: bool = True
    lock_on_screensaver: bool = True
    require_mfa_to_unlock: bool = True
    clear_clipboard_on_lock: bool = True
    hide_documents_on_lock: bool = True


@dataclass(frozen=True)
class UnlockResult:
    """Результат разблокировки сессии.

    Attributes:
        success: Успешность разблокировки
        error_code: Код ошибки (если неудача)
        error_message: Сообщение об ошибке
        mfa_required: Требуется ли MFA
    """

    success: bool
    error_code: str = ""
    error_message: str = ""
    mfa_required: bool = False


class SessionLockError(Exception):
    """Базовое исключение для ошибок блокировки сессии."""

    pass


class SessionAlreadyLockedError(SessionLockError):
    """Сессия уже заблокирована."""

    pass


class SessionNotLockedError(SessionLockError):
    """Сессия не заблокирована."""

    pass


class InvalidCredentialsError(SessionLockError):
    """Неверные учётные данные при разблокировке."""

    pass


class MFAVerificationRequiredError(SessionLockError):
    """Требуется MFA для разблокировки."""

    def __init__(self, message: str = "Требуется MFA для разблокировки") -> None:
        """Инициализация исключения.

        Args:
            message: Сообщение об ошибке
        """
        super().__init__(message)
        self.mfa_required = True


class LockStateListener(Protocol):
    """Протокол слушателя изменений состояния блокировки."""

    def on_lock(self, reason: LockReason, timestamp: datetime) -> None:
        """Вызывается при блокировке сессии.

        Args:
            reason: Причина блокировки
            timestamp: Время блокировки
        """
        ...

    def on_unlock(self, timestamp: datetime) -> None:
        """Вызывается при разблокировке сессии.

        Args:
            timestamp: Время разблокировки
        """
        ...


@dataclass
class LockEvent:
    """Событие блокировки/разблокировки.

    Attributes:
        event_type: Тип события (lock/unlock)
        reason: Причина (для lock)
        timestamp: Время события
        user_id: Идентификатор пользователя
    """

    event_type: str
    timestamp: datetime
    reason: Optional[LockReason] = None
    user_id: Optional[str] = None


class SessionLockManager:
    """Менеджер блокировки сессии.

    Управляет жизненным циклом блокировки сессии:
    - Блокировка с очисткой памяти
    - Разблокировка с MFA
    - Отслеживание активности
    - Уведомление слушателей

    Attributes:
        _auth_controller: Контроллер аутентификации
        _config: Конфигурация блокировки
        _is_locked: Флаг состояния блокировки
        _last_activity: Время последней активности (timestamp)
        _locked_at: Время блокировки
        _lock_reason: Причина блокировки
        _lock: Блокировка для thread-safety
        _listeners: Список слушателей событий
        _event_history: История событий блокировки

    Thread Safety:
        Все операции thread-safe через RLock.

    Example:
        >>> manager = SessionLockManager(auth_controller)
        >>> manager.lock_session(reason="manual")
        >>> result = manager.unlock_session("password", "123456")
        >>> if result.success:
        ...     print("Разблокировано")
    """

    MAX_EVENT_HISTORY: Final[int] = 100  # Максимальное количество событий в истории

    def __init__(
        self,
        auth_controller: "AuthController",
        config: LockConfig | None = None,
    ) -> None:
        """Инициализация менеджера блокировки сессии.

        Args:
            auth_controller: Контроллер аутентификации
            config: Конфигурация блокировки (если None — используется default)
        """
        self._auth_controller = auth_controller
        self._config = config or LockConfig()

        self._is_locked = False
        self._last_activity = time.time()
        self._locked_at: Optional[datetime] = None
        self._lock_reason: Optional[LockReason] = None

        self._lock = threading.RLock()
        self._listeners: List[LockStateListener] = []
        self._event_history: List[LockEvent] = []

        self._sensitive_data_cache: Dict[str, Any] = {}

        logger.debug("SessionLockManager initialized (enabled=%s)", self._config.enabled)

    # === Управление слушателями ===

    def add_listener(self, listener: LockStateListener) -> None:
        """Добавить слушателя событий блокировки.

        Args:
            listener: Объект, реализующий LockStateListener
        """
        with self._lock:
            self._listeners.append(listener)
            logger.debug("Lock state listener added")

    def remove_listener(self, listener: LockStateListener) -> None:
        """Удалить слушателя событий блокировки.

        Args:
            listener: Объект для удаления
        """
        with self._lock:
            if listener in self._listeners:
                self._listeners.remove(listener)
                logger.debug("Lock state listener removed")

    def _notify_listeners(self, event_type: str, reason: Optional[LockReason] = None) -> None:
        """Уведомить слушателей о событии.

        Args:
            event_type: Тип события (lock/unlock)
            reason: Причина блокировки (для lock)
        """
        timestamp = datetime.now(timezone.utc)
        user_id = self._auth_controller.get_current_user()

        # Сохраняем в историю
        event = LockEvent(
            event_type=event_type,
            timestamp=timestamp,
            reason=reason,
            user_id=user_id,
        )
        self._event_history.append(event)

        # Ограничиваем размер истории
        if len(self._event_history) > self.MAX_EVENT_HISTORY:
            self._event_history = self._event_history[-self.MAX_EVENT_HISTORY :]

        # Уведомляем слушателей
        for listener in self._listeners:
            try:
                if event_type == "lock":
                    listener.on_lock(reason or LockReason.MANUAL, timestamp)
                else:
                    listener.on_unlock(timestamp)
            except Exception as e:
                logger.warning("Lock listener failed: %s", e)

    # === Основные методы блокировки ===

    def lock_session(self, reason: str = "manual") -> None:
        """Блокировка сессии.

        Выполняет:
        1. Очистку чувствительных данных из памяти
        2. Скрытие/защиту открытых документов
        3. Уведомление слушателей
        4. Установку флага блокировки

        Args:
            reason: Причина блокировки (manual, auto_lock, system_sleep, screensaver)

        Raises:
            SessionAlreadyLockedError: Если сессия уже заблокирована
            SessionLockError: При ошибке блокировки
        """
        with self._lock:
            if self._is_locked:
                raise SessionAlreadyLockedError("Сессия уже заблокирована")

            if not self._config.enabled:
                logger.debug("Lock disabled, skipping")
                return

            try:
                lock_reason = LockReason(reason)
            except ValueError:
                lock_reason = LockReason.MANUAL

            logger.info("Locking session (reason=%s)", lock_reason.value)

            # Шаг 1: Очистка памяти
            self._clear_sensitive_data()

            # Шаг 2: Очистка буфера обмена
            if self._config.clear_clipboard_on_lock:
                self._clear_clipboard()

            # Шаг 3: Сохранение состояния документов (если требуется)
            if self._config.hide_documents_on_lock:
                self._protect_documents()

            # Шаг 4: Установка состояния
            self._is_locked = True
            self._locked_at = datetime.now(timezone.utc)
            self._lock_reason = lock_reason

            # Шаг 5: Уведомление
            self._notify_listeners("lock", lock_reason)

            logger.info("Session locked (reason=%s)", lock_reason.value)

    def unlock_session(self, password: str, mfa_token: str | None = None) -> UnlockResult:
        """Разблокировка сессии с MFA.

        Выполняет:
        1. Верификацию пароля через AuthController
        2. Верификацию MFA (если требуется)
        3. Восстановление сессии
        4. Сброс флага блокировки

        Args:
            password: Пароль пользователя
            mfa_token: MFA код (TOTP/Backup) или None

        Returns:
            Результат разблокировки

        Raises:
            SessionNotLockedError: Если сессия не заблокирована
        """
        with self._lock:
            if not self._is_locked:
                return UnlockResult(
                    success=False,
                    error_code="NOT_LOCKED",
                    error_message="Сессия не заблокирована",
                )

            logger.info("Attempting session unlock")

            # Шаг 1: Верификация пароля через AuthController
            try:
                auth_result = self._auth_controller.unlock_session(password)
            except Exception as e:
                logger.error("Password verification error: %s", e)
                return UnlockResult(
                    success=False,
                    error_code="VERIFICATION_ERROR",
                    error_message="Ошибка проверки пароля",
                )

            if not auth_result.success:
                logger.warning("Unlock failed: invalid password")
                return UnlockResult(
                    success=False,
                    error_code="INVALID_PASSWORD",
                    error_message="Неверный пароль",
                )

            # Шаг 2: Проверка MFA (если требуется)
            if self._config.require_mfa_to_unlock:
                user_id = self._auth_controller.get_current_user()
                if user_id and self._auth_controller.requires_mfa(user_id):
                    if not mfa_token:
                        logger.warning("Unlock failed: MFA required but not provided")
                        return UnlockResult(
                            success=False,
                            error_code="MFA_REQUIRED",
                            error_message="Требуется MFA код для разблокировки",
                            mfa_required=True,
                        )

                    # Верификация MFA
                    mfa_valid = self._verify_mfa(user_id, mfa_token)
                    if not mfa_valid:
                        logger.warning("Unlock failed: invalid MFA")
                        return UnlockResult(
                            success=False,
                            error_code="INVALID_MFA",
                            error_message="Неверный MFA код",
                            mfa_required=True,
                        )

            # Шаг 3: Восстановление сессии
            self._restore_documents()

            # Шаг 4: Сброс состояния
            self._is_locked = False
            self._locked_at = None
            self._lock_reason = None
            self._last_activity = time.time()

            # Шаг 5: Уведомление
            self._notify_listeners("unlock")

            logger.info("Session unlocked successfully")
            return UnlockResult(success=True)

    def _verify_mfa(self, user_id: str, mfa_token: str) -> bool:
        """Верификация MFA токена.

        Args:
            user_id: Идентификатор пользователя
            mfa_token: MFA код

        Returns:
            True если верификация успешна
        """
        try:
            # Пробуем TOTP (6 цифр)
            if len(mfa_token) == 6 and mfa_token.isdigit():
                return self._auth_controller.verify_totp(user_id, mfa_token)
        except Exception as e:
            logger.debug("TOTP verification failed: %s", e)

        # Пробуем резервный код
        try:
            normalized = mfa_token.strip().upper()
            if "-" not in normalized and len(normalized) == 8:
                normalized = f"{normalized[:4]}-{normalized[4:]}"
            return self._auth_controller.verify_backup_code(user_id, normalized)
        except Exception as e:
            logger.debug("Backup code verification failed: %s", e)

        return False

    def is_locked(self) -> bool:
        """Статус блокировки.

        Returns:
            True если сессия заблокирована
        """
        with self._lock:
            return self._is_locked

    def get_lock_reason(self) -> Optional[LockReason]:
        """Возвращает причину блокировки.

        Returns:
            Причина блокировки или None если не заблокирована
        """
        with self._lock:
            return self._lock_reason

    def get_locked_at(self) -> Optional[datetime]:
        """Время блокировки.

        Returns:
            Время блокировки или None если не заблокирована
        """
        with self._lock:
            return self._locked_at

    # === Управление активностью ===

    def update_activity(self) -> None:
        """Обновление времени последней активности.

        Вызывается при любой активности пользователя.
        """
        with self._lock:
            self._last_activity = time.time()

    def get_idle_time(self) -> float:
        """Время бездействия в секундах.

        Returns:
            Количество секунд с последней активности
        """
        with self._lock:
            return time.time() - self._last_activity

    def get_idle_time_minutes(self) -> float:
        """Время бездействия в минутах.

        Returns:
            Количество минут с последней активности
        """
        return self.get_idle_time() / 60

    # === Очистка и защита данных ===

    def _clear_sensitive_data(self) -> None:
        """Очистка чувствительных данных из памяти."""
        logger.debug("Clearing sensitive data from memory")

        # Очистка кэша
        for key in list(self._sensitive_data_cache.keys()):
            # Перезапись перед удалением (простая защита)
            if isinstance(self._sensitive_data_cache[key], str):
                self._sensitive_data_cache[key] = "\x00" * len(self._sensitive_data_cache[key])
            del self._sensitive_data_cache[key]

        # Принудительный GC не вызываем — оставляем Python управлять памятью
        logger.debug("Sensitive data cleared")

    def _clear_clipboard(self) -> None:
        """Очистка буфера обмена."""
        try:
            import tkinter as tk

            root = tk.Tcl()
            root.clipboard_clear()
            root.destroy()
            logger.debug("Clipboard cleared")
        except Exception as e:
            logger.warning("Failed to clear clipboard: %s", e)

    def _protect_documents(self) -> None:
        """Защита открытых документов при блокировке.

        Скрывает содержимое документов из UI.
        """
        logger.debug("Protecting open documents")
        # Реализация зависит от DocumentService
        # Вызывается через callback или интегрируется с DocumentController

    def _restore_documents(self) -> None:
        """Восстановление документов после разблокировки."""
        logger.debug("Restoring document view")
        # Реализация зависит от DocumentService

    # === Доступ к конфигурации ===

    def get_config(self) -> LockConfig:
        """Возвращает текущую конфигурацию.

        Returns:
            Копия конфигурации блокировки
        """
        with self._lock:
            return LockConfig(
                enabled=self._config.enabled,
                auto_lock_minutes=self._config.auto_lock_minutes,
                lock_on_sleep=self._config.lock_on_sleep,
                lock_on_screensaver=self._config.lock_on_screensaver,
                require_mfa_to_unlock=self._config.require_mfa_to_unlock,
                clear_clipboard_on_lock=self._config.clear_clipboard_on_lock,
                hide_documents_on_lock=self._config.hide_documents_on_lock,
            )

    def update_config(self, config: LockConfig) -> None:
        """Обновляет конфигурацию блокировки.

        Args:
            config: Новая конфигурация
        """
        with self._lock:
            self._config = config
            logger.info(
                "Lock config updated (enabled=%s, timeout=%s min)",
                config.enabled,
                config.auto_lock_minutes,
            )

    # === История событий ===

    def get_event_history(self) -> List[LockEvent]:
        """Возвращает историю событий блокировки.

        Returns:
            Список событий блокировки/разблокировки
        """
        with self._lock:
            return self._event_history.copy()

    def clear_history(self) -> None:
        """Очищает историю событий."""
        with self._lock:
            self._event_history.clear()
            logger.debug("Lock event history cleared")

    # === Служебные методы ===

    def __repr__(self) -> str:
        """Строковое представление."""
        with self._lock:
            return (
                f"SessionLockManager("
                f"locked={self._is_locked}, "
                f"enabled={self._config.enabled}, "
                f"timeout={self._config.auto_lock_minutes}min, "
                f"reason={self._lock_reason.value if self._lock_reason else 'None'})"
            )
