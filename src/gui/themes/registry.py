"""Реестр тем для FX Text Processor 3.

Предоставляет thread-safe singleton ThemeRegistry для регистрации,
выбора и получения тем оформления GUI.

Architecture:
    - ThemeRegistry: singleton с RLock
    - Lazy registration встроенных тем
    - Thread-safe доступ к текущей теме

Example:
    >>> from src.gui.themes import ThemeRegistry
    >>> registry = ThemeRegistry.get_instance()
    >>> registry.register(my_theme)
    >>> registry.set_current("classic_green")
    >>> theme = registry.get_current()
    >>> theme.get_color("bg")
    '#000000'

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import threading
from typing import ClassVar, Optional

from src.gui.core.exceptions import GUIError
from src.gui.themes.protocol import ThemeProtocol


class ThemeRegistryError(GUIError):
    """Ошибка реестра тем.

    Attributes:
        message: Описание ошибки.
    """

    def __init__(self, message: str = "") -> None:
        """Инициализация ошибки реестра.

        Args:
            message: Описание ошибки.
        """
        super().__init__(message or "Ошибка реестра тем")


class ThemeNotFoundError(ThemeRegistryError):
    """Theme не найдена в реестре.

    Attributes:
        theme_name: Имя ненайденной темы.
    """

    def __init__(self, name: str) -> None:
        """Инициализация ошибки.

        Args:
            name: Имя ненайденной темы.
        """
        self.theme_name = name
        super().__init__(f"Theme '{name}' не найдена")


class ThemeRegistry:
    """Thread-safe singleton реестр тем.

    Управляет регистрацией, выбором и применением тем.
    Реализует паттерн Singleton с thread-safe инициализацией через RLock.

    Attributes:
        _themes: Словарь зарегистрированных тем (name -> ThemeProtocol).
        _current_name: Имя текущей активной темы.

    Thread Safety:
        Все операции с состоянием защищены RLock.

    Example:
        >>> registry = ThemeRegistry.get_instance()
        >>> registry.register(my_theme)
        >>> registry.set_current("classic_green")
        >>> theme = registry.get_current()

    Version: 1.0
    """

    _instance: ClassVar[Optional[ThemeRegistry]] = None
    _lock: ClassVar[threading.RLock] = threading.RLock()
    _initialized: bool = False

    def __new__(cls) -> ThemeRegistry:
        """Создание singleton экземпляра.

        Returns:
            ThemeRegistry экземпляр.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Инициализация реестра тем.

        Вызывается один раз при первом создании singleton.
        Регистрирует встроенные темы из подмодулей.
        """
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            self._themes: dict[str, ThemeProtocol] = {}
            self._current_name: str = ""
            self._operation_lock: threading.RLock = threading.RLock()

            # Регистрация встроенных тем
            self._register_builtin_themes()

            self._initialized = True

    @classmethod
    def get_instance(cls) -> ThemeRegistry:
        """Возвращает singleton экземпляр реестра.

        Returns:
            ThemeRegistry singleton.

        Example:
            >>> registry = ThemeRegistry.get_instance()
        """
        return cls()

    @classmethod
    def initialize(cls) -> ThemeRegistry:
        """Явно инициализирует singleton реестр тем.

        Returns:
            ThemeRegistry singleton.

        Example:
            >>> ThemeRegistry.initialize()
        """
        return cls.get_instance()

    def _register_builtin_themes(self) -> None:
        """Регистрация встроенных тем из подмодулей.

        Использует отложенный импорт для избежания циклических зависимостей.
        """
        try:
            from src.gui.themes.implementations import (
                amber,
                classic_green,
                high_contrast,
                phosphor_white,
                retro_green,
            )

            # Регистрируем темы если они экспортируют адаптированные экземпляры
            for module, attr_name in (
                (classic_green, "CLASSIC_GREEN_THEME"),
                (retro_green, "RETRO_GREEN_THEME"),
                (amber, "AMBER_THEME"),
                (phosphor_white, "PHOSPHOR_WHITE_THEME"),
                (high_contrast, "HIGH_CONTRAST_THEME"),
            ):
                theme = getattr(module, attr_name, None)
                if theme is not None:
                    self.register(theme)

        except ImportError as exc:
            raise ThemeRegistryError(f"Error loading built-in themes: {exc}") from exc

    def register(self, theme: ThemeProtocol) -> None:
        """Регистрирует тему.

        Args:
            theme: Theme для регистрации.

        Raises:
            ThemeRegistryError: Если тема с таким именем уже существует.

        Example:
            >>> registry.register(my_theme)
        """
        with self._operation_lock:
            if theme.name in self._themes:
                raise ThemeRegistryError(f"Theme '{theme.name}' already registered")
            self._themes[theme.name] = theme

    def get(self, name: str) -> ThemeProtocol:
        """Возвращает тему по имени.

        Args:
            name: Имя темы.

        Returns:
            ThemeProtocol с указанным именем.

        Raises:
            ThemeNotFoundError: Если тема не найдена.

        Example:
            >>> theme = registry.get("classic_green")
        """
        with self._operation_lock:
            if name not in self._themes:
                raise ThemeNotFoundError(name)
            return self._themes[name]

    def list_themes(self) -> list[str]:
        """Возвращает список имён зарегистрированных тем.

        Returns:
            Отсортированный список имён тем.

        Example:
            >>> names = registry.list_themes()
            >>> print(names)
            ['amber', 'classic_green', 'high_contrast', ...]
        """
        with self._operation_lock:
            return sorted(self._themes.keys())

    def get_current(self) -> ThemeProtocol:
        """Возвращает текущую активную тему.

        Returns:
            Активная ThemeProtocol.

        Raises:
            ThemeNotFoundError: Если текущая тема не установлена.
        """
        with self._operation_lock:
            if not self._current_name:
                # Fallback to the first available theme if none is set
                if self._themes:
                    first_theme_name = next(iter(self._themes))
                    self._current_name = first_theme_name
                    return self._themes[first_theme_name]
                raise ThemeNotFoundError("")
            return self._themes[self._current_name]

    def set_current(self, name: str) -> None:
        """Устанавливает текущую тему.

        Args:
            name: Имя темы для установки.

        Raises:
            ThemeNotFoundError: Если тема не найдена.

        Example:
            >>> registry.set_current("amber")
        """
        with self._operation_lock:
            if name not in self._themes:
                raise ThemeNotFoundError(name)
            self._current_name = name


# =============================================================================
# MODULE FUNCTIONS
# =============================================================================


def get_registry() -> ThemeRegistry:
    """Возвращает singleton экземпляр ThemeRegistry.

    Returns:
        ThemeRegistry singleton.

    Example:
        >>> registry = get_registry()
        >>> registry.set_current("classic_green")
    """
    return ThemeRegistry.get_instance()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "ThemeRegistry",
    "ThemeRegistryError",
    "ThemeNotFoundError",
    "get_registry",
]
