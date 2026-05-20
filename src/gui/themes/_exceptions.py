"""Иерархия исключений для модуля тем GUI.

Определяет единую иерархию исключений для системы тем,
объединяя ошибки реестра, поиска и применения тем.

Все исключения наследуются от GUIError через ThemeError,
обеспечивая совместимость с общей системой обработки ошибок GUI.

Architecture:
    ThemeError (→ GUIError → Exception)
    ├── ThemeNotFoundError — тема не найдена в реестре
    ├── ThemeRegistryError — ошибка операции реестра тем
    └── ThemeApplicationError — ошибка применения темы к виджету

Example:
    >>> from src.gui.themes._exceptions import ThemeNotFoundError
    >>> raise ThemeNotFoundError("missing_theme")
    ThemeNotFoundError: missing_theme - Тема 'missing_theme' не найдена

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from typing import Optional

from src.gui.core.exceptions import GUIError


class ThemeError(GUIError):
    """Базовое исключение для ошибок темы.

    Все исключения модуля тем наследуются от ThemeError,
    который расширяет GUIError для совместимости с общей
    системой обработки ошибок GUI.

    Attributes:
        theme_name: Имя темы, связанной с ошибкой.

    Example:
        >>> raise ThemeError("custom_theme", "Custom error message")
        ThemeError: custom_theme - Custom error message
    """

    def __init__(
        self,
        theme_name: str = "",
        message: Optional[str] = None,
    ) -> None:
        """Инициализация исключения темы.

        Args:
            theme_name: Имя темы, связанной с ошибкой.
            message: Описание ошибки (опционально).
        """
        self.theme_name = theme_name
        super().__init__(message or self.__class__.__name__)

    def __str__(self) -> str:
        """Строковое представление исключения.

        Returns:
            Строка в формате «имя_темы — сообщение» или только
            имя класса, если детали отсутствуют.
        """
        parts = [self.theme_name] if self.theme_name else []
        if self.message:
            parts.append(self.message)
        return " - ".join(parts) if parts else self.__class__.__name__


class ThemeNotFoundError(ThemeError):
    """Тема не найдена в реестре.

    Возникает при попытке получить или установить тему,
    которая не зарегистрирована в ThemeManager или ThemeRegistry.

    Attributes:
        theme_name: Имя ненайденной темы.

    Example:
        >>> raise ThemeNotFoundError("missing_theme")
        ThemeNotFoundError: missing_theme - Тема 'missing_theme' не найдена
    """

    def __init__(self, name: str = "") -> None:
        """Инициализация исключения.

        Args:
            name: Имя ненайденной темы.
        """
        self.theme_name = name
        super().__init__(name, f"Тема '{name}' не найдена")


class ThemeRegistryError(ThemeError):
    """Ошибка операции реестра тем.

    Возникает при нарушении правил реестра: повторная регистрация,
    ошибка загрузки встроенных тем и т.д.

    Example:
        >>> raise ThemeRegistryError("custom_theme", "Тема уже зарегистрирована")
        ThemeRegistryError: custom_theme - Тема уже зарегистрирована
    """

    def __init__(
        self,
        theme_name: str = "",
        message: Optional[str] = None,
    ) -> None:
        """Инициализация ошибки реестра.

        Args:
            theme_name: Имя темы, связанной с ошибкой.
            message: Описание ошибки (опционально).
        """
        super().__init__(theme_name, message or "Ошибка реестра тем")


class ThemeApplicationError(ThemeError):
    """Ошибка применения темы к виджету.

    Возникает, когда не удаётся применить тему к Tkinter виджету.

    Attributes:
        widget_type: Тип виджета, к которому применялась тема.
        cause: Исходное исключение, вызвавшее ошибку.

    Example:
        >>> cause = ValueError("Original error")
        >>> raise ThemeApplicationError("Button", "classic_green", cause)
        ThemeApplicationError: classic_green -
            Ошибка применения темы 'classic_green' к виджету 'Button'
    """

    def __init__(
        self,
        widget_type: str = "",
        theme_name: str = "",
        cause: Optional[Exception] = None,
    ) -> None:
        """Инициализация исключения.

        Args:
            widget_type: Тип виджета.
            theme_name: Имя темы.
            cause: Исходное исключение.
        """
        self.widget_type = widget_type
        self.cause = cause
        super().__init__(
            theme_name,
            f"Ошибка применения темы '{theme_name}' к виджету '{widget_type}'",
        )


__all__ = [
    "ThemeError",
    "ThemeNotFoundError",
    "ThemeRegistryError",
    "ThemeApplicationError",
]
