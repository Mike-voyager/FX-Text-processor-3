"""Система тем для FX Text Processor 3.

Модуль предоставляет систему темирования GUI с поддержкой ретро-терминальных
цветовых схем (VT100, Amber CRT, Phosphor) и современных вариантов.

Architecture:
    - Theme: immutable dataclass с цветовой схемой
    - ThemeVariant: LIGHT/DARK варианты темы
    - ThemeManager: thread-safe singleton для управления темами

Example:
    >>> from src.gui.themes import get_theme_manager, ThemeVariant
    >>> manager = get_theme_manager()
    >>> theme = manager.get_theme("classic_green")
    >>> manager.apply_to_widget(my_button)
    >>> dark_theme = manager.get_variant(ThemeVariant.DARK)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from enum import Enum, auto
from threading import Lock
from typing import ClassVar, Optional

from src.gui.core.exceptions import GUIError
from src.gui.themes.protocol import ThemeProtocol
from src.gui.themes.registry import ThemeRegistry, ThemeRegistryError, get_registry

# =============================================================================
# THEME EXCEPTIONS
# =============================================================================


class ThemeError(GUIError):
    """Ошибка системы тем.

    Attributes:
        theme_name: Имя темы, вызвавшей ошибку
        message: Описание ошибки

    Example:
        >>> raise ThemeError("unknown_theme", "Тема не найдена")
        ThemeError: Тема не найдена
    """

    def __init__(
        self,
        theme_name: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        """Инициализация ошибки темы.

        Args:
            theme_name: Имя темы, вызвавшей ошибку
            message: Описание ошибки
        """
        self.theme_name = theme_name
        if message is None:
            message = f"Ошибка темы '{theme_name}'" if theme_name else "Ошибка темы"
        super().__init__(message)


class ThemeNotFoundError(ThemeError):
    """Тема не найдена в реестре.

    Attributes:
        theme_name: Запрошенное имя темы

    Example:
        >>> raise ThemeNotFoundError("nonexistent")
        ThemeNotFoundError: Тема 'nonexistent' не найдена
    """

    def __init__(self, theme_name: str) -> None:
        """Инициализация ошибки.

        Args:
            theme_name: Имя ненайденной темы
        """
        message = f"Тема '{theme_name}' не найдена"
        super().__init__(theme_name, message)


class ThemeApplicationError(ThemeError):
    """Ошибка применения темы к виджету.

    Attributes:
        widget_type: Тип виджета
        theme_name: Имя темы

    Example:
        >>> raise ThemeApplicationError("Button", "classic_green")
        ThemeApplicationError: Не удалось применить тему к виджету Button
    """

    def __init__(
        self,
        widget_type: str,
        theme_name: str,
        cause: Optional[Exception] = None,
    ) -> None:
        """Инициализация ошибки.

        Args:
            widget_type: Тип виджета
            theme_name: Имя темы
            cause: Исходное исключение
        """
        self.widget_type = widget_type
        self.cause = cause
        message = f"Не удалось применить тему '{theme_name}' к виджету {widget_type}"
        super().__init__(theme_name, message)


# =============================================================================
# THEME DATA CLASS
# =============================================================================


@dataclass(frozen=True)
class Theme:
    """Immutable цветовая схема темы.

    Представляет собой полную цветовую схему GUI с набором цветов
    для фона, текста, акцентов и состояний.

    Attributes:
        bg_color: Цвет фона (hex)
        fg_color: Цвет текста (hex)
        accent_color: Акцентный цвет для выделения (hex)
        warning_color: Цвет предупреждений (hex)
        error_color: Цвет ошибок (hex)
        success_color: Цвет успешных операций (hex)
        border_color: Цвет рамок (hex)
        font_family: Семейство шрифтов
        font_size: Базовый размер шрифта (pt)

    Example:
        >>> theme = Theme(
        ...     bg_color="#000000",
        ...     fg_color="#00FF00",
        ...     accent_color="#00AA00",
        ...     warning_color="#FFA500",
        ...     error_color="#FF0000",
        ...     success_color="#00FF00",
        ...     border_color="#003300",
        ...     font_family="Courier New",
        ...     font_size=12,
        ... )

    Version: 1.0
    """

    bg_color: str
    fg_color: str
    accent_color: str
    warning_color: str
    error_color: str
    success_color: str
    border_color: str
    font_family: str
    font_size: int

    def __post_init__(self) -> None:
        """Валидация значений темы после создания."""
        # Валидация hex цветов
        hex_colors = [
            self.bg_color,
            self.fg_color,
            self.accent_color,
            self.warning_color,
            self.error_color,
            self.success_color,
            self.border_color,
        ]
        for color in hex_colors:
            object.__setattr__(  # pylint: disable=unnecessary-dunder-call
                self, "_validated", self._validate_hex_color(color)
            )

        # Валидация размера шрифта
        if self.font_size < 6 or self.font_size > 72:
            raise ValueError(f"font_size должен быть между 6 и 72, получен {self.font_size}")

        # Валидация font_family
        if not self.font_family or not self.font_family.strip():
            raise ValueError("font_family не может быть пустым")

    @staticmethod
    def _validate_hex_color(color: str) -> bool:
        """Валидация hex цвета.

        Args:
            color: Строка цвета в формате #RRGGBB

        Returns:
            True если цвет валиден

        Raises:
            ValueError: Если цвет невалиден
        """
        if not color:
            raise ValueError("Цвет не может быть пустым")
        if not color.startswith("#"):
            raise ValueError(f"Цвет должен начинаться с '#', получен '{color}'")
        if len(color) != 7:
            raise ValueError(f"Цвет должен быть в формате #RRGGBB, получен '{color}'")

        # Проверка hex символов
        hex_part = color[1:]
        try:
            int(hex_part, 16)
        except ValueError as exc:
            raise ValueError(f"Невалидные hex символы в цвете '{color}'") from exc

        return True

    def with_font_size(self, size: int) -> Theme:
        """Создаёт копию темы с другим размером шрифта.

        Args:
            size: Новый размер шрифта

        Returns:
            Новый Theme с изменённым font_size

        Example:
            >>> big_theme = theme.with_font_size(14)
        """
        return Theme(
            bg_color=self.bg_color,
            fg_color=self.fg_color,
            accent_color=self.accent_color,
            warning_color=self.warning_color,
            error_color=self.error_color,
            success_color=self.success_color,
            border_color=self.border_color,
            font_family=self.font_family,
            font_size=size,
        )

    def with_colors(
        self,
        bg_color: Optional[str] = None,
        fg_color: Optional[str] = None,
        accent_color: Optional[str] = None,
    ) -> Theme:
        """Создаёт копию темы с изменёнными цветами.

        Args:
            bg_color: Новый цвет фона (опционально)
            fg_color: Новый цвет текста (опционально)
            accent_color: Новый акцентный цвет (опционально)

        Returns:
            Новый Theme с изменёнными цветами

        Example:
            >>> dark_theme = theme.with_colors(bg_color="#001100")
        """
        return Theme(
            bg_color=bg_color or self.bg_color,
            fg_color=fg_color or self.fg_color,
            accent_color=accent_color or self.accent_color,
            warning_color=self.warning_color,
            error_color=self.error_color,
            success_color=self.success_color,
            border_color=self.border_color,
            font_family=self.font_family,
            font_size=self.font_size,
        )


# =============================================================================
# THEME VARIANT ENUM
# =============================================================================


class ThemeVariant(Enum):
    """Варианты темы (светлая/тёмная).

    Используется для получения адаптированной версии темы
    под разные условия освещения.

    Example:
        >>> variant = ThemeVariant.DARK
        >>> theme = manager.get_variant(variant)
    """

    LIGHT = auto()
    """Светлый вариант темы."""

    DARK = auto()
    """Тёмный вариант темы (добавляет затемнение фона)."""


# =============================================================================
# THEME MANAGER (SINGLETON)
# =============================================================================


class ThemeManager:
    """Thread-safe singleton менеджер тем.

    Управляет регистрацией, выбором и применением тем к виджетам GUI.
    Реализует паттерн Singleton с thread-safe инициализацией.

    Attributes:
        current_theme: Активная тема
        themes: Словарь зарегистрированных тем

    Thread Safety:
        Все операции с состоянием защищены Lock.

    Example:
        >>> manager = ThemeManager()  # Получает singleton
        >>> theme = manager.get_theme("classic_green")
        >>> manager.set_theme("classic_green")
        >>> manager.apply_to_widget(my_button)

    Version: 1.0
    """

    _instance: ClassVar[Optional[ThemeManager]] = None
    _lock: ClassVar[Lock] = Lock()
    _initialized: bool = False

    def __new__(cls) -> ThemeManager:
        """Создание singleton экземпляра.

        Returns:
            ThemeManager экземпляр
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Инициализация менеджера тем.

        Вызывается один раз при первом создании singleton.
        Регистрирует встроенные темы из подмодулей.
        """
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            self._themes: dict[str, Theme] = {}
            self._current_theme_name: str = "classic_green"
            self._operation_lock: Lock = Lock()

            # Регистрация встроенных тем
            self._register_builtin_themes()

            self._initialized = True

    def _register_builtin_themes(self) -> None:
        """Регистрация встроенных тем из подмодулей.

        Импортирует и регистрирует все стандартные темы.
        """
        try:
            from src.gui.themes.implementations import (
                amber,
                classic_green,
                high_contrast,
                phosphor_white,
                retro_green,
            )

            self._themes["classic_green"] = classic_green.THEME  # type: ignore[assignment]
            self._themes["retro_green"] = retro_green.THEME  # type: ignore[assignment]
            self._themes["amber"] = amber.THEME  # type: ignore[assignment]
            self._themes["phosphor_white"] = phosphor_white.THEME  # type: ignore[assignment]
            self._themes["high_contrast"] = high_contrast.THEME  # type: ignore[assignment]

        except ImportError as exc:
            # Если подмодули не найдены, создаём fallback тему
            self._themes["classic_green"] = Theme(
                bg_color="#000000",
                fg_color="#00FF00",
                accent_color="#00AA00",
                warning_color="#FFA500",
                error_color="#FF0000",
                success_color="#00FF00",
                border_color="#003300",
                font_family="Courier New",
                font_size=12,
            )
            raise ThemeError(message=f"Ошибка загрузки встроенных тем: {exc}") from exc

    def get_theme(self, name: str) -> Theme:
        """Получает тему по имени.

        Args:
            name: Имя темы

        Returns:
            Theme с указанным именем

        Raises:
            ThemeNotFoundError: Если тема не найдена

        Example:
            >>> theme = manager.get_theme("classic_green")
        """
        with self._operation_lock:
            if name not in self._themes:
                raise ThemeNotFoundError(name)
            return self._themes[name]

    def set_theme(self, name: str) -> None:
        """Устанавливает активную тему.

        Args:
            name: Имя темы для установки

        Raises:
            ThemeNotFoundError: Если тема не найдена

        Example:
            >>> manager.set_theme("amber")
        """
        with self._operation_lock:
            if name not in self._themes:
                raise ThemeNotFoundError(name)
            self._current_theme_name = name

    def get_current_theme(self) -> Theme:
        """Получает текущую активную тему.

        Returns:
            Активная Theme

        Example:
            >>> current = manager.get_current_theme()
            >>> print(current.bg_color)
        """
        with self._operation_lock:
            return self._themes[self._current_theme_name]

    def get_current_theme_name(self) -> str:
        """Получает имя текущей активной темы.

        Returns:
            Имя активной темы

        Example:
            >>> name = manager.get_current_theme_name()
            >>> print(name)
            'classic_green'
        """
        with self._operation_lock:
            return self._current_theme_name

    def list_themes(self) -> list[str]:
        """Возвращает список доступных тем.

        Returns:
            Список имён зарегистрированных тем

        Example:
            >>> themes = manager.list_themes()
            >>> print(themes)
            ['classic_green', 'retro_green', 'amber', ...]
        """
        with self._operation_lock:
            return sorted(self._themes.keys())

    def register_theme(self, name: str, theme: Theme) -> None:
        """Регистрирует новую тему.

        Args:
            name: Уникальное имя темы
            theme: Theme для регистрации

        Raises:
            ThemeError: Если тема с таким именем уже существует

        Example:
            >>> custom_theme = Theme(...)
            >>> manager.register_theme("my_theme", custom_theme)
        """
        with self._operation_lock:
            if name in self._themes:
                raise ThemeError(name, f"Тема '{name}' уже зарегистрирована")
            self._themes[name] = theme

    def unregister_theme(self, name: str) -> None:
        """Удаляет тему из реестра.

        Args:
            name: Имя темы для удаления

        Raises:
            ThemeNotFoundError: Если тема не найдена
            ThemeError: Если пытаемся удалить текущую активную тему

        Example:
            >>> manager.unregister_theme("custom_theme")
        """
        with self._operation_lock:
            if name not in self._themes:
                raise ThemeNotFoundError(name)
            if name == self._current_theme_name:
                raise ThemeError(name, "Нельзя удалить текущую активную тему")
            del self._themes[name]

    def apply_to_widget(self, widget: tk.Widget) -> None:
        """Применяет текущую тему к Tkinter виджету.

        Настраивает цвета фона, текста и шрифт виджета согласно
        текущей активной теме. Работает с базовыми виджетами
        (Frame, Label, Button, Entry, Text и др.).

        Args:
            widget: Tkinter виджет для стилизации

        Raises:
            ThemeApplicationError: Если применение темы не удалось
            TypeError: Если widget не является tk.Widget

        Example:
            >>> button = tk.Button(root, text="Click")
            >>> manager.apply_to_widget(button)
        """
        if not isinstance(widget, (tk.Widget, tk.BaseWidget)):
            raise TypeError(f"widget должен быть tk.Widget, получен {type(widget).__name__}")

        try:
            theme = self.get_current_theme()
            widget_type = widget.winfo_class()

            # Базовые настройки для всех виджетов
            if hasattr(widget, "configure"):
                # Настройка фона
                try:
                    widget.configure(bg=theme.bg_color)  # type: ignore[call-arg]
                except tk.TclError:
                    pass  # Некоторые виджеты не поддерживают bg

                # Настройка текста
                try:
                    widget.configure(fg=theme.fg_color)  # type: ignore[call-arg]
                except tk.TclError:
                    pass

                # Настройка шрифта
                try:
                    widget.configure(font=(theme.font_family, theme.font_size))  # type: ignore[call-arg]
                except tk.TclError:
                    pass

                # Специфичные настройки для разных типов виджетов
                if widget_type in ("TButton", "Button"):
                    try:
                        widget.configure(
                            activebackground=theme.accent_color,
                            activeforeground=theme.bg_color,
                        )  # type: ignore[call-arg]
                    except tk.TclError:
                        pass

                elif widget_type in ("TEntry", "Entry"):
                    try:
                        widget.configure(
                            insertbackground=theme.fg_color,
                            selectbackground=theme.accent_color,
                            selectforeground=theme.bg_color,
                        )  # type: ignore[call-arg]
                    except tk.TclError:
                        pass

                elif widget_type in ("TText", "Text"):
                    try:
                        widget.configure(
                            insertbackground=theme.fg_color,
                            selectbackground=theme.accent_color,
                            selectforeground=theme.bg_color,
                        )  # type: ignore[call-arg]
                    except tk.TclError:
                        pass

        except Exception as exc:
            widget_type = widget.winfo_class() if hasattr(widget, "winfo_class") else "Unknown"
            raise ThemeApplicationError(
                widget_type=widget_type,
                theme_name=self._current_theme_name,
                cause=exc,
            ) from exc

    def get_variant(self, variant: ThemeVariant) -> Theme:
        """Получает вариант текущей темы.

        Создаёт адаптированную версию текущей темы для
        светлого или тёмного варианта.

        Args:
            variant: LIGHT или DARK вариант

        Returns:
            Адаптированная Theme

        Example:
            >>> dark_theme = manager.get_variant(ThemeVariant.DARK)
        """
        theme = self.get_current_theme()

        if variant == ThemeVariant.LIGHT:
            # Светлый вариант: светлее фон, тёмнее текст
            return self._lighten_theme(theme, factor=0.2)
        # DARK вариант: темнее фон
        return self._darken_theme(theme, factor=0.3)

    @staticmethod
    def _lighten_theme(theme: Theme, factor: float) -> Theme:
        """Осветляет тему.

        Args:
            theme: Исходная тема
            factor: Коэффициент осветления (0.0 - 1.0)

        Returns:
            Осветлённая Theme
        """

        def lighten_color(color: str, f: float) -> str:
            """Осветляет hex цвет."""
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)

            r = min(255, int(r + (255 - r) * f))
            g = min(255, int(g + (255 - g) * f))
            b = min(255, int(b + (255 - b) * f))

            return f"#{r:02x}{g:02x}{b:02x}"

        def darken_color(color: str, f: float) -> str:
            """Затемняет hex цвет."""
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)

            r = max(0, int(r * (1 - f)))
            g = max(0, int(g * (1 - f)))
            b = max(0, int(b * (1 - f)))

            return f"#{r:02x}{g:02x}{b:02x}"

        return Theme(
            bg_color=lighten_color(theme.bg_color, factor),
            fg_color=darken_color(theme.fg_color, factor / 2),
            accent_color=theme.accent_color,
            warning_color=theme.warning_color,
            error_color=theme.error_color,
            success_color=theme.success_color,
            border_color=lighten_color(theme.border_color, factor / 2),
            font_family=theme.font_family,
            font_size=theme.font_size,
        )

    @staticmethod
    def _darken_theme(theme: Theme, factor: float) -> Theme:
        """Затемняет тему.

        Args:
            theme: Исходная тема
            factor: Коэффициент затемнения (0.0 - 1.0)

        Returns:
            Затемнённая Theme
        """

        def darken_color(color: str, f: float) -> str:
            """Затемняет hex цвет."""
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)

            r = max(0, int(r * (1 - f)))
            g = max(0, int(g * (1 - f)))
            b = max(0, int(b * (1 - f)))

            return f"#{r:02x}{g:02x}{b:02x}"

        def lighten_color(color: str, f: float) -> str:
            """Осветляет hex цвет."""
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)

            r = min(255, int(r + (255 - r) * f))
            g = min(255, int(g + (255 - g) * f))
            b = min(255, int(b + (255 - b) * f))

            return f"#{r:02x}{g:02x}{b:02x}"

        return Theme(
            bg_color=darken_color(theme.bg_color, factor),
            fg_color=lighten_color(theme.fg_color, factor / 2),
            accent_color=theme.accent_color,
            warning_color=theme.warning_color,
            error_color=theme.error_color,
            success_color=theme.success_color,
            border_color=darken_color(theme.border_color, factor / 2),
            font_family=theme.font_family,
            font_size=theme.font_size,
        )

    def reset(self) -> None:
        """Сбрасывает singleton состояние (для тестирования).

        Очищает все зарегистрированные темы и сбрасывает
        singleton экземпляр. Использовать только в тестах!

        Example:
            >>> manager.reset()  # Только для тестирования
        """
        with self._lock:
            with self._operation_lock:
                self._themes.clear()
                self._current_theme_name = "classic_green"
                self._initialized = False
                ThemeManager._instance = None


# =============================================================================
# MODULE-LEVEL FUNCTIONS
# =============================================================================


def get_theme_manager() -> ThemeManager:
    """Получает singleton экземпляр ThemeManager.

    Returns:
        ThemeManager singleton

    Example:
        >>> manager = get_theme_manager()
        >>> theme = manager.get_current_theme()
    """
    return ThemeManager()


# =============================================================================
# MODULE EXPORTS
# =============================================================================

# Re-export theme constants from implementations for backward compatibility
# (placed after all class definitions to avoid circular imports)
from src.gui.themes.implementations.amber import AMBER_THEME  # noqa: E402
from src.gui.themes.implementations.classic_green import CLASSIC_GREEN_THEME  # noqa: E402
from src.gui.themes.implementations.high_contrast import HIGH_CONTRAST_THEME  # noqa: E402
from src.gui.themes.implementations.phosphor_white import PHOSPHOR_WHITE_THEME  # noqa: E402
from src.gui.themes.implementations.retro_green import RETRO_GREEN_THEME  # noqa: E402

__all__ = [
    # Classes
    "Theme",
    "ThemeVariant",
    "ThemeManager",
    # New protocol & registry
    "ThemeProtocol",
    "ThemeRegistry",
    "ThemeRegistryError",
    # Exceptions
    "ThemeError",
    "ThemeNotFoundError",
    "ThemeApplicationError",
    # Functions
    "get_theme_manager",
    "get_registry",
    # Theme constants (backward compatibility)
    "CLASSIC_GREEN_THEME",
    "RETRO_GREEN_THEME",
    "AMBER_THEME",
    "PHOSPHOR_WHITE_THEME",
    "HIGH_CONTRAST_THEME",
]
