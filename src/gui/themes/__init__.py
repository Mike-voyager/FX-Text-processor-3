"""Модуль тем оформления GUI для FX Text Processor 3.

Предоставляет Theme, ThemeManager, ThemeProtocol, ThemeRegistry,
ThemeAdapter и встроенные темы.

Example:
    >>> from src.gui.themes import Theme, ThemeManager, get_theme_manager
    >>> manager = get_theme_manager()
    >>> manager.set_theme("classic_green")
    >>> theme = manager.get_current_theme()
    >>> theme.bg_color
    '#000000'

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import dataclasses
import enum
import re
import threading
import tkinter as tk
from typing import Any, ClassVar, Optional

from src.gui.themes.adapter import ThemeAdapter
from src.gui.themes.protocol import ThemeProtocol
from src.gui.themes.registry import (
    ThemeRegistry,
    ThemeRegistryError,
    get_registry,
)

# =============================================================================
# EXCEPTIONS
# =============================================================================


class ThemeError(Exception):
    """Базовое исключение для ошибок темы.

    Attributes:
        theme_name: Имя темы, связанной с ошибкой.

    Example:
        >>> raise ThemeError("custom_theme", "Custom error message")
        ThemeError: custom_theme - Custom error message
    """

    def __init__(self, theme_name: str = "", message: str = "") -> None:
        """Инициализация исключения темы.

        Args:
            theme_name: Имя темы, связанной с ошибкой.
            message: Описание ошибки.
        """
        self.theme_name = theme_name
        super().__init__(message)

    def __str__(self) -> str:
        """Строковое представление исключения."""
        parts = [self.theme_name] if self.theme_name else []
        if self.args and self.args[0]:
            parts.append(str(self.args[0]))
        return " - ".join(parts) if parts else self.__class__.__name__


class ThemeNotFoundError(ThemeError):
    """Тема не найдена в реестре.

    Attributes:
        theme_name: Имя ненайденной темы.

    Example:
        >>> raise ThemeNotFoundError("missing_theme")
        ThemeNotFoundError: missing_theme - Theme 'missing_theme' не найдена
    """

    def __init__(self, name: str = "") -> None:
        """Инициализация исключения.

        Args:
            name: Имя ненайденной темы.
        """
        self.theme_name = name
        super().__init__(name, f"Theme '{name}' не найдена")


class ThemeApplicationError(ThemeError):
    """Ошибка применения темы к виджету.

    Attributes:
        widget_type: Тип виджета, к которому применялась тема.
        cause: Исходное исключение, вызвавшее ошибку.

    Example:
        >>> cause = ValueError("Original error")
        >>> raise ThemeApplicationError("Button", "classic_green", cause)
        ThemeApplicationError: Button - classic_green - ...
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


# =============================================================================
# THEME VARIANT ENUM
# =============================================================================


class ThemeVariant(enum.Enum):
    """Вариант темы (светлая / тёмная).

    Example:
        >>> ThemeVariant.LIGHT
        <ThemeVariant.LIGHT: 'light'>
    """

    LIGHT = "light"
    DARK = "dark"


# =============================================================================
# THEME DATACLASS
# =============================================================================


@dataclasses.dataclass(frozen=True)
class Theme:
    """Неизменяемая dataclass темы оформления.

    Attributes:
        bg_color: Цвет фона (#RRGGBB).
        fg_color: Цвет текста (#RRGGBB).
        accent_color: Акцентный цвет (#RRGGBB).
        warning_color: Цвет предупреждения (#RRGGBB).
        error_color: Цвет ошибки (#RRGGBB).
        success_color: Цвет успеха (#RRGGBB).
        border_color: Цвет границы (#RRGGBB).
        font_family: Семейство шрифтов.
        font_size: Размер шрифта (6–72).

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
        """Валидация значений после создания.

        Raises:
            ValueError: Если цвет не в формате #RRGGBB или font_size вне диапазона.
        """
        for field_name in (
            "bg_color",
            "fg_color",
            "accent_color",
            "warning_color",
            "error_color",
            "success_color",
            "border_color",
        ):
            value: str = getattr(self, field_name)
            if not value.startswith("#"):
                raise ValueError("Цвет должен начинаться с #")
            if len(value) != 7 or not re.fullmatch(r"#[0-9A-Fa-f]{6}", value):
                raise ValueError(f"Цвет '{field_name}' должен быть в формате #RRGGBB")
        if not (6 <= self.font_size <= 72):
            raise ValueError("font_size должен быть в диапазоне 6-72")

    def with_font_size(self, size: int) -> Theme:
        """Возвращает новую тему с изменённым размером шрифта.

        Args:
            size: Новый размер шрифта.

        Returns:
            Новый экземпляр Theme с изменённым font_size.
        """
        return dataclasses.replace(self, font_size=size)

    def with_colors(self, **kwargs: Any) -> Theme:
        """Возвращает новую тему с изменёнными цветами.

        Args:
            **kwargs: Пары ключ-значение для замены цветовых полей.

        Returns:
            Новый экземпляр Theme с изменёнными цветами.
        """
        return dataclasses.replace(self, **kwargs)


# =============================================================================
# THEME MANAGER (singleton)
# =============================================================================


class ThemeManager:
    """Singleton менеджер тем оформления GUI.

    Управляет регистрацией, выбором и применением тем.
    Реализует паттерн Singleton с thread-safe инициализацией.

    Attributes:
        _instance: Singleton экземпляр.
        _lock: RLock для thread-safe создания.
        _initialized: Флаг завершения инициализации.

    Example:
        >>> manager = ThemeManager()
        >>> manager.set_theme("classic_green")
        >>> theme = manager.get_current_theme()
    """

    _instance: ClassVar[Optional[ThemeManager]] = None
    _lock: ClassVar[threading.RLock] = threading.RLock()

    def __new__(cls) -> ThemeManager:
        """Создание singleton экземпляра.

        Returns:
            ThemeManager экземпляр.
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Инициализация менеджера тем.

        Вызывается один раз при первом создании singleton.
        Регистрирует встроенные темы.
        """
        if getattr(self, "_initialized", False):
            return

        with self._lock:
            if getattr(self, "_initialized", False):
                return

            self._themes: dict[str, Theme] = {}
            self._current_name: str = ""
            self._operation_lock: threading.RLock = threading.RLock()
            self._register_builtin_themes()
            self._initialized = True

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

            mapping: dict[str, Optional[Theme]] = {
                "classic_green": classic_green.THEME,
                "retro_green": retro_green.THEME,
                "amber": amber.THEME,
                "phosphor_white": phosphor_white.THEME,
                "high_contrast": high_contrast.THEME,
            }
            for name, theme in mapping.items():
                if theme is not None:
                    self._themes[name] = theme
        except ImportError:
            pass

    def reset(self) -> None:
        """Сброс singleton состояния.

        Очищает реестр тем и сбрасывает флаг инициализации.
        """
        with self._lock:
            self._themes.clear()
            self._current_name = ""
            self._initialized = False
            ThemeManager._instance = None

    def set_theme(self, name: str) -> None:
        """Устанавливает текущую тему.

        Args:
            name: Имя темы для установки.

        Raises:
            ThemeNotFoundError: Если тема не найдена.
        """
        with self._operation_lock:
            if name not in self._themes:
                raise ThemeNotFoundError(name)
            self._current_name = name

    def get_theme(self, name: str) -> Theme:
        """Возвращает тему по имени.

        Args:
            name: Имя темы.

        Returns:
            Экземпляр Theme.

        Raises:
            ThemeNotFoundError: Если тема не найдена.
        """
        with self._operation_lock:
            if name not in self._themes:
                raise ThemeNotFoundError(name)
            return self._themes[name]

    def get_current_theme(self) -> Theme:
        """Возвращает текущую активную тему.

        Returns:
            Активная Theme.

        Raises:
            ThemeNotFoundError: Если тема не установлена и реестр пуст.
        """
        with self._operation_lock:
            if not self._current_name:
                if self._themes:
                    first_name = next(iter(self._themes))
                    self._current_name = first_name
                    return self._themes[first_name]
                raise ThemeNotFoundError("")
            return self._themes[self._current_name]

    def get_current_theme_name(self) -> str:
        """Возвращает имя текущей активной темы.

        Returns:
            Имя текущей темы.
        """
        with self._operation_lock:
            if not self._current_name and self._themes:
                first_name = next(iter(self._themes))
                self._current_name = first_name
            return self._current_name

    def list_themes(self) -> list[str]:
        """Возвращает список имён зарегистрированных тем.

        Returns:
            Отсортированный список имён тем.
        """
        with self._operation_lock:
            return sorted(self._themes.keys())

    def register_theme(self, name: str, theme: Theme) -> None:
        """Регистрирует новую тему.

        Args:
            name: Уникальное имя темы.
            theme: Экземпляр Theme для регистрации.

        Raises:
            ThemeError: Если тема с таким именем уже зарегистрирована.
        """
        with self._operation_lock:
            if name in self._themes:
                raise ThemeError(name, f"Theme '{name}' уже зарегистрирована")
            self._themes[name] = theme

    def unregister_theme(self, name: str) -> None:
        """Удаляет тему из реестра.

        Args:
            name: Имя темы для удаления.

        Raises:
            ThemeNotFoundError: Если тема не найдена.
            ThemeError: Если пытаются удалить текущую активную тему.
        """
        with self._operation_lock:
            if name not in self._themes:
                raise ThemeNotFoundError(name)
            if name == self._current_name:
                raise ThemeError(name, "Нельзя удалить текущую тему")
            del self._themes[name]

    def apply_to_widget(self, widget: Any, style: str = "") -> None:
        """Применяет текущую тему к виджету.

        Args:
            widget: Tkinter виджет для стилизации.
            style: Тип стиля (например, "button", "entry", "label").

        Raises:
            TypeError: Если widget не является tk.Widget.
        """
        if not isinstance(widget, tk.BaseWidget):
            raise TypeError("widget должен быть tk.BaseWidget")

        theme = self.get_current_theme()

        if hasattr(widget, "configure"):
            try:
                widget.configure(bg=theme.bg_color)  # type: ignore[call-arg]
            except tk.TclError:
                pass

            try:
                widget.configure(fg=theme.fg_color)  # type: ignore[call-arg]
            except tk.TclError:
                pass

            try:
                widget.configure(
                    font=(theme.font_family, theme.font_size),
                )  # type: ignore[call-arg]
            except tk.TclError:
                pass

            if style in ("button", "tk.Button"):
                try:
                    widget.configure(
                        activebackground=theme.accent_color,
                        activeforeground=theme.bg_color,
                    )  # type: ignore[call-arg]
                except tk.TclError:
                    pass
            elif style in ("entry", "tk.Entry", "text", "tk.Text"):
                try:
                    widget.configure(
                        insertbackground=theme.fg_color,
                        selectbackground=theme.accent_color,
                        selectforeground=theme.bg_color,
                    )  # type: ignore[call-arg]
                except tk.TclError:
                    pass

    def get_variant(self, variant: ThemeVariant) -> Theme:
        """Возвращает вариант текущей темы (светлый / тёмный).

        Args:
            variant: Вариант темы.

        Returns:
            Новый экземпляр Theme с адаптированными цветами.
        """
        theme = self.get_current_theme()
        if variant == ThemeVariant.DARK:
            return dataclasses.replace(
                theme,
                bg_color=self._darken(theme.bg_color),
                fg_color=self._lighten(theme.fg_color),
            )
        return dataclasses.replace(
            theme,
            bg_color=self._lighten(theme.bg_color),
            fg_color=self._darken(theme.fg_color),
        )

    @staticmethod
    def _darken(hex_color: str) -> str:
        """Затемняет hex-цвет на фиксированное значение.

        Args:
            hex_color: Исходный цвет (#RRGGBB).

        Returns:
            Затемнённый цвет (#RRGGBB).
        """
        r = max(int(hex_color[1:3], 16) - 40, 0)
        g = max(int(hex_color[3:5], 16) - 40, 0)
        b = max(int(hex_color[5:7], 16) - 40, 0)
        return f"#{r:02X}{g:02X}{b:02X}"

    @staticmethod
    def _lighten(hex_color: str) -> str:
        """Осветляет hex-цвет на фиксированное значение.

        Args:
            hex_color: Исходный цвет (#RRGGBB).

        Returns:
            Осветлённый цвет (#RRGGBB).
        """
        r = min(int(hex_color[1:3], 16) + 40, 255)
        g = min(int(hex_color[3:5], 16) + 40, 255)
        b = min(int(hex_color[5:7], 16) + 40, 255)
        return f"#{r:02X}{g:02X}{b:02X}"


# =============================================================================
# FACTORY FUNCTION
# =============================================================================


def get_theme_manager() -> ThemeManager:
    """Возвращает singleton экземпляр ThemeManager.

    Returns:
        ThemeManager singleton.

    Example:
        >>> manager = get_theme_manager()
        >>> manager.set_theme("classic_green")
    """
    return ThemeManager()


# =============================================================================
# RE-EXPORTS FROM IMPLEMENTATIONS
# =============================================================================

from src.gui.themes.implementations import (  # noqa: E402
    amber,
    classic_green,
    high_contrast,
    phosphor_white,
    retro_green,
)

__all__ = [
    "Theme",
    "ThemeManager",
    "get_theme_manager",
    "ThemeProtocol",
    "ThemeRegistry",
    "ThemeAdapter",
    "get_registry",
    "ThemeRegistryError",
    "ThemeError",
    "ThemeNotFoundError",
    "ThemeApplicationError",
    "ThemeVariant",
    "amber",
    "classic_green",
    "high_contrast",
    "phosphor_white",
    "retro_green",
]
