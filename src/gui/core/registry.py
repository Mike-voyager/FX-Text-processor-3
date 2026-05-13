"""Централизованный реестр GUI виджетов.

Thread-safe Singleton реестр всех виджетов FX Text Processor 3 GUI.
Обеспечивает:
- Регистрацию виджетов с валидацией WidgetProtocol
- Фабричные методы для создания экземпляров
- Thread-safe доступ (RLock)
- Query API для поиска виджетов
- Статистику по реестру

Example:
    >>> from src.gui.core.registry import WidgetRegistry
    >>> registry = WidgetRegistry.get_instance()
    >>> button = registry.create("button_primary", widget_id="btn_01")
    >>> isinstance(button, WidgetProtocol)
    True

Thread Safety:
    Все публичные методы thread-safe благодаря RLock.
    Можно безопасно вызывать из разных потоков.

Version: 1.0
Date: April 6, 2026
Priority: 🔴 CRITICAL (Phase 1)
"""

from __future__ import annotations

__author__ = "FX Text Processor Team"
__date__ = "April 2026"
__version__ = "1.0"

import logging
import threading
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from src.gui.core.exceptions import (
    ProtocolValidationError,
    WidgetCreationError,
    WidgetNotFoundError,
    WidgetRegistryError,
)
from src.gui.core.protocols import WidgetProtocol

logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMS
# ==============================================================================


class WidgetCategory(str, Enum):
    """Категория виджета GUI.

    Используется для группировки виджетов по функциональному назначению.
    Наследует str для корректной JSON сериализации.

    Categories:
        - CONTAINER: Контейнеры для размещения других виджетов (Frame, Panel)
        - INPUT: Поля ввода данных (Entry, Text, ComboBox)
        - DISPLAY: Виджеты отображения (Label, StatusBar, Canvas)
        - DIALOG: Диалоговые окна (Modal, Popup)
        - MENU: Элементы меню (Menu, MenuItem, Toolbar)
        - TOOLBAR: Панели инструментов (Toolbar, ToolbarSection)
        - CUSTOM: Пользовательские виджеты специфичные для приложения

    Example:
        >>> category = WidgetCategory.CONTAINER
        >>> category.value
        'container'
        >>> category.label()
        'Контейнер'
    """

    CONTAINER = "container"
    INPUT = "input"
    DISPLAY = "display"
    DIALOG = "dialog"
    MENU = "menu"
    TOOLBAR = "toolbar"
    CUSTOM = "custom"

    def label(self) -> str:
        """Человекочитаемое название категории на русском.

        Returns:
            Локализованное название

        Example:
            >>> WidgetCategory.CONTAINER.label()
            'Контейнер'
        """
        labels = {
            WidgetCategory.CONTAINER: "Контейнер",
            WidgetCategory.INPUT: "Ввод данных",
            WidgetCategory.DISPLAY: "Отображение",
            WidgetCategory.DIALOG: "Диалог",
            WidgetCategory.MENU: "Меню",
            WidgetCategory.TOOLBAR: "Панель инструментов",
            WidgetCategory.CUSTOM: "Пользовательский",
        }
        return labels[self]

    @classmethod
    def from_str(cls, value: str) -> WidgetCategory:
        """Парсинг из строки (case-insensitive).

        Args:
            value: Строковое представление ("container" или "CONTAINER")

        Returns:
            Соответствующий WidgetCategory

        Raises:
            ValueError: Некорректное значение

        Example:
            >>> WidgetCategory.from_str("container")
            <WidgetCategory.CONTAINER: 'container'>
        """
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(
                f"Неизвестная категория виджета: {value}. "
                f"Допустимые значения: {[c.value for c in cls]}"
            ) from None


class WidgetComplexity(str, Enum):
    """Уровень сложности виджета.

    Определяет архитектурную сложность и уровень композиции виджета.

    Levels:
        - PRIMITIVE: Базовые элементы (Button, Label, Entry)
        - COMPOUND: Составные виджеты (FormField, ToolbarSection)
        - COMPOSITE: Комплексные виджеты (DocumentView, FormDesigner)

    Example:
        >>> complexity = WidgetComplexity.COMPOUND
        >>> complexity.value
        'compound'
        >>> complexity.label()
        'Составной'
    """

    PRIMITIVE = "primitive"
    COMPOUND = "compound"
    COMPOSITE = "composite"

    def label(self) -> str:
        """Человекочитаемое название уровня сложности на русском.

        Returns:
            Локализованное название
        """
        labels = {
            WidgetComplexity.PRIMITIVE: "Примитив",
            WidgetComplexity.COMPOUND: "Составной",
            WidgetComplexity.COMPOSITE: "Комплексный",
        }
        return labels[self]

    @classmethod
    def from_str(cls, value: str) -> WidgetComplexity:
        """Парсинг из строки (case-insensitive).

        Args:
            value: Строковое представление ("primitive" или "PRIMITIVE")

        Returns:
            Соответствующий WidgetComplexity

        Raises:
            ValueError: Некорректное значение
        """
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(
                f"Неизвестный уровень сложности: {value}. "
                f"Допустимые значения: {[c.value for c in cls]}"
            ) from None


# ==============================================================================
# DATACLASSES
# ==============================================================================


@dataclass(frozen=True)
class WidgetMetadata:
    """Метаданные GUI виджета.

    Immutable dataclass содержащий все характеристики виджета:
    - Категоризация (category, complexity)
    - Информация о версии и авторе
    - Описание и назначение
    - Требования безопасности (requires_mfa)
    - Поддерживаемые события

    Attributes:
        category: Категория виджета (CONTAINER, INPUT, DISPLAY, и т.д.)
        complexity: Уровень сложности (PRIMITIVE, COMPOUND, COMPOSITE)
        version: Версия виджета (например, "1.0.0")
        author: Автор виджета (имя разработчика или команда)
        description: Описание назначения виджета
        supported_events: Множество поддерживаемых типов событий
        requires_mfa: Требуется ли MFA для использования виджета
        extra: Дополнительные параметры (гибкое поле)

    Example:
        >>> metadata = WidgetMetadata(
        ...     category=WidgetCategory.INPUT,
        ...     complexity=WidgetComplexity.PRIMITIVE,
        ...     version="1.0.0",
        ...     author="FX Team",
        ...     description="Базовое поле ввода текста",
        ...     supported_events={"focus", "change", "blur"},
        ...     requires_mfa=False,
        ... )
        >>> metadata.category
        <WidgetCategory.INPUT: 'input'>
        >>> metadata.requires_mfa
        False
    """

    category: WidgetCategory
    complexity: WidgetComplexity
    version: str
    author: str
    description: str
    supported_events: Set[str] = field(default_factory=set)
    requires_mfa: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Валидация метаданных после инициализации.

        Raises:
            ValueError: Некорректные значения полей
            TypeError: Неверные типы
        """
        # Валидация version
        if not self.version or not self.version.strip():
            raise ValueError("version не может быть пустым")

        # Валидация author
        if not self.author or not self.author.strip():
            raise ValueError("author не может быть пустым")

        # Валидация description
        if not self.description or not self.description.strip():
            raise ValueError("description не может быть пустым")

        # Валидация supported_events
        if not isinstance(self.supported_events, set):
            raise TypeError(
                f"supported_events должен быть Set[str], получено "
                f"{type(self.supported_events).__name__}"
            )

        # Валидация типов событий
        for event in self.supported_events:
            if not isinstance(event, str):
                raise TypeError(
                    f"Все события должны быть строками, получено {type(event).__name__}"
                )
            if not event.strip():
                raise ValueError("Имя события не может быть пустой строкой")

    def __hash__(self) -> int:
        """Хеш по ключевым полям виджета."""
        return hash((self.category, self.complexity, self.version, self.author))

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь (для JSON/YAML).

        Returns:
            Словарь с примитивными типами

        Example:
            >>> metadata.to_dict()
            {'category': 'input', 'complexity': 'primitive', ...}
        """
        return {
            "category": self.category.value,
            "complexity": self.complexity.value,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "supported_events": list(self.supported_events),
            "requires_mfa": self.requires_mfa,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WidgetMetadata:
        """Десериализация из словаря.

        Args:
            data: Словарь с метаданными (из to_dict())

        Returns:
            WidgetMetadata instance

        Raises:
            ValueError: Некорректные данные
        """
        # Копировать data, чтобы не изменять оригинал
        data = data.copy()

        # Преобразовать строки обратно в Enum
        data["category"] = WidgetCategory.from_str(data["category"])
        data["complexity"] = WidgetComplexity.from_str(data["complexity"])

        # Преобразовать список событий в множество
        data["supported_events"] = set(data.get("supported_events", []))

        return cls(**data)


@dataclass(frozen=True)
class WidgetRegistryEntry:
    """Запись в реестре GUI виджетов.

    Attributes:
        widget_type: Уникальный тип виджета (например, "button_primary")
        factory: Фабричная функция для создания экземпляра
        metadata: Метаданные виджета

    Example:
        >>> entry = WidgetRegistryEntry(
        ...     widget_type="button_primary",
        ...     factory=PrimaryButton,
        ...     metadata=PrimaryButton.metadata,
        ... )
    """

    widget_type: str
    factory: Callable[..., Any]
    metadata: WidgetMetadata


@dataclass(frozen=True)
class WidgetRegistryStatistics:
    """Статистика зарегистрированных виджетов.

    Attributes:
        total: Общее количество виджетов
        by_category: Количество по категориям
        by_complexity: Количество по уровням сложности
        requires_mfa_count: Количество виджетов требующих MFA

    Example:
        >>> stats = registry.get_statistics()
        >>> print(f"Total: {stats.total}")
        Total: 42
        >>> print(f"Input widgets: {stats.by_category[WidgetCategory.INPUT]}")
        Input widgets: 8
    """

    total: int
    by_category: Dict[WidgetCategory, int]
    by_complexity: Dict[WidgetComplexity, int]
    requires_mfa_count: int

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь.

        Returns:
            Словарь со статистикой

        Example:
            >>> stats.to_dict()
            {'total': 42, 'by_category': {...}, ...}
        """
        return {
            "total": self.total,
            "by_category": {cat.value: count for cat, count in self.by_category.items()},
            "by_complexity": {comp.value: count for comp, count in self.by_complexity.items()},
            "requires_mfa_count": self.requires_mfa_count,
        }


# ==============================================================================
# MAIN CLASS: WIDGET REGISTRY
# ==============================================================================


class WidgetRegistry:
    """Thread-safe реестр GUI виджетов.

    Singleton класс для централизованного управления всеми виджетами GUI.
    Обеспечивает:
    - Регистрацию виджетов с валидацией WidgetProtocol
    - Фабричные методы для создания экземпляров
    - Thread-safe доступ
    - Query API для поиска виджетов

    Attributes:
        _instance: Singleton instance
        _lock: RLock для thread-safety
        _registry: Словарь {widget_type -> WidgetRegistryEntry}
        _initialized: Флаг инициализации

    Example:
        >>> registry = WidgetRegistry.get_instance()
        >>> registry.register(
        ...     widget_type="button_primary",
        ...     factory=PrimaryButton,
        ...     metadata=PrimaryButton.metadata,
        ... )
        >>> button = registry.create("button_primary", widget_id="btn_01")
        >>> isinstance(button, WidgetProtocol)
        True

    Thread Safety:
        Все публичные методы thread-safe благодаря RLock.
        Можно безопасно вызывать из разных потоков.
    """

    # Singleton instance (class-level)
    _instance: Optional[WidgetRegistry] = None
    _lock: threading.RLock = threading.RLock()

    def __init__(self) -> None:
        """Приватный конструктор (используйте get_instance()).

        Raises:
            RuntimeError: Если попытка создать второй экземпляр
        """
        if WidgetRegistry._instance is not None:
            raise RuntimeError("WidgetRegistry is a singleton. Use WidgetRegistry.get_instance()")

        # Реестр: {widget_type -> WidgetRegistryEntry}
        self._registry: Dict[str, WidgetRegistryEntry] = {}

        # Флаг инициализации
        self._initialized: bool = False

        logger.info("WidgetRegistry initialized")

    @classmethod
    def get_instance(cls) -> WidgetRegistry:
        """Получить singleton instance реестра.

        Returns:
            Единственный экземпляр WidgetRegistry

        Thread Safety:
            Thread-safe double-checked locking

        Example:
            >>> registry = WidgetRegistry.get_instance()
            >>> registry2 = WidgetRegistry.get_instance()
            >>> registry is registry2
            True
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Сбросить singleton (только для тестов).

        WARNING:
            Используйте только в unit-тестах!
            В production коде вызов этого метода может
            нарушить работу системы.
        """
        with cls._lock:
            cls._instance = None
            logger.warning("WidgetRegistry instance reset (testing only!)")

    def register(
        self,
        widget_type: str,
        factory: Callable[..., Any],
        metadata: WidgetMetadata,
        *,
        validate: bool = True,
    ) -> None:
        """Зарегистрировать виджет в реестре.

        Args:
            widget_type: Уникальный тип виджета (например, "button_primary")
            factory: Фабричная функция для создания экземпляра
            metadata: Метаданные виджета
            validate: Валидировать соответствие WidgetProtocol (по умолчанию True)

        Raises:
            WidgetRegistryError: Если виджет уже зарегистрирован или тип пустой
            TypeError: Если factory не callable или метаданные некорректны
            ProtocolValidationError: Если экземпляр не соответствует WidgetProtocol (validate=True)

        Example:
            >>> from src.gui.components.primitive.button import PrimaryButton
            >>> registry.register(
            ...     widget_type="button_primary",
            ...     factory=PrimaryButton,
            ...     metadata=PrimaryButton.metadata,
            ... )

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            # Валидация widget_type
            if not widget_type or not widget_type.strip():
                raise WidgetRegistryError("Тип виджета не может быть пустым")

            widget_type = widget_type.strip()

            # Проверка дубликатов
            if widget_type in self._registry:
                raise WidgetRegistryError(
                    f"Виджет '{widget_type}' уже зарегистрирован. "
                    f"Используйте unregister() для удаления старой регистрации."
                )

            # Валидация factory
            if not callable(factory):
                raise TypeError(f"factory должна быть callable, получено {type(factory).__name__}")

            # Валидация metadata
            if not isinstance(metadata, WidgetMetadata):
                raise TypeError(
                    f"metadata должна быть WidgetMetadata, получено {type(metadata).__name__}"
                )

            # Валидация соответствия Protocol
            if validate:
                self._validate_protocol(widget_type, factory)

            # Регистрация
            entry = WidgetRegistryEntry(
                widget_type=widget_type,
                factory=factory,
                metadata=metadata,
            )
            self._registry[widget_type] = entry

            logger.info(
                f"Registered widget: {widget_type} "
                f"(category={metadata.category.value}, "
                f"complexity={metadata.complexity.value})"
            )

    def _validate_protocol(
        self,
        widget_type: str,
        factory: Callable[..., Any],
    ) -> None:
        """Валидация соответствия экземпляра WidgetProtocol.

        Args:
            widget_type: Тип виджета для логирования
            factory: Фабрика для создания тестового экземпляра

        Raises:
            ProtocolValidationError: Если экземпляр не соответствует WidgetProtocol
        """
        try:
            # Создать тестовый экземпляр с widget_id
            instance = factory(widget_id=f"_test_{widget_type}")

            # Проверка isinstance с @runtime_checkable Protocol
            if not isinstance(instance, WidgetProtocol):
                raise ProtocolValidationError(
                    protocol_name="WidgetProtocol",
                    implementation=type(instance).__name__,
                    message=f"Экземпляр {type(instance).__name__} не реализует WidgetProtocol",
                )

            logger.debug(f"Protocol validation passed: {widget_type} -> WidgetProtocol")

        except ProtocolValidationError:
            raise
        except (TypeError, ValueError, RuntimeError) as e:
            logger.error(f"Failed to validate protocol for {widget_type}: {e}", exc_info=True)
            raise ProtocolValidationError(
                protocol_name="WidgetProtocol",
                implementation=factory.__name__ if hasattr(factory, "__name__") else str(factory),
                message=f"Не удалось валидировать WidgetProtocol для {widget_type}: {e}",
            ) from e

    def create(self, widget_type: str, **kwargs: Any) -> Any:
        """Создать экземпляр виджета по типу.

        Args:
            widget_type: Тип виджета (например, "button_primary")
            **kwargs: Аргументы для передачи в фабрику

        Returns:
            Новый экземпляр виджета

        Raises:
            WidgetNotFoundError: Если виджет не найден в реестре
            WidgetCreationError: Если не удалось создать экземпляр

        Example:
            >>> button = registry.create("button_primary", widget_id="btn_01")
            >>> isinstance(button, WidgetProtocol)
            True

        Thread Safety:
            Thread-safe с RLock
        """
        with self._lock:
            if widget_type not in self._registry:
                available = ", ".join(sorted(self._registry.keys())[:5])
                raise WidgetNotFoundError(
                    widget_type=widget_type,
                    message=f"Виджет '{widget_type}' не найден в реестре. "
                    f"Доступные (первые 5): {available}...",
                )

            entry = self._registry[widget_type]

            try:
                instance = entry.factory(**kwargs)
                logger.debug(f"Created instance of {widget_type}")
                return instance

            except (TypeError, ValueError, RuntimeError) as e:
                factory_name = (
                    entry.factory.__name__
                    if hasattr(entry.factory, "__name__")
                    else str(entry.factory)
                )
                logger.error(f"Failed to create instance of {widget_type}: {e}", exc_info=True)
                raise WidgetCreationError(
                    widget_type=widget_type,
                    factory_name=factory_name,
                    message=f"Не удалось создать экземпляр {widget_type}: {e}",
                    cause=e,
                ) from e

    def get_metadata(self, widget_type: str) -> WidgetMetadata:
        """Получить метаданные виджета.

        Args:
            widget_type: Тип виджета

        Returns:
            Метаданные виджета

        Raises:
            WidgetNotFoundError: Если виджет не найден

        Example:
            >>> meta = registry.get_metadata("button_primary")
            >>> meta.category
            <WidgetCategory.INPUT: 'input'>
        """
        with self._lock:
            if widget_type not in self._registry:
                raise WidgetNotFoundError(
                    widget_type=widget_type,
                    message=f"Виджет '{widget_type}' не найден в реестре",
                )
            return self._registry[widget_type].metadata

    def list_widgets(self) -> List[WidgetMetadata]:
        """Получить список метаданных всех зарегистрированных виджетов.

        Returns:
            Список WidgetMetadata (sorted by widget_type)

        Example:
            >>> metas = registry.list_widgets()
            >>> {m.category for m in metas}
            {<WidgetCategory.INPUT: 'input'>, ...}
        """
        with self._lock:
            return sorted(
                (entry.metadata for entry in self._registry.values()),
                key=lambda m: (m.category.value, m.complexity.value),
            )

    def list_by_category(self, category: WidgetCategory) -> List[str]:
        """Получить список виджетов по категории.

        Args:
            category: Категория виджетов

        Returns:
            Список типов виджетов в категории (sorted)

        Example:
            >>> registry.list_by_category(WidgetCategory.INPUT)
            ['entry_text', 'entry_number', 'combo_box', ...]
        """
        with self._lock:
            return sorted(
                [
                    widget_type
                    for widget_type, entry in self._registry.items()
                    if entry.metadata.category == category
                ]
            )

    def list_by_complexity(self, complexity: WidgetComplexity) -> List[str]:
        """Получить список виджетов по уровню сложности.

        Args:
            complexity: Уровень сложности

        Returns:
            Список типов виджетов (sorted)

        Example:
            >>> registry.list_by_complexity(WidgetComplexity.PRIMITIVE)
            ['button_primary', 'label', 'entry', ...]
        """
        with self._lock:
            return sorted(
                [
                    widget_type
                    for widget_type, entry in self._registry.items()
                    if entry.metadata.complexity == complexity
                ]
            )

    def list_requires_mfa(self) -> List[str]:
        """Получить список виджетов требующих MFA.

        Returns:
            Список типов виджетов требующих MFA (sorted)

        Example:
            >>> registry.list_requires_mfa()
            ['crypto_profile_selector', 'key_export_dialog', ...]
        """
        with self._lock:
            return sorted(
                [
                    widget_type
                    for widget_type, entry in self._registry.items()
                    if entry.metadata.requires_mfa
                ]
            )

    def search(
        self,
        *,
        category: Optional[WidgetCategory] = None,
        complexity: Optional[WidgetComplexity] = None,
        requires_mfa: Optional[bool] = None,
    ) -> List[str]:
        """Поиск виджетов по множественным критериям.

        Args:
            category: Фильтр по категории
            complexity: Фильтр по уровню сложности
            requires_mfa: Фильтр по требованию MFA

        Returns:
            Список типов виджетов, соответствующих всем фильтрам

        Example:
            >>> # Все примитивные виджеты ввода
            >>> registry.search(
            ...     category=WidgetCategory.INPUT,
            ...     complexity=WidgetComplexity.PRIMITIVE,
            ... )
            ['entry_text', 'entry_number', ...]

            >>> # Все виджеты требующие MFA
            >>> registry.search(requires_mfa=True)
            ['crypto_profile_selector', ...]
        """
        with self._lock:
            results: List[str] = []

            for widget_type, entry in self._registry.items():
                meta = entry.metadata

                # Проверка всех фильтров (AND логика)
                if category is not None and meta.category != category:
                    continue

                if complexity is not None and meta.complexity != complexity:
                    continue

                if requires_mfa is not None and meta.requires_mfa != requires_mfa:
                    continue

                results.append(widget_type)

            return sorted(results)

    def get_statistics(self) -> WidgetRegistryStatistics:
        """Получить статистику по зарегистрированным виджетам.

        Returns:
            WidgetRegistryStatistics с подсчётами

        Example:
            >>> stats = registry.get_statistics()
            >>> stats.total
            42
            >>> stats.by_category[WidgetCategory.INPUT]
            8
            >>> stats.requires_mfa_count
            3
        """
        with self._lock:
            return self._calculate_statistics()

    def _calculate_statistics(self) -> WidgetRegistryStatistics:
        """Внутренний метод для подсчёта статистики."""
        total = len(self._registry)

        categories = Counter(entry.metadata.category for entry in self._registry.values())

        complexities = Counter(entry.metadata.complexity for entry in self._registry.values())

        requires_mfa_count = sum(
            1 for entry in self._registry.values() if entry.metadata.requires_mfa
        )

        return WidgetRegistryStatistics(
            total=total,
            by_category=dict(categories),
            by_complexity=dict(complexities),
            requires_mfa_count=requires_mfa_count,
        )

    def is_registered(self, widget_type: str) -> bool:
        """Проверка, зарегистрирован ли виджет.

        Args:
            widget_type: Тип виджета

        Returns:
            True если зарегистрирован, False иначе

        Example:
            >>> registry.is_registered("button_primary")
            True
            >>> registry.is_registered("unknown_widget")
            False
        """
        with self._lock:
            return widget_type in self._registry

    def unregister(self, widget_type: str) -> None:
        """Удалить виджет из реестра.

        WARNING:
            Используйте с осторожностью! Удаление виджета
            может нарушить работу зависимого кода.

        Args:
            widget_type: Тип виджета

        Raises:
            WidgetNotFoundError: Если виджет не найден
        """
        with self._lock:
            if widget_type not in self._registry:
                raise WidgetNotFoundError(
                    widget_type=widget_type,
                    message=f"Виджет '{widget_type}' не найден в реестре",
                )

            del self._registry[widget_type]
            logger.warning(f"Unregistered widget: {widget_type}")


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__ = [
    # Enums
    "WidgetCategory",
    "WidgetComplexity",
    # Dataclasses
    "WidgetMetadata",
    "WidgetRegistryEntry",
    "WidgetRegistryStatistics",
    # Main class
    "WidgetRegistry",
]
