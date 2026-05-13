"""Сервис горячих клавиш.

Управляет привязками клавиатурных сочетаний к действиям.
Поддерживает контекстные привязки, конфликты, импорт/экспорт.

Module: src/services/key_bindings_service.py
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Типы и константы
# ---------------------------------------------------------------------------


class KeyModifier(Enum):
    """Модификаторы клавиш."""

    CTRL = "Ctrl"
    ALT = "Alt"
    SHIFT = "Shift"
    META = "Meta"  # Command на macOS


class KeyContext(Enum):
    """Контекст действия."""

    GLOBAL = "global"  # Глобальный
    EDITOR = "editor"  # Редактор
    DIALOG = "dialog"  # Диалог
    MENU = "menu"  # Меню


@dataclass(frozen=True)
class KeyBinding:
    """Привязка клавиш.

    Attrs:
        key: Клавиша (a-z, F1-F12, etc.)
        modifiers: Модификаторы (Ctrl, Alt, Shift)
        context: Контекст действия
    """

    key: str
    modifiers: Tuple[KeyModifier, ...] = field(default_factory=tuple)
    context: KeyContext = KeyContext.GLOBAL

    def __str__(self) -> str:
        """Возвращает строковое представление."""
        parts = [m.value for m in self.modifiers] + [self.key]
        return "+".join(parts)

    def matches(self, key: str, modifiers: Tuple[KeyModifier, ...]) -> bool:
        """Проверяет совпадение с нажатыми клавишами.

        Args:
            key: Нажатая клавиша
            modifiers: Нажатые модификаторы

        Returns:
            True если совпадает
        """
        return self.key.lower() == key.lower() and set(self.modifiers) == set(modifiers)


@dataclass(frozen=True)
class Action:
    """Действие.

    Attrs:
        id: Идентификатор действия
        name: Имя для отображения
        description: Описание
        category: Категория (File, Edit, etc.)
        default_binding: Привязка по умолчанию (optional)
        is_repeatable: Можно ли повторять
        is_enabled: Активно ли действие
    """

    id: str
    name: str
    description: str = ""
    category: str = "General"
    default_binding: Optional[KeyBinding] = None
    is_repeatable: bool = False
    is_enabled: bool = True


@dataclass(frozen=True)
class BindingConflict:
    """Конфликт привязок.

    Attrs:
        action_id: ID действия
        binding: Привязка
        conflicts_with: Список конфликтующих действий
    """

    action_id: str
    binding: KeyBinding
    conflicts_with: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# KeyBindingsService
# ---------------------------------------------------------------------------


class KeyBindingsService:
    """Сервис управления горячими клавишами.

    Предоставляет:
    - Регистрация действий с привязками
    - Проверка конфликтов
    - Поиск действия по клавишам
    - Импорт/экспорт конфигурации
    - Сброс к настройкам по умолчанию

    Пример:
        >>> service = KeyBindingsService()
        >>> service.register_action(Action(id="save", name="Save", default_binding=KeyBinding("s", (KeyModifier.CTRL,))))
        >>> action = service.find_action("s", (KeyModifier.CTRL,))
        >>> print(action.name)  # "Save"
    """

    def __init__(self) -> None:
        """Инициализирует сервис."""
        # Зарегистрированные действия
        self._actions: Dict[str, Action] = {}

        # Привязки: KeyBinding -> action_id
        self._bindings: Dict[str, str] = {}  # str(KeyBinding) -> action_id

        # Обработчики: action_id -> callback
        self._handlers: Dict[str, Callable[[], None]] = {}

        # История выполненных действий
        self._history: List[str] = []
        self._max_history = 100

        # Инициализируем стандартные действия
        self._init_default_actions()

    def _init_default_actions(self) -> None:
        """Инициализирует стандартные действия."""
        # File
        self.register_action(
            Action(
                id="file.new",
                name="New Document",
                description="Create a new document",
                category="File",
                default_binding=KeyBinding("n", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="file.open",
                name="Open Document",
                description="Open an existing document",
                category="File",
                default_binding=KeyBinding("o", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="file.save",
                name="Save",
                description="Save the current document",
                category="File",
                default_binding=KeyBinding("s", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="file.save_as",
                name="Save As",
                description="Save with a new name",
                category="File",
                default_binding=KeyBinding("s", (KeyModifier.CTRL, KeyModifier.SHIFT)),
            )
        )
        self.register_action(
            Action(
                id="file.print",
                name="Print",
                description="Print the document",
                category="File",
                default_binding=KeyBinding("p", (KeyModifier.CTRL,)),
            )
        )

        # Edit
        self.register_action(
            Action(
                id="edit.undo",
                name="Undo",
                description="Undo the last action",
                category="Edit",
                default_binding=KeyBinding("z", (KeyModifier.CTRL,)),
                is_repeatable=True,
            )
        )
        self.register_action(
            Action(
                id="edit.redo",
                name="Redo",
                description="Redo the last undone action",
                category="Edit",
                default_binding=KeyBinding("z", (KeyModifier.CTRL, KeyModifier.SHIFT)),
                is_repeatable=True,
            )
        )
        self.register_action(
            Action(
                id="edit.cut",
                name="Cut",
                description="Cut selection to clipboard",
                category="Edit",
                default_binding=KeyBinding("x", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="edit.copy",
                name="Copy",
                description="Copy selection to clipboard",
                category="Edit",
                default_binding=KeyBinding("c", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="edit.paste",
                name="Paste",
                description="Paste from clipboard",
                category="Edit",
                default_binding=KeyBinding("v", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="edit.find",
                name="Find",
                description="Find text in document",
                category="Edit",
                default_binding=KeyBinding("f", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="edit.replace",
                name="Find and Replace",
                description="Find and replace text",
                category="Edit",
                default_binding=KeyBinding("h", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="edit.select_all",
                name="Select All",
                description="Select all content",
                category="Edit",
                default_binding=KeyBinding("a", (KeyModifier.CTRL,)),
            )
        )

        # Navigation
        self.register_action(
            Action(
                id="nav.home",
                name="Go to Start",
                description="Move to start of line/document",
                category="Navigation",
                default_binding=KeyBinding("Home", ()),
            )
        )
        self.register_action(
            Action(
                id="nav.end",
                name="Go to End",
                description="Move to end of line/document",
                category="Navigation",
                default_binding=KeyBinding("End", ()),
            )
        )
        self.register_action(
            Action(
                id="nav.page_up",
                name="Page Up",
                description="Move one page up",
                category="Navigation",
                default_binding=KeyBinding("Page_Up", ()),
            )
        )
        self.register_action(
            Action(
                id="nav.page_down",
                name="Page Down",
                description="Move one page down",
                category="Navigation",
                default_binding=KeyBinding("Page_Down", ()),
            )
        )

        # View
        self.register_action(
            Action(
                id="view.zoom_in",
                name="Zoom In",
                description="Increase zoom level",
                category="View",
                default_binding=KeyBinding("plus", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="view.zoom_out",
                name="Zoom Out",
                description="Decrease zoom level",
                category="View",
                default_binding=KeyBinding("minus", (KeyModifier.CTRL,)),
            )
        )
        self.register_action(
            Action(
                id="view.zoom_reset",
                name="Reset Zoom",
                description="Reset to default zoom",
                category="View",
                default_binding=KeyBinding("0", (KeyModifier.CTRL,)),
            )
        )

    # ---------- Регистрация действий ----------

    def register_action(
        self,
        action: Action,
        handler: Optional[Callable[[], None]] = None,
    ) -> bool:
        """Регистрирует действие с привязкой.

        Args:
            action: Действие для регистрации
            handler: Обработчик (optional)

        Returns:
            True если успешно
        """
        if action.id in self._actions:
            logger.warning("Действие уже зарегистрировано: %s", action.id)
            return False

        self._actions[action.id] = action

        # Регистрируем привязку по умолчанию
        if action.default_binding:
            binding_key = str(action.default_binding)
            self._bindings[binding_key] = action.id

        # Регистрируем обработчик
        if handler:
            self._handlers[action.id] = handler

        logger.debug("Зарегистрировано действие: %s", action.id)
        return True

    def register_handler(self, action_id: str, handler: Callable[[], None]) -> bool:
        """Регистрирует обработчик для действия.

        Args:
            action_id: ID действия
            handler: Обработчик

        Returns:
            True если успешно
        """
        if action_id not in self._actions:
            logger.warning("Действие не найдено: %s", action_id)
            return False

        self._handlers[action_id] = handler
        return True

    def unregister_action(self, action_id: str) -> bool:
        """Удаляет действие.

        Args:
            action_id: ID действия

        Returns:
            True если успешно
        """
        if action_id not in self._actions:
            return False

        action = self._actions[action_id]

        # Удаляем привязку
        if action.default_binding:
            binding_key = str(action.default_binding)
            if binding_key in self._bindings:
                del self._bindings[binding_key]

        # Удаляем действие и обработчик
        del self._actions[action_id]
        if action_id in self._handlers:
            del self._handlers[action_id]

        logger.debug("Удалено действие: %s", action_id)
        return True

    # ---------- Привязки ----------

    def bind(
        self,
        action_id: str,
        key: str,
        modifiers: Tuple[KeyModifier, ...] = (),
        context: KeyContext = KeyContext.GLOBAL,
    ) -> Optional[BindingConflict]:
        """Привязывает клавиши к действию.

        Args:
            action_id: ID действия
            key: Клавиша
            modifiers: Модификаторы
            context: Контекст

        Returns:
            BindingConflict если есть конфликт, иначе None
        """
        if action_id not in self._actions:
            logger.warning("Действие не найдено: %s", action_id)
            return None

        binding = KeyBinding(key, modifiers, context)
        binding_key = str(binding)

        # Проверяем конфликты
        existing = self._bindings.get(binding_key)
        if existing and existing != action_id:
            conflict = BindingConflict(
                action_id=action_id,
                binding=binding,
                conflicts_with=[existing],
            )
            logger.warning(
                "Конфликт привязки: %s -> %s (уже привязано к %s)", binding_key, action_id, existing
            )
            return conflict

        # Удаляем старую привязку если есть
        for old_key, old_action in list(self._bindings.items()):
            if old_action == action_id:
                del self._bindings[old_key]

        # Устанавливаем новую привязку
        self._bindings[binding_key] = action_id
        logger.debug("Привязка: %s -> %s", binding_key, action_id)
        return None

    def unbind(self, action_id: str) -> bool:
        """Удаляет привязку действия.

        Args:
            action_id: ID действия

        Returns:
            True если привязка удалена
        """
        removed = False
        for binding_key, bound_action in list(self._bindings.items()):
            if bound_action == action_id:
                del self._bindings[binding_key]
                removed = True

        return removed

    # ---------- Поиск и выполнение ----------

    def find_action(self, key: str, modifiers: Tuple[KeyModifier, ...]) -> Optional[Action]:
        """Находит действие по клавишам.

        Args:
            key: Клавиша
            modifiers: Модификаторы

        Returns:
            Действие или None
        """
        # Создаём временную привязку для поиска
        temp_binding = KeyBinding(key, modifiers)
        binding_key = str(temp_binding)

        action_id = self._bindings.get(binding_key)
        if action_id and action_id in self._actions:
            return self._actions[action_id]

        return None

    def find_binding(self, action_id: str) -> Optional[KeyBinding]:
        """Находит привязку для действия.

        Args:
            action_id: ID действия

        Returns:
            Привязка или None
        """
        for binding_key, bound_action in self._bindings.items():
            if bound_action == action_id:
                # Парсим строку обратно в KeyBinding
                parts = binding_key.split("+")
                if len(parts) == 1:
                    return KeyBinding(parts[0])
                key = parts[-1]
                modifiers = tuple(KeyModifier(p) for p in parts[:-1])
                return KeyBinding(key, modifiers)

        return None

    def execute(self, action_id: str) -> bool:
        """Выполняет действие.

        Args:
            action_id: ID действия

        Returns:
            True если выполнено
        """
        action = self._actions.get(action_id)
        if not action:
            logger.warning("Действие не найдено: %s", action_id)
            return False

        if not action.is_enabled:
            logger.debug("Действие отключено: %s", action_id)
            return False

        handler = self._handlers.get(action_id)
        if handler:
            try:
                handler()
                self._add_to_history(action_id)
                return True
            except Exception as exc:
                logger.error("Ошибка выполнения действия %s: %s", action_id, exc)
                return False

        logger.debug("Нет обработчика для действия: %s", action_id)
        return False

    def handle_key(self, key: str, modifiers: Tuple[KeyModifier, ...]) -> bool:
        """Обрабатывает нажатие клавиши.

        Args:
            key: Клавиша
            modifiers: Модификаторы

        Returns:
            True если действие выполнено
        """
        action = self.find_action(key, modifiers)
        if action:
            return self.execute(action.id)
        return False

    # ---------- Запросы ----------

    def get_action(self, action_id: str) -> Optional[Action]:
        """Возвращает действие по ID.

        Args:
            action_id: ID действия

        Returns:
            Действие или None
        """
        return self._actions.get(action_id)

    def get_all_actions(self) -> List[Action]:
        """Возвращает все действия."""
        return list(self._actions.values())

    def get_actions_by_category(self, category: str) -> List[Action]:
        """Возвращает действия по категории.

        Args:
            category: Категория

        Returns:
            Список действий
        """
        return [a for a in self._actions.values() if a.category == category]

    def get_categories(self) -> List[str]:
        """Возвращает все категории."""
        return sorted(set(a.category for a in self._actions.values()))

    def get_conflicts(self) -> List[BindingConflict]:
        """Возвращает все конфликты привязок.

        Returns:
            Список конфликтов
        """
        # Группируем привязки по ключу
        binding_actions: Dict[str, List[str]] = {}
        for binding_key, action_id in self._bindings.items():
            if binding_key not in binding_actions:
                binding_actions[binding_key] = []
            binding_actions[binding_key].append(action_id)

        # Находим конфликты
        conflicts: List[BindingConflict] = []
        for binding_key, actions in binding_actions.items():
            if len(actions) > 1:
                # Парсим привязку
                parts = binding_key.split("+")
                key = parts[-1]
                modifiers = tuple(KeyModifier(p) for p in parts[:-1]) if len(parts) > 1 else ()

                for action_id in actions:
                    conflicts.append(
                        BindingConflict(
                            action_id=action_id,
                            binding=KeyBinding(key, modifiers),
                            conflicts_with=[a for a in actions if a != action_id],
                        )
                    )

        return conflicts

    # ---------- История ----------

    def get_history(self, limit: int = 20) -> List[str]:
        """Возвращает историю выполненных действий.

        Args:
            limit: Максимум записей

        Returns:
            Список ID действий (последние сначала)
        """
        return list(reversed(self._history[-limit:]))

    def clear_history(self) -> None:
        """Очищает историю."""
        self._history.clear()

    # ---------- Импорт/экспорт ----------

    def export_bindings(self) -> Dict[str, Any]:
        """Экспортирует привязки в словарь.

        Returns:
            Словарь с привязками
        """
        bindings: Dict[str, Any] = {}
        for binding_key, action_id in self._bindings.items():
            bindings[binding_key] = action_id

        return {
            "version": 1,
            "bindings": bindings,
        }

    def import_bindings(self, data: Dict[str, Any]) -> int:
        """Импортирует привязки из словаря.

        Args:
            data: Словарь с привязками

        Returns:
            Количество импортированных привязок
        """
        version = data.get("version", 1)
        if version != 1:
            logger.warning("Неподдерживаемая версия конфигурации: %s", version)
            return 0

        bindings = data.get("bindings", {})
        imported = 0

        for binding_key, action_id in bindings.items():
            if action_id in self._actions:
                self._bindings[binding_key] = action_id
                imported += 1

        logger.info("Импортировано %d привязок", imported)
        return imported

    def save_to_file(self, path: Path) -> bool:
        """Сохраняет привязки в файл.

        Args:
            path: Путь к файлу

        Returns:
            True если успешно
        """
        try:
            data = self.export_bindings()
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.info("Привязки сохранены в %s", path)
            return True
        except Exception as exc:
            logger.error("Ошибка сохранения привязок: %s", exc)
            return False

    def load_from_file(self, path: Path) -> int:
        """Загружает привязки из файла.

        Args:
            path: Путь к файлу

        Returns:
            Количество загруженных привязок
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return self.import_bindings(data)
        except Exception as exc:
            logger.error("Ошибка загрузки привязок: %s", exc)
            return 0

    def reset_to_defaults(self) -> int:
        """Сбрасывает привязки к настройкам по умолчанию.

        Returns:
            Количество сброшенных привязок
        """
        self._bindings.clear()

        for action_id, action in self._actions.items():
            if action.default_binding:
                self._bindings[str(action.default_binding)] = action_id

        logger.info("Привязки сброшены к настройкам по умолчанию")
        return len(self._bindings)

    # ---------- Внутренние методы ----------

    def _add_to_history(self, action_id: str) -> None:
        """Добавляет действие в историю.

        Args:
            action_id: ID действия
        """
        self._history.append(action_id)

        # Ограничиваем размер
        if len(self._history) > self._max_history:
            self._history.pop(0)


__all__ = [
    "KeyBindingsService",
    "KeyBinding",
    "KeyModifier",
    "KeyContext",
    "Action",
    "BindingConflict",
]
