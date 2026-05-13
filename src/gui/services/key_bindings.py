"""Глобальный сервис регистрации и диспетчеризации клавиатурных shortcuts.

Предоставляет Singleton thread-safe сервис для регистрации хоткеев
с поддержкой scopes, MFA-флага и санитизации ввода.

Example:
    >>> service = KeyBindingsService()
    >>> bid = service.register("Ctrl+N", callback=new_doc, scope="global")
    >>> handled = service.dispatch(event)
"""

from __future__ import annotations

import logging
import re
import threading
import tkinter as tk
from dataclasses import dataclass
from typing import Any, Callable, ClassVar, Final, Optional

logger: logging.Logger = logging.getLogger(__name__)

#: Допустимые модификаторы (case-insensitive при парсинге).
_VALID_MODIFIERS: Final[frozenset[str]] = frozenset({"ctrl", "cmd", "alt", "shift"})

#: Регулярное выражение для валидации keysym/клавиши.
_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^(?:[a-zA-Z0-9]|F[1-9]|F1[0-2]|\+|-)$")

#: Маппинг спецсимволов в Tkinter keysym.
_KEYSYM_MAP: Final[dict[str, str]] = {
    "+": "plus",
    "-": "minus",
}

#: Обратный маппинг keysym → символ shortcut.
_REVERSE_KEYSYM_MAP: Final[dict[str, str]] = {
    "plus": "+",
    "minus": "-",
    "KP_Add": "+",
    "KP_Subtract": "-",
}

#: Модификаторы, игнорируемые при генерации shortcut из event.
_IGNORE_KEYSYMS: Final[frozenset[str]] = frozenset(
    {
        "Control_L",
        "Control_R",
        "Alt_L",
        "Alt_R",
        "Shift_L",
        "Shift_R",
        "Meta_L",
        "Meta_R",
        "Command_L",
        "Command_R",
        "Caps_Lock",
        "Num_Lock",
    }
)


@dataclass(frozen=True)
class _Binding:
    """Внутренняя структура зарегистрированного binding."""

    binding_id: str
    shortcut: str
    callback: Callable[[], None]
    scope: str
    requires_mfa: bool
    tk_sequence: str


class KeyBindingsService:
    """Глобальный thread-safe сервис клавиатурных shortcuts (Singleton).

    Attributes:
        _bindings: mapping binding_id → _Binding.
        _scopes: mapping scope → (normalized_shortcut → binding_id).
    """

    _instance: ClassVar[Optional["KeyBindingsService"]] = None
    _singleton_lock: ClassVar[threading.Lock] = threading.Lock()

    def __new__(cls, *args: Any, **kwargs: Any) -> "KeyBindingsService":
        if cls._instance is None:
            with cls._singleton_lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._initialized: bool = True
        self._service_lock: threading.Lock = threading.Lock()
        self._counter: int = 0
        self._bindings: dict[str, _Binding] = {}
        self._scopes: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------
    # Публичный API
    # ------------------------------------------------------------------

    def register(
        self,
        shortcut: str,
        callback: Callable[[], None],
        scope: str = "global",
        *,
        requires_mfa: bool = False,
    ) -> str:
        """Регистрирует keyboard shortcut.

        Args:
            shortcut: Строка вида ``Ctrl+N``, ``Ctrl+Shift+B``, ``Ctrl++``.
            callback: Функция без аргументов, вызываемая при нажатии.
            scope: Область действия (по умолчанию ``global``).
            requires_mfa: Если True — shortcut требует MFA (флаг для будущего использования).

        Returns:
            Уникальный ``binding_id``.

        Raises:
            ValueError: Если shortcut содержит недопустимые символы.
        """
        normalized = self._normalize_and_validate_shortcut(shortcut)
        tk_seq = self._shortcut_to_tk_sequence(normalized)

        with self._service_lock:
            self._counter += 1
            binding_id = f"kb-{self._counter:04d}"
            binding = _Binding(
                binding_id=binding_id,
                shortcut=normalized,
                callback=callback,
                scope=scope,
                requires_mfa=requires_mfa,
                tk_sequence=tk_seq,
            )
            self._bindings[binding_id] = binding
            self._scopes.setdefault(scope, {})[normalized] = binding_id

        logger.debug(
            "Registered shortcut %s (id=%s) in scope=%s",
            normalized,
            binding_id,
            scope,
        )
        return binding_id

    def unregister(self, binding_id: str) -> bool:
        """Удаляет регистрацию по ``binding_id``.

        Args:
            binding_id: Идентификатор, возвращённый ``register()``.

        Returns:
            True если binding был удалён, False если не найден.
        """
        with self._service_lock:
            binding = self._bindings.pop(binding_id, None)
            if binding is None:
                return False
            scope_map = self._scopes.get(binding.scope)
            if scope_map is not None:
                scope_map.pop(binding.shortcut, None)
                if not scope_map:
                    del self._scopes[binding.scope]
        logger.debug("Unregistered binding_id=%s", binding_id)
        return True

    def dispatch(self, event: tk.Event) -> bool:
        """Диспетчеризует событие клавиатуры.

        Args:
            event: Событие Tkinter ``<Key>`` или аналогичное.

        Returns:
            True если событие было обработано (shortcut найден и вызван).
        """
        shortcut = self._event_to_shortcut(event)
        if shortcut is None:
            return False

        with self._service_lock:
            scope_map = self._scopes.get("global", {})
            binding_id = scope_map.get(shortcut)
            binding = self._bindings.get(binding_id) if binding_id is not None else None

        if binding is None:
            return False

        if binding.requires_mfa:
            logger.info("MFA required for shortcut %s — skipped", binding.shortcut)
            return False

        try:
            binding.callback()
        except Exception as e:
            logger.exception("Error in key binding callback id=%s: %s", binding.binding_id, e)
            return False

        logger.debug("Dispatched shortcut %s (id=%s)", binding.shortcut, binding.binding_id)
        return True

    def check_conflicts(self, shortcut: str, scope: str) -> list[str]:
        """Возвращает список ``binding_id`` с конфликтующим shortcut в scope.

        Args:
            shortcut: Shortcut для проверки.
            scope: Scope для проверки.

        Returns:
            Список conflicting ``binding_id`` (обычно 0 или 1 элемент).
        """
        normalized = self._normalize_and_validate_shortcut(shortcut)
        with self._service_lock:
            scope_map = self._scopes.get(scope, {})
            bid = scope_map.get(normalized)
            if bid is not None:
                return [bid]
        return []

    def get_bindings_for_scope(self, scope: str) -> dict[str, str]:
        """Возвращает mapping shortcut → binding_id для указанного scope.

        Args:
            scope: Имя scope.

        Returns:
            Копия словаря bindings для scope.
        """
        with self._service_lock:
            return dict(self._scopes.get(scope, {}))

    def clear_scope(self, scope: str) -> None:
        """Удаляет все bindings из указанного scope.

        Args:
            scope: Scope для очистки.
        """
        with self._service_lock:
            scope_map = self._scopes.pop(scope, {})
            for bid in scope_map.values():
                self._bindings.pop(bid, None)
        logger.debug("Cleared scope=%s", scope)

    def load_defaults(self) -> None:
        """Загружает стандартные bindings по умолчанию.

        Переопределяется в подклассах или вызывается явно при старте.
        """
        logger.debug("load_defaults() called — no default bindings pre-defined")

    # ------------------------------------------------------------------
    # Внутренние методы
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_shortcut(shortcut: str) -> tuple[list[str], str]:
        """Парсит shortcut на модификаторы и клавишу.

        Поддерживает ``Ctrl++`` (key='+'): ``Ctrl+`` → ['Ctrl'], key='+'.
        """
        parts = shortcut.split("+")
        if parts[-1] == "":
            key = "+"
            mods = [p for p in parts[:-1] if p != ""]
        else:
            key = parts[-1]
            mods = parts[:-1]
        return mods, key

    def _normalize_and_validate_shortcut(self, shortcut: str) -> str:
        """Нормализует и валидирует shortcut.

        Returns:
            Нормализованная строка (например ``Ctrl+n`` или ``Ctrl+Shift+B``).

        Raises:
            ValueError: При недопустимых модификаторах или клавише.
        """
        mods, key = self._parse_shortcut(shortcut)
        normalized_mods: list[str] = []
        for m in mods:
            m_lower = m.strip().lower()
            if m_lower not in _VALID_MODIFIERS:
                raise ValueError(f"Недопустимый модификатор: {m!r}")
            normalized_mods.append(m_lower.capitalize())

        key = key.strip()
        if not key:
            raise ValueError("Клавиша не указана")

        # Нормализация букв: без Shift → lowercase, со Shift → uppercase.
        if len(key) == 1 and key.isalpha():
            if "Shift" in normalized_mods:
                key = key.upper()
            else:
                key = key.lower()
        elif len(key) == 1 and key.isdigit():
            pass  # цифры как есть
        elif key in ("+", "-"):
            pass  # спецсимволы
        elif key.upper().startswith("F") and key[1:].isdigit() and 1 <= int(key[1:]) <= 12:
            key = key.upper()
        else:
            raise ValueError(f"Недопустимая клавиша: {key!r}")

        return "+".join(normalized_mods + [key])

    def _shortcut_to_tk_sequence(self, shortcut: str) -> str:
        """Конвертирует нормализованный shortcut в Tkinter event sequence.

        Args:
            shortcut: Нормализованный shortcut, например ``Ctrl+n``.

        Returns:
            Tkinter event sequence, например ``<Control-n>``.
        """
        mods, key = self._parse_shortcut(shortcut)
        tk_mods: list[str] = []
        for m in mods:
            m_lower = m.lower()
            if m_lower == "ctrl":
                tk_mods.append("Control")
            elif m_lower == "cmd":
                tk_mods.append("Command")
            elif m_lower == "alt":
                tk_mods.append("Alt")
            elif m_lower == "shift":
                tk_mods.append("Shift")

        # Конвертация клавиши в keysym
        tk_key = _KEYSYM_MAP.get(key, key)
        # lowercase для букв в Tk sequence (без Shift)
        if len(tk_key) == 1 and tk_key.isalpha() and "Shift" not in tk_mods:
            tk_key = tk_key.lower()

        if tk_mods:
            return f"<{'-'.join(tk_mods + [tk_key])}>"
        return f"<{tk_key}>"

    def _event_to_shortcut(self, event: tk.Event) -> Optional[str]:
        """Преобразует ``tk.Event`` в нормализованный shortcut.

        Args:
            event: Событие клавиатуры.

        Returns:
            Нормализованный shortcut или None если событие — чистый модификатор.
        """
        state: int | str = event.state
        if not isinstance(state, int):
            return None
        mods: list[str] = []

        if state & 0x0004:
            mods.append("Ctrl")
        if state & 0x0008:
            mods.append("Alt")
        if state & 0x0001:
            mods.append("Shift")
        # Mod4 (0x0080) часто Command на macOS; на Linux может быть Mod4/Mod5,
        # поэтому проверяем аккуратно.
        if state & 0x0080:
            mods.append("Cmd")

        key = event.keysym
        if key in _IGNORE_KEYSYMS:
            return None

        # Маппинг keysym → символ shortcut
        if key in _REVERSE_KEYSYM_MAP:
            key = _REVERSE_KEYSYM_MAP[key]
        elif len(key) == 1 and key.isalpha():
            if "Shift" not in mods:
                key = key.lower()
            else:
                key = key.upper()
        elif key.lower().startswith("f") and key[1:].isdigit():
            key = key.upper()

        if not key:
            return None

        raw = "+".join(mods + [key])
        try:
            return self._normalize_and_validate_shortcut(raw)
        except ValueError:
            return None
