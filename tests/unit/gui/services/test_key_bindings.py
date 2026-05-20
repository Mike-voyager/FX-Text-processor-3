"""Unit-тесты для KeyBindingsService.

Проверяет:
- Singleton-поведение сервиса
- Регистрация и удаление keyboard shortcuts
- Парсинг и нормализация shortcut строк
- Конвертация shortcut в Tkinter event sequence
- Диспетчеризация событий (dispatch)
- Scope-изоляция bindings
- MFA-флаг
- Валидация shortcut строк
- Thread-safety

Coverage target: ≥90%
"""

from __future__ import annotations

import threading
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.services.key_bindings import KeyBindingsService, _Binding


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture(autouse=True)
def _reset_singleton() -> Generator[None, None, None]:
    """Сбрасывает Singleton между тестами."""
    KeyBindingsService._instance = None  # type: ignore[attr-defined]
    KeyBindingsService._singleton_lock = threading.Lock()  # type: ignore[attr-defined]
    yield
    KeyBindingsService._instance = None  # type: ignore[attr-defined]
    KeyBindingsService._singleton_lock = threading.Lock()  # type: ignore[attr-defined]


@pytest.fixture
def service() -> KeyBindingsService:
    """Создаёт свежий экземпляр KeyBindingsService."""
    return KeyBindingsService()


# =============================================================================
# TEST: Singleton
# =============================================================================


@pytest.mark.gui
class TestSingleton:
    """Тесты Singleton-поведения KeyBindingsService."""

    def test_singleton_returns_same_instance(self) -> None:
        """Два вызова конструктора возвращают один и тот же экземпляр."""
        s1 = KeyBindingsService()
        s2 = KeyBindingsService()
        assert s1 is s2

    def test_singleton_thread_safety(self) -> None:
        """Singleton корректно создаётся из разных потоков."""
        instances: list[KeyBindingsService] = []

        def create_instance() -> None:
            instances.append(KeyBindingsService())

        threads = [threading.Thread(target=create_instance) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Все экземпляры должны быть одним и тем же объектом
        assert all(inst is instances[0] for inst in instances)


# =============================================================================
# TEST: Shortcut Parsing & Validation
# =============================================================================


@pytest.mark.gui
class TestShortcutParsing:
    """Тесты парсинга и нормализации shortcut строк."""

    def test_parse_ctrl_n(self) -> None:
        """Парсинг Ctrl+N."""
        mods, key = KeyBindingsService._parse_shortcut("Ctrl+N")
        assert mods == ["Ctrl"]
        assert key == "N"

    def test_parse_ctrl_shift_b(self) -> None:
        """Парсинг Ctrl+Shift+B."""
        mods, key = KeyBindingsService._parse_shortcut("Ctrl+Shift+B")
        assert mods == ["Ctrl", "Shift"]
        assert key == "B"

    def test_parse_ctrl_plus(self) -> None:
        """Парсинг Ctrl++ (клавиша '+')."""
        mods, key = KeyBindingsService._parse_shortcut("Ctrl++")
        assert mods == ["Ctrl"]
        assert key == "+"

    def test_parse_ctrl_minus(self) -> None:
        """Парсинг Ctrl+- (клавиша '-')."""
        mods, key = KeyBindingsService._parse_shortcut("Ctrl+-")
        assert mods == ["Ctrl"]
        assert key == "-"

    def test_normalize_lowercases_letter_without_shift(self, service: KeyBindingsService) -> None:
        """Буква без Shift нормализуется в lowercase."""
        result = service._normalize_and_validate_shortcut("Ctrl+N")
        assert result == "Ctrl+n"

    def test_normalize_uppercases_letter_with_shift(self, service: KeyBindingsService) -> None:
        """Буква со Shift остаётся uppercase."""
        result = service._normalize_and_validate_shortcut("Ctrl+Shift+B")
        assert result == "Ctrl+Shift+B"

    def test_normalize_f_keys(self, service: KeyBindingsService) -> None:
        """F-клавиши нормализуются в uppercase."""
        result = service._normalize_and_validate_shortcut("Ctrl+F1")
        assert result == "Ctrl+F1"

    def test_normalize_plus_sign(self, service: KeyBindingsService) -> None:
        """Знак '+' корректно нормализуется."""
        result = service._normalize_and_validate_shortcut("Ctrl++")
        assert "+" in result

    def test_invalid_modifier_raises(self, service: KeyBindingsService) -> None:
        """Недопустимый модификатор вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid modifier"):
            service._normalize_and_validate_shortcut("Super+N")

    def test_invalid_key_no_key_raises(self, service: KeyBindingsService) -> None:
        """Shortcut без клавиши вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid key"):
            service._normalize_and_validate_shortcut("Ctrl")

    def test_invalid_key_raises(self, service: KeyBindingsService) -> None:
        """Недопустимая клавиша вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid key"):
            service._normalize_and_validate_shortcut("Ctrl+@")


# =============================================================================
# TEST: Shortcut to Tkinter Sequence
# =============================================================================


@pytest.mark.gui
class TestShortcutToTkSequence:
    """Тесты конвертации shortcut в Tkinter event sequence."""

    def test_ctrl_n_to_tk(self, service: KeyBindingsService) -> None:
        """Ctrl+n → <Control-n>."""
        result = service._shortcut_to_tk_sequence("Ctrl+n")
        assert result == "<Control-n>"

    def test_ctrl_shift_b_to_tk(self, service: KeyBindingsService) -> None:
        """Ctrl+Shift+B → <Control-Shift-B>."""
        result = service._shortcut_to_tk_sequence("Ctrl+Shift+B")
        assert result == "<Control-Shift-B>"

    def test_ctrl_f1_to_tk(self, service: KeyBindingsService) -> None:
        """Ctrl+F1 → <Control-F1>."""
        result = service._shortcut_to_tk_sequence("Ctrl+F1")
        assert result == "<Control-F1>"

    def test_alt_n_to_tk(self, service: KeyBindingsService) -> None:
        """Alt+n → <Alt-n>."""
        result = service._shortcut_to_tk_sequence("Alt+n")
        assert result == "<Alt-n>"


# =============================================================================
# TEST: Registration
# =============================================================================


@pytest.mark.gui
class TestRegistration:
    """Тесты регистрации keyboard shortcuts."""

    def test_register_returns_binding_id(self, service: KeyBindingsService) -> None:
        """register() возвращает строковый binding_id."""
        callback = MagicMock()
        binding_id = service.register("Ctrl+N", callback)
        assert isinstance(binding_id, str)
        assert binding_id.startswith("kb-")

    def test_register_auto_replaces_same_shortcut(self, service: KeyBindingsService) -> None:
        """Повторная регистрация того же shortcut заменяет старый binding."""
        cb1 = MagicMock()
        cb2 = MagicMock()
        bid1 = service.register("Ctrl+N", cb1, scope="global")
        bid2 = service.register("Ctrl+N", cb2, scope="global")
        # binding_id должен быть другим
        assert bid1 != bid2
        # Старый binding удалён — только один binding в scope
        bindings = service.get_bindings_for_scope("global")
        assert len(bindings) == 1

    def test_register_different_scopes(self, service: KeyBindingsService) -> None:
        """Одинаковый shortcut в разных scope не конфликтует."""
        cb1 = MagicMock()
        cb2 = MagicMock()
        bid1 = service.register("Ctrl+N", cb1, scope="editor")
        bid2 = service.register("Ctrl+N", cb2, scope="global")
        assert bid1 != bid2
        assert len(service.get_bindings_for_scope("editor")) == 1
        assert len(service.get_bindings_for_scope("global")) == 1


# =============================================================================
# TEST: Unregistration
# =============================================================================


@pytest.mark.gui
class TestUnregistration:
    """Тесты удаления регистрации keyboard shortcuts."""

    def test_unregister_existing_binding(self, service: KeyBindingsService) -> None:
        """unregister() удаляет существующий binding."""
        callback = MagicMock()
        bid = service.register("Ctrl+N", callback)
        result = service.unregister(bid)
        assert result is True
        assert len(service.get_bindings_for_scope("global")) == 0

    def test_unregister_nonexistent_returns_false(self, service: KeyBindingsService) -> None:
        """unregister() возвращает False для несуществующего binding_id."""
        result = service.unregister("kb-9999")
        assert result is False


# =============================================================================
# TEST: Dispatch
# =============================================================================


@pytest.mark.gui
class TestDispatch:
    """Тесты диспетчеризации событий."""

    def _make_event(self, keysym: str, state: int = 0) -> MagicMock:
        """Создаёт mock tk.Event."""
        event = MagicMock()
        event.keysym = keysym
        event.state = state
        return event

    def test_dispatch_calls_callback(self, service: KeyBindingsService) -> None:
        """dispatch() вызывает callback при совпадении shortcut."""
        callback = MagicMock()
        service.register("Ctrl+N", callback, scope="global")
        event = self._make_event("n", state=0x0004)  # Ctrl
        result = service.dispatch(event, scope="global")
        assert result is True
        callback.assert_called_once()

    def test_dispatch_returns_false_for_no_binding(self, service: KeyBindingsService) -> None:
        """dispatch() возвращает False если shortcut не найден."""
        event = self._make_event("z", state=0x0004)  # Ctrl+Z (не зарегистрирован)
        result = service.dispatch(event, scope="global")
        assert result is False

    def test_dispatch_falls_back_to_global(self, service: KeyBindingsService) -> None:
        """dispatch() выполняет fallback в global scope."""
        callback = MagicMock()
        service.register("Ctrl+N", callback, scope="global")
        event = self._make_event("n", state=0x0004)
        result = service.dispatch(event, scope="editor")
        assert result is True
        callback.assert_called_once()

    def test_dispatch_mfa_binding_returns_false(self, service: KeyBindingsService) -> None:
        """dispatch() возвращает False для binding с requires_mfa=True."""
        callback = MagicMock()
        service.register("Ctrl+Shift+D", callback, scope="global", requires_mfa=True)
        event = self._make_event("D", state=0x0004 | 0x0001)  # Ctrl+Shift
        result = service.dispatch(event, scope="global")
        assert result is False
        callback.assert_not_called()

    def test_dispatch_ignores_modifier_only_events(self, service: KeyBindingsService) -> None:
        """dispatch() игнорирует события чистых модификаторов."""
        event = self._make_event("Control_L", state=0x0004)
        result = service.dispatch(event, scope="global")
        assert result is False


# =============================================================================
# TEST: Scope Management
# =============================================================================


@pytest.mark.gui
class TestScopeManagement:
    """Тесты управления scope."""

    def test_get_bindings_for_scope(self, service: KeyBindingsService) -> None:
        """get_bindings_for_scope() возвращает bindings для scope."""
        service.register("Ctrl+N", MagicMock(), scope="editor")
        service.register("Ctrl+S", MagicMock(), scope="editor")
        service.register("Ctrl+O", MagicMock(), scope="global")
        editor_bindings = service.get_bindings_for_scope("editor")
        assert len(editor_bindings) == 2

    def test_clear_scope(self, service: KeyBindingsService) -> None:
        """clear_scope() удаляет все bindings из scope."""
        service.register("Ctrl+N", MagicMock(), scope="editor")
        service.register("Ctrl+S", MagicMock(), scope="editor")
        service.register("Ctrl+O", MagicMock(), scope="global")
        service.clear_scope("editor")
        assert len(service.get_bindings_for_scope("editor")) == 0
        assert len(service.get_bindings_for_scope("global")) == 1

    def test_check_conflicts(self, service: KeyBindingsService) -> None:
        """check_conflicts() возвращает конфликтующие bindings."""
        bid = service.register("Ctrl+N", MagicMock(), scope="global")
        conflicts = service.check_conflicts("Ctrl+N", scope="global")
        assert bid in conflicts

    def test_check_conflicts_no_conflict(self, service: KeyBindingsService) -> None:
        """check_conflicts() возвращает пустой список если нет конфликта."""
        service.register("Ctrl+N", MagicMock(), scope="editor")
        conflicts = service.check_conflicts("Ctrl+N", scope="global")
        assert conflicts == []


# =============================================================================
# TEST: _Binding Dataclass
# =============================================================================


@pytest.mark.gui
class TestBindingDataclass:
    """Тесты внутренней dataclass _Binding."""

    def test_binding_is_frozen(self) -> None:
        """_Binding иммутабельна (frozen=True)."""
        binding = _Binding(
            binding_id="kb-0001",
            shortcut="Ctrl+n",
            callback=lambda: None,
            scope="global",
            requires_mfa=False,
            tk_sequence="<Control-n>",
        )
        with pytest.raises(AttributeError):
            binding.scope = "editor"  # type: ignore[misc]


# =============================================================================
# TEST: Error Handling
# =============================================================================


@pytest.mark.gui
class TestErrorHandling:
    """Тесты обработки ошибок."""

    def test_callback_exception_returns_false(self, service: KeyBindingsService) -> None:
        """dispatch() возвращает False при исключении в callback."""
        failing_callback = MagicMock(side_effect=RuntimeError("callback error"))
        service.register("Ctrl+N", failing_callback, scope="global")
        event = MagicMock()
        event.keysym = "n"
        event.state = 0x0004  # Ctrl
        result = service.dispatch(event, scope="global")
        assert result is False

    def test_non_int_state_returns_false(self, service: KeyBindingsService) -> None:
        """dispatch() возвращает False если event.state не int."""
        event = MagicMock()
        event.keysym = "n"
        event.state = "invalid"  # type: ignore[assignment]
        result = service.dispatch(event, scope="global")
        assert result is False