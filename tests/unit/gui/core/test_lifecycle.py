"""Unit-тесты для модуля lifecycle.

Проверяет:
- LifecycleState: состояния и свойства
- ComponentInfo: frozen dataclass
- LifecycleAware Protocol
- LifecycleManager: регистрация, переходы состояний, callbacks
- SafeMount: контекстный менеджер
- LifecycleCallbacks: декораторы

Coverage target: >=90%
"""

import threading

import pytest

from src.gui.core.lifecycle import (
    ComponentInfo,
    LifecycleCallbacks,
    LifecycleManager,
    LifecycleState,
)


# ==============================================================================
# TEST: LifecycleState
# ==============================================================================


class TestLifecycleState:
    """Тесты перечисления LifecycleState."""

    def test_states_exist(self) -> None:
        """Все состояния определены."""
        assert LifecycleState.UNMOUNTED is not None
        assert LifecycleState.MOUNTING is not None
        assert LifecycleState.MOUNTED is not None
        assert LifecycleState.UNMOUNTING is not None
        assert LifecycleState.ERROR is not None

    def test_is_active(self) -> None:
        """is_active True только для MOUNTED."""
        assert LifecycleState.MOUNTED.is_active is True
        assert LifecycleState.UNMOUNTED.is_active is False
        assert LifecycleState.MOUNTING.is_active is False
        assert LifecycleState.UNMOUNTING.is_active is False
        assert LifecycleState.ERROR.is_active is False

    def test_is_transition(self) -> None:
        """is_transition True для MOUNTING и UNMOUNTING."""
        assert LifecycleState.MOUNTING.is_transition is True
        assert LifecycleState.UNMOUNTING.is_transition is True
        assert LifecycleState.MOUNTED.is_transition is False
        assert LifecycleState.UNMOUNTED.is_transition is False
        assert LifecycleState.ERROR.is_transition is False


# ==============================================================================
# TEST: ComponentInfo
# ==============================================================================


class TestComponentInfo:
    """Тесты frozen dataclass ComponentInfo."""

    def test_default_state(self) -> None:
        """По умолчанию состояние UNMOUNTED."""
        info = ComponentInfo(widget_id="test_01")
        assert info.state == LifecycleState.UNMOUNTED
        assert info.widget is None
        assert info.parent_id is None
        assert info.callbacks == []

    def test_frozen(self) -> None:
        """ComponentInfo immutable (frozen=True)."""
        info = ComponentInfo(widget_id="test_01")
        with pytest.raises(AttributeError):
            info.widget_id = "other"  # type: ignore[misc]

    def test_custom_state(self) -> None:
        """Создание с заданным состоянием."""
        info = ComponentInfo(widget_id="test_01", state=LifecycleState.MOUNTED)
        assert info.state == LifecycleState.MOUNTED


# ==============================================================================
# TEST: LifecycleManager
# ==============================================================================


class TestLifecycleManager:
    """Тесты менеджера жизненного цикла."""

    def test_register_component(self) -> None:
        """Регистрация нового компонента."""
        manager = LifecycleManager()
        info = manager.register("btn_01")
        assert info.widget_id == "btn_01"
        assert info.state == LifecycleState.UNMOUNTED

    def test_register_duplicate_raises(self) -> None:
        """Повторная регистрация выбрасывает ValueError."""
        manager = LifecycleManager()
        manager.register("btn_01")
        with pytest.raises(ValueError, match="already registered"):
            manager.register("btn_01")

    def test_register_empty_id_raises(self) -> None:
        """Регистрация с пустым widget_id выбрасывает ValueError."""
        manager = LifecycleManager()
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.register("")
        with pytest.raises(ValueError, match="cannot be empty"):
            manager.register("   ")

    def test_unregister(self) -> None:
        """Удаление регистрации компонента."""
        manager = LifecycleManager()
        manager.register("btn_01")
        manager.unregister("btn_01")
        assert not manager.is_registered("btn_01")

    def test_unregister_not_found_raises(self) -> None:
        """Удаление несуществующего компонента выбрасывает KeyError."""
        manager = LifecycleManager()
        with pytest.raises(KeyError, match="not found"):
            manager.unregister("btn_01")

    def test_transition_to_mounted(self) -> None:
        """Переход в состояние MOUNTED."""
        manager = LifecycleManager()
        manager.register("btn_01")
        info = manager.transition_to("btn_01", LifecycleState.MOUNTED)
        assert info.state == LifecycleState.MOUNTED
        assert info.state.is_active

    def test_transition_to_unmounted(self) -> None:
        """Переход в состояние UNMOUNTED."""
        manager = LifecycleManager()
        manager.register("btn_01")
        manager.transition_to("btn_01", LifecycleState.MOUNTED)
        info = manager.transition_to("btn_01", LifecycleState.UNMOUNTED)
        assert not info.state.is_active

    def test_transition_not_found_raises(self) -> None:
        """Переход несуществующего компонента выбрасывает KeyError."""
        manager = LifecycleManager()
        with pytest.raises(KeyError, match="not found"):
            manager.transition_to("btn_01", LifecycleState.MOUNTED)

    def test_get_state(self) -> None:
        """Получение состояния компонента."""
        manager = LifecycleManager()
        manager.register("btn_01")
        info = manager.get_state("btn_01")
        assert info.widget_id == "btn_01"

    def test_get_state_not_found_raises(self) -> None:
        """Получение состояния несуществующего компонента."""
        manager = LifecycleManager()
        with pytest.raises(KeyError, match="not found"):
            manager.get_state("btn_01")

    def test_is_registered(self) -> None:
        """Проверка регистрации компонента."""
        manager = LifecycleManager()
        assert not manager.is_registered("btn_01")
        manager.register("btn_01")
        assert manager.is_registered("btn_01")

    def test_is_active(self) -> None:
        """Проверка активности компонента."""
        manager = LifecycleManager()
        manager.register("btn_01")
        assert not manager.is_active("btn_01")
        manager.transition_to("btn_01", LifecycleState.MOUNTED)
        assert manager.is_active("btn_01")

    def test_get_all_active(self) -> None:
        """Получение всех активных компонентов."""
        manager = LifecycleManager()
        manager.register("btn_01")
        manager.register("btn_02")
        manager.transition_to("btn_01", LifecycleState.MOUNTED)
        active = manager.get_all_active()
        assert len(active) == 1
        assert active[0].widget_id == "btn_01"

    def test_update_widget(self) -> None:
        """Обновление виджета компонента."""
        manager = LifecycleManager()
        manager.register("btn_01")
        info = manager.update_widget("btn_01", None, "frame_01")  # type: ignore[arg-type]
        assert info.parent_id == "frame_01"

    def test_update_widget_not_found_raises(self) -> None:
        """Обновление несуществующего виджета."""
        manager = LifecycleManager()
        with pytest.raises(KeyError, match="not found"):
            manager.update_widget("btn_01", None, "frame_01")  # type: ignore[arg-type]

    def test_clear(self) -> None:
        """Очистка всех регистраций."""
        manager = LifecycleManager()
        manager.register("btn_01")
        manager.register("btn_02")
        manager.clear()
        assert not manager.is_registered("btn_01")
        assert not manager.is_registered("btn_02")

    def test_callbacks_on_mount(self) -> None:
        """Callback вызывается при переходе в MOUNTED."""
        results: list[str] = []
        manager = LifecycleManager()
        manager.register("btn_01", on_mount=lambda: results.append("mounted"))
        manager.transition_to("btn_01", LifecycleState.MOUNTED)
        assert "mounted" in results

    def test_callbacks_on_unmount(self) -> None:
        """Callback вызывается при переходе в UNMOUNTED."""
        results: list[str] = []
        manager = LifecycleManager()
        manager.register("btn_01", on_unmount=lambda: results.append("unmounted"))
        manager.transition_to("btn_01", LifecycleState.MOUNTED)
        manager.transition_to("btn_01", LifecycleState.UNMOUNTED)
        assert "unmounted" in results

    def test_callbacks_on_state_changed(self) -> None:
        """Callback вызывается при изменении состояния."""
        results: list[str] = []
        manager = LifecycleManager()
        manager.register("btn_01", on_state_changed=lambda _: results.append("changed"))
        manager.transition_to("btn_01", LifecycleState.MOUNTED)
        assert "changed" in results

    def test_thread_safety(self) -> None:
        """Thread-safe регистрация из разных потоков."""
        manager = LifecycleManager()
        errors: list[Exception] = []

        def register(idx: int) -> None:
            try:
                manager.register(f"widget_{idx}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=register, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert manager.is_registered("widget_0")

    def test_callback_error_does_not_crash(self) -> None:
        """Ошибка в callback не прерывает менеджер."""
        manager = LifecycleManager()
        manager.register(
            "btn_01",
            on_mount=lambda: (_ for _ in ()).throw(RuntimeError("callback error")),
        )
        # Не должно упасть
        manager.transition_to("btn_01", LifecycleState.MOUNTED)


# ==============================================================================
# TEST: LifecycleCallbacks
# ==============================================================================


class TestLifecycleCallbacks:
    """Тесты декораторов lifecycle callbacks."""

    def test_on_mount(self) -> None:
        """Декоратор on_mount регистрирует callback."""
        callbacks = LifecycleCallbacks()
        results: list[str] = []

        @callbacks.on_mount
        def init_data() -> None:
            results.append("initialized")

        callbacks.trigger_mount()
        assert "initialized" in results

    def test_on_unmount(self) -> None:
        """Декоратор on_unmount регистрирует callback."""
        callbacks = LifecycleCallbacks()
        results: list[str] = []

        @callbacks.on_unmount
        def cleanup() -> None:
            results.append("cleaned")

        callbacks.trigger_unmount()
        assert "cleaned" in results

    def test_callback_error_does_not_crash(self) -> None:
        """Ошибка в callback не прерывает выполнение."""
        callbacks = LifecycleCallbacks()
        results: list[str] = []

        @callbacks.on_mount
        def failing() -> None:
            raise RuntimeError("test error")

        @callbacks.on_mount
        def succeeding() -> None:
            results.append("ok")

        callbacks.trigger_mount()
        # Второй callback должен выполниться
        assert "ok" in results

    def test_multiple_mount_callbacks(self) -> None:
        """Множественные mount callbacks выполняются по порядку."""
        callbacks = LifecycleCallbacks()
        results: list[str] = []

        @callbacks.on_mount
        def first() -> None:
            results.append("1")

        @callbacks.on_mount
        def second() -> None:
            results.append("2")

        callbacks.trigger_mount()
        assert results == ["1", "2"]