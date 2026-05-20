"""Тесты для виджета ThemedEntry.

Проверяет базовую функциональность поля ввода:
- Создание с параметрами и без
- Placeholder текст
- Валидация через callback
- Режим редактирования (enter/exit)
- Отображение и скрытие ошибок
- Синхронизация с моделью

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/components/primitive/test_entry.py -v
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Iterator
from unittest.mock import MagicMock

import pytest
from src.gui.components.primitive.entry import ThemedEntry
from src.gui.core.exceptions import LifecycleError


# =============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture  # type: ignore[misc]
def tk_app() -> Iterator[tk.Tk]:
    """Fixture: создаёт корневое окно Tk."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture  # type: ignore[misc]
def parent_frame(tk_app: tk.Tk) -> tk.Frame:
    """Fixture: создаёт родительский фрейм."""
    frame = tk.Frame(tk_app)
    frame.pack()
    return frame


@pytest.fixture  # type: ignore[misc]
def mock_controller() -> MagicMock:
    """Fixture: создаёт мок ControllerProtocol."""
    controller = MagicMock()
    controller.dispatch = MagicMock()
    return controller


@pytest.fixture  # type: ignore[misc]
def entry(parent_frame: tk.Frame, mock_controller: MagicMock) -> Iterator[ThemedEntry]:
    """Fixture: создаёт ThemedEntry и монтирует его."""
    e = ThemedEntry(
        widget_id="test_entry",
        placeholder="Введите текст",
        controller=mock_controller,
    )
    e.mount(parent_frame)
    yield e
    if e._is_mounted:
        e.unmount()


@pytest.fixture  # type: ignore[misc]
def entry_no_validator(parent_frame: tk.Frame) -> Iterator[ThemedEntry]:
    """Fixture: создаёт ThemedEntry без валидатора."""
    e = ThemedEntry(widget_id="no_validator_entry")
    e.mount(parent_frame)
    yield e
    if e._is_mounted:
        e.unmount()


# =============================================================================
# CONSTRUCTOR TESTS
# ==============================================================================


@pytest.mark.gui
class TestThemedEntryConstructor:
    """Тесты для конструктора ThemedEntry."""

    def test_init_defaults(self) -> None:
        """Тест: создание с параметрами по умолчанию."""
        entry = ThemedEntry(widget_id="test")
        assert entry.widget_id == "test"
        assert entry._placeholder == ""
        assert entry._show == ""
        assert entry._validator is None
        assert entry._controller is None
        assert entry._has_error is False
        assert entry._placeholder_shown is False

    def test_init_with_placeholder(self) -> None:
        """Тест: создание с placeholder."""
        entry = ThemedEntry(widget_id="test", placeholder="Подсказка")
        assert entry._placeholder == "Подсказка"

    def test_init_with_show_char(self) -> None:
        """Тест: создание с символом маскировки."""
        entry = ThemedEntry(widget_id="test", show="*")
        assert entry._show == "*"

    def test_init_with_validator(self) -> None:
        """Тест: создание с валидатором."""
        validator = lambda x: len(x) >= 3  # noqa: E731
        entry = ThemedEntry(widget_id="test", validator=validator)
        assert entry._validator is validator

    def test_init_with_controller(self, mock_controller: MagicMock) -> None:
        """Тест: создание с контроллером."""
        entry = ThemedEntry(widget_id="test", controller=mock_controller)
        assert entry._controller is mock_controller

    def test_init_empty_widget_id_raises(self) -> None:
        """Тест: пустой widget_id вызывает ошибку."""
        with pytest.raises((ValueError, TypeError)):
            ThemedEntry(widget_id="")


# =============================================================================
# MOUNT / UNMOUNT TESTS
# ==============================================================================


@pytest.mark.gui
class TestThemedEntryMount:
    """Тесты для монтирования ThemedEntry."""

    def test_mount_creates_widget(self, entry: ThemedEntry) -> None:
        """Тест: mount создаёт tk.Entry виджет."""
        assert entry._tk_widget is not None
        assert isinstance(entry._tk_widget, tk.Entry)

    def test_mount_sets_mounted_flag(self, entry: ThemedEntry) -> None:
        """Тест: mount устанавливает флаг _is_mounted."""
        assert entry._is_mounted is True

    def test_mount_with_placeholder_shows_placeholder(
        self, parent_frame: tk.Frame
    ) -> None:
        """Тест: mount с placeholder отображает его при пустом поле."""
        e = ThemedEntry(widget_id="ph_test", placeholder="Введите имя")
        e.mount(parent_frame)
        # После монтирования placeholder должен быть показан
        assert e._placeholder_shown is True
        e.unmount()

    def test_mount_without_placeholder_no_placeholder(
        self, parent_frame: tk.Frame
    ) -> None:
        """Тест: mount без placeholder не устанавливает флаг placeholder."""
        e = ThemedEntry(widget_id="no_ph_test")
        e.mount(parent_frame)
        assert e._placeholder_shown is False
        e.unmount()

    def test_unmount_cleans_up(self, parent_frame: tk.Frame) -> None:
        """Тест: unmount очищает ресурсы."""
        e = ThemedEntry(widget_id="unmount_test", placeholder="Подсказка")
        e.mount(parent_frame)
        assert e.is_mounted() is True
        e.unmount()
        assert e.is_mounted() is False
        assert e._tk_widget is None


# =============================================================================
# TEXT OPERATIONS TESTS
# ==============================================================================


@pytest.mark.gui
class TestThemedEntryTextOperations:
    """Тесты для текстовых операций ThemedEntry."""

    def test_set_and_get_text(self, entry: ThemedEntry) -> None:
        """Тест: установка и получение текста."""
        entry.set_text("Hello")
        assert entry.get_text() == "Hello"

    def test_set_empty_text_shows_placeholder(self, entry: ThemedEntry) -> None:
        """Тест: установка пустого текста показывает placeholder."""
        entry.set_text("")
        # Пустой текст должен показать placeholder
        assert entry._placeholder_shown is True

    def test_get_text_without_mount_returns_empty(self) -> None:
        """Тест: get_text без mount возвращает пустую строку."""
        entry = ThemedEntry(widget_id="unmounted")
        assert entry.get_text() == ""

    def test_set_text_without_mount_no_error(self) -> None:
        """Тест: set_text без mount не вызывает ошибку."""
        entry = ThemedEntry(widget_id="unmounted")
        entry.set_text("test")  # Не должно падать


# =============================================================================
# PLACEHOLDER TESTS
# ==============================================================================


@pytest.mark.gui
class TestThemedEntryPlaceholder:
    """Тесты для placeholder ThemedEntry."""

    def test_set_placeholder(self, entry: ThemedEntry) -> None:
        """Тест: установка placeholder текста."""
        entry.set_placeholder("Новая подсказка")
        assert entry._placeholder == "Новая подсказка"

    def test_placeholder_displayed_on_mount(self, parent_frame: tk.Frame) -> None:
        """Тест: placeholder отображается при первичном монтировании."""
        e = ThemedEntry(widget_id="ph_mount_test", placeholder="Введите текст")
        e.mount(parent_frame)
        # При монтировании с placeholder и пустым полем — placeholder показан
        assert e._placeholder_shown is True
        e.unmount()

    def test_placeholder_not_shown_with_show_char(self, parent_frame: tk.Frame) -> None:
        """Тест: placeholder не показан для полей с маскировкой (пароль)."""
        e = ThemedEntry(widget_id="pwd_test", placeholder="Пароль", show="*")
        e.mount(parent_frame)
        # При show="*" placeholder не должен отображаться
        assert e._placeholder_shown is False
        e.unmount()

    def test_placeholder_hidden_on_focus_in(self, entry: ThemedEntry) -> None:
        """Тест: placeholder скрывается при получении фокуса."""
        # Сначала убеждаемся, что placeholder показан
        assert entry._placeholder_shown is True
        # Имитируем получение фокуса
        entry._on_focus_in()
        assert entry._placeholder_shown is False

    def test_placeholder_shown_on_focus_out_when_empty(
        self, entry: ThemedEntry
    ) -> None:
        """Тест: placeholder показан при потере фокуса если поле пустое."""
        # Входим в режим редактирования и выходим (поле пустое)
        entry.enter_edit_mode()
        entry.exit_edit_mode()
        # Placeholder должен быть показан
        assert entry._placeholder_shown is True

    def test_get_text_returns_empty_when_placeholder_shown(
        self, entry: ThemedEntry
    ) -> None:
        """Тест: get_text возвращает пустую строку когда показан placeholder."""
        assert entry._placeholder_shown is True
        assert entry.get_text() == ""


# =============================================================================
# VALIDATION TESTS
# ==============================================================================


@pytest.mark.gui
class TestThemedEntryValidation:
    """Тесты для валидации ThemedEntry."""

    def test_validate_without_validator_returns_true(
        self, entry_no_validator: ThemedEntry
    ) -> None:
        """Тест: валидация без валидатора возвращает True."""
        entry_no_validator.set_text("любой текст")
        assert entry_no_validator.validate() is True

    def test_validate_pass_with_valid_text(self, parent_frame: tk.Frame) -> None:
        """Тест: валидация проходит для валидного текста."""
        validator = lambda x: len(x) >= 3  # noqa: E731
        entry = ThemedEntry(widget_id="v_entry", validator=validator)
        entry.mount(parent_frame)
        entry.set_text("valid text")
        assert entry.validate() is True
        assert entry._has_error is False
        entry.unmount()

    def test_validate_fail_with_invalid_text(self, parent_frame: tk.Frame) -> None:
        """Тест: валидация не проходит для невалидного текста."""
        validator = lambda x: len(x) >= 3  # noqa: E731
        entry = ThemedEntry(widget_id="v_entry2", validator=validator)
        entry.mount(parent_frame)
        entry.set_text("ab")
        assert entry.validate() is False
        assert entry._has_error is True
        entry.unmount()

    def test_validate_clears_error_on_success(self, parent_frame: tk.Frame) -> None:
        """Тест: успешная валидация очищает ошибку."""
        validator = lambda x: len(x) >= 3  # noqa: E731
        entry = ThemedEntry(widget_id="v_entry3", validator=validator)
        entry.mount(parent_frame)
        entry.set_text("ab")
        entry.validate()
        assert entry._has_error is True
        entry.set_text("valid text")
        entry.validate()
        assert entry._has_error is False
        entry.unmount()


# =============================================================================
# ERROR DISPLAY TESTS
# ==============================================================================


@pytest.mark.gui
class TestThemedEntryErrorDisplay:
    """Тесты для отображения ошибок ThemedEntry."""

    def test_show_error_sets_flag(self, entry: ThemedEntry) -> None:
        """Тест: show_error устанавливает флаг ошибки."""
        entry.show_error("Тестовая ошибка")
        assert entry._has_error is True

    def test_clear_error_clears_flag(self, entry: ThemedEntry) -> None:
        """Тест: clear_error снимает флаг ошибки."""
        entry.show_error("Тестовая ошибка")
        assert entry._has_error is True
        entry.clear_error()
        assert entry._has_error is False

    def test_clear_error_without_mount_no_error(self) -> None:
        """Тест: clear_error без mount не вызывает ошибку."""
        entry = ThemedEntry(widget_id="unmounted_err")
        entry.clear_error()  # Не должно падать
        assert entry._has_error is False

    def test_show_error_without_mount_sets_flag(self) -> None:
        """Тест: show_error без mount устанавливает флаг (но не стилизует)."""
        entry = ThemedEntry(widget_id="unmounted_err2")
        entry.show_error("Ошибка")
        assert entry._has_error is True


# =============================================================================
# EDIT MODE TESTS
# ==============================================================================


@pytest.mark.gui
class TestThemedEntryEditMode:
    """Тесты для режима редактирования ThemedEntry."""

    def test_enter_edit_mode(self, entry: ThemedEntry) -> None:
        """Тест: вход в режим редактирования."""
        entry.enter_edit_mode()
        assert entry._is_editing is True

    def test_exit_edit_mode(self, entry: ThemedEntry) -> None:
        """Тест: выход из режима редактирования."""
        entry.enter_edit_mode()
        entry.exit_edit_mode()
        assert entry._is_editing is False

    def test_enter_edit_mode_unmounted_raises(self) -> None:
        """Тест: enter_edit_mode без mount вызывает LifecycleError."""
        entry = ThemedEntry(widget_id="unmounted_edit")
        with pytest.raises(LifecycleError):
            entry.enter_edit_mode()

    def test_exit_edit_mode_unmounted_raises(self) -> None:
        """Тест: exit_edit_mode без mount вызывает LifecycleError."""
        entry = ThemedEntry(widget_id="unmounted_edit2")
        with pytest.raises(LifecycleError):
            entry.exit_edit_mode()

    def test_get_edit_value_returns_text(self, entry: ThemedEntry) -> None:
        """Тест: get_edit_value возвращает текущий текст."""
        entry.set_text("test value")
        assert entry.get_edit_value() == "test value"

    def test_get_edit_value_returns_empty_when_unmounted(self) -> None:
        """Тест: get_edit_value без mount возвращает пустую строку.

        Делегирует к get_text(), который безопасно возвращает ""
        для несмонтированного виджета.
        """
        entry = ThemedEntry(widget_id="unmounted_edit3")
        assert entry.get_edit_value() == ""

    def test_set_edit_value_updates_text(self, entry: ThemedEntry) -> None:
        """Тест: set_edit_value обновляет текст поля."""
        entry.set_edit_value("new value")
        assert entry.get_edit_value() == "new value"

    def test_set_edit_value_without_mount_no_error(self) -> None:
        """Тест: set_edit_value без mount не вызывает ошибку.

        Делегирует к set_text(), который безопасно игнорирует вызов
        для несмонтированного виджета.
        """
        entry = ThemedEntry(widget_id="unmounted_edit4")
        entry.set_edit_value("test")  # Не должно падать


# =============================================================================
# SYNC TO MODEL TESTS
# ==============================================================================


@pytest.mark.gui
class TestThemedEntrySync:
    """Тесты для синхронизации ThemedEntry с моделью."""

    def test_sync_to_model_dispatches_on_change(
        self, entry: ThemedEntry, mock_controller: MagicMock
    ) -> None:
        """Тест: sync_to_model отправляет событие при изменении."""
        # Сбрасываем мок после mount (который вызывает dispatch для widget_mounted)
        mock_controller.dispatch.reset_mock()
        entry.enter_edit_mode()
        entry.set_text("новое значение")
        result = entry.sync_to_model()
        assert result is True
        mock_controller.dispatch.assert_called_once_with(
            "entry_changed", value="новое значение", widget_id="test_entry"
        )

    def test_sync_to_model_no_dispatch_when_unchanged(
        self, entry: ThemedEntry, mock_controller: MagicMock
    ) -> None:
        """Тест: sync_to_model не отправляет событие без изменений."""
        mock_controller.dispatch.reset_mock()
        entry.enter_edit_mode()
        result = entry.sync_to_model()
        assert result is False

    def test_has_changes_returns_true_after_edit(self, entry: ThemedEntry) -> None:
        """Тест: has_changes возвращает True после изменения текста."""
        entry.enter_edit_mode()
        entry.set_text("изменённый текст")
        assert entry.has_changes() is True

    def test_has_changes_returns_false_without_edit(self, entry: ThemedEntry) -> None:
        """Тест: has_changes возвращает False без изменений."""
        entry.enter_edit_mode()
        # Текст не менялся с момента входа в edit mode
        assert entry.has_changes() is False


# =============================================================================
# COMPLETE WORKFLOW TESTS
# ==============================================================================


@pytest.mark.gui
class TestThemedEntryWorkflow:
    """Тесты полного workflow ThemedEntry."""

    def test_edit_workflow(
        self, parent_frame: tk.Frame, mock_controller: MagicMock
    ) -> None:
        """Тест: полный цикл редактирования (mount → edit → sync → unmount)."""
        e = ThemedEntry(
            widget_id="workflow_entry",
            controller=mock_controller,
        )
        e.mount(parent_frame)

        # Входим в режим редактирования
        e.enter_edit_mode()
        assert e._is_editing is True

        # Вводим текст
        e.set_text("новый текст")
        assert e.has_changes() is True

        # Выходим из режима (должен вызвать sync_to_model)
        e.exit_edit_mode()
        assert e._is_editing is False

        # Демонтируем
        e.unmount()
        assert e.is_mounted() is False

    def test_placeholder_lifecycle(self, parent_frame: tk.Frame) -> None:
        """Тест: полный цикл placeholder (mount → show → hide → show)."""
        e = ThemedEntry(
            widget_id="ph_lifecycle",
            placeholder="Подсказка",
        )
        e.mount(parent_frame)

        # При монтировании placeholder показан
        assert e._placeholder_shown is True
        assert e.get_text() == ""

        # При входе в редактирование placeholder скрывается
        e._on_focus_in()
        assert e._placeholder_shown is False

        # Вводим текст
        e.set_text("реальный текст")
        assert e.get_text() == "реальный текст"

        # При выходе из редактирования с текстом — placeholder не нужен
        e._on_focus_out()
        assert e._placeholder_shown is False

        # Очищаем текст — при потере фокуса placeholder показывается
        e.enter_edit_mode()
        e.set_text("")
        e.exit_edit_mode()
        assert e._placeholder_shown is True

        e.unmount()


# =============================================================================
# MODULE EXPORTS
# ==============================================================================


__all__: list[str] = [
    "TestThemedEntryConstructor",
    "TestThemedEntryMount",
    "TestThemedEntryTextOperations",
    "TestThemedEntryPlaceholder",
    "TestThemedEntryValidation",
    "TestThemedEntryErrorDisplay",
    "TestThemedEntryEditMode",
    "TestThemedEntrySync",
    "TestThemedEntryWorkflow",
]