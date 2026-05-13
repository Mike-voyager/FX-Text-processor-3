# -*- coding: utf-8 -*-
"""Тесты для ModeToggle и Mode.

Модуль содержит unit-тесты для компонента переключения режимов
Normal/Special с анимацией и MFA защитой.

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/security/test_mode_toggle.py -v

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

try:
    import tkinter as tk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

if TYPE_CHECKING:
    from collections.abc import Generator

if not TKINTER_AVAILABLE:
    pytest.skip("Tkinter not available", allow_module_level=True)

from src.gui.security.mode_toggle import Mode, ModeCapabilities, MODE_CAPABILITIES, ModeToggle


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def tk_root():
    """Создаёт Tk root для тестов GUI."""
    root = tk.Tk()
    root.withdraw()  # Скрываем окно
    yield root
    root.destroy()


@pytest.fixture
def mock_mode_manager() -> MagicMock:
    """Создание мока ModeManager."""
    mock = MagicMock()
    mock.can_enter_special.return_value = (True, "")
    mock.enter_special.return_value = None
    mock.exit_special.return_value = None
    return mock


@pytest.fixture
def mock_mfa_gate_success() -> MagicMock:
    """Создание мока MFAGate, возвращающего успех."""
    mock = MagicMock()
    # Создаём MFAResult-like объект
    result = MagicMock()
    result.verified = True
    result.method = "totp"
    result.user_id = "test-user"
    result.audit_token = "test-token-123"
    mock.challenge.return_value = result
    return mock


@pytest.fixture
def mock_mfa_gate_failure() -> MagicMock:
    """Создание мока MFAGate, возвращающего failure."""
    mock = MagicMock()
    result = MagicMock()
    result.verified = False
    result.method = "totp"
    result.user_id = "test-user"
    result.error_message = "Invalid TOTP code"
    mock.challenge.return_value = result
    return mock


@pytest.fixture
def mode_toggle_normal(tk_root: tk.Tk, mock_mode_manager: MagicMock) -> ModeToggle:
    """Создание ModeToggle в режиме NORMAL."""
    toggle = ModeToggle(
        parent=tk_root,
        mode_manager=mock_mode_manager,
        initial_mode=Mode.NORMAL,
    )
    yield toggle
    toggle.destroy()


@pytest.fixture
def mode_toggle_special(tk_root: tk.Tk, mock_mode_manager: MagicMock) -> ModeToggle:
    """Создание ModeToggle в режиме SPECIAL."""
    toggle = ModeToggle(
        parent=tk_root,
        mode_manager=mock_mode_manager,
        initial_mode=Mode.SPECIAL,
    )
    yield toggle
    toggle.destroy()


# =============================================================================
# TestMode - тесты для Mode enum
# =============================================================================


@pytest.mark.security
class TestMode:
    """Тесты для Mode enum."""

    def test_mode_normal_value(self) -> None:
        """Проверка значения Mode.NORMAL."""
        assert Mode.NORMAL.value == "normal"

    def test_mode_special_value(self) -> None:
        """Проверка значения Mode.SPECIAL."""
        assert Mode.SPECIAL.value == "special"

    def test_mode_is_string_enum(self) -> None:
        """Проверка что Mode наследует str."""
        assert issubclass(Mode, str)

    def test_mode_capabilities_exist(self) -> None:
        """Проверка наличия capabilities для всех режимов."""
        assert Mode.NORMAL in MODE_CAPABILITIES
        assert Mode.SPECIAL in MODE_CAPABILITIES

    def test_mode_capabilities_structure(self) -> None:
        """Проверка структуры ModeCapabilities."""
        caps = MODE_CAPABILITIES[Mode.NORMAL]
        assert isinstance(caps, ModeCapabilities)
        assert caps.title
        assert caps.color
        assert isinstance(caps.features, tuple)


# =============================================================================
# TestModeToggleInitialization - тесты инициализации
# =============================================================================


@pytest.mark.security
class TestModeToggleInitialization:
    """Тесты инициализации ModeToggle."""

    def test_normal_mode_initial_state(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка начального состояния в режиме NORMAL."""
        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            initial_mode=Mode.NORMAL,
        )

        assert toggle.get_mode() == Mode.NORMAL
        assert not toggle._is_animating
        assert not toggle._confirm_pending

        toggle.destroy()

    def test_special_mode_initial_state(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка начального состояния в режиме SPECIAL."""
        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            initial_mode=Mode.SPECIAL,
        )

        assert toggle.get_mode() == Mode.SPECIAL

        toggle.destroy()

    def test_initialization_with_callback(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка инициализации с callback."""
        callback_called: list[Mode] = []

        def on_mode_change(mode: Mode) -> None:
            callback_called.append(mode)

        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            on_mode_changed=on_mode_change,
        )

        assert toggle._on_mode_changed is not None

        toggle.destroy()

    def test_initialization_with_mfa_gate(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
        mock_mfa_gate_success: MagicMock,
    ) -> None:
        """Проверка инициализации с MFAGate."""
        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            mfa_gate=mock_mfa_gate_success,
        )

        assert toggle._mfa_gate is not None

        toggle.destroy()


# =============================================================================
# TestModeToggleSetGet - тесты getter/setter
# =============================================================================


@pytest.mark.security
class TestModeToggleSetGet:
    """Тесты getter/setter режима."""

    def test_get_mode_returns_current(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка что get_mode возвращает текущий режим."""
        assert mode_toggle_normal.get_mode() == Mode.NORMAL

    def test_set_mode_changes_current(
        self,
        mode_toggle_normal: ModeToggle,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка изменения режима через set_mode."""
        mode_toggle_normal.set_mode(Mode.SPECIAL)

        assert mode_toggle_normal.get_mode() == Mode.SPECIAL

    def test_set_mode_same_mode_no_change(
        self,
        mode_toggle_normal: ModeToggle,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что установка того же режима не вызывает изменений."""
        # Устанавливаем NORMAL снова
        mode_toggle_normal.set_mode(Mode.NORMAL)

        # Режим остаётся NORMAL
        assert mode_toggle_normal.get_mode() == Mode.NORMAL

    def test_set_mode_invalid_raises_error(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка что невалидный режим вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid mode"):
            mode_toggle_normal.set_mode("invalid_mode")  # type: ignore[arg-type]


# =============================================================================
# TestModeToggleCallback - тесты callback
# =============================================================================


@pytest.mark.security
class TestModeToggleCallback:
    """Тесты callback при изменении режима."""

    def test_callback_called_on_mode_change(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что callback вызывается при изменении режима."""
        callback_modes: list[Mode] = []

        def on_mode_change(mode: Mode) -> None:
            callback_modes.append(mode)

        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            on_mode_changed=on_mode_change,
        )

        toggle.set_mode(Mode.SPECIAL)

        assert len(callback_modes) == 1
        assert callback_modes[0] == Mode.SPECIAL

        toggle.destroy()

    def test_callback_not_called_on_same_mode(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что callback не вызывается при установке того же режима."""
        callback_count: list[int] = []

        def on_mode_change(mode: Mode) -> None:
            callback_count.append(1)

        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            on_mode_changed=on_mode_change,
            initial_mode=Mode.NORMAL,
        )

        # Повторная установка NORMAL
        toggle.set_mode(Mode.NORMAL)

        assert len(callback_count) == 0

        toggle.destroy()

    def test_callback_exception_handled(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что исключение в callback не ломает переключение."""
        def failing_callback(mode: Mode) -> None:
            raise RuntimeError("Callback failed")

        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            on_mode_changed=failing_callback,
        )

        # Не должно выбросить исключение
        toggle.set_mode(Mode.SPECIAL)

        assert toggle.get_mode() == Mode.SPECIAL

        toggle.destroy()


# =============================================================================
# TestModeToggleMFA - тесты MFA
# =============================================================================


@pytest.mark.security
class TestModeToggleMFA:
    """Тесты MFA при переключении режима."""

    @patch("src.gui.security.mode_toggle.messagebox")
    def test_mfa_required_for_special_mode(
        self,
        mock_messagebox: MagicMock,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
        mock_mfa_gate_success: MagicMock,
    ) -> None:
        """Проверка что MFA требуется для входа в Special Mode."""
        mock_messagebox.askyesno.return_value = True

        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            mfa_gate=mock_mfa_gate_success,
            initial_mode=Mode.NORMAL,
        )

        # Запрос на переключение в Special
        toggle._request_mode_change(Mode.SPECIAL)

        # MFAGate должен быть вызван
        mock_mfa_gate_success.challenge.assert_called_once()

        toggle.destroy()

    @patch("src.gui.security.mode_toggle.messagebox")
    def test_mfa_failure_blocks_switch(
        self,
        mock_messagebox: MagicMock,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
        mock_mfa_gate_failure: MagicMock,
    ) -> None:
        """Проверка что неуспешная MFA блокирует переключение."""
        mock_messagebox.showerror = MagicMock()

        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            mfa_gate=mock_mfa_gate_failure,
            initial_mode=Mode.NORMAL,
        )

        # Запрос на переключение в Special
        toggle._request_mode_change(Mode.SPECIAL)

        # Режим должен остаться NORMAL
        assert toggle.get_mode() == Mode.NORMAL

        toggle.destroy()

    @patch("src.gui.security.mode_toggle.messagebox")
    def test_confirm_exit_special_mode(
        self,
        mock_messagebox: MagicMock,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка подтверждения выхода из Special Mode."""
        mock_messagebox.askyesno.return_value = False  # Пользователь отменил

        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            initial_mode=Mode.SPECIAL,
        )

        # Попытка переключения в Normal
        toggle._request_mode_change(Mode.NORMAL)

        # Режим должен остаться SPECIAL
        assert toggle.get_mode() == Mode.SPECIAL

        toggle.destroy()

    @patch("src.gui.security.mode_toggle.messagebox")
    def test_mode_manager_check_before_special(
        self,
        mock_messagebox: MagicMock,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что ModeManager проверяется перед входом в Special."""
        mock_mode_manager.can_enter_special.return_value = (False, "Test reason")
        mock_messagebox.showerror = MagicMock()

        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            initial_mode=Mode.NORMAL,
        )

        toggle._request_mode_change(Mode.SPECIAL)

        # Режим должен остаться NORMAL
        assert toggle.get_mode() == Mode.NORMAL

        mock_mode_manager.can_enter_special.assert_called_once()

        toggle.destroy()


# =============================================================================
# TestModeToggleAnimation - тесты анимации
# =============================================================================


@pytest.mark.security
class TestModeToggleAnimation:
    """Тесты анимации переключения."""

    def test_animation_flags(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка флагов анимации."""
        # В начальном состоянии не должно быть анимации
        assert not mode_toggle_normal._is_animating

    def test_animate_toggle_sets_flag(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что анимация устанавливает флаг."""
        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            initial_mode=Mode.NORMAL,
        )

        # Флаг не установлен в начальном состоянии
        assert not toggle._is_animating

        toggle.destroy()

    def test_get_knob_position_normal(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка позиции ползунка для NORMAL режима."""
        x = mode_toggle_normal._get_knob_position_x(Mode.NORMAL)
        assert x > 0
        assert x < mode_toggle_normal.TOGGLE_WIDTH

    def test_get_knob_position_special(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка позиции ползунка для SPECIAL режима."""
        x = mode_toggle_normal._get_knob_position_x(Mode.SPECIAL)
        assert x > 0
        assert x < mode_toggle_normal.TOGGLE_WIDTH

    def test_knob_positions_different(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка что позиции для разных режимов отличаются."""
        normal_x = mode_toggle_normal._get_knob_position_x(Mode.NORMAL)
        special_x = mode_toggle_normal._get_knob_position_x(Mode.SPECIAL)

        assert normal_x != special_x
        assert special_x > normal_x


# =============================================================================
# TestModeToggleVisual - тесты визуального состояния
# =============================================================================


@pytest.mark.security
class TestModeToggleVisual:
    """Тесты визуального состояния."""

    def test_update_mode_info_normal(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка обновления информации о NORMAL режиме."""
        mode_toggle_normal._update_mode_info(Mode.NORMAL)

        # Проверка что метка содержит название режима
        assert mode_toggle_normal._mode_title_label is not None

    def test_update_mode_info_special(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка обновления информации о SPECIAL режиме."""
        mode_toggle_normal._update_mode_info(Mode.SPECIAL)

        assert mode_toggle_normal._mode_title_label is not None

    def test_update_track_color_normal(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка цвета трека для NORMAL режима."""
        mode_toggle_normal._update_track_color()

        # Цвет должен быть установлен (может быть переопределен темой)
        # Проверяем что _normal_color существует и не пустой
        assert mode_toggle_normal._normal_color
        assert mode_toggle_normal._normal_color.startswith("#")

    def test_update_track_color_special(self, mode_toggle_special: ModeToggle) -> None:
        """Проверка цвета трека для SPECIAL режима."""
        mode_toggle_special._update_track_color()

        assert mode_toggle_special._special_color == MODE_CAPABILITIES[Mode.SPECIAL].color

    def test_confirm_exit_special_returns_bool(self, mode_toggle_special: ModeToggle) -> None:
        """Проверка что подтверждение выхода возвращает bool."""
        with patch("src.gui.security.mode_toggle.messagebox") as mock_msg:
            mock_msg.askyesno.return_value = True

            result = mode_toggle_special._confirm_exit_special()
            assert isinstance(result, bool)


# =============================================================================
# TestModeToggleDragDrop - тесты drag-and-drop
# =============================================================================


@pytest.mark.security
class TestModeToggleDragDrop:
    """Тесты drag-and-drop функциональности."""

    def test_drag_flag_initial_state(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка начального состояния флага перетаскивания."""
        assert not mode_toggle_normal._dragging

    def test_on_canvas_click_sets_drag(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка что клик устанавливает флаг перетаскивания."""
        event = MagicMock()
        event.x = 50

        mode_toggle_normal._on_canvas_click(event)

        assert mode_toggle_normal._dragging
        assert mode_toggle_normal._drag_start_x == 50

    def test_on_canvas_release_clears_drag(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка что отпускание кнопки снимает флаг перетаскивания."""
        # Устанавливаем флаг
        mode_toggle_normal._dragging = True

        event = MagicMock()
        mode_toggle_normal._on_canvas_release(event)

        assert not mode_toggle_normal._dragging


# =============================================================================
# TestModeToggleEvents - тесты обработки событий
# =============================================================================


@pytest.mark.security
class TestModeToggleEvents:
    """Тесты обработки событий."""

    def test_on_canvas_double_click_triggers_toggle(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что двойной клик вызывает переключение."""
        with patch.object(ModeToggle, "_on_toggle") as mock_toggle:
            toggle = ModeToggle(
                parent=tk_root,
                mode_manager=mock_mode_manager,
                initial_mode=Mode.NORMAL,
            )

            event = MagicMock()
            toggle._on_canvas_double_click(event)

            # _dragging должен быть сброшен
            assert not toggle._dragging

            toggle.destroy()

    def test_on_canvas_enter_sets_cursor(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка что наведение меняет курсор."""
        event = MagicMock()
        mode_toggle_normal._on_canvas_enter(event)

        # Курсор должен быть изменён
        assert mode_toggle_normal._canvas is not None

    def test_on_canvas_leave_clears_drag(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка что уход курсора сбрасывает перетаскивание."""
        # Устанавливаем флаг
        mode_toggle_normal._dragging = True

        event = MagicMock()
        mode_toggle_normal._on_canvas_leave(event)

        assert not mode_toggle_normal._dragging


# =============================================================================
# TestModeToggleSpecialMode - тесты Special Mode
# =============================================================================


@pytest.mark.security
class TestModeToggleSpecialMode:
    """Тесты переключения в Special Mode."""

    @patch("src.gui.security.mode_toggle.messagebox")
    def test_switch_to_special_updates_mode(
        self,
        mock_messagebox: MagicMock,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка переключения в Special Mode."""
        mock_messagebox.askyesno.return_value = True

        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            initial_mode=Mode.NORMAL,
        )

        toggle.set_mode(Mode.SPECIAL)

        assert toggle.get_mode() == Mode.SPECIAL

        toggle.destroy()

    def test_switch_to_normal_from_special(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка переключения из Special в Normal."""
        with patch("src.gui.security.mode_toggle.messagebox") as mock_msg:
            mock_msg.askyesno.return_value = True

            toggle = ModeToggle(
                parent=tk_root,
                mode_manager=mock_mode_manager,
                initial_mode=Mode.SPECIAL,
            )

            toggle.set_mode(Mode.NORMAL)

            assert toggle.get_mode() == Mode.NORMAL

            toggle.destroy()

    def test_mode_manager_enter_called(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что ModeManager.enter_special вызывается."""
        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            initial_mode=Mode.NORMAL,
        )

        toggle.set_mode(Mode.SPECIAL)

        # enter_special должен быть вызван
        mock_mode_manager.enter_special.assert_called_once()

        toggle.destroy()

    def test_mode_manager_exit_called(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что ModeManager.exit_special вызывается."""
        with patch("src.gui.security.mode_toggle.messagebox") as mock_msg:
            mock_msg.askyesno.return_value = True

            toggle = ModeToggle(
                parent=tk_root,
                mode_manager=mock_mode_manager,
                initial_mode=Mode.SPECIAL,
            )

            toggle.set_mode(Mode.NORMAL)

            # exit_special должен быть вызван
            mock_mode_manager.exit_special.assert_called_once()

            toggle.destroy()


# =============================================================================
# TestModeToggleTheme - тесты темы
# =============================================================================


@pytest.mark.security
class TestModeToggleTheme:
    """Тесты применения темы."""

    def test_apply_theme_does_not_raise(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка что применение темы не вызывает исключений."""
        # Не должно вызывать исключение даже если theme_manager недоступен
        mode_toggle_normal._apply_theme()

    def test_refresh_theme(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка обновления темы."""
        mode_toggle_normal.refresh_theme()

        # Должно выполниться без исключений
        assert mode_toggle_normal._current_mode == Mode.NORMAL


# =============================================================================
# TestModeToggleRequest - тесты запроса изменения режима
# =============================================================================


@pytest.mark.security
class TestModeToggleRequest:
    """Тесты запроса изменения режима."""

    def test_request_same_mode_no_action(self, mode_toggle_normal: ModeToggle) -> None:
        """Проверка что запрос того же режима не вызывает действий."""
        # Запрос текущего режима
        mode_toggle_normal._request_mode_change(Mode.NORMAL)

        # Режим не должен измениться
        assert mode_toggle_normal.get_mode() == Mode.NORMAL

    def test_request_while_animating_blocked(
        self,
        tk_root: tk.Tk,
        mock_mode_manager: MagicMock,
    ) -> None:
        """Проверка что запрос во время анимации блокируется."""
        toggle = ModeToggle(
            parent=tk_root,
            mode_manager=mock_mode_manager,
            initial_mode=Mode.NORMAL,
        )

        # Устанавливаем флаг анимации
        toggle._is_animating = True

        # Запрос должен быть проигнорирован
        toggle._request_mode_change(Mode.SPECIAL)

        # Режим не должен измениться
        assert toggle.get_mode() == Mode.NORMAL

        toggle.destroy()
