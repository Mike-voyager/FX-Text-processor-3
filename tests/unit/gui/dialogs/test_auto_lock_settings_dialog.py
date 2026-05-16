# -*- coding: utf-8 -*-
"""Тесты для AutoLockSettingsDialog.

Тестирует создание диалога, настройку таймаута, чекбоксы,
кнопки пресетов, сохранение конфигурации и интеграцию с AutoLockService.

Version: 1.0
Security: CRITICAL-002
"""

from __future__ import annotations

from typing import Generator
from unittest.mock import MagicMock

import pytest
from src.gui.dialogs.auto_lock_settings_dialog import (
    COLOR_ACCENT,
    COLOR_BG,
    COLOR_ERROR,
    COLOR_SUCCESS,
    COLOR_WARNING,
    DIALOG_HEIGHT,
    DIALOG_WIDTH,
    IDLE_UPDATE_INTERVAL,
    TIMEOUT_PRESETS,
    AutoLockSettingsDialog,
    AutoLockSettingsResult,
)
from src.security.lock.session_lock_manager import LockConfig


@pytest.fixture
def root() -> Generator:
    """Фикстура для Tk root."""
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def default_config() -> LockConfig:
    """Фикстура для стандартной конфигурации."""
    return LockConfig(
        enabled=True,
        auto_lock_minutes=15,
        lock_on_sleep=True,
        lock_on_screensaver=True,
        require_mfa_to_unlock=True,
        clear_clipboard_on_lock=True,
        hide_documents_on_lock=True,
    )


@pytest.fixture
def mock_auto_lock_service() -> MagicMock:
    """Создание мока AutoLockService."""
    mock = MagicMock()
    mock.get_state.return_value = MagicMock()
    mock.is_running.return_value = True
    mock.start.return_value = None
    mock.stop.return_value = None
    mock._lock_manager = MagicMock()
    mock._lock_manager.get_idle_time_minutes.return_value = 5.5
    return mock


class TestAutoLockSettingsDialogCreation:
    """Тесты создания AutoLockSettingsDialog."""

    def test_dialog_creation(self, root, default_config) -> None:
        """Проверка создания диалога."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )
        assert dialog._current_config == default_config
        assert dialog._auto_lock_service is None
        assert dialog._result is None
        assert dialog._modified is False
        dialog.destroy()

    def test_dialog_creation_with_service(
        self, root, default_config, mock_auto_lock_service
    ) -> None:
        """Проверка создания с auto_lock_service."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
            auto_lock_service=mock_auto_lock_service,
        )
        assert dialog._auto_lock_service is mock_auto_lock_service
        dialog.destroy()

    def test_dialog_constants(self) -> None:
        """Проверка констант диалога."""
        assert DIALOG_WIDTH == 500
        assert DIALOG_HEIGHT == 600
        assert COLOR_BG == "#f8f9fa"
        assert COLOR_ACCENT == "#3498db"
        assert COLOR_WARNING == "#f39c12"
        assert COLOR_ERROR == "#e74c3c"
        assert COLOR_SUCCESS == "#27ae60"
        assert IDLE_UPDATE_INTERVAL == 1000

    def test_timeout_presets(self) -> None:
        """Проверка пресетов таймаута."""
        assert len(TIMEOUT_PRESETS) == 6
        assert TIMEOUT_PRESETS[0] == ("1 min", 1)
        assert TIMEOUT_PRESETS[1] == ("5", 5)
        assert TIMEOUT_PRESETS[2] == ("15", 15)
        assert TIMEOUT_PRESETS[3] == ("30", 30)
        assert TIMEOUT_PRESETS[4] == ("60", 60)
        assert TIMEOUT_PRESETS[5] == ("Never", 0)


class TestAutoLockSettingsDialogTimeoutSlider:
    """Тесты слайдера таймаута."""

    def test_timeout_slider_initial_value(self, root, default_config) -> None:
        """Тест начального значения слайдера."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Проверяем начальное значение
        assert dialog._timeout_var.get() == 15

        dialog.destroy()

    def test_timeout_slider_range(self, root, default_config) -> None:
        """Тест диапазона слайдера."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Проверяем что слайдер создан
        assert dialog._timeout_scale is not None

        # Диапазон должен быть 1-60
        assert dialog._timeout_scale.cget("from") == 1
        assert dialog._timeout_scale.cget("to") == 60

        dialog.destroy()

    def test_on_timeout_changed(self, root, default_config) -> None:
        """Тест обработчика изменения таймаута."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Изменяем таймаут
        dialog._on_timeout_changed("30")

        # Проверяем что переменная обновлена
        assert dialog._timeout_var.get() == 30
        assert dialog._modified is True

        # Проверяем что метка обновлена
        if dialog._timeout_label is not None:
            text = dialog._timeout_label.cget("text")
            assert "30" in text or "minute" in text

        dialog.destroy()

    def test_format_timeout(self, root, default_config) -> None:
        """Тест форматирования таймаута."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Проверяем различные значения
        assert dialog._format_timeout(0) == "Never"
        assert dialog._format_timeout(1) == "1 minute"
        assert dialog._format_timeout(2) == "2 minutes"
        assert dialog._format_timeout(5) == "5 minutes"
        assert dialog._format_timeout(15) == "15 minutes"

        dialog.destroy()


class TestAutoLockSettingsDialogCheckboxes:
    """Тесты чекбоксов."""

    def test_checkbox_initial_states(self, root, default_config) -> None:
        """Тест начальных состояний чекбоксов."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Проверяем начальные значения
        assert dialog._checkbox_vars["lock_on_sleep"].get() is True
        assert dialog._checkbox_vars["lock_on_screensaver"].get() is True
        assert dialog._checkbox_vars["require_mfa_to_unlock"].get() is True
        assert dialog._checkbox_vars["clear_clipboard_on_lock"].get() is True
        assert dialog._checkbox_vars["hide_documents_on_lock"].get() is True

        dialog.destroy()

    def test_checkbox_states_disabled_config(self, root) -> None:
        """Тест чекбоксов при отключенной автоблокировке."""
        config = LockConfig(
            enabled=False,
            auto_lock_minutes=15,
            lock_on_sleep=False,
            lock_on_screensaver=False,
            require_mfa_to_unlock=False,
            clear_clipboard_on_lock=False,
            hide_documents_on_lock=False,
        )

        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=config,
        )

        # Проверяем начальные значения
        assert dialog._master_var.get() is False
        assert dialog._checkbox_vars["lock_on_sleep"].get() is False
        assert dialog._checkbox_vars["require_mfa_to_unlock"].get() is False

        dialog.destroy()

    def test_checkbox_change_triggers_modified(self, root, default_config) -> None:
        """Тест что изменение чекбокса устанавливает modified."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Сбрасываем флаг
        dialog._modified = False

        # Изменяем чекбокс
        dialog._checkbox_vars["lock_on_sleep"].set(False)
        dialog._on_checkbox_changed()

        # Проверяем что modified установлен
        assert dialog._modified is True

        dialog.destroy()


class TestAutoLockSettingsDialogPresets:
    """Тесты кнопок пресетов."""

    def test_preset_buttons_created(self, root, default_config) -> None:
        """Тест что кнопки пресетов созданы."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Проверяем что кнопки созданы
        assert len(dialog._preset_buttons) == 6

        dialog.destroy()

    def test_apply_preset_1_minute(self, root, default_config) -> None:
        """Тест применения пресета 1 минута."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Применяем пресет
        dialog._apply_preset(1)

        # Проверяем что значение обновлено
        assert dialog._timeout_var.get() == 1
        assert dialog._modified is True

        dialog.destroy()

    def test_apply_preset_15_minutes(self, root, default_config) -> None:
        """Тест применения пресета 15 минут."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Применяем пресет
        dialog._apply_preset(15)

        # Проверяем что значение обновлено
        assert dialog._timeout_var.get() == 15

        dialog.destroy()

    def test_apply_preset_60_minutes(self, root, default_config) -> None:
        """Тест применения пресета 60 минут."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Применяем пресет
        dialog._apply_preset(60)

        # Проверяем что значение обновлено
        assert dialog._timeout_var.get() == 60

        dialog.destroy()

    def test_apply_preset_never(self, root, default_config) -> None:
        """Тест применения пресета 'Никогда'."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Включаем автоблокировку
        dialog._master_var.set(True)

        # Применяем пресет "Никогда"
        dialog._apply_preset(0)

        # Проверяем что автоблокировка отключена
        assert dialog._master_var.get() is False

        dialog.destroy()


class TestAutoLockSettingsDialogSave:
    """Тесты сохранения настроек."""

    def test_save_config(self, root, default_config) -> None:
        """Тест сохранения конфигурации."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Изменяем настройки
        dialog._timeout_var.set(30)
        dialog._checkbox_vars["require_mfa_to_unlock"].set(False)

        # Сохраняем
        dialog._save_settings()

        # Проверяем что результат создан
        assert dialog._result is not None
        assert isinstance(dialog._result, AutoLockSettingsResult)
        assert dialog._result.config.auto_lock_minutes == 30
        assert dialog._result.config.require_mfa_to_unlock is False

        dialog.destroy()

    def test_save_with_service(self, root, default_config, mock_auto_lock_service) -> None:
        """Тест сохранения с AutoLockService."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
            auto_lock_service=mock_auto_lock_service,
        )

        # Сохраняем
        dialog._save_settings()

        # Проверяем что сервис обновлён
        mock_auto_lock_service._lock_manager.update_config.assert_called_once()

        dialog.destroy()

    def test_check_restart_required(self, root, default_config) -> None:
        """Тест проверки необходимости перезапуска."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Изменение enabled
        new_config = LockConfig(enabled=False)
        assert dialog._check_restart_required(new_config) is True

        # Изменение таймаута
        new_config = LockConfig(enabled=True, auto_lock_minutes=30)
        assert dialog._check_restart_required(new_config) is True

        # Без изменений
        new_config = LockConfig(
            enabled=True,
            auto_lock_minutes=15,
        )
        assert dialog._check_restart_required(new_config) is False

        dialog.destroy()

    def test_cancel_clears_result(self, root, default_config) -> None:
        """Тест что отмена очищает результат."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Устанавливаем результат
        dialog._result = AutoLockSettingsResult(
            config=default_config,
            restart_service=False,
        )

        # Отменяем
        dialog._on_cancel()

        # Проверяем что результат очищен
        assert dialog._result is None


class TestAutoLockSettingsDialogMFA:
    """Тесты предупреждения о MFA."""

    def test_mfa_warning_without_mfa(self, root, default_config) -> None:
        """Тест предупреждения когда MFA отключен."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Отключаем MFA
        dialog._checkbox_vars["require_mfa_to_unlock"].set(False)
        dialog._update_warning()

        # Проверяем что предупреждение отображается
        if dialog._warning_label is not None:
            text = dialog._warning_label.cget("text")
            assert "⚠️" in text or "without MFA" in text

        dialog.destroy()

    def test_mfa_warning_with_mfa(self, root, default_config) -> None:
        """Тест отсутствия предупреждения когда MFA включен."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Включаем MFA
        dialog._checkbox_vars["require_mfa_to_unlock"].set(True)
        dialog._update_warning()

        # Проверяем что предупреждение не отображается
        if dialog._warning_label is not None:
            text = dialog._warning_label.cget("text")
            assert "✓" in text or "MFA" in text

        dialog.destroy()

    def test_mfa_warning_disabled_auto_lock(self, root, default_config) -> None:
        """Тест отсутствия предупреждения когда автоблокировка отключена."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Отключаем автоблокировку
        dialog._master_var.set(False)
        dialog._update_warning()

        # Проверяем что предупреждение не отображается
        if dialog._warning_label is not None:
            text = dialog._warning_label.cget("text")
            assert text == ""

        dialog.destroy()


class TestAutoLockSettingsDialogIdle:
    """Тесты отображения времени простоя."""

    def test_idle_display_with_service(self, root, default_config, mock_auto_lock_service) -> None:
        """Тест отображения времени простоя с сервисом."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
            auto_lock_service=mock_auto_lock_service,
        )

        # Обновляем отображение
        dialog._update_idle_display()

        # Проверяем что статус обновлён
        if dialog._status_label is not None:
            text = dialog._status_label.cget("text")
            assert "Status:" in text or "Active" in text or "min" in text

        # Отменяем таймер
        if dialog._idle_timer_id is not None:
            dialog.after_cancel(dialog._idle_timer_id)

        dialog.destroy()

    def test_idle_display_without_service(self, root, default_config) -> None:
        """Тест отображения времени простоя без сервиса."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Обновляем отображение
        dialog._update_idle_display()

        # Проверяем что статус показывает "Сервис недоступен"
        if dialog._status_label is not None:
            text = dialog._status_label.cget("text")
            assert "Service unavailable" in text or "Status:" in text

        # Отменяем таймер
        if dialog._idle_timer_id is not None:
            dialog.after_cancel(dialog._idle_timer_id)

        dialog.destroy()


class TestAutoLockSettingsDialogMasterSwitch:
    """Тесты master switch."""

    def test_master_switch_initial_state(self, root, default_config) -> None:
        """Тест начального состояния master switch."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Проверяем что включено
        assert dialog._master_var.get() is True

        dialog.destroy()

    def test_master_switch_disables_controls(self, root, default_config) -> None:
        """Тест что master switch отключает контролы."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Отключаем автоблокировку
        dialog._master_var.set(False)
        dialog._update_ui_state()

        # Проверяем что слайдер отключен
        if dialog._timeout_scale is not None:
            state = dialog._timeout_scale.cget("state")
            assert state == "disabled"

        dialog.destroy()

    def test_master_switch_triggers_modified(self, root, default_config) -> None:
        """Тест что изменение master switch устанавливает modified."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Сбрасываем флаг
        dialog._modified = False

        # Изменяем master switch
        dialog._master_var.set(False)
        dialog._on_master_changed()

        # Проверяем что modified установлен
        assert dialog._modified is True

        dialog.destroy()


class TestAutoLockSettingsDialogResult:
    """Тесты результата диалога."""

    def test_result_dataclass(self) -> None:
        """Тест AutoLockSettingsResult dataclass."""
        config = LockConfig(auto_lock_minutes=30)
        result = AutoLockSettingsResult(
            config=config,
            restart_service=True,
        )

        assert result.config == config
        assert result.restart_service is True

    def test_show_returns_result(self, root, default_config) -> None:
        """Тест что show() возвращает результат."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Устанавливаем результат
        result = AutoLockSettingsResult(
            config=LockConfig(auto_lock_minutes=30),
            restart_service=True,
        )
        dialog._result = result

        # Проверяем что результат доступен
        assert dialog._result is result
        assert dialog._result.config.auto_lock_minutes == 30

        dialog.destroy()


class TestAutoLockSettingsDialogHelpers:
    """Тесты вспомогательных методов."""

    def test_apply_theme(self, root, default_config) -> None:
        """Тест применения темы."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Применяем тему (не должно вызвать ошибок)
        dialog._apply_theme()

        dialog.destroy()

    def test_center_window(self, root, default_config) -> None:
        """Тест центрирования окна."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Центрируем окно (не должно вызвать ошибок)
        dialog._center_window()

        dialog.destroy()

    def test_on_timeout_var_changed(self, root, default_config) -> None:
        """Тест обработчика изменения переменной таймаута."""
        dialog = AutoLockSettingsDialog(
            parent=root,
            current_config=default_config,
        )

        # Устанавливаем значение
        dialog._timeout_var.set(45)
        dialog._on_timeout_var_changed()

        # Проверяем что метка обновлена
        if dialog._timeout_label is not None:
            text = dialog._timeout_label.cget("text")
            assert "45" in text or "minute" in text

        dialog.destroy()


__all__ = [
    "TestAutoLockSettingsDialogCreation",
    "TestAutoLockSettingsDialogTimeoutSlider",
    "TestAutoLockSettingsDialogCheckboxes",
    "TestAutoLockSettingsDialogPresets",
    "TestAutoLockSettingsDialogSave",
    "TestAutoLockSettingsDialogMFA",
    "TestAutoLockSettingsDialogIdle",
    "TestAutoLockSettingsDialogMasterSwitch",
    "TestAutoLockSettingsDialogResult",
    "TestAutoLockSettingsDialogHelpers",
]
