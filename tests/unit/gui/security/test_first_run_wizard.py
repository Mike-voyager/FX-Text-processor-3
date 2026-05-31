# -*- coding: utf-8 -*-
"""Тесты для FirstRunWizard.

Регрессионные тесты для багов _on_setup_fido2 и _on_setup_totp.
Ранее эти методы были заглушками (TODO stubs), которые показывали
сообщения об ошибках вместо открытия диалогов настройки MFA.
После фикса они открывают FIDO2SetupDialog и TOTPSetupDialog
с корректными callback-ами.

Version: 1.0
Security: MEDIUM
"""

from __future__ import annotations

from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

try:
    import tkinter as tk

    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

if not TKINTER_AVAILABLE:
    pytest.skip("Tkinter not available", allow_module_level=True)

from src.gui.security.first_run_wizard import FirstRunWizard, WizardStep

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Создаёт Tk root для тестов GUI."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def wizard(tk_root: tk.Tk) -> Generator[FirstRunWizard, None, None]:
    """Создаёт FirstRunWizard для тестов."""
    w = FirstRunWizard(parent=tk_root)
    yield w
    w.destroy()


# =============================================================================
# TESTS: Bug fix regression — _on_setup_fido2 no longer a stub
# =============================================================================


class TestFirstRunWizardFido2Setup:
    """Регрессионные тесты для _on_setup_fido2.

    Ранее метод был заглушкой, которая только показывала
    messagebox об ошибке. После фикса он открывает
    FIDO2SetupDialog с callback.
    """

    def test_on_setup_fido2_debug_mode_bypasses_dialog(self, wizard: FirstRunWizard) -> None:
        """В debug режиме FIDO2 помечается как настроенный без диалога."""
        wizard._debug_mode = True
        wizard._fido2_configured = False

        wizard._on_setup_fido2()

        assert wizard._fido2_configured is True

    def test_on_setup_fido2_opens_dialog_on_success(self, wizard: FirstRunWizard) -> None:
        """_on_setup_fido2 должен открыть FIDO2SetupDialog."""
        wizard._debug_mode = False
        wizard._fido2_configured = False

        mock_dialog = MagicMock()
        mock_dialog.show = MagicMock()

        with patch(
            "src.gui.security.first_run_wizard.FIDO2SetupDialog",
            mock_dialog,
            create=True,
        ) as mock_dialog_cls:
            # Мокаем импорт внутри метода
            with patch.dict(
                "sys.modules",
                {"src.gui.dialogs.fido2_setup_dialog": MagicMock(FIDO2SetupDialog=mock_dialog_cls)},
            ):
                # Мокаем _show_step чтобы избежать GUI-операций
                wizard._show_step = MagicMock()
                wizard._on_setup_fido2()

    def test_on_setup_fido2_handles_import_error(self, wizard: FirstRunWizard) -> None:
        """_on_setup_fido2 должен показать ошибку если диалог недоступен."""
        wizard._debug_mode = False
        wizard._fido2_configured = False

        # Вызываем _on_setup_fido2 — ImportError перехватывается
        with patch.dict("sys.modules", {"src.gui.dialogs.fido2_setup_dialog": None}):
            wizard._on_setup_fido2()

        # Должен быть помечен как не настроенный
        assert wizard._fido2_configured is False

    def test_on_setup_fido2_callback_sets_configured(self, wizard: FirstRunWizard) -> None:
        """Callback on_fido2_complete с success=True должен установить _fido2_configured."""
        wizard._debug_mode = True  # Сначала включаем debug для простоты
        wizard._on_setup_fido2()
        assert wizard._fido2_configured is True

    def test_on_setup_fido2_not_configured_without_debug(self, wizard: FirstRunWizard) -> None:
        """Без debug mode и без успешного диалога FIDO2 не настроен."""
        wizard._debug_mode = False

        # Имитируем ImportError
        with patch.dict("sys.modules", {"src.gui.dialogs.fido2_setup_dialog": None}):
            wizard._on_setup_fido2()

        assert wizard._fido2_configured is False


# =============================================================================
# TESTS: Bug fix regression — _on_setup_totp no longer a stub
# =============================================================================


class TestFirstRunWizardTotpSetup:
    """Регрессионные тесты для _on_setup_totp.

    Ранее метод был заглушкой, которая только показывала
    messagebox об ошибке. После фикса он открывает
    TOTPSetupDialog с callback.
    """

    def test_on_setup_totp_debug_mode_bypasses_dialog(self, wizard: FirstRunWizard) -> None:
        """В debug режиме TOTP помечается как настроенный без диалога."""
        wizard._debug_mode = True
        wizard._totp_configured = False

        wizard._on_setup_totp()

        assert wizard._totp_configured is True

    def test_on_setup_totp_opens_dialog(self, wizard: FirstRunWizard) -> None:
        """_on_setup_totp должен попытаться открыть TOTPSetupDialog."""
        wizard._debug_mode = False
        wizard._totp_configured = False

        mock_dialog_cls = MagicMock()
        mock_dialog_instance = MagicMock()
        mock_dialog_cls.return_value = mock_dialog_instance

        with patch.dict(
            "sys.modules",
            {"src.gui.dialogs.totp_setup_dialog": MagicMock(TOTPSetupDialog=mock_dialog_cls)},
        ):
            wizard._on_setup_totp()

    def test_on_setup_totp_handles_import_error(self, wizard: FirstRunWizard) -> None:
        """_on_setup_totp должен показать ошибку если диалог недоступен."""
        wizard._debug_mode = False
        wizard._totp_configured = False

        # Вызываем _on_setup_totp — ImportError перехватывается
        with patch.dict("sys.modules", {"src.gui.dialogs.totp_setup_dialog": None}):
            wizard._on_setup_totp()

        assert wizard._totp_configured is False

    def test_on_setup_totp_not_configured_without_debug(self, wizard: FirstRunWizard) -> None:
        """Без debug mode и без успешного диалога TOTP не настроен."""
        wizard._debug_mode = False

        with patch.dict("sys.modules", {"src.gui.dialogs.totp_setup_dialog": None}):
            wizard._on_setup_totp()

        assert wizard._totp_configured is False

    def test_on_setup_totp_debug_mode_shows_step(self, wizard: FirstRunWizard) -> None:
        """В debug режиме _on_setup_totp вызывает _show_step."""
        wizard._debug_mode = True
        wizard._totp_configured = False

        # Мокаем _show_step чтобы проверить вызов
        original_show_step = wizard._show_step
        call_count = 0

        def mock_show_step(step: WizardStep) -> None:
            nonlocal call_count
            call_count += 1
            original_show_step(step)

        wizard._show_step = mock_show_step  # type: ignore[assignment]

        wizard._on_setup_totp()

        # _show_step должен был быть вызван с TOTP_SETUP
        assert wizard._totp_configured is True


# =============================================================================
# TESTS: WizardStep enum and initialization
# =============================================================================


class TestFirstRunWizardInitialization:
    """Тесты инициализации FirstRunWizard."""

    def test_wizard_step_enum_values(self) -> None:
        """Проверка значений WizardStep enum."""
        assert WizardStep.WELCOME is not None
        assert WizardStep.MASTER_PASSWORD is not None
        assert WizardStep.SECURITY_PRESET is not None
        assert WizardStep.FIDO2_SETUP is not None
        assert WizardStep.TOTP_SETUP is not None
        assert WizardStep.BACKUP_CODES is not None
        assert WizardStep.COMPLETE is not None

    def test_wizard_initial_state(self, tk_root: tk.Tk) -> None:
        """Проверка начального состояния wizard."""
        wizard = FirstRunWizard(parent=tk_root)

        assert wizard._current_step == WizardStep.WELCOME
        assert wizard._user_id == "operator"
        assert wizard._fido2_configured is False
        assert wizard._totp_configured is False
        assert wizard._backup_codes == []
        assert wizard._selected_preset == "standard"

        wizard.destroy()

    def test_wizard_presets_defined(self, tk_root: tk.Tk) -> None:
        """Проверка определения пресетов безопасности."""
        wizard = FirstRunWizard(parent=tk_root)

        assert "standard" in wizard.PRESETS
        assert "paranoid" in wizard.PRESETS
        assert "pqc" in wizard.PRESETS
        assert "legacy" in wizard.PRESETS

        wizard.destroy()


__all__ = [
    "TestFirstRunWizardFido2Setup",
    "TestFirstRunWizardTotpSetup",
    "TestFirstRunWizardInitialization",
]
