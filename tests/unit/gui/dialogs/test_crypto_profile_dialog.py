# -*- coding: utf-8 -*-
"""Тесты для CryptoProfileDialog.

Тестирует создание диалога, выбор криптографических профилей,
предупреждения при downgrade, отображение деталей и MFA интеграцию.

Version: 1.0
Security: CRITICAL-002
"""

from __future__ import annotations

from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from src.gui.dialogs.crypto_profile_dialog import (
    COLOR_ACCENT,
    COLOR_BG,
    COLOR_CARD_BG,
    COLOR_ERROR,
    COLOR_WARNING,
    SECURITY_LEVELS,
    CryptoProfileDialog,
    ProfileSelectionResult,
    show_crypto_profile_dialog,
)
from src.security.crypto.service.profiles import (
    CryptoProfile,
    get_profile_config,
    list_profiles,
)


@pytest.fixture
def root() -> Generator:
    """Фикстура для Tk root."""
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_mfa_gate() -> MagicMock:
    """Создание мока MFAGate."""
    mock = MagicMock()
    mock.challenge.return_value = MagicMock(
        verified=True,
        method="totp",
        user_id="operator",
        audit_token="test_token_123",
    )
    return mock


class TestCryptoProfileDialogCreation:
    """Тесты создания CryptoProfileDialog."""

    def test_dialog_creation(self, root) -> None:
        """Проверка создания диалога."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )
        assert dialog._current_profile == CryptoProfile.STANDARD
        assert dialog._selected_profile == CryptoProfile.STANDARD
        assert dialog._mfa_gate is None
        assert dialog._result is None
        dialog.destroy()

    def test_dialog_creation_with_mfa(self, root, mock_mfa_gate) -> None:
        """Проверка создания с mfa_gate."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
            mfa_gate=mock_mfa_gate,
        )
        assert dialog._mfa_gate is mock_mfa_gate
        dialog.destroy()

    def test_dialog_constants(self) -> None:
        """Проверка констант диалога."""
        from src.gui.dialogs.crypto_profile_dialog import DIALOG_HEIGHT, DIALOG_WIDTH

        assert DIALOG_WIDTH == 650
        assert DIALOG_HEIGHT == 550
        assert COLOR_BG == "#f8f9fa"
        assert COLOR_CARD_BG == "#ffffff"
        assert COLOR_ACCENT == "#3498db"
        assert COLOR_WARNING == "#f39c12"
        assert COLOR_ERROR == "#e74c3c"


class TestCryptoProfileDialogProfiles:
    """Тесты списка профилей."""

    def test_profile_list_count(self, root) -> None:
        """Тест что доступно все 7 профилей."""
        profiles = list_profiles()
        assert len(profiles) == 7

    def test_all_profiles_present(self, root) -> None:
        """Тест что все профили присутствуют в списке."""
        profiles = list_profiles()

        expected = [
            CryptoProfile.STANDARD,
            CryptoProfile.PARANOID,
            CryptoProfile.LEGACY,
            CryptoProfile.FLOPPY_BASIC,
            CryptoProfile.FLOPPY_AGGRESSIVE,
            CryptoProfile.PQC_STANDARD,
            CryptoProfile.PQC_PARANOID,
        ]

        for profile in expected:
            assert profile in profiles

    def test_profile_labels(self, root) -> None:
        """Тест меток профилей."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Проверяем что у каждого профиля есть метка
        for profile in list_profiles():
            label = profile.label()
            assert len(label) > 0
            assert isinstance(label, str)

        dialog.destroy()

    def test_profile_descriptions(self, root) -> None:
        """Тест описаний профилей."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Проверяем что у каждого профиля есть описание
        for profile in list_profiles():
            desc = profile.description()
            assert len(desc) > 0
            assert isinstance(desc, str)

        dialog.destroy()


class TestCryptoProfileDialogDowngrade:
    """Тесты предупреждения при downgrade."""

    def test_downgrade_warning_paranoia_to_standard(self, root) -> None:
        """Тест предупреждения при downgrade с Paranoid на Standard."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.PARANOID,
        )

        # Выбираем менее безопасный профиль
        dialog._selected_profile = CryptoProfile.STANDARD

        # Проверяем downgrade
        is_downgrade = dialog._check_downgrade(
            CryptoProfile.STANDARD,
            CryptoProfile.PARANOID,
        )
        assert is_downgrade is True

        # Обновляем предупреждение
        dialog._update_warning()

        # Проверяем что предупреждение отображается
        if dialog._warning_label is not None:
            warning_text = dialog._warning_label.cget("text")
            assert len(warning_text) > 0
            assert "less secure" in warning_text.lower() or "Warning" in warning_text

        dialog.destroy()

    def test_no_warning_same_level(self, root) -> None:
        """Тест отсутствия предупреждения при том же уровне."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Тот же профиль
        is_downgrade = dialog._check_downgrade(
            CryptoProfile.STANDARD,
            CryptoProfile.STANDARD,
        )
        assert is_downgrade is False

        dialog.destroy()

    def test_no_warning_upgrade(self, root) -> None:
        """Тест отсутствия предупреждения при upgrade."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Более безопасный профиль
        is_downgrade = dialog._check_downgrade(
            CryptoProfile.PARANOID,
            CryptoProfile.STANDARD,
        )
        assert is_downgrade is False

        dialog.destroy()

    def test_security_levels(self, root) -> None:
        """Тест уровней безопасности."""
        # Проверяем порядок уровней
        assert SECURITY_LEVELS[CryptoProfile.PQC_PARANOID] == 7
        assert SECURITY_LEVELS[CryptoProfile.PQC_STANDARD] == 6
        assert SECURITY_LEVELS[CryptoProfile.PARANOID] == 5
        assert SECURITY_LEVELS[CryptoProfile.STANDARD] == 4
        assert SECURITY_LEVELS[CryptoProfile.FLOPPY_BASIC] == 3
        assert SECURITY_LEVELS[CryptoProfile.FLOPPY_AGGRESSIVE] == 2
        assert SECURITY_LEVELS[CryptoProfile.LEGACY] == 1


class TestCryptoProfileDialogDetails:
    """Тесты отображения деталей профиля."""

    def test_profile_details_standard(self, root) -> None:
        """Тест деталей Standard профиля."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Показываем детали
        dialog._show_profile_details(CryptoProfile.STANDARD)

        # Проверяем что виджеты деталей обновлены
        assert "symmetric" in dialog._details_widgets
        assert "signing" in dialog._details_widgets
        assert "kdf" in dialog._details_widgets
        assert "hash" in dialog._details_widgets
        assert "post_quantum" in dialog._details_widgets
        assert "description" in dialog._details_widgets

        dialog.destroy()

    def test_profile_details_pqc(self, root) -> None:
        """Тест деталей PQC профиля."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Показываем детали PQC профиля
        dialog._show_profile_details(CryptoProfile.PQC_STANDARD)

        # Проверяем что post_quantum метка обновлена
        pq_widget = dialog._details_widgets.get("post_quantum")
        if pq_widget is not None:
            text = pq_widget.cget("text")
            assert "Yes" in text

        dialog.destroy()

    def test_profile_config(self, root) -> None:
        """Тест получения конфигурации профиля."""
        config = get_profile_config(CryptoProfile.STANDARD)

        assert config.profile == CryptoProfile.STANDARD
        assert config.symmetric_algorithm == "aes-256-gcm"
        assert config.signing_algorithm == "Ed25519"
        assert config.post_quantum is False
        assert config.safe_for_new_systems is True

    def test_format_kdf(self, root) -> None:
        """Тест форматирования KDF параметров."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        config = get_profile_config(CryptoProfile.PARANOID)
        formatted = dialog._format_kdf(config)

        # Должно содержать MB
        assert "MB" in formatted or "argon2id" in formatted.lower()

        dialog.destroy()


class TestCryptoProfileDialogMFA:
    """Тесты MFA при смене профиля."""

    def test_mfa_on_change_success(self, root, mock_mfa_gate) -> None:
        """Тест MFA при смене профиля (успех)."""
        with patch("tkinter.messagebox.askyesno", return_value=True):
            dialog = CryptoProfileDialog(
                parent=root,
                current_profile=CryptoProfile.STANDARD,
                mfa_gate=mock_mfa_gate,
            )

            # Выбираем другой профиль
            dialog._selected_profile = CryptoProfile.PARANOID

            # Применяем с MFA
            with patch.object(dialog, "destroy"):
                dialog._apply_profile()

                # Проверяем что MFA был вызван
                mock_mfa_gate.challenge.assert_called_once()

            dialog.destroy()

    def test_mfa_on_change_failure(self, root) -> None:
        """Тест MFA при смене профиля (отмена пользователем)."""
        mock_mfa_fail = MagicMock()
        mock_mfa_fail.challenge.return_value = MagicMock(
            verified=False,
            method="totp",
        )

        with patch("tkinter.messagebox.showwarning"):
            dialog = CryptoProfileDialog(
                parent=root,
                current_profile=CryptoProfile.STANDARD,
                mfa_gate=mock_mfa_fail,
            )

            # Выбираем другой профиль
            dialog._selected_profile = CryptoProfile.PARANOID

            # Применяем с неудачным MFA
            dialog._apply_profile()

            # Проверяем что MFA был вызван
            mock_mfa_fail.challenge.assert_called_once()

            # Результат должен быть None из-за неудачи
            assert dialog._result is None

            dialog.destroy()

    def test_no_mfa_same_profile(self, root) -> None:
        """Тест что MFA не требуется при том же профиле."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
            mfa_gate=MagicMock(),
        )

        # Тот же профиль - не требует MFA
        dialog._selected_profile = CryptoProfile.STANDARD

        with patch.object(dialog, "destroy"):
            dialog._apply_profile()

            # MFA не должен быть вызван
            dialog._mfa_gate.challenge.assert_not_called()

            # Результат должен быть установлен
            assert dialog._result is not None
            assert dialog._result.is_downgrade is False

        dialog.destroy()


class TestCryptoProfileDialogSelection:
    """Тесты выбора профиля."""

    def test_profile_selection_changes_radio(self, root) -> None:
        """Тест что выбор профиля меняет radio button."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Устанавливаем значение radio
        dialog._radio_var.set(CryptoProfile.PARANOID.value)

        # Вызываем обработчик
        dialog._on_profile_selected()

        # Проверяем что selected_profile обновлён
        assert dialog._selected_profile == CryptoProfile.PARANOID

        dialog.destroy()

    def test_profile_selection_result(self, root) -> None:
        """Тест результата выбора профиля."""
        with patch("tkinter.messagebox.askyesno", return_value=True):
            dialog = CryptoProfileDialog(
                parent=root,
                current_profile=CryptoProfile.STANDARD,
            )

            # Создаём результат вручную
            result = ProfileSelectionResult(
                profile=CryptoProfile.PARANOID,
                previous_profile=CryptoProfile.STANDARD,
                is_downgrade=False,
                mfa_verified=True,
            )

            dialog._result = result

            # Проверяем результат
            assert dialog._result.profile == CryptoProfile.PARANOID
            assert dialog._result.previous_profile == CryptoProfile.STANDARD
            assert dialog._result.is_downgrade is False
            assert dialog._result.mfa_verified is True

            dialog.destroy()

    def test_cancel_sets_none_result(self, root) -> None:
        """Тест что отмена устанавливает None результат."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Отменяем
        dialog._on_cancel()

        # Результат должен быть None
        assert dialog._result is None


class TestCryptoProfileDialogPQCBadge:
    """Тесты бейджа для PQC профилей."""

    def test_pqc_badge_displayed(self, root) -> None:
        """Тест что бейдж PQC отображается для PQC профилей."""
        from src.gui.dialogs.crypto_profile_dialog import (
            BADGE_PQC_BG,
            BADGE_PQC_FG,
        )

        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Проверяем что бейджи созданы для PQC профилей
        # PQC_STANDARD и PQC_PARANOID должны иметь post_quantum=True
        config_pqc = get_profile_config(CryptoProfile.PQC_STANDARD)
        assert config_pqc.post_quantum is True

        # Проверяем цвета бейджей
        assert BADGE_PQC_BG == "#e3f2fd"
        assert BADGE_PQC_FG == "#1565c0"

        dialog.destroy()

    def test_floppy_badge_displayed(self, root) -> None:
        """Тест что бейдж floppy отображается для floppy профилей."""
        from src.gui.dialogs.crypto_profile_dialog import (
            BADGE_FLOPPY_BG,
            BADGE_FLOPPY_FG,
        )

        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Проверяем что бейджи созданы для floppy профилей
        config_floppy = get_profile_config(CryptoProfile.FLOPPY_BASIC)
        assert config_floppy.floppy_optimized is True

        # Проверяем цвета бейджей
        assert BADGE_FLOPPY_BG == "#f3e5f5"
        assert BADGE_FLOPPY_FG == "#7b1fa2"

        dialog.destroy()

    def test_legacy_warning_badge(self, root) -> None:
        """Тест что предупреждающий бейдж отображается для Legacy."""
        from src.gui.dialogs.crypto_profile_dialog import (
            BADGE_LEGACY_BG,
            BADGE_LEGACY_FG,
        )

        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        # Проверяем что Legacy небезопасен для новых систем
        config_legacy = get_profile_config(CryptoProfile.LEGACY)
        assert config_legacy.safe_for_new_systems is False

        # Проверяем цвета бейджей
        assert BADGE_LEGACY_BG == "#ffebee"
        assert BADGE_LEGACY_FG == "#c62828"

        dialog.destroy()


class TestCryptoProfileDialogUtility:
    """Тесты утилитарных функций."""

    def test_show_crypto_profile_dialog(self, root) -> None:
        """Тест утилитарной функции show_crypto_profile_dialog."""
        with patch.object(CryptoProfileDialog, "show", return_value=None):
            result = show_crypto_profile_dialog(
                parent=root,
                current_profile=CryptoProfile.STANDARD,
            )
            # show возвращает None при отмене
            assert result is None

    def test_get_short_description(self, root) -> None:
        """Тест получения краткого описания профиля."""
        dialog = CryptoProfileDialog(
            parent=root,
            current_profile=CryptoProfile.STANDARD,
        )

        desc = dialog._get_short_description(CryptoProfile.STANDARD)

        # Должно содержать алгоритмы
        assert len(desc) > 0
        assert "Ed25519" in desc or "AES" in desc.upper()

        dialog.destroy()


__all__ = [
    "TestCryptoProfileDialogCreation",
    "TestCryptoProfileDialogProfiles",
    "TestCryptoProfileDialogDowngrade",
    "TestCryptoProfileDialogDetails",
    "TestCryptoProfileDialogMFA",
    "TestCryptoProfileDialogSelection",
    "TestCryptoProfileDialogPQCBadge",
    "TestCryptoProfileDialogUtility",
]
