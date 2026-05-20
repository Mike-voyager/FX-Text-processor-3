"""Тесты для workflow constants.

Проверяет корректность всех констант модуля constants.py:
типы, значения, полноту словарей, неизменяемость.
"""

from __future__ import annotations

from typing import Dict, Set

import pytest

from src.gui.workflow.constants import (
    ARCHIVED_CONFIRMATION_TEXT,
    ARCHIVED_WARNING_MESSAGE,
    CONNECTOR_HEIGHT,
    DIALOG_HEIGHT,
    DIALOG_WIDTH,
    FREE_ROLE_SWITCHING_DESCRIPTION,
    FREE_ROLE_SWITCHING_LABEL,
    FREE_ROLE_SWITCHING_TOOLTIP,
    MAX_SNAPSHOTS_PER_DOCUMENT,
    MAX_UNDO_STEPS,
    MFA_REQUIRED_ROLES,
    MFA_REQUIRED_TRANSITIONS,
    MIN_DIALOG_HEIGHT,
    MIN_DIALOG_WIDTH,
    NON_UNDOABLE_STATES,
    PADDING_LARGE,
    PADDING_NORMAL,
    PADDING_SMALL,
    ROLE_COLORS,
    ROLE_COLORS_LIGHT,
    ROLE_ICONS,
    ROLE_NAMES_RU,
    STATUS_COLORS,
    STATUS_COLORS_LIGHT,
    STATUS_NAMES_RU,
    STATUS_ORDER,
    STATUS_CIRCLE_SIZE,
    UNDO_REDO_ICONS,
    UNDO_REDO_SHORTCUTS,
)


class TestStatusColors:
    """Тесты цветов статусов."""

    def test_status_colors_has_all_statuses(self) -> None:
        """STATUS_COLORS содержит все ожидаемые статусы."""
        expected = {"draft", "filled", "validated", "approved",
                    "signed", "printed", "archived", "rejected"}
        assert set(STATUS_COLORS.keys()) == expected

    def test_status_colors_are_hex(self) -> None:
        """Все значения STATUS_COLORS — HEX-цвета."""
        for key, value in STATUS_COLORS.items():
            assert value.startswith("#"), f"{key}: {value} не HEX"
            assert len(value) == 7, f"{key}: {value} неправильная длина"

    def test_status_colors_light_has_same_keys(self) -> None:
        """STATUS_COLORS_LIGHT имеет те же ключи что STATUS_COLORS."""
        assert set(STATUS_COLORS_LIGHT.keys()) == set(STATUS_COLORS.keys())


class TestRoleColors:
    """Тесты цветов ролей."""

    def test_role_colors_has_all_roles(self) -> None:
        """ROLE_COLORS содержит все ожидаемые роли."""
        expected = {"operator", "editor", "supervisor", "signatory"}
        assert set(ROLE_COLORS.keys()) == expected

    def test_role_colors_are_hex(self) -> None:
        """Все значения ROLE_COLORS — HEX-цвета."""
        for key, value in ROLE_COLORS.items():
            assert value.startswith("#"), f"{key}: {value} не HEX"

    def test_role_colors_light_has_same_keys(self) -> None:
        """ROLE_COLORS_LIGHT имеет те же ключи что ROLE_COLORS."""
        assert set(ROLE_COLORS_LIGHT.keys()) == set(ROLE_COLORS.keys())


class TestRoleIcons:
    """Тесты иконок ролей."""

    def test_role_icons_has_all_roles(self) -> None:
        """ROLE_ICONS содержит все ожидаемые роли."""
        expected = {"operator", "editor", "supervisor", "signatory"}
        assert set(ROLE_ICONS.keys()) == expected

    def test_role_icons_non_empty(self) -> None:
        """Все иконки ролей не пустые."""
        for key, value in ROLE_ICONS.items():
            assert len(value) > 0, f"{key}: пустая иконка"


class TestLocalizedNames:
    """Тесты локализованных названий."""

    def test_status_names_ru_has_all_statuses(self) -> None:
        """STATUS_NAMES_RU содержит все статусы."""
        expected = {"draft", "filled", "validated", "approved",
                    "signed", "printed", "archived", "rejected"}
        assert set(STATUS_NAMES_RU.keys()) == expected

    def test_status_names_ru_are_russian(self) -> None:
        """STATUS_NAMES_RU содержит русские названия."""
        for key, value in STATUS_NAMES_RU.items():
            # Русский текст содержит кириллические символы
            assert any("А" <= c <= "я" for c in value), (
                f"{key}: '{value}' не содержит кириллицы"
            )

    def test_role_names_ru_has_all_roles(self) -> None:
        """ROLE_NAMES_RU содержит все роли."""
        expected = {"operator", "editor", "supervisor", "signatory"}
        assert set(ROLE_NAMES_RU.keys()) == expected

    def test_role_names_ru_are_russian(self) -> None:
        """ROLE_NAMES_RU содержит русские названия."""
        for key, value in ROLE_NAMES_RU.items():
            assert any("А" <= c <= "я" for c in value), (
                f"{key}: '{value}' не содержит кириллицы"
            )


class TestMFARequirements:
    """Тесты требований MFA."""

    def test_mfa_required_transitions_is_set(self) -> None:
        """MFA_REQUIRED_TRANSITIONS — множество кортежей."""
        assert isinstance(MFA_REQUIRED_TRANSITIONS, set)
        for item in MFA_REQUIRED_TRANSITIONS:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_mfa_required_transitions_contains_key_pairs(self) -> None:
        """MFA_REQUIRED_TRANSITIONS содержит критические переходы."""
        assert ("filled", "validated") in MFA_REQUIRED_TRANSITIONS
        assert ("validated", "approved") in MFA_REQUIRED_TRANSITIONS
        assert ("approved", "signed") in MFA_REQUIRED_TRANSITIONS

    def test_mfa_required_roles_is_set(self) -> None:
        """MFA_REQUIRED_ROLES — множество строк."""
        assert isinstance(MFA_REQUIRED_ROLES, set)
        for item in MFA_REQUIRED_ROLES:
            assert isinstance(item, str)

    def test_mfa_required_roles_contains_privileged(self) -> None:
        """MFA_REQUIRED_ROLES содержит привилегированные роли."""
        assert "supervisor" in MFA_REQUIRED_ROLES
        assert "signatory" in MFA_REQUIRED_ROLES


class TestUndoRedoSettings:
    """Тесты настроек undo/redo."""

    def test_max_undo_steps_positive(self) -> None:
        """MAX_UNDO_STEPS > 0."""
        assert MAX_UNDO_STEPS > 0

    def test_max_snapshots_positive(self) -> None:
        """MAX_SNAPSHOTS_PER_DOCUMENT > 0."""
        assert MAX_SNAPSHOTS_PER_DOCUMENT > 0

    def test_non_undoable_states_is_set(self) -> None:
        """NON_UNDOABLE_STATES — множество строк."""
        assert isinstance(NON_UNDOABLE_STATES, set)
        assert "archived" in NON_UNDOABLE_STATES

    def test_undo_redo_icons(self) -> None:
        """UNDO_REDO_ICONS содержит иконки undo и redo."""
        assert "undo" in UNDO_REDO_ICONS
        assert "redo" in UNDO_REDO_ICONS
        assert len(UNDO_REDO_ICONS["undo"]) > 0
        assert len(UNDO_REDO_ICONS["redo"]) > 0

    def test_undo_redo_shortcuts(self) -> None:
        """UNDO_REDO_SHORTCUTS содержит шорткаты."""
        assert "undo" in UNDO_REDO_SHORTCUTS
        assert "redo" in UNDO_REDO_SHORTCUTS


class TestArchivedConfirmation:
    """Тесты текстов подтверждения архивации."""

    def test_archived_confirmation_text(self) -> None:
        """ARCHIVED_CONFIRMATION_TEXT — непустая строка."""
        assert isinstance(ARCHIVED_CONFIRMATION_TEXT, str)
        assert len(ARCHIVED_CONFIRMATION_TEXT) > 0

    def test_archived_warning_message(self) -> None:
        """ARCHIVED_WARNING_MESSAGE — непустая строка с предупреждением."""
        assert isinstance(ARCHIVED_WARNING_MESSAGE, str)
        assert len(ARCHIVED_WARNING_MESSAGE) > 0


class TestUIDimensions:
    """Тесты размеров UI."""

    def test_dialog_dimensions(self) -> None:
        """Размеры диалога корректны."""
        assert DIALOG_WIDTH > MIN_DIALOG_WIDTH
        assert DIALOG_HEIGHT > MIN_DIALOG_HEIGHT
        assert MIN_DIALOG_WIDTH > 0
        assert MIN_DIALOG_HEIGHT > 0

    def test_padding_order(self) -> None:
        """PADDING_SMALL < PADDING_NORMAL < PADDING_LARGE."""
        assert PADDING_SMALL < PADDING_NORMAL < PADDING_LARGE

    def test_status_circle_size_positive(self) -> None:
        """STATUS_CIRCLE_SIZE > 0."""
        assert STATUS_CIRCLE_SIZE > 0

    def test_connector_height_positive(self) -> None:
        """CONNECTOR_HEIGHT > 0."""
        assert CONNECTOR_HEIGHT > 0


class TestStatusOrder:
    """Тесты порядка состояний."""

    def test_status_order_is_list(self) -> None:
        """STATUS_ORDER — список строк."""
        assert isinstance(STATUS_ORDER, list)
        for item in STATUS_ORDER:
            assert isinstance(item, str)

    def test_status_order_starts_with_draft(self) -> None:
        """STATUS_ORDER начинается с draft."""
        assert STATUS_ORDER[0] == "draft"

    def test_status_order_ends_with_archived(self) -> None:
        """STATUS_ORDER заканчивается на archived."""
        assert STATUS_ORDER[-1] == "archived"


class TestFreeRoleSwitching:
    """Тесты свободного переключения ролей."""

    def test_free_role_switching_label(self) -> None:
        """FREE_ROLE_SWITCHING_LABEL — непустая строка."""
        assert isinstance(FREE_ROLE_SWITCHING_LABEL, str)
        assert len(FREE_ROLE_SWITCHING_LABEL) > 0

    def test_free_role_switching_description(self) -> None:
        """FREE_ROLE_SWITCHING_DESCRIPTION — непустая строка."""
        assert isinstance(FREE_ROLE_SWITCHING_DESCRIPTION, str)
        assert len(FREE_ROLE_SWITCHING_DESCRIPTION) > 0

    def test_free_role_switching_tooltip(self) -> None:
        """FREE_ROLE_SWITCHING_TOOLTIP — непустая строка."""
        assert isinstance(FREE_ROLE_SWITCHING_TOOLTIP, str)
        assert len(FREE_ROLE_SWITCHING_TOOLTIP) > 0