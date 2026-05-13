"""Тесты для RoleBadge."""

from __future__ import annotations

import pytest
import tkinter as tk

from src.view.workflow import Role
from src.view.workflow.role_badge import RoleBadge


@pytest.fixture
def root():
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


class TestRoleBadge:
    """Тесты для бейджа роли."""

    def test_init_default_role(self, root):
        """Тест инициализации с дефолтной ролью."""
        badge = RoleBadge(root)
        assert badge.get_role() == Role.OPERATOR

    def test_init_custom_role(self, root):
        """Тест инициализации с кастомной ролью."""
        badge = RoleBadge(root, role=Role.EDITOR)
        assert badge.get_role() == Role.EDITOR

    def test_all_roles(self, root):
        """Тест всех ролей."""
        for role in Role:
            badge = RoleBadge(root, role=role)
            assert badge.get_role() == role

    def test_set_role(self, root):
        """Тест установки роли."""
        badge = RoleBadge(root)
        badge.set_role(Role.SUPERVISOR)
        assert badge.get_role() == Role.SUPERVISOR

    def test_get_role_color(self, root):
        """Тест получения цвета роли."""
        badge = RoleBadge(root, role=Role.SIGNATORY)
        color = badge.get_role_color()
        assert color == "#CC0000"  # Красный для SIGNATORY

    def test_role_colors_fixed(self, root):
        """Тест что цвета ролей фиксированы."""
        expected_colors = {
            Role.OPERATOR: "#0033AA",
            Role.EDITOR: "#006600",
            Role.SUPERVISOR: "#CC6600",
            Role.SIGNATORY: "#CC0000",
        }

        for role, expected_color in expected_colors.items():
            badge = RoleBadge(root, role=role)
            assert badge.get_role_color() == expected_color


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
