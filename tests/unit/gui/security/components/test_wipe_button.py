"""Тесты для WipeButton.

Покрывает: создание, связывание с SecureEntry, wipe при нажатии,
set_target, get_target, trigger_wipe, валидацию типа target.

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/security/components/test_wipe_button.py -v

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Generator
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

from src.gui.security.components.secure_entry import SecureEntry
from src.gui.security.components.wipe_button import WipeButton


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
def secure_entry(tk_root: tk.Tk) -> Generator[SecureEntry, None, None]:
    """Создаёт SecureEntry для тестов."""
    entry = SecureEntry(tk_root, secure=True)  # type: ignore[arg-type]
    yield entry
    try:
        if entry.winfo_exists():
            entry.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def wipe_button(
    tk_root: tk.Tk,
    secure_entry: SecureEntry,
) -> Generator[WipeButton, None, None]:
    """Создаёт WipeButton с SecureEntry."""
    btn = WipeButton(tk_root, target=secure_entry)  # type: ignore[arg-type]
    yield btn
    try:
        if btn.winfo_exists():
            btn.destroy()
    except tk.TclError:
        pass


# =============================================================================
# TestWipeButtonInit - тесты инициализации
# =============================================================================


@pytest.mark.security
class TestWipeButtonInit:
    """Тесты инициализации WipeButton."""

    def test_init_with_secure_entry(
        self,
        tk_root: tk.Tk,
        secure_entry: SecureEntry,
    ) -> None:
        """Инициализация с SecureEntry."""
        btn = WipeButton(tk_root, target=secure_entry)  # type: ignore[arg-type]
        assert btn._target is secure_entry
        btn.destroy()

    def test_init_default_text(
        self,
        tk_root: tk.Tk,
        secure_entry: SecureEntry,
    ) -> None:
        """Текст кнопки по умолчанию."""
        btn = WipeButton(tk_root, target=secure_entry)  # type: ignore[arg-type]
        # Текст содержит "Очистить" или wipe
        text = btn.cget("text")
        assert len(text) > 0
        btn.destroy()

    def test_init_custom_text(
        self,
        tk_root: tk.Tk,
        secure_entry: SecureEntry,
    ) -> None:
        """Пользовательский текст кнопки."""
        btn = WipeButton(tk_root, target=secure_entry, text="Clear")  # type: ignore[arg-type]
        assert btn.cget("text") == "Clear"
        btn.destroy()

    def test_init_rejects_non_secure_entry(
        self,
        tk_root: tk.Tk,
    ) -> None:
        """Ошибка при передаче не SecureEntry."""
        with pytest.raises(TypeError, match="SecureEntry"):
            WipeButton(tk_root, target=tk.Entry(tk_root))  # type: ignore[arg-type]

    def test_init_inherits_from_button(
        self,
        wipe_button: WipeButton,
    ) -> None:
        """WipeButton наследуется от tk.Button."""
        assert isinstance(wipe_button, tk.Button)


# =============================================================================
# TestWipeButtonWipe - тесты wipe при нажатии
# =============================================================================


@pytest.mark.security
class TestWipeButtonWipe:
    """Тесты wipe при нажатии кнопки."""

    def test_click_calls_wipe(
        self,
        wipe_button: WipeButton,
        secure_entry: SecureEntry,
    ) -> None:
        """Нажатие кнопки вызывает wipe() у SecureEntry."""
        secure_entry.insert(0, "secret data")
        with patch.object(secure_entry, "wipe") as mock_wipe:
            wipe_button._on_click()
            mock_wipe.assert_called_once()

    def test_click_no_target_no_error(
        self,
        tk_root: tk.Tk,
        secure_entry: SecureEntry,
    ) -> None:
        """Нажатие без target не вызывает ошибку."""
        btn = WipeButton(tk_root, target=secure_entry)  # type: ignore[arg-type]
        btn._target = None  # type: ignore[assignment]
        # Не должно выбросить исключение
        btn._on_click()
        btn.destroy()

    def test_click_destroyed_target_no_error(
        self,
        wipe_button: WipeButton,
        secure_entry: SecureEntry,
    ) -> None:
        """Нажатие с уничтоженным target не вызывает ошибку."""
        secure_entry.destroy()
        with patch.object(secure_entry, "winfo_exists", return_value=False):
            # Не должно выбросить исключение
            wipe_button._on_click()

    def test_wipe_clears_entry_value(
        self,
        wipe_button: WipeButton,
        secure_entry: SecureEntry,
    ) -> None:
        """wipe() очищает значение SecureEntry."""
        secure_entry.insert(0, "sensitive password")
        wipe_button._on_click()
        assert secure_entry.get() == ""


# =============================================================================
# TestWipeButtonSetTarget - тесты set_target
# =============================================================================


@pytest.mark.security
class TestWipeButtonSetTarget:
    """Тесты set_target()."""

    def test_set_target_changes_target(
        self,
        tk_root: tk.Tk,
        secure_entry: SecureEntry,
    ) -> None:
        """set_target() меняет связанный SecureEntry."""
        btn = WipeButton(tk_root, target=secure_entry)  # type: ignore[arg-type]
        new_entry = SecureEntry(tk_root, secure=True)  # type: ignore[arg-type]
        btn.set_target(new_entry)

        assert btn._target is new_entry
        btn.destroy()
        new_entry.destroy()

    def test_set_target_rejects_non_secure_entry(
        self,
        wipe_button: WipeButton,
    ) -> None:
        """set_target() отклоняет не SecureEntry."""
        with pytest.raises(TypeError, match="SecureEntry"):
            wipe_button.set_target(MagicMock())  # type: ignore[arg-type]


# =============================================================================
# TestWipeButtonGetTarget - тесты get_target
# =============================================================================


@pytest.mark.security
class TestWipeButtonGetTarget:
    """Тесты get_target()."""

    def test_get_target_returns_current(
        self,
        wipe_button: WipeButton,
        secure_entry: SecureEntry,
    ) -> None:
        """get_target() возвращает текущий target."""
        result = wipe_button.get_target()
        assert result is secure_entry

    def test_get_target_returns_secure_entry_type(
        self,
        wipe_button: WipeButton,
    ) -> None:
        """get_target() возвращает тип SecureEntry."""
        result = wipe_button.get_target()
        assert isinstance(result, SecureEntry)


# =============================================================================
# TestWipeButtonTriggerWipe - тесты trigger_wipe
# =============================================================================


@pytest.mark.security
class TestWipeButtonTriggerWipe:
    """Тесты trigger_wipe()."""

    def test_trigger_wipe_calls_on_click(
        self,
        wipe_button: WipeButton,
    ) -> None:
        """trigger_wipe() вызывает _on_click()."""
        with patch.object(wipe_button, "_on_click") as mock_click:
            wipe_button.trigger_wipe()
            mock_click.assert_called_once()

    def test_trigger_wipe_clears_entry(
        self,
        wipe_button: WipeButton,
        secure_entry: SecureEntry,
    ) -> None:
        """trigger_wipe() очищает SecureEntry."""
        secure_entry.insert(0, "data to wipe")
        wipe_button.trigger_wipe()
        assert secure_entry.get() == ""


# =============================================================================
# TestWipeButtonModuleExports - тесты экспортов
# =============================================================================


class TestWipeButtonModuleExports:
    """Тесты экспортов модуля."""

    def test_wipe_button_importable(self) -> None:
        """WipeButton импортируется."""
        from src.gui.security.components.wipe_button import WipeButton
        assert WipeButton is not None

    def test_wipe_button_in_components_init(self) -> None:
        """WipeButton экспортируется через components.__init__."""
        from src.gui.security.components import WipeButton
        assert WipeButton is not None


__all__: list[str] = [
    "TestWipeButtonInit",
    "TestWipeButtonWipe",
    "TestWipeButtonSetTarget",
    "TestWipeButtonGetTarget",
    "TestWipeButtonTriggerWipe",
    "TestWipeButtonModuleExports",
]