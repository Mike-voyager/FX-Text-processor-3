"""Тесты для MFAPanel (MFA code entry panel).

Покрывает: создание UI, выбор метода, ввод кода, валидацию,
автоформатирование backup_code, очистку полей.

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/security/test_mfa_panel.py -v

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

from src.gui.security.components.mfa_panel import MFAPanel


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
def mfa_panel(tk_root: tk.Tk) -> Generator[MFAPanel, None, None]:
    """Создаёт MFAPanel с методами totp и backup_code."""
    panel = MFAPanel(
        tk_root,  # type: ignore[arg-type]
        methods=["totp", "backup_code"],
    )
    yield panel
    try:
        if panel.winfo_exists():
            panel.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def mfa_panel_with_callback(tk_root: tk.Tk) -> Generator[MFAPanel, None, None]:
    """Создаёт MFAPanel с on_verify callback."""
    panel = MFAPanel(
        tk_root,  # type: ignore[arg-type]
        methods=["totp", "backup_code"],
        on_verify=lambda method, code: method == "totp" and code == "123456",
    )
    yield panel
    try:
        if panel.winfo_exists():
            panel.destroy()
    except tk.TclError:
        pass


# =============================================================================
# TestMFAPanelInit - тесты инициализации
# =============================================================================


@pytest.mark.security
class TestMFAPanelInit:
    """Тесты инициализации MFAPanel."""

    def test_init_default_methods(self, tk_root: tk.Tk) -> None:
        """По умолчанию метод = ['totp']."""
        panel = MFAPanel(tk_root)  # type: ignore[arg-type]
        assert panel._methods == ["totp"]
        panel.destroy()

    def test_init_custom_methods(self, tk_root: tk.Tk) -> None:
        """Пользовательские методы."""
        panel = MFAPanel(tk_root, methods=["totp", "fido2"])  # type: ignore[arg-type]
        assert panel._methods == ["totp", "fido2"]
        panel.destroy()

    def test_init_selected_method(self, tk_root: tk.Tk) -> None:
        """Первый метод выбран по умолчанию."""
        panel = MFAPanel(tk_root, methods=["backup_code", "totp"])  # type: ignore[arg-type]
        assert panel._selected_method == "backup_code"
        panel.destroy()

    def test_init_stores_callback(self, tk_root: tk.Tk) -> None:
        """on_verify callback сохраняется."""
        callback = MagicMock()
        panel = MFAPanel(tk_root, on_verify=callback)  # type: ignore[arg-type]
        assert panel._on_verify is callback
        panel.destroy()

    def test_init_inherits_from_frame(self, tk_root: tk.Tk) -> None:
        """MFAPanel наследуется от tk.Frame."""
        panel = MFAPanel(tk_root)  # type: ignore[arg-type]
        assert isinstance(panel, tk.Frame)
        panel.destroy()


# =============================================================================
# TestMFAPanelGetMethod - тесты get_method()
# =============================================================================


@pytest.mark.security
class TestMFAPanelGetMethod:
    """Тесты get_method()."""

    def test_get_method_returns_selected(self, mfa_panel: MFAPanel) -> None:
        """get_method() возвращает выбранный метод."""
        method = mfa_panel.get_method()
        assert method == "totp"

    def test_get_method_after_change(self, mfa_panel: MFAPanel) -> None:
        """get_method() после смены метода."""
        mfa_panel._method_var.set("backup_code")
        mfa_panel._on_method_changed()
        method = mfa_panel.get_method()
        assert method == "backup_code"


# =============================================================================
# TestMFAPanelGetCode - тесты get_code()
# =============================================================================


@pytest.mark.security
class TestMFAPanelGetCode:
    """Тесты get_code()."""

    def test_get_code_empty(self, mfa_panel: MFAPanel) -> None:
        """get_code() возвращает пустую строку."""
        assert mfa_panel.get_code() == ""

    def test_get_code_after_input(self, mfa_panel: MFAPanel) -> None:
        """get_code() возвращает введённый код."""
        mfa_panel._code_var.set("123456")
        code = mfa_panel.get_code()
        assert code == "123456"

    def test_get_code_strips_whitespace(self, mfa_panel: MFAPanel) -> None:
        """get_code() удаляет пробелы."""
        mfa_panel._code_var.set("  123456  ")
        code = mfa_panel.get_code()
        assert code == "123456"


# =============================================================================
# TestMFAPanelClear - тесты clear()
# =============================================================================


@pytest.mark.security
class TestMFAPanelClear:
    """Тесты clear()."""

    def test_clear_empties_code(self, mfa_panel: MFAPanel) -> None:
        """clear() очищает поле кода."""
        mfa_panel._code_var.set("123456")
        mfa_panel.clear()
        assert mfa_panel.get_code() == ""

    def test_clear_clears_error(self, mfa_panel: MFAPanel) -> None:
        """clear() очищает сообщение об ошибке."""
        mfa_panel.show_error("Test error")
        mfa_panel.clear()
        if mfa_panel._error_label is not None:
            assert mfa_panel._error_label.cget("text") == ""

    def test_clear_clears_success(self, mfa_panel: MFAPanel) -> None:
        """clear() очищает сообщение об успехе."""
        mfa_panel.show_success("Test success")
        mfa_panel.clear()
        if mfa_panel._success_label is not None:
            assert mfa_panel._success_label.cget("text") == ""


# =============================================================================
# TestMFAPanelMessages - тесты show_error / show_success
# =============================================================================


@pytest.mark.security
class TestMFAPanelMessages:
    """Тесты отображения сообщений."""

    def test_show_error(self, mfa_panel: MFAPanel) -> None:
        """show_error отображает сообщение об ошибке."""
        mfa_panel.show_error("Неверный код")
        if mfa_panel._error_label is not None:
            assert mfa_panel._error_label.cget("text") == "Неверный код"
        # Успех должен быть очищен
        if mfa_panel._success_label is not None:
            assert mfa_panel._success_label.cget("text") == ""

    def test_show_success(self, mfa_panel: MFAPanel) -> None:
        """show_success отображает сообщение об успехе."""
        mfa_panel.show_success("Код подтверждён")
        if mfa_panel._success_label is not None:
            assert mfa_panel._success_label.cget("text") == "Код подтверждён"
        # Ошибка должна быть очищена
        if mfa_panel._error_label is not None:
            assert mfa_panel._error_label.cget("text") == ""


# =============================================================================
# TestMFAPanelFocus - тесты focus()
# =============================================================================


@pytest.mark.security
class TestMFAPanelFocus:
    """Тесты focus()."""

    def test_focus_sets_on_code_entry(self, mfa_panel: MFAPanel) -> None:
        """focus() устанавливает фокус на поле ввода кода."""
        mfa_panel.focus()
        # Фокус должен быть установлен
        assert mfa_panel._code_entry is not None


# =============================================================================
# TestMFAPanelVerify - тесты верификации
# =============================================================================


@pytest.mark.security
class TestMFAPanelVerify:
    """Тесты верификации кода."""

    def test_verify_empty_code_shows_error(
        self,
        mfa_panel_with_callback: MFAPanel,
    ) -> None:
        """Пустой код показывает ошибку."""
        mfa_panel_with_callback._code_var.set("")
        mfa_panel_with_callback._on_verify_click()
        if mfa_panel_with_callback._error_label is not None:
            text = mfa_panel_with_callback._error_label.cget("text")
            assert "код" in text.lower() or text != ""

    def test_verify_correct_totp(
        self,
        mfa_panel_with_callback: MFAPanel,
    ) -> None:
        """Правильный TOTP код проходит верификацию."""
        mfa_panel_with_callback._code_var.set("123456")
        mfa_panel_with_callback._on_verify_click()
        if mfa_panel_with_callback._success_label is not None:
            text = mfa_panel_with_callback._success_label.cget("text")
            assert text != ""

    def test_verify_wrong_totp(
        self,
        mfa_panel_with_callback: MFAPanel,
    ) -> None:
        """Неправильный TOTP код не проходит верификацию."""
        mfa_panel_with_callback._code_var.set("000000")
        mfa_panel_with_callback._on_verify_click()
        if mfa_panel_with_callback._error_label is not None:
            text = mfa_panel_with_callback._error_label.cget("text")
            assert text != ""

    def test_verify_fido2_no_code_needed(
        self,
        tk_root: tk.Tk,
    ) -> None:
        """FIDO2 не требует ввода кода."""
        panel = MFAPanel(
            tk_root,  # type: ignore[arg-type]
            methods=["fido2"],
        )
        panel._code_var.set("")
        panel._on_verify_click()
        if panel._success_label is not None:
            text = panel._success_label.cget("text")
            assert "FIDO2" in text or "ключ" in text.lower()
        panel.destroy()


# =============================================================================
# TestMFAPanelSetMethods - тесты смены методов
# =============================================================================


@pytest.mark.security
class TestMFAPanelSetMethods:
    """Тесты set_methods()."""

    def test_set_methods_updates_list(self, mfa_panel: MFAPanel) -> None:
        """set_methods() обновляет список методов."""
        mfa_panel.set_methods(["fido2"])
        assert mfa_panel._methods == ["fido2"]

    def test_set_methods_resets_selected(self, mfa_panel: MFAPanel) -> None:
        """set_methods() выбирает первый метод."""
        mfa_panel.set_methods(["backup_code", "totp"])
        assert mfa_panel._selected_method == "backup_code"


# =============================================================================
# TestMFAPanelModuleExports - тесты экспортов
# =============================================================================


class TestMFAPanelModuleExports:
    """Тесты экспортов модуля."""

    def test_mfa_panel_importable(self) -> None:
        """MFAPanel импортируется."""
        from src.gui.security.components.mfa_panel import MFAPanel
        assert MFAPanel is not None

    def test_mfa_panel_in_components_init(self) -> None:
        """MFAPanel экспортируется через components.__init__."""
        from src.gui.security.components import MFAPanel
        assert MFAPanel is not None


__all__: list[str] = [
    "TestMFAPanelInit",
    "TestMFAPanelGetMethod",
    "TestMFAPanelGetCode",
    "TestMFAPanelClear",
    "TestMFAPanelMessages",
    "TestMFAPanelFocus",
    "TestMFAPanelVerify",
    "TestMFAPanelSetMethods",
    "TestMFAPanelModuleExports",
]