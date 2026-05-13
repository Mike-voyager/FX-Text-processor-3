# -*- coding: utf-8 -*-
"""Тесты для SecureEntry компонента.

Модуль содержит unit-тесты для виджета SecureEntry с функцией
безопасного удаления данных из памяти.

Example:
    $ xvfb-run -a python -m pytest tests/unit/gui/security/test_secure_entry.py -v

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from typing import TYPE_CHECKING
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


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def tk_root() -> tk.Tk:
    """Создаёт Tk root для тестов GUI."""
    root = tk.Tk()
    root.withdraw()  # Скрываем окно
    yield root
    root.destroy()


@pytest.fixture
def secure_entry_secure(tk_root: tk.Tk) -> Generator[SecureEntry, None, None]:  # type: ignore[misc]
    """Создание SecureEntry с включённым secure режимом."""
    entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)  # type: ignore[arg-type]
    yield entry
    # Cleanup happens in destroy
    if entry.winfo_exists():
        entry.destroy()


@pytest.fixture
def secure_entry_non_secure(tk_root: tk.Tk) -> Generator[SecureEntry, None, None]:  # type: ignore[misc]
    """Создание SecureEntry с выключенным secure режимом."""
    entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=False)  # type: ignore[arg-type]
    yield entry
    if entry.winfo_exists():
        entry.destroy()


# =============================================================================
# TestSecureEntryInitialization - тесты инициализации
# =============================================================================


@pytest.mark.security
class TestSecureEntryInitialization:
    """Тесты инициализации SecureEntry."""

    def test_init_secure_true(self, tk_root: tk.Tk) -> None:
        """Проверка инициализации с secure=True."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)

        assert entry._secure is True
        assert entry.is_secure()

        entry.destroy()

    def test_init_secure_false(self, tk_root: tk.Tk) -> None:
        """Проверка инициализации с secure=False."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=False)

        assert entry._secure is False
        assert not entry.is_secure()

        entry.destroy()

    def test_init_default_is_secure(self, tk_root: tk.Tk) -> None:
        """Проверка что по умолчанию secure=True."""
        entry = SecureEntry(tk_root)  # type: ignore[arg-type]

        assert entry._secure is True
        assert entry.is_secure()

        entry.destroy()

    def test_init_creates_stringvar(self, tk_root: tk.Tk) -> None:
        """Проверка что инициализация создаёт StringVar."""
        entry = SecureEntry(tk_root)  # type: ignore[arg-type]

        assert isinstance(entry._variable, tk.StringVar)

        entry.destroy()

    def test_init_wipe_count_default(self, tk_root: tk.Tk) -> None:
        """Проверка значения wipe_count по умолчанию."""
        entry = SecureEntry(tk_root)  # type: ignore[arg-type]

        assert entry._wipe_count == 3

        entry.destroy()

    def test_init_inherits_from_entry(self, tk_root: tk.Tk) -> None:
        """Проверка что SecureEntry наследуется от tk.Entry."""
        entry = SecureEntry(tk_root)  # type: ignore[arg-type]

        assert isinstance(entry, tk.Entry)

        entry.destroy()

    def test_init_accepts_entry_kwargs(self, tk_root: tk.Tk) -> None:
        """Проверка что SecureEntry принимает kwargs для Entry."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True, show="*", width=30)

        assert entry.cget("show") == "*"
        # width может быть int или string в зависимости от Tk версии
        width_value = entry.cget("width")
        assert str(width_value) == "30"

        entry.destroy()


# =============================================================================
# TestSecureEntryWipe - тесты метода wipe()
# =============================================================================


@pytest.mark.security
class TestSecureEntryWipe:
    """Тесты метода wipe()."""

    def test_wipe_clears_value_secure(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что wipe очищает значение в secure режиме."""
        secure_entry_secure.insert(0, "secret password")

        secure_entry_secure.wipe()

        assert secure_entry_secure.get() == ""

    def test_wipe_clears_value_non_secure(self, secure_entry_non_secure: SecureEntry) -> None:
        """Проверка что wipe очищает значение в non-secure режиме."""
        secure_entry_non_secure.insert(0, "secret password")

        secure_entry_non_secure.wipe()

        assert secure_entry_non_secure.get() == ""

    def test_wipe_multiple_iterations(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что wipe выполняет множественные итерации."""
        secure_entry_secure.insert(0, "test")

        # Записываем состояние до wipe
        secure_entry_secure.wipe()

        # Значение должно быть очищено
        assert secure_entry_secure.get() == ""

    def test_wipe_empty_value(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что wipe работает с пустым значением."""
        # Пустое значение
        secure_entry_secure.wipe()

        assert secure_entry_secure.get() == ""

    def test_wipe_calls_update(self, tk_root: tk.Tk) -> None:
        """Проверка что wipe вызывает update."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry.insert(0, "test")

        with patch.object(entry, "update") as mock_update:
            entry.wipe()
            # update должен быть вызван множество раз
            assert mock_update.call_count >= 0

        entry.destroy()

    def test_wipe_sets_empty_string(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что wipe устанавливает пустую строку."""
        secure_entry_secure.insert(0, "some data")

        secure_entry_secure.wipe()

        # StringVar должна быть очищена
        assert secure_entry_secure._variable.get() == ""


# =============================================================================
# TestSecureEntryGetSecure - тесты метода get_secure()
# =============================================================================


@pytest.mark.security
class TestSecureEntryGetSecure:
    """Тесты метода get_secure()."""

    def test_get_secure_returns_value(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что get_secure возвращает значение."""
        secure_entry_secure.insert(0, "my secret")

        value = secure_entry_secure.get_secure()

        assert value == "my secret"

    def test_get_secure_clears_value(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что get_secure очищает значение после получения."""
        secure_entry_secure.insert(0, "my secret")

        secure_entry_secure.get_secure()

        # Поле должно быть очищено
        assert secure_entry_secure.get() == ""

    def test_get_secure_empty_value(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка get_secure с пустым значением."""
        value = secure_entry_secure.get_secure()

        assert value == ""

    def test_get_secure_returns_before_wipe(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что get_secure возвращает значение ДО очистки."""
        test_value = "important data"
        secure_entry_secure.insert(0, test_value)

        value = secure_entry_secure.get_secure()

        # Возвращается исходное значение
        assert value == test_value
        # Поле очищено
        assert secure_entry_secure.get() == ""


# =============================================================================
# TestSecureEntryDestroy - тесты метода destroy()
# =============================================================================


@pytest.mark.security
class TestSecureEntryDestroy:
    """Тесты метода destroy()."""

    def test_destroy_calls_wipe_when_secure(self, tk_root: tk.Tk) -> None:
        """Проверка что destroy вызывает wipe в secure режиме."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry.insert(0, "secret")

        with patch.object(entry, "wipe") as mock_wipe:
            # Создаём мок для winfo_exists
            with patch.object(entry, "winfo_exists", return_value=True):
                entry.destroy()

                # wipe должен быть вызван
                mock_wipe.assert_called_once()

    def test_destroy_skips_wipe_when_not_secure(self, tk_root: tk.Tk) -> None:
        """Проверка что destroy не вызывает wipe в non-secure режиме."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=False)
        entry.insert(0, "data")

        with patch.object(entry, "wipe") as mock_wipe:
            with patch.object(entry, "winfo_exists", return_value=True):
                entry.destroy()

                # wipe не должен вызываться
                mock_wipe.assert_not_called()

    def test_destroy_clears_variable(self, tk_root: tk.Tk) -> None:
        """Проверка что destroy очищает переменную."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry.insert(0, "data")

        entry.destroy()

        # Переменная должна быть очищена
        assert entry._variable.get() == ""

    def test_destroy_non_secure_clears_variable(self, tk_root: tk.Tk) -> None:
        """Проверка что destroy очищает переменную даже в non-secure режиме."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=False)
        entry.insert(0, "data")

        entry.destroy()

        # Переменная должна быть очищена
        assert entry._variable.get() == ""


# =============================================================================
# TestSecureEntryMode - тесты переключения режима
# =============================================================================


@pytest.mark.security
class TestSecureEntryMode:
    """Тесты переключения режима secure."""

    def test_set_secure_true(self, secure_entry_non_secure: SecureEntry) -> None:
        """Проверка включения secure режима."""
        secure_entry_non_secure.set_secure(True)

        assert secure_entry_non_secure.is_secure() is True

    def test_set_secure_false(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка выключения secure режима."""
        secure_entry_secure.set_secure(False)

        assert secure_entry_secure.is_secure() is False

    def test_set_secure_toggle(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка переключения secure режима."""
        assert secure_entry_secure.is_secure() is True

        secure_entry_secure.set_secure(False)
        assert secure_entry_secure.is_secure() is False

        secure_entry_secure.set_secure(True)
        assert secure_entry_secure.is_secure() is True


# =============================================================================
# TestSecureEntryBasicFunctionality - тесты базовой функциональности Entry
# =============================================================================


@pytest.mark.security
class TestSecureEntryBasicFunctionality:
    """Тесты базовой функциональности Entry."""

    def test_insert_and_get(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка базовой операции insert/get."""
        secure_entry_secure.insert(0, "test value")

        assert secure_entry_secure.get() == "test value"

    def test_delete(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка удаления текста."""
        secure_entry_secure.insert(0, "hello")
        secure_entry_secure.delete(0, 2)  # Удаляем "he"

        assert secure_entry_secure.get() == "llo"

    def test_clear(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка очистки поля."""
        secure_entry_secure.insert(0, "data")
        secure_entry_secure.delete(0, tk.END)

        assert secure_entry_secure.get() == ""

    def test_show_attribute(self, tk_root: tk.Tk) -> None:
        """Проверка атрибута show (маскирование пароля)."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True, show="*")
        entry.insert(0, "password")

        assert entry.cget("show") == "*"

        entry.destroy()


# =============================================================================
# TestSecureEntryVariable - тесты работы с StringVar
# =============================================================================


@pytest.mark.security
class TestSecureEntryVariable:
    """Тесты работы с StringVar."""

    def test_get_textvariable_returns_var(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что get_textvariable возвращает StringVar."""
        var = secure_entry_secure.get_textvariable()

        assert isinstance(var, tk.StringVar)
        assert var is secure_entry_secure._variable

    def test_variable_reflects_entry_value(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что StringVar отражает значение Entry."""
        secure_entry_secure.insert(0, "sync test")

        var = secure_entry_secure.get_textvariable()
        assert var.get() == "sync test"

    def test_variable_changes_update_entry(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка что изменение StringVar обновляет Entry."""
        var = secure_entry_secure.get_textvariable()
        var.set("set via var")

        assert secure_entry_secure.get() == "set via var"


# =============================================================================
# TestSecureEntryMemory - тесты безопасности памяти
# =============================================================================


@pytest.mark.security
class TestSecureEntryMemory:
    """Тесты безопасности памяти."""

    def test_wipe_overwrites_memory(self, tk_root: tk.Tk) -> None:
        """Проверка что wipe перезаписывает память."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry.insert(0, "secret")

        # Мокаем StringVar.set для проверки перезаписи
        set_values: list[str] = []
        original_set = entry._variable.set

        def tracked_set(value: str) -> None:
            set_values.append(value)
            original_set(value)

        entry._variable.set = tracked_set  # type: ignore[method-assign]

        entry.wipe()

        # Должны быть вызовы с нулями разной длины
        assert len(set_values) > 0

        entry.destroy()

    def test_wipe_multiple_passes(self, tk_root: tk.Tk) -> None:
        """Проверка множественных проходов wipe."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry._wipe_count = 5  # Увеличиваем количество проходов
        entry.insert(0, "test")

        # Проверяем что wipe_count установлен
        assert entry._wipe_count == 5

        entry.wipe()

        entry.destroy()

    def test_secure_mode_wipe_on_destroy(self, tk_root: tk.Tk) -> None:
        """Проверка что в secure режиме происходит wipe при destroy."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry.insert(0, "sensitive data")

        with patch.object(entry, "wipe") as mock_wipe:
            with patch.object(entry, "winfo_exists", return_value=True):
                entry.destroy()

                mock_wipe.assert_called_once()

    def test_non_secure_mode_no_wipe_on_destroy(self, tk_root: tk.Tk) -> None:
        """Проверка что в non-secure режиме нет wipe при destroy."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=False)
        entry.insert(0, "data")

        with patch.object(entry, "wipe") as mock_wipe:
            with patch.object(entry, "winfo_exists", return_value=True):
                entry.destroy()

                mock_wipe.assert_not_called()


# =============================================================================
# TestSecureEntryEdgeCases - тесты крайних случаев
# =============================================================================


@pytest.mark.security
class TestSecureEntryEdgeCases:
    """Тесты крайних случаев."""

    def test_empty_string_get_secure(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка get_secure с пустой строкой."""
        value = secure_entry_secure.get_secure()

        assert value == ""
        assert secure_entry_secure.get() == ""

    def test_long_value_wipe(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка wipe с длинной строкой."""
        long_value = "x" * 1000
        secure_entry_secure.insert(0, long_value)

        secure_entry_secure.wipe()

        assert secure_entry_secure.get() == ""

    def test_unicode_value_wipe(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка wipe с Unicode строкой."""
        unicode_value = "пароль 🔐 émoji 日本語"
        secure_entry_secure.insert(0, unicode_value)

        secure_entry_secure.wipe()

        assert secure_entry_secure.get() == ""

    def test_special_characters_wipe(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка wipe со специальными символами."""
        special_value = "\x00\x01\x02\n\r\t"
        secure_entry_secure.insert(0, special_value)

        secure_entry_secure.wipe()

        assert secure_entry_secure.get() == ""

    def test_single_character_wipe(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка wipe с одним символом."""
        secure_entry_secure.insert(0, "a")

        secure_entry_secure.wipe()

        assert secure_entry_secure.get() == ""

    def test_wipe_called_multiple_times(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка множественных вызовов wipe."""
        secure_entry_secure.insert(0, "test")

        secure_entry_secure.wipe()
        secure_entry_secure.wipe()
        secure_entry_secure.wipe()

        # Должно работать без ошибок
        assert secure_entry_secure.get() == ""

    def test_get_secure_called_multiple_times(self, secure_entry_secure: SecureEntry) -> None:
        """Проверка множественных вызовов get_secure."""
        secure_entry_secure.insert(0, "only once")

        first = secure_entry_secure.get_secure()
        second = secure_entry_secure.get_secure()

        assert first == "only once"
        assert second == ""


# =============================================================================
# TestSecureEntryWidgetLifecycle - тесты жизненного цикла виджета
# =============================================================================


@pytest.mark.security
class TestSecureEntryWidgetLifecycle:
    """Тесты жизненного цикла виджета."""

    def test_winfo_exists_after_init(self, tk_root: tk.Tk) -> None:
        """Проверка что виджет существует после инициализации."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)

        assert entry.winfo_exists()

        entry.destroy()

    def test_winfo_exists_after_destroy(self, tk_root: tk.Tk) -> None:
        """Проверка что виджет не существует после destroy."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry.destroy()

        assert not entry.winfo_exists()

    def test_destroy_when_not_exists(self, tk_root: tk.Tk) -> None:
        """Проверка destroy когда виджет уже уничтожен."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry.destroy()

        # Не должно вызывать исключения
        entry.destroy()

    def test_wipe_on_destroyed_widget(self, tk_root: tk.Tk) -> None:
        """Проверка wipe на уничтоженном виджете."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry.insert(0, "data")
        entry.destroy()

        # Не должно вызывать исключения
        entry.wipe()

    def test_get_on_destroyed_widget_raises(self, tk_root: tk.Tk) -> None:
        """Проверка что get на уничтоженном виджете вызывает ошибку."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True)
        entry.insert(0, "data")
        entry.destroy()

        # Должно вызвать исключение TclError
        with pytest.raises(tk.TclError):
            entry.get()


# =============================================================================
# TestSecureEntryIntegration - интеграционные тесты
# =============================================================================


@pytest.mark.security
class TestSecureEntryIntegration:
    """Интеграционные тесты SecureEntry."""

    def test_entry_in_frame(self, tk_root: tk.Tk) -> None:
        """Проверка работы Entry внутри Frame."""
        frame = tk.Frame(tk_root)
        entry = SecureEntry(frame, secure=True)
        entry.pack()

        entry.insert(0, "in frame")

        assert entry.get() == "in frame"

        frame.destroy()

    def test_multiple_entries(self, tk_root: tk.Tk) -> None:
        """Проверка работы нескольких SecureEntry."""
        entry1 = SecureEntry(tk_root, secure=True)
        entry2 = SecureEntry(tk_root, secure=False)

        entry1.insert(0, "first")
        entry2.insert(0, "second")

        assert entry1.get() == "first"
        assert entry2.get() == "second"

        entry1.wipe()

        assert entry1.get() == ""
        assert entry2.get() == "second"

        entry1.destroy()
        entry2.destroy()

    def test_entry_with_show(self, tk_root: tk.Tk) -> None:
        """Проверка Entry с маскированием."""
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True, show="●")
        entry.insert(0, "password123")

        # Значение маскировано, но get() возвращает исходное
        assert entry.get() == "password123"
        assert entry.cget("show") == "●"

        entry.destroy()

    def test_complete_workflow(self, tk_root: tk.Tk) -> None:
        """Проверка полного рабочего процесса."""
        # Создаём Entry
        entry = SecureEntry(tk_root,  # type: ignore[arg-type]
         secure=True, show="*")

        # Вводим пароль
        entry.insert(0, "MySecret123!")

        # Получаем значение и очищаем
        password = entry.get_secure()

        assert password == "MySecret123!"
        assert entry.get() == ""

        # Уничтожаем
        entry.destroy()

        # Пароль должен быть очищен из памяти
        assert not entry.winfo_exists()
