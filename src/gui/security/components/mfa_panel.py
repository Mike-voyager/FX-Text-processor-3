"""MFA Panel - панель для ввода многофакторной аутентификации.

Модуль предоставляет MFAPanel - виджет для выбора метода MFA
и ввода соответствующего кода подтверждения.

Example:
    >>> import tkinter as tk
    >>> root = tk.Tk()
    >>> def on_verify(method: str, code: str) -> bool:
    ...     return verify_totp(code)
    >>> panel = MFAPanel(root, methods=["totp", "backup_code"], on_verify=on_verify)
    >>> panel.pack()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import re
import tkinter as tk
from typing import Any, Callable, Optional


class MFAPanel(tk.Frame):
    """Панель для ввода MFA кода с выбором метода.

    Предоставляет интерфейс для выбора метода MFA (TOTP,
    Backup Code, FIDO2) и ввода соответствующего кода.
    Поддерживает автоматическое форматирование и валидацию.

    Attributes:
        _methods: Список доступных методов MFA.
        _selected_method: Текущий выбранный метод.
        _on_verify: Callback для проверки кода.
        _theme_manager: Менеджер тем для стилизации.
        _code_var: Переменная для поля ввода кода.
        _method_var: Переменная для выбора метода.

    Example:
        >>> panel = MFAPanel(
        ...     parent=root,
        ...     methods=["totp", "backup_code"],
        ...     on_verify=lambda m, c: verify(m, c)
        ... )
        >>> panel.pack()
        >>> panel.focus()  # Установить фокус на ввод
    """

    # Отображаемые имена методов
    _METHOD_NAMES: dict[str, str] = {
        "totp": "TOTP (Google Authenticator)",
        "backup_code": "Резервные коды",
        "fido2": "FIDO2 Security Key",
    }

    def __init__(
        self,
        parent: tk.Widget,
        methods: Optional[list[str]] = None,
        on_verify: Optional[Callable[[str, str], bool]] = None,
        theme_manager: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация MFAPanel.

        Args:
            parent: Родительский виджет.
            methods: Список методов ["totp", "backup_code", "fido2"].
            on_verify: Callback для проверки кода.
            theme_manager: Менеджер тем для стилизации.
            **kwargs: Дополнительные параметры для tk.Frame.

        Example:
            >>> panel = MFAPanel(
            ...     parent=root,
            ...     methods=["totp", "backup_code"],
            ...     on_verify=my_verify_callback
            ... )
        """
        super().__init__(parent, **kwargs)

        self._methods: list[str] = methods or ["totp"]
        self._on_verify: Optional[Callable[[str, str], bool]] = on_verify
        self._theme_manager: Optional[Any] = theme_manager

        self._selected_method: str = self._methods[0] if self._methods else "totp"
        self._method_var: tk.StringVar = tk.StringVar(value=self._selected_method)
        self._code_var: tk.StringVar = tk.StringVar()

        # UI элементы
        self._code_entry: Optional[tk.Entry] = None
        self._error_label: Optional[tk.Label] = None
        self._success_label: Optional[tk.Label] = None
        self._verify_btn: Optional[tk.Button] = None
        self._method_radios: list[tk.Radiobutton] = []

        # Применяем тему если есть
        if self._theme_manager is not None:
            self._apply_theme()

        # Создаём UI
        self._create_ui()

        # Настраиваем отслеживание изменений метода
        self._method_var.trace_add("write", self._on_method_changed)

        # Настраиваем автоформатирование для backup_code
        self._code_var.trace_add("write", self._on_code_changed)

    def _apply_theme(self) -> None:
        """Применяет текущую тему к панели."""
        if self._theme_manager is None:
            return

        try:
            self._theme_manager.apply_to_widget(self)
        except (AttributeError, KeyError, tk.TclError) as e:
            # Игнорируем ошибки применения темы
            logging.getLogger(__name__).warning(f"Theme application failed: {e}")

    def _create_ui(self) -> None:
        """Создаёт UI элементы панели."""
        # Фрейм для выбора метода
        method_frame = tk.LabelFrame(
            self,
            text="Метод двухфакторной аутентификации",
            padx=10,
            pady=5,
        )
        method_frame.pack(fill=tk.X, pady=(0, 10))

        if self._theme_manager is not None:
            try:
                self._theme_manager.apply_to_widget(method_frame)
            except (AttributeError, KeyError, tk.TclError) as e:
                logging.getLogger(__name__).warning(f"Theme application failed: {e}")

        # Radio buttons для методов
        for method in self._methods:
            display_name = self._METHOD_NAMES.get(method, method)
            rb = tk.Radiobutton(
                method_frame,
                text=display_name,
                variable=self._method_var,
                value=method,
                anchor=tk.W,
            )
            rb.pack(fill=tk.X, pady=2)
            self._method_radios.append(rb)

            if self._theme_manager is not None:
                try:
                    self._theme_manager.apply_to_widget(rb)
                except (AttributeError, KeyError, tk.TclError) as e:
                    logging.getLogger(__name__).warning(f"Theme application failed: {e}")

        # Фрейм для ввода кода
        code_frame = tk.Frame(self)
        code_frame.pack(fill=tk.X, pady=5)

        if self._theme_manager is not None:
            try:
                self._theme_manager.apply_to_widget(code_frame)
            except (AttributeError, KeyError, tk.TclError) as e:
                logging.getLogger(__name__).warning(f"Theme application failed: {e}")

        # Метка и поле ввода
        code_label = tk.Label(
            code_frame,
            text="Код подтверждения:",
        )
        code_label.pack(side=tk.LEFT, padx=(0, 5))

        if self._theme_manager is not None:
            try:
                self._theme_manager.apply_to_widget(code_label)
            except (AttributeError, KeyError, tk.TclError) as e:
                logging.getLogger(__name__).warning(f"Theme application failed: {e}")

        self._code_entry = tk.Entry(
            code_frame,
            textvariable=self._code_var,
            width=20,
            justify=tk.CENTER,
            font=("Courier", 12),
        )
        self._code_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._code_entry.bind("<Return>", lambda e: self._on_verify_click())

        if self._theme_manager is not None:
            try:
                self._theme_manager.apply_to_widget(self._code_entry)
            except (AttributeError, KeyError, tk.TclError) as e:
                logging.getLogger(__name__).warning(f"Theme application failed: {e}")

        # Кнопка подтверждения
        self._verify_btn = tk.Button(
            self,
            text="Подтвердить",
            command=self._on_verify_click,
            padx=15,
            pady=5,
        )
        self._verify_btn.pack(pady=10)

        if self._theme_manager is not None:
            try:
                self._theme_manager.apply_to_widget(self._verify_btn)
            except (AttributeError, KeyError, tk.TclError) as e:
                logging.getLogger(__name__).warning(f"Theme application failed: {e}")

        # Label для ошибок
        self._error_label = tk.Label(
            self,
            text="",
            fg="#FF0000",
            wraplength=300,
        )
        self._error_label.pack(fill=tk.X)

        if self._theme_manager is not None:
            try:
                self._theme_manager.apply_to_widget(self._error_label)
            except (AttributeError, KeyError, tk.TclError) as e:
                logging.getLogger(__name__).warning(f"Theme application failed: {e}")

        # Label для успеха
        self._success_label = tk.Label(
            self,
            text="",
            fg="#00AA00",
            wraplength=300,
        )
        self._success_label.pack(fill=tk.X)

        if self._theme_manager is not None:
            try:
                self._theme_manager.apply_to_widget(self._success_label)
            except (AttributeError, KeyError, tk.TclError) as e:
                logging.getLogger(__name__).warning(f"Theme application failed: {e}")

        # Обновляем placeholder в зависимости от метода
        self._update_code_placeholder()

    def _on_method_changed(self, *args: Any) -> None:
        """Обработчик смены метода MFA.

        Args:
            *args: Аргументы от trace_add.
        """
        self._selected_method = self._method_var.get()
        self._update_code_placeholder()
        self.clear()

    def _on_code_changed(self, *args: Any) -> None:
        """Обработчик изменения кода (автоформатирование).

        Для backup_code добавляет автоматическое форматирование
        в виде XXXX-XXXX при вводе.

        Args:
            *args: Аргументы от trace_add.
        """
        if self._selected_method != "backup_code":
            return

        code = self._code_var.get()
        if not code:
            return

        # Удаляем все не-alphanumeric символы
        cleaned = re.sub(r"[^a-zA-Z0-9]", "", code)

        # Форматируем как XXXX-XXXX если 8 символов
        if len(cleaned) == 8:
            formatted = f"{cleaned[:4]}-{cleaned[4:]}"
            if formatted != code:
                self._code_var.set(formatted)

    def _update_code_placeholder(self) -> None:
        """Обновляет placeholder для поля кода."""
        if self._code_entry is None:
            return

        if self._selected_method == "totp":
            self._code_entry.configure(show="*")
        elif self._selected_method == "backup_code":
            self._code_entry.configure(show="")
        else:
            self._code_entry.configure(show="*")

    def _on_verify_click(self) -> None:
        """Обработчик нажатия кнопки подтверждения."""
        code = self._code_var.get().strip()

        if not code:
            self.show_error("Введите код подтверждения")
            return

        # Для FIDO2 код не требуется
        if self._selected_method == "fido2":
            self.show_success("Используйте FIDO2 ключ")
            return

        if self._on_verify is not None:
            try:
                result = self._on_verify(self._selected_method, code)
                if result:
                    self.show_success("Код подтверждён")
                else:
                    self.show_error("Неверный код")
            except Exception as e:
                self.show_error(f"Ошибка верификации: {e}")

    def get_code(self) -> str:
        """Возвращает введённый код.

        Returns:
            Строка с кодом подтверждения.

        Example:
            >>> code = panel.get_code()
            >>> print(code)
            "123456"
        """
        return self._code_var.get().strip()

    def get_method(self) -> str:
        """Возвращает выбранный метод MFA.

        Returns:
            Строка с именем метода ("totp", "backup_code", "fido2").

        Example:
            >>> method = panel.get_method()
            >>> print(method)
            "totp"
        """
        return self._selected_method

    def show_error(self, message: str) -> None:
        """Показывает сообщение об ошибке.

        Args:
            message: Текст ошибки для отображения.

        Example:
            >>> panel.show_error("Неверный код")
        """
        if self._error_label is not None:
            self._error_label.configure(text=message)
        if self._success_label is not None:
            self._success_label.configure(text="")

    def show_success(self, message: str) -> None:
        """Показывает сообщение об успехе.

        Args:
            message: Текст успеха для отображения.

        Example:
            >>> panel.show_success("Код подтверждён")
        """
        if self._success_label is not None:
            self._success_label.configure(text=message)
        if self._error_label is not None:
            self._error_label.configure(text="")

    def clear(self) -> None:
        """Очищает поля ввода и сообщения.

        Example:
            >>> panel.clear()
        """
        self._code_var.set("")
        if self._error_label is not None:
            self._error_label.configure(text="")
        if self._success_label is not None:
            self._success_label.configure(text="")

    def focus(self) -> None:
        """Устанавливает фокус на поле ввода кода.

        Example:
            >>> panel.focus()
        """
        if self._code_entry is not None and self._code_entry.winfo_exists():
            self._code_entry.focus_set()

    def set_methods(self, methods: list[str]) -> None:
        """Устанавливает список доступных методов MFA.

        Пересоздаёт radio buttons для нового списка методов.
        Если текущий метод недоступен, выбирается первый.

        Args:
            methods: Новый список методов.

        Example:
            >>> panel.set_methods(["totp", "fido2"])
        """
        self._methods = methods

        # Удаляем старые radio buttons
        for rb in self._method_radios:
            rb.destroy()
        self._method_radios.clear()

        # Пересоздаём UI
        for widget in self.winfo_children():
            widget.destroy()
        self._create_ui()

        # Проверяем выбранный метод
        if self._selected_method not in self._methods and self._methods:
            self._method_var.set(self._methods[0])
            self._selected_method = self._methods[0]
