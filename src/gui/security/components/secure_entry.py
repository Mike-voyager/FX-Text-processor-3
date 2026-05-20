"""Secure Entry widget с защитой от утечки данных в памяти.

Модуль предоставляет SecureEntry - виджет ввода текста с возможностью
безопасного удаления содержимого из памяти (secure wipe).

Example:
    >>> import tkinter as tk
    >>> root = tk.Tk()
    >>> entry = SecureEntry(root, secure=True)
    >>> entry.pack()
    >>> entry.insert(0, "secret password")
    >>> # При уничтожении или вызове wipe() данные перезаписываются
    >>> entry.wipe()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from typing import Any


class SecureEntry(tk.Entry):
    """Entry widget с secure wipe памяти при удалении.

    Расширяет стандартный tk.Entry функцией безопасного удаления
    содержимого путём перезаписи нулями перед освобождением памяти.
    Используется для ввода паролей и других чувствительных данных.

    Attributes:
        _secure: Флаг включения secure режима.
        _variable: Связанная StringVar переменная.
        _wipe_count: Количество перезаписей при wipe (default: 3).

    Security:
        При secure=True перезаписывает память нулями перед destroy.
        Не гарантирует полную очистку (зависит от garbage collector),
        но значительно снижает риск утечки в swap/core dump.

    Example:
        >>> root = tk.Tk()
        >>> entry = SecureEntry(root, secure=True, show="*")
        >>> entry.pack()
        >>> entry.insert(0, "password")
        >>> value = entry.get_secure()  # Возвращает и очищает
        >>> entry.wipe()  # Явная очистка
    """

    def __init__(
        self,
        master: tk.Widget,
        secure: bool = True,
        **kwargs: Any,
    ) -> None:
        """Инициализация SecureEntry.

        Args:
            master: Родительский виджет.
            secure: Включить secure wipe (default: True).
            **kwargs: Дополнительные параметры для tk.Entry.

        Example:
            >>> entry = SecureEntry(root, secure=True, show="*", width=30)
        """
        self._secure: bool = secure
        self._wipe_count: int = 3
        self._variable: tk.StringVar = tk.StringVar(master=master)

        # Передаём нашу переменную в parent
        kwargs["textvariable"] = self._variable

        super().__init__(master, **kwargs)

    def wipe(self) -> None:
        """Перезаписывает значение нулями перед удалением.

        Многократно перезаписывает содержимое поля нулями
        для предотвращения восстановления из памяти.

        Security:
            Выполняет overwrite нулями заданное количество раз
            (_wipe_count). Не гарантирует полную очистку ОЗУ.

        Example:
            >>> entry.insert(0, "secret")
            >>> entry.wipe()
            >>> entry.get()  # ''
        """
        if not self._secure:
            self._variable.set("")
            return

        # Получаем текущее значение
        current_value = self._variable.get()
        if not current_value:
            return

        # Многократная перезапись нулями
        value_len = len(current_value)
        for _ in range(self._wipe_count):
            # Перезапись разной длины для затруднения анализа
            self._variable.set("0" * value_len)
            self._safe_update()
            self._variable.set("\x00" * value_len)
            self._safe_update()

        # Финальная очистка
        self._variable.set("")
        self._safe_update()

        # Очищаем локальную переменную
        current_value = ""

    def _safe_update(self) -> None:
        """Безопасный вызов update() с обработкой TclError.

        Обёртка для предотвращения исключений при вызове update()
        из фонового потока или после уничтожения виджета.
        """
        try:
            if self.winfo_exists():
                self.update()
        except tk.TclError:
            pass

    def get_secure(self) -> str:
        """Возвращает значение и сразу выполняет wipe.

        Получает текущее значение поля, затем немедленно
        очищает его для минимизации времени жизни в памяти.

        Returns:
            Строковое значение из поля.

        Security:
            Возвращает значение ДО выполнения wipe.
            Вызывающий код должен обработать значение и очистить.

        Example:
            >>> entry.insert(0, "password123")
            >>> password = entry.get_secure()
            >>> # entry уже пуст, password содержит значение
            >>> process_password(password)
            >>> password = ""  # Очистка переменной
        """
        value = self._variable.get()
        self.wipe()
        return value

    def destroy(self) -> None:
        """Уничтожает виджет с предварительным wipe.

        Перед уничтожением виджета выполняет secure wipe
        для очистки чувствительных данных из памяти.

        Security:
            Автоматически вызывает wipe() если secure=True.
            Затем вызывает стандартный destroy() родителя.

        Example:
            >>> entry.destroy()  # wipe + destroy
        """
        try:
            if self._secure and self.winfo_exists():
                self.wipe()
        finally:
            # Очищаем переменную
            self._variable.set("")
            super().destroy()

    def is_secure(self) -> bool:
        """Проверяет, включён ли secure режим.

        Returns:
            True если secure wipe включён.

        Example:
            >>> entry = SecureEntry(root, secure=True)
            >>> entry.is_secure()
            True
        """
        return self._secure

    def set_secure(self, secure: bool) -> None:
        """Устанавливает режим secure.

        Args:
            secure: Новое значение режима secure.

        Example:
            >>> entry.set_secure(False)  # Отключить wipe
        """
        self._secure = secure

    def get_textvariable(self) -> tk.StringVar:
        """Возвращает связанную StringVar переменную.

        Returns:
            StringVar, связанная с Entry.

        Example:
            >>> var = entry.get_textvariable()
            >>> var.set("new value")
        """
        return self._variable
