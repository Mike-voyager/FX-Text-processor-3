"""Centralized window management для FX Text Processor 3.

Реализует централизованное управление окнами приложения с поддержкой
многоконного режима. Отслеживает все диалоги для быстрого закрытия
при блокировке сессии.

Security:
    - Ограничение максимального количества окон (MAX_WINDOWS) для
      предотвращения исчерпания ресурсов.
    - UUID для идентификации окон.
    - Отслеживание всех диалогов для быстрого закрытия при
      блокировке сессии.
"""

from __future__ import annotations

import time
import tkinter as tk
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Optional

# Security constraints
MAX_WINDOWS: Final[int] = 50


@dataclass
class WindowInfo:
    """Информация о зарегистрированном окне.

    Attributes:
        window_id: Уникальный идентификатор окна (UUID).
        toplevel: Ссылка на Tkinter Toplevel виджет.
        title: Заголовок окна.
        document_path: Путь к документу, связанному с окном (опционально).
        is_modal: True если окно модальное.
        created_at: Временная метка создания (Unix timestamp).
        z_order: Z-order порядок окна для управления слоями.
        is_minimized: True если окно свёрнуто.
        documents: Список привязанных документов.

    Example:
        >>> info = WindowInfo(
        ...     window_id="550e8400-e29b-41d4-a716-446655440000",
        ...     toplevel=toplevel_widget,
        ...     title="Document 1",
        ...     document_path=Path("/docs/file.fxsd"),
        ...     is_modal=False,
        ...     created_at=1712812800.0,
        ...     z_order=5
        ... )
    """

    window_id: str
    toplevel: tk.Toplevel | tk.Tk
    title: str
    document_path: Optional[Path]
    is_modal: bool
    created_at: float
    z_order: int
    is_minimized: bool = False
    documents: list[str] = field(default_factory=list)

    @property
    def window(self) -> tk.Toplevel | tk.Tk:
        """Ссылка на виджет окна (алиас для toplevel)."""
        return self.toplevel

    def __post_init__(self) -> None:
        if self.document_path is not None:
            doc_id = str(self.document_path)
            if doc_id not in self.documents:
                self.documents.append(doc_id)


class WindowManager:
    """Централизованный менеджер окон для многоконного режима.

    Управляет регистрацией, отслеживанием и жизненным циклом всех
    окон приложения. Обеспечивает безопасность через ограничение
    количества окон и отслеживание для быстрого закрытия при
    блокировке сессии.

    Attributes:
        _root: Главное окно приложения (tk.Tk).
        _windows: Словарь зарегистрированных окон {window_id: WindowInfo}.
        _next_z_order: Счётчик для определения Z-order.

    Security:
        - MAX_WINDOWS предотвращает исчерпание ресурсов.
        - Все окна отслеживаются для быстрого закрытия при блокировке.

    Example:
        >>> root = tk.Tk()
        >>> manager = WindowManager(root)
        >>> toplevel = tk.Toplevel(root)
        >>> window_id = manager.register_window(toplevel, "New Doc")
        >>> manager.get_window(window_id)
        <tkinter.Toplevel object ...>
    """

    def __init__(self, root: tk.Tk) -> None:
        """Инициализирует менеджер окон.

        Args:
            root: Главное окно приложения.
        """
        self._root: tk.Tk = root
        self._windows: dict[str, WindowInfo] = {}
        self._next_z_order: int = 0
        self._main_window_id: Optional[str] = None

    def set_main_window_id(self, window_id: str) -> None:
        """Устанавливает ID главного окна.

        Args:
            window_id: Идентификатор главного окна.
        """
        self._main_window_id = window_id

    def get_main_window_id(self) -> Optional[str]:
        """Возвращает ID главного окна.

        Returns:
            Идентификатор главного окна или None.
        """
        return self._main_window_id

    def is_main_window(self, window_id: str) -> bool:
        """Проверяет является ли окно главным.

        Args:
            window_id: Идентификатор окна.

        Returns:
            True если это главное окно.
        """
        return window_id == self._main_window_id

    def register_window(
        self,
        window: tk.Toplevel | tk.Tk,
        title: str = "",
        document_path: Optional[Path] = None,
        is_modal: bool = False,
        is_main: bool = False,
    ) -> str:
        """Регистрирует новое окно в менеджере.

        Создаёт уникальный идентификатор и добавляет окно в реестр.
        Проверяет ограничение MAX_WINDOWS.

        Args:
            window: Окно для регистрации (Toplevel или Tk).
            title: Заголовок окна.
            document_path: Путь к связанному документу (опционально).
            is_modal: True если окно модальное.

        Returns:
            Уникальный идентификатор окна (UUID).

        Raises:
            RuntimeError: Если превышен лимит MAX_WINDOWS.

        Example:
            >>> toplevel = tk.Toplevel(root)
            >>> window_id = manager.register_window(
            ...     toplevel, "My Doc", Path("/docs/file.fxsd")
            ... )
        """
        # Проверяем, не зарегистрировано ли уже это окно
        for existing_id, existing_info in self._windows.items():
            if existing_info.toplevel is window:
                return existing_id

        if len(self._windows) >= MAX_WINDOWS:
            raise RuntimeError(
                f"Maximum window limit ({MAX_WINDOWS}) reached. Close unused windows."
            )

        window_id = str(uuid.uuid4())
        z_order = self._next_z_order
        self._next_z_order += 1

        window_info = WindowInfo(
            window_id=window_id,
            toplevel=window,
            title=title,
            document_path=document_path,
            is_modal=is_modal,
            created_at=time.time(),
            z_order=z_order,
            is_minimized=False,
        )

        self._windows[window_id] = window_info

        # Если это главное окно (Tk или явно is_main), сохраняем его ID
        if isinstance(window, tk.Tk) or is_main:
            self._main_window_id = window_id

        return window_id

    def unregister_window(self, window_id: str) -> None:
        """Удаляет регистрацию окна.

        Args:
            window_id: Идентификатор окна для удаления.

        Raises:
            KeyError: Если окно с таким ID not found.

        Example:
            >>> manager.unregister_window(window_id)
        """
        if window_id not in self._windows:
            raise ValueError(f"Window not found: {window_id}")

        del self._windows[window_id]

    def get_window(self, window_id: str) -> tk.Toplevel | tk.Tk | None:
        """Возвращает ссылку на окно по ID.

        Args:
            window_id: Идентификатор окна.

        Returns:
            Ссылка на Toplevel/Tk или None если окно not found.

        Example:
            >>> window = manager.get_window(window_id)
            >>> if window:
            ...     window.focus()
        """
        info = self._windows.get(window_id)
        if info is None:
            return None
        return info.toplevel

    def bring_to_front(self, window_id: str) -> None:
        """Выводит окно на передний план.

        Обновляет Z-order окна и активирует его.

        Args:
            window_id: Идентификатор окна.

        Raises:
            KeyError: Если окно not found.

        Example:
            >>> manager.bring_to_front(window_id)
        """
        info = self._windows.get(window_id)
        if info is None:
            raise KeyError(f"Window with ID '{window_id}' not found")

        # Обновляем Z-order
        old_info = self._windows[window_id]
        new_z_order = self._next_z_order
        self._next_z_order += 1

        new_info = WindowInfo(
            window_id=old_info.window_id,
            toplevel=old_info.toplevel,
            title=old_info.title,
            document_path=old_info.document_path,
            is_modal=old_info.is_modal,
            created_at=old_info.created_at,
            z_order=new_z_order,
        )
        self._windows[window_id] = new_info

        # Выводим на передний план
        try:
            info.toplevel.lift()
            info.toplevel.focus_force()
        except tk.TclError:
            pass

    def update_window_title(self, window_id: str, new_title: str) -> bool:
        """Обновляет заголовок зарегистрированного окна.

        Создаёт новый WindowInfo с обновлённым заголовком.

        Args:
            window_id: Идентификатор окна.
            new_title: Новый заголовок.

        Returns:
            True если заголовок обновлён, False если окно not found.

        Example:
            >>> manager.update_window_title(window_id, "New Title")
        """
        if window_id not in self._windows:
            return False

        old_info = self._windows[window_id]
        new_info = WindowInfo(
            window_id=old_info.window_id,
            toplevel=old_info.toplevel,
            title=new_title,
            document_path=old_info.document_path,
            is_modal=old_info.is_modal,
            created_at=old_info.created_at,
            z_order=old_info.z_order,
            is_minimized=old_info.is_minimized,
        )
        self._windows[window_id] = new_info
        return True

    def minimize_all(self) -> int:
        """Сворачивает все зарегистрированные окна.

        Главное окно (root) не затрагивается.

        Returns:
            Количество свёрнутых окон.

        Example:
            >>> count = manager.minimize_all()
        """
        count = 0
        for info in self._windows.values():
            if info.window_id != self._main_window_id:
                try:
                    info.toplevel.iconify()
                    count += 1
                except tk.TclError:
                    pass
        return count

    def restore_all(self) -> int:
        """Восстанавливает все свёрнутые окна.

        Returns:
            Количество восстановленных окон.

        Example:
            >>> count = manager.restore_all()
        """
        count = 0
        for info in self._windows.values():
            if info.window_id != self._main_window_id:
                try:
                    info.toplevel.deiconify()
                    count += 1
                except tk.TclError:
                    pass
        return count

    def close_all_except_main(self) -> int:
        """Закрывает все окна кроме главного.

        Используется при блокировке сессии для быстрого закрытия
        всех диалогов и окон документов.

        Returns:
            Количество закрытых окон.

        Security:
            - Критичный метод для блокировки сессии.
            - Закрывает все окна, кроме root.

        Example:
            >>> # При блокировке сессии
            >>> closed = manager.close_all_except_main()
        """
        closed_count = 0
        # Создаём копию ключей, так как словарь будет изменяться
        window_ids = list(self._windows.keys())
        for window_id in window_ids:
            if window_id == self._main_window_id:
                continue
            info = self._windows.get(window_id)
            if info is not None:
                try:
                    info.toplevel.destroy()
                    closed_count += 1
                except tk.TclError:
                    pass
                # unregister будет вызван из обработчика destroy
                # но на случай если его нет — удаляем явно
                if window_id in self._windows:
                    del self._windows[window_id]
        return closed_count

    def get_window_list(self) -> list[WindowInfo]:
        """Возвращает список всех зарегистрированных окон.

        Список отсортирован по Z-order (от нижнего к верхнему).

        Returns:
            Список WindowInfo объектов.

        Example:
            >>> windows = manager.get_window_list()
            >>> for w in windows:
            ...     print(f"{w.title}: {w.window_id}")
        """
        return sorted(self._windows.values(), key=lambda w: w.z_order)

    def transfer_document(self, from_id: str, to_id: str, doc_id: str) -> bool:
        """Передаёт документ от одного окна к другому.

        Args:
            from_id: Идентификатор исходного окна.
            to_id: Идентификатор целевого окна.
            doc_id: Идентификатор документа.

        Returns:
            True если передача успешна, False при ошибке.
        """
        from_info = self._windows.get(from_id)
        to_info = self._windows.get(to_id)

        if from_info is None or to_info is None:
            return False

        # Проверяем что у исходного окна есть документ
        if doc_id not in from_info.documents:
            return False

        # Переносим документ
        from_info.documents.remove(doc_id)
        if doc_id not in to_info.documents:
            to_info.documents.append(doc_id)

        return True

    def get_window_count(self) -> int:
        """Возвращает количество зарегистрированных окон.

        Returns:
            Текущее количество окон.

        Example:
            >>> count = manager.get_window_count()
            >>> if count > 10:
            ...     print("Много окон открыто")
        """
        return len(self._windows)

    def is_window_registered(self, window_id: str) -> bool:
        """Проверяет, зарегистрировано ли окно.

        Args:
            window_id: Идентификатор окна.

        Returns:
            True если окно зарегистрировано.

        Example:
            >>> if manager.is_window_registered(window_id):
            ...     manager.bring_to_front(window_id)
        """
        return window_id in self._windows

    def assign_document(self, window_id: str, doc_id: str) -> bool:
        """Назначает документ окну (добавляет в список documents).

        Args:
            window_id: Идентификатор окна.
            doc_id: Идентификатор документа.

        Returns:
            True если назначение успешно.
        """
        if window_id not in self._windows:
            return False

        info = self._windows[window_id]
        if doc_id not in info.documents:
            info.documents.append(doc_id)
        return True

    def get_window_info(self, window_id: str) -> Optional[WindowInfo]:
        """Возвращает информацию о конкретном окне.

        Args:
            window_id: Идентификатор окна.

        Returns:
            WindowInfo или None если окно not found.
        """
        return self._windows.get(window_id)

    def clear_all(self) -> int:
        """Удаляет все регистрации окон.

        Returns:
            Количество удалённых окон.
        """
        count = len(self._windows)
        self._windows.clear()
        self._next_z_order = 0
        self._main_window_id = None
        return count
