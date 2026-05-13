"""CardFileTabBar для FX Text Processor 3.

Реализует вкладки карточного файла с поддержкой:
- Иконок типа документа (FreeForm / StructuredForm)
- Индикатора изменений (modified)
- Кнопки закрытия на hover
- Кнопки добавления новой вкладки
- Scroll при переполнении
- Контекстного меню (Close, Close All, Close Others)

Security:
- Ограничение длины заголовка (50 символов)
- Санитизация document_id
- Нет eval/exec

Example:
    >>> tab_bar = CardFileTabBar(parent_frame, controller=ctrl)
    >>> tab_bar.mount(parent_frame)
    >>> tab_bar.add_tab("doc_1", "Document 1", DocumentMode.FREE_FORM)
    >>> tab_bar.set_tab_modified("doc_1", True)
    >>> tab_bar.set_active_tab("doc_1")

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import re
import tkinter as tk
from dataclasses import dataclass, field
from typing import Any, Callable, Final, Optional, Pattern

from src.documents.types.document_type import DocumentMode
from src.gui.components.base.widget import BaseWidget
from src.gui.components.sync.window_sync_indicator import (
    SYNC_STATUS_COLORS,
    SyncStatus,
    TabSyncIndicator,
)
from src.gui.layout.layout_constants import PADDING_SMALL, TABBAR_HEIGHT
from src.gui.themes import ThemeRegistry

logger: logging.Logger = logging.getLogger(__name__)


def _theme_color(key: str) -> str:
    """Возвращает цвет из текущей темы.

    Args:
        key: Идентификатор цвета.

    Returns:
        Цвет в формате HEX.
    """
    try:
        return ThemeRegistry.get_instance().get_current().get_color(key)
    except (AttributeError, KeyError):
        # Log the error if needed, but in this case, we are just returning a fallback color.
        # Since this is a theme color function, we don't want to break the UI if the theme fails.
        # We'll log at debug level.
        logger.debug("Failed to get theme color, using fallback")
        return "#333333"


# Constants
MAX_TABS: Final[int] = 20
MAX_TITLE_LENGTH: Final[int] = 50
TAB_MIN_WIDTH: Final[int] = 80
TAB_MAX_WIDTH: Final[int] = 200
TAB_HEIGHT: Final[int] = TABBAR_HEIGHT - 4  # 2px padding top/bottom

# Icons for document types
ICON_FREEFORM: Final[str] = "📄"
ICON_STRUCTURED: Final[str] = "📋"
ICON_SPECIAL: Final[str] = "🔴"
ICON_CLOSE: Final[str] = "×"
ICON_NEW: Final[str] = "+"
ICON_MODIFIED: Final[str] = "(*)"

# Tab state indicators
INDICATOR_MODIFIED: Final[str] = "●"
INDICATOR_ENCRYPTED: Final[str] = "🔒"
INDICATOR_READONLY: Final[str] = "👁️"

# Indicator colors (static by spec)
MODIFIED_COLOR: Final[str] = "#FFA500"
ENCRYPTED_COLOR: Final[str] = "#00FF00"
READONLY_COLOR: Final[str] = "#808080"

# Document ID validation pattern
DOCUMENT_ID_PATTERN: Final[Pattern[str]] = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class TabInfo:
    """Информация о вкладке.

    Attributes:
        document_id: Уникальный идентификатор документа.
        title: Заголовок вкладки.
        mode: Режим документа (FreeForm / StructuredForm).
        modified: Флаг изменений.
        encrypted: Флаг шифрования.
        readonly: Флаг только для чтения.
        is_special: Флаг Special Mode.
        sync_status: Статус синхронизации.
        widget: Ссылка на виджет вкладки.
        sync_indicator: Ссылка на TabSyncIndicator.
    """

    document_id: str
    title: str
    mode: DocumentMode
    modified: bool = False
    encrypted: bool = False
    readonly: bool = False
    is_special: bool = False
    sync_status: str = field(default=SyncStatus.OFFLINE)
    widget: Optional[tk.Frame] = field(default=None, repr=False)
    sync_indicator: Optional[TabSyncIndicator] = field(default=None, repr=False)


class CardFileTabBar(BaseWidget):
    """Вкладки карточного файла с поддержкой множественных документов.

    Реализует CardFileTabBarProtocol, предоставляя:
    - Добавление/удаление вкладок
    - Переключение активной вкладки
    - Индикацию изменений
    - Scroll при переполнении
    - Контекстное меню

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        on_new_tab: Callback для создания новой вкладки.
        on_tab_close: Callback для закрытия вкладки.
        on_tab_activate: Callback для активации вкладки.

    Example:
        >>> def on_new():
        ...     print("Create new document")
        >>> tab_bar = CardFileTabBar(parent_frame, on_new_tab=on_new)
        >>> tab_bar.mount(parent_frame)
        >>> tab_bar.add_tab("doc_1", "Test", DocumentMode.FREE_FORM)
    """

    def __init__(
        self,
        widget_id: str = "cardfile_tabbar",
        controller: Optional[Any] = None,
        on_new_tab: Optional[Callable[[], None]] = None,
        on_tab_close: Optional[Callable[[str], bool]] = None,
        on_tab_activate: Optional[Callable[[str], None]] = None,
        sync_service: Optional[Any] = None,
    ) -> None:
        """Инициализация CardFileTabBar.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
            on_new_tab: Callback для создания новой вкладки.
            on_tab_close: Callback для закрытия вкладки (должен вернуть True/False).
            on_tab_activate: Callback для активации вкладки.
            sync_service: Опциональный SyncService для индикаторов синхронизации.

        Example:
            >>> tab_bar = CardFileTabBar(
            ...     on_new_tab=lambda: print("New"),
            ...     on_tab_close=lambda id: True,
            ...     on_tab_activate=lambda id: print(f"Active: {id}"),
            ... )
        """
        super().__init__(widget_id=widget_id, controller=controller)

        # Callbacks
        self._on_new_tab: Optional[Callable[[], None]] = on_new_tab
        self._on_tab_close: Optional[Callable[[str], bool]] = on_tab_close
        self._on_tab_activate: Optional[Callable[[str], None]] = on_tab_activate

        # Sync service
        self._sync_service: Optional[Any] = sync_service

        # Tab storage
        self._tabs: dict[str, TabInfo] = {}
        self._active_tab_id: Optional[str] = None
        self._tab_order: list[str] = []

        # Widget references
        self._tk_frame: Optional[tk.Frame] = None
        self._tk_canvas: Optional[tk.Canvas] = None
        self._tk_scroll_frame: Optional[tk.Frame] = None
        self._tk_new_btn: Optional[tk.Button] = None
        self._tk_context_menu: Optional[tk.Menu] = None

        # Scroll state
        self._scroll_x: int = 0
        self._max_scroll: int = 0

        # Hover state for close buttons
        self._hover_tab_id: Optional[str] = None

    @property
    def widget(self) -> tk.Widget:
        """Возвращает tkinter widget для размещения.

        Returns:
            Корневой Frame CardFileTabBar.

        Raises:
            RuntimeError: Если виджет не смонтирован.
        """
        if self._tk_frame is None:
            raise RuntimeError("CardFileTabBar не смонтирован")
        return self._tk_frame

    def show(self) -> None:
        """Показывает компонент."""
        if self._tk_frame is not None:
            self._tk_frame.pack(fill="x", side="top")

    def hide(self) -> None:
        """Скрывает компонент."""
        if self._tk_frame is not None:
            self._tk_frame.pack_forget()

    def is_visible(self) -> bool:
        """Проверяет видимость компонента.

        Returns:
            True если виджет отображается.
        """
        if self._tk_frame is None:
            return False
        return self._tk_frame.winfo_viewable() == 1

    def add_tab(
        self,
        document_id: str,
        title: str,
        mode: DocumentMode,
        modified: bool = False,
    ) -> None:
        """Добавляет новую вкладку.

        Args:
            document_id: Уникальный идентификатор документа.
            title: Заголовок вкладки (будет обрезан до 50 символов).
            mode: Режим документа (FREE_FORM / STRUCTURED_FORM).
            modified: Флаг изменений.

        Raises:
            ValueError: Если достигнут лимит вкладок (MAX_TABS).
            ValueError: Если document_id невалиден.

        Example:
            >>> tab_bar.add_tab("doc_1", "My Document", DocumentMode.FREE_FORM)
            >>> tab_bar.add_tab("doc_2", "Form", DocumentMode.STRUCTURED_FORM, modified=True)
        """
        # Security: Sanitize document_id
        if not self._is_valid_document_id(document_id):
            raise ValueError(
                f"Невалидный document_id: '{document_id}'. Разрешены только буквы, цифры, _ и -"
            )

        # Check for duplicates
        if document_id in self._tabs:
            # Activate existing tab
            self.set_active_tab(document_id)
            return

        # Check max tabs limit
        if len(self._tabs) >= MAX_TABS:
            raise ValueError(f"Достигнут лимит вкладок: {MAX_TABS}")

        # Security: Limit title length
        safe_title = title[:MAX_TITLE_LENGTH] if title else "Untitled"

        # Create tab info
        tab_info = TabInfo(
            document_id=document_id,
            title=safe_title,
            mode=mode,
            modified=modified,
        )

        self._tabs[document_id] = tab_info
        self._tab_order.append(document_id)

        # Create tab widget
        if self._tk_scroll_frame is not None and self.is_mounted():
            self._create_tab_widget(tab_info)
            self._update_scroll_region()
            self._update_layout()

        # Set as active if first tab
        if len(self._tabs) == 1:
            self.set_active_tab(document_id)

    def close_tab(self, document_id: str) -> bool:
        """Закрывает вкладку.

        Args:
            document_id: Идентификатор документа для закрытия.

        Returns:
            True если вкладка успешно закрыта, False если отменено или не найдена.

        Example:
            >>> if tab_bar.close_tab("doc_1"):
            ...     print("Tab closed successfully")
        """
        # Security: Sanitize document_id
        if not self._is_valid_document_id(document_id):
            return False

        if document_id not in self._tabs:
            return False

        # Call callback for confirmation
        if self._on_tab_close is not None:
            if not self._on_tab_close(document_id):
                return False

        # Unmount sync_indicator перед удалением
        tab_info = self._tabs[document_id]
        if tab_info.sync_indicator is not None:
            try:
                tab_info.sync_indicator.unmount()
            except (tk.TclError, RuntimeError):
                logger.debug("Sync indicator unmount failed (non-critical)")

        # Remove tab widget
        if tab_info.widget is not None:
            tab_info.widget.destroy()

        # Remove from storage
        del self._tabs[document_id]
        if document_id in self._tab_order:
            self._tab_order.remove(document_id)

        # Update active tab
        if self._active_tab_id == document_id:
            self._active_tab_id = None
            if self._tab_order:
                self.set_active_tab(self._tab_order[-1])

        self._update_scroll_region()
        self._update_layout()
        return True

    def set_active_tab(self, document_id: str) -> None:
        """Устанавливает активную вкладку.

        Args:
            document_id: Идентификатор документа для активации.

        Raises:
            ValueError: Если document_id невалиден.

        Example:
            >>> tab_bar.set_active_tab("doc_1")
        """
        # Security: Sanitize document_id
        if not self._is_valid_document_id(document_id):
            raise ValueError(f"Невалидный document_id: '{document_id}'")

        if document_id not in self._tabs:
            return

        # Deactivate previous tab
        if self._active_tab_id is not None and self._active_tab_id in self._tabs:
            old_tab = self._tabs[self._active_tab_id]
            self._update_tab_appearance(old_tab, active=False)

        # Activate new tab
        self._active_tab_id = document_id
        new_tab = self._tabs[document_id]
        self._update_tab_appearance(new_tab, active=True)

        # Ensure tab is visible (scroll to it)
        self._scroll_to_tab(document_id)

        # Call callback
        if self._on_tab_activate is not None:
            self._on_tab_activate(document_id)

    def set_tab_modified(self, document_id: str, modified: bool) -> None:
        """Устанавливает индикатор изменений для вкладки.

        Args:
            document_id: Идентификатор документа.
            modified: True если документ был изменён.

        Raises:
            ValueError: Если document_id невалиден.

        Example:
            >>> tab_bar.set_tab_modified("doc_1", True)
        """
        # Security: Sanitize document_id
        if not self._is_valid_document_id(document_id):
            raise ValueError(f"Невалидный document_id: '{document_id}'")

        if document_id not in self._tabs:
            return

        tab_info = self._tabs[document_id]
        tab_info.modified = modified

        # Update tab appearance
        self._update_tab_appearance(tab_info, active=(document_id == self._active_tab_id))

    def set_tab_encrypted(self, document_id: str, encrypted: bool) -> None:
        """Устанавливает индикатор шифрования для вкладки.

        Args:
            document_id: Идентификатор документа.
            encrypted: True если документ зашифрован.

        Raises:
            ValueError: Если document_id невалиден.
        """
        if not self._is_valid_document_id(document_id):
            raise ValueError(f"Невалидный document_id: '{document_id}'")

        if document_id not in self._tabs:
            return

        tab_info = self._tabs[document_id]
        tab_info.encrypted = encrypted
        self._update_tab_appearance(tab_info, active=(document_id == self._active_tab_id))

    def set_tab_readonly(self, document_id: str, readonly: bool) -> None:
        """Устанавливает индикатор только для чтения для вкладки.

        Args:
            document_id: Идентификатор документа.
            readonly: True если документ только для чтения.

        Raises:
            ValueError: Если document_id невалиден.
        """
        if not self._is_valid_document_id(document_id):
            raise ValueError(f"Невалидный document_id: '{document_id}'")

        if document_id not in self._tabs:
            return

        tab_info = self._tabs[document_id]
        tab_info.readonly = readonly
        self._update_tab_appearance(tab_info, active=(document_id == self._active_tab_id))

    def set_tab_mode(self, document_id: str, mode: DocumentMode) -> None:
        """Устанавливает режим документа для вкладки.

        Args:
            document_id: Идентификатор документа.
            mode: Новый режим документа.

        Raises:
            ValueError: Если document_id невалиден.
        """
        if not self._is_valid_document_id(document_id):
            raise ValueError(f"Невалидный document_id: '{document_id}'")

        if document_id not in self._tabs:
            return

        tab_info = self._tabs[document_id]
        tab_info.mode = mode
        self._update_tab_appearance(tab_info, active=(document_id == self._active_tab_id))

    def set_tab_special(self, document_id: str, is_special: bool) -> None:
        """Устанавливает индикатор Special Mode для вкладки.

        Args:
            document_id: Идентификатор документа.
            is_special: True если вкладка в Special Mode.

        Raises:
            ValueError: Если document_id невалиден.
        """
        if not self._is_valid_document_id(document_id):
            raise ValueError(f"Невалидный document_id: '{document_id}'")

        if document_id not in self._tabs:
            return

        tab_info = self._tabs[document_id]
        tab_info.is_special = is_special
        self._update_tab_appearance(tab_info, active=(document_id == self._active_tab_id))

    def set_tab_sync_status(self, document_id: str, status: str) -> None:
        """Устанавливает статус синхронизации для вкладки.

        Args:
            document_id: Идентификатор документа.
            status: Статус из SyncStatus (SYNCED, SYNCING, CONFLICT, OFFLINE).

        Raises:
            ValueError: Если document_id невалиден или статус неизвестен.
        """
        if not self._is_valid_document_id(document_id):
            raise ValueError(f"Невалидный document_id: '{document_id}'")
        if status not in SYNC_STATUS_COLORS:
            raise ValueError(f"Невалидный статус синхронизации: '{status}'")

        if document_id not in self._tabs:
            return

        tab_info = self._tabs[document_id]
        tab_info.sync_status = status
        if tab_info.sync_indicator is not None:
            tab_info.sync_indicator.set_status(status)
        else:
            self._update_tab_appearance(tab_info, active=(document_id == self._active_tab_id))

    def get_active_tab(self) -> Optional[str]:
        """Возвращает идентификатор активной вкладки.

        Returns:
            document_id активной вкладки или None если нет активных вкладок.

        Example:
            >>> active_id = tab_bar.get_active_tab()
            >>> if active_id:
            ...     print(f"Active tab: {active_id}")
        """
        return self._active_tab_id

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт фактический Tkinter виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный корневой Frame.
        """
        # Root frame
        self._tk_frame = tk.Frame(
            parent,
            height=TABBAR_HEIGHT,
            bg=_theme_color("tab_inactive_bg"),
            relief="flat",
        )
        self._tk_frame.pack_propagate(False)

        # Canvas for scrolling tabs
        self._tk_canvas = tk.Canvas(
            self._tk_frame,
            height=TABBAR_HEIGHT,
            bg=_theme_color("tab_inactive_bg"),
            highlightthickness=0,
        )
        self._tk_canvas.pack(side="left", fill="both", expand=True)

        # Frame inside canvas for tabs
        self._tk_scroll_frame = tk.Frame(
            self._tk_canvas,
            height=TABBAR_HEIGHT - 2,
            bg=_theme_color("tab_inactive_bg"),
        )
        self._tk_canvas.create_window(
            (0, 0),
            window=self._tk_scroll_frame,
            anchor="nw",
            height=TABBAR_HEIGHT - 2,
        )

        # New tab button
        self._tk_new_btn = tk.Button(
            self._tk_frame,
            text=ICON_NEW,
            width=2,
            height=1,
            bg=_theme_color("new_btn_bg"),
            fg=_theme_color("new_btn_fg"),
            activebackground=_theme_color("new_btn_hover"),
            relief="flat",
            cursor="hand2",
            command=self._on_new_tab_click,
        )
        self._tk_new_btn.pack(side="right", padx=PADDING_SMALL, pady=2)

        # Bind scroll events
        self._tk_canvas.bind("<Configure>", self._on_canvas_configure)
        self._tk_canvas.bind("<MouseWheel>", self._on_mousewheel)
        self._tk_canvas.bind("<Button-4>", self._on_mousewheel)  # Linux scroll up
        self._tk_canvas.bind("<Button-5>", self._on_mousewheel)  # Linux scroll down

        # Recreate existing tabs (if any)
        for document_id in self._tab_order:
            if document_id in self._tabs:
                self._create_tab_widget(self._tabs[document_id])

        self._update_scroll_region()
        self._update_layout()

        return self._tk_frame

    def _setup_bindings(self) -> None:
        """Настраивает event bindings."""
        pass  # Bindings set up in _create_tk_widget

    def _cleanup(self) -> None:
        """Очищает ресурсы перед демонтированием."""
        self._tk_context_menu = None
        self._tk_new_btn = None
        self._tk_scroll_frame = None
        self._tk_canvas = None
        self._tk_frame = None

    def _is_valid_document_id(self, document_id: str) -> bool:
        """Проверяет валидность document_id.

        Args:
            document_id: Идентификатор для проверки.

        Returns:
            True если document_id валиден.
        """
        if not document_id or not isinstance(document_id, str):
            return False
        return bool(DOCUMENT_ID_PATTERN.match(document_id))

    def _sanitize_title(self, title: str) -> str:
        """Санитизирует заголовок вкладки.

        Args:
            title: Исходный заголовок.

        Returns:
            Санитизированный заголовок.
        """
        if not title:
            return "Untitled"
        # Remove control characters
        sanitized = "".join(c for c in title if c.isprintable() or c.isspace())
        return sanitized[:MAX_TITLE_LENGTH]

    def _get_icon_for_mode(self, mode: DocumentMode, is_special: bool = False) -> str:
        """Возвращает иконку для режима документа.

        Args:
            mode: Режим документа.
            is_special: True если вкладка в Special Mode.

        Returns:
            Иконка в виде строки.
        """
        if is_special:
            return ICON_SPECIAL
        if mode == DocumentMode.FREE_FORM:
            return ICON_FREEFORM
        return ICON_STRUCTURED

    def _create_tab_widget(self, tab_info: TabInfo) -> None:
        """Создаёт виджет вкладки.

        Args:
            tab_info: Информация о вкладке.
        """
        if self._tk_scroll_frame is None:
            return

        # Tab frame
        tab_frame = tk.Frame(
            self._tk_scroll_frame,
            height=TAB_HEIGHT,
            bg=_theme_color("tab_inactive_bg"),
            relief="raised",
            bd=1,
        )
        tab_frame.pack_propagate(False)

        # Store widget reference
        tab_info.widget = tab_frame

        # Modified indicator
        mod_label = tk.Label(
            tab_frame,
            text=INDICATOR_MODIFIED,
            font=("Segoe UI Emoji", 9),
            bg=_theme_color("tab_inactive_bg"),
            fg=MODIFIED_COLOR,
            padx=2,
        )

        # Encrypted indicator
        enc_label = tk.Label(
            tab_frame,
            text=INDICATOR_ENCRYPTED,
            font=("Segoe UI Emoji", 9),
            bg=_theme_color("tab_inactive_bg"),
            fg=ENCRYPTED_COLOR,
            padx=2,
        )

        # Readonly indicator
        ro_label = tk.Label(
            tab_frame,
            text=INDICATOR_READONLY,
            font=("Segoe UI Emoji", 9),
            bg=_theme_color("tab_inactive_bg"),
            fg=READONLY_COLOR,
            padx=2,
        )

        # Title label
        title_label = tk.Label(
            tab_frame,
            text=tab_info.title,
            bg=_theme_color("tab_inactive_bg"),
            fg=_theme_color("tab_inactive_fg"),
            font=("TkDefaultFont", 9),
            padx=4,
            pady=2,
            cursor="hand2",
        )
        title_label.pack(side="left", fill="both", expand=True)

        # Close button
        close_btn = tk.Label(
            tab_frame,
            text=ICON_CLOSE,
            bg=_theme_color("tab_inactive_bg"),
            fg=_theme_color("tab_inactive_fg"),
            font=("TkDefaultFont", 10, "bold"),
            padx=4,
            cursor="hand2",
        )
        close_btn.pack(side="right", fill="y")

        # Sync indicator (before close button)
        sync_indicator = TabSyncIndicator(
            tab_frame=tab_frame,
            document_id=tab_info.document_id,
            sync_service=self._sync_service,  # ← NEW
            status=tab_info.sync_status,
        )
        sync_indicator.mount(before_widget=close_btn)
        tab_info.sync_indicator = sync_indicator

        # Store references for dynamic updates
        indicators: dict[str, tk.Label] = {
            "modified": mod_label,
            "encrypted": enc_label,
            "readonly": ro_label,
        }
        tab_frame._indicators = indicators  # type: ignore[attr-defined]
        tab_frame._title_label = title_label  # type: ignore[attr-defined]
        tab_frame._close_btn = close_btn  # type: ignore[attr-defined]

        # Bind events
        def make_tab_click_handler(tid: str) -> Callable[[tk.Event], None]:
            def handler(e: tk.Event) -> None:
                self._on_tab_click(tid)

            return handler

        def make_tab_right_click_handler(tid: str) -> Callable[[tk.Event], None]:
            def handler(e: tk.Event) -> None:
                self._on_tab_right_click(tid, e)

            return handler

        def make_close_hover_handler(btn: tk.Label) -> Callable[[tk.Event], None]:
            def handler(e: tk.Event) -> None:
                btn.config(fg=_theme_color("close_hover"))

            return handler

        def make_close_leave_handler(btn: tk.Label) -> Callable[[tk.Event], None]:
            def handler(e: tk.Event) -> None:
                btn.config(fg=_theme_color("tab_inactive_fg"))

            return handler

        def make_close_click_handler(tid: str) -> Callable[[tk.Event], None]:
            def handler(e: tk.Event) -> None:
                self._on_close_click(tid)

            return handler

        tab_frame.bind("<Button-1>", make_tab_click_handler(tab_info.document_id))
        title_label.bind("<Button-1>", make_tab_click_handler(tab_info.document_id))
        tab_frame.bind("<Button-3>", make_tab_right_click_handler(tab_info.document_id))
        title_label.bind("<Button-3>", make_tab_right_click_handler(tab_info.document_id))

        # Hover events for close button
        close_btn.bind("<Enter>", make_close_hover_handler(close_btn))
        close_btn.bind("<Leave>", make_close_leave_handler(close_btn))
        close_btn.bind("<Button-1>", make_close_click_handler(tab_info.document_id))

        # Apply initial indicator visibility
        self._apply_indicators(tab_frame, tab_info, bg=_theme_color("tab_inactive_bg"))

        # Pack the tab
        tab_frame.pack(side="left", fill="y", padx=(2, 0), pady=2)

    def _apply_indicators(
        self,
        tab_frame: tk.Frame,
        tab_info: TabInfo,
        bg: str,
    ) -> None:
        """Применяет видимость и стиль индикаторов вкладки.

        Args:
            tab_frame: Frame вкладки.
            tab_info: Информация о вкладке.
            bg: Цвет фона.
        """
        indicators: dict[str, tk.Label] = getattr(tab_frame, "_indicators", {})
        flag_map = {
            "modified": tab_info.modified,
            "encrypted": tab_info.encrypted,
            "readonly": tab_info.readonly,
        }
        color_map = {
            "modified": MODIFIED_COLOR,
            "encrypted": ENCRYPTED_COLOR,
            "readonly": READONLY_COLOR,
        }

        for key, label in indicators.items():
            if key == "modified":
                # Modified indicator отображается в тексте заголовка
                label.pack_forget()
                continue
            if flag_map.get(key):
                label.config(bg=bg, fg=color_map[key])
                label.pack(side="left", fill="y", before=tab_frame._title_label)  # type: ignore[attr-defined]
            else:
                label.pack_forget()

    def _update_tab_appearance(self, tab_info: TabInfo, active: bool) -> None:
        """Обновляет внешний вид вкладки.

        Args:
            tab_info: Информация о вкладке.
            active: True если вкладка активна.
        """
        if tab_info.widget is None:
            return

        bg_color = _theme_color("tab_active_bg") if active else _theme_color("tab_inactive_bg")

        # Update frame
        tab_info.widget.config(bg=bg_color)

        # Update title
        title_label: Optional[tk.Label] = getattr(tab_info.widget, "_title_label", None)
        if title_label is not None:
            icon = self._get_icon_for_mode(tab_info.mode, tab_info.is_special)
            prefix = f"{INDICATOR_MODIFIED} " if tab_info.modified else ""
            title_text = f"{prefix}{icon} {tab_info.title}"
            fg_color = (
                MODIFIED_COLOR
                if tab_info.modified
                else _theme_color("tab_active_fg" if active else "tab_inactive_fg")
            )
            title_label.config(text=title_text, bg=bg_color, fg=fg_color)

        # Update close button background
        close_btn: Optional[tk.Label] = getattr(tab_info.widget, "_close_btn", None)
        if close_btn is not None:
            close_btn.config(bg=bg_color)

        # Update indicators visibility and colors
        self._apply_indicators(tab_info.widget, tab_info, bg=bg_color)

    def _update_layout(self) -> None:
        """Обновляет layout вкладок."""
        if self._tk_canvas is None or self._tk_scroll_frame is None:
            return

        # Update scroll region
        self._update_scroll_region()

        # Ensure active tab is visible
        if self._active_tab_id:
            self._scroll_to_tab(self._active_tab_id)

    def _update_scroll_region(self) -> None:
        """Обновляет область прокрутки canvas."""
        if self._tk_canvas is None or self._tk_scroll_frame is None:
            return

        self._tk_scroll_frame.update_idletasks()
        bbox = self._tk_canvas.bbox("all")
        if bbox:
            self._tk_canvas.config(scrollregion=bbox)
            self._max_scroll = max(0, bbox[2] - self._tk_canvas.winfo_width())

    def _scroll_to_tab(self, document_id: str) -> None:
        """Прокручивает к указанной вкладке.

        Args:
            document_id: Идентификатор вкладки.
        """
        if document_id not in self._tabs or self._tk_canvas is None:
            return

        tab_info = self._tabs[document_id]
        if tab_info.widget is None:
            return

        # Get widget position
        x = tab_info.widget.winfo_x()
        width = tab_info.widget.winfo_width()
        canvas_width = self._tk_canvas.winfo_width()

        # Calculate scroll position
        if x < self._scroll_x:
            # Tab is to the left of visible area
            self._scroll_x = max(0, x - 10)
        elif x + width > self._scroll_x + canvas_width:
            # Tab is to the right of visible area
            self._scroll_x = min(self._max_scroll, x + width - canvas_width + 10)

        self._tk_canvas.xview_moveto(self._scroll_x / max(1, self._tk_canvas.bbox("all")[2]))

    def _on_tab_click(self, document_id: str) -> None:
        """Обрабатывает клик по вкладке.

        Args:
            document_id: Идентификатор вкладки.
        """
        self.set_active_tab(document_id)

    def _on_close_click(self, document_id: str) -> None:
        """Обрабатывает клик по кнопке закрытия.

        Args:
            document_id: Идентификатор вкладки.
        """
        self.close_tab(document_id)

    def _on_new_tab_click(self) -> None:
        """Обрабатывает клик по кнопке создания новой вкладки."""
        if self._on_new_tab is not None:
            self._on_new_tab()

    def _on_tab_right_click(self, document_id: str, event: tk.Event) -> None:
        """Обрабатывает правый клик по вкладке.

        Args:
            document_id: Идентификатор вкладки.
            event: Событие мыши.
        """
        self._show_context_menu(document_id, event.x_root, event.y_root)

    def _show_context_menu(self, document_id: str, x: int, y: int) -> None:
        """Показывает контекстное меню.

        Args:
            document_id: Идентификатор вкладки.
            x: X координата для меню.
            y: Y координата для меню.
        """
        if self._tk_frame is None:
            return

        # Create menu if not exists
        if self._tk_context_menu is None:
            self._tk_context_menu = tk.Menu(self._tk_frame, tearoff=0)

        # Clear existing items
        self._tk_context_menu.delete(0, "end")

        # Add items - define callbacks properly to avoid type inference issues
        def make_close_handler(tid: str) -> Callable[[], None]:
            def handler() -> None:
                self.close_tab(tid)

            return handler

        def make_close_others_handler(tid: str) -> Callable[[], None]:
            def handler() -> None:
                self._close_other_tabs(tid)

            return handler

        self._tk_context_menu.add_command(
            label="Закрыть",
            command=make_close_handler(document_id),
        )
        self._tk_context_menu.add_command(
            label="Закрыть все",
            command=self._close_all_tabs,
        )
        self._tk_context_menu.add_command(
            label="Закрыть остальные",
            command=make_close_others_handler(document_id),
        )

        # Show menu
        self._tk_context_menu.tk_popup(x, y)

    def _close_all_tabs(self) -> None:
        """Закрывает все вкладки."""
        # Make a copy since we're modifying during iteration
        tab_ids = list(self._tab_order)
        for document_id in tab_ids:
            self.close_tab(document_id)

    def _close_other_tabs(self, keep_document_id: str) -> None:
        """Закрывает все вкладки кроме указанной.

        Args:
            keep_document_id: Идентификатор вкладки, которую нужно оставить.
        """
        # Make a copy since we're modifying during iteration
        tab_ids = list(self._tab_order)
        for document_id in tab_ids:
            if document_id != keep_document_id:
                self.close_tab(document_id)

    def _on_canvas_configure(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает изменение размера canvas.

        Args:
            event: Событие конфигурации.
        """
        self._update_scroll_region()

    def _on_mousewheel(self, event: tk.Event) -> None:
        """Обрабатывает прокрутку колёсиком мыши.

        Args:
            event: Событие прокрутки.
        """
        if self._tk_canvas is None:
            return

        # Determine scroll direction
        if hasattr(event, "delta"):
            # Windows/macOS
            if event.delta > 0:
                direction = -1
            else:
                direction = 1
        else:
            # Linux
            if event.num == 4:
                direction = -1
            else:
                direction = 1

        # Scroll
        scroll_amount = 30 * direction
        self._tk_canvas.xview_scroll(scroll_amount, "units")
        self._scroll_x = max(0, self._scroll_x + scroll_amount)


# Module exports
__all__: list[str] = [
    "CardFileTabBar",
    "TabInfo",
    "MAX_TABS",
    "MAX_TITLE_LENGTH",
]

__version__: Final[str] = "1.1"
__author__: Final[str] = "FX Text Processor Team"
__date__: Final[str] = "May 2026"
