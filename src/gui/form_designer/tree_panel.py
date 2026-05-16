"""Tree Panel для Form Designer.

Предоставляет иерархическое дерево документов по индексам:
ROOT_CODE → SUBTYPE → SERIES → CUSTOM → SEQUENCE

Example:
    >>> tree = TreePanel(parent=frame)
    >>> tree.add_document_index("DVN-44-K53-IX")
    >>> tree.add_document_index("DVN-44-K53-X")

Version: 1.0
"""

from __future__ import annotations

import logging
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Final, Optional, Tuple

logger: Final = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

PANEL_WIDTH: Final[int] = 200
PANEL_MIN_HEIGHT: Final[int] = 400

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_SELECTED: Final[str] = "#0078d4"
COLOR_HOVER: Final[str] = "#e5e5e5"


# =============================================================================
# TreePanel
# =============================================================================


class TreePanel:
    """Панель дерева для навигации по документам.

    Attributes:
        _parent: Родительский виджет.
        _tree: Treeview widget.
        _document_indices: Словарь индексов документов.
        _on_select: Callback при выборе.

    Example:
        >>> panel = TreePanel(parent=frame, on_select=on_tree_select)
        >>> panel.add_document_index("DVN-44-K53-IX")
    """

    def __init__(
        self,
        parent: tk.Widget,
        on_select: Optional[Callable[[str], None]] = None,
        on_double_click: Optional[Callable[[str], None]] = None,
        on_create: Optional[Callable[[Optional[str]], None]] = None,
        on_delete: Optional[Callable[[str], None]] = None,
        on_copy: Optional[Callable[[str], None]] = None,
        on_paste: Optional[Callable[[Optional[str]], None]] = None,
        on_rename: Optional[Callable[[str], None]] = None,
        on_reorder: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        """Инициализация панели дерева.

        Args:
            parent: Родительский виджет.
            on_select: Callback при выборе элемента.
            on_double_click: Callback при двойном клике.
            on_create: Callback создания элемента (parent_id или None).
            on_delete: Callback удаления элемента.
            on_copy: Callback копирования элемента.
            on_paste: Callback вставки (parent_id или None).
            on_rename: Callback переименования элемента.
            on_reorder: Callback при перетаскивании (old_path, new_path).
        """
        self._parent: tk.Widget = parent
        self._on_select: Optional[Callable[[str], None]] = on_select
        self._on_double_click: Optional[Callable[[str], None]] = on_double_click
        self._cb_create: Optional[Callable[[Optional[str]], None]] = on_create
        self._cb_delete: Optional[Callable[[str], None]] = on_delete
        self._cb_copy: Optional[Callable[[str], None]] = on_copy
        self._cb_paste: Optional[Callable[[Optional[str]], None]] = on_paste
        self._cb_rename: Optional[Callable[[str], None]] = on_rename
        self._cb_reorder: Optional[Callable[[str, str], None]] = on_reorder

        # State
        self._document_indices: dict[str, dict[str, Any]] = {}
        self._node_map: dict[str, str] = {}  # index -> tree node id
        self._clipboard: Optional[str] = None  # For copy/paste
        self._drag_source: Optional[str] = None  # For drag-drop reordering
        self._hovered_item: Optional[str] = None  # Item under drag cursor
        self._hovered_original_tags: Optional[Tuple[str, ...]] = None  # Original tags

        # Create UI
        self._create_ui()

    def _create_ui(self) -> None:
        """Создаёт пользовательский интерфейс."""
        # Main frame
        self._frame = tk.Frame(self._parent, width=PANEL_WIDTH, bg=COLOR_BG)
        self._frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        self._frame.pack_propagate(False)

        # Header
        header = tk.Frame(self._frame, bg="#e0e0e0", padx=5, pady=5)
        header.pack(fill=tk.X)

        tk.Label(
            header,
            text="📁 Documents",
            font=("Arial", 10, "bold"),
            bg="#e0e0e0",
            fg="#2c3e50",
        ).pack(anchor=tk.W)

        # Treeview
        tree_frame = tk.Frame(self._frame, bg=COLOR_BG)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self._tree = ttk.Treeview(
            tree_frame,
            columns=("type",),
            show="tree",
            selectmode="browse",
        )
        self._tree.column("#0", width=PANEL_WIDTH - 40, minwidth=100)
        self._tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self._tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._tree.config(yscrollcommand=scrollbar.set)

        # Bindings
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self._tree.bind("<Double-1>", self._on_tree_double_click)

        # Context menu
        self._create_context_menu()

        # Drag-drop for reordering
        self._setup_drag_drop()

        # Add root categories
        self._create_root_categories()

    def _create_root_categories(self) -> None:
        """Создаёт корневые категории."""
        categories = [
            ("DVN", "📁 DVN", "Verbal Note"),
            ("INV", "📁 INV", "Invoice"),
            ("MEM", "📁 MEM", "Memo"),
        ]

        for node_id, text, tooltip in categories:
            self._tree.insert(
                "",
                tk.END,
                iid=node_id,
                text=text,
                values=(tooltip,),
                tags=("category",),
            )

        # Configure tags
        self._tree.tag_configure("category", font=("Arial", 9, "bold"))
        self._tree.tag_configure("document", font=("Arial", 9))
        self._tree.tag_configure("selected", background=COLOR_SELECTED)
        self._tree.tag_configure("hover", background=COLOR_HOVER)

    def _create_context_menu(self) -> None:
        """Создаёт контекстное меню."""
        self._context_menu = tk.Menu(self._tree, tearoff=0)
        self._context_menu.add_command(label="➕ Create", command=self._on_create)
        self._context_menu.add_command(label="🗑️ Delete", command=self._on_delete)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="📋 Copy", command=self._on_copy)
        self._context_menu.add_command(label="📄 Paste", command=self._on_paste)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="✏️ Rename", command=self._on_rename)

        self._tree.bind("<Button-3>", self._show_context_menu)

    def _show_context_menu(self, event: tk.Event) -> None:
        """Показывает контекстное меню.

        Args:
            event: Событие клика.
        """
        item = self._tree.identify_row(event.y)
        if item:
            self._tree.selection_set(item)
            self._context_menu.post(event.x_root, event.y_root)

    def _parse_index(self, index: str) -> list[str]:
        """Парсит индекс документа.

        Args:
            index: Индекс (например, "DVN-44-K53-IX").

        Returns:
            Список частей индекса.
        """
        return index.split("-")

    def add_document_index(self, index: str, metadata: Optional[dict[str, Any]] = None) -> None:
        """Добавляет индекс документа в дерево.

        Args:
            index: Индекс документа (например, "DVN-44-K53-IX").
            metadata: Метаданные документа.
        """
        if index in self._document_indices:
            return

        parts = self._parse_index(index)
        if len(parts) < 2:
            return

        # Build tree hierarchy
        root_code = parts[0]
        current_parent = root_code

        # Ensure root exists
        if not self._tree.exists(root_code):
            self._tree.insert(
                "",
                tk.END,
                iid=root_code,
                text=f"📁 {root_code}",
                tags=("category",),
            )

        # Build path
        current_path = root_code
        for i, part in enumerate(parts[1:], 1):
            current_path = f"{current_path}-{part}"
            node_id = current_path.replace("-", "_")

            if not self._tree.exists(node_id):
                if i == len(parts) - 1:
                    # Leaf node (document)
                    display_text = f"📄 {part}"
                    tags = ("document",)
                else:
                    # Intermediate node
                    display_text = f"📁 {part}"
                    tags = ("category",)

                parent_id = current_parent.replace("-", "_")
                self._tree.insert(
                    parent_id,
                    tk.END,
                    iid=node_id,
                    text=display_text,
                    tags=tags,
                )

            current_parent = current_path

        # Store metadata
        self._document_indices[index] = metadata or {}
        self._node_map[index] = node_id

        logger.debug("Added document index: %s", index)

    def remove_document_index(self, index: str) -> None:
        """Удаляет индекс документа.

        Args:
            index: Индекс документа.
        """
        if index not in self._node_map:
            return

        node_id = self._node_map[index]
        if self._tree.exists(node_id):
            self._tree.delete(node_id)

        del self._document_indices[index]
        del self._node_map[index]

    def get_selected_index(self) -> Optional[str]:
        """Возвращает выбранный индекс.

        Returns:
            Индекс документа или None.
        """
        selection = self._tree.selection()
        if not selection:
            return None

        node_id = selection[0]
        for index, mapped_id in self._node_map.items():
            if mapped_id == node_id:
                return index

        return None

    def _on_tree_select(self, event: tk.Event) -> None:
        """Обработчик выбора в дереве.

        Args:
            event: Событие выбора.
        """
        index = self.get_selected_index()
        if index and self._on_select:
            self._on_select(index)

    def _on_tree_double_click(self, event: tk.Event) -> None:
        """Обработчик двойного клика.

        Args:
            event: Событие клика.
        """
        index = self.get_selected_index()
        if index and self._on_double_click:
            self._on_double_click(index)

    def _on_create(self) -> None:
        """Обработчик создания элемента."""
        selected = self.get_selected_index()
        if self._cb_create is not None:
            self._cb_create(selected)
        logger.info("Create action triggered for: %s", selected)

    def _on_delete(self) -> None:
        """Обработчик удаления."""
        index = self.get_selected_index()
        if index and self._cb_delete is not None:
            self._cb_delete(index)
            self.remove_document_index(index)
            logger.info("Deleted index: %s", index)

    def _on_copy(self) -> None:
        """Обработчик копирования в буфер."""
        index = self.get_selected_index()
        if index:
            self._clipboard = index
            logger.info("Copied to clipboard: %s", index)

    def _on_paste(self) -> None:
        """Обработчик вставки из буфера."""
        if self._clipboard and self._cb_paste is not None:
            selected = self.get_selected_index()
            self._cb_paste(selected)
            logger.info("Paste triggered for: %s", selected)

    def _on_rename(self) -> None:
        """Обработчик переименования элемента."""
        index = self.get_selected_index()
        if index and self._cb_rename is not None:
            self._cb_rename(index)
            logger.info("Rename triggered for: %s", index)

    def _setup_drag_drop(self) -> None:
        """Настраивает drag-drop для переупорядочивания элементов."""
        self._tree.bind("<Button-1>", self._on_drag_start)
        self._tree.bind("<B1-Motion>", self._on_drag_motion)
        self._tree.bind("<ButtonRelease-1>", self._on_drag_end)

    def _get_level(self, item: str) -> int:
        """Возвращает глубину узла в дереве (0 = корень).

        Args:
            item: Идентификатор узла.

        Returns:
            Уровень вложенности.
        """
        level = 0
        parent = self._tree.parent(item)
        while parent:
            level += 1
            parent = self._tree.parent(parent)
        return level

    def _is_descendant(self, ancestor: str, candidate: str) -> bool:
        """Проверяет, является ли candidate потомком ancestor.

        Args:
            ancestor: Потенциальный предок.
            candidate: Проверяемый узел.

        Returns:
            True если candidate находится в поддереве ancestor.
        """
        parent = self._tree.parent(candidate)
        while parent:
            if parent == ancestor:
                return True
            parent = self._tree.parent(parent)
        return False

    def _is_valid_move(self, source: str, target: str) -> bool:
        """Проверяет валидность перетаскивания.

        Правила:
        - Нельзя перетаскивать в самого себя или своего потомка.
        - Нельзя переместить ROOT (уровень 0) в SEQUENCE (лист).
        - SOURCE и TARGET должны быть на допустимых уровнях.

        Args:
            source: Исходный узел.
            target: Целевой узел.

        Returns:
            True если перемещение разрешено.
        """
        if source == target or self._is_descendant(source, target):
            return False

        src_level = self._get_level(source)
        tgt_level = self._get_level(target)

        # Корневые категории нельзя перемещать внутрь других узлов
        if src_level == 0 and tgt_level > 0:
            return False

        # Нельзя перемещать категорию в лист (SEQUENCE)
        children = self._tree.get_children(target)
        if not children and tgt_level >= 4:
            return False

        return True

    def _clear_hover(self) -> None:
        """Снимает подсветку hover с текущего элемента."""
        if self._hovered_item and self._tree.exists(self._hovered_item):
            tags = self._tree.item(self._hovered_item, "tags")
            if isinstance(tags, str):
                tags = tuple(t for t in tags.split() if t != "hover")
            else:
                tags = tuple(t for t in tags if t != "hover")
            self._tree.item(self._hovered_item, tags=tags)
        self._hovered_item = None
        self._hovered_original_tags = None

    def _set_hover(self, item: str) -> None:
        """Устанавливает подсветку hover на элемент.

        Args:
            item: Идентификатор узла.
        """
        if self._hovered_item == item:
            return
        self._clear_hover()
        if self._tree.exists(item):
            self._hovered_item = item
            tags = self._tree.item(item, "tags")
            if isinstance(tags, str):
                tag_list = list(tags.split())
            else:
                tag_list = list(tags)
            if "hover" not in tag_list:
                tag_list.append("hover")
            self._tree.item(item, tags=tuple(tag_list))

    def _on_drag_start(self, event: tk.Event) -> None:
        """Обработчик начала drag.

        Args:
            event: Событие мыши.
        """
        item = self._tree.identify_row(event.y)
        if item and item not in ("DVN", "INV", "MEM"):
            self._drag_source = item
        else:
            self._drag_source = None

    def _on_drag_motion(self, event: tk.Event) -> None:
        """Обработчик движения во время drag.

        Args:
            event: Событие мыши.
        """
        if self._drag_source is None:
            return
        target = self._tree.identify_row(event.y)
        if target and self._is_valid_move(self._drag_source, target):
            self._set_hover(target)
            self._tree.config(cursor="hand2")
        else:
            self._clear_hover()
            self._tree.config(cursor="no")

    def _on_drag_end(self, event: tk.Event) -> None:
        """Обработчик окончания drag.

        Args:
            event: Событие мыши.
        """
        self._tree.config(cursor="")
        if self._drag_source is None:
            self._clear_hover()
            return

        target = self._tree.identify_row(event.y)
        if (
            target
            and target != self._drag_source
            and self._is_valid_move(self._drag_source, target)
        ):
            logger.info("Drag-drop: %s -> %s", self._drag_source, target)
            # Перемещаем узел в дереве
            parent = self._tree.parent(target)
            if parent:
                self._tree.move(self._drag_source, parent, self._tree.index(target))
            else:
                self._tree.move(self._drag_source, "", self._tree.index(target))
            # Обновляем отображение
            old_path = self._drag_source
            new_path = self._tree.parent(self._drag_source) or ""
            if self._cb_reorder is not None:
                try:
                    self._cb_reorder(old_path, new_path)
                except Exception as exc:
                    logger.error("Error in on_reorder callback: %s", exc)

        self._drag_source = None
        self._clear_hover()

    def clear(self) -> None:
        """Очищает дерево."""
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._document_indices.clear()
        self._node_map.clear()
        self._create_root_categories()

    @property
    def widget(self) -> tk.Frame:
        """Возвращает виджет панели.

        Returns:
            Frame панели.
        """
        return self._frame


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__: list[str] = [
    "TreePanel",
    "PANEL_WIDTH",
]
