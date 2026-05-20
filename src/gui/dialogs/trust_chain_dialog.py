"""Диалог просмотра цепочки доверия (Trust Chain).

Предоставляет UI для просмотра и верификации цепочки доверия шаблонов:
- Иерархическое отображение цепочки Root → Master → Template
- Colorовая индикация статуса (🟢 valid, 🟡 warning, 🔴 invalid)
- Детальная информация о каждом звене цепочки
- Интеграция с TrustChainServiceProtocol

Example:
    >>> from src.gui.dialogs.trust_chain_dialog import TrustChainDialog
    >>> from src.services.template_manager import FormTemplate
    >>> dialog = TrustChainDialog(
    ...     parent=root,
    ...     template=template,
    ...     trust_service=trust_service,
    ... )
    >>> dialog.show()

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk
from typing import Any, Callable, Final, Optional

from src.gui.dialogs.base_dialog import BaseDialog
from src.services.protocols.template_security import (
    TrustChainLink,
    TrustChainServiceProtocol,
    TrustStatus,
    TrustVerificationResult,
)
from src.services.template_manager import FormTemplate

# UI Constants
DIALOG_WIDTH: Final[int] = 600
DIALOG_HEIGHT: Final[int] = 500
MIN_DIALOG_WIDTH: Final[int] = 500
MIN_DIALOG_HEIGHT: Final[int] = 400

# Colors
COLOR_BG: Final[str] = "#f8f9fa"
COLOR_HEADER: Final[str] = "#e9ecef"
COLOR_BORDER: Final[str] = "#dee2e6"
COLOR_TEXT: Final[str] = "#212529"

# Status colors for treeview tags
COLOR_VALID: Final[str] = "#28a745"  # Green
COLOR_WARNING: Final[str] = "#ffc107"  # Yellow/Orange
COLOR_INVALID: Final[str] = "#dc3545"  # Red
COLOR_INFO: Final[str] = "#17a2b8"  # Cyan/Info

# Status emojis
STATUS_EMOJIS: Final[dict[TrustStatus, str]] = {
    TrustStatus.TRUSTED: "🟢",
    TrustStatus.UNTRUSTED: "🔴",
    TrustStatus.REVOKED: "🚫",
    TrustStatus.EXPIRED: "🟡",
    TrustStatus.PENDING: "⏳",
}

# Treeview tag mappings
STATUS_TO_TAG: Final[dict[TrustStatus, str]] = {
    TrustStatus.TRUSTED: "valid",
    TrustStatus.UNTRUSTED: "invalid",
    TrustStatus.REVOKED: "invalid",
    TrustStatus.EXPIRED: "warning",
    TrustStatus.PENDING: "warning",
}


class TrustChainDialog(BaseDialog):
    """Диалог просмотра цепочки доверия шаблона.

    Отображает иерархическую цепочку сертификатов с цветовой индикацией
    статуса каждого звена. Поддерживает детальный просмотр информации
    о ключе и повторную верификацию цепочки.

    Attributes:
        _template: Шаблон для проверки.
        _trust_service: Сервис цепочек доверия.
        _chain_links: Загруженная цепочка доверия.
        _verification_result: Результат последней верификации.

    Example:
        >>> dialog = TrustChainDialog(parent, template, trust_service)
        >>> dialog.show()
    """

    def __init__(
        self,
        parent: tk.Widget,
        template: FormTemplate,
        trust_service: TrustChainServiceProtocol,
        *,
        verification_mode: bool = False,
        on_whitelist: Optional[Callable[[str], None]] = None,
        on_reject: Optional[Callable[[str], None]] = None,
        **kwargs: Any,
    ) -> None:
        """Инициализация диалога цепочки доверия.

        Args:
            parent: Родительский виджет.
            template: Шаблон для проверки цепочки доверия.
            trust_service: Сервис для работы с цепочками доверия.
            verification_mode: True — режим верификации с кнопками Whitelist/Reject.
            on_whitelist: Callback при нажатии «Add to Whitelist».
            on_reject: Callback при нажатии «Reject».
            **kwargs: Дополнительные именованные аргументы для Toplevel.
        """
        super().__init__(parent, modal=True, **kwargs)

        self._parent: tk.Widget = parent
        self._template: FormTemplate = template
        self._trust_service: TrustChainServiceProtocol = trust_service
        self._verification_mode: bool = verification_mode
        self._on_whitelist_cb: Optional[Callable[[str], None]] = on_whitelist
        self._on_reject_cb: Optional[Callable[[str], None]] = on_reject
        self._chain_links: list[TrustChainLink] = []
        self._verification_result: Optional[TrustVerificationResult] = None
        self._current_selection: Optional[str] = None
        self._display_link: Optional[TrustChainLink] = None

        self._create_ui()
        self._setup_window()
        self._configure_tree_styles()
        self._load_trust_chain()

    def _setup_window(self) -> None:
        """Настраивает параметры окна диалога."""
        self.title("Trust Chain Verification")
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.minsize(MIN_DIALOG_WIDTH, MIN_DIALOG_HEIGHT)

        # Center the dialog
        self.update_idletasks()
        parent_x = self._parent.winfo_rootx()
        parent_y = self._parent.winfo_rooty()
        parent_width = self._parent.winfo_width()
        parent_height = self._parent.winfo_height()

        x = parent_x + (parent_width - DIALOG_WIDTH) // 2
        y = parent_y + (parent_height - DIALOG_HEIGHT) // 2
        self.geometry(f"+{x}+{y}")

    def _configure_tree_styles(self) -> None:
        """Настраивает стили Treeview для цветовой индикации."""
        style = ttk.Style()

        # Configure treeview colors
        style.configure("TrustTree.Treeview", background=COLOR_BG, foreground=COLOR_TEXT)
        style.configure("TrustTree.Treeview.Heading", font=("Helvetica", 10, "bold"))

        # Tag configurations for colored rows (безопасно: _tree создан в _create_ui)
        if hasattr(self, "_tree") and self._tree is not None:
            self._tree.tag_configure("valid", foreground=COLOR_VALID)
            self._tree.tag_configure("warning", foreground=COLOR_WARNING)
            self._tree.tag_configure("invalid", foreground=COLOR_INVALID)
            self._tree.tag_configure("info", foreground=COLOR_INFO)

    def _create_ui(self) -> None:
        """Создаёт UI компоненты диалога."""
        self.config(bg=COLOR_BG)

        # Main container with padding
        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)  # Treeview row

        # Header section
        self._create_header(main_frame)

        # Treeview section
        self._create_treeview(main_frame)

        # Detail panel
        self._create_detail_panel(main_frame)

        # Verification panel (only in verification_mode)
        if self._verification_mode:
            self._create_verification_panel(main_frame)

        # Button bar
        self._create_button_bar(main_frame)

    def _create_header(self, parent: ttk.Frame) -> None:
        """Создаёт заголовок диалога.

        Args:
            parent: Родительский фрейм.
        """
        # Title
        title = ttk.Label(
            parent,
            text="Trust Chain Verification",
            font=("Helvetica", 14, "bold"),
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        # Template info frame
        info_frame = ttk.LabelFrame(parent, text="Template", padding="10")
        info_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        info_frame.columnconfigure(0, weight=1)

        template_name = self._template.name or self._template.template_id
        template_file = f"{self._template.template_id}.fxstpl"

        ttk.Label(
            info_frame,
            text=f"Name: {template_name}",
            font=("Helvetica", 10),
        ).grid(row=0, column=0, sticky="w")

        ttk.Label(
            info_frame,
            text=f"File: {template_file}",
            font=("Helvetica", 9),
            foreground="gray",
        ).grid(row=1, column=0, sticky="w")

        if self._template.doc_type:
            ttk.Label(
                info_frame,
                text=f"Type: {self._template.doc_type}",
                font=("Helvetica", 9),
                foreground="gray",
            ).grid(row=2, column=0, sticky="w")

    def _create_treeview(self, parent: ttk.Frame) -> None:
        """Создаёт Treeview для отображения цепочки доверия.

        Args:
            parent: Родительский фрейм.
        """
        # Treeview frame with label
        tree_frame = ttk.LabelFrame(parent, text="Certificate chain", padding="10")
        tree_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 10))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        # Treeview with columns
        columns = ("status", "name", "algorithm", "key_id")
        self._tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="tree headings",
            height=8,
            selectmode="browse",
        )

        # Configure headings
        self._tree.heading("#0", text="Chain")
        self._tree.heading("status", text="Status")
        self._tree.heading("name", text="Name")
        self._tree.heading("algorithm", text="Algorithm")
        self._tree.heading("key_id", text="Key ID")

        # Configure column widths
        self._tree.column("#0", width=150, minwidth=100)
        self._tree.column("status", width=80, minwidth=60)
        self._tree.column("name", width=150, minwidth=100)
        self._tree.column("algorithm", width=100, minwidth=80)
        self._tree.column("key_id", width=150, minwidth=100)

        # Scrollbar
        scrollbar = ttk.Scrollbar(
            tree_frame,
            orient=tk.VERTICAL,
            command=self._tree.yview,
        )
        self._tree.configure(yscrollcommand=scrollbar.set)

        # Grid placement
        self._tree.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Bind selection event
        self._tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _create_detail_panel(self, parent: ttk.Frame) -> None:
        """Создаёт панель детальной информации.

        Args:
            parent: Родительский фрейм.
        """
        detail_frame = ttk.LabelFrame(parent, text="Details", padding="10")
        detail_frame.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        detail_frame.columnconfigure(0, weight=1)

        self._detail_text = tk.Text(
            detail_frame,
            height=4,
            wrap=tk.WORD,
            font=("Helvetica", 9),
            bg=COLOR_BG,
            relief=tk.FLAT,
            state=tk.DISABLED,
        )
        self._detail_text.grid(row=0, column=0, sticky="ew")

        # Default message
        self._update_detail_text("Select a certificate chain link to view details.")

    def _create_button_bar(self, parent: ttk.Frame) -> None:
        """Создаёт панель кнопок.

        При verification_mode=False показывает кнопки Details/Verify/Close.
        При verification_mode=True показывает Close.

        Args:
            parent: Родительский фрейм.
        """
        button_frame = ttk.Frame(parent)
        button_frame.grid(row=5, column=0, sticky="ew")
        button_frame.columnconfigure(0, weight=1)

        if not self._verification_mode:
            # Left side buttons
            left_buttons = ttk.Frame(button_frame)
            left_buttons.grid(row=0, column=0, sticky="w")

            self._details_button = ttk.Button(
                left_buttons,
                text="📋 Details",
                command=self._show_details,
                state=tk.DISABLED,
            )
            self._details_button.pack(side=tk.LEFT, padx=(0, 5))

            self._verify_button = ttk.Button(
                left_buttons,
                text="🔍 Verify",
                command=self._verify_chain,
            )
            self._verify_button.pack(side=tk.LEFT)

        # Right side - Close button
        self._close_button = ttk.Button(
            button_frame,
            text="❌ Close",
            command=self._close,
        )
        self._close_button.grid(row=0, column=1, sticky="e")

    def _create_verification_panel(self, parent: ttk.Frame) -> None:
        """Создаёт панель верификации с fingerprint и кнопками.

        Панель отображается только при verification_mode=True.
        Содержит:
        - Public key fingerprint
        - Даты Signed / Expires
        - Кнопки Add to Whitelist, Reject, Close

        Args:
            parent: Родительский фрейм.
        """
        panel = ttk.LabelFrame(parent, text="Verification", padding="10")
        panel.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        panel.columnconfigure(0, weight=1)

        link = self._get_display_link()

        # Public key fingerprint
        fingerprint = "-"
        if link and link.public_key:
            import hashlib

            fp = hashlib.sha256(link.public_key).hexdigest()[:8]
            fingerprint = f"SHA256: {fp}..."
        ttk.Label(
            panel,
            text=f"Public key fingerprint: {fingerprint}",
            font=("Helvetica", 10, "bold"),
        ).grid(row=0, column=0, sticky="w")

        # Signed date
        signed_str = "-"
        if link:
            signed_str = link.added_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        ttk.Label(
            panel,
            text=f"Signed: {signed_str}",
            font=("Helvetica", 9),
        ).grid(row=1, column=0, sticky="w")

        # Expires date
        expires_str = "Never"
        if link and link.expires_at:
            expires_str = link.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        ttk.Label(
            panel,
            text=f"Expires: {expires_str}",
            font=("Helvetica", 9),
        ).grid(row=2, column=0, sticky="w")

        # Buttons
        btn_frame = ttk.Frame(panel)
        btn_frame.grid(row=3, column=0, sticky="w", pady=(10, 0))

        ttk.Button(
            btn_frame,
            text="➕ Add to Whitelist",
            command=self._on_whitelist_click,
        ).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(
            btn_frame,
            text="❌ Reject",
            command=self._on_reject_click,
        ).pack(side=tk.LEFT, padx=(0, 5))

        ttk.Button(
            btn_frame,
            text="Close",
            command=self._close,
        ).pack(side=tk.LEFT)

    def _get_display_link(self) -> Optional[TrustChainLink]:
        """Возвращает звено цепочки для отображения в панели верификации.

        Returns:
            TrustChainLink выбранного элемента, или первое звено цепочки.
        """
        if self._current_selection:
            link = self._get_link_by_id(self._current_selection)
            if link:
                return link
        if self._chain_links:
            return self._chain_links[0]
        return None

    def _on_whitelist_click(self) -> None:
        """Обработчик нажатия «Add to Whitelist»."""
        link = self._get_display_link()
        if link is None:
            return
        if self._on_whitelist_cb is not None:
            self._on_whitelist_cb(link.key_id)
        self.destroy()

    def _on_reject_click(self) -> None:
        """Обработчик нажатия «Reject»."""
        link = self._get_display_link()
        if link is None:
            return
        if self._on_reject_cb is not None:
            self._on_reject_cb(link.key_id)
        self.destroy()

    def _load_trust_chain(self) -> None:
        """Загружает и отображает цепочку доверия."""
        # Clear existing items
        for item in self._tree.get_children():
            self._tree.delete(item)

        self._chain_links = []

        try:
            # Get signing key from template signature (if available)
            signing_key_id: Optional[str] = None
            if self._template.signature:
                # In real implementation, extract key_id from signature
                signing_key_id = f"key-{self._template.template_id[:8]}"

            if not signing_key_id:
                # Insert placeholder when no signature
                self._tree.insert(
                    "",
                    tk.END,
                    iid="no-sig",
                    text="No signature",
                    values=("⏳", "No signing key", "-", "-"),
                    tags=("warning",),
                )
                self._update_detail_text("Template is not signed. Trust chain unavailable.")
                return

            # Get trust chain from service
            self._chain_links = self._trust_service.get_trust_chain(signing_key_id)

            if not self._chain_links:
                self._tree.insert(
                    "",
                    tk.END,
                    iid="no-chain",
                    text="No trust chain",
                    values=("⏳", "Chain not found", "-", signing_key_id[:16]),
                    tags=("warning",),
                )
                return

            # Build hierarchical tree
            self._build_tree_hierarchy()

            # Run initial verification
            self._verify_chain(silent=True)

        except Exception as e:
            self._tree.insert(
                "",
                tk.END,
                iid="error",
                text="Error",
                values=("🔴", str(e), "-", "-"),
                tags=("invalid",),
            )

    def _build_tree_hierarchy(self) -> None:
        """Строит иерархическое дерево цепочки доверия."""
        if not self._chain_links:
            return

        # Create a map of key_id to link
        link_map: dict[str, TrustChainLink] = {}
        for link in self._chain_links:
            link_map[link.key_id] = link

        # Find root (parent_key_id is None)
        root_links = [link for link in self._chain_links if link.is_root()]

        # If no explicit root, use the last link as root
        if not root_links and self._chain_links:
            root_links = [self._chain_links[-1]]

        # Insert root
        for root in root_links:
            self._insert_link_recursive(root, "")

    def _insert_link_recursive(
        self,
        link: TrustChainLink,
        parent_id: str,
    ) -> str:
        """Рекурсивно вставляет звено цепочки в дерево.

        Args:
            link: Звено цепочки для вставки.
            parent_id: ID родительского элемента в дереве.

        Returns:
            ID созданного элемента в дереве.
        """
        # Determine status
        status = TrustStatus.TRUSTED  # Default
        if link.is_expired():
            status = TrustStatus.EXPIRED

        # Get display name
        if link.is_root():
            display_name = "Root CA (self-signed)"
        elif link.parent_key_id and any(
            cl.key_id == link.parent_key_id and cl.is_root() for cl in self._chain_links
        ):
            display_name = "Master Key"
        elif link.key_id.startswith(f"key-{self._template.template_id[:8]}"):
            display_name = "This Template"
        else:
            display_name = link.metadata.get("name", "Intermediate Key")

        # Format key_id for display
        short_key_id = link.key_id[:16] + "..." if len(link.key_id) > 16 else link.key_id

        # Get emoji for status
        emoji = STATUS_EMOJIS.get(status, "⚪")
        tag = STATUS_TO_TAG.get(status, "info")

        # Insert into tree
        iid = self._tree.insert(
            parent_id,
            tk.END,
            iid=link.key_id,
            text=display_name,
            values=(emoji, display_name, link.algorithm, short_key_id),
            tags=(tag,),
        )

        # Find and insert children
        for child_link in self._chain_links:
            if child_link.parent_key_id == link.key_id:
                self._insert_link_recursive(child_link, iid)

        return iid

    def _on_tree_select(self, event: Optional[tk.Event] = None) -> None:
        """Обрабатывает выбор элемента в Treeview.

        Args:
            event: Событие выбора (опционально).
        """
        selection = self._tree.selection()
        if not selection:
            return

        self._current_selection = selection[0]
        self._details_button.configure(state=tk.NORMAL)

        # Update detail panel with basic info
        link = self._get_link_by_id(self._current_selection)
        if link:
            self._update_detail_panel_for_link(link)

    def _get_link_by_id(self, key_id: str) -> Optional[TrustChainLink]:
        """Возвращает звено цепочки по ID ключа.

        Args:
            key_id: ID ключа.

        Returns:
            TrustChainLink или None если не найден.
        """
        for link in self._chain_links:
            if link.key_id == key_id:
                return link
        return None

    def _update_detail_panel_for_link(self, link: TrustChainLink) -> None:
        """Обновляет панель деталей информацией о звене.

        Args:
            link: Звено цепочки для отображения.
        """
        lines: list[str] = []
        lines.append(f"Key ID: {link.key_id}")
        lines.append(f"Algorithm: {link.algorithm}")
        lines.append(f"Added: {link.added_at.strftime('%Y-%m-%d %H:%M:%S')}")

        if link.expires_at:
            lines.append(f"Expires: {link.expires_at.strftime('%Y-%m-%d %H:%M:%S')}")
            if link.is_expired():
                lines.append("⚠️ Certificate has expired!")
        else:
            lines.append("Expires: Never (no expiration)")

        if link.is_root():
            lines.append("Type: Root CA (self-signed)")
        else:
            lines.append(f"Signed by: {link.parent_key_id}")

        if link.metadata:
            if "name" in link.metadata:
                lines.append(f"Name: {link.metadata['name']}")
            if "email" in link.metadata:
                lines.append(f"Email: {link.metadata['email']}")
            if "organization" in link.metadata:
                lines.append(f"Organization: {link.metadata['organization']}")

        self._update_detail_text("\n".join(lines))

    def _update_detail_text(self, text: str) -> None:
        """Обновляет текст в панели деталей.

        Args:
            text: Новый текст для отображения.
        """
        self._detail_text.configure(state=tk.NORMAL)
        self._detail_text.delete(1.0, tk.END)
        self._detail_text.insert(1.0, text)
        self._detail_text.configure(state=tk.DISABLED)

    def _show_details(self) -> None:
        """Показывает детальную информацию о выбранном звене."""
        if not self._current_selection:
            return

        link = self._get_link_by_id(self._current_selection)
        if not link:
            return

        # Create detail dialog
        detail_dialog = tk.Toplevel(self)
        detail_dialog.title(f"Certificate Details - {link.key_id[:16]}...")
        detail_dialog.geometry("450x400")
        detail_dialog.transient(self)
        try:
            detail_dialog.grab_set()
        except tk.TclError:
            pass

        # Content frame
        content = ttk.Frame(detail_dialog, padding="20")
        content.pack(fill=tk.BOTH, expand=True)

        # Header
        ttk.Label(
            content,
            text="Certificate Details",
            font=("Helvetica", 12, "bold"),
        ).pack(anchor="w", pady=(0, 15))

        # Details frame
        details_frame = ttk.Frame(content)
        details_frame.pack(fill=tk.BOTH, expand=True)

        # Key ID
        self._add_detail_row(details_frame, 0, "Key ID:", link.key_id)

        # Algorithm
        self._add_detail_row(details_frame, 1, "Algorithm:", link.algorithm)

        # Public key (truncated)
        pub_key_hex = link.public_key.hex()[:64] + "..."
        self._add_detail_row(details_frame, 2, "Public Key:", pub_key_hex)

        # Added date
        self._add_detail_row(
            details_frame,
            3,
            "Added:",
            link.added_at.strftime("%Y-%m-%d %H:%M:%S"),
        )

        # Expires
        expires_str = link.expires_at.strftime("%Y-%m-%d %H:%M:%S") if link.expires_at else "Never"
        self._add_detail_row(details_frame, 4, "Expires:", expires_str)

        # Parent key
        parent_str = link.parent_key_id if link.parent_key_id else "Self-signed (Root)"
        self._add_detail_row(details_frame, 5, "Parent Key:", parent_str)

        # Signature
        if link.signature:
            sig_hex = link.signature.hex()[:64] + "..."
            self._add_detail_row(details_frame, 6, "Signature:", sig_hex)
        else:
            self._add_detail_row(details_frame, 6, "Signature:", "None (Root CA)")

        # Metadata
        if link.metadata:
            row = 7
            for key, value in link.metadata.items():
                self._add_detail_row(details_frame, row, f"{key.capitalize()}:", str(value))
                row += 1

        # Close button
        ttk.Button(content, text="Close", command=detail_dialog.destroy).pack(
            pady=(15, 0),
        )

    def _add_detail_row(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        value: str,
    ) -> None:
        """Добавляет строку с детальной информацией.

        Args:
            parent: Родительский фрейм.
            row: Номер строки.
            label: Метка.
            value: Значение.
        """
        ttk.Label(
            parent,
            text=label,
            font=("Helvetica", 9, "bold"),
        ).grid(row=row, column=0, sticky="nw", padx=(0, 10), pady=(2, 2))

        ttk.Label(
            parent,
            text=value,
            font=("Helvetica", 9),
            wraplength=300,
        ).grid(row=row, column=1, sticky="nw", pady=(2, 2))

    def _verify_chain(self, silent: bool = False) -> None:
        """Выполняет верификацию цепочки доверия.

        Args:
            silent: Если True, не показывать сообщения об успехе.
        """
        try:
            self._verification_result = self._trust_service.verify_template(
                self._template,
                verify_chain=True,
            )

            # Update tree with verification status
            self._update_tree_with_verification()

            if not silent:
                if self._verification_result.can_trust:
                    messagebox.showinfo(
                        "Verification Success",
                        "Trust chain verification completed successfully.\n"
                        f"Chain depth: {self._verification_result.chain_depth}",
                        parent=self,
                    )
                else:
                    errors = "\n".join(self._verification_result.errors)
                    messagebox.showerror(
                        "Verification Failed",
                        f"Trust chain verification failed:\n{errors}",
                        parent=self,
                    )

        except Exception as e:
            if not silent:
                messagebox.showerror(
                    "Verification Error",
                    f"Error during verification: {str(e)}",
                    parent=self,
                )

    def _update_tree_with_verification(self) -> None:
        """Обновляет Treeview на основе результатов верификации."""
        if not self._verification_result:
            return

        # Update status based on verification result
        status = self._verification_result.trust_status
        emoji = STATUS_EMOJIS.get(status, "⚪")
        tag = STATUS_TO_TAG.get(status, "info")

        # Update tree items with new status
        for item_id in self._tree.get_children():
            self._update_item_status_recursive(item_id, emoji, tag)

    def _update_item_status_recursive(
        self,
        item_id: str,
        emoji: str,
        tag: str,
    ) -> None:
        """Рекурсивно обновляет статус элементов дерева.

        Args:
            item_id: ID элемента.
            emoji: Эмодзи статуса.
            tag: Тег для цвета.
        """
        # Get current values
        values = list(self._tree.item(item_id, "values"))
        if values:
            values[0] = emoji  # Update status column
            self._tree.item(item_id, values=tuple(values), tags=(tag,))

        # Update children
        for child_id in self._tree.get_children(item_id):
            self._update_item_status_recursive(child_id, emoji, tag)

    def _close(self) -> None:
        """Закрывает диалог."""
        self.destroy()

    def show(self) -> Optional[TrustVerificationResult]:
        """Показывает диалог и возвращает результат.

        Returns:
            TrustVerificationResult или None если диалог закрыт.
        """
        self.wait_window()
        return self._verification_result


class TrustChainDisplayHelper:
    """Вспомогательный класс для отображения Trust Chain.

    Предоставляет утилиты для форматирования и отображения
    информации о цепочке доверия.

    Example:
        >>> helper = TrustChainDisplayHelper()
        >>> formatted = helper.format_chain(chain_data)
    """

    def __init__(self) -> None:
        """Инициализация хелпера."""
        pass

    def format_chain(self, chain_data: dict[str, Any]) -> str:
        """Форматирует данные цепочки для отображения.

        Args:
            chain_data: Сырые данные цепочки доверия.

        Returns:
            Отформатированная строка для отображения.
        """
        return f"Chain: {len(chain_data)} items"


# Backward compatibility alias
TrustChainVerificationDialog = TrustChainDialog


__all__: list[str] = [
    "TrustChainDialog",
    "TrustChainVerificationDialog",
    "TrustChainDisplayHelper",
    "STATUS_EMOJIS",
    "STATUS_TO_TAG",
]
