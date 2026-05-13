"""Виджет комментариев к полю формы.

Предоставляет:
- FieldCommentWidget: иконка и popup для комментариев к полю
- Комментарии с авторами, ролями, временем и уровнем важности
- Добавление и разрешение комментариев

Example:
    >>> widget = FieldCommentWidget(
    ...     parent=frame,
    ...     field_id="recipient",
    ...     comments=[],
    ...     on_add=handle_add,
    ...     on_resolve=handle_resolve,
    ... )
    >>> widget.mount(parent_frame)
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from tkinter import messagebox
from typing import Any, Final, Optional, Protocol


class Severity(Enum):
    """Уровень серьёзности комментария."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class Role(Enum):
    """Роль пользователя."""

    OPERATOR = "operator"
    EDITOR = "editor"
    SUPERVISOR = "supervisor"
    SIGNATORY = "signatory"

    @property
    def display_name(self) -> str:
        """Возвращает локализованное название роли."""
        names: dict[Role, str] = {
            Role.OPERATOR: "Оператор",
            Role.EDITOR: "Редактор",
            Role.SUPERVISOR: "Супервизор",
            Role.SIGNATORY: "Подписант",
        }
        return names.get(self, self.value)


@dataclass(frozen=True)
class Comment:
    """Комментарий к полю формы.

    Attributes:
        comment_id: Уникальный идентификатор комментария.
        field_id: Идентификатор поля.
        text: Текст комментария.
        author: Имя автора комментария.
        author_role: Роль автора.
        severity: Уровень важности.
        created_at: Время создания.
        resolved: Решён ли комментарий.
        resolved_at: Время решения (если применимо).
        resolved_by: Кем решён (если применимо).
    """

    comment_id: str
    field_id: str
    text: str
    author: str
    author_role: Role
    severity: Severity
    created_at: datetime
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None


class OnAddCallback(Protocol):
    """Протокол для callback добавления комментария."""

    def __call__(
        self,
        field_id: str,
        text: str,
        severity: Severity,
    ) -> Optional[str]:
        """Вызывается при добавлении комментария.

        Args:
            field_id: Идентификатор поля.
            text: Текст комментария.
            severity: Уровень важности.

        Returns:
            ID созданного комментария или None в случае ошибки.
        """
        ...


class OnResolveCallback(Protocol):
    """Протокол для callback разрешения комментария."""

    def __call__(self, comment_id: str) -> bool:
        """Вызывается при разрешении комментария.

        Args:
            comment_id: Идентификатор комментария.

        Returns:
            True если разрешение успешно.
        """
        ...


class FieldCommentWidget:
    """Виджет комментариев к полю формы.

    Отображает иконку рядом с полем, открывает popup
    для просмотра/добавления/разрешения комментариев.

    Attributes:
        SEVERITY_ICONS: Иконки для уровней важности.
        SEVERITY_COLORS: Цвета для уровней важности.

    Example:
        >>> widget = FieldCommentWidget(
        ...     parent=frame,
        ...     field_id="recipient",
        ...     comments=[],
        ...     on_add=lambda f, t, s: str(uuid4()),
        ...     on_resolve=lambda c: True,
        ... )
    """

    SEVERITY_ICONS: Final[dict[Severity, str]] = {
        Severity.INFO: "💬",
        Severity.WARNING: "⚠️",
        Severity.ERROR: "🚨",
    }

    SEVERITY_COLORS: Final[dict[Severity, str]] = {
        Severity.INFO: "#3498db",
        Severity.WARNING: "#f39c12",
        Severity.ERROR: "#e74c3c",
    }

    def __init__(
        self,
        parent: tk.Widget,
        field_id: str,
        comments: list[Comment],
        on_add: OnAddCallback,
        on_resolve: OnResolveCallback,
        current_user: str = "",
        current_role: Role = Role.OPERATOR,
    ) -> None:
        """Инициализация виджета комментариев.

        Args:
            parent: Родительский Tkinter виджет.
            field_id: Идентификатор поля.
            comments: Список существующих комментариев.
            on_add: Callback при добавлении комментария.
            on_resolve: Callback при разрешении комментария.
            current_user: Имя текущего пользователя.
            current_role: Роль текущего пользователя.
        """
        self._parent: tk.Widget = parent
        self._field_id: str = field_id
        self._comments: list[Comment] = list(comments)
        self._on_add: OnAddCallback = on_add
        self._on_resolve: OnResolveCallback = on_resolve
        self._current_user: str = current_user
        self._current_role: Role = current_role

        # UI элементы
        self._icon_label: Optional[tk.Label] = None
        self._popup: Optional[tk.Toplevel] = None
        self._comments_frame: Optional[tk.Frame] = None
        self._severity_var: tk.StringVar = tk.StringVar(value=Severity.INFO.value)

    @property
    def field_id(self) -> str:
        """Возвращает идентификатор поля."""
        return self._field_id

    @property
    def comments(self) -> tuple[Comment, ...]:
        """Возвращает список комментариев (read-only)."""
        return tuple(self._comments)

    @property
    def unresolved_count(self) -> int:
        """Возвращает количество неразрешённых комментариев."""
        return sum(1 for c in self._comments if not c.resolved)

    @property
    def highest_severity(self) -> Severity:
        """Возвращает максимальный уровень важности среди неразрешённых."""
        severities = [c.severity for c in self._comments if not c.resolved]
        if Severity.ERROR in severities:
            return Severity.ERROR
        if Severity.WARNING in severities:
            return Severity.WARNING
        return Severity.INFO

    def mount(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт и возвращает Tkinter виджет.

        Args:
            parent: Родительский виджет для размещения.

        Returns:
            Созданный виджет иконки.
        """
        self._icon_label = tk.Label(
            parent,
            text=self._get_icon(),
            cursor="hand2",
            font=("TkDefaultFont", 12),
        )
        self._icon_label.bind("<Button-1>", lambda e: self._show_popup())
        self._update_icon()
        return self._icon_label

    def _get_icon(self) -> str:
        """Возвращает иконку на основе максимального уровня важности."""
        if not self._comments:
            return self.SEVERITY_ICONS[Severity.INFO]
        return self.SEVERITY_ICONS[self.highest_severity]

    def _update_icon(self) -> None:
        """Обновляет отображение иконки."""
        if self._icon_label is not None:
            self._icon_label.config(text=self._get_icon())
            # Обновляем цвет/видимость в зависимости от наличия комментариев
            if self._comments:
                color = self.SEVERITY_COLORS[self.highest_severity]
                self._icon_label.config(fg=color)
            else:
                self._icon_label.config(fg="#bdc3c7")  # Gray when no comments

    def _show_popup(self) -> None:
        """Открывает popup окно с комментариями."""
        if self._popup is not None and self._popup.winfo_exists():
            self._popup.lift()
            return

        self._popup = tk.Toplevel(self._parent)
        self._popup.title(f"Комментарии к полю: {self._field_id}")
        self._popup.geometry("450x500")
        self._popup.transient(self._parent.winfo_toplevel())
        self._popup.grab_set()
        self._popup.resizable(True, True)

        # Центрируем окно
        self._popup.update_idletasks()
        x = (self._popup.winfo_screenwidth() // 2) - (450 // 2)
        y = (self._popup.winfo_screenheight() // 2) - (500 // 2)
        self._popup.geometry(f"450x500+{x}+{y}")

        self._create_popup_content()

    def _create_popup_content(self) -> None:
        """Создаёт содержимое popup окна."""
        if self._popup is None:
            return

        # Header
        header_frame = tk.Frame(self._popup, bg="#2c3e50", padx=10, pady=10)
        header_frame.pack(fill=tk.X)

        header_text = f"Комментарии ({self.unresolved_count} неразрешённых)"
        tk.Label(
            header_frame,
            text=header_text,
            fg="white",
            bg="#2c3e50",
            font=("TkDefaultFont", 12, "bold"),
        ).pack(anchor=tk.W)

        tk.Label(
            header_frame,
            text=f"Поле: {self._field_id}",
            fg="#bdc3c7",
            bg="#2c3e50",
            font=("TkDefaultFont", 9),
        ).pack(anchor=tk.W)

        # Scrollable comments area
        scroll_frame = tk.Frame(self._popup, padx=10, pady=10)
        scroll_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(scroll_frame, highlightthickness=0)
        scrollbar = tk.Scrollbar(scroll_frame, orient=tk.VERTICAL, command=canvas.yview)

        self._comments_frame = tk.Frame(canvas, padx=5, pady=5)
        self._comments_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )

        canvas.create_window((0, 0), window=self._comments_frame, anchor=tk.NW, width=400)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind mousewheel
        def _on_mousewheel(event: Any) -> None:
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Refresh comments display
        self._refresh_comments_display()

        # Add comment section
        add_frame = tk.LabelFrame(self._popup, text="Добавить комментарий", padx=10, pady=10)
        add_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        # Severity selector
        severity_frame = tk.Frame(add_frame)
        severity_frame.pack(fill=tk.X, pady=(0, 5))

        tk.Label(severity_frame, text="Важность:").pack(side=tk.LEFT)

        self._severity_var.set(Severity.INFO.value)
        for sev in Severity:
            rb = tk.Radiobutton(
                severity_frame,
                text=f"{self.SEVERITY_ICONS[sev]} {sev.value.upper()}",
                variable=self._severity_var,
                value=sev.value,
            )
            rb.pack(side=tk.LEFT, padx=5)

        # Text input
        text_frame = tk.Frame(add_frame)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        text_widget = tk.Text(text_frame, height=4, width=40, font=("TkDefaultFont", 9))
        text_widget.pack(fill=tk.BOTH, expand=True)

        # Buttons
        btn_frame = tk.Frame(add_frame)
        btn_frame.pack(fill=tk.X, pady=(5, 0))

        def on_add_click() -> None:
            text = text_widget.get("1.0", tk.END).strip()
            if not text:
                if self._popup is not None:
                    messagebox.showwarning(
                        "Пустой комментарий",
                        "Пожалуйста, введите текст комментария.",
                        parent=self._popup,
                    )
                return

            severity = Severity(self._severity_var.get())
            self._add_comment(text, severity)
            text_widget.delete("1.0", tk.END)

        tk.Button(
            btn_frame,
            text="Добавить",
            command=on_add_click,
            bg="#27ae60",
            fg="white",
            font=("TkDefaultFont", 9, "bold"),
        ).pack(side=tk.LEFT, padx=(0, 5))

        tk.Button(
            btn_frame,
            text="Закрыть",
            command=self._popup.destroy,
            font=("TkDefaultFont", 9),
        ).pack(side=tk.RIGHT)

        # Cleanup on close
        def on_popup_close() -> None:
            canvas.unbind_all("<MouseWheel>")
            if self._popup is not None:
                self._popup.destroy()
                self._popup = None

        self._popup.protocol("WM_DELETE_WINDOW", on_popup_close)

    def _refresh_comments_display(self) -> None:
        """Обновляет отображение списка комментариев."""
        if self._comments_frame is None:
            return

        # Clear existing content
        for widget in self._comments_frame.winfo_children():
            widget.destroy()

        if not self._comments:
            tk.Label(
                self._comments_frame,
                text="Нет комментариев",
                fg="#7f8c8d",
                font=("TkDefaultFont", 10, "italic"),
            ).pack(pady=20)
            return

        # Sort by creation time (newest last)
        sorted_comments = sorted(self._comments, key=lambda c: c.created_at)

        for comment in sorted_comments:
            self._create_comment_widget(comment)

    def _create_comment_widget(self, comment: Comment) -> None:
        """Создаёт виджет для отображения одного комментария.

        Args:
            comment: Комментарий для отображения.
        """
        if self._comments_frame is None:
            return

        # Frame with border
        frame = tk.Frame(self._comments_frame, relief=tk.GROOVE, borderwidth=1, padx=8, pady=8)
        frame.pack(fill=tk.X, pady=(0, 10))

        # Header with icon, author, role, time
        header_frame = tk.Frame(frame)
        header_frame.pack(fill=tk.X)

        # Severity icon
        icon_label = tk.Label(
            header_frame,
            text=self.SEVERITY_ICONS[comment.severity],
            font=("TkDefaultFont", 14),
        )
        icon_label.pack(side=tk.LEFT)

        # Author and role
        author_frame = tk.Frame(header_frame)
        author_frame.pack(side=tk.LEFT, padx=(5, 0))

        tk.Label(
            author_frame,
            text=comment.author,
            font=("TkDefaultFont", 9, "bold"),
        ).pack(anchor=tk.W)

        role_color = self._get_role_color(comment.author_role)
        tk.Label(
            author_frame,
            text=comment.author_role.display_name,
            fg=role_color,
            font=("TkDefaultFont", 8),
        ).pack(anchor=tk.W)

        # Timestamp and status
        meta_frame = tk.Frame(header_frame)
        meta_frame.pack(side=tk.RIGHT)

        time_str = comment.created_at.strftime("%d.%m.%Y %H:%M")
        tk.Label(
            meta_frame,
            text=time_str,
            fg="#7f8c8d",
            font=("TkDefaultFont", 8),
        ).pack(anchor=tk.E)

        if comment.resolved:
            resolved_by = comment.resolved_by or "?"
            resolved_date = comment.resolved_at.strftime("%d.%m.%Y") if comment.resolved_at else ""
            resolved_str = f"Разрешено: {resolved_by}, {resolved_date}"
            tk.Label(
                meta_frame,
                text=resolved_str,
                fg="#27ae60",
                font=("TkDefaultFont", 8),
            ).pack(anchor=tk.E)
        else:
            tk.Label(
                meta_frame,
                text="Не разрешено",
                fg="#e74c3c",
                font=("TkDefaultFont", 8),
            ).pack(anchor=tk.E)

        # Comment text
        text_color = "#7f8c8d" if comment.resolved else "black"
        text_label = tk.Label(
            frame,
            text=comment.text,
            wraplength=350,
            justify=tk.LEFT,
            fg=text_color,
            font=("TkDefaultFont", 9),
        )
        text_label.pack(fill=tk.X, pady=(5, 0), anchor=tk.W)

        # Resolve button (only for unresolved comments)
        if not comment.resolved:
            btn_frame = tk.Frame(frame)
            btn_frame.pack(fill=tk.X, pady=(5, 0))

            def on_resolve(cid: str = comment.comment_id) -> None:
                self._resolve_comment(cid)

            tk.Button(
                btn_frame,
                text="Разрешить",
                command=on_resolve,
                bg="#27ae60",
                fg="white",
                font=("TkDefaultFont", 8),
            ).pack(side=tk.RIGHT)

        # Add separator
        tk.Frame(self._comments_frame, height=1, bg="#ecf0f1").pack(fill=tk.X, pady=2)

    def _get_role_color(self, role: Role) -> str:
        """Возвращает цвет для роли.

        Args:
            role: Роль пользователя.

        Returns:
            Цвет в hex формате.
        """
        colors: dict[Role, str] = {
            Role.OPERATOR: "#3498db",
            Role.EDITOR: "#2ecc71",
            Role.SUPERVISOR: "#f39c12",
            Role.SIGNATORY: "#e74c3c",
        }
        return colors.get(role, "#95a5a6")

    def _add_comment(self, text: str, severity: Severity) -> None:
        """Добавляет новый комментарий.

        Args:
            text: Текст комментария.
            severity: Уровень важности.
        """
        comment_id = self._on_add(self._field_id, text, severity)
        if comment_id is not None:
            # Create local comment
            new_comment = Comment(
                comment_id=comment_id,
                field_id=self._field_id,
                text=text,
                author=self._current_user,
                author_role=self._current_role,
                severity=severity,
                created_at=datetime.now(),
            )
            self._comments.append(new_comment)
            self._update_icon()
            self._refresh_comments_display()

    def _resolve_comment(self, comment_id: str) -> None:
        """Разрешает комментарий.

        Args:
            comment_id: Идентификатор комментария.
        """
        success = self._on_resolve(comment_id)
        if success:
            # Update local comment
            updated_comments: list[Comment] = []
            for c in self._comments:
                if c.comment_id == comment_id:
                    updated_comment = Comment(
                        comment_id=c.comment_id,
                        field_id=c.field_id,
                        text=c.text,
                        author=c.author,
                        author_role=c.author_role,
                        severity=c.severity,
                        created_at=c.created_at,
                        resolved=True,
                        resolved_at=datetime.now(),
                        resolved_by=self._current_user,
                    )
                    updated_comments.append(updated_comment)
                else:
                    updated_comments.append(c)
            self._comments = updated_comments
            self._update_icon()
            self._refresh_comments_display()

    def set_comments(self, comments: list[Comment]) -> None:
        """Устанавливает список комментариев.

        Args:
            comments: Новый список комментариев.
        """
        self._comments = list(comments)
        self._update_icon()
        if self._popup is not None and self._popup.winfo_exists():
            self._refresh_comments_display()

    def add_local_comment(
        self,
        comment_id: str,
        text: str,
        severity: Severity,
    ) -> None:
        """Добавляет комментарий локально (без callback).

        Args:
            comment_id: ID комментария.
            text: Текст комментария.
            severity: Уровень важности.
        """
        new_comment = Comment(
            comment_id=comment_id,
            field_id=self._field_id,
            text=text,
            author=self._current_user,
            author_role=self._current_role,
            severity=severity,
            created_at=datetime.now(),
        )
        self._comments.append(new_comment)
        self._update_icon()
        if self._popup is not None and self._popup.winfo_exists():
            self._refresh_comments_display()

    def close_popup(self) -> None:
        """Закрывает popup окно если открыто."""
        if self._popup is not None and self._popup.winfo_exists():
            self._popup.destroy()
            self._popup = None


__all__: list[str] = [
    "FieldCommentWidget",
    "Comment",
    "Severity",
    "Role",
]
