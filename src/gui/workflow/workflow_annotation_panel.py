"""WorkflowAnnotationPanel — inline-панель workflow-аннотаций для документа.

Предоставляет:
- Отображение аннотаций (комментариев, замечаний, резолюций, подписей) inline
- Карточки аннотаций с иконкой, автором, ролью, временем, текстом, статусом
- Добавление, ответ и закрытие (resolve) аннотаций
- Показ/скрытие истории ответов
- Интеграция с контроллером через dispatch()

Example:
    >>> from src.gui.workflow.workflow_annotation_panel import WorkflowAnnotationPanel
    >>> panel = WorkflowAnnotationPanel(
    ...     parent=frame,
    ...     annotations=[],
    ...     current_user="Иванов",
    ...     current_role=WorkflowRole.OPERATOR,
    ...     on_add=my_add_callback,
    ...     controller=ctrl,
    ... )
    >>> panel.mount(frame)

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Final, Optional, Protocol

from src.gui.components.base.widget import BaseWidget
from src.gui.workflow.constants import ROLE_COLORS, ROLE_NAMES_RU

if TYPE_CHECKING:
    from src.gui.core.protocols import ControllerProtocol


# =============================================================================
# ENUMS
# =============================================================================


class AnnotationType(Enum):
    """Тип workflow-аннотации.

    Attributes:
        COMMENT: Комментарий — информационное сообщение.
        REMARK: Замечание — требует внимания/исправления.
        RESOLUTION: Резолюция — решение по документу.
        SIGNATURE: Подпись — электронная подпись.
    """

    COMMENT = "comment"
    REMARK = "remark"
    RESOLUTION = "resolution"
    SIGNATURE = "signature"


class AnnotationStatus(Enum):
    """Статус аннотации.

    Attributes:
        OPEN: Аннотация открыта.
        CLOSED: Аннотация закрыта (resolved).
    """

    OPEN = "open"
    CLOSED = "closed"


# =============================================================================
# MODELS
# =============================================================================


@dataclass(frozen=True)
class WorkflowAnnotation:
    """Модель workflow-аннотации.

    Attributes:
        annotation_id: Уникальный идентификатор аннотации.
        annot_type: Тип аннотации.
        author: Имя автора.
        author_role: Роль автора (строковое значение).
        timestamp: Время создания.
        text: Текст сообщения.
        status: Статус аннотации.
        resolved_by: Кем закрыта (если применимо).
        resolved_at: Время закрытия (если применимо).
        replies: Список вложенных ответов (reply-аннотаций).
    """

    annotation_id: str
    annot_type: AnnotationType
    author: str
    author_role: str
    timestamp: datetime
    text: str
    status: AnnotationStatus = AnnotationStatus.OPEN
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    replies: list[WorkflowAnnotation] = field(default_factory=list)


# =============================================================================
# CALLBACK PROTOCOLS
# =============================================================================


class OnAddAnnotationCallback(Protocol):
    """Протокол для callback добавления аннотации."""

    def __call__(
        self,
        text: str,
        annot_type: AnnotationType,
        parent_id: Optional[str] = None,
    ) -> Optional[str]:
        """Вызывается при добавлении аннотации.

        Args:
            text: Текст аннотации.
            annot_type: Тип аннотации.
            parent_id: ID родительской аннотации (для ответа).

        Returns:
            ID созданной аннотации или None в случае ошибки.
        """
        ...


class OnResolveAnnotationCallback(Protocol):
    """Протокол для callback закрытия (resolve) аннотации."""

    def __call__(self, annotation_id: str) -> bool:
        """Вызывается при закрытии аннотации.

        Args:
            annotation_id: Идентификатор аннотации.

        Returns:
            True если закрытие успешно.
        """
        ...


class OnReplyAnnotationCallback(Protocol):
    """Протокол для callback ответа на аннотацию."""

    def __call__(self, parent_id: str, text: str) -> Optional[str]:
        """Вызывается при добавлении ответа.

        Args:
            parent_id: ID родительской аннотации.
            text: Текст ответа.

        Returns:
            ID созданного ответа или None в случае ошибки.
        """
        ...


# =============================================================================
# CONSTANTS
# =============================================================================

# Иконки для типов аннотаций
_ANNOTATION_ICONS: Final[dict[AnnotationType, str]] = {
    AnnotationType.COMMENT: "💬",
    AnnotationType.REMARK: "⚠",
    AnnotationType.RESOLUTION: "✓",
    AnnotationType.SIGNATURE: "🔏",
}

# Color для типов аннотаций
_ANNOTATION_COLORS: Final[dict[AnnotationType, str]] = {
    AnnotationType.COMMENT: "#3498db",  # Синий
    AnnotationType.REMARK: "#f39c12",  # Оранжевый
    AnnotationType.RESOLUTION: "#27ae60",  # Зелёный
    AnnotationType.SIGNATURE: "#e74c3c",  # Красный
}

# Colorа статусов аннотации
_STATUS_COLORS: Final[dict[AnnotationStatus, str]] = {
    AnnotationStatus.OPEN: "#e74c3c",  # Красный
    AnnotationStatus.CLOSED: "#7f8c8d",  # Серый
}

# Локализованные названия статусов
_STATUS_NAMES_RU: Final[dict[AnnotationStatus, str]] = {
    AnnotationStatus.OPEN: "Открыто",
    AnnotationStatus.CLOSED: "Закрыто",
}

# Локализованные названия типов
_TYPE_NAMES_RU: Final[dict[AnnotationType, str]] = {
    AnnotationType.COMMENT: "Комментарий",
    AnnotationType.REMARK: "Замечание",
    AnnotationType.RESOLUTION: "Резолюция",
    AnnotationType.SIGNATURE: "Подпись",
}

# Значения по умолчанию
_DEFAULT_PANEL_WIDTH: Final[int] = 400
_DEFAULT_CARD_PADX: Final[int] = 8
_DEFAULT_CARD_PADY: Final[int] = 6
_DEFAULT_CARD_BORDER: Final[int] = 1


# =============================================================================
# WORKFLOW ANNOTATION PANEL
# =============================================================================


class WorkflowAnnotationPanel(BaseWidget):
    """Inline-панель workflow-аннотаций для документа.

    Отображает аннотации в документе, поддерживает добавление,
    ответ и закрытие, а также показ/скрытие истории ответов.

    Attributes:
        _annotations: Текущий список аннотаций.
        _current_user: Имя текущего пользователя.
        _current_role: Роль текущего пользователя.
        _on_add: Callback при добавлении аннотации.
        _on_resolve: Callback при закрытии аннотации.
        _on_reply: Callback при ответе на аннотацию.

    Example:
        >>> panel = WorkflowAnnotationPanel(
        ...     parent=frame,
        ...     annotations=[],
        ...     current_user="Петров",
        ...     current_role="operator",
        ... )
        >>> panel.mount(frame)
    """

    @property
    def widget(self) -> tk.Widget:
        """Возвращает tkinter widget для размещения.

        Returns:
            Корневой Frame панели.

        Raises:
            RuntimeError: Если виджет не смонтирован.
        """
        if self._main_frame is None:
            raise RuntimeError("WorkflowAnnotationPanel not mounted")
        return self._main_frame

    def __init__(
        self,
        parent: tk.Widget,
        annotations: list[WorkflowAnnotation],
        current_user: str = "",
        current_role: str = "operator",
        on_add: Optional[OnAddAnnotationCallback] = None,
        on_resolve: Optional[OnResolveAnnotationCallback] = None,
        on_reply: Optional[OnReplyAnnotationCallback] = None,
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация панели аннотаций.

        Args:
            parent: Родительский Tkinter виджет.
            annotations: Начальный список аннотаций.
            current_user: Имя текущего пользователя.
            current_role: Роль текущего пользователя.
            on_add: Callback при добавлении аннотации.
            on_resolve: Callback при закрытии аннотации.
            on_reply: Callback при ответе.
            controller: Контроллер для dispatch (опционально).
        """
        super().__init__(widget_id="workflow_annotation_panel", controller=controller)

        self._parent: tk.Widget = parent
        self._annotations: list[WorkflowAnnotation] = list(annotations)
        self._current_user: str = current_user
        self._current_role: str = current_role
        self._on_add: Optional[OnAddAnnotationCallback] = on_add
        self._on_resolve: Optional[OnResolveAnnotationCallback] = on_resolve
        self._on_reply: Optional[OnReplyAnnotationCallback] = on_reply

        # UI references
        self._main_frame: Optional[tk.Frame] = None
        self._canvas: Optional[tk.Canvas] = None
        self._annotations_frame: Optional[tk.Frame] = None
        self._input_text: Optional[tk.Text] = None
        self._type_var: Optional[tk.StringVar] = None
        self._count_label: Optional[tk.Label] = None
        self._toggle_all_btn: Optional[tk.Button] = None
        self._history_visible: dict[str, bool] = {}
        self._reply_texts: dict[str, tk.Text] = {}

    # -------------------------------------------------------------------------
    # Tkinter widget construction
    # -------------------------------------------------------------------------

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт Tkinter виджет панели аннотаций.

        Args:
            parent: Родительский виджет.

        Returns:
            Созданный фрейм с панелью аннотаций.
        """
        self._main_frame = tk.Frame(parent, padx=5, pady=5, bd=2, relief=tk.GROOVE)

        # Заголовок
        self._create_header(self._main_frame)

        # Scrollable список аннотаций
        self._create_annotations_list(self._main_frame)

        # Область добавления новой аннотации
        self._create_add_section(self._main_frame)

        # Начальное отображение
        self._update_display()

        return self._main_frame

    def _create_header(self, parent: tk.Frame) -> None:
        """Создаёт заголовок панели.

        Args:
            parent: Родительский фрейм.
        """
        header = tk.Frame(parent, bg="#ecf0f1", padx=5, pady=5)
        header.pack(fill=tk.X, pady=(0, 5))

        self._count_label = tk.Label(
            header,
            text=self._get_header_text(),
            bg="#ecf0f1",
            font=("TkDefaultFont", 10, "bold"),
        )
        self._count_label.pack(side=tk.LEFT)

        self._toggle_all_btn = tk.Button(
            header,
            text="Показать историю",
            font=("TkDefaultFont", 8),
            command=self._toggle_all_history,
        )
        self._toggle_all_btn.pack(side=tk.RIGHT)

    def _create_annotations_list(self, parent: tk.Frame) -> None:
        """Создаёт scrollable список аннотаций.

        Args:
            parent: Родительский фрейм.
        """
        scroll_frame = tk.Frame(parent)
        scroll_frame.pack(fill=tk.BOTH, expand=True)

        self._canvas = tk.Canvas(scroll_frame, highlightthickness=0)
        scrollbar = tk.Scrollbar(scroll_frame, orient=tk.VERTICAL, command=self._canvas.yview)

        self._annotations_frame = tk.Frame(self._canvas, padx=3, pady=3)
        self._annotations_frame.bind(
            "<Configure>",
            self._on_annotations_configure,
        )

        self._canvas.create_window(
            (0, 0), window=self._annotations_frame, anchor=tk.NW, width=_DEFAULT_PANEL_WIDTH - 20
        )
        self._canvas.configure(yscrollcommand=scrollbar.set)

        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def _on_annotations_configure(self, event: tk.Event) -> None:
        """Обновляет scrollregion canvas при изменении размеров списка.

        Args:
            event: Событие Configure.
        """
        if self._canvas is not None:
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _create_add_section(self, parent: tk.Frame) -> None:
        """Создаёт область добавления новой аннотации.

        Args:
            parent: Родительский фрейм.
        """
        add_frame = tk.LabelFrame(parent, text="Добавить аннотацию", padx=5, pady=5)
        add_frame.pack(fill=tk.X, pady=(5, 0))

        # Выбор типа
        type_frame = tk.Frame(add_frame)
        type_frame.pack(fill=tk.X, pady=(0, 3))

        self._type_var = tk.StringVar(value=AnnotationType.COMMENT.value)

        for atype in AnnotationType:
            rb = tk.Radiobutton(
                type_frame,
                text=f"{_ANNOTATION_ICONS[atype]} {_TYPE_NAMES_RU[atype]}",
                variable=self._type_var,
                value=atype.value,
                font=("TkDefaultFont", 8),
            )
            rb.pack(side=tk.LEFT, padx=3)

        # Текстовое поле
        self._input_text = tk.Text(add_frame, height=3, width=40, font=("TkDefaultFont", 9))
        self._input_text.pack(fill=tk.X, pady=3)

        # Кнопки
        btn_frame = tk.Frame(add_frame)
        btn_frame.pack(fill=tk.X)

        tk.Button(
            btn_frame,
            text="Добавить",
            bg="#3498db",
            fg="white",
            font=("TkDefaultFont", 9, "bold"),
            command=self._on_add_clicked,
        ).pack(side=tk.LEFT)

    # -------------------------------------------------------------------------
    # Display updates
    # -------------------------------------------------------------------------

    def _update_display(self) -> None:
        """Обновляет отображение списка аннотаций."""
        if self._annotations_frame is None:
            return

        # Очистка
        for child in self._annotations_frame.winfo_children():
            child.destroy()

        if not self._annotations:
            tk.Label(
                self._annotations_frame,
                text="Нет аннотаций",
                fg="#7f8c8d",
                font=("TkDefaultFont", 10, "italic"),
            ).pack(pady=20)
        else:
            for annotation in self._annotations:
                self._create_card(annotation)

        if self._count_label is not None:
            self._count_label.config(text=self._get_header_text())

    def _create_card(self, annotation: WorkflowAnnotation) -> None:
        """Создаёт карточку аннотации.

        Args:
            annotation: Аннотация для отображения.
        """
        if self._annotations_frame is None:
            return

        card = tk.Frame(
            self._annotations_frame,
            relief=tk.GROOVE,
            bd=_DEFAULT_CARD_BORDER,
            padx=_DEFAULT_CARD_PADX,
            pady=_DEFAULT_CARD_PADY,
            bg="white",
        )
        card.pack(fill=tk.X, pady=(0, 8))
        card._annotation_id = annotation.annotation_id  # type: ignore[attr-defined]

        # Верхняя строка: иконка + автор + роль + время + статус
        header = tk.Frame(card, bg="white")
        header.pack(fill=tk.X)

        icon_color = _ANNOTATION_COLORS[annotation.annot_type]
        icon_label = tk.Label(
            header,
            text=_ANNOTATION_ICONS[annotation.annot_type],
            font=("TkDefaultFont", 14),
            bg="white",
            fg=icon_color,
        )
        icon_label.pack(side=tk.LEFT)

        # Автор и роль
        author_frame = tk.Frame(header, bg="white")
        author_frame.pack(side=tk.LEFT, padx=(5, 0))

        tk.Label(
            author_frame,
            text=annotation.author,
            font=("TkDefaultFont", 9, "bold"),
            bg="white",
        ).pack(anchor=tk.W)

        role_color = ROLE_COLORS.get(annotation.author_role, "#95a5a6")
        role_name = ROLE_NAMES_RU.get(annotation.author_role, annotation.author_role)
        tk.Label(
            author_frame,
            text=role_name,
            fg=role_color,
            font=("TkDefaultFont", 8),
            bg="white",
        ).pack(anchor=tk.W)

        # Время и статус
        meta_frame = tk.Frame(header, bg="white")
        meta_frame.pack(side=tk.RIGHT)

        time_str = annotation.timestamp.strftime("%d.%m.%Y %H:%M")
        tk.Label(
            meta_frame,
            text=time_str,
            fg="#7f8c8d",
            font=("TkDefaultFont", 8),
            bg="white",
        ).pack(anchor=tk.E)

        status_text = _STATUS_NAMES_RU[annotation.status]
        status_color = _STATUS_COLORS[annotation.status]
        tk.Label(
            meta_frame,
            text=status_text,
            fg=status_color,
            font=("TkDefaultFont", 8, "bold"),
            bg="white",
        ).pack(anchor=tk.E)

        # Текст аннотации
        text_color = "#7f8c8d" if annotation.status == AnnotationStatus.CLOSED else "#2c3e50"
        tk.Label(
            card,
            text=annotation.text,
            wraplength=_DEFAULT_PANEL_WIDTH - 60,
            justify=tk.LEFT,
            fg=text_color,
            font=("TkDefaultFont", 9),
            bg="white",
        ).pack(fill=tk.X, pady=(5, 0), anchor=tk.W)

        # Информация о закрытии
        if annotation.status == AnnotationStatus.CLOSED and annotation.resolved_by:
            resolved_str = (
                f"Закрыто: {annotation.resolved_by}, "
                f"{annotation.resolved_at.strftime('%d.%m.%Y') if annotation.resolved_at else ''}"
            )
            tk.Label(
                card,
                text=resolved_str,
                fg="#27ae60",
                font=("TkDefaultFont", 8),
                bg="white",
            ).pack(anchor=tk.W)

        # Кнопки действий
        actions = tk.Frame(card, bg="white")
        actions.pack(fill=tk.X, pady=(5, 0))

        if annotation.status == AnnotationStatus.OPEN:
            from functools import partial

            tk.Button(
                actions,
                text="Ответить",
                font=("TkDefaultFont", 8),
                command=partial(self._on_reply_clicked, annotation.annotation_id),
            ).pack(side=tk.LEFT, padx=(0, 5))

            tk.Button(
                actions,
                text="Закрыть",
                font=("TkDefaultFont", 8),
                bg="#27ae60",
                fg="white",
                command=partial(self._on_resolve_clicked, annotation.annotation_id),
            ).pack(side=tk.RIGHT)

        # История ответов (reply-аннотации)
        if annotation.replies:
            visible = self._history_visible.get(annotation.annotation_id, False)
            from functools import partial

            history_btn = tk.Button(
                card,
                text=f"История ({len(annotation.replies)}) {'▼' if visible else '▶'}",
                font=("TkDefaultFont", 8),
                bg="white",
                command=partial(self._toggle_history, annotation.annotation_id),
            )
            history_btn.pack(anchor=tk.W, pady=(3, 0))

            if visible:
                self._create_replies_section(card, annotation.replies)

    def _create_replies_section(self, parent: tk.Frame, replies: list[WorkflowAnnotation]) -> None:
        """Создаёт секцию ответов внутри карточки.

        Args:
            parent: Родительский фрейм карточки.
            replies: Список reply-аннотаций.
        """
        replies_frame = tk.Frame(parent, bg="#f8f9fa", padx=5, pady=5)
        replies_frame.pack(fill=tk.X, pady=(3, 0))

        for reply in replies:
            reply_frame = tk.Frame(replies_frame, bg="#f8f9fa")
            reply_frame.pack(fill=tk.X, pady=(0, 4))

            # Иконка типа
            icon_color = _ANNOTATION_COLORS.get(reply.annot_type, "#95a5a6")
            tk.Label(
                reply_frame,
                text=_ANNOTATION_ICONS.get(reply.annot_type, "💬"),
                fg=icon_color,
                font=("TkDefaultFont", 10),
                bg="#f8f9fa",
            ).pack(side=tk.LEFT)

            # Автор и роль
            author_info = tk.Frame(reply_frame, bg="#f8f9fa")
            author_info.pack(side=tk.LEFT, padx=(5, 0))

            tk.Label(
                author_info,
                text=reply.author,
                font=("TkDefaultFont", 8, "bold"),
                bg="#f8f9fa",
            ).pack(anchor=tk.W)

            role_color = ROLE_COLORS.get(reply.author_role, "#95a5a6")
            role_name = ROLE_NAMES_RU.get(reply.author_role, reply.author_role)
            tk.Label(
                author_info,
                text=role_name,
                fg=role_color,
                font=("TkDefaultFont", 7),
                bg="#f8f9fa",
            ).pack(anchor=tk.W)

            # Время
            time_str = reply.timestamp.strftime("%d.%m.%Y %H:%M")
            tk.Label(
                reply_frame,
                text=time_str,
                fg="#7f8c8d",
                font=("TkDefaultFont", 7),
                bg="#f8f9fa",
            ).pack(side=tk.RIGHT)

            # Текст
            tk.Label(
                replies_frame,
                text=reply.text,
                wraplength=_DEFAULT_PANEL_WIDTH - 80,
                justify=tk.LEFT,
                fg="#2c3e50",
                font=("TkDefaultFont", 8),
                bg="#f8f9fa",
            ).pack(fill=tk.X, anchor=tk.W, pady=(2, 0))

    def _get_header_text(self) -> str:
        """Возвращает текст заголовка с количеством аннотаций.

        Returns:
            Строка заголовка.
        """
        total = len(self._annotations)
        open_count = sum(1 for a in self._annotations if a.status == AnnotationStatus.OPEN)
        return f"Аннотации ({total}, открыто: {open_count})"

    # -------------------------------------------------------------------------
    # Actions
    # -------------------------------------------------------------------------

    def _on_add_clicked(self) -> None:
        """Обрабатывает нажатие кнопки добавления аннотации."""
        if self._input_text is None or self._type_var is None:
            return

        text = self._input_text.get("1.0", tk.END).strip()
        if not text:
            return

        annot_type = AnnotationType(self._type_var.get())

        # Используем dispatch через контроллер, если он есть
        if self._controller is not None:
            self._controller.dispatch(
                "annotation_add",
                text=text,
                annot_type=annot_type.value,
                author=self._current_user,
                author_role=self._current_role,
            )
        elif self._on_add is not None:
            result = self._on_add(text, annot_type)
            if result:
                new_annotation = WorkflowAnnotation(
                    annotation_id=result,
                    annot_type=annot_type,
                    author=self._current_user,
                    author_role=self._current_role,
                    timestamp=datetime.now(),
                    text=text,
                )
                self._annotations.append(new_annotation)
                self._update_display()

        # Очистка поля ввода
        self._input_text.delete("1.0", tk.END)

    def _on_reply_clicked(self, annotation_id: str) -> None:
        """Обрабатывает нажатие кнопки ответа.

        Args:
            annotation_id: ID аннотации.
        """
        # Проверяем, нет ли уже открытого поля для ответа
        reply_key = f"reply_{annotation_id}"
        if reply_key in self._reply_texts:
            return

        # Находим карточку по annotation_id (сохраняем в widget dict)
        target_card: Optional[tk.Widget] = None
        if self._annotations_frame is not None:
            for card in self._annotations_frame.winfo_children():
                # Проверяем, соответствует ли карточка нужной аннотации
                if hasattr(card, "_annotation_id"):
                    card_annotation_id = card._annotation_id  # noqa: SLF001
                    if card_annotation_id == annotation_id:
                        target_card = card
                        break

        # Если не нашли по атрибуту, ищем по позиции (порядок карточек = порядок аннотаций)
        if target_card is None and self._annotations_frame is not None:
            children = self._annotations_frame.winfo_children()
            for i, annotation in enumerate(self._annotations):
                if annotation.annotation_id == annotation_id and i < len(children):
                    target_card = children[i]
                    break

        if target_card is None:
            return

        # Создаём поле для ввода ответа внутри карточки
        reply_frame = tk.Frame(target_card, bg="white")
        reply_frame.pack(fill=tk.X, pady=(5, 0))

        text_widget = tk.Text(reply_frame, height=2, width=30, font=("TkDefaultFont", 8))
        text_widget.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._reply_texts[reply_key] = text_widget

        def send_reply(
            aid: str = annotation_id,
            tw: tk.Text = text_widget,
            rf: tk.Frame = reply_frame,
        ) -> None:
            text = tw.get("1.0", tk.END).strip()
            if not text:
                return
            self._do_reply(aid, text)
            tw.destroy()
            rf.destroy()
            if reply_key in self._reply_texts:
                del self._reply_texts[reply_key]

        tk.Button(
            reply_frame,
            text="Отправить",
            font=("TkDefaultFont", 8),
            command=send_reply,
        ).pack(side=tk.RIGHT, padx=(5, 0))

    def _do_reply(self, parent_id: str, text: str) -> None:
        """Выполняет добавление ответа.

        Args:
            parent_id: ID родительской аннотации.
            text: Текст ответа.
        """
        if self._controller is not None:
            self._controller.dispatch(
                "annotation_reply",
                parent_id=parent_id,
                text=text,
                author=self._current_user,
                author_role=self._current_role,
            )
        elif self._on_reply is not None:
            result = self._on_reply(parent_id, text)
            if result:
                for i, annotation in enumerate(self._annotations):
                    if annotation.annotation_id == parent_id:
                        reply = WorkflowAnnotation(
                            annotation_id=result,
                            annot_type=AnnotationType.COMMENT,
                            author=self._current_user,
                            author_role=self._current_role,
                            timestamp=datetime.now(),
                            text=text,
                        )
                        # Замена замороженного объекта
                        updated_replies = list(annotation.replies) + [reply]
                        self._annotations[i] = WorkflowAnnotation(
                            annotation_id=annotation.annotation_id,
                            annot_type=annotation.annot_type,
                            author=annotation.author,
                            author_role=annotation.author_role,
                            timestamp=annotation.timestamp,
                            text=annotation.text,
                            status=annotation.status,
                            resolved_by=annotation.resolved_by,
                            resolved_at=annotation.resolved_at,
                            replies=updated_replies,
                        )
                        break
                self._update_display()

    def _on_resolve_clicked(self, annotation_id: str) -> None:
        """Обрабатывает нажатие кнопки закрытия аннотации.

        Args:
            annotation_id: ID аннотации для закрытия.
        """
        if self._controller is not None:
            self._controller.dispatch(
                "annotation_resolve",
                annotation_id=annotation_id,
                resolved_by=self._current_user,
            )
        elif self._on_resolve is not None:
            success = self._on_resolve(annotation_id)
            if success:
                self._resolve_local(annotation_id)

    def _resolve_local(self, annotation_id: str) -> None:
        """Локально закрывает аннотацию.

        Args:
            annotation_id: ID аннотации для закрытия.
        """
        for i, annotation in enumerate(self._annotations):
            if annotation.annotation_id == annotation_id:
                self._annotations[i] = WorkflowAnnotation(
                    annotation_id=annotation.annotation_id,
                    annot_type=annotation.annot_type,
                    author=annotation.author,
                    author_role=annotation.author_role,
                    timestamp=annotation.timestamp,
                    text=annotation.text,
                    status=AnnotationStatus.CLOSED,
                    resolved_by=self._current_user,
                    resolved_at=datetime.now(),
                    replies=annotation.replies,
                )
                self._update_display()
                return

    def _toggle_history(self, annotation_id: str) -> None:
        """Переключает видимость истории ответов для аннотации.

        Args:
            annotation_id: ID аннотации.
        """
        current = self._history_visible.get(annotation_id, False)
        self._history_visible[annotation_id] = not current
        self._update_display()

    def _toggle_all_history(self) -> None:
        """Переключает видимость истории для всех аннотаций."""
        if not self._annotations:
            return

        # Если хотя бы одна открыта — закрываем все, иначе открываем все
        any_visible = any(
            self._history_visible.get(a.annotation_id, False)
            for a in self._annotations
            if a.replies
        )

        for annotation in self._annotations:
            if annotation.replies:
                self._history_visible[annotation.annotation_id] = not any_visible

        if self._toggle_all_btn is not None:
            btn_text = "Скрыть историю" if not any_visible else "Показать историю"
            self._toggle_all_btn.config(text=btn_text)

        self._update_display()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def set_annotations(self, annotations: list[WorkflowAnnotation]) -> None:
        """Устанавливает новый список аннотаций.

        Args:
            annotations: Новый список аннотаций.
        """
        self._annotations = list(annotations)
        self._update_display()

    def add_local_annotation(self, annotation: WorkflowAnnotation) -> None:
        """Добавляет аннотацию локально (без callback).

        Args:
            annotation: Аннотация для добавления.
        """
        self._annotations.append(annotation)
        self._update_display()

    def resolve_local(self, annotation_id: str, resolved_by: str) -> None:
        """Локально закрывает аннотацию.

        Args:
            annotation_id: ID аннотации для закрытия.
            resolved_by: Имя пользователя, закрывшего аннотацию.
        """
        self._current_user = resolved_by
        self._resolve_local(annotation_id)

    # -------------------------------------------------------------------------
    # Cleanup
    # -------------------------------------------------------------------------

    def _cleanup(self) -> None:
        """Очищает ресурсы и callback'и перед демонтированием."""
        self._annotations = []
        self._on_add = None
        self._on_resolve = None
        self._on_reply = None
        self._history_visible.clear()
        self._reply_texts.clear()
        super()._cleanup()


__all__: list[str] = [
    "WorkflowAnnotationPanel",
    "AnnotationType",
    "AnnotationStatus",
    "WorkflowAnnotation",
    "OnAddAnnotationCallback",
    "OnResolveAnnotationCallback",
    "OnReplyAnnotationCallback",
]
