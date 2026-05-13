"""Тесты для WorkflowAnnotationPanel.

Тестирует создание, отображение, добавление, закрытие,
ответы, историю и cleanup панели аннотаций.
"""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path

_project_root = str(Path(__file__).resolve().parents[4])
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# Pre-emptively break the circular import chain by replacing
# ``src.gui.components`` with a namespace package that only exposes
# ``src.gui.components.base.widget`` without pulling in form_field→dialogs→renderers.
# We evict anything that may have been loaded already by pytest or its plugins.
for key in list(sys.modules.keys()):
    if key.startswith("src.gui.components"):
        del sys.modules[key]

for _mod_name, _relpath in [
    ("src.gui.components", "src/gui/components"),
    ("src.gui.components.base", "src/gui/components/base"),
    ("src.gui.components.base.widget", "src/gui/components/base/widget.py"),
]:
    if _mod_name not in sys.modules:
        _m = types.ModuleType(_mod_name)
        if _relpath.endswith(".py"):
            _m.__file__ = os.path.join(_project_root, _relpath)
        else:
            _m.__path__ = [os.path.join(_project_root, _relpath)]
        sys.modules[_mod_name] = _m

# Inject widget submodule so import of BaseWidget works without loading
# the real __init__.py of src.gui.components.
from importlib.machinery import SourceFileLoader  # noqa: E402
_widget_mod = SourceFileLoader(
    "src.gui.components.base.widget",
    os.path.join(_project_root, "src/gui/components/base/widget.py"),
).load_module()

sys.modules["src.gui.components.base.widget"] = _widget_mod
sys.modules["src.gui.components.base"].widget = _widget_mod
sys.modules["src.gui.components"].BaseWidget = _widget_mod.BaseWidget
sys.modules["src.gui.components"].SmartBaseWidget = _widget_mod.SmartBaseWidget

import tkinter as tk
from datetime import datetime
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.workflow.workflow_annotation_panel import (
    AnnotationStatus,
    AnnotationType,
    OnAddAnnotationCallback,
    OnReplyAnnotationCallback,
    OnResolveAnnotationCallback,
    WorkflowAnnotation,
    WorkflowAnnotationPanel,
    _ANNOTATION_COLORS,
    _ANNOTATION_ICONS,
    _STATUS_COLORS,
    _STATUS_NAMES_RU,
    _TYPE_NAMES_RU,
)


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Фикстура для Tk root."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def sample_annotation() -> WorkflowAnnotation:
    """Фикстура для тестовой аннотации."""
    return WorkflowAnnotation(
        annotation_id="ann_1",
        annot_type=AnnotationType.COMMENT,
        author="Иванов",
        author_role="operator",
        timestamp=datetime(2026, 5, 7, 12, 0),
        text="Тестовый комментарий",
    )


@pytest.fixture
def resolved_annotation() -> WorkflowAnnotation:
    """Фикстура для закрытой аннотации."""
    return WorkflowAnnotation(
        annotation_id="ann_2",
        annot_type=AnnotationType.REMARK,
        author="Петров",
        author_role="editor",
        timestamp=datetime(2026, 5, 6, 10, 0),
        text="Замечание по документу",
        status=AnnotationStatus.CLOSED,
        resolved_by="Сидоров",
        resolved_at=datetime(2026, 5, 6, 14, 0),
    )


@pytest.fixture
def annotation_with_replies() -> WorkflowAnnotation:
    """Фикстура для аннотации с ответами."""
    reply = WorkflowAnnotation(
        annotation_id="reply_1",
        annot_type=AnnotationType.COMMENT,
        author="Сидоров",
        author_role="supervisor",
        timestamp=datetime(2026, 5, 7, 13, 0),
        text="Подтверждаю",
    )
    return WorkflowAnnotation(
        annotation_id="ann_3",
        annot_type=AnnotationType.COMMENT,
        author="Иванов",
        author_role="operator",
        timestamp=datetime(2026, 5, 7, 12, 0),
        text="Вопрос",
        replies=[reply],
    )


class TestWorkflowAnnotationPanelInit:
    """Тесты инициализации панели."""

    def test_init_empty(self, root: tk.Tk) -> None:
        """Тест инициализации без аннотаций."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
        )
        assert panel._annotations == []
        assert panel._current_user == "Тест"
        assert panel._current_role == "operator"
        assert panel._controller is None

    def test_init_with_annotations(self, root: tk.Tk, sample_annotation: WorkflowAnnotation) -> None:
        """Тест инициализации с аннотациями."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[sample_annotation],
            current_user="Тест",
            current_role="operator",
        )
        assert len(panel._annotations) == 1
        assert panel._annotations[0].annotation_id == "ann_1"

    def test_init_with_callbacks(self, root: tk.Tk) -> None:
        """Тест инициализации с callback'ами."""
        on_add = MagicMock()
        on_resolve = MagicMock()
        on_reply = MagicMock()

        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
            on_add=on_add,
            on_resolve=on_resolve,
            on_reply=on_reply,
        )
        assert panel._on_add is on_add
        assert panel._on_resolve is on_resolve
        assert panel._on_reply is on_reply


class TestWorkflowAnnotationPanelMount:
    """Тесты монтирования виджета."""

    def test_mount_creates_widget(self, root: tk.Tk) -> None:
        """Тест что mount создаёт виджет."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
        )
        widget = panel.mount(root)
        assert isinstance(widget, tk.Widget)
        panel.unmount()

    def test_mount_with_annotations(self, root: tk.Tk, sample_annotation: WorkflowAnnotation) -> None:
        """Тест mount с аннотациями."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[sample_annotation],
            current_user="Тест",
            current_role="operator",
        )
        widget = panel.mount(root)
        assert isinstance(widget, tk.Widget)
        panel.unmount()

    def test_is_mounted_after_mount(self, root: tk.Tk) -> None:
        """Тест что флаг установлен после mount."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
        )
        assert not panel.is_mounted()
        panel.mount(root)
        assert panel.is_mounted()
        panel.unmount()
        assert not panel.is_mounted()

    def test_unmount_cleanup(self, root: tk.Tk) -> None:
        """Тест что unmount очищает ресурсы."""
        on_add = MagicMock()
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
            on_add=on_add,
        )
        panel.mount(root)
        panel.unmount()
        assert panel._annotations == []
        assert panel._on_add is None

    def test_mount_twice_raises(self, root: tk.Tk) -> None:
        """Тест повторного mount вызывает ошибку."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
        )
        panel.mount(root)
        with pytest.raises(Exception):
            panel.mount(root)
        panel.unmount()


class TestWorkflowAnnotationPanelDisplay:
    """Тесты отображения аннотаций."""

    def test_empty_display(self, root: tk.Tk) -> None:
        """Тест отображение при пустом списке."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
        )
        panel.mount(root)
        panel._update_display()
        panel.unmount()

    def test_single_annotation_display(self, root: tk.Tk, sample_annotation: WorkflowAnnotation) -> None:
        """Тест отображение одной аннотации."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[sample_annotation],
            current_user="Тест",
            current_role="operator",
        )
        panel.mount(root)
        panel._update_display()
        panel.unmount()

    def test_resolved_annotation_display(self, root: tk.Tk, resolved_annotation: WorkflowAnnotation) -> None:
        """Тест отображение закрытой аннотации."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[resolved_annotation],
            current_user="Тест",
            current_role="operator",
        )
        panel.mount(root)
        panel._update_display()
        panel.unmount()

    def test_annotation_with_replies_display(self, root: tk.Tk, annotation_with_replies: WorkflowAnnotation) -> None:
        """Тест отображение аннотации с ответами."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[annotation_with_replies],
            current_user="Тест",
            current_role="operator",
        )
        panel.mount(root)
        # Сразу видим историю
        panel._history_visible[annotation_with_replies.annotation_id] = True
        panel._update_display()
        panel.unmount()


class TestWorkflowAnnotationPanelAdd:
    """Тесты добавления аннотаций."""

    def test_add_via_callback(self, root: tk.Tk) -> None:
        """Тест добавления через callback."""
        def on_add(text: str, annot_type: AnnotationType, parent_id: str | None = None) -> str | None:
            return "new_id"

        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
            on_add=on_add,
        )
        panel.mount(root)
        panel._input_text.insert("1.0", "Новая аннотация")
        panel._on_add_clicked()
        assert len(panel._annotations) == 1
        assert panel._annotations[0].text == "Новая аннотация"
        panel.unmount()

    def test_add_empty_text(self, root: tk.Tk) -> None:
        """Тест что пустой текст не добавляет аннотацию."""
        def on_add(text: str, annot_type: AnnotationType, parent_id: str | None = None) -> str | None:
            return "new_id"

        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
            on_add=on_add,
        )
        panel.mount(root)
        panel._on_add_clicked()
        assert len(panel._annotations) == 0
        panel.unmount()

    def test_add_via_controller_dispatch(self, root: tk.Tk) -> None:
        """Тест dispatch через контроллер."""
        controller = MagicMock()
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
            controller=controller,
        )
        panel.mount(root)
        panel._input_text.insert("1.0", "Через контроллер")
        panel._on_add_clicked()
        assert controller.dispatch.call_count >= 1
        panel.unmount()


class TestWorkflowAnnotationPanelResolve:
    """Тесты закрытия аннотаций."""

    def test_resolve_via_callback(self, root: tk.Tk, sample_annotation: WorkflowAnnotation) -> None:
        """Тест закрытия через callback."""
        def on_resolve(annotation_id: str) -> bool:
            return True

        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[sample_annotation],
            current_user="Тест",
            current_role="operator",
            on_resolve=on_resolve,
        )
        panel.mount(root)
        panel._on_resolve_clicked("ann_1")
        assert panel._annotations[0].status == AnnotationStatus.CLOSED
        assert panel._annotations[0].resolved_by == "Тест"
        panel.unmount()

    def test_resolve_via_controller(self, root: tk.Tk, sample_annotation: WorkflowAnnotation) -> None:
        """Тест закрытия через контроллер."""
        controller = MagicMock()
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[sample_annotation],
            current_user="Тест",
            current_role="operator",
            controller=controller,
        )
        panel.mount(root)
        panel._on_resolve_clicked("ann_1")
        assert controller.dispatch.call_count >= 1
        panel.unmount()

    def test_resolve_local(self, root: tk.Tk, sample_annotation: WorkflowAnnotation) -> None:
        """Тест локального закрытия."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[sample_annotation],
            current_user="Тест",
            current_role="operator",
        )
        panel.resolve_local("ann_1", "Админ")
        assert panel._annotations[0].status == AnnotationStatus.CLOSED
        assert panel._annotations[0].resolved_by == "Админ"


class TestWorkflowAnnotationPanelReply:
    """Тесты ответов на аннотации."""

    def test_add_local_annotation(self, root: tk.Tk, sample_annotation: WorkflowAnnotation) -> None:
        """Тест локального добавления аннотации."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[sample_annotation],
            current_user="Тест",
            current_role="operator",
        )
        new_annotation = WorkflowAnnotation(
            annotation_id="ann_2",
            annot_type=AnnotationType.COMMENT,
            author="Петров",
            author_role="editor",
            timestamp=datetime.now(),
            text="Ответ",
        )
        panel.add_local_annotation(new_annotation)
        assert len(panel._annotations) == 2

    def test_set_annotations(self, root: tk.Tk, sample_annotation: WorkflowAnnotation) -> None:
        """Тест установки списка аннотаций."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[sample_annotation],
            current_user="Тест",
            current_role="operator",
        )
        panel.set_annotations([])
        assert len(panel._annotations) == 0


class TestWorkflowAnnotationPanelHistory:
    """Тесты истории ответов."""

    def test_toggle_history(self, root: tk.Tk, annotation_with_replies: WorkflowAnnotation) -> None:
        """Тест переключения истории."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[annotation_with_replies],
            current_user="Тест",
            current_role="operator",
        )
        panel._toggle_history("ann_3")
        assert panel._history_visible["ann_3"]
        panel._toggle_history("ann_3")
        assert not panel._history_visible["ann_3"]

    def test_toggle_all_history(self, root: tk.Tk, annotation_with_replies: WorkflowAnnotation) -> None:
        """Тест переключения истории для всех аннотаций."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[annotation_with_replies],
            current_user="Тест",
            current_role="operator",
        )
        panel._toggle_all_history()
        assert panel._history_visible.get("ann_3", False)
        panel._toggle_all_history()
        assert not panel._history_visible.get("ann_3", False)


class TestWorkflowAnnotationPanelModels:
    """Тесты моделей данных."""

    def test_annotation_frozen(self) -> None:
        """Тест что WorkflowAnnotation immutable."""
        annotation = WorkflowAnnotation(
            annotation_id="ann_1",
            annot_type=AnnotationType.COMMENT,
            author="Иванов",
            author_role="operator",
            timestamp=datetime.now(),
            text="Текст",
        )
        with pytest.raises(AttributeError):
            annotation.text = "Новый текст"  # type: ignore[misc]

    def test_annotation_status_values(self) -> None:
        """Тест значений статусов."""
        assert AnnotationStatus.OPEN.value == "open"
        assert AnnotationStatus.CLOSED.value == "closed"

    def test_annotation_type_values(self) -> None:
        """Тест значений типов."""
        assert AnnotationType.COMMENT.value == "comment"
        assert AnnotationType.REMARK.value == "remark"
        assert AnnotationType.RESOLUTION.value == "resolution"
        assert AnnotationType.SIGNATURE.value == "signature"

    def test_annotation_with_replies(self) -> None:
        """Тест аннотации с ответами."""
        reply = WorkflowAnnotation(
            annotation_id="reply_1",
            annot_type=AnnotationType.COMMENT,
            author="Петров",
            author_role="editor",
            timestamp=datetime.now(),
            text="Ответ",
        )
        annotation = WorkflowAnnotation(
            annotation_id="ann_1",
            annot_type=AnnotationType.COMMENT,
            author="Иванов",
            author_role="operator",
            timestamp=datetime.now(),
            text="Вопрос",
            replies=[reply],
        )
        assert len(annotation.replies) == 1
        assert annotation.replies[0].annotation_id == "reply_1"


class TestWorkflowAnnotationPanelConstants:
    """Тесты констант и локализации."""

    def test_all_types_have_icons(self) -> None:
        """Тест что все типы имеют иконки."""
        for atype in AnnotationType:
            assert atype in _ANNOTATION_ICONS
            assert len(_ANNOTATION_ICONS[atype]) > 0

    def test_all_types_have_colors(self) -> None:
        """Тест что все типы имеют цвета."""
        for atype in AnnotationType:
            assert atype in _ANNOTATION_COLORS
            assert _ANNOTATION_COLORS[atype].startswith("#")
            assert len(_ANNOTATION_COLORS[atype]) == 7

    def test_all_statuses_have_colors(self) -> None:
        """Тест что все статусы имеют цвета."""
        for status in AnnotationStatus:
            assert status in _STATUS_COLORS
            assert _STATUS_COLORS[status].startswith("#")
            assert len(_STATUS_COLORS[status]) == 7

    def test_all_statuses_have_names(self) -> None:
        """Тест что все статусы имеют названия."""
        for status in AnnotationStatus:
            assert status in _STATUS_NAMES_RU
            assert len(_STATUS_NAMES_RU[status]) > 0

    def test_all_types_have_type_names(self) -> None:
        """Тест что все типы имеют названия."""
        for atype in AnnotationType:
            assert atype in _TYPE_NAMES_RU
            assert len(_TYPE_NAMES_RU[atype]) > 0


class TestWorkflowAnnotationPanelWidget:
    """Тесты доступа к виджету."""

    def test_widget_raises_when_not_mounted(self, root: tk.Tk) -> None:
        """Тест что widget вызывает RuntimeError если не смонтирован."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
        )
        with pytest.raises(RuntimeError):
            _ = panel.widget

    def test_widget_returns_when_mounted(self, root: tk.Tk) -> None:
        """Тест что widget возвращается после mount."""
        panel = WorkflowAnnotationPanel(
            parent=root,
            annotations=[],
            current_user="Тест",
            current_role="operator",
        )
        panel.mount(root)
        w = panel.widget
        assert isinstance(w, tk.Widget)
        panel.unmount()


__all__: list[str] = [
    "TestWorkflowAnnotationPanelInit",
    "TestWorkflowAnnotationPanelMount",
    "TestWorkflowAnnotationPanelDisplay",
    "TestWorkflowAnnotationPanelAdd",
    "TestWorkflowAnnotationPanelResolve",
    "TestWorkflowAnnotationPanelReply",
    "TestWorkflowAnnotationPanelHistory",
    "TestWorkflowAnnotationPanelModels",
    "TestWorkflowAnnotationPanelConstants",
    "TestWorkflowAnnotationPanelWidget",
]
