"""Workflow UI компоненты для FX Text Processor 3 (GUI layer).

Предоставляет виджеты для управления workflow документов:
- FieldCommentWidget: виджет комментариев к полю
- WorkflowStateManager: управление состояниями с undo/redo
- TransitionCommand: Command паттерн для transitions
- TransitionDialog: диалог перехода состояния
- RoleSwitchDialog: смена роли с MFA

Version: 1.2
Date: April 2026
"""

from __future__ import annotations

# Constants (A3)
from src.gui.workflow.constants import (
    ARCHIVED_CONFIRMATION_TEXT,
    FREE_ROLE_SWITCHING_LABEL,
    MAX_UNDO_STEPS,
    MFA_REQUIRED_ROLES,
    MFA_REQUIRED_TRANSITIONS,
    ROLE_COLORS,
    ROLE_ICONS,
    ROLE_NAMES_RU,
    STATUS_COLORS,
    STATUS_NAMES_RU,
    UNDO_REDO_ICONS,
)

# Events (A6)
from src.gui.workflow.events import (
    CommentEvent,
    MFAChallengeEvent,
    RoleChangeEvent,
    StateTransitionEvent,
    UndoRedoEvent,
    WorkflowErrorEvent,
    WorkflowEventBus,
    WorkflowUIEvent,
    create_transition_event,
)

# Base components (existing)
from src.gui.workflow.field_comment_widget import (
    Comment,
    FieldCommentWidget,
)
from src.gui.workflow.field_comment_widget import Role as Role
from src.gui.workflow.field_comment_widget import Severity as Severity

# MFA checker (A5)
from src.gui.workflow.mfa_checker import (
    MFAOperationDescriber,
    MFARequirementChecker,
)

# Protocols (A1)
from src.gui.workflow.protocols import (
    WorkflowStateListener,
    WorkflowTransitionResult,
    WorkflowUIProtocol,
)

# Snapshot (A2)
from src.gui.workflow.snapshot import (
    SnapshotManager,
    SnapshotMetadata,
    TransitionSnapshot,
)

# State Manager (B1)
from src.gui.workflow.state_manager import (
    TransitionRequest,
    TransitionResult,
    WorkflowStateManager,
)

# Transition Command (B2)
from src.gui.workflow.transition_command import (
    WorkflowCommandFactory,
    WorkflowCommandHistory,
    WorkflowTransitionCommand,
)

# Undo/Redo menu (A4)
from src.gui.workflow.undo_redo_menu import (
    UndoRedoMenuItems,
    UndoRedoToolbarButtons,
)

# Workflow Manager (B4)
from src.gui.workflow.workflow_manager import (
    ROLE_ACTIONS,
    STATE_ACTIONS,
    WorkflowManager,
)

# Workflow Toolbar (B3)
from src.gui.workflow.workflow_toolbar import (
    WorkflowToolbar,
)
from src.gui.workflow.workflow_annotation_panel import (
    AnnotationStatus,
    AnnotationType,
    OnAddAnnotationCallback,
    OnReplyAnnotationCallback,
    OnResolveAnnotationCallback,
    WorkflowAnnotation,
    WorkflowAnnotationPanel,
)

__all__ = [
    # Base components
    "FieldCommentWidget",
    "Comment",
    "Severity",
    "Role",
    # Protocols
    "WorkflowUIProtocol",
    "WorkflowStateListener",
    "WorkflowTransitionResult",
    # Snapshot
    "TransitionSnapshot",
    "SnapshotMetadata",
    "SnapshotManager",
    # Constants
    "STATUS_COLORS",
    "ROLE_COLORS",
    "ROLE_ICONS",
    "STATUS_NAMES_RU",
    "ROLE_NAMES_RU",
    "MFA_REQUIRED_TRANSITIONS",
    "MFA_REQUIRED_ROLES",
    "UNDO_REDO_ICONS",
    "MAX_UNDO_STEPS",
    "ARCHIVED_CONFIRMATION_TEXT",
    "FREE_ROLE_SWITCHING_LABEL",
    # Undo/Redo
    "UndoRedoMenuItems",
    "UndoRedoToolbarButtons",
    # MFA
    "MFARequirementChecker",
    "MFAOperationDescriber",
    # Events
    "WorkflowUIEvent",
    "StateTransitionEvent",
    "UndoRedoEvent",
    "RoleChangeEvent",
    "MFAChallengeEvent",
    "CommentEvent",
    "WorkflowErrorEvent",
    "WorkflowEventBus",
    "create_transition_event",
    # Command
    "WorkflowTransitionCommand",
    "WorkflowCommandFactory",
    "WorkflowCommandHistory",
    # State Manager
    "WorkflowStateManager",
    "TransitionRequest",
    "TransitionResult",
    # Workflow Toolbar
    "WorkflowToolbar",
    # Workflow Manager
    "WorkflowManager",
    "ROLE_ACTIONS",
    "STATE_ACTIONS",
    # Workflow Annotation Panel
    "WorkflowAnnotationPanel",
    "WorkflowAnnotation",
    "AnnotationType",
    "AnnotationStatus",
    "OnAddAnnotationCallback",
    "OnResolveAnnotationCallback",
    "OnReplyAnnotationCallback",
]
