"""Константы для workflow UI компонентов.

Централизованное хранение всех констант, используемых
в workflow-related компонентах.

Version: 1.0
Date: April 2026
"""

from typing import TYPE_CHECKING, Dict, Final, Set, Tuple

if TYPE_CHECKING:
    pass


# =============================================================================
# ЦВЕТА СОСТОЯНИЙ (Status Colors)
# =============================================================================

STATUS_COLORS: Final[Dict[str, str]] = {
    "draft": "#95a5a6",  # Gray - Черновик
    "filled": "#3498db",  # Blue - Заполнена
    "validated": "#f39c12",  # Orange - Проверена
    "approved": "#2ecc71",  # Green - Утверждена
    "signed": "#27ae60",  # Green - Подписана
    "printed": "#9b59b6",  # Purple - Напечатана
    "archived": "#2c3e50",  # Dark Blue - Архивирована
    "rejected": "#e74c3c",  # Red - Отклонена
}

STATUS_COLORS_LIGHT: Final[Dict[str, str]] = {
    "draft": "#bdc3c7",
    "filled": "#85c1e9",
    "validated": "#f8c471",
    "approved": "#82e0aa",
    "signed": "#7dcea0",
    "printed": "#bb8fce",
    "archived": "#5d6d7e",
    "rejected": "#ec7063",
}


# =============================================================================
# ЦВЕТА РОЛЕЙ (Role Colors)
# =============================================================================

ROLE_COLORS: Final[Dict[str, str]] = {
    "operator": "#3498db",  # Blue - Оператор
    "editor": "#2ecc71",  # Green - Редактор
    "supervisor": "#f39c12",  # Orange - Супервайзер
    "signatory": "#e74c3c",  # Red - Подписант
}

ROLE_COLORS_LIGHT: Final[Dict[str, str]] = {
    "operator": "#85c1e9",
    "editor": "#82e0aa",
    "supervisor": "#f8c471",
    "signatory": "#ec7063",
}


# =============================================================================
# ИКОНКИ РОЛЕЙ (Role Icons)
# =============================================================================

ROLE_ICONS: Final[Dict[str, str]] = {
    "operator": "👤",
    "editor": "✏️",
    "supervisor": "👁️",
    "signatory": "🔏",
}


# =============================================================================
# ЛОКАЛИЗОВАННЫЕ НАЗВАНИЯ (Localized Names)
# =============================================================================

STATUS_NAMES_RU: Final[Dict[str, str]] = {
    "draft": "Черновик",
    "filled": "Заполнена",
    "validated": "Проверена",
    "approved": "Утверждена",
    "signed": "Подписана",
    "printed": "Напечатана",
    "archived": "Архивирована",
    "rejected": "Отклонена",
}

ROLE_NAMES_RU: Final[Dict[str, str]] = {
    "operator": "Оператор",
    "editor": "Редактор",
    "supervisor": "Супервайзер",
    "signatory": "Подписант",
}


# =============================================================================
# MFA ТРЕБОВАНИЯ (MFA Requirements)
# =============================================================================

# Переходы, требующие MFA (from_state, to_state)
MFA_REQUIRED_TRANSITIONS: Final[Set[Tuple[str, str]]] = {
    ("filled", "validated"),
    ("validated", "approved"),
    ("approved", "signed"),
    ("signed", "archived"),
    ("validated", "filled"),  # Откат
    ("approved", "validated"),  # Откат
    ("signed", "approved"),  # Откат
}

# Роли, всегда требующие MFA для любых действий
MFA_REQUIRED_ROLES: Final[Set[str]] = {
    "supervisor",
    "signatory",
}


# =============================================================================
# UNDO/REDO (Undo/Redo Settings)
# =============================================================================

UNDO_REDO_ICONS: Final[Dict[str, str]] = {
    "undo": "↶",
    "redo": "↷",
}

UNDO_REDO_SHORTCUTS: Final[Dict[str, str]] = {
    "undo": "Ctrl+Z",
    "redo": "Ctrl+Y",
}

MAX_UNDO_STEPS: Final[int] = 50
MAX_SNAPSHOTS_PER_DOCUMENT: Final[int] = 100

# Состояния, для которых undo невозможен
NON_UNDOABLE_STATES: Final[Set[str]] = {
    "archived",  # Терминальное состояние
}


# =============================================================================
# ARCHIVED ПОДТВЕРЖДЕНИЕ (Archived Confirmation)
# =============================================================================

ARCHIVED_CONFIRMATION_TEXT: Final[str] = "ARCHIVE"
ARCHIVED_WARNING_MESSAGE: Final[str] = (
    "Вы собираетесь перевести документ в статус АРХИВИРОВАН. "
    "Это необратимое действие! Документ будет заблокирован для редактирования."
)
ARCHIVED_CONFIRMATION_PROMPT: Final[str] = 'Для подтверждения введите: "{}"'.format(
    ARCHIVED_CONFIRMATION_TEXT
)


# =============================================================================
# РАЗМЕРЫ UI (UI Dimensions)
# =============================================================================

DIALOG_WIDTH: Final[int] = 500
DIALOG_HEIGHT: Final[int] = 450
MIN_DIALOG_WIDTH: Final[int] = 400
MIN_DIALOG_HEIGHT: Final[int] = 350

STATUS_CIRCLE_SIZE: Final[int] = 40
CONNECTOR_HEIGHT: Final[int] = 4
PADDING_SMALL: Final[int] = 5
PADDING_NORMAL: Final[int] = 10
PADDING_LARGE: Final[int] = 15


# =============================================================================
# ПОРЯДОК СОСТОЯНИЙ (Status Order)
# =============================================================================

STATUS_ORDER: Final[list[str]] = [
    "draft",
    "filled",
    "validated",
    "approved",
    "signed",
    "archived",
]


# =============================================================================
# СВОБОДНОЕ ПЕРЕКЛЮЧЕНИЕ РОЛЕЙ (Free Role Switching)
# =============================================================================

FREE_ROLE_SWITCHING_LABEL: Final[str] = "Свободное переключение ролей"
FREE_ROLE_SWITCHING_DESCRIPTION: Final[str] = "(все переключения требуют MFA)"
FREE_ROLE_SWITCHING_TOOLTIP: Final[str] = (
    "В режиме свободного переключения MFA требуется для смены на любую роль"
)


__all__ = [
    # Colors
    "STATUS_COLORS",
    "STATUS_COLORS_LIGHT",
    "ROLE_COLORS",
    "ROLE_COLORS_LIGHT",
    # Icons
    "ROLE_ICONS",
    # Names
    "STATUS_NAMES_RU",
    "ROLE_NAMES_RU",
    # MFA
    "MFA_REQUIRED_TRANSITIONS",
    "MFA_REQUIRED_ROLES",
    # Undo/Redo
    "UNDO_REDO_ICONS",
    "UNDO_REDO_SHORTCUTS",
    "MAX_UNDO_STEPS",
    "MAX_SNAPSHOTS_PER_DOCUMENT",
    "NON_UNDOABLE_STATES",
    # Archived
    "ARCHIVED_CONFIRMATION_TEXT",
    "ARCHIVED_WARNING_MESSAGE",
    "ARCHIVED_CONFIRMATION_PROMPT",
    # UI
    "DIALOG_WIDTH",
    "DIALOG_HEIGHT",
    "MIN_DIALOG_WIDTH",
    "MIN_DIALOG_HEIGHT",
    "STATUS_CIRCLE_SIZE",
    "CONNECTOR_HEIGHT",
    "PADDING_SMALL",
    "PADDING_NORMAL",
    "PADDING_LARGE",
    # Order
    "STATUS_ORDER",
    # Free role switching
    "FREE_ROLE_SWITCHING_LABEL",
    "FREE_ROLE_SWITCHING_DESCRIPTION",
    "FREE_ROLE_SWITCHING_TOOLTIP",
]
