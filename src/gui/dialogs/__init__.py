"""Диалоги FX Text Processor 3.

Модуль содержит все диалоги приложения:
- Файловые операции (open, save, print)
- Настройки (paper, profile)
- Безопасность (MFA, health check)
- Workflow (reject, timeline)
- Шаблоны (import, export)
- Штрих-коды (barcode, QR)
- Навигация (goto, bookmarks)

Example:
    >>> from src.gui.dialogs import MFAVerificationDialog, TemplateImportDialog
    >>> dialog = MFAVerificationDialog(parent, auth_controller)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

# Setup dialogs
from src.gui.dialogs.auto_lock_settings_dialog import (
    AutoLockSettingsDialog,
    AutoLockSettingsResult,
)
from src.gui.dialogs.backup_codes_dialog import (
    BackupCodeDisplay,
    BackupCodesDialog,
)
from src.gui.dialogs.barcode_dialog import (
    BarcodeConflictDialog,
    BarcodeMode,
    BarcodeSelectionResult,
    BarcodeSettings,
    BarcodeSettingsPanel,
    BarcodeTypeSelector,
)

# Barcode dialogs (NEW - separated into individual modules)
from src.gui.dialogs.calendar_dialog import CalendarDialog

# File dialogs
from src.gui.dialogs.confirm_dialog import SaveChangesDialog
from src.gui.dialogs.crypto_profile_dialog import (
    CryptoProfileDialog,
    ProfileSelectionResult,
)
from src.gui.dialogs.fido2_setup_dialog import FIDO2SetupDialog

# Utility dialogs
from src.gui.dialogs.find_replace_dialog import FindReplaceDialog
from src.gui.dialogs.floppy_optimizer_dialog import (
    FloppyOptimizerDialog,
    OptimizationOptions,
)
from src.gui.dialogs.health_check_dialog import HealthCheckDialog
from src.gui.dialogs.integrity_dialog import IntegrityDialog

# Security dialogs
from src.gui.dialogs.mfa_verification_dialog import MFAVerificationDialog

# Navigation dialogs
from src.gui.dialogs.navigation_dialogs import (
    BookmarkItem,
    BookmarksDialog,
    GotoDialog,
)
from src.gui.dialogs.open_dialog import OpenFileDialog

# Paper dialogs
from src.gui.dialogs.paper_profile_dialog import PaperProfileDialog
from src.gui.dialogs.paper_setup import PaperSetupDialog
from src.gui.dialogs.print_dialog import PrintDialog
from src.gui.dialogs.print_preview_dialog import PrintPreviewDialog
from src.gui.dialogs.print_settings import PrintDialogResult, PrintSettings
from src.gui.dialogs.qr_code_dialog import (
    QRCodeResult,
    QRCodeSettings,
    QRCodeSettingsDialog,
)

# Workflow dialogs
from src.gui.dialogs.reject_dialog import RejectDialog
from src.gui.dialogs.role_switch_dialog import RoleSwitchDialog
from src.gui.dialogs.save_dialog import SaveFileDialog
from src.gui.dialogs.security_health_check_dialog import SecurityHealthCheckDialog
from src.gui.dialogs.special_character_dialog import (
    SpecialCharacterDialog,
    SpecialCharResult,
)

# Template dialogs
from src.gui.dialogs.template_export_dialog import (
    ExportResult,
    TemplateExportDialog,
)
from src.gui.dialogs.template_import_dialog import (
    ImportResult,
    TemplateImportDialog,
    TemplatePreviewPanel,
)
from src.gui.dialogs.template_preview_panel import TemplatePreviewWidget
from src.gui.dialogs.totp_setup_dialog import TOTPSetupDialog
from src.gui.dialogs.transition_dialog import TransitionDialog
from src.gui.dialogs.trust_chain_dialog import (
    STATUS_EMOJIS,
    STATUS_TO_TAG,
    TrustChainDialog,
    TrustChainDisplayHelper,
    TrustChainVerificationDialog,  # backward compatibility alias
)
from src.gui.dialogs.workflow_dialogs import (
    AddCommentDialog,
    CommentData,
    CrossDocumentLookupPanel,
    PrefillDialog,
)
from src.gui.dialogs.workflow_timeline_dialog import WorkflowTimelineDialog

__all__: list[str] = [
    # Calendar dialog
    "CalendarDialog",
    # File dialogs
    "SaveChangesDialog",
    "OpenFileDialog",
    "SaveFileDialog",
    "PrintDialog",
    "PrintPreviewDialog",
    "PrintSettings",
    "PrintDialogResult",
    # Security dialogs
    "MFAVerificationDialog",
    "HealthCheckDialog",
    "IntegrityDialog",
    "SecurityHealthCheckDialog",
    # Setup dialogs
    "AutoLockSettingsDialog",
    "AutoLockSettingsResult",
    "BackupCodesDialog",
    "BackupCodeDisplay",
    "CryptoProfileDialog",
    "ProfileSelectionResult",
    "FIDO2SetupDialog",
    "TOTPSetupDialog",
    # Workflow dialogs
    "RejectDialog",
    "WorkflowTimelineDialog",
    "AddCommentDialog",
    "CommentData",
    "CrossDocumentLookupPanel",
    "PrefillDialog",
    "RoleSwitchDialog",
    "TransitionDialog",
    # Paper dialogs
    "PaperProfileDialog",
    "PaperSetupDialog",
    # Template dialogs
    "TemplateExportDialog",
    "TemplateImportDialog",
    "TemplatePreviewPanel",
    "TemplatePreviewWidget",
    "ExportResult",
    "ImportResult",
    # Trust chain dialogs
    "TrustChainDialog",
    "TrustChainDisplayHelper",
    "TrustChainVerificationDialog",  # deprecated: use TrustChainDialog
    "STATUS_EMOJIS",
    "STATUS_TO_TAG",
    # Floppy optimizer dialogs
    "FloppyOptimizerDialog",
    "OptimizationOptions",
    # Barcode dialogs
    "BarcodeTypeSelector",
    "BarcodeSettingsPanel",
    "BarcodeSettings",
    "BarcodeMode",
    "BarcodeSelectionResult",
    "BarcodeConflictDialog",
    # QR code dialogs
    "QRCodeSettingsDialog",
    "QRCodeSettings",
    "QRCodeResult",
    # Navigation dialogs
    "GotoDialog",
    "BookmarksDialog",
    "BookmarkItem",
    # Special Character dialog
    "SpecialCharacterDialog",
    "SpecialCharResult",
    # Utility
    "FindReplaceDialog",
]
