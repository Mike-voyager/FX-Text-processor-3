"""Сервисный слой приложения.

Содержит бизнес-логику, отделённую от Model (dataclasses).
Model — только данные, Service — операции над данными.

Модули:
    - barcode_service: Работа со штрихкодами
    - document_manager_service: MDI менеджер документов
    - command_history_service: Undo/Redo стек
    - auto_save_service: Автосохранение
    - notification_service: Toast уведомления

Фаза 2 (Document Operations):
    - clipboard_service: Буфер обмена
    - find_replace_service: Поиск и замена
    - document_stats_service: Статистика документа
    - document_lock_service: Защита от двойного открытия

Фаза 3 (Output Services):
    - print_queue_service: Очередь печати
    - export_service: Экспорт в PDF/HTML
    - batch_service: Пакетные операции

Фаза 4 (Advanced Services):
    - key_bindings_service: Горячие клавиши
    - version_history_service: История версий
    - index_search_service: Поиск по индексу
    - watermark_service: Водяные знаки
    - paper_format_service: Профили бумаги
"""

from src.services.auto_save_service import (
    AutoSaveCallback,
    AutoSaveConfig,
    AutoSaveErrorCallback,
    AutoSaveService,
    AutoSaveStats,
)
from src.services.barcode_service import BarcodeService
from src.services.batch_service import (
    BatchCallback,
    BatchItem,
    BatchOperation,
    BatchOperationType,
    BatchResult,
    BatchService,
    BatchStatus,
    ItemProcessor,
    ItemStatus,
)
from src.services.clipboard_service import (
    ClipboardBackendProtocol,
    ClipboardData,
    ClipboardEntry,
    ClipboardFormat,
    ClipboardService,
    CopyResult,
    PasteResult,
)
from src.services.command_history_service import (
    CommandHistory,
    CommandHistoryService,
    CommandProtocol,
    HistoryResult,
)
from src.services.document_lock_service import (
    LOCK_EXTENSION,
    LOCK_TIMEOUT_SECONDS,
    DocumentLockService,
    LockInfo,
    LockResult,
)
from src.services.document_manager_service import (
    AuditCallbackProtocol,
    CloseResult,
    CreateResult,
    DocumentLockProtocol,
    DocumentManagerService,
    OpenResult,
    SaveResult,
)
from src.services.document_stats_service import (
    CharacterStats,
    DocumentStats,
    DocumentStatsService,
    LineStats,
    PageStats,
    ParagraphStats,
    WordStats,
)
from src.services.export_service import (
    BatchExportResult,
    ExportCallback,
    ExportFormat,
    ExportOptions,
    ExportResult,
    ExportService,
    ExportStatus,
    RendererProtocol,
)
from src.services.find_replace_service import (
    FindReplaceService,
    Match,
    ReplaceResult,
    SearchDirection,
    SearchOptions,
    SearchResult,
    SearchScope,
)
from src.services.index_search_service import (
    IndexEntry,
    IndexSearchService,
    IndexStorage,
    SearchField,
    SearchOperator,
    SearchQuery,
    SearchResponse,
    SearchResult,
    SortOrder,
)

# Phase 4: Advanced Services
from src.services.key_bindings_service import (
    Action,
    BindingConflict,
    KeyBinding,
    KeyBindingsService,
    KeyContext,
    KeyModifier,
)
from src.services.notification_service import (
    DismissCallback,
    Notification,
    NotificationAction,
    NotificationCallback,
    NotificationPriority,
    NotificationService,
    NotificationType,
    ShowResult,
)
from src.services.paper_format_service import (
    Margins,
    Orientation,
    PaperFormatService,
    PaperProfile,
    PaperSize,
    PaperType,
    PrintableArea,
    TrayType,
)
from src.services.trust_chain_service import (
    ChainValidationError,
    InvalidSignatureError,
    KeyAlreadyExistsError,
    KeyEntry,
    KeyNotFoundError,
    TrustChainError,
    TrustChainService,
)

# Phase 3: Output Services
from src.services.print_queue_service import (
    PrinterAdapterProtocol,
    PrintJob,
    PrintJobStatus,
    PrintPriority,
    PrintQueueCallback,
    PrintQueueService,
    QueueStats,
)
from src.services.version_history_service import (
    DiffType,
    StorageBackend,
    VersionDiff,
    VersionHistoryService,
    VersionInfo,
    VersionSnapshot,
    VersionType,
)
from src.services.watermark_service import (
    ImageWatermark,
    PatternWatermark,
    TextStyle,
    TextWatermark,
    WatermarkBlendMode,
    WatermarkConfig,
    WatermarkPosition,
    WatermarkResult,
    WatermarkService,
    WatermarkType,
)

__all__ = [
    # Barcode
    "BarcodeService",
    # Document Manager
    "DocumentManagerService",
    "DocumentLockProtocol",
    "AuditCallbackProtocol",
    "CreateResult",
    "OpenResult",
    "CloseResult",
    "SaveResult",
    # Command History
    "CommandHistoryService",
    "CommandHistory",
    "CommandProtocol",
    "HistoryResult",
    # Auto Save
    "AutoSaveService",
    "AutoSaveConfig",
    "AutoSaveStats",
    "AutoSaveCallback",
    "AutoSaveErrorCallback",
    # Notifications
    "NotificationService",
    "Notification",
    "NotificationAction",
    "NotificationType",
    "NotificationPriority",
    "NotificationCallback",
    "DismissCallback",
    "ShowResult",
    # Clipboard
    "ClipboardService",
    "ClipboardData",
    "ClipboardEntry",
    "ClipboardFormat",
    "CopyResult",
    "PasteResult",
    "ClipboardBackendProtocol",
    # Find & Replace
    "FindReplaceService",
    "SearchOptions",
    "SearchDirection",
    "SearchScope",
    "Match",
    "SearchResult",
    "ReplaceResult",
    # Document Stats
    "DocumentStatsService",
    "DocumentStats",
    "CharacterStats",
    "WordStats",
    "ParagraphStats",
    "LineStats",
    "PageStats",
    # Document Lock
    "DocumentLockService",
    "LockInfo",
    "LockResult",
    "LOCK_EXTENSION",
    "LOCK_TIMEOUT_SECONDS",
    # Phase 3: Print Queue
    "PrintQueueService",
    "PrintJob",
    "PrintJobStatus",
    "PrintPriority",
    "QueueStats",
    "PrinterAdapterProtocol",
    "PrintQueueCallback",
    # Phase 3: Export
    "ExportService",
    "ExportFormat",
    "ExportStatus",
    "ExportOptions",
    "ExportResult",
    "BatchExportResult",
    "RendererProtocol",
    "ExportCallback",
    # Phase 3: Batch Operations
    "BatchService",
    "BatchOperation",
    "BatchOperationType",
    "BatchStatus",
    "BatchItem",
    "ItemStatus",
    "BatchResult",
    "BatchCallback",
    "ItemProcessor",
    # Phase 4: Key Bindings
    "KeyBindingsService",
    "KeyBinding",
    "KeyModifier",
    "KeyContext",
    "Action",
    "BindingConflict",
    # Phase 4: Version History
    "VersionHistoryService",
    "VersionInfo",
    "VersionType",
    "VersionDiff",
    "VersionSnapshot",
    "DiffType",
    "StorageBackend",
    # Phase 4: Index Search
    "IndexSearchService",
    "SearchQuery",
    "SearchResult",
    "SearchResponse",
    "SearchField",
    "SearchOperator",
    "SortOrder",
    "IndexEntry",
    "IndexStorage",
    # Phase 4: Watermark
    "WatermarkService",
    "WatermarkType",
    "WatermarkPosition",
    "WatermarkBlendMode",
    "TextStyle",
    "TextWatermark",
    "ImageWatermark",
    "PatternWatermark",
    "WatermarkConfig",
    "WatermarkResult",
    # Phase 4: Paper Format
    "PaperFormatService",
    "PaperProfile",
    "PaperSize",
    "Orientation",
    "PaperType",
    "TrayType",
    "Margins",
    "PrintableArea",
    # Trust Chain Service
    "TrustChainService",
    "TrustChainError",
    "KeyNotFoundError",
    "KeyAlreadyExistsError",
    "InvalidSignatureError",
    "ChainValidationError",
    "KeyEntry",
]
