"""Панели FX Text Processor 3.

Модуль содержит панели приложения:
- CrossDocumentLookupPanel — поиск значений полей по иерархии документов
- CrossDocumentLookupDialog — модальный диалог cross-document lookup

Example:
    >>> from src.gui.panels import CrossDocumentLookupPanel
    >>> panel = CrossDocumentLookupPanel(
    ...     parent=parent_frame,
    ...     document_service=doc_service,
    ...     current_index="DVN-44-K53-X",
    ...     on_value_selected=lambda fid, val: print(f"Selected {fid}={val}")
    ... )

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

from src.gui.panels.cross_document_lookup import (
    CACHE_SIZE_LIMIT,
    CACHE_TTL_SECONDS,
    MAX_RESULTS,
    CacheEntry,
    CrossDocumentLookupDialog,
    CrossDocumentLookupPanel,
    DocumentServiceProtocol,
    FieldValueResult,
    HierarchyLevel,
    SearchCriteria,
    ValueSelectedCallback,
    show_lookup_dialog,
)

# Alias для обратной совместимости и краткости
CrossDocumentLookup = CrossDocumentLookupPanel

__all__ = [
    "CACHE_SIZE_LIMIT",
    "CACHE_TTL_SECONDS",
    "MAX_RESULTS",
    "CacheEntry",
    "CrossDocumentLookup",
    "CrossDocumentLookupDialog",
    "CrossDocumentLookupPanel",
    "DocumentServiceProtocol",
    "FieldValueResult",
    "HierarchyLevel",
    "SearchCriteria",
    "ValueSelectedCallback",
    "show_lookup_dialog",
]
