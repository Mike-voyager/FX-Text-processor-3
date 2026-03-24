"""
Модуль аудита: неизменяемый журнал событий с хеш-цепочкой.

Реализует immutable audit log с криптографической защитой целостности
по схеме hash-chain: каждое событие содержит хеш предыдущего события.

Components:
    - AuditEventType: Перечисление типов событий
    - AuditEvent: Событие аудита
    - AuditLog: Неизменяемый журнал
    - verify_chain_integrity(): Проверка целостности цепочки

Security:
    - Все операции только append (добавление)
    - HMAC-SHA256 подпись каждого события
    - SHA3-256 хеш-цепочка
    - Невозможность удаления или модификации записей

Version: 1.0
Date: March 2026
Priority: 🔴 CRITICAL (Phase 1)
"""

from __future__ import annotations

from src.security.audit.events import AuditEventType
from src.security.audit.logger import AuditEvent, AuditLog, verify_chain_integrity

__all__: list[str] = [
    "AuditEventType",
    "AuditEvent",
    "AuditLog",
    "verify_chain_integrity",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-22"
