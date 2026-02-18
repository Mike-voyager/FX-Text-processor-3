"""
UI-вспомогательные функции для криптографического модуля.

Набор функций для форматирования и отображения информации об алгоритмах
в пользовательском интерфейсе (Tkinter). Использует метаданные из
AlgorithmRegistry для генерации читаемых описаний, значков и рекомендаций.

Основные функции:
    get_security_badge()         — Эмодзи-значок уровня безопасности
    get_floppy_badge()           — Эмодзи-значок пригодности для дискет
    format_algorithm_info()      — Полное описание алгоритма для UI
    format_algorithm_short()     — Краткое описание для выпадающего списка
    list_recommended_algorithms() — Рекомендуемые алгоритмы по категории
    get_algorithm_warning()      — Предупреждение для небезопасных алгоритмов

Example:
    >>> from src.security.crypto.service.ui_helpers import (
    ...     get_security_badge, list_recommended_algorithms
    ... )
    >>> from src.security.crypto.core.registry import AlgorithmRegistry
    >>> registry = AlgorithmRegistry.get_instance()
    >>> meta = registry.get_metadata("aes-256-gcm")
    >>> get_security_badge(meta)
    '✅'
    >>> list_recommended_algorithms("symmetric")
    ['aes-256-gcm', 'chacha20-poly1305', 'aes-256-gcm-siv']

Version: 1.0
Date: February 17, 2026
Priority: Phase 7 — Service Layer
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    AlgorithmMetadata,
    FloppyFriendly,
    ImplementationStatus,
    SecurityLevel,
)
from src.security.crypto.core.registry import AlgorithmRegistry

__all__ = [
    "get_security_badge",
    "get_floppy_badge",
    "get_status_badge",
    "format_algorithm_info",
    "format_algorithm_short",
    "list_recommended_algorithms",
    "get_algorithm_warning",
    "format_key_sizes",
    "get_profile_summary",
]

logger = logging.getLogger(__name__)

# Максимальный размер ключа для floppy-friendly (байт)
_FLOPPY_EXCELLENT_THRESHOLD = 100
_FLOPPY_ACCEPTABLE_THRESHOLD = 1000


# ==============================================================================
# BADGE FUNCTIONS
# ==============================================================================


def get_security_badge(metadata: AlgorithmMetadata) -> str:
    """
    Получить эмодзи-значок уровня безопасности алгоритма.

    Args:
        metadata: Метаданные алгоритма из AlgorithmRegistry

    Returns:
        Эмодзи для отображения в UI:
        ⛔ — BROKEN (не использовать),
        ⚠️  — LEGACY (только совместимость),
        ✅ — STANDARD (рекомендуется),
        🏆 — HIGH (повышенная безопасность),
        🛡️  — QUANTUM_RESISTANT (постквантовый)

    Example:
        >>> registry = AlgorithmRegistry.get_instance()
        >>> meta = registry.get_metadata("aes-256-gcm")
        >>> get_security_badge(meta)
        '✅'
        >>> meta_des = registry.get_metadata("des")
        >>> get_security_badge(meta_des)
        '⛔'
    """
    return metadata.security_level.emoji()


def get_floppy_badge(metadata: AlgorithmMetadata) -> str:
    """
    Получить эмодзи-значок пригодности алгоритма для дискет 3.5".

    Args:
        metadata: Метаданные алгоритма

    Returns:
        Эмодзи для отображения в UI:
        💚 — EXCELLENT (< 100 байт overhead),
        💛 — ACCEPTABLE (100–1000 байт overhead),
        ❌ — POOR (> 1000 байт overhead)

    Example:
        >>> meta = registry.get_metadata("Ed25519")
        >>> get_floppy_badge(meta)
        '💚'
        >>> meta_pqc = registry.get_metadata("ML-DSA-65")
        >>> get_floppy_badge(meta_pqc)
        '❌'
    """
    _badges: Dict[FloppyFriendly, str] = {
        FloppyFriendly.EXCELLENT: "💚",
        FloppyFriendly.ACCEPTABLE: "💛",
        FloppyFriendly.POOR: "❌",
    }
    return _badges[metadata.floppy_friendly]


def get_status_badge(metadata: AlgorithmMetadata) -> str:
    """
    Получить эмодзи-значок статуса реализации алгоритма.

    Args:
        metadata: Метаданные алгоритма

    Returns:
        Эмодзи статуса:
        ✅ — STABLE,
        🧪 — EXPERIMENTAL,
        ⚠️  — DEPRECATED,
        ❌ — BROKEN

    Example:
        >>> meta = registry.get_metadata("aes-256-gcm")
        >>> get_status_badge(meta)
        '✅'
    """
    _badges: Dict[ImplementationStatus, str] = {
        ImplementationStatus.STABLE: "✅",
        ImplementationStatus.EXPERIMENTAL: "🧪",
        ImplementationStatus.DEPRECATED: "⚠️",
    }
    return _badges.get(metadata.status, "❓")


# ==============================================================================
# FORMAT FUNCTIONS
# ==============================================================================


def format_algorithm_short(metadata: AlgorithmMetadata) -> str:
    """
    Краткое описание алгоритма для выпадающего списка (Combobox).

    Формат: «<значок> <name> — <описание>»

    Args:
        metadata: Метаданные алгоритма

    Returns:
        Строка вида «✅ AES-256-GCM — AES-256 в режиме GCM»

    Example:
        >>> meta = registry.get_metadata("aes-256-gcm")
        >>> format_algorithm_short(meta)
        '✅ AES-256-GCM — AES-256 в режиме Galois/Counter Mode'
    """
    badge = get_security_badge(metadata)
    name = metadata.name
    desc = metadata.description_ru or metadata.description_en or ""
    if desc:
        return f"{badge} {name} — {desc}"
    return f"{badge} {name}"


def format_algorithm_info(metadata: AlgorithmMetadata) -> str:
    """
    Полное описание алгоритма для всплывающей подсказки или панели деталей.

    Включает все характеристики: безопасность, размеры ключей, дискетный
    рейтинг, статус, библиотеку и рекомендуемые сценарии.

    Args:
        metadata: Метаданные алгоритма

    Returns:
        Многострочный текст с полным описанием алгоритма

    Example:
        >>> meta = registry.get_metadata("Ed25519")
        >>> print(format_algorithm_info(meta))
        ✅ Ed25519
        Категория: Цифровая подпись
        Безопасность: Стандартный ✅
        Дискета: Отлично 💚
        ...
    """
    lines: List[str] = []

    # Заголовок
    badge = get_security_badge(metadata)
    lines.append(f"{badge} {metadata.name}")
    lines.append("")

    # Категория
    lines.append(f"Категория: {metadata.category.label()}")

    # Безопасность
    sec_label = metadata.security_level.label()
    sec_emoji = metadata.security_level.emoji()
    lines.append(f"Безопасность: {sec_label} {sec_emoji}")

    # Дискета
    floppy_label = metadata.floppy_friendly.label()
    floppy_emoji = get_floppy_badge(metadata)
    lines.append(f"Дискета: {floppy_label} {floppy_emoji}")

    # Статус
    status_emoji = get_status_badge(metadata)
    lines.append(f"Статус: {metadata.status.value} {status_emoji}")

    # Размеры ключей (если применимо)
    key_info = format_key_sizes(metadata)
    if key_info:
        lines.append("")
        lines.append("Размеры:")
        lines.append(key_info)

    # Флаги
    flags: List[str] = []
    if metadata.is_aead:
        flags.append("AEAD (аутентифицированное шифрование)")
    if metadata.is_post_quantum:
        flags.append("Post-Quantum (квантово-устойчивый)")
    if flags:
        lines.append("")
        for flag in flags:
            lines.append(f"  • {flag}")

    # Описание
    desc = metadata.description_ru or metadata.description_en
    if desc:
        lines.append("")
        lines.append(desc)

    # Сценарии использования
    if metadata.use_cases:
        lines.append("")
        lines.append("Применение:")
        for use_case in metadata.use_cases:
            lines.append(f"  • {use_case}")

    # Библиотека
    lines.append("")
    lines.append(f"Библиотека: {metadata.library}")

    # Предупреждение если небезопасный
    warning = get_algorithm_warning(metadata)
    if warning:
        lines.append("")
        lines.append(f"⚠️  ВНИМАНИЕ: {warning}")

    return "\n".join(lines)


def format_key_sizes(metadata: AlgorithmMetadata) -> str:
    """
    Форматировать информацию о размерах ключей/подписей.

    Args:
        metadata: Метаданные алгоритма

    Returns:
        Строка с размерами (пустая если нет применимых данных)

    Example:
        >>> meta = registry.get_metadata("Ed25519")
        >>> format_key_sizes(meta)
        '  Публичный ключ: 32 байт\\n  Приватный ключ: 32 байт\\n  Подпись: 64 байт'
    """
    parts: List[str] = []

    if metadata.key_size is not None:
        parts.append(f"  Ключ: {metadata.key_size} байт")
    if metadata.public_key_size is not None:
        parts.append(f"  Публичный ключ: {metadata.public_key_size} байт")
    if metadata.private_key_size is not None:
        parts.append(f"  Приватный ключ: {metadata.private_key_size} байт")
    if metadata.signature_size is not None:
        parts.append(f"  Подпись: {metadata.signature_size} байт")
    if metadata.nonce_size is not None:
        parts.append(f"  Nonce/IV: {metadata.nonce_size} байт")
    if metadata.digest_size is not None:
        parts.append(f"  Дайджест: {metadata.digest_size} байт")
    if metadata.max_plaintext_size is not None:
        mb = metadata.max_plaintext_size / (1024 * 1024)
        parts.append(f"  Макс. данные: {mb:.0f} MB")

    return "\n".join(parts)


# ==============================================================================
# RECOMMENDATION FUNCTIONS
# ==============================================================================


def list_recommended_algorithms(
    category: str,
    *,
    floppy_mode: bool = False,
    post_quantum: bool = False,
    include_legacy: bool = False,
) -> List[str]:
    """
    Список рекомендуемых алгоритмов для заданной категории.

    Алгоритмы отсортированы по приоритету (stable > experimental,
    затем по уровню безопасности). Legacy и broken исключаются если
    include_legacy=False.

    Args:
        category: Категория алгоритма — одно из:
            "symmetric", "signing", "asymmetric", "kex", "hash", "kdf"
        floppy_mode: Предпочитать алгоритмы с FloppyFriendly.EXCELLENT
        post_quantum: Предпочитать постквантовые алгоритмы
        include_legacy: Включить LEGACY и BROKEN алгоритмы

    Returns:
        Список registry ID алгоритмов в порядке рекомендации

    Raises:
        ValueError: Неизвестная категория

    Example:
        >>> list_recommended_algorithms("symmetric")
        ['aes-256-gcm', 'chacha20-poly1305', 'aes-256-gcm-siv', ...]

        >>> list_recommended_algorithms("signing", floppy_mode=True)
        ['Ed25519', 'Ed448', 'ECDSA-P256', ...]

        >>> list_recommended_algorithms("signing", post_quantum=True)
        ['ML-DSA-65', 'ML-DSA-44', 'ML-DSA-87', 'Ed25519', ...]
    """
    _category_map: Dict[str, AlgorithmCategory] = {
        "symmetric": AlgorithmCategory.SYMMETRIC_CIPHER,
        "signing": AlgorithmCategory.SIGNATURE,
        "asymmetric": AlgorithmCategory.ASYMMETRIC_ENCRYPTION,
        "kex": AlgorithmCategory.KEY_EXCHANGE,
        "hash": AlgorithmCategory.HASH,
        "kdf": AlgorithmCategory.KDF,
    }

    if category not in _category_map:
        raise ValueError(
            f"Неизвестная категория: '{category}'. "
            f"Допустимые значения: {list(_category_map.keys())}"
        )

    algo_category = _category_map[category]
    registry = AlgorithmRegistry.get_instance()
    all_names = registry.list_algorithms()

    result: List[str] = []
    for name in all_names:
        try:
            meta = registry.get_metadata(name)
        except Exception:
            continue

        if meta.category != algo_category:
            continue

        # Исключить BROKEN всегда
        if meta.security_level == SecurityLevel.BROKEN:
            continue

        # Исключить LEGACY если не запрошено
        if not include_legacy and meta.security_level == SecurityLevel.LEGACY:
            continue

        # Исключить DEPRECATED если не запрошено
        if not include_legacy and meta.status == ImplementationStatus.DEPRECATED:
            continue

        result.append(name)

    # Сортировка: stable > experimental, затем по приоритетам
    def _sort_key(name: str) -> tuple:  # type: ignore[type-arg]
        try:
            meta = registry.get_metadata(name)
        except Exception:
            return (99, 99, 99, name)

        # 0 = stable, 1 = experimental, 2 = deprecated
        status_order = {
            ImplementationStatus.STABLE: 0,
            ImplementationStatus.EXPERIMENTAL: 1,
            ImplementationStatus.DEPRECATED: 2,
        }.get(meta.status, 9)

        # Floppy: excellent=0, acceptable=1, poor=2
        floppy_order = meta.floppy_friendly.value - 1  # 0,1,2

        # PQC: если post_quantum=True, PQC алгоритмы идут первыми
        pqc_order: int
        if post_quantum:
            pqc_order = 0 if meta.is_post_quantum else 1
        else:
            pqc_order = 0 if not meta.is_post_quantum else 1

        # Security level priority (higher = better = lower number in sort)
        sec_order = {
            SecurityLevel.QUANTUM_RESISTANT: 0,
            SecurityLevel.HIGH: 1,
            SecurityLevel.STANDARD: 2,
            SecurityLevel.LEGACY: 3,
            SecurityLevel.BROKEN: 4,
        }.get(meta.security_level, 9)

        if floppy_mode:
            return (status_order, pqc_order, floppy_order, sec_order, name)
        else:
            return (status_order, pqc_order, sec_order, floppy_order, name)

    result.sort(key=_sort_key)
    return result


def get_algorithm_warning(metadata: AlgorithmMetadata) -> Optional[str]:
    """
    Получить строку предупреждения для небезопасного/устаревшего алгоритма.

    Args:
        metadata: Метаданные алгоритма

    Returns:
        Строка предупреждения или None если алгоритм безопасен

    Example:
        >>> meta_des = registry.get_metadata("des")
        >>> get_algorithm_warning(meta_des)
        'DES взломан. Не используйте для новых систем. Только для legacy-расшифровки.'

        >>> meta_aes = registry.get_metadata("aes-256-gcm")
        >>> get_algorithm_warning(meta_aes) is None
        True
    """
    if metadata.security_level == SecurityLevel.BROKEN:
        return (
            f"{metadata.name} является взломанным алгоритмом. "
            "НЕ используйте для защиты данных. "
            "Допустимо только для legacy-расшифровки старых данных."
        )

    if metadata.security_level == SecurityLevel.LEGACY:
        return (
            f"{metadata.name} — устаревший алгоритм. "
            "Используйте только для совместимости со старыми системами. "
            "Мигрируйте на современные алгоритмы при первой возможности."
        )

    if metadata.status == ImplementationStatus.DEPRECATED:
        return (
            f"{metadata.name} помечен как DEPRECATED. "
            "Переходите на рекомендуемую замену."
        )

    if metadata.status == ImplementationStatus.EXPERIMENTAL:
        return (
            f"{metadata.name} — экспериментальный алгоритм. "
            "Не рекомендуется для production использования."
        )

    return None


def get_profile_summary(profile_name: str) -> str:
    """
    Получить краткое текстовое описание профиля для UI.

    Args:
        profile_name: Имя профиля (значение CryptoProfile, например "standard")

    Returns:
        Строка с описанием профиля и его ключевыми алгоритмами

    Example:
        >>> get_profile_summary("standard")
        'Стандартный: AES-256-GCM + Ed25519 + X25519'
    """
    from src.security.crypto.service.profiles import CryptoProfile, get_profile_config

    try:
        profile = CryptoProfile(profile_name)
    except ValueError:
        return f"Неизвестный профиль: {profile_name}"

    config = get_profile_config(profile)
    label = profile.label()
    sym = config.symmetric_algorithm.upper()
    sig = config.signing_algorithm
    kex = config.kex_algorithm.upper()

    pqc_tag = " [PQC]" if config.post_quantum else ""
    floppy_tag = " [💾]" if config.floppy_optimized else ""

    return f"{label}{pqc_tag}{floppy_tag}: {sym} + {sig} + {kex}"


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-17"
