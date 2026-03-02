"""
Общие fixtures для тестов crypto advanced модулей.

Предоставляет переиспользуемые тестовые данные и моки.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_plaintext() -> bytes:
    """Типичный plaintext для тестов шифрования."""
    return b"This is a test message for encryption."


@pytest.fixture
def large_plaintext() -> bytes:
    """Большой plaintext для тестов производительности."""
    return b"X" * 100000  # 100KB


@pytest.fixture
def unicode_plaintext() -> bytes:
    """Unicode plaintext для тестов кодировок."""
    return "Привет, мир! 日本語 🚀".encode("utf-8")


@pytest.fixture
def empty_plaintext() -> bytes:
    """Пустой plaintext для негативных тестов."""
    return b""
