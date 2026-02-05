# -*- coding: utf-8 -*-
"""
RU: BLAKE3 высокоскоростное хеширование - в 10× быстрее SHA-256.
EN: BLAKE3 high-performance hashing - 10× faster than SHA-256.

Features:
- Parallel hashing (multi-threaded)
- Can be used as KDF, MAC, PRF
- Configurable output length
- SIMD-optimized
"""
from __future__ import annotations

import logging
from typing import Final, Optional

_LOGGER: Final = logging.getLogger(__name__)

try:
    import blake3
    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False
    _LOGGER.warning("blake3 not available - install with: pip install blake3")


def compute_hash_blake3(data: bytes, length: int = 32) -> str:
    """
    Compute BLAKE3 hash with configurable output length.
    
    Args:
        data: bytes to hash.
        length: output length in bytes (default 32 = 256 bits).
    
    Returns:
        Hexadecimal hash string.
    
    Raises:
        ImportError: if blake3 not installed.
    
    Examples:
        >>> compute_hash_blake3(b"hello")
        'ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f'
        
        >>> compute_hash_blake3(b"hello", length=64)  # 512-bit output
        '...'
    """
    if not BLAKE3_AVAILABLE:
        raise ImportError("blake3 not available")
    
    hasher = blake3.blake3(data)
    return hasher.digest(length).hex()


def blake3_derive_key(
    context: str, 
    key_material: bytes, 
    length: int = 32
) -> bytes:
    """
    Key derivation via BLAKE3.
    
    Args:
        context: domain separation context string.
        key_material: input key material.
        length: output key length in bytes.
    
    Returns:
        Derived key bytes.
    
    Examples:
        >>> master = b"\\x00" * 32
        >>> doc_key = blake3_derive_key("document-encryption", master)
        >>> api_key = blake3_derive_key("api-tokens", master)
        >>> # doc_key and api_key are cryptographically independent
    """
    if not BLAKE3_AVAILABLE:
        raise ImportError("blake3 not available")
    
    return blake3.blake3(key_material, derive_key_context=context).digest(length)


def hmac_blake3(key: bytes, message: bytes, length: int = 32) -> bytes:
    """
    Fast MAC using BLAKE3 keyed mode.
    
    10× faster than HMAC-SHA256 for large messages.
    
    Args:
        key: MAC key (32 bytes recommended).
        message: message to authenticate.
        length: MAC length in bytes.
    
    Returns:
        MAC tag bytes.
    
    Examples:
        >>> key = b"\\x00" * 32
        >>> mac = hmac_blake3(key, b"message")
        >>> # Verify
        >>> mac2 = hmac_blake3(key, b"message")
        >>> assert mac == mac2
    """
    if not BLAKE3_AVAILABLE:
        raise ImportError("blake3 not available")
    
    if len(key) < 16:
        raise ValueError("BLAKE3 key must be >= 16 bytes")
    
    return blake3.blake3(message, key=key).digest(length)


def blake3_hash_file(filepath: str, chunk_size: int = 1024*1024) -> str:
    """
    Hash large file with BLAKE3 (streaming mode).
    
    Args:
        filepath: path to file.
        chunk_size: read chunk size (default 1MB).
    
    Returns:
        Hex hash string (32 bytes = 256 bits).
    """
    if not BLAKE3_AVAILABLE:
        raise ImportError("blake3 not available")
    
    hasher = blake3.blake3()
    
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    
    return hasher.hexdigest()


__all__ = [
    "BLAKE3_AVAILABLE",
    "compute_hash_blake3",
    "blake3_derive_key",
    "hmac_blake3",
    "blake3_hash_file",
]
