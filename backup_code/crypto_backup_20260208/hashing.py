# -*- coding: utf-8 -*-
"""
RU: Криптографическое хеширование данных (не паролей!).
EN: Cryptographic hashing for data (not passwords!).

Algorithms:
- SHA-256: Standard, widely compatible
- SHA3-256: NIST FIPS 202 standard
- BLAKE2b: High-performance (faster than SHA-256)
- BLAKE3: Ultra-fast (10× faster than SHA-256) - optional

For password hashing, use passwords.py (Argon2id/PBKDF2).

Use cases:
- File integrity verification
- Digital signatures pre-hashing
- Message digests
- Content-addressable storage
- Checksums
"""
from __future__ import annotations

import hashlib
import logging
from typing import Callable, Final, Optional, Protocol

_LOGGER: Final = logging.getLogger(__name__)


# Type for hash objects from hashlib
class _HashProtocol(Protocol):

    def update(self, data: bytes) -> None: ...

    def hexdigest(self) -> str: ...


# Try import BLAKE3
try:
    from .blake3_hash import BLAKE3_AVAILABLE, blake3_hash_file, compute_hash_blake3
except ImportError:
    BLAKE3_AVAILABLE = False
    compute_hash_blake3: Optional[Callable[[bytes], str]] = None  # type: ignore
    blake3_hash_file: Optional[Callable[[str, int], str]] = None  # type: ignore


def compute_hash(data: bytes, *, algorithm: str = "sha3-256") -> str:
    """
    Compute cryptographic hash of data.

    Args:
        data: bytes to hash.
        algorithm: hash algorithm name.

    Returns:
        Hexadecimal hash string.

    Raises:
        ValueError: on unsupported algorithm.

    Examples:
        >>> compute_hash(b"hello", algorithm="sha3-256")
        '3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392'

        >>> compute_hash(b"hello", algorithm="blake3")  # if available
        'ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f'
    """
    if algorithm == "sha256":
        return compute_hash_sha256(data)
    elif algorithm == "sha3-256":
        return compute_hash_sha3_256(data)
    elif algorithm == "blake2b":
        return compute_hash_blake2b(data)
    elif algorithm == "blake3":
        if not BLAKE3_AVAILABLE or compute_hash_blake3 is None:
            raise ValueError("BLAKE3 not available - install: pip install blake3")
        return compute_hash_blake3(data)
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def compute_hash_sha256(data: bytes) -> str:
    """
    Compute SHA-256 hash (legacy/compatibility).

    Args:
        data: bytes to hash.

    Returns:
        64-character hex string.

    Performance: ~150 MB/s on modern CPU
    """
    return hashlib.sha256(data).hexdigest()


def compute_hash_sha3_256(data: bytes) -> str:
    """
    Compute SHA3-256 hash (NIST FIPS 202 standard).

    Args:
        data: bytes to hash.

    Returns:
        64-character hex string.

    Performance: ~100 MB/s on modern CPU
    Security: More resistant to length extension attacks than SHA-256
    """
    return hashlib.sha3_256(data).hexdigest()


def compute_hash_blake2b(data: bytes, digest_size: int = 64) -> str:
    """
    Compute BLAKE2b hash (high-performance alternative).

    Args:
        data: bytes to hash.
        digest_size: output size in bytes (1-64, default 64 = 512 bits).

    Returns:
        Hexadecimal hash string (length = digest_size * 2).

    Performance: ~350 MB/s on modern CPU
    Security: Finalist of SHA-3 competition, as secure as SHA-3
    """
    if not (1 <= digest_size <= 64):
        raise ValueError("BLAKE2b digest_size must be 1-64 bytes")

    return hashlib.blake2b(data, digest_size=digest_size).hexdigest()


def hash_file(
    filepath: str, algorithm: str = "sha3-256", chunk_size: int = 1024 * 1024
) -> str:
    """
    Hash large file efficiently (streaming mode).

    Args:
        filepath: path to file.
        algorithm: hash algorithm ('sha256', 'sha3-256', 'blake2b', 'blake3').
        chunk_size: read chunk size in bytes (default 1MB).

    Returns:
        Hexadecimal hash string.

    Examples:
        >>> hash_file("/path/to/large.iso", algorithm="blake3")
        'a1b2c3d4...'
    """
    if algorithm == "blake3":
        if not BLAKE3_AVAILABLE or blake3_hash_file is None:
            raise ValueError("BLAKE3 not available")
        return blake3_hash_file(filepath, chunk_size)

    # Standard hashlib streaming
    if algorithm == "sha256":
        hasher: _HashProtocol = hashlib.sha256()
    elif algorithm == "sha3-256":
        hasher = hashlib.sha3_256()
    elif algorithm == "blake2b":
        hasher = hashlib.blake2b()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)

    return hasher.hexdigest()


def verify_file(filepath: str, expected_hash: str, algorithm: str = "sha3-256") -> bool:
    """
    Verify file integrity against expected hash.

    Args:
        filepath: path to file.
        expected_hash: expected hash value (hex string).
        algorithm: hash algorithm used.

    Returns:
        True if hash matches, False otherwise.

    Examples:
        >>> verify_file("download.zip", "a1b2c3...", algorithm="sha256")
        True
    """
    try:
        actual_hash = hash_file(filepath, algorithm)
        return actual_hash.lower() == expected_hash.lower()
    except Exception as e:
        _LOGGER.error("File verification failed: %s", e)
        return False


__all__ = [
    "BLAKE3_AVAILABLE",
    "compute_hash",
    "compute_hash_sha256",
    "compute_hash_sha3_256",
    "compute_hash_blake2b",
    "hash_file",
    "verify_file",
]
