"""
Symmetric encryption algorithms (10 ciphers in one monolithic module).

Реализует все симметричные шифры из CRYPTO_MASTER_PLAN v2.3:

**AEAD Ciphers (Modern, 7 algorithms):**
- AES-128-GCM - Fast variant (128-bit key)
- AES-256-GCM - Industry standard (256-bit key)
- ChaCha20-Poly1305 - Software-optimized
- XChaCha20-Poly1305 - Extended nonce (192-bit)
- AES-256-SIV - Nonce-reuse resistant
- AES-256-OCB - Parallelizable AEAD
- AES-256-GCM-SIV - NEW! Nonce-misuse resistant

**Legacy Ciphers (2 algorithms):**
- 3DES-EDE3 - LEGACY (use only for compatibility)
- DES - BROKEN (use only for legacy decryption)

**Non-AEAD Ciphers (1 algorithm):**
- AES-256-CTR - Requires separate HMAC

Changes from v2.2:
    ❌ REMOVED: Camellia, ARIA, Serpent, Twofish (unavailable in Python)
    ✅ ADDED: AES-256-GCM-SIV (nonce-misuse resistant, cryptography 42.0+)

Security Guidelines:
    ✅ RECOMMENDED: AES-256-GCM or ChaCha20-Poly1305
    ⚠️  LEGACY: 3DES-EDE3 (migrate ASAP)
    ⛔ BROKEN: DES (DO NOT USE for new systems)
    🛡️ PARANOID: AES-256-SIV, AES-256-GCM-SIV (nonce-misuse resistant)

Example:
    >>> from src.security.crypto.algorithms.symmetric import get_algorithm
    >>> cipher = get_algorithm("aes-256-gcm")
    >>> key = os.urandom(32)
    >>> nonce, ciphertext = cipher.encrypt(key, b"Secret message")
    >>> plaintext = cipher.decrypt(key, nonce, ciphertext)

Compliance:
    - NIST FIPS 197 (AES)
    - NIST FIPS 140-3 (Cryptographic Module Validation)
    - NIST SP 800-38D (GCM mode)
    - NIST SP 800-38A (CTR mode)
    - RFC 8439 (ChaCha20-Poly1305)
    - RFC 8452 (AES-GCM-SIV)

Version: 1.0.0
Date: February 9, 2026
"""

from __future__ import annotations

import logging
import os
from typing import Optional, Tuple, cast

# Cryptography library (modern AEAD ciphers)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
    AESOCB3,
    AESSIV,
    ChaCha20Poly1305 as ChaCha20Poly1305Impl,
)

from src.security.crypto.core.metadata import (
    create_symmetric_metadata,
)

# Try to import AES-GCM-SIV (requires cryptography >= 42.0)
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

    HAS_GCMSIV = True
except ImportError:
    HAS_GCMSIV = False

# Pycryptodome (XChaCha20, DES)
try:
    from Crypto.Cipher import ChaCha20_Poly1305 as XChaCha20Impl
    from Crypto.Cipher import DES as DESImpl

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

# Project imports
from src.security.crypto.core.exceptions import (
    DecryptionFailedError,
    EncryptionFailedError,
    InvalidKeyError,
    InvalidNonceError,
)
from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    AlgorithmMetadata,
    FloppyFriendly,
    ImplementationStatus,
    SecurityLevel,
)
from src.security.crypto.core.protocols import SymmetricCipherProtocol

logger = logging.getLogger(__name__)

__all__ = [
    # AEAD ciphers
    "AES128GCM",
    "AES256GCM",
    "ChaCha20Poly1305",
    "XChaCha20Poly1305",
    "AES256SIV",
    "AES256OCB",
    "AES256GCMSIV",
    # Legacy
    "TripleDES",
    "DES",
    # Non-AEAD
    "AES256CTR",
    # Helpers
    "get_algorithm",
    "ALGORITHMS",
    "ALL_METADATA",
]


# ==============================================================================
# AEAD CIPHERS (MODERN) - 7 algorithms
# ==============================================================================


class AES256GCM:
    """
    AES-256-GCM (Galois/Counter Mode) - Industry standard AEAD cipher.

    Provides authenticated encryption with hardware acceleration via AES-NI.
    One of the fastest and most reliable ciphers for general-purpose use.

    Security Properties:
        - Key: 256 bits (32 bytes)
        - Nonce: 96 bits (12 bytes) - MUST be unique per key!
        - Tag: 128 bits (16 bytes) - authentication tag
        - Security level: 128-bit (nonce-respecting adversary)
        - Max data per key: 2^39 - 256 bits (~68 GB)

    Performance:
        - With AES-NI: 4-10 GB/s
        - Without AES-NI: 100-200 MB/s

    Compliance:
        - NIST FIPS 197 (AES)
        - NIST FIPS 140-3
        - NIST SP 800-38D (GCM mode)
        - TLS 1.3 mandatory cipher

    Example:
        >>> cipher = AES256GCM()
        >>> key = os.urandom(32)
        >>> nonce, ct = cipher.encrypt(key, b"Secret data")
        >>> pt = cipher.decrypt(key, nonce, ct)
        >>> assert pt == b"Secret data"

    Security Warning:
        ⚠️  CRITICAL: Nonce MUST be unique for each encryption with same key!
        Nonce reuse = catastrophic failure (plaintext + key recovery).
    """

    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16
    # Protocol-required attributes (SymmetricCipherProtocol)
    algorithm_name = "AES-256-GCM"
    key_size = 32
    nonce_size = 12
    is_aead = True

    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с AES-256-GCM."""
        # === VALIDATION ===

        # Validate types FIRST (Zero Trust)
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # Validate sizes
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(
                f"AES-256-GCM requires {self.KEY_SIZE}-byte key, got {len(key)}"
            )

        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)
        elif len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(
                f"AES-256-GCM requires {self.NONCE_SIZE}-byte nonce, got {len(nonce)}"
            )

        try:
            cipher = AESGCM(key)
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
            logger.debug(f"AES-256-GCM: Encrypted {len(plaintext)} bytes")
            return nonce, ciphertext
        except Exception as e:
            raise EncryptionFailedError(f"AES-256-GCM encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с AES-256-GCM."""
        # === VALIDATION ===

        # Validate types FIRST
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        # Validate sizes
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size: {len(key)}")

        if len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size: {len(nonce)}")

        try:
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, aad)
            logger.debug(f"AES-256-GCM: Decrypted {len(plaintext)} bytes")
            return plaintext
        except Exception as e:
            raise DecryptionFailedError(
                f"AES-256-GCM decryption failed: invalid tag or key"
            ) from e


class AES128GCM:
    """
    AES-128-GCM - Faster variant of AES-256-GCM (128-bit key).

    ~20% faster than AES-256-GCM with sufficient security for most use cases.

    Key Differences:
        - Key: 128 bits (16 bytes) instead of 256 bits
        - Security: 64-bit quantum margin vs 128-bit
        - Speed: 5-12 GB/s vs 4-10 GB/s

    When to Use:
        ✓ High-throughput applications
        ✓ Short-term data protection (<5 years)
        ✓ Non-critical confidential data

    Example:
        >>> cipher = AES128GCM()
        >>> key = os.urandom(16)  # 16 bytes, NOT 32!
        >>> nonce, ct = cipher.encrypt(key, b"Fast encryption")
    """

    KEY_SIZE = 16
    NONCE_SIZE = 12
    TAG_SIZE = 16
    algorithm_name = "AES-128-GCM"
    key_size = 16
    nonce_size = 12
    is_aead = True

    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с AES-128-GCM."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"AES-128-GCM requires {self.KEY_SIZE}-byte key")

        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)
        elif len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size: {len(nonce)}")

        try:
            cipher = AESGCM(key)
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
            return nonce, ciphertext
        except Exception as e:
            raise EncryptionFailedError(f"AES-128-GCM encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с AES-128-GCM."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size: {len(key)}")

        if len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size: {len(nonce)}")

        try:
            cipher = AESGCM(key)
            return cipher.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise DecryptionFailedError("AES-128-GCM decryption failed") from e


class ChaCha20Poly1305:
    """
    ChaCha20-Poly1305 - Software-optimized AEAD cipher.

    Excellent alternative to AES-GCM for systems without AES-NI hardware.
    Constant-time implementation (no cache-timing attacks).

    Security Properties:
        - Key: 256 bits (32 bytes)
        - Nonce: 96 bits (12 bytes)
        - Tag: 128 bits (16 bytes, Poly1305 MAC)

    Performance:
        - Pure software: 500-1000 MB/s
        - Faster than AES-GCM without hardware acceleration
        - Mobile/IoT friendly

    Compliance:
        - RFC 8439
        - TLS 1.3 mandatory cipher

    Example:
        >>> cipher = ChaCha20Poly1305()
        >>> key = os.urandom(32)
        >>> nonce, ct = cipher.encrypt(key, b"Mobile data")
    """

    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16
    algorithm_name = "ChaCha20-Poly1305"
    key_size = 32
    nonce_size = 12
    is_aead = True
    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с ChaCha20-Poly1305."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"ChaCha20 requires {self.KEY_SIZE}-byte key")

        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)
        elif len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size: {len(nonce)}")

        try:
            cipher = ChaCha20Poly1305Impl(key)
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
            return nonce, ciphertext
        except Exception as e:
            raise EncryptionFailedError("ChaCha20-Poly1305 encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с ChaCha20-Poly1305."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size")

        if len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size")

        try:
            cipher = ChaCha20Poly1305Impl(key)
            return cipher.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise DecryptionFailedError("ChaCha20-Poly1305 decryption failed") from e


class XChaCha20Poly1305:
    """
    XChaCha20-Poly1305 - Extended nonce variant of ChaCha20-Poly1305.

    Key Feature: 192-bit nonce (24 bytes) allows safe random nonce generation.

    Security Properties:
        - Key: 256 bits (32 bytes)
        - Nonce: 192 bits (24 bytes) - KEY DIFFERENCE!
        - Tag: 128 bits (16 bytes)
        - Can encrypt 2^96 messages with same key (vs 2^32 for ChaCha20)

    Use Cases:
        - High-throughput services (billions of messages)
        - Random nonce generation (no collision risk)
        - Long-lived keys

    Example:
        >>> cipher = XChaCha20Poly1305()
        >>> key = os.urandom(32)
        >>> # Random nonce is SAFE (192-bit collision-resistant)
        >>> nonce, ct = cipher.encrypt(key, b"High-volume data")

    Note:
        Requires pycryptodome library.
    """

    KEY_SIZE = 32
    NONCE_SIZE = 24  # 192 bits (extended)
    TAG_SIZE = 16

    algorithm_name = "XChaCha20-Poly1305"
    key_size = 32
    nonce_size = 24
    is_aead = True
    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с XChaCha20-Poly1305."""
        if not HAS_PYCRYPTODOME:
            raise RuntimeError(
                "XChaCha20-Poly1305 requires pycryptodome. Install: pip install pycryptodome"
            )

        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"XChaCha20 requires {self.KEY_SIZE}-byte key")

        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)
        elif len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"XChaCha20 requires {self.NONCE_SIZE}-byte nonce")

        try:
            cipher = XChaCha20Impl.new(key=key, nonce=nonce)
            if aad:
                cipher.update(aad)
            ciphertext = cipher.encrypt(plaintext)
            tag = cipher.digest()
            return nonce, ciphertext + tag
        except Exception as e:
            raise EncryptionFailedError("XChaCha20-Poly1305 encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с XChaCha20-Poly1305."""
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("XChaCha20-Poly1305 requires pycryptodome")

        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size")

        if len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size")

        try:
            # Split ciphertext and tag
            ct, tag = ciphertext[:-16], ciphertext[-16:]
            cipher = XChaCha20Impl.new(key=key, nonce=nonce)
            if aad:
                cipher.update(aad)
            plaintext = cipher.decrypt(ct)
            cipher.verify(tag)
            return plaintext
        except Exception as e:
            raise DecryptionFailedError("XChaCha20-Poly1305 decryption failed") from e


class AES256SIV:
    """
    AES-256-SIV - Nonce-reuse resistant AEAD cipher.

    Synthetic IV mode provides misuse-resistance: nonce reuse reveals only
    equality of plaintexts, NOT the plaintexts themselves.

    Security Properties:
        - Key: 512 bits (64 bytes) - TWO 256-bit keys!
        - Nonce: Variable (typically 16 bytes)
        - Tag: 128 bits (16 bytes, SIV)
        - Nonce reuse: Safe (deterministic for same plaintext)

    Trade-offs:
        - 2x slower than AES-GCM (two AES passes)
        - NOT parallelizable
        - Larger key size (64 bytes)

    Use Cases:
        - Applications with difficult nonce management
        - Defense-in-depth (protection against nonce reuse bugs)
        - Deterministic encryption needs

    Example:
        >>> cipher = AES256SIV()
        >>> key = os.urandom(64)  # 64 bytes!
        >>> nonce, ct = cipher.encrypt(key, b"data", nonce=b"fixed_nonce_123")
        >>> # Nonce reuse is SAFE (reveals equality only)
    """

    KEY_SIZE = 64  # Two 256-bit keys
    NONCE_SIZE = 16
    TAG_SIZE = 16

    algorithm_name = "AES-256-SIV"
    key_size = 64
    nonce_size = 16
    is_aead = True
    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с AES-256-SIV."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"AES-256-SIV requires {self.KEY_SIZE}-byte key")

        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)
        elif len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size: {len(nonce)}")

        try:
            cipher = AESSIV(key)
            # SIV uses AAD differently (includes nonce as AAD)
            aad_list = [nonce] + ([aad] if aad else [])
            ciphertext = cipher.encrypt(plaintext, aad_list)
            return nonce, ciphertext
        except Exception as e:
            raise EncryptionFailedError("AES-256-SIV encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с AES-256-SIV."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size")

        if len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size")

        try:
            cipher = AESSIV(key)
            aad_list = [nonce] + ([aad] if aad else [])
            return cipher.decrypt(ciphertext, aad_list)
        except Exception as e:
            raise DecryptionFailedError("AES-256-SIV decryption failed") from e


class AES256OCB:
    """
    AES-256-OCB - Parallelizable AEAD cipher.

    Offset Codebook mode supports parallel encryption/decryption,
    achieving up to 4x speedup on multi-core systems.

    Security Properties:
        - Key: 256 bits (32 bytes)
        - Nonce: 96-120 bits (12-15 bytes, variable)
        - Tag: 128 bits (16 bytes)

    Performance:
        - Single-core: Similar to GCM
        - Multi-core: Up to 4x faster (parallelizable)
        - Single-pass AEAD (unlike 2-pass SIV)

    Patent Note:
        Patents expired in 2021 - now freely usable.

    Example:
        >>> cipher = AES256OCB()
        >>> key = os.urandom(32)
        >>> nonce, ct = cipher.encrypt(key, b"Parallel data")
    """

    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16
    algorithm_name = "AES-256-OCB"
    key_size = 32
    nonce_size = 12
    is_aead = True
    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с AES-256-OCB."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"AES-256-OCB requires {self.KEY_SIZE}-byte key")

        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)
        elif len(nonce) not in range(12, 16):  # OCB allows 12-15 bytes
            raise InvalidNonceError(f"OCB nonce must be 12-15 bytes, got {len(nonce)}")

        try:
            cipher = AESOCB3(key)
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
            return nonce, ciphertext
        except Exception as e:
            raise EncryptionFailedError("AES-256-OCB encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с AES-256-OCB."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size")

        if len(nonce) not in range(12, 16):
            raise InvalidNonceError(f"Invalid nonce size")

        try:
            cipher = AESOCB3(key)
            return cipher.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise DecryptionFailedError("AES-256-OCB decryption failed") from e


class AES256GCMSIV:
    """
    AES-256-GCM-SIV - NEW! Nonce-misuse resistant variant of GCM.

    Best of both worlds: combines nonce-misuse resistance of SIV with
    speed and hardware acceleration of GCM.

    Security Properties:
        - Key: 256 bits (32 bytes)
        - Nonce: 96 bits (12 bytes)
        - Tag: 128 bits (16 bytes)
        - Nonce reuse: Safe (deterministic, reveals equality only)

    Performance:
        - ~80% of GCM speed (vs 50% for SIV)
        - 2x faster than AES-SIV
        - Hardware acceleration support (AES-NI)

    Requirements:
        Requires cryptography >= 42.0.0

    Example:
        >>> cipher = AES256GCMSIV()
        >>> key = os.urandom(32)
        >>> nonce, ct = cipher.encrypt(key, b"Misuse-resistant data")

    References:
        - RFC 8452: https://tools.ietf.org/html/rfc8452
    """

    KEY_SIZE = 32
    NONCE_SIZE = 12
    TAG_SIZE = 16
    algorithm_name = "AES-256-GCM-SIV"
    key_size = 32
    nonce_size = 12
    is_aead = True
    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с AES-256-GCM-SIV."""
        if not HAS_GCMSIV:
            raise RuntimeError(
                "AES-256-GCM-SIV requires cryptography >= 42.0.0. "
                "Install: pip install --upgrade cryptography"
            )

        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"AES-256-GCM-SIV requires {self.KEY_SIZE}-byte key")

        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)
        elif len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size: {len(nonce)}")

        try:
            cipher = AESGCMSIV(key)
            ciphertext = cipher.encrypt(nonce, plaintext, aad)
            logger.info("NEW! Using AES-256-GCM-SIV (nonce-misuse resistant)")
            return nonce, ciphertext
        except Exception as e:
            raise EncryptionFailedError("AES-256-GCM-SIV encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с AES-256-GCM-SIV."""
        if not HAS_GCMSIV:
            raise RuntimeError("AES-256-GCM-SIV requires cryptography >= 42.0.0")

        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        if aad is not None and not isinstance(aad, bytes):
            raise TypeError(f"AAD must be bytes, got {type(aad).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size")

        if len(nonce) != self.NONCE_SIZE:
            raise InvalidNonceError(f"Invalid nonce size")

        try:
            cipher = AESGCMSIV(key)
            return cipher.decrypt(nonce, ciphertext, aad)
        except Exception as e:
            raise DecryptionFailedError("AES-256-GCM-SIV decryption failed") from e


# ==============================================================================
# LEGACY CIPHERS - 2 algorithms
# ==============================================================================


class TripleDES:
    """
    TripleDES (3DES-EDE3) - LEGACY cipher.

    ⚠️  WARNING: DEPRECATED by NIST in 2023. Use only for legacy compatibility!

    Security Issues:
        - Effective key size: 112 bits (not 168!)
        - Sweet32 attack: birthday bound after 32 GB
        - 10-100x slower than AES

    Migration Path:
        Use AES-256-GCM for new systems.

    Example:
        >>> cipher = TripleDES()
        >>> key = os.urandom(24)  # 192-bit key
        >>> # NOT AEAD! Requires separate HMAC
        >>> nonce, ct = cipher.encrypt(key, b"legacy data")
    """

    KEY_SIZE = 24  # 192 bits (3 × 64-bit keys)
    IV_SIZE = 8  # DES block size
    BLOCK_SIZE = 8

    def __init__(self) -> None:
        logger.warning("TripleDES is DEPRECATED. Migrate to AES-256-GCM ASAP!")

    algorithm_name = "3DES-EDE3"
    key_size = 24
    nonce_size = 8
    is_aead = False
    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с TripleDES-CBC."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"3DES requires {self.KEY_SIZE}-byte key")

        if nonce is None:
            nonce = os.urandom(self.IV_SIZE)
        elif len(nonce) != self.IV_SIZE:
            raise InvalidNonceError(f"3DES requires {self.IV_SIZE}-byte IV")

        try:
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(nonce))
            encryptor = cipher.encryptor()

            # PKCS7 padding
            from cryptography.hazmat.primitives import padding

            padder = padding.PKCS7(self.BLOCK_SIZE * 8).padder()
            padded = padder.update(plaintext) + padder.finalize()

            ciphertext = encryptor.update(padded) + encryptor.finalize()
            return nonce, ciphertext
        except Exception as e:
            raise EncryptionFailedError("TripleDES encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с TripleDES-CBC."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size")

        if len(nonce) != self.IV_SIZE:
            raise InvalidNonceError(f"Invalid IV size")

        try:
            cipher = Cipher(algorithms.TripleDES(key), modes.CBC(nonce))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()

            # Remove PKCS7 padding
            from cryptography.hazmat.primitives import padding

            unpadder = padding.PKCS7(self.BLOCK_SIZE * 8).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
            return plaintext
        except Exception as e:
            raise DecryptionFailedError("TripleDES decryption failed") from e


class DES:
    """
    DES (Data Encryption Standard) - BROKEN cipher.

    ⛔ CRITICAL: BROKEN by brute-force in 1999 (EFF's Deep Crack).

    Security Status:
        - 56-bit key = brute-forceable in hours
        - NIST FIPS 46-3 withdrawn in 2005
        - NO security guarantee

    Use ONLY for:
        - Decrypting ancient data
        - Academic research
        - Historical purposes

    DO NOT USE for new applications!

    Example:
        >>> cipher = DES()  # Logs security warning!
        >>> key = os.urandom(8)
        >>> # BROKEN! Use AES-256-GCM instead!
    """

    KEY_SIZE = 8  # 56 bits + 8 parity bits
    IV_SIZE = 8
    BLOCK_SIZE = 8

    def __init__(self) -> None:
        logger.critical(
            "DES cipher initialized! This algorithm is BROKEN. "
            "Use AES-256-GCM instead!"
        )

    algorithm_name = "DES"
    key_size = 8
    nonce_size = 8
    is_aead = False
    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с DES-CBC (BROKEN!)."""
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("DES requires pycryptodome")

        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"DES requires {self.KEY_SIZE}-byte key")

        if nonce is None:
            nonce = os.urandom(self.IV_SIZE)
        elif len(nonce) != self.IV_SIZE:
            raise InvalidNonceError(f"DES requires {self.IV_SIZE}-byte IV")

        try:
            cipher = DESImpl.new(key, DESImpl.MODE_CBC, iv=nonce)

            # PKCS7 padding
            pad_len = self.BLOCK_SIZE - (len(plaintext) % self.BLOCK_SIZE)
            padded = plaintext + bytes([pad_len] * pad_len)

            ciphertext = cipher.encrypt(padded)
            logger.warning("⛔ DES encryption used! MIGRATE TO AES ASAP!")
            return nonce, ciphertext
        except Exception as e:
            raise EncryptionFailedError("DES encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с DES-CBC (BROKEN!)."""
        if not HAS_PYCRYPTODOME:
            raise RuntimeError("DES requires pycryptodome")

        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size")

        if len(nonce) != self.IV_SIZE:
            raise InvalidNonceError(f"Invalid IV size")

        try:
            cipher = DESImpl.new(key, DESImpl.MODE_CBC, iv=nonce)
            padded = cipher.decrypt(ciphertext)

            # Remove PKCS7 padding
            pad_len = padded[-1]
            plaintext = padded[:-pad_len]
            return plaintext
        except Exception as e:
            raise DecryptionFailedError("DES decryption failed") from e


# ==============================================================================
# NON-AEAD CIPHERS - 1 algorithm
# ==============================================================================


class AES256CTR:
    """
    AES-256-CTR - Stream cipher mode (non-AEAD).

    ⚠️  WARNING: NOT AUTHENTICATED ENCRYPTION!
    Provides confidentiality only - NO integrity/authenticity protection.
    MUST use separate HMAC for authentication.

    Security Properties:
        - Key: 256 bits (32 bytes)
        - IV: 128 bits (16 bytes, full AES block as counter)
        - NO TAG (not AEAD)

    Use Cases:
        - Custom AEAD construction (CTR + HMAC)
        - Legacy systems requiring CTR mode
        - Disk encryption with separate MAC

    Recommended:
        Use AES-256-GCM instead (built-in authentication).

    Example:
        >>> cipher = AES256CTR()
        >>> key = os.urandom(32)
        >>> nonce, ct = cipher.encrypt(key, b"data")
        >>> # Add HMAC separately!
        >>> import hmac
        >>> mac = hmac.new(mac_key, ct, 'sha256').digest()
    """

    KEY_SIZE = 32
    IV_SIZE = 16  # Full AES block

    def __init__(self) -> None:
        logger.warning("AES-256-CTR is NOT AEAD. Use separate HMAC for authentication!")

    algorithm_name = "AES-256-CTR"
    key_size = 32
    nonce_size = 16
    is_aead = False
    def generate_key(self) -> bytes:
        """
        Генерировать криптографически стойкий ключ нужного размера.

        Returns:
            Случайные байты ключа (длина == KEY_SIZE)

        Example:
            >>> key = cipher.generate_key()
            >>> len(key) == cipher.KEY_SIZE
            True
        """
        return os.urandom(self.KEY_SIZE)

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        *,
        aad: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Зашифровать данные с AES-256-CTR (non-AEAD)."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(plaintext, bytes):
            raise TypeError(f"Plaintext must be bytes, got {type(plaintext).__name__}")

        if nonce is not None and not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"AES-256-CTR requires {self.KEY_SIZE}-byte key")

        if nonce is None:
            nonce = os.urandom(self.IV_SIZE)
        elif len(nonce) != self.IV_SIZE:
            raise InvalidNonceError(f"AES-CTR requires {self.IV_SIZE}-byte IV")

        try:
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            return nonce, ciphertext
        except Exception as e:
            raise EncryptionFailedError("AES-256-CTR encryption failed") from e

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """Расшифровать данные с AES-256-CTR (non-AEAD)."""
        # === TYPE VALIDATION ===
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key).__name__}")

        if not isinstance(nonce, bytes):
            raise TypeError(f"Nonce must be bytes, got {type(nonce).__name__}")

        if not isinstance(ciphertext, bytes):
            raise TypeError(
                f"Ciphertext must be bytes, got {type(ciphertext).__name__}"
            )

        # === SIZE VALIDATION ===
        if len(key) != self.KEY_SIZE:
            raise InvalidKeyError(f"Invalid key size")

        if len(nonce) != self.IV_SIZE:
            raise InvalidNonceError(f"Invalid IV size")

        try:
            cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except Exception as e:
            raise DecryptionFailedError("AES-256-CTR decryption failed") from e


# ==============================================================================
# METADATA REGISTRY
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. AES-128-GCM - Fast variant for performance-critical systems
# ------------------------------------------------------------------------------

AES128GCM_METADATA = create_symmetric_metadata(
    name="AES-128-GCM",
    library="cryptography",
    implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESGCM",
    key_size=16,
    nonce_size=12,
    is_aead=True,
    security_level=SecurityLevel.STANDARD,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "AES-128-GCM — быстрый вариант AES-256-GCM для систем, "
        "где производительность критична. Используется в TLS 1.3, "
        "IPsec, и веб-приложениях. Обеспечивает конфиденциальность "
        "и аутентичность данных."
    ),
    description_en=(
        "AES-128-GCM is a fast variant of AES-256-GCM for performance-critical "
        "systems. Used in TLS 1.3, IPsec, and web applications. Provides both "
        "confidentiality and authenticity."
    ),
    test_vectors_source="NIST CAVP, RFC 5288",
    use_cases=[
        "TLS 1.3 connections",
        "High-throughput web services",
        "Mobile applications (battery-efficient)",
        "IoT devices with limited CPU",
        "Real-time encrypted streaming",
    ],
)

# ------------------------------------------------------------------------------
# 2. AES-256-GCM - Industry standard AEAD cipher (RECOMMENDED)
# ------------------------------------------------------------------------------

AES256GCM_METADATA = create_symmetric_metadata(
    name="AES-256-GCM",
    library="cryptography",
    implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESGCM",
    key_size=32,
    nonce_size=12,
    is_aead=True,
    security_level=SecurityLevel.STANDARD,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "AES-256-GCM — индустриальный стандарт для шифрования с аутентификацией. "
        "Используется в TLS 1.3, SSH, disk encryption, и cloud storage. "
        "Оптимальный баланс безопасности и производительности. "
        "РЕКОМЕНДУЕТСЯ для большинства применений."
    ),
    description_en=(
        "AES-256-GCM is the industry standard for authenticated encryption. "
        "Used in TLS 1.3, SSH, disk encryption, and cloud storage. "
        "Optimal balance of security and performance. "
        "RECOMMENDED for most applications."
    ),
    test_vectors_source="NIST CAVP, RFC 5288",
    use_cases=[
        "File encryption (documents, databases)",
        "API authentication tokens",
        "Cloud storage encryption",
        "VPN tunnels (WireGuard)",
        "Encrypted messaging (Signal Protocol)",
        "Database field-level encryption",
    ],
)

# ------------------------------------------------------------------------------
# 3. ChaCha20-Poly1305 - Software-optimized AEAD cipher
# ------------------------------------------------------------------------------

CHACHA20_POLY1305_METADATA = create_symmetric_metadata(
    name="ChaCha20-Poly1305",
    library="cryptography",
    implementation_class="cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305",
    key_size=32,
    nonce_size=12,
    is_aead=True,
    security_level=SecurityLevel.STANDARD,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "ChaCha20-Poly1305 — программно-оптимизированный AEAD шифр. "
        "Быстрее AES-GCM на устройствах без аппаратного AES-NI. "
        "Используется в WireGuard, TLS 1.3, SSH. Constant-time реализация "
        "защищает от cache-timing атак."
    ),
    description_en=(
        "ChaCha20-Poly1305 is a software-optimized AEAD cipher. "
        "Faster than AES-GCM on devices without AES-NI hardware acceleration. "
        "Used in WireGuard, TLS 1.3, SSH. Constant-time implementation "
        "protects against cache-timing attacks."
    ),
    test_vectors_source="RFC 8439",
    use_cases=[
        "Mobile encryption (ARM CPUs without AES-NI)",
        "Embedded systems (Raspberry Pi, ESP32)",
        "VPN (WireGuard)",
        "SSH connections",
        "Side-channel resistant applications",
    ],
)

# ------------------------------------------------------------------------------
# 4. XChaCha20-Poly1305 - Extended nonce ChaCha20
# ------------------------------------------------------------------------------

XCHACHA20_POLY1305_METADATA = create_symmetric_metadata(
    name="XChaCha20-Poly1305",
    library="pycryptodome",
    implementation_class="Crypto.Cipher.ChaCha20_Poly1305",
    key_size=32,
    nonce_size=24,  # 192 bits!
    is_aead=True,
    security_level=SecurityLevel.HIGH,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "XChaCha20-Poly1305 — расширенная версия ChaCha20 с 192-битным nonce. "
        "Позволяет генерировать случайные nonce без риска коллизий. "
        "Используется в libsodium, age encryption, и modern file encryption."
    ),
    description_en=(
        "XChaCha20-Poly1305 is an extended variant of ChaCha20 with 192-bit nonce. "
        "Allows random nonce generation without collision risk. "
        "Used in libsodium, age encryption, and modern file encryption systems."
    ),
    test_vectors_source="draft-irtf-cfrg-xchacha",
    use_cases=[
        "File encryption with random nonces",
        "Long-lived sessions (no nonce counter)",
        "Distributed systems (random nonces safe)",
        "Age encryption tool",
        "libsodium applications",
    ],
    extra={
        "nonce_collision_resistance": "2^96 security (vs 2^48 for standard ChaCha20)",
        "libsodium_compatible": True,
    },
)

# ------------------------------------------------------------------------------
# 5. AES-256-SIV - Nonce-reuse resistant AEAD
# ------------------------------------------------------------------------------

AES256_SIV_METADATA = create_symmetric_metadata(
    name="AES-256-SIV",
    library="cryptography",
    implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESSIV",
    key_size=64,  # Two 256-bit keys
    nonce_size=16,
    is_aead=True,
    security_level=SecurityLevel.HIGH,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "AES-256-SIV — детерминированный AEAD шифр, устойчивый к повторному "
        "использованию nonce. При одинаковых plaintext+nonce даёт одинаковый "
        "ciphertext (deterministic). Используется в ключевых системах, где "
        "гарантия уникальности nonce невозможна."
    ),
    description_en=(
        "AES-256-SIV is a deterministic AEAD cipher resistant to nonce reuse. "
        "Same plaintext+nonce produces same ciphertext (deterministic). "
        "Used in key wrapping systems where nonce uniqueness cannot be guaranteed."
    ),
    test_vectors_source="RFC 5297",
    use_cases=[
        "Key wrapping (KEK encryption)",
        "Database encryption (deterministic search)",
        "Systems with unreliable nonce generation",
        "Stateless encryption (cookies, tokens)",
        "Legacy system migration",
    ],
    extra={
        "nonce_reuse_safe": True,
        "deterministic": True,
        "use_two_keys": "K1 for MAC, K2 for encryption",
    },
)

# ------------------------------------------------------------------------------
# 6. AES-256-OCB - Parallelizable AEAD cipher
# ------------------------------------------------------------------------------

AES256_OCB_METADATA = create_symmetric_metadata(
    name="AES-256-OCB",
    library="cryptography",
    implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESOCB3",
    key_size=32,
    nonce_size=12,  # 12-15 bytes supported
    is_aead=True,
    security_level=SecurityLevel.HIGH,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "AES-256-OCB — параллелизуемый AEAD шифр с высокой производительностью. "
        "Один проход для шифрования и аутентификации (vs два прохода в GCM). "
        "Быстрее AES-GCM, но защищён патентами (бесплатно для open-source)."
    ),
    description_en=(
        "AES-256-OCB is a parallelizable AEAD cipher with high performance. "
        "Single-pass encryption and authentication (vs two passes in GCM). "
        "Faster than AES-GCM, but patent-encumbered (free for open-source)."
    ),
    test_vectors_source="RFC 7253",
    use_cases=[
        "High-performance encryption (servers)",
        "Parallel processing (multi-core CPUs)",
        "Open-source projects (patent-free license)",
        "Real-time video encryption",
    ],
    extra={
        "patent_status": "Free for open-source (Rogaway license)",
        "performance": "~1.5x faster than AES-GCM",
        "nonce_size_range": "12-15 bytes",
    },
)

# ------------------------------------------------------------------------------
# 7. AES-256-GCM-SIV - NEW! Nonce-misuse resistant GCM
# ------------------------------------------------------------------------------

AES256_GCM_SIV_METADATA = create_symmetric_metadata(
    name="AES-256-GCM-SIV",
    library="cryptography",
    implementation_class="cryptography.hazmat.primitives.ciphers.aead.AESGCMSIV",
    key_size=32,
    nonce_size=12,
    is_aead=True,
    security_level=SecurityLevel.HIGH,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "AES-256-GCM-SIV — улучшенная версия GCM, устойчивая к nonce-misuse. "
        "При повторном использовании nonce теряется только конфиденциальность "
        "(но не аутентичность). Детерминированный шифр. Требует cryptography >= 42.0. "
        "NEW in 2024!"
    ),
    description_en=(
        "AES-256-GCM-SIV is an improved GCM variant resistant to nonce misuse. "
        "Nonce reuse only leaks confidentiality (not authenticity). "
        "Deterministic cipher. Requires cryptography >= 42.0. "
        "NEW in 2024!"
    ),
    test_vectors_source="RFC 8452",
    use_cases=[
        "Systems with nonce generation risks",
        "Defense-in-depth (GCM alternative)",
        "Modern cloud applications",
        "Google Cloud KMS compatible",
    ],
    extra={
        "nonce_misuse_resistant": True,
        "deterministic": True,
        "requires": "cryptography >= 42.0.0",
        "adoption_year": 2024,
    },
)

# ------------------------------------------------------------------------------
# 8. TripleDES (3DES-EDE3) - LEGACY cipher
# ------------------------------------------------------------------------------

TRIPLE_DES_METADATA = create_symmetric_metadata(
    name="3DES-EDE3",
    library="cryptography",
    implementation_class="cryptography.hazmat.primitives.ciphers.algorithms.TripleDES",
    key_size=24,
    nonce_size=8,
    is_aead=False,
    security_level=SecurityLevel.LEGACY,
    status=ImplementationStatus.DEPRECATED,
    description_ru=(
        "TripleDES (3DES-EDE3) — УСТАРЕВШИЙ блочный шифр. Эффективная длина ключа "
        "112 бит (слабее AES-128). Медленный и уязвимый к Sweet32 атаке. "
        "Не имеет встроенной аутентификации (требует HMAC). "
        "ТОЛЬКО для совместимости с legacy системами. МИГРИРУЙТЕ на AES-256-GCM!"
    ),
    description_en=(
        "TripleDES (3DES-EDE3) is a LEGACY block cipher. Effective key length "
        "112 bits (weaker than AES-128). Slow and vulnerable to Sweet32 attack. "
        "No built-in authentication (requires HMAC). "
        "ONLY for legacy system compatibility. MIGRATE to AES-256-GCM!"
    ),
    test_vectors_source="NIST SP 800-67",
    use_cases=[
        "⚠️ Legacy banking systems (pre-2010)",
        "⚠️ Old payment terminals (PCI-DSS 3.2.1 sunset 2023)",
        "⚠️ Mainframe compatibility",
    ],
    extra={
        "pci_dss_status": "Deprecated since 2023",
        "sweet32_vulnerable": True,
        "max_data_per_key": "2^32 blocks (~32 GB)",
        "migration_urgency": "CRITICAL",
    },
)

# ------------------------------------------------------------------------------
# 9. DES - BROKEN cipher (for research/legacy only)
# ------------------------------------------------------------------------------

DES_METADATA = create_symmetric_metadata(
    name="DES",
    library="pycryptodome",
    implementation_class="Crypto.Cipher.DES",
    key_size=8,  # 56 bits + 8 parity
    nonce_size=8,
    is_aead=False,
    security_level=SecurityLevel.BROKEN,
    status=ImplementationStatus.DEPRECATED,
    description_ru=(
        "DES (Data Encryption Standard) — СЛОМАННЫЙ шифр. Брутфорс за несколько часов. "
        "Эффективная длина ключа 56 бит. Взломан в 1998 году (DES Challenge). "
        "НЕ ИСПОЛЬЗОВАТЬ в production. ТОЛЬКО для исследований и чтения legacy данных. "
        "⛔ КРИТИЧЕСКИ ОПАСНО!"
    ),
    description_en=(
        "DES (Data Encryption Standard) is a BROKEN cipher. Brute-forced in hours. "
        "Effective key length 56 bits. Broken in 1998 (DES Challenge). "
        "DO NOT USE in production. ONLY for research and reading legacy data. "
        "⛔ CRITICALLY INSECURE!"
    ),
    test_vectors_source="FIPS 46-3 (withdrawn)",
    use_cases=[
        "⛔ Academic research only",
        "⛔ Reading ancient encrypted archives",
        "⛔ Security demonstrations (how NOT to encrypt)",
    ],
    extra={
        "broken_since": 1998,
        "brute_force_time": "< 24 hours with modern hardware",
        "fips_status": "WITHDRAWN",
        "danger_level": "CRITICAL — DO NOT USE",
    },
)

# ------------------------------------------------------------------------------
# 10. AES-256-CTR - Non-AEAD stream cipher
# ------------------------------------------------------------------------------

AES256_CTR_METADATA = create_symmetric_metadata(
    name="AES-256-CTR",
    library="cryptography",
    implementation_class="cryptography.hazmat.primitives.ciphers.algorithms.AES",
    key_size=32,
    nonce_size=16,
    is_aead=False,
    security_level=SecurityLevel.STANDARD,
    status=ImplementationStatus.STABLE,
    description_ru=(
        "AES-256-CTR — режим счётчика AES (stream cipher). НЕ обеспечивает "
        "аутентичность (требует отдельный HMAC). Используется в IPsec, SSH, "
        "и некоторых legacy системах. ДЛЯ НОВЫХ ПРОЕКТОВ ИСПОЛЬЗУЙТЕ AES-256-GCM!"
    ),
    description_en=(
        "AES-256-CTR is AES Counter mode (stream cipher). Does NOT provide "
        "authentication (requires separate HMAC). Used in IPsec, SSH, "
        "and some legacy systems. FOR NEW PROJECTS USE AES-256-GCM!"
    ),
    test_vectors_source="NIST SP 800-38A",
    use_cases=[
        "⚠️ Disk encryption with separate MAC (LUKS, dm-crypt)",
        "⚠️ IPsec ESP (with separate HMAC)",
        "⚠️ SSH encryption layer",
        "⚠️ Custom protocols with external authentication",
    ],
    extra={
        "requires_mac": "MUST use HMAC-SHA256 or Poly1305",
        "malleable": "Ciphertext can be modified (no authentication)",
        "recommendation": "Use AES-GCM instead for AEAD",
    },
)

# ------------------------------------------------------------------------------
# Collect all metadata
# ------------------------------------------------------------------------------

ALL_METADATA: list[AlgorithmMetadata] = [
    AES128GCM_METADATA,
    AES256GCM_METADATA,
    CHACHA20_POLY1305_METADATA,
    XCHACHA20_POLY1305_METADATA,
    AES256_SIV_METADATA,
    AES256_OCB_METADATA,
    AES256_GCM_SIV_METADATA,
    TRIPLE_DES_METADATA,
    DES_METADATA,
    AES256_CTR_METADATA,
]

# Validate that all metadata matches expected algorithms
_EXPECTED_ALGORITHM_COUNT = 10
assert len(ALL_METADATA) == _EXPECTED_ALGORITHM_COUNT, (
    f"Expected {_EXPECTED_ALGORITHM_COUNT} metadata objects, "
    f"got {len(ALL_METADATA)}"
)

logger.info(
    f"Loaded {len(ALL_METADATA)} symmetric cipher metadata objects: "
    f"{[m.name for m in ALL_METADATA]}"
)

# ==============================================================================
# ALGORITHM REGISTRY & HELPERS
# ==============================================================================

ALGORITHMS = {
    "aes-128-gcm": AES128GCM,
    "aes-256-gcm": AES256GCM,
    "chacha20-poly1305": ChaCha20Poly1305,
    "xchacha20-poly1305": XChaCha20Poly1305,
    "aes-256-siv": AES256SIV,
    "aes-256-ocb": AES256OCB,
    "aes-256-gcm-siv": AES256GCMSIV,
    "3des-ede3": TripleDES,
    "des": DES,
    "aes-256-ctr": AES256CTR,
}


def get_algorithm(algorithm_id: str) -> SymmetricCipherProtocol:
    """
    Получить экземпляр алгоритма по ID.

    Args:
        algorithm_id: ID алгоритма (например, "aes-256-gcm")

    Returns:
        Экземпляр алгоритма

    Raises:
        KeyError: Если алгоритм не найден
        RuntimeError: Если библиотека не установлена

    Example:
        >>> cipher = get_algorithm("aes-256-gcm")
        >>> key = os.urandom(32)
        >>> nonce, ct = cipher.encrypt(key, b"message")
    """
    if algorithm_id not in ALGORITHMS:
        raise KeyError(
            f"Algorithm '{algorithm_id}' not found. "
            f"Available: {list(ALGORITHMS.keys())}"
        )

    cipher_class = ALGORITHMS[algorithm_id]

    try:
        instance = cipher_class()
        # Type cast для mypy (все классы реализуют Protocol)
        return cast(SymmetricCipherProtocol, instance)
    except RuntimeError as e:
        # Re-raise library dependency errors
        raise RuntimeError(
            f"Cannot initialize '{algorithm_id}': {e}. " f"Install required library."
        ) from e
