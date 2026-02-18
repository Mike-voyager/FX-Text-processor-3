"""
Key Exchange & Key Encapsulation Mechanisms (KEX/KEM).

Этот модуль реализует 8 алгоритмов key exchange для установления
общего секрета (shared secret) между двумя сторонами:

Classical Key Exchange (5):
    1. X25519 (RFC 7748) — Curve25519 ECDH, default для TLS 1.3
    2. X448 (RFC 7748) — Curve448 ECDH, повышенная безопасность
    3. ECDH-P256 (NIST) — secp256r1, NIST рекомендуемая
    4. ECDH-P384 (NIST) — secp384r1, NSA Suite B
    5. ECDH-P521 (NIST) — secp521r1, максимальная классическая безопасность

Post-Quantum KEM (3) - ⚠️ FIPS 203 ML-KEM:
    6. ML-KEM-512 (FIPS 203) — NIST Level 1, 128-bit quantum security
    7. ML-KEM-768 (FIPS 203) — NIST Level 3, 192-bit quantum security
    8. ML-KEM-1024 (FIPS 203) — NIST Level 5, 256-bit quantum security

⚠️ CRITICAL MIGRATION (August 2024):
    Kyber512/768/1024 (NIST Round 3) → ML-KEM-512/768/1024 (FIPS 203)

    Changes:
    - Algorithm names: "Kyber768" → "ML-KEM-768" in liboqs
    - API update: secret_key parameter in KeyEncapsulation constructor
    - Standard: Draft → Official FIPS 203 (August 13, 2024)
    - Compatibility: NOT compatible with Kyber Round 3

    Requirements:
    - liboqs-python >= 0.15.0 (Kyber removed in 0.15.0+)

    See: SIGNING_UPDATE.md for full migration guide

Key Exchange Types:

    Diffie-Hellman (DH):
        - Both parties exchange public keys
        - Derive shared secret independently
        - Symmetric: either party can initiate

    Key Encapsulation Mechanism (KEM):
        - Sender encapsulates: (ciphertext, shared_secret) from receiver's public key
        - Receiver decapsulates: shared_secret from ciphertext + own private key
        - Asymmetric: receiver generates keypair first

Security Considerations:

    Classical KEX (ECDH):
        - Vulnerable to quantum attacks (Shor's algorithm)
        - Provides perfect forward secrecy (ephemeral keys)
        - Constant-time implementations (timing attack resistant)
        - Recommended: X25519 for general use, P-256 for compliance

    Post-Quantum KEM (ML-KEM):
        - Resistant to quantum attacks (lattice-based)
        - Larger key sizes (1-4 KB vs 32-66 bytes)
        - Slower performance (~10-100x slower than ECDH)
        - Standardized: FIPS 203 (official NIST standard, not draft)

Performance:

    Classical ECDH:
        - X25519: ~50,000 ops/sec (ultra-fast)
        - X448: ~20,000 ops/sec (fast)
        - ECDH-P256/384/521: ~10,000-30,000 ops/sec (fast)

    Post-Quantum KEM:
        - ML-KEM-512: ~5,000 ops/sec (medium)
        - ML-KEM-768: ~3,000 ops/sec (medium)
        - ML-KEM-1024: ~2,000 ops/sec (slow)

Use Cases:

    X25519:
        - TLS 1.3 (default key exchange)
        - SSH (modern versions)
        - Signal Protocol
        - General-purpose secure communication

    ECDH-P256/384:
        - Government/enterprise compliance (NIST, FIPS)
        - Legacy interoperability
        - NSA Suite B cryptography

    ML-KEM (Post-Quantum):
        - Quantum-resistant communication
        - Long-term data protection (10+ years)
        - Hybrid KEX (classical + PQC)
        - Future-proofing against quantum computers

Compliance:
    - RFC 7748: Elliptic Curves for Security (X25519, X448)
    - NIST SP 800-56A Rev. 3: Key Establishment Schemes (ECDH)
    - FIPS 203: Module-Lattice-Based KEM Standard (ML-KEM)
    - NIST PQC Standardization: Post-Quantum Cryptography

References:
    - RFC 7748: https://tools.ietf.org/html/rfc7748
    - NIST SP 800-56A: https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final
    - FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
    - liboqs: https://github.com/open-quantum-safe/liboqs

Examples:
    >>> # Classical ECDH (X25519)
    >>> from src.security.crypto.algorithms.key_exchange import get_kex_algorithm
    >>>
    >>> # Party A
    >>> kex_a = get_kex_algorithm("x25519")
    >>> priv_a, pub_a = kex_a.generate_keypair()
    >>>
    >>> # Party B
    >>> kex_b = get_kex_algorithm("x25519")
    >>> priv_b, pub_b = kex_b.generate_keypair()
    >>>
    >>> # Derive shared secrets
    >>> shared_a = kex_a.derive_shared_secret(priv_a, pub_b)
    >>> shared_b = kex_b.derive_shared_secret(priv_b, pub_a)
    >>> assert shared_a == shared_b

    >>> # Post-Quantum KEM (ML-KEM-768)
    >>> kem = get_kex_algorithm("ml-kem-768")
    >>>
    >>> # Receiver (Party B) generates keypair
    >>> priv_b, pub_b = kem.generate_keypair()
    >>>
    >>> # Sender (Party A) encapsulates
    >>> ciphertext, shared_a = kem.encapsulate(pub_b)
    >>>
    >>> # Receiver (Party B) decapsulates
    >>> shared_b = kem.decapsulate(priv_b, ciphertext)
    >>> assert shared_a == shared_b

Version: 2.4 (ML-KEM migration)
Date: February 10, 2026
Author: Mike Voyager
"""

from __future__ import annotations

import logging
from typing import Tuple, Type, Optional
from abc import ABC, abstractmethod

# Cryptography library (classical KEX)
from cryptography.hazmat.primitives.asymmetric import x25519, x448, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Project imports
from src.security.crypto.core.protocols import KeyExchangeProtocol
from src.security.crypto.core.metadata import (
    AlgorithmMetadata,
    AlgorithmCategory,
    SecurityLevel,
    FloppyFriendly,
    ImplementationStatus,
)
from src.security.crypto.core.exceptions import (
    KeyGenerationError,
    CryptoError,
    InvalidKeyError,
    AlgorithmNotSupportedError,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# CONSTANTS
# ==============================================================================

# Classical ECDH key sizes
X25519_KEY_SIZE = 32  # bytes
X448_KEY_SIZE = 56  # bytes
P256_KEY_SIZE = 32  # bytes (coordinate)
P384_KEY_SIZE = 48  # bytes
P521_KEY_SIZE = 66  # bytes

# ML-KEM key sizes (FIPS 203)
MLKEM512_PUBLIC_KEY_SIZE = 800  # bytes
MLKEM512_PRIVATE_KEY_SIZE = 1632  # bytes
MLKEM512_CIPHERTEXT_SIZE = 768  # bytes

MLKEM768_PUBLIC_KEY_SIZE = 1184  # bytes
MLKEM768_PRIVATE_KEY_SIZE = 2400  # bytes
MLKEM768_CIPHERTEXT_SIZE = 1088  # bytes

MLKEM1024_PUBLIC_KEY_SIZE = 1568  # bytes
MLKEM1024_PRIVATE_KEY_SIZE = 3168  # bytes
MLKEM1024_CIPHERTEXT_SIZE = 1568  # bytes

# Shared secret size (uniform across all algorithms)
SHARED_SECRET_SIZE = 32  # bytes (256 bits)


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================


def _ensure_bytes(value: bytes, name: str) -> None:
    """
    Проверить, что значение является bytes.

    Args:
        value: Значение для проверки
        name: Имя параметра (для сообщения об ошибке)

    Raises:
        TypeError: Если value не является bytes
    """
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes, got {type(value).__name__}")


def _validate_key_size(
    key: bytes, expected_size: int, key_name: str, algorithm: str
) -> None:
    """
    Проверить размер ключа.

    Args:
        key: Ключ для проверки
        expected_size: Ожидаемый размер в байтах
        key_name: Имя ключа (для сообщения об ошибке)
        algorithm: Имя алгоритма (для сообщения об ошибке)

    Raises:
        InvalidKeyError: Если размер ключа неверен
    """
    if len(key) != expected_size:
        raise InvalidKeyError(
            f"{algorithm} {key_name} must be {expected_size} bytes, "
            f"got {len(key)} bytes"
        )


# ==============================================================================
# BASE CLASSES
# ==============================================================================


class _DHKeyExchangeBase(KeyExchangeProtocol):
    """
    Базовый класс для Diffie-Hellman based key exchange.

    Реализует общую логику для ECDH алгоритмов (X25519, X448, P-256, P-384, P-521).
    """

    ALGORITHM_NAME: str
    KEY_SIZE: int
    SHARED_SECRET_SIZE: int = SHARED_SECRET_SIZE

    def __init__(self) -> None:
        """Инициализировать DH key exchange."""
        self._logger = logger.getChild(self.ALGORITHM_NAME.lower())

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Генерация пары ключей."""
        ...

    @abstractmethod
    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """Вывести shared secret из своего private key и peer public key."""
        ...


class _KEMBase(KeyExchangeProtocol):
    """
    Базовый класс для Key Encapsulation Mechanisms (KEM).

    Реализует общую логику для PQC KEM алгоритмов (ML-KEM-512/768/1024).

    Note:
        KEM отличается от DH:
        - DH: обе стороны обмениваются ключами, выводят shared secret симметрично
        - KEM: отправитель encapsulates (создаёт ciphertext + shared secret),
               получатель decapsulates (извлекает shared secret из ciphertext)
    """

    ALGORITHM_NAME: str
    _OQS_NAME: str  # Name in liboqs library
    PUBLIC_KEY_SIZE: int
    PRIVATE_KEY_SIZE: int
    CIPHERTEXT_SIZE: int
    SHARED_SECRET_SIZE: int = SHARED_SECRET_SIZE

    def __init__(self) -> None:
        """Инициализировать KEM."""
        self._logger = logger.getChild(self.ALGORITHM_NAME.lower())

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Генерация пары ключей KEM."""
        ...

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate: создать ciphertext и shared secret.

        Args:
            public_key: Публичный ключ получателя

        Returns:
            (ciphertext, shared_secret):
                - ciphertext: передать получателю
                - shared_secret: использовать для шифрования
        """
        ...

    @abstractmethod
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate: извлечь shared secret из ciphertext.

        Args:
            private_key: Свой приватный ключ
            ciphertext: Ciphertext от отправителя

        Returns:
            Shared secret
        """
        ...

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """
        Унифицированный интерфейс для KeyExchangeProtocol.

        Для KEM это означает encapsulate с peer_public_key.

        ⚠️ NOTE: Этот метод возвращает только shared_secret, теряя ciphertext.
        Для полноценного использования KEM используйте encapsulate/decapsulate!
        Этот метод предназначен только для совместимости с DH-based KEX.

        Args:
            private_key: Не используется для KEM (оставлен для совместимости)
            peer_public_key: Публичный ключ для encapsulation

        Returns:
            Shared secret (без ciphertext)
        """
        _, shared_secret = self.encapsulate(peer_public_key)
        return shared_secret


# ==============================================================================
# CLASSICAL KEY EXCHANGE (ECDH)
# ==============================================================================


class X25519KeyExchange(_DHKeyExchangeBase):
    """
    X25519 — Elliptic Curve Diffie-Hellman на Curve25519.

    X25519 — это функция ключевого обмена на основе эллиптической кривой
    Curve25519 (Montgomery curve). Это де-факто стандарт для современных
    протоколов (TLS 1.3, SSH, Signal).

    Параметры:
        - Кривая: Curve25519 (y² = x³ + 486662x² + x)
        - Key size: 32 байта (256 бит)
        - Shared secret: 32 байта
        - Security: ~128 бит (эквивалент AES-128)

    Security Features:
        - Constant-time implementation (защита от timing attacks)
        - No point validation needed (безопасна по дизайну)
        - Perfect forward secrecy (при использовании ephemeral keys)
        - Resistant to most side-channel attacks

    Performance:
        - Key generation: ~10 μs
        - Key exchange: ~50 μs (~50,000 ops/sec)
        - Fastest среди всех ECDH curves

    Use Cases:
        - TLS 1.3 (default key exchange)
        - SSH (OpenSSH 6.5+)
        - Signal Protocol (messaging)
        - WireGuard VPN
        - General-purpose secure communication

    Compliance:
        - RFC 7748: Elliptic Curves for Security
        - NIST SP 800-56A Rev. 3: Key Establishment

    References:
        - RFC 7748: https://tools.ietf.org/html/rfc7748
        - Curve25519: https://cr.yp.to/ecdh.html

    Example:
        >>> # Алиса и Боб хотят установить shared secret
        >>> kex = X25519KeyExchange()
        >>>
        >>> # Алиса генерирует keypair
        >>> priv_alice, pub_alice = kex.generate_keypair()
        >>>
        >>> # Боб генерирует keypair
        >>> priv_bob, pub_bob = kex.generate_keypair()
        >>>
        >>> # Обмен публичными ключами (по открытому каналу)
        >>> # Алиса отправляет pub_alice → Бобу
        >>> # Боб отправляет pub_bob → Алисе
        >>>
        >>> # Алиса вычисляет shared secret
        >>> shared_alice = kex.derive_shared_secret(priv_alice, pub_bob)
        >>>
        >>> # Боб вычисляет shared secret
        >>> shared_bob = kex.derive_shared_secret(priv_bob, pub_alice)
        >>>
        >>> # Shared secrets совпадают
        >>> assert shared_alice == shared_bob
        >>>
        >>> # Теперь можно использовать для симметричного шифрования
        >>> # (обычно через KDF: HKDF-SHA256)
    """

    ALGORITHM_NAME = "X25519"
    KEY_SIZE = X25519_KEY_SIZE
    SHARED_SECRET_SIZE = SHARED_SECRET_SIZE

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Сгенерировать новую пару ключей X25519.

        Returns:
            Кортеж (private_key, public_key) в raw binary формате (32 байта каждый)

        Raises:
            KeyGenerationError: При ошибке генерации ключей

        Security Note:
            - Использует cryptographically secure random (os.urandom)
            - Private key автоматически "clamped" (биты 0,1,2,255 фиксированы)
            - Public key вычисляется как scalar multiplication базовой точки
        """
        try:
            self._logger.debug("Generating X25519 keypair...")

            # Generate private key
            private_key_obj = x25519.X25519PrivateKey.generate()
            public_key_obj = private_key_obj.public_key()

            # Serialize to raw bytes (32 bytes each)
            private_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            self._logger.debug(
                f"Generated X25519 keypair: "
                f"private={len(private_bytes)}B, public={len(public_bytes)}B"
            )

            return private_bytes, public_bytes

        except Exception as exc:
            self._logger.error(f"X25519 key generation failed: {exc}", exc_info=True)
            raise KeyGenerationError("X25519 key generation failed") from exc

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """
        Вывести shared secret с помощью X25519 ECDH.

        Args:
            private_key: Свой приватный ключ (32 байта)
            peer_public_key: Публичный ключ партнёра (32 байта)

        Returns:
            Shared secret (32 байта)

        Raises:
            TypeError: Если ключи не являются bytes
            InvalidKeyError: Если размер ключей неверен
            CryptoError: Если ECDH не удался

        Security Note:
            - Операция constant-time (защита от timing attacks)
            - Shared secret детерминирован (для одних ключей всегда одинаковый)
            - НЕ используйте shared secret напрямую как ключ шифрования!
              Пропустите через KDF (HKDF-SHA256)
        """
        # Zero Trust: validate all inputs
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(peer_public_key, "peer_public_key")
        _validate_key_size(private_key, self.KEY_SIZE, "private_key", "X25519")
        _validate_key_size(peer_public_key, self.KEY_SIZE, "public_key", "X25519")

        try:
            # Deserialize keys
            private_key_obj = x25519.X25519PrivateKey.from_private_bytes(private_key)
            peer_public_key_obj = x25519.X25519PublicKey.from_public_bytes(
                peer_public_key
            )

            # Perform ECDH
            shared_secret = private_key_obj.exchange(peer_public_key_obj)

            self._logger.debug(
                f"X25519 ECDH: derived {len(shared_secret)}B shared secret"
            )

            return shared_secret

        except (TypeError, InvalidKeyError):
            raise
        except Exception as exc:
            self._logger.error(f"X25519 key exchange failed: {exc}", exc_info=True)
            raise CryptoError("X25519 key exchange failed") from exc


class X448KeyExchange(_DHKeyExchangeBase):
    """
    X448 — Elliptic Curve Diffie-Hellman на Curve448.

    X448 — это функция ключевого обмена на основе эллиптической кривой
    Curve448 (Edwards curve). Обеспечивает более высокий уровень безопасности
    по сравнению с X25519 за счёт больших ключей.

    Параметры:
        - Кривая: Curve448 (Edwards curve)
        - Key size: 56 байт (448 бит)
        - Shared secret: 56 байт
        - Security: ~224 бит (paranoid level)

    Performance:
        - Slower than X25519 (~20,000 ops/sec vs ~50,000)
        - Still very fast for most use cases

    Use Cases:
        - Ultra-high security requirements
        - Long-term key protection
        - Paranoid security posture

    Compliance:
        - RFC 7748: Elliptic Curves for Security

    Example:
        >>> kex = X448KeyExchange()
        >>> priv_a, pub_a = kex.generate_keypair()
        >>> priv_b, pub_b = kex.generate_keypair()
        >>> shared_a = kex.derive_shared_secret(priv_a, pub_b)
        >>> shared_b = kex.derive_shared_secret(priv_b, pub_a)
        >>> assert shared_a == shared_b
    """

    ALGORITHM_NAME = "X448"
    KEY_SIZE = X448_KEY_SIZE
    SHARED_SECRET_SIZE = X448_KEY_SIZE  # X448 uses 56-byte shared secret

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Сгенерировать новую пару ключей X448."""
        try:
            self._logger.debug("Generating X448 keypair...")

            private_key_obj = x448.X448PrivateKey.generate()
            public_key_obj = private_key_obj.public_key()

            private_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            self._logger.debug(
                f"Generated X448 keypair: "
                f"private={len(private_bytes)}B, public={len(public_bytes)}B"
            )

            return private_bytes, public_bytes

        except Exception as exc:
            self._logger.error(f"X448 key generation failed: {exc}", exc_info=True)
            raise KeyGenerationError("X448 key generation failed") from exc

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """Вывести shared secret с помощью X448 ECDH."""
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(peer_public_key, "peer_public_key")
        _validate_key_size(private_key, self.KEY_SIZE, "private_key", "X448")
        _validate_key_size(peer_public_key, self.KEY_SIZE, "public_key", "X448")

        try:
            private_key_obj = x448.X448PrivateKey.from_private_bytes(private_key)
            peer_public_key_obj = x448.X448PublicKey.from_public_bytes(peer_public_key)

            shared_secret = private_key_obj.exchange(peer_public_key_obj)

            self._logger.debug(
                f"X448 ECDH: derived {len(shared_secret)}B shared secret"
            )

            return shared_secret

        except (TypeError, InvalidKeyError):
            raise
        except Exception as exc:
            self._logger.error(f"X448 key exchange failed: {exc}", exc_info=True)
            raise CryptoError("X448 key exchange failed") from exc


class ECDHP256KeyExchange(_DHKeyExchangeBase):
    """
    ECDH-P256 — Elliptic Curve Diffie-Hellman на secp256r1 (NIST P-256).

    P-256 — это NIST стандартизированная эллиптическая кривая, широко
    используемая в enterprise и government системах.

    Параметры:
        - Кривая: secp256r1 (NIST P-256, prime256v1)
        - Key size: 32 байта (256 бит, координата)
        - Shared secret: 32 байта
        - Security: ~128 бит (эквивалент AES-128)

    Performance:
        - Slower than X25519 (~30,000 ops/sec vs ~50,000)
        - Requires point validation

    Use Cases:
        - NIST/FIPS compliance required
        - Government systems
        - Enterprise PKI
        - TLS (widely supported)

    Compliance:
        - NIST SP 800-56A: Key Establishment
        - FIPS 186-4: Digital Signature Standard
        - NSA Suite B Cryptography

    Example:
        >>> kex = ECDHP256KeyExchange()
        >>> priv_a, pub_a = kex.generate_keypair()
        >>> priv_b, pub_b = kex.generate_keypair()
        >>> shared_a = kex.derive_shared_secret(priv_a, pub_b)
        >>> shared_b = kex.derive_shared_secret(priv_b, pub_a)
        >>> assert shared_a == shared_b
    """

    ALGORITHM_NAME = "ECDH-P256"
    KEY_SIZE = P256_KEY_SIZE
    SHARED_SECRET_SIZE = SHARED_SECRET_SIZE

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Сгенерировать новую пару ключей ECDH-P256."""
        try:
            self._logger.debug("Generating ECDH-P256 keypair...")

            private_key_obj = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key_obj = private_key_obj.public_key()

            # Serialize private key (DER format, PKCS#8)
            private_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            # Serialize public key (DER format, SubjectPublicKeyInfo)
            public_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            self._logger.debug(
                f"Generated ECDH-P256 keypair: "
                f"private={len(private_bytes)}B, public={len(public_bytes)}B"
            )

            return private_bytes, public_bytes

        except Exception as exc:
            self._logger.error(f"ECDH-P256 key generation failed: {exc}", exc_info=True)
            raise KeyGenerationError("ECDH-P256 key generation failed") from exc

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """Вывести shared secret с помощью ECDH-P256."""
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(peer_public_key, "peer_public_key")

        try:
            # Deserialize keys from DER
            private_key_obj = serialization.load_der_private_key(
                private_key, password=None, backend=default_backend()
            )
            peer_public_key_obj = serialization.load_der_public_key(
                peer_public_key, backend=default_backend()
            )

            # Validate key types
            if not isinstance(private_key_obj, ec.EllipticCurvePrivateKey):
                raise InvalidKeyError("Private key must be EC private key")
            if not isinstance(peer_public_key_obj, ec.EllipticCurvePublicKey):
                raise InvalidKeyError("Public key must be EC public key")

            # Perform ECDH
            shared_secret = private_key_obj.exchange(ec.ECDH(), peer_public_key_obj)

            self._logger.debug(
                f"ECDH-P256: derived {len(shared_secret)}B shared secret"
            )

            return shared_secret

        except (TypeError, InvalidKeyError):
            raise
        except Exception as exc:
            self._logger.error(f"ECDH-P256 key exchange failed: {exc}", exc_info=True)
            raise CryptoError("ECDH-P256 key exchange failed") from exc


class ECDHP384KeyExchange(_DHKeyExchangeBase):
    """
    ECDH-P384 — Elliptic Curve Diffie-Hellman на secp384r1 (NIST P-384).

    P-384 обеспечивает более высокий уровень безопасности по сравнению с P-256.

    Параметры:
        - Кривая: secp384r1 (NIST P-384)
        - Key size: 48 байт (384 бит)
        - Shared secret: 48 байт
        - Security: ~192 бит

    Compliance:
        - NSA Suite B Cryptography (TOP SECRET)
        - NIST SP 800-56A

    Example:
        >>> kex = ECDHP384KeyExchange()
        >>> priv_a, pub_a = kex.generate_keypair()
        >>> priv_b, pub_b = kex.generate_keypair()
        >>> shared = kex.derive_shared_secret(priv_a, pub_b)
    """

    ALGORITHM_NAME = "ECDH-P384"
    KEY_SIZE = P384_KEY_SIZE
    SHARED_SECRET_SIZE = P384_KEY_SIZE  # P-384 uses 48-byte shared secret

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Сгенерировать новую пару ключей ECDH-P384."""
        try:
            self._logger.debug("Generating ECDH-P384 keypair...")

            private_key_obj = ec.generate_private_key(ec.SECP384R1(), default_backend())
            public_key_obj = private_key_obj.public_key()

            private_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            self._logger.debug(
                f"Generated ECDH-P384 keypair: "
                f"private={len(private_bytes)}B, public={len(public_bytes)}B"
            )

            return private_bytes, public_bytes

        except Exception as exc:
            self._logger.error(f"ECDH-P384 key generation failed: {exc}", exc_info=True)
            raise KeyGenerationError("ECDH-P384 key generation failed") from exc

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """Вывести shared secret с помощью ECDH-P384."""
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(peer_public_key, "peer_public_key")

        try:
            private_key_obj = serialization.load_der_private_key(
                private_key, password=None, backend=default_backend()
            )
            peer_public_key_obj = serialization.load_der_public_key(
                peer_public_key, backend=default_backend()
            )

            if not isinstance(private_key_obj, ec.EllipticCurvePrivateKey):
                raise InvalidKeyError("Private key must be EC private key")
            if not isinstance(peer_public_key_obj, ec.EllipticCurvePublicKey):
                raise InvalidKeyError("Public key must be EC public key")

            shared_secret = private_key_obj.exchange(ec.ECDH(), peer_public_key_obj)

            self._logger.debug(
                f"ECDH-P384: derived {len(shared_secret)}B shared secret"
            )

            return shared_secret

        except (TypeError, InvalidKeyError):
            raise
        except Exception as exc:
            self._logger.error(f"ECDH-P384 key exchange failed: {exc}", exc_info=True)
            raise CryptoError("ECDH-P384 key exchange failed") from exc


class ECDHP521KeyExchange(_DHKeyExchangeBase):
    """
    ECDH-P521 — Elliptic Curve Diffie-Hellman на secp521r1 (NIST P-521).

    P-521 обеспечивает максимальный уровень классической безопасности
    среди NIST curves.

    Параметры:
        - Кривая: secp521r1 (NIST P-521)
        - Key size: 66 байт (521 бит, не 512!)
        - Shared secret: 66 байт
        - Security: ~256 бит (paranoid level)

    Compliance:
        - NIST SP 800-56A

    Example:
        >>> kex = ECDHP521KeyExchange()
        >>> priv_a, pub_a = kex.generate_keypair()
        >>> priv_b, pub_b = kex.generate_keypair()
        >>> shared = kex.derive_shared_secret(priv_a, pub_b)
    """

    ALGORITHM_NAME = "ECDH-P521"
    KEY_SIZE = P521_KEY_SIZE
    SHARED_SECRET_SIZE = P521_KEY_SIZE  # P-521 uses 66-byte shared secret

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Сгенерировать новую пару ключей ECDH-P521."""
        try:
            self._logger.debug("Generating ECDH-P521 keypair...")

            private_key_obj = ec.generate_private_key(ec.SECP521R1(), default_backend())
            public_key_obj = private_key_obj.public_key()

            private_bytes = private_key_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_bytes = public_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            self._logger.debug(
                f"Generated ECDH-P521 keypair: "
                f"private={len(private_bytes)}B, public={len(public_bytes)}B"
            )

            return private_bytes, public_bytes

        except Exception as exc:
            self._logger.error(f"ECDH-P521 key generation failed: {exc}", exc_info=True)
            raise KeyGenerationError("ECDH-P521 key generation failed") from exc

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        """Вывести shared secret с помощью ECDH-P521."""
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(peer_public_key, "peer_public_key")

        try:
            private_key_obj = serialization.load_der_private_key(
                private_key, password=None, backend=default_backend()
            )
            peer_public_key_obj = serialization.load_der_public_key(
                peer_public_key, backend=default_backend()
            )

            if not isinstance(private_key_obj, ec.EllipticCurvePrivateKey):
                raise InvalidKeyError("Private key must be EC private key")
            if not isinstance(peer_public_key_obj, ec.EllipticCurvePublicKey):
                raise InvalidKeyError("Public key must be EC public key")

            shared_secret = private_key_obj.exchange(ec.ECDH(), peer_public_key_obj)

            self._logger.debug(
                f"ECDH-P521: derived {len(shared_secret)}B shared secret"
            )

            return shared_secret

        except (TypeError, InvalidKeyError):
            raise
        except Exception as exc:
            self._logger.error(f"ECDH-P521 key exchange failed: {exc}", exc_info=True)
            raise CryptoError("ECDH-P521 key exchange failed") from exc


# ==============================================================================
# POST-QUANTUM KEM (ML-KEM / FIPS 203)
# ==============================================================================


class MLKEM512(_KEMBase):
    """
    ML-KEM-512 — Module-Lattice-Based KEM (NIST FIPS 203).

    ML-KEM-512 — это post-quantum алгоритм key encapsulation на основе
    lattice-based криптографии (Module-LWE).

    Параметры:
        - Type: Post-Quantum Key Encapsulation Mechanism
        - Базис: Module-LWE (lattice-based)
        - Уровень безопасности: NIST Level 1 (128-bit quantum security)
        - Размер ключей: public=800 B, private=1,632 B
        - Размер ciphertext: 768 B
        - Shared secret: 32 байта

    Migration Note:
        - Заменяет Kyber512 (NIST Round 3)
        - Несовместим с Kyber512 (другие параметры)
        - Требуется liboqs-python >= 0.15.0

    Performance:
        - Encapsulation: ~200 μs (~5,000 ops/sec)
        - Decapsulation: ~250 μs (~4,000 ops/sec)
        - Slower than classical ECDH (~100x)

    Use Cases:
        - Quantum-resistant key exchange
        - Hybrid KEX (classical + PQC)
        - IoT devices (smallest PQC KEM)
        - Resource-constrained environments

    Compliance:
        - FIPS 203: Module-Lattice-Based KEM Standard
        - NIST PQC Standardization (winner)

    References:
        - FIPS 203: https://csrc.nist.gov/pubs/fips/203/final

    Example:
        >>> # Сторона B (receiver)
        >>> kem = MLKEM512()
        >>> priv_b, pub_b = kem.generate_keypair()
        >>>
        >>> # Сторона A (sender) - encapsulate
        >>> ciphertext, shared_a = kem.encapsulate(pub_b)
        >>>
        >>> # Сторона B (receiver) - decapsulate
        >>> shared_b = kem.decapsulate(priv_b, ciphertext)
        >>>
        >>> assert shared_a == shared_b
    """

    ALGORITHM_NAME = "ML-KEM-512"
    _OQS_NAME = "ML-KEM-512"  # ⚠️ NOT "Kyber512"!
    PUBLIC_KEY_SIZE = MLKEM512_PUBLIC_KEY_SIZE
    PRIVATE_KEY_SIZE = MLKEM512_PRIVATE_KEY_SIZE
    CIPHERTEXT_SIZE = MLKEM512_CIPHERTEXT_SIZE
    SHARED_SECRET_SIZE = SHARED_SECRET_SIZE

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Генерация ML-KEM-512 keypair."""
        try:
            self._logger.debug("Generating ML-KEM-512 keypair...")

            try:
                import oqs
            except ImportError as exc:
                raise AlgorithmNotSupportedError(
                    algorithm=self._OQS_NAME,
                    reason="liboqs-python not installed",
                    required_library="liboqs-python>=0.15.0",
                ) from exc

            with oqs.KeyEncapsulation(self._OQS_NAME) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()

                self._logger.debug(
                    f"Generated ML-KEM-512 keypair: "
                    f"private={len(private_key)}B, public={len(public_key)}B"
                )

                return private_key, public_key

        except oqs.MechanismNotSupportedError as exc:
            raise AlgorithmNotSupportedError(
                algorithm=self._OQS_NAME,
                reason="Algorithm not available in liboqs",
                required_library="liboqs-python>=0.15.0",
            ) from exc
        except AlgorithmNotSupportedError:
            raise
        except Exception as exc:
            self._logger.error(f"ML-KEM-512 keygen failed: {exc}", exc_info=True)
            raise KeyGenerationError("ML-KEM-512 keygen failed") from exc

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate: создать ciphertext и shared secret.

        Args:
            public_key: Публичный ключ получателя (800 байт)

        Returns:
            (ciphertext, shared_secret):
                - ciphertext: 768 байт (передать получателю)
                - shared_secret: 32 байта (использовать для шифрования)

        Raises:
            TypeError: Если public_key не bytes
            InvalidKeyError: Если размер ключа неверен
            CryptoError: Если encapsulation не удался
        """
        _ensure_bytes(public_key, "public_key")
        _validate_key_size(public_key, self.PUBLIC_KEY_SIZE, "public_key", "ML-KEM-512")

        try:
            import oqs

            with oqs.KeyEncapsulation(self._OQS_NAME) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)

                self._logger.debug(
                    f"ML-KEM-512 encapsulation: "
                    f"ciphertext={len(ciphertext)}B, shared={len(shared_secret)}B"
                )

                return ciphertext, shared_secret

        except Exception as exc:
            self._logger.error(f"ML-KEM-512 encapsulation failed: {exc}", exc_info=True)
            raise CryptoError("ML-KEM-512 encapsulation failed") from exc

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate: извлечь shared secret из ciphertext.

        Args:
            private_key: Свой приватный ключ (1,632 байта)
            ciphertext: Ciphertext от отправителя (768 байт)

        Returns:
            Shared secret (32 байта)

        Raises:
            TypeError: Если ключи не bytes
            InvalidKeyError: Если размер неверен
            CryptoError: Если decapsulation не удался
        """
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(ciphertext, "ciphertext")
        _validate_key_size(
            private_key, self.PRIVATE_KEY_SIZE, "private_key", "ML-KEM-512"
        )
        _validate_key_size(ciphertext, self.CIPHERTEXT_SIZE, "ciphertext", "ML-KEM-512")

        try:
            import oqs

            # ⚠️ NEW API (liboqs 0.15+): pass secret_key in constructor
            with oqs.KeyEncapsulation(self._OQS_NAME, secret_key=private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)

                self._logger.debug(
                    f"ML-KEM-512 decapsulation: shared={len(shared_secret)}B"
                )

                return bytes(shared_secret)

        except Exception as exc:
            self._logger.error(f"ML-KEM-512 decapsulation failed: {exc}", exc_info=True)
            raise CryptoError("ML-KEM-512 decapsulation failed") from exc


class MLKEM768(_KEMBase):
    """
    ML-KEM-768 — Module-Lattice-Based KEM (NIST FIPS 203).

    ML-KEM-768 — это РЕКОМЕНДУЕМЫЙ post-quantum алгоритм KEM,
    обеспечивающий баланс между безопасностью и производительностью.

    Параметры:
        - Type: Post-Quantum Key Encapsulation Mechanism
        - Базис: Module-LWE (lattice-based)
        - Уровень безопасности: NIST Level 3 (192-bit quantum security)
        - Размер ключей: public=1,184 B, private=2,400 B
        - Размер ciphertext: 1,088 B
        - Shared secret: 32 байта

    Migration Note:
        - Заменяет Kyber768 (NIST Round 3)
        - Несовместим с Kyber768 (другие параметры)
        - Требуется liboqs-python >= 0.15.0

    Performance:
        - Encapsulation: ~300 μs (~3,000 ops/sec)
        - Decapsulation: ~350 μs (~2,800 ops/sec)

    Use Cases:
        - Default PQC key exchange (recommended)
        - Hybrid KEX (X25519 + ML-KEM-768)
        - TLS 1.3 post-quantum extensions
        - General-purpose quantum-resistant communication

    Compliance:
        - FIPS 203: Module-Lattice-Based KEM Standard

    Example:
        >>> kem = MLKEM768()
        >>> priv_b, pub_b = kem.generate_keypair()
        >>> ct, shared_a = kem.encapsulate(pub_b)
        >>> shared_b = kem.decapsulate(priv_b, ct)
        >>> assert shared_a == shared_b
    """

    ALGORITHM_NAME = "ML-KEM-768"
    _OQS_NAME = "ML-KEM-768"  # ⚠️ NOT "Kyber768"!
    PUBLIC_KEY_SIZE = MLKEM768_PUBLIC_KEY_SIZE
    PRIVATE_KEY_SIZE = MLKEM768_PRIVATE_KEY_SIZE
    CIPHERTEXT_SIZE = MLKEM768_CIPHERTEXT_SIZE
    SHARED_SECRET_SIZE = SHARED_SECRET_SIZE

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Генерация ML-KEM-768 keypair."""
        try:
            self._logger.debug("Generating ML-KEM-768 keypair...")

            try:
                import oqs
            except ImportError as exc:
                raise AlgorithmNotSupportedError(
                    algorithm=self._OQS_NAME,
                    reason="Algorithm not available in liboqs",
                    required_library="liboqs-python>=0.15.0",
                ) from exc

            with oqs.KeyEncapsulation(self._OQS_NAME) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()

                self._logger.debug(
                    f"Generated ML-KEM-768 keypair: "
                    f"private={len(private_key)}B, public={len(public_key)}B"
                )

                return private_key, public_key

        except oqs.MechanismNotSupportedError as exc:
            raise AlgorithmNotSupportedError(
                algorithm=self._OQS_NAME,
                reason="Algorithm not available in liboqs",
                required_library="liboqs-python>=0.15.0",
            ) from exc
        except AlgorithmNotSupportedError:
            raise
        except Exception as exc:
            self._logger.error(f"ML-KEM-768 keygen failed: {exc}", exc_info=True)
            raise KeyGenerationError("ML-KEM-768 keygen failed") from exc

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate с ML-KEM-768."""
        _ensure_bytes(public_key, "public_key")
        _validate_key_size(public_key, self.PUBLIC_KEY_SIZE, "public_key", "ML-KEM-768")

        try:
            import oqs

            with oqs.KeyEncapsulation(self._OQS_NAME) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)

                self._logger.debug(
                    f"ML-KEM-768 encapsulation: "
                    f"ciphertext={len(ciphertext)}B, shared={len(shared_secret)}B"
                )

                return ciphertext, shared_secret

        except Exception as exc:
            self._logger.error(f"ML-KEM-768 encapsulation failed: {exc}", exc_info=True)
            raise CryptoError("ML-KEM-768 encapsulation failed") from exc

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate с ML-KEM-768."""
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(ciphertext, "ciphertext")
        _validate_key_size(
            private_key, self.PRIVATE_KEY_SIZE, "private_key", "ML-KEM-768"
        )
        _validate_key_size(ciphertext, self.CIPHERTEXT_SIZE, "ciphertext", "ML-KEM-768")

        try:
            import oqs

            with oqs.KeyEncapsulation(self._OQS_NAME, secret_key=private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)

                self._logger.debug(
                    f"ML-KEM-768 decapsulation: shared={len(shared_secret)}B"
                )

                return bytes(shared_secret)

        except Exception as exc:
            self._logger.error(f"ML-KEM-768 decapsulation failed: {exc}", exc_info=True)
            raise CryptoError("ML-KEM-768 decapsulation failed") from exc


class MLKEM1024(_KEMBase):
    """
    ML-KEM-1024 — Module-Lattice-Based KEM (NIST FIPS 203).

    ML-KEM-1024 обеспечивает максимальный уровень post-quantum безопасности.

    Параметры:
        - Type: Post-Quantum Key Encapsulation Mechanism
        - Базис: Module-LWE (lattice-based)
        - Уровень безопасности: NIST Level 5 (256-bit quantum security)
        - Размер ключей: public=1,568 B, private=3,168 B
        - Размер ciphertext: 1,568 B
        - Shared secret: 32 байта

    Migration Note:
        - Заменяет Kyber1024 (NIST Round 3)
        - Несовместим с Kyber1024
        - Требуется liboqs-python >= 0.15.0

    Performance:
        - Encapsulation: ~500 μs (~2,000 ops/sec)
        - Decapsulation: ~600 μs (~1,600 ops/sec)
        - Slowest among ML-KEM variants

    Use Cases:
        - Ultra-high quantum security requirements
        - Long-term data protection (20+ years)
        - Paranoid security posture
        - Government/military applications

    Compliance:
        - FIPS 203: Module-Lattice-Based KEM Standard

    Example:
        >>> kem = MLKEM1024()
        >>> priv_b, pub_b = kem.generate_keypair()
        >>> ct, shared_a = kem.encapsulate(pub_b)
        >>> shared_b = kem.decapsulate(priv_b, ct)
        >>> assert shared_a == shared_b
    """

    ALGORITHM_NAME = "ML-KEM-1024"
    _OQS_NAME = "ML-KEM-1024"  # ⚠️ NOT "Kyber1024"!
    PUBLIC_KEY_SIZE = MLKEM1024_PUBLIC_KEY_SIZE
    PRIVATE_KEY_SIZE = MLKEM1024_PRIVATE_KEY_SIZE
    CIPHERTEXT_SIZE = MLKEM1024_CIPHERTEXT_SIZE
    SHARED_SECRET_SIZE = SHARED_SECRET_SIZE

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Генерация ML-KEM-1024 keypair."""
        try:
            self._logger.debug("Generating ML-KEM-1024 keypair...")

            try:
                import oqs
            except ImportError as exc:
                raise AlgorithmNotSupportedError(
                    algorithm=self._OQS_NAME,
                    reason="liboqs-python not installed",
                    required_library="liboqs-python>=0.15.0",
                ) from exc

            with oqs.KeyEncapsulation(self._OQS_NAME) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()

                self._logger.debug(
                    f"Generated ML-KEM-1024 keypair: "
                    f"private={len(private_key)}B, public={len(public_key)}B"
                )

                return private_key, public_key

        except oqs.MechanismNotSupportedError as exc:
            raise AlgorithmNotSupportedError(
                algorithm=self._OQS_NAME,
                reason="Algorithm not available in liboqs",
                required_library="liboqs-python>=0.15.0",
            ) from exc
        except AlgorithmNotSupportedError:
            raise
        except Exception as exc:
            self._logger.error(f"ML-KEM-1024 keygen failed: {exc}", exc_info=True)
            raise KeyGenerationError("ML-KEM-1024 keygen failed") from exc

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate с ML-KEM-1024."""
        _ensure_bytes(public_key, "public_key")
        _validate_key_size(
            public_key, self.PUBLIC_KEY_SIZE, "public_key", "ML-KEM-1024"
        )

        try:
            import oqs

            with oqs.KeyEncapsulation(self._OQS_NAME) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)

                self._logger.debug(
                    f"ML-KEM-1024 encapsulation: "
                    f"ciphertext={len(ciphertext)}B, shared={len(shared_secret)}B"
                )

                return ciphertext, shared_secret

        except Exception as exc:
            self._logger.error(
                f"ML-KEM-1024 encapsulation failed: {exc}", exc_info=True
            )
            raise CryptoError("ML-KEM-1024 encapsulation failed") from exc

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate с ML-KEM-1024."""
        _ensure_bytes(private_key, "private_key")
        _ensure_bytes(ciphertext, "ciphertext")
        _validate_key_size(
            private_key, self.PRIVATE_KEY_SIZE, "private_key", "ML-KEM-1024"
        )
        _validate_key_size(
            ciphertext, self.CIPHERTEXT_SIZE, "ciphertext", "ML-KEM-1024"
        )

        try:
            import oqs

            with oqs.KeyEncapsulation(self._OQS_NAME, secret_key=private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)

                self._logger.debug(
                    f"ML-KEM-1024 decapsulation: shared={len(shared_secret)}B"
                )

                return bytes(shared_secret)

        except Exception as exc:
            self._logger.error(
                f"ML-KEM-1024 decapsulation failed: {exc}", exc_info=True
            )
            raise CryptoError("ML-KEM-1024 decapsulation failed") from exc


# ==============================================================================
# ALGORITHM METADATA
# ==============================================================================

METADATA_X25519 = AlgorithmMetadata(
    name="X25519",
    category=AlgorithmCategory.KEY_EXCHANGE,
    protocol_class=KeyExchangeProtocol,
    library="cryptography",
    implementation_class="X25519KeyExchange",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=256,  # bits
    public_key_size=32,
    private_key_size=32,
    description_ru=(
        "X25519 — Elliptic Curve Diffie-Hellman на Curve25519. "
        "Default key exchange для TLS 1.3. Ultra-fast, constant-time."
    ),
    description_en=(
        "X25519 — Elliptic Curve Diffie-Hellman on Curve25519. "
        "Default key exchange for TLS 1.3. Ultra-fast, constant-time."
    ),
    use_cases=[
        "TLS 1.3 (default)",
        "SSH (modern)",
        "Signal Protocol",
        "WireGuard VPN",
        "General-purpose secure communication",
    ],
    test_vectors_source="RFC 7748",
)

METADATA_X448 = AlgorithmMetadata(
    name="X448",
    category=AlgorithmCategory.KEY_EXCHANGE,
    protocol_class=KeyExchangeProtocol,
    library="cryptography",
    implementation_class="X448KeyExchange",
    security_level=SecurityLevel.HIGH,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=448,  # bits
    public_key_size=56,
    private_key_size=56,
    description_ru=(
        "X448 — Elliptic Curve Diffie-Hellman на Curve448. "
        "Повышенная безопасность (~224 бит). Constant-time."
    ),
    description_en=(
        "X448 — Elliptic Curve Diffie-Hellman on Curve448. "
        "Enhanced security (~224 bits). Constant-time."
    ),
    use_cases=[
        "Ultra-high security requirements",
        "Long-term key protection",
        "Paranoid security posture",
    ],
    test_vectors_source="RFC 7748",
)

METADATA_ECDH_P256 = AlgorithmMetadata(
    name="ECDH-P256",
    category=AlgorithmCategory.KEY_EXCHANGE,
    protocol_class=KeyExchangeProtocol,
    library="cryptography",
    implementation_class="ECDHP256KeyExchange",
    security_level=SecurityLevel.STANDARD,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=256,  # bits
    public_key_size=91,  # DER-encoded
    private_key_size=138,  # DER-encoded PKCS#8
    description_ru=(
        "ECDH-P256 — Elliptic Curve Diffie-Hellman на secp256r1 (NIST P-256). "
        "NIST рекомендуемая кривая. FIPS 186-4."
    ),
    description_en=(
        "ECDH-P256 — Elliptic Curve Diffie-Hellman on secp256r1 (NIST P-256). "
        "NIST recommended curve. FIPS 186-4."
    ),
    use_cases=[
        "NIST/FIPS compliance",
        "Government systems",
        "Enterprise PKI",
        "TLS (widely supported)",
    ],
    test_vectors_source="NIST SP 800-56A",
)

METADATA_ECDH_P384 = AlgorithmMetadata(
    name="ECDH-P384",
    category=AlgorithmCategory.KEY_EXCHANGE,
    protocol_class=KeyExchangeProtocol,
    library="cryptography",
    implementation_class="ECDHP384KeyExchange",
    security_level=SecurityLevel.HIGH,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=384,  # bits
    public_key_size=120,  # DER-encoded
    private_key_size=185,  # DER-encoded PKCS#8
    description_ru=(
        "ECDH-P384 — Elliptic Curve Diffie-Hellman на secp384r1 (NIST P-384). "
        "NSA Suite B Cryptography (TOP SECRET). Security: ~192 бит."
    ),
    description_en=(
        "ECDH-P384 — Elliptic Curve Diffie-Hellman on secp384r1 (NIST P-384). "
        "NSA Suite B Cryptography (TOP SECRET). Security: ~192 bits."
    ),
    use_cases=[
        "NSA Suite B (TOP SECRET)",
        "High-security government",
        "Enterprise compliance",
    ],
    test_vectors_source="NIST SP 800-56A",
)

METADATA_ECDH_P521 = AlgorithmMetadata(
    name="ECDH-P521",
    category=AlgorithmCategory.KEY_EXCHANGE,
    protocol_class=KeyExchangeProtocol,
    library="cryptography",
    implementation_class="ECDHP521KeyExchange",
    security_level=SecurityLevel.HIGH,
    floppy_friendly=FloppyFriendly.EXCELLENT,
    status=ImplementationStatus.STABLE,
    key_size=521,  # bits (not 512!)
    public_key_size=158,  # DER-encoded
    private_key_size=241,  # DER-encoded PKCS#8
    description_ru=(
        "ECDH-P521 — Elliptic Curve Diffie-Hellman на secp521r1 (NIST P-521). "
        "Максимальная классическая безопасность (~256 бит)."
    ),
    description_en=(
        "ECDH-P521 — Elliptic Curve Diffie-Hellman on secp521r1 (NIST P-521). "
        "Maximum classical security (~256 bits)."
    ),
    use_cases=[
        "Maximum classical security",
        "Paranoid security posture",
        "Long-term key protection",
    ],
    test_vectors_source="NIST SP 800-56A",
)

METADATA_MLKEM512 = AlgorithmMetadata(
    name="ML-KEM-512",
    category=AlgorithmCategory.KEY_EXCHANGE,
    protocol_class=KeyExchangeProtocol,
    library="liboqs-python",
    implementation_class="MLKEM512",
    security_level=SecurityLevel.QUANTUM_RESISTANT,  # Post-quantum
    floppy_friendly=FloppyFriendly.POOR,
    status=ImplementationStatus.STABLE,
    key_size=512,  # parameter set (not bits)
    public_key_size=MLKEM512_PUBLIC_KEY_SIZE,
    private_key_size=MLKEM512_PRIVATE_KEY_SIZE,
    is_post_quantum=True,
    description_ru=(
        "ML-KEM-512 — Module-Lattice-Based KEM (FIPS 203). "
        "Заменяет Kyber512. NIST Level 1 (128-bit quantum security). "
        "Стандартизирован в августе 2024."
    ),
    description_en=(
        "ML-KEM-512 — Module-Lattice-Based KEM (FIPS 203). "
        "Replaces Kyber512. NIST Level 1 (128-bit quantum security). "
        "Standardized August 2024."
    ),
    use_cases=[
        "Quantum-resistant key exchange",
        "IoT devices (smallest PQC KEM)",
        "Hybrid KEX (classical + PQC)",
        "Resource-constrained environments",
    ],
    test_vectors_source="FIPS 203",
)

METADATA_MLKEM768 = AlgorithmMetadata(
    name="ML-KEM-768",
    category=AlgorithmCategory.KEY_EXCHANGE,
    protocol_class=KeyExchangeProtocol,
    library="liboqs-python",
    implementation_class="MLKEM768",
    security_level=SecurityLevel.QUANTUM_RESISTANT,  # Post-quantum
    floppy_friendly=FloppyFriendly.POOR,
    status=ImplementationStatus.STABLE,
    key_size=768,  # parameter set
    public_key_size=MLKEM768_PUBLIC_KEY_SIZE,
    private_key_size=MLKEM768_PRIVATE_KEY_SIZE,
    is_post_quantum=True,
    description_ru=(
        "ML-KEM-768 — Module-Lattice-Based KEM (FIPS 203). "
        "Заменяет Kyber768. NIST Level 3 (192-bit quantum security). "
        "РЕКОМЕНДУЕТСЯ как default PQC KEM."
    ),
    description_en=(
        "ML-KEM-768 — Module-Lattice-Based KEM (FIPS 203). "
        "Replaces Kyber768. NIST Level 3 (192-bit quantum security). "
        "RECOMMENDED as default PQC KEM."
    ),
    use_cases=[
        "Default PQC key exchange (recommended)",
        "Hybrid KEX (X25519 + ML-KEM-768)",
        "TLS 1.3 post-quantum extensions",
        "General-purpose quantum-resistant communication",
    ],
    test_vectors_source="FIPS 203",
)

METADATA_MLKEM1024 = AlgorithmMetadata(
    name="ML-KEM-1024",
    category=AlgorithmCategory.KEY_EXCHANGE,
    protocol_class=KeyExchangeProtocol,
    library="liboqs-python",
    implementation_class="MLKEM1024",
    security_level=SecurityLevel.QUANTUM_RESISTANT,  # Post-quantum
    floppy_friendly=FloppyFriendly.POOR,
    status=ImplementationStatus.STABLE,
    key_size=1024,  # parameter set
    public_key_size=MLKEM1024_PUBLIC_KEY_SIZE,
    private_key_size=MLKEM1024_PRIVATE_KEY_SIZE,
    is_post_quantum=True,
    description_ru=(
        "ML-KEM-1024 — Module-Lattice-Based KEM (FIPS 203). "
        "Заменяет Kyber1024. NIST Level 5 (256-bit quantum security). "
        "Максимальная post-quantum безопасность."
    ),
    description_en=(
        "ML-KEM-1024 — Module-Lattice-Based KEM (FIPS 203). "
        "Replaces Kyber1024. NIST Level 5 (256-bit quantum security). "
        "Maximum post-quantum security."
    ),
    use_cases=[
        "Ultra-high quantum security",
        "Long-term data protection (20+ years)",
        "Government/military applications",
        "Paranoid security posture",
    ],
    test_vectors_source="FIPS 203",
)


# ==============================================================================
# REGISTRY
# ==============================================================================

ALL_METADATA: list[AlgorithmMetadata] = [
    # Classical ECDH
    METADATA_X25519,
    METADATA_X448,
    METADATA_ECDH_P256,
    METADATA_ECDH_P384,
    METADATA_ECDH_P521,
    # Post-Quantum KEM (ML-KEM)
    METADATA_MLKEM512,
    METADATA_MLKEM768,
    METADATA_MLKEM1024,
]

KEY_EXCHANGE_ALGORITHMS: dict[str, tuple[Type[object], AlgorithmMetadata]] = {
    # Classical ECDH
    "x25519": (X25519KeyExchange, METADATA_X25519),
    "x448": (X448KeyExchange, METADATA_X448),
    "ecdh-p256": (ECDHP256KeyExchange, METADATA_ECDH_P256),
    "ecdh-p384": (ECDHP384KeyExchange, METADATA_ECDH_P384),
    "ecdh-p521": (ECDHP521KeyExchange, METADATA_ECDH_P521),
    # Post-Quantum KEM (FIPS 203)
    "ml-kem-512": (MLKEM512, METADATA_MLKEM512),
    "ml-kem-768": (MLKEM768, METADATA_MLKEM768),
    "ml-kem-1024": (MLKEM1024, METADATA_MLKEM1024),
}


def get_kex_algorithm(algorithm_id: str) -> KeyExchangeProtocol:
    """
    Получить реализацию алгоритма key exchange по ID.

    Args:
        algorithm_id: ID алгоритма.
            Доступные значения:
            Classical ECDH:
            - "x25519": X25519 (Curve25519, recommended)
            - "x448": X448 (Curve448, paranoid)
            - "ecdh-p256": ECDH-P256 (secp256r1, NIST)
            - "ecdh-p384": ECDH-P384 (secp384r1, NSA Suite B)
            - "ecdh-p521": ECDH-P521 (secp521r1, maximum classical)

            Post-Quantum KEM (ML-KEM):
            - "ml-kem-512": ML-KEM-512 (NIST Level 1)
            - "ml-kem-768": ML-KEM-768 (NIST Level 3, recommended)
            - "ml-kem-1024": ML-KEM-1024 (NIST Level 5, maximum PQC)

    Returns:
        Экземпляр класса, реализующего KeyExchangeProtocol.

    Raises:
        KeyError: Если алгоритм не найден.
        AlgorithmNotSupportedError: Если требуемая библиотека недоступна.

    Example:
        >>> # Classical ECDH
        >>> kex = get_kex_algorithm("x25519")
        >>> priv, pub = kex.generate_keypair()
        >>> shared = kex.derive_shared_secret(priv, peer_pub)

        >>> # Post-Quantum KEM
        >>> kem = get_kex_algorithm("ml-kem-768")
        >>> priv, pub = kem.generate_keypair()
        >>> ct, shared = kem.encapsulate(peer_pub)
        >>> shared = kem.decapsulate(priv, ct)

        >>> # List available algorithms
        >>> from src.security.crypto.algorithms.key_exchange import KEY_EXCHANGE_ALGORITHMS
        >>> print(list(KEY_EXCHANGE_ALGORITHMS.keys()))
    """
    try:
        kex_cls, metadata = KEY_EXCHANGE_ALGORITHMS[algorithm_id]
    except KeyError as exc:
        available = list(KEY_EXCHANGE_ALGORITHMS.keys())
        raise KeyError(
            f"Key exchange algorithm '{algorithm_id}' not found. "
            f"Available: {available}"
        ) from exc

    return kex_cls()  # type: ignore[return-value]


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__ = [
    # Classical ECDH Classes
    "X25519KeyExchange",
    "X448KeyExchange",
    "ECDHP256KeyExchange",
    "ECDHP384KeyExchange",
    "ECDHP521KeyExchange",
    # Post-Quantum KEM Classes
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
    # Metadata
    "METADATA_X25519",
    "METADATA_X448",
    "METADATA_ECDH_P256",
    "METADATA_ECDH_P384",
    "METADATA_ECDH_P521",
    "METADATA_MLKEM512",
    "METADATA_MLKEM768",
    "METADATA_MLKEM1024",
    "ALL_METADATA",
    # Registry
    "KEY_EXCHANGE_ALGORITHMS",
    "get_kex_algorithm",
    # Constants
    "X25519_KEY_SIZE",
    "X448_KEY_SIZE",
    "P256_KEY_SIZE",
    "P384_KEY_SIZE",
    "P521_KEY_SIZE",
    "MLKEM512_PUBLIC_KEY_SIZE",
    "MLKEM512_PRIVATE_KEY_SIZE",
    "MLKEM512_CIPHERTEXT_SIZE",
    "MLKEM768_PUBLIC_KEY_SIZE",
    "MLKEM768_PRIVATE_KEY_SIZE",
    "MLKEM768_CIPHERTEXT_SIZE",
    "MLKEM1024_PUBLIC_KEY_SIZE",
    "MLKEM1024_PRIVATE_KEY_SIZE",
    "MLKEM1024_CIPHERTEXT_SIZE",
    "SHARED_SECRET_SIZE",
]
