"""
Реализация всех 20 алгоритмов цифровых подписей из CRYPTO_MASTER_PLAN v2.3.

Архитектура:
    - 10 классических алгоритмов (Ed25519, Ed448, ECDSA×4, RSA-PSS×3, RSA-PKCS1v15)
    - 8 постквантовых стандартов NIST (ML-DSA×3, Falcon×2, SLH-DSA×3)
    - 2 legacy PQC алгоритма (Dilithium2, SPHINCS+-128s) — DEPRECATED

Обновления стандартов (2024-2026):
    ✅ ML-DSA (FIPS 204) заменяет Dilithium
    ✅ SLH-DSA (FIPS 205) заменяет SPHINCS+

Категории алгоритмов:
    1. EdDSA (Ed25519, Ed448) — fast, compact signatures
    2. ECDSA (P-256, P-384, P-521, secp256k1) — NIST/Bitcoin curves
    3. RSA-PSS (2048, 3072, 4096) — provably secure padding
    4. RSA-PKCS1v15 — legacy, deprecated
    5. ML-DSA (44, 65, 87) — lattice-based PQC (NIST standard)
    6. Falcon (512, 1024) — NTRU-based PQC (NIST finalist)
    7. SLH-DSA (128s, 192s, 256s) — stateless hash-based PQC (NIST standard)

Dependencies:
    - cryptography: классические алгоритмы (Ed25519/Ed448/ECDSA/RSA)
    - liboqs-python: постквантовые алгоритмы (ML-DSA/Falcon/SLH-DSA)

Example:
    >>> from src.security.crypto.algorithms.signing import Ed25519Signer
    >>> from src.security.crypto.core.registry import AlgorithmRegistry
    >>>
    >>> # Способ 1: прямое создание
    >>> signer = Ed25519Signer()
    >>> private_key, public_key = signer.generate_keypair()
    >>> message = b"Important document"
    >>> signature = signer.sign(private_key, message)
    >>> assert signer.verify(public_key, message, signature)
    >>>
    >>> # Способ 2: через реестр (рекомендуется)
    >>> registry = AlgorithmRegistry.get_instance()
    >>> signer = registry.create("Ed25519")
    >>> private_key, public_key = signer.generate_keypair()

Security Notes:
    - НИКОГДА не используйте одну и ту же подпись для разных сообщений
    - Храните приватные ключи в безопасном хранилище (SecureMemory)
    - Для production используйте только STABLE алгоритмы
    - RSA-PKCS1v15 deprecated, используйте RSA-PSS
    - Dilithium/SPHINCS+ deprecated, используйте ML-DSA/SLH-DSA

Performance Guide:
    - Fastest: Ed25519 (10x быстрее RSA-2048)
    - Most compact: Ed25519 (64 bytes signature)
    - Post-quantum: ML-DSA-65 (рекомендуется NIST)
    - Hash-based PQC: SLH-DSA-SHA2-128s (stateless)

Version: 1.0
Date: February 10, 2026
Author: Mike Voyager
Priority: 🔴 CRITICAL (Phase 2 + Phase 4 PQC)
"""

from __future__ import annotations

import logging
from typing import Tuple, Type, cast, Protocol as TypingProtocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    ed25519,
    ed448,
    rsa,
    ec,
    padding as rsa_padding,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_der_private_key,
    load_der_public_key,
)

from src.security.crypto.core.protocols import SignatureProtocol
from src.security.crypto.core.metadata import (
    create_signature_metadata,
    SecurityLevel,
    ImplementationStatus,
    FloppyFriendly,
)
from src.security.crypto.core.registry import AlgorithmRegistry
from src.security.crypto.core.exceptions import (
    SigningFailedError,
    VerificationFailedError,
    KeyGenerationError,
    InvalidKeyError,
    AlgorithmNotSupportedError,
)

logger = logging.getLogger(__name__)


# ==============================================================================
# LIBOQS DETECTION & CONFIGURATION
# ==============================================================================

try:
    import oqs  # type: ignore[import-untyped]

    HAS_LIBOQS = True
    logger.info("liboqs-python detected, PQC signatures available")
except ImportError:
    oqs = None  # type: ignore[assignment]
    HAS_LIBOQS = False
    logger.warning(
        "liboqs-python not installed, post-quantum signatures unavailable. "
        "Install: pip install liboqs-python"
    )


# ==============================================================================
# TYPE ALIASES & PROTOCOLS
# ==============================================================================

# Union типов для ключей cryptography
CryptoPrivateKey = (
    rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
    | ed448.Ed448PrivateKey
)

CryptoPublicKey = (
    rsa.RSAPublicKey
    | ec.EllipticCurvePublicKey
    | ed25519.Ed25519PublicKey
    | ed448.Ed448PublicKey
)


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================


def _encode_private_key_der(key: CryptoPrivateKey) -> bytes:
    """
    Сериализация приватного ключа в DER формат (PKCS#8).

    Args:
        key: Приватный ключ из cryptography

    Returns:
        DER-encoded приватный ключ

    Note:
        Использует PKCS#8 без шифрования для совместимости.
        В production храните ключи в SecureMemory!
    """
    return key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


def _encode_public_key_der(key: CryptoPublicKey) -> bytes:
    """
    Сериализация публичного ключа в DER формат (SubjectPublicKeyInfo).

    Args:
        key: Публичный ключ из cryptography

    Returns:
        DER-encoded публичный ключ
    """
    return key.public_bytes(
        encoding=Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def _load_private_key_der(data: bytes) -> object:
    """
    Загрузка приватного ключа из DER формата.

    Args:
        data: DER-encoded приватный ключ

    Returns:
        Объект приватного ключа

    Raises:
        InvalidKeyError: Некорректный формат ключа
    """
    try:
        return load_der_private_key(data, password=None)
    except Exception as exc:
        raise InvalidKeyError(
            "Invalid private key DER format. "
            "Expected PKCS#8 DER-encoded private key."
        ) from exc


def _load_public_key_der(data: bytes) -> object:
    """
    Загрузка публичного ключа из DER формата.

    Args:
        data: DER-encoded публичный ключ

    Returns:
        Объект публичного ключа

    Raises:
        InvalidKeyError: Некорректный формат ключа
    """
    try:
        return load_der_public_key(data)
    except Exception as exc:
        raise InvalidKeyError(
            "Invalid public key DER format. "
            "Expected SubjectPublicKeyInfo DER-encoded public key."
        ) from exc


# ==============================================================================
# CLASSICAL SIGNATURES: EdDSA (Ed25519 / Ed448)
# ==============================================================================


class Ed25519Signer(SignatureProtocol):
    """
    Ed25519 цифровая подпись (RFC 8032, FIPS 186-5).

    Характеристики:
        - Кривая: Curve25519 (Edwards curve)
        - Размер подписи: 64 bytes
        - Размер публичного ключа: 32 bytes
        - Размер приватного ключа: 32 bytes
        - Безопасность: ~128 bits (эквивалент RSA-3072)

    Преимущества:
        ✅ Очень быстрая (10x быстрее RSA-2048)
        ✅ Компактные подписи (64 байта)
        ✅ Детерминированная (no random nonce)
        ✅ Защита от side-channel атак

    Применение:
        - SSH подписи (ssh-ed25519)
        - Git коммиты (подпись коммитов)
        - TLS сертификаты
        - API токены (JWT)

    Example:
        >>> signer = Ed25519Signer()
        >>> priv, pub = signer.generate_keypair()
        >>> msg = b"Document v1.0"
        >>> sig = signer.sign(priv, msg)
        >>> assert signer.verify(pub, msg, sig)
        >>> assert len(sig) == 64

    References:
        - RFC 8032: EdDSA specification
        - FIPS 186-5: Digital Signature Standard
        - https://ed25519.cr.yp.to/
    """

    algorithm_name: str = "Ed25519"
    signature_size: int = 64
    public_key_size: int = 32
    private_key_size: int = 32
    is_post_quantum: bool = False

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Генерация новой пары ключей Ed25519.

        Returns:
            Tuple[bytes, bytes]: (private_key_der, public_key_der)

        Raises:
            KeyGenerationError: Не удалось сгенерировать ключи

        Example:
            >>> signer = Ed25519Signer()
            >>> priv, pub = signer.generate_keypair()
            >>> len(priv), len(pub)
            (85, 44)  # DER encoding overhead
        """
        try:
            key = ed25519.Ed25519PrivateKey.generate()
            pub = key.public_key()
            return _encode_private_key_der(key), _encode_public_key_der(pub)
        except Exception as exc:
            raise KeyGenerationError(
                "Ed25519 key generation failed. "
                "This might indicate a system CSPRNG issue."
            ) from exc

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Создать Ed25519 подпись сообщения.

        Args:
            private_key: DER-encoded приватный ключ Ed25519
            message: Сообщение для подписи

        Returns:
            64-byte подпись

        Raises:
            TypeError: Неверный тип аргументов
            InvalidKeyError: Некорректный приватный ключ
            SigningFailedError: Не удалось создать подпись

        Security Note:
            Ed25519 детерминированная — одно сообщение всегда даёт одну подпись.
            Это защищает от nonce reuse атак (в отличие от ECDSA).

        Example:
            >>> priv, pub = signer.generate_keypair()
            >>> sig = signer.sign(priv, b"Hello")
            >>> len(sig)
            64
        """
        if not isinstance(private_key, bytes) or not isinstance(message, bytes):
            raise TypeError("private_key and message must be bytes")

        key_obj = _load_private_key_der(private_key)
        if not isinstance(key_obj, ed25519.Ed25519PrivateKey):
            raise InvalidKeyError(
                "Expected Ed25519 private key, got " f"{type(key_obj).__name__}"
            )

        try:
            return key_obj.sign(message)
        except Exception as exc:
            raise SigningFailedError(
                "Ed25519 signing failed", algorithm="Ed25519"
            ) from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Проверить Ed25519 подпись.

        Args:
            public_key: DER-encoded публичный ключ Ed25519
            message: Подписанное сообщение
            signature: 64-byte подпись

        Returns:
            True если подпись валидна, False иначе

        Raises:
            TypeError: Неверный тип аргументов
            InvalidKeyError: Некорректный публичный ключ

        Note:
            НЕ бросает исключение при неверной подписи (returns False).
            Это позволяет безопасно обрабатывать невалидные подписи.

        Example:
            >>> assert signer.verify(pub, b"Hello", sig)
            >>> assert not signer.verify(pub, b"Bye", sig)
        """
        if not all(isinstance(x, bytes) for x in (public_key, message, signature)):
            raise TypeError("public_key, message and signature must be bytes")

        key_obj = _load_public_key_der(public_key)
        if not isinstance(key_obj, ed25519.Ed25519PublicKey):
            raise InvalidKeyError(
                "Expected Ed25519 public key, got " f"{type(key_obj).__name__}"
            )

        try:
            key_obj.verify(signature, message)
            return True
        except Exception:
            # Любая ошибка верификации = невалидная подпись
            return False


class Ed448Signer(SignatureProtocol):
    """
    Ed448 цифровая подпись (RFC 8032).

    Характеристики:
        - Кривая: Curve448 (Edwards curve)
        - Размер подписи: 114 bytes
        - Размер публичного ключа: 57 bytes
        - Размер приватного ключа: 57 bytes
        - Безопасность: ~224 bits (эквивалент RSA-15360)

    Преимущества:
        ✅ Очень высокая безопасность (224-bit level)
        ✅ Детерминированная
        ✅ Защита от side-channel атак
        ✅ Поддержка context strings (domain separation)

    Применение:
        - High-security системы
        - Long-term архивы (долгосрочная безопасность)
        - Government/military applications

    Example:
        >>> signer = Ed448Signer()
        >>> priv, pub = signer.generate_keypair()
        >>> msg = b"Top Secret Document"
        >>> sig = signer.sign(priv, msg)
        >>> assert signer.verify(pub, msg, sig)
        >>> assert len(sig) == 114

    References:
        - RFC 8032: EdDSA specification
        - https://ed448goldilocks.sourceforge.io/
    """

    algorithm_name: str = "Ed448"
    signature_size: int = 114
    public_key_size: int = 57
    private_key_size: int = 57
    is_post_quantum: bool = False

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Генерация новой пары ключей Ed448."""
        try:
            key = ed448.Ed448PrivateKey.generate()
            pub = key.public_key()
            return _encode_private_key_der(key), _encode_public_key_der(pub)
        except Exception as exc:
            raise KeyGenerationError("Ed448 key generation failed") from exc

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Создать Ed448 подпись (114 bytes)."""
        if not isinstance(private_key, bytes) or not isinstance(message, bytes):
            raise TypeError("private_key and message must be bytes")

        key_obj = _load_private_key_der(private_key)
        if not isinstance(key_obj, ed448.Ed448PrivateKey):
            raise InvalidKeyError("Expected Ed448 private key")

        try:
            return key_obj.sign(message)
        except Exception as exc:
            raise SigningFailedError("Ed448 signing failed", algorithm="Ed448") from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Проверить Ed448 подпись."""
        if not all(isinstance(x, bytes) for x in (public_key, message, signature)):
            raise TypeError("public_key, message and signature must be bytes")

        key_obj = _load_public_key_der(public_key)
        if not isinstance(key_obj, ed448.Ed448PublicKey):
            raise InvalidKeyError("Expected Ed448 public key")

        try:
            key_obj.verify(signature, message)
            return True
        except Exception:
            return False


# ==============================================================================
# CLASSICAL SIGNATURES: ECDSA (NIST Curves + secp256k1)
# ==============================================================================


class _ECDSASignerBase(SignatureProtocol):
    """
    Базовый класс для ECDSA подписей на различных кривых.

    ECDSA (Elliptic Curve Digital Signature Algorithm) — стандарт цифровой подписи
    на эллиптических кривых (FIPS 186-5, ANSI X9.62).

    Warning:
        ECDSA требует КАЧЕСТВЕННОГО случайного nonce для каждой подписи.
        Повторное использование nonce полностью компрометирует приватный ключ!
        (PlayStation 3 hack, 2010)

    Security Note:
        cryptography library использует deterministic nonce (RFC 6979),
        что защищает от nonce reuse атак.

    Subclasses:
        - ECDSAP256Signer (NIST P-256)
        - ECDSAP384Signer (NIST P-384)
        - ECDSAP521Signer (NIST P-521)
        - ECDSASecp256k1Signer (Bitcoin/Ethereum curve)
    """

    _CURVE: ec.EllipticCurve
    _HASH: Type[hashes.HashAlgorithm]
    algorithm_name: str
    signature_size: int
    public_key_size: int
    private_key_size: int
    is_post_quantum: bool = False

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Генерация пары ключей ECDSA."""
        try:
            key = ec.generate_private_key(self._CURVE)
            pub = key.public_key()
            return _encode_private_key_der(key), _encode_public_key_der(pub)
        except Exception as exc:
            raise KeyGenerationError(
                f"{self.algorithm_name} key generation failed"
            ) from exc

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Создать ECDSA подпись.

        Note:
            Использует deterministic nonce (RFC 6979) для защиты от nonce reuse.
        """
        if not isinstance(private_key, bytes) or not isinstance(message, bytes):
            raise TypeError("private_key and message must be bytes")

        key_obj = _load_private_key_der(private_key)
        if not isinstance(key_obj, ec.EllipticCurvePrivateKey):
            raise InvalidKeyError(f"Expected {self.algorithm_name} private key")

        try:
            return key_obj.sign(message, ec.ECDSA(self._HASH()))
        except Exception as exc:
            raise SigningFailedError(
                f"{self.algorithm_name} signing failed", algorithm=self.algorithm_name
            ) from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Проверить ECDSA подпись."""
        if not all(isinstance(x, bytes) for x in (public_key, message, signature)):
            raise TypeError("public_key, message and signature must be bytes")

        key_obj = _load_public_key_der(public_key)
        if not isinstance(key_obj, ec.EllipticCurvePublicKey):
            raise InvalidKeyError(f"Expected {self.algorithm_name} public key")

        try:
            key_obj.verify(signature, message, ec.ECDSA(self._HASH()))
            return True
        except Exception:
            return False


class ECDSAP256Signer(_ECDSASignerBase):
    """
    ECDSA на NIST P-256 кривой (secp256r1, prime256v1).

    Характеристики:
        - Кривая: NIST P-256 (secp256r1)
        - Хеш: SHA-256
        - Размер подписи: ~64-72 bytes (DER encoding)
        - Безопасность: ~128 bits

    Применение:
        - TLS/SSL сертификаты
        - US Government systems
        - X.509 сертификаты

    Example:
        >>> signer = ECDSAP256Signer()
        >>> priv, pub = signer.generate_keypair()
        >>> sig = signer.sign(priv, b"data")
    """

    algorithm_name = "ECDSA-P256"
    _CURVE = ec.SECP256R1()
    _HASH = hashes.SHA256
    signature_size = 64  # Approximate (DER encoding varies)
    public_key_size = 64
    private_key_size = 32


class ECDSAP384Signer(_ECDSASignerBase):
    """
    ECDSA на NIST P-384 кривой (secp384r1).

    Характеристики:
        - Кривая: NIST P-384 (secp384r1)
        - Хеш: SHA-384
        - Размер подписи: ~96-104 bytes
        - Безопасность: ~192 bits

    Применение:
        - High-security TLS
        - Suite B (NSA/US DoD)
    """

    algorithm_name = "ECDSA-P384"
    _CURVE = ec.SECP384R1()
    _HASH = hashes.SHA384
    signature_size = 96
    public_key_size = 96
    private_key_size = 48


class ECDSAP521Signer(_ECDSASignerBase):
    """
    ECDSA на NIST P-521 кривой (secp521r1).

    Характеристики:
        - Кривая: NIST P-521 (secp521r1)
        - Хеш: SHA-512
        - Размер подписи: ~132-139 bytes
        - Безопасность: ~256 bits

    Применение:
        - Maximum security требования
        - Long-term архивы
    """

    algorithm_name = "ECDSA-P521"
    _CURVE = ec.SECP521R1()
    _HASH = hashes.SHA512
    signature_size = 132
    public_key_size = 132
    private_key_size = 66


class ECDSASecp256k1Signer(_ECDSASignerBase):
    """
    ECDSA на secp256k1 кривой (Bitcoin/Ethereum).

    Характеристики:
        - Кривая: secp256k1 (Koblitz curve)
        - Хеш: SHA-256
        - Размер подписи: 64 bytes (r,s)
        - Безопасность: ~128 bits

    Применение:
        - Bitcoin транзакции
        - Ethereum транзакции
        - Криптовалюты (большинство)

    Note:
        Не является NIST стандартом, но широко используется в blockchain.

    Example:
        >>> signer = ECDSASecp256k1Signer()
        >>> priv, pub = signer.generate_keypair()
        >>> # Подпись Bitcoin транзакции
        >>> tx_hash = hashlib.sha256(transaction).digest()
        >>> sig = signer.sign(priv, tx_hash)
    """

    algorithm_name = "ECDSA-secp256k1"
    _CURVE = ec.SECP256K1()
    _HASH = hashes.SHA256
    signature_size = 64
    public_key_size = 64
    private_key_size = 32


# ==============================================================================
# CLASSICAL SIGNATURES: RSA-PSS
# ==============================================================================


class _RSAPSSSignerBase(SignatureProtocol):
    """
    Базовый класс для RSA-PSS подписей различных размеров.

    RSA-PSS (Probabilistic Signature Scheme) — современный стандарт RSA подписи
    с доказуемой безопасностью (PKCS#1 v2.2, RFC 8017).

    Преимущества над RSA-PKCS1v15:
        ✅ Доказуемая безопасность (provable security)
        ✅ Защита от chosen-message атак
        ✅ Recommended by NIST/FIPS 186-5

    Применение:
        - TLS 1.3 (обязательно RSA-PSS)
        - Подпись документов
        - Code signing
        - X.509 сертификаты (новые)

    Subclasses:
        - RSAPSS2048Signer (минимально допустимый)
        - RSAPSS3072Signer (рекомендуется)
        - RSAPSS4096Signer (максимальная безопасность)
    """

    _KEY_SIZE: int
    algorithm_name: str
    signature_size: int
    public_key_size: int
    private_key_size: int
    is_post_quantum: bool = False

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Генерация пары ключей RSA."""
        try:
            key = rsa.generate_private_key(
                public_exponent=65537, key_size=self._KEY_SIZE
            )
            pub = key.public_key()
            return _encode_private_key_der(key), _encode_public_key_der(pub)
        except Exception as exc:
            raise KeyGenerationError(
                f"{self.algorithm_name} key generation failed"
            ) from exc

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Создать RSA-PSS подпись.

        Uses:
            - MGF1 с SHA-256
            - MAX salt length (максимальная энтропия)
        """
        if not isinstance(private_key, bytes) or not isinstance(message, bytes):
            raise TypeError("private_key and message must be bytes")

        key_obj = _load_private_key_der(private_key)
        if not isinstance(key_obj, rsa.RSAPrivateKey):
            raise InvalidKeyError(f"Expected {self.algorithm_name} private key")

        padding = rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH,
        )

        try:
            return key_obj.sign(message, padding, hashes.SHA256())
        except Exception as exc:
            raise SigningFailedError(
                f"{self.algorithm_name} signing failed", algorithm=self.algorithm_name
            ) from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Проверить RSA-PSS подпись."""
        if not all(isinstance(x, bytes) for x in (public_key, message, signature)):
            raise TypeError("public_key, message and signature must be bytes")

        key_obj = _load_public_key_der(public_key)
        if not isinstance(key_obj, rsa.RSAPublicKey):
            raise InvalidKeyError(f"Expected {self.algorithm_name} public key")

        padding = rsa_padding.PSS(
            mgf=rsa_padding.MGF1(hashes.SHA256()),
            salt_length=rsa_padding.PSS.MAX_LENGTH,
        )

        try:
            key_obj.verify(signature, message, padding, hashes.SHA256())
            return True
        except Exception:
            return False


class RSAPSS2048Signer(_RSAPSSSignerBase):
    """
    RSA-PSS с 2048-bit ключом.

    Характеристики:
        - Размер ключа: 2048 bits
        - Размер подписи: 256 bytes
        - Безопасность: ~112 bits
        - Хеш: SHA-256

    Note:
        Минимально допустимый размер для новых систем.
        Рекомендуется переходить на 3072-bit.

    Применение:
        - Legacy compatibility
        - Resource-constrained systems
    """

    algorithm_name = "RSA-PSS-2048"
    _KEY_SIZE = 2048
    signature_size = 256
    public_key_size = 294  # DER encoding
    private_key_size = 1217  # DER encoding


class RSAPSS3072Signer(_RSAPSSSignerBase):
    """
    RSA-PSS с 3072-bit ключом (рекомендуется).

    Характеристики:
        - Размер ключа: 3072 bits
        - Размер подписи: 384 bytes
        - Безопасность: ~128 bits
        - Хеш: SHA-256

    Применение:
        - Production системы (рекомендуется)
        - Эквивалент AES-128 security
    """

    algorithm_name = "RSA-PSS-3072"
    _KEY_SIZE = 3072
    signature_size = 384
    public_key_size = 422
    private_key_size = 1769


class RSAPSS4096Signer(_RSAPSSSignerBase):
    """
    RSA-PSS с 4096-bit ключом (максимальная безопасность).

    Характеристики:
        - Размер ключа: 4096 bits
        - Размер подписи: 512 bytes
        - Безопасность: ~140 bits
        - Хеш: SHA-256

    Применение:
        - High-security требования
        - Long-term архивы (до 2030+)
        - Government systems
    """

    algorithm_name = "RSA-PSS-4096"
    _KEY_SIZE = 4096
    signature_size = 512
    public_key_size = 550
    private_key_size = 2349


# ==============================================================================
# LEGACY: RSA-PKCS1v15
# ==============================================================================


class RSAPKCS1v15Signer(SignatureProtocol):
    """
    RSA-PKCS1v15 подпись (legacy, DEPRECATED).

    ⚠️  WARNING: DEPRECATED алгоритм!
        Используйте RSA-PSS для новых систем.

    Проблемы:
        ❌ Нет доказуемой безопасности
        ❌ Уязвим к chosen-message атакам (Bleichenbacher)
        ❌ Не рекомендуется NIST/FIPS 186-5

    Поддержка:
        Оставлен только для совместимости с legacy системами.

    Применение:
        - Legacy TLS < 1.3
        - Старые X.509 сертификаты
        - Совместимость с устаревшими системами

    Migration Path:
        RSA-PKCS1v15 → RSA-PSS (preferred)
        RSA-PKCS1v15 → Ed25519 (modern)

    Example:
        >>> # ⚠️  НЕ ИСПОЛЬЗУЙТЕ В НОВОМ КОДЕ!
        >>> signer = RSAPKCS1v15Signer()  # legacy only
        >>> priv, pub = signer.generate_keypair()
    """

    algorithm_name: str = "RSA-PKCS1v15"
    signature_size: int = 256  # 2048-bit key
    public_key_size: int = 294
    private_key_size: int = 1217
    is_post_quantum: bool = False

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Генерация 2048-bit RSA ключа (legacy)."""
        try:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub = key.public_key()
            return _encode_private_key_der(key), _encode_public_key_der(pub)
        except Exception as exc:
            raise KeyGenerationError("RSA-PKCS1v15 key generation failed") from exc

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """Создать RSA-PKCS1v15 подпись (DEPRECATED)."""
        if not isinstance(private_key, bytes) or not isinstance(message, bytes):
            raise TypeError("private_key and message must be bytes")

        key_obj = _load_private_key_der(private_key)
        if not isinstance(key_obj, rsa.RSAPrivateKey):
            raise InvalidKeyError("Expected RSA private key")

        try:
            return key_obj.sign(message, rsa_padding.PKCS1v15(), hashes.SHA256())
        except Exception as exc:
            raise SigningFailedError(
                "RSA-PKCS1v15 signing failed", algorithm="RSA-PKCS1v15"
            ) from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Проверить RSA-PKCS1v15 подпись."""
        if not all(isinstance(x, bytes) for x in (public_key, message, signature)):
            raise TypeError("public_key, message and signature must be bytes")

        key_obj = _load_public_key_der(public_key)
        if not isinstance(key_obj, rsa.RSAPublicKey):
            raise InvalidKeyError("Expected RSA public key")

        try:
            key_obj.verify(signature, message, rsa_padding.PKCS1v15(), hashes.SHA256())
            return True
        except Exception:
            return False


# ==============================================================================
# POST-QUANTUM SIGNATURES: BASE CLASS
# ==============================================================================


class _OQSSignerBase(SignatureProtocol):
    """
    Базовый класс для постквантовых подписей через liboqs-python.

    Поддерживаемые семейства:
        - ML-DSA (Module-Lattice-Based DSA, FIPS 204)
        - Falcon (NTRU-based, NIST finalist)
        - SLH-DSA (Stateless Hash-Based, FIPS 205)

    Installation:
        pip install liboqs-python

    Security Level Mapping (NIST):
        - Level 1: ~AES-128 (ML-DSA-44, Falcon-512, SLH-DSA-128s)
        - Level 3: ~AES-192 (ML-DSA-65, SLH-DSA-192s)
        - Level 5: ~AES-256 (ML-DSA-87, Falcon-1024, SLH-DSA-256s)

    Key Format:
        Raw bytes (не DER). Прямой формат liboqs.

    Example:
        >>> if HAS_LIBOQS:
        ...     signer = MLDSA65Signer()
        ...     priv, pub = signer.generate_keypair()
    """

    _OQS_NAME: str
    algorithm_name: str
    signature_size: int
    public_key_size: int
    private_key_size: int
    is_post_quantum: bool = True

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Генерация постквантовой пары ключей.

        Returns:
            Tuple[bytes, bytes]: (private_key_raw, public_key_raw)

        Raises:
            AlgorithmNotSupportedError: liboqs-python не установлен
            KeyGenerationError: Не удалось сгенерировать ключи

        Note:
            Ключи в raw формате (не DER), специфичном для liboqs.
        """
        if not HAS_LIBOQS or oqs is None:
            raise AlgorithmNotSupportedError(
                algorithm=self.algorithm_name,
                reason="liboqs-python not installed",
                required_library="liboqs-python",
            )

        try:
            with oqs.Signature(self._OQS_NAME) as sig:  # type: ignore[call-arg]
                public_key = cast(bytes, sig.generate_keypair())
                private_key = cast(bytes, sig.export_secret_key())
            return private_key, public_key
        except Exception as exc:
            raise KeyGenerationError(
                f"{self.algorithm_name} key generation failed"
            ) from exc

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Создать постквантовую подпись.

        Args:
            private_key: Raw приватный ключ (liboqs формат)
            message: Сообщение для подписи

        Returns:
            Подпись (размер зависит от алгоритма)

        Raises:
            TypeError: Неверный тип аргументов
            AlgorithmNotSupportedError: liboqs-python не установлен
            SigningFailedError: Не удалось создать подпись
        """
        if not isinstance(private_key, bytes) or not isinstance(message, bytes):
            raise TypeError("private_key and message must be bytes")

        if not HAS_LIBOQS or oqs is None:
            raise AlgorithmNotSupportedError(
                algorithm=self.algorithm_name,
                reason="liboqs-python not installed",
                required_library="liboqs-python",
            )

        try:
            # Create new signature object with the private key
            with oqs.Signature(self._OQS_NAME, secret_key=private_key) as sig:  # type: ignore[call-arg]
                result = sig.sign(message)
                return cast(bytes, result)
        except Exception as exc:
            raise SigningFailedError(
                f"{self.algorithm_name} signing failed", algorithm=self.algorithm_name
            ) from exc

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Проверить постквантовую подпись.

        Args:
            public_key: Raw публичный ключ (liboqs формат)
            message: Подписанное сообщение
            signature: Подпись

        Returns:
            True если подпись валидна, False иначе

        Raises:
            TypeError: Неверный тип аргументов
            AlgorithmNotSupportedError: liboqs-python не установлен
        """
        if not all(isinstance(x, bytes) for x in (public_key, message, signature)):
            raise TypeError("public_key, message and signature must be bytes")

        if not HAS_LIBOQS or oqs is None:
            raise AlgorithmNotSupportedError(
                algorithm=self.algorithm_name,
                reason="liboqs-python not installed",
                required_library="liboqs-python",
            )

        try:
            with oqs.Signature(self._OQS_NAME) as sig:  # type: ignore[call-arg]
                ok = sig.verify(message, signature, public_key)
                return bool(ok)
        except Exception:
            return False


# ==============================================================================
# POST-QUANTUM: ML-DSA (NIST FIPS 204, replaces Dilithium)
# ==============================================================================


class MLDSA44Signer(_OQSSignerBase):
    """
    ML-DSA-44 подпись (NIST FIPS 204, Level 1).

    Характеристики:
        - Семейство: Module-Lattice-Based DSA
        - Размер подписи: 2420 bytes
        - Размер публичного ключа: 1312 bytes
        - Размер приватного ключа: 2560 bytes
        - Безопасность: NIST Level 1 (~AES-128)
        - Статус: NIST стандарт (2024)

    Преимущества:
        ✅ NIST стандартизирован (FIPS 204)
        ✅ Lattice-based (квантовобезопасный)
        ✅ Быстрая верификация

    Применение:
        - IoT devices (минимальная безопасность)
        - Embedded systems
        - Hybrid signature schemes

    Replaces:
        Dilithium2 (legacy)

    Example:
        >>> signer = MLDSA44Signer()
        >>> priv, pub = signer.generate_keypair()
        >>> sig = signer.sign(priv, b"message")
        >>> len(sig)
        2420

    References:
        - NIST FIPS 204 (2024)
        - https://csrc.nist.gov/pubs/fips/204/final
    """

    algorithm_name = "ML-DSA-44"
    _OQS_NAME = "ML-DSA-44"
    signature_size = 2420
    public_key_size = 1312
    private_key_size = 2560


class MLDSA65Signer(_OQSSignerBase):
    """
    ML-DSA-65 подпись (NIST FIPS 204, Level 3, РЕКОМЕНДУЕТСЯ).

    Характеристики:
        - Семейство: Module-Lattice-Based DSA
        - Размер подписи: 3309 bytes
        - Размер публичного ключа: 1952 bytes
        - Размер приватного ключа: 4032 bytes
        - Безопасность: NIST Level 3 (~AES-192)
        - Статус: NIST стандарт (2024)

    Преимущества:
        ✅ NIST стандартизирован (FIPS 204)
        ✅ Рекомендуется для production
        ✅ Баланс безопасность/производительность

    Применение:
        - Production systems (рекомендуется)
        - TLS post-quantum
        - Government/military
        - Code signing

    Replaces:
        Dilithium3 (legacy)

    ⭐ RECOMMENDED для большинства применений.

    References:
        - NIST FIPS 204 (2024)
    """

    algorithm_name = "ML-DSA-65"
    _OQS_NAME = "ML-DSA-65"
    signature_size = 3309
    public_key_size = 1952
    private_key_size = 4032


class MLDSA87Signer(_OQSSignerBase):
    """
    ML-DSA-87 подпись (NIST FIPS 204, Level 5).

    Характеристики:
        - Семейство: Module-Lattice-Based DSA
        - Размер подписи: 4627 bytes
        - Размер публичного ключа: 2592 bytes
        - Размер приватного ключа: 4896 bytes
        - Безопасность: NIST Level 5 (~AES-256)
        - Статус: NIST стандарт (2024)

    Применение:
        - Maximum security требования
        - Long-term архивы (30+ лет)
        - Top Secret classification

    Replaces:
        Dilithium5 (legacy)

    References:
        - NIST FIPS 204 (2024)
    """

    algorithm_name = "ML-DSA-87"
    _OQS_NAME = "ML-DSA-87"
    signature_size = 4627
    public_key_size = 2592
    private_key_size = 4896


# ==============================================================================
# POST-QUANTUM: Falcon (NIST Finalist)
# ==============================================================================


class Falcon512Signer(_OQSSignerBase):
    """
    Falcon-512 подпись (NIST finalist, Level 1).

    Характеристики:
        - Семейство: NTRU-based lattice
        - Размер подписи: 666 bytes (компактная!)
        - Размер публичного ключа: 897 bytes
        - Размер приватного ключа: 1281 bytes
        - Безопасность: NIST Level 1 (~AES-128)
        - Статус: NIST finalist (не стандартизирован)

    Преимущества:
        ✅ Самые компактные подписи среди PQC
        ✅ Быстрая верификация
        ✅ NTRU-based (альтернатива lattice)

    Недостатки:
        ⚠️  Не стандартизирован NIST (finalist only)
        ⚠️  Сложная реализация (floating-point arithmetic)

    Применение:
        - Bandwidth-constrained systems
        - Альтернатива ML-DSA (диверсификация)

    Example:
        >>> signer = Falcon512Signer()
        >>> priv, pub = signer.generate_keypair()
        >>> sig = signer.sign(priv, b"compact signature")
        >>> len(sig)
        666  # Очень компактная!

    References:
        - https://falcon-sign.info/
    """

    algorithm_name = "Falcon-512"
    _OQS_NAME = "Falcon-512"
    signature_size = 666
    public_key_size = 897
    private_key_size = 1281


class Falcon1024Signer(_OQSSignerBase):
    """
    Falcon-1024 подпись (NIST finalist, Level 5).

    Характеристики:
        - Семейство: NTRU-based lattice
        - Размер подписи: 1280 bytes
        - Размер публичного ключа: 1793 bytes
        - Размер приватного ключа: 2305 bytes
        - Безопасность: NIST Level 5 (~AES-256)
        - Статус: NIST finalist

    Применение:
        - High-security требования
        - Альтернатива ML-DSA-87

    References:
        - https://falcon-sign.info/
    """

    algorithm_name = "Falcon-1024"
    _OQS_NAME = "Falcon-1024"
    signature_size = 1280
    public_key_size = 1793
    private_key_size = 2305


# ==============================================================================
# POST-QUANTUM: SLH-DSA (NIST FIPS 205, replaces SPHINCS+)
# ==============================================================================


class SLHDSASHA2_128sSigner(_OQSSignerBase):
    """
    SLH-DSA-SHA2-128s подпись (NIST FIPS 205, Level 1).

    Характеристики:
        - Семейство: Stateless Hash-Based
        - Размер подписи: 7856 bytes (большая!)
        - Размер публичного ключа: 32 bytes (компактный!)
        - Размер приватного ключа: 64 bytes
        - Безопасность: NIST Level 1 (~AES-128)
        - Статус: NIST стандарт (2024)

    Преимущества:
        ✅ Hash-based (консервативная безопасность)
        ✅ Stateless (в отличие от XMSS)
        ✅ Minimal trust assumptions
        ✅ Компактные ключи (32 bytes public key!)

    Недостатки:
        ❌ Очень большие подписи (7856 bytes)
        ❌ Медленная генерация подписи

    Применение:
        - Long-term архивы (100+ лет)
        - Conservative security requirements
        - Firmware signing (где размер подписи OK)

    Replaces:
        SPHINCS+-SHA2-128s-simple (legacy)

    Example:
        >>> signer = SLHDSASHA2_128sSigner()
        >>> priv, pub = signer.generate_keypair()
        >>> len(pub)  # Компактный публичный ключ!
        32
        >>> sig = signer.sign(priv, b"message")
        >>> len(sig)  # Но подпись огромная
        7856

    References:
        - NIST FIPS 205 (2024)
        - https://csrc.nist.gov/pubs/fips/205/final
    """

    algorithm_name = "SLH-DSA-SHA2-128s"
    _OQS_NAME = "SLH_DSA_PURE_SHA2_128S"  # Имя в liboqs
    signature_size = 7856
    public_key_size = 32
    private_key_size = 64


class SLHDSASHA2_192sSigner(_OQSSignerBase):
    """
    SLH-DSA-SHA2-192s подпись (NIST FIPS 205, Level 3).

    Характеристики:
        - Размер подписи: 16224 bytes
        - Размер публичного ключа: 48 bytes
        - Размер приватного ключа: 96 bytes
        - Безопасность: NIST Level 3 (~AES-192)

    Применение:
        - Long-term security (150+ лет)

    References:
        - NIST FIPS 205 (2024)
    """

    algorithm_name = "SLH-DSA-SHA2-192s"
    _OQS_NAME = "SLH_DSA_PURE_SHA2_192S"
    signature_size = 16224
    public_key_size = 48
    private_key_size = 96


class SLHDSASHA2_256sSigner(_OQSSignerBase):
    """
    SLH-DSA-SHA2-256s подпись (NIST FIPS 205, Level 5).

    Характеристики:
        - Размер подписи: 29792 bytes (огромная!)
        - Размер публичного ключа: 64 bytes
        - Размер приватного ключа: 128 bytes
        - Безопасность: NIST Level 5 (~AES-256)

    Применение:
        - Maximum paranoia security
        - Ultra-long-term архивы (200+ лет)

    Replaces:
        SPHINCS+-SHA2-256s-simple (legacy)

    References:
        - NIST FIPS 205 (2024)
    """

    algorithm_name = "SLH-DSA-SHA2-256s"
    _OQS_NAME = "SLH_DSA_PURE_SHA2_256S"
    signature_size = 29792
    public_key_size = 64
    private_key_size = 128


# ==============================================================================
# LEGACY PQC: Dilithium / SPHINCS+ (DEPRECATED, use ML-DSA / SLH-DSA)
# ==============================================================================


class Dilithium2Signer(_OQSSignerBase):
    """
    Dilithium2 подпись (DEPRECATED, используйте ML-DSA-44).

    ⚠️  DEPRECATED: Заменён на ML-DSA-44 (NIST FIPS 204).

    Migration Path:
        Dilithium2 → ML-DSA-44

    Оставлен для backward compatibility с кодом 2022-2024.
    """

    algorithm_name = "Dilithium2"
    _OQS_NAME = "Dilithium2"
    signature_size = 2420
    public_key_size = 1312
    private_key_size = 2528


class SPHINCSPlus128sSigner(_OQSSignerBase):
    """
    SPHINCS+-SHA2-128s-simple подпись (DEPRECATED, используйте SLH-DSA-SHA2-128s).

    ⚠️  DEPRECATED: Заменён на SLH-DSA-SHA2-128s (NIST FIPS 205).

    Migration Path:
        SPHINCS+-SHA2-128s-simple → SLH-DSA-SHA2-128s

    Оставлен для backward compatibility.
    """

    algorithm_name = "SPHINCS+-128s"
    _OQS_NAME = "SPHINCS+-SHA2-128s-simple"
    signature_size = 7856
    public_key_size = 32
    private_key_size = 64


# ==============================================================================
# REGISTRATION
# ==============================================================================


def _register_all_signatures() -> None:
    """
    Зарегистрировать все 20 алгоритмов подписи в глобальном реестре.

    Регистрирует:
        - 10 классических (Ed25519, Ed448, ECDSA×4, RSA-PSS×3, RSA-PKCS1v15)
        - 8 постквантовых NIST (ML-DSA×3, Falcon×2, SLH-DSA×3)
        - 2 legacy PQC (Dilithium2, SPHINCS+-128s) — помечены DEPRECATED

    Note:
        Вызывается автоматически при импорте модуля.
    """
    registry = AlgorithmRegistry.get_instance()
    registered_count = 0

    # ========== CLASSICAL: EdDSA ==========

    registry.register_algorithm(
        name="Ed25519",
        factory=Ed25519Signer,
        metadata=create_signature_metadata(
            name="Ed25519",
            library="cryptography",
            implementation_class="src.security.crypto.algorithms.signing.Ed25519Signer",
            signature_size=64,
            public_key_size=32,
            private_key_size=32,
            security_level=SecurityLevel.STANDARD,
            status=ImplementationStatus.STABLE,
            description_ru="EdDSA подпись на кривой Curve25519 (RFC 8032)",
            description_en="EdDSA signature on Curve25519 (RFC 8032)",
            test_vectors_source="RFC 8032",
            use_cases=["SSH", "Git", "TLS", "API tokens"],
        ),
    )
    registered_count += 1

    registry.register_algorithm(
        name="Ed448",
        factory=Ed448Signer,
        metadata=create_signature_metadata(
            name="Ed448",
            library="cryptography",
            implementation_class="src.security.crypto.algorithms.signing.Ed448Signer",
            signature_size=114,
            public_key_size=57,
            private_key_size=57,
            security_level=SecurityLevel.HIGH,
            status=ImplementationStatus.STABLE,
            description_ru="EdDSA подпись на кривой Curve448 (RFC 8032, 224-bit security)",
            description_en="EdDSA signature on Curve448 (RFC 8032, 224-bit security)",
            test_vectors_source="RFC 8032",
            use_cases=["High-security systems", "Long-term archives"],
        ),
    )
    registered_count += 1

    # ========== CLASSICAL: ECDSA ==========

    ecdsa_classes: Tuple[Type[_ECDSASignerBase], ...] = (
        ECDSAP256Signer,
        ECDSAP384Signer,
        ECDSAP521Signer,
        ECDSASecp256k1Signer,
    )

    for ecdsa_cls in ecdsa_classes:
        signer_instance = ecdsa_cls()
        registry.register_algorithm(
            name=signer_instance.algorithm_name,
            factory=ecdsa_cls,
            metadata=create_signature_metadata(
                name=signer_instance.algorithm_name,
                library="cryptography",
                implementation_class=f"src.security.crypto.algorithms.signing.{ecdsa_cls.__name__}",
                signature_size=signer_instance.signature_size,
                public_key_size=signer_instance.public_key_size,
                private_key_size=signer_instance.private_key_size,
                security_level=SecurityLevel.STANDARD,
                status=ImplementationStatus.STABLE,
                description_ru=f"ECDSA подпись на кривой {signer_instance.algorithm_name.split('-')[1]}",
                description_en=f"ECDSA signature on {signer_instance.algorithm_name.split('-')[1]} curve",
                test_vectors_source="FIPS 186-5",
                use_cases=(
                    ["TLS", "X.509"]
                    if "secp256k1" not in signer_instance.algorithm_name
                    else ["Bitcoin", "Ethereum", "Blockchain"]
                ),
            ),
        )
        registered_count += 1

    # ========== CLASSICAL: RSA-PSS ==========

    rsa_pss_classes: Tuple[Type[_RSAPSSSignerBase], ...] = (
        RSAPSS2048Signer,
        RSAPSS3072Signer,
        RSAPSS4096Signer,
    )

    for rsa_cls in rsa_pss_classes:
        rsa_instance = rsa_cls()
        key_bits = rsa_instance._KEY_SIZE
        security_level = (
            SecurityLevel.STANDARD if key_bits == 2048 else SecurityLevel.HIGH
        )

        registry.register_algorithm(
            name=rsa_instance.algorithm_name,
            factory=rsa_cls,
            metadata=create_signature_metadata(
                name=rsa_instance.algorithm_name,
                library="cryptography",
                implementation_class=f"src.security.crypto.algorithms.signing.{rsa_cls.__name__}",
                signature_size=rsa_instance.signature_size,
                public_key_size=rsa_instance.public_key_size,
                private_key_size=rsa_instance.private_key_size,
                security_level=security_level,
                status=ImplementationStatus.STABLE,
                description_ru=f"RSA-PSS подпись с {key_bits}-битным ключом (PKCS#1 v2.2)",
                description_en=f"RSA-PSS signature with {key_bits}-bit key (PKCS#1 v2.2)",
                test_vectors_source="RFC 8017",
                use_cases=["TLS 1.3", "Code signing", "Document signing"],
            ),
        )
        registered_count += 1

    # ========== CLASSICAL: RSA-PKCS1v15 (legacy) ==========

    pkcs_signer = RSAPKCS1v15Signer()
    registry.register_algorithm(
        name=pkcs_signer.algorithm_name,
        factory=RSAPKCS1v15Signer,
        metadata=create_signature_metadata(
            name=pkcs_signer.algorithm_name,
            library="cryptography",
            implementation_class="src.security.crypto.algorithms.signing.RSAPKCS1v15Signer",
            signature_size=pkcs_signer.signature_size,
            public_key_size=pkcs_signer.public_key_size,
            private_key_size=pkcs_signer.private_key_size,
            security_level=SecurityLevel.LEGACY,
            status=ImplementationStatus.DEPRECATED,
            description_ru="RSA-PKCS1v15 подпись (устаревший, используйте RSA-PSS)",
            description_en="RSA-PKCS1v15 signature (legacy, use RSA-PSS instead)",
            test_vectors_source="RFC 8017",
            use_cases=["Legacy compatibility only"],
        ),
    )
    registered_count += 1

    # ========== POST-QUANTUM: ML-DSA (NIST standard) ==========

    mldsa_classes: Tuple[Type[_OQSSignerBase], ...] = (
        MLDSA44Signer,
        MLDSA65Signer,
        MLDSA87Signer,
    )

    for mldsa_cls in mldsa_classes:
        mldsa_instance = mldsa_cls()
        registry.register_algorithm(
            name=mldsa_instance.algorithm_name,
            factory=mldsa_cls,
            metadata=create_signature_metadata(
                name=mldsa_instance.algorithm_name,
                library="liboqs-python",
                implementation_class=f"src.security.crypto.algorithms.signing.{mldsa_cls.__name__}",
                signature_size=mldsa_instance.signature_size,
                public_key_size=mldsa_instance.public_key_size,
                private_key_size=mldsa_instance.private_key_size,
                is_post_quantum=True,
                security_level=SecurityLevel.QUANTUM_RESISTANT,
                status=ImplementationStatus.STABLE,
                description_ru=f"ML-DSA постквантовая подпись (NIST FIPS 204, уровень {mldsa_instance.algorithm_name[-2:]})",
                description_en=f"ML-DSA post-quantum signature (NIST FIPS 204, Level {mldsa_instance.algorithm_name[-2:]})",
                test_vectors_source="NIST FIPS 204",
                use_cases=[
                    "Post-quantum TLS",
                    "Government systems",
                    "Long-term security",
                ],
            ),
        )
        registered_count += 1

    # ========== POST-QUANTUM: Falcon ==========

    falcon_classes: Tuple[Type[_OQSSignerBase], ...] = (
        Falcon512Signer,
        Falcon1024Signer,
    )

    for falcon_cls in falcon_classes:
        falcon_instance = falcon_cls()  # <-- Новое имя переменной
        registry.register_algorithm(
            name=falcon_instance.algorithm_name,
            factory=falcon_cls,
            metadata=create_signature_metadata(
                name=falcon_instance.algorithm_name,
                library="liboqs-python",
                implementation_class=f"src.security.crypto.algorithms.signing.{falcon_cls.__name__}",
                signature_size=falcon_instance.signature_size,
                public_key_size=falcon_instance.public_key_size,
                private_key_size=falcon_instance.private_key_size,
                is_post_quantum=True,
                security_level=SecurityLevel.QUANTUM_RESISTANT,
                status=ImplementationStatus.STABLE,
                description_ru=f"Falcon постквантовая подпись (NIST finalist, NTRU-based)",
                description_en=f"Falcon post-quantum signature (NIST finalist, NTRU-based)",
                test_vectors_source="https://falcon-sign.info/",
                use_cases=["Compact PQC signatures", "Bandwidth-constrained"],
            ),
        )
        registered_count += 1

    # ========== POST-QUANTUM: SLH-DSA (NIST standard) ==========

    slhdsa_classes: Tuple[Type[_OQSSignerBase], ...] = (
        SLHDSASHA2_128sSigner,
        SLHDSASHA2_192sSigner,
        SLHDSASHA2_256sSigner,
    )

    for slhdsa_cls in slhdsa_classes:
        slhdsa_instance = slhdsa_cls()
        registry.register_algorithm(
            name=slhdsa_instance.algorithm_name,
            factory=slhdsa_cls,
            metadata=create_signature_metadata(
                name=slhdsa_instance.algorithm_name,
                library="liboqs-python",
                implementation_class=f"src.security.crypto.algorithms.signing.{slhdsa_cls.__name__}",
                signature_size=slhdsa_instance.signature_size,
                public_key_size=slhdsa_instance.public_key_size,
                private_key_size=slhdsa_instance.private_key_size,
                is_post_quantum=True,
                security_level=SecurityLevel.QUANTUM_RESISTANT,
                status=ImplementationStatus.STABLE,
                description_ru=f"SLH-DSA stateless hash-based подпись (NIST FIPS 205)",
                description_en=f"SLH-DSA stateless hash-based signature (NIST FIPS 205)",
                test_vectors_source="NIST FIPS 205",
                use_cases=[
                    "Ultra-long-term security",
                    "Firmware signing",
                    "Conservative security",
                ],
            ),
        )
        registered_count += 1

    # ========== LEGACY PQC: Dilithium (DEPRECATED) ==========

    dilithium_signer = Dilithium2Signer()
    registry.register_algorithm(
        name=dilithium_signer.algorithm_name,
        factory=Dilithium2Signer,
        metadata=create_signature_metadata(
            name=dilithium_signer.algorithm_name,
            library="liboqs-python",
            implementation_class="src.security.crypto.algorithms.signing.Dilithium2Signer",
            signature_size=dilithium_signer.signature_size,
            public_key_size=dilithium_signer.public_key_size,
            private_key_size=dilithium_signer.private_key_size,
            is_post_quantum=True,
            security_level=SecurityLevel.QUANTUM_RESISTANT,
            status=ImplementationStatus.DEPRECATED,
            description_ru="Dilithium2 подпись (DEPRECATED, используйте ML-DSA-44)",
            description_en="Dilithium2 signature (DEPRECATED, use ML-DSA-44 instead)",
            test_vectors_source="Dilithium Round 3",
            use_cases=["Backward compatibility only"],
        ),
    )
    registered_count += 1

    # ========== LEGACY PQC: SPHINCS+ (DEPRECATED) ==========

    sphincs_signer = SPHINCSPlus128sSigner()
    registry.register_algorithm(
        name=sphincs_signer.algorithm_name,
        factory=SPHINCSPlus128sSigner,
        metadata=create_signature_metadata(
            name=sphincs_signer.algorithm_name,
            library="liboqs-python",
            implementation_class="src.security.crypto.algorithms.signing.SPHINCSPlus128sSigner",
            signature_size=sphincs_signer.signature_size,
            public_key_size=sphincs_signer.public_key_size,
            private_key_size=sphincs_signer.private_key_size,
            is_post_quantum=True,
            security_level=SecurityLevel.QUANTUM_RESISTANT,
            status=ImplementationStatus.DEPRECATED,
            description_ru="SPHINCS+-128s подпись (DEPRECATED, используйте SLH-DSA-SHA2-128s)",
            description_en="SPHINCS+-128s signature (DEPRECATED, use SLH-DSA-SHA2-128s instead)",
            test_vectors_source="SPHINCS+ Round 3",
            use_cases=["Backward compatibility only"],
        ),
    )
    registered_count += 1

    logger.info(
        f"Successfully registered {registered_count} signature algorithms "
        f"(10 classical + 8 PQC standards + 2 legacy PQC)"
    )


# Автоматическая регистрация при импорте модуля
_register_all_signatures()


# ==============================================================================
# MODULE EXPORTS
# ==============================================================================

__all__ = [
    # Classical: EdDSA
    "Ed25519Signer",
    "Ed448Signer",
    # Classical: ECDSA
    "ECDSAP256Signer",
    "ECDSAP384Signer",
    "ECDSAP521Signer",
    "ECDSASecp256k1Signer",
    # Classical: RSA-PSS
    "RSAPSS2048Signer",
    "RSAPSS3072Signer",
    "RSAPSS4096Signer",
    # Classical: RSA-PKCS1v15 (legacy)
    "RSAPKCS1v15Signer",
    # Post-Quantum: ML-DSA (NIST standard)
    "MLDSA44Signer",
    "MLDSA65Signer",
    "MLDSA87Signer",
    # Post-Quantum: Falcon
    "Falcon512Signer",
    "Falcon1024Signer",
    # Post-Quantum: SLH-DSA (NIST standard)
    "SLHDSASHA2_128sSigner",
    "SLHDSASHA2_192sSigner",
    "SLHDSASHA2_256sSigner",
    # Legacy PQC (deprecated)
    "Dilithium2Signer",
    "SPHINCSPlus128sSigner",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-10"
__status__ = "Production"
