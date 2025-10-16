"""
Модуль функций вывода ключей (KDF) для ESC/P Text Editor — безопасное преобразование паролей в криптографические ключи.

Особенности:
- Поддержка Argon2id (рекомендуется — memory-hard, устойчив к GPU/ASIC атакам) и PBKDF2-HMAC-SHA256 (для legacy/совместимости).
- Автоматическая генерация криптостойкой соли с проверкой энтропии.
- Гибкая настройка параметров: time_cost, memory_cost, parallelism (Argon2id) и iterations (PBKDF2).
- Встроенные проверки безопасности: валидация длины пароля/соли, предупреждения о низкой энтропии.
- Сериализация ключей в HEX/Base64 для хранения и передачи.
- Zeroization чувствительных данных после использования (best-effort для Python).
- Fail-secure: явные исключения при ошибках, детальное логирование для аудита.
- Protocol-интерфейс KdfProvider для DI и расширяемости.
- Готовность к интеграции с SIEM/audit trails.

Classes:
    KDFAlgorithm: enum поддерживаемых алгоритмов.
    KdfProvider: protocol-интерфейс для провайдеров KDF.
    KDFParameterError, KDFAlgorithmError, KDFEntropyWarning: специализированные исключения.

Functions:
    derive_key(): главная функция вывода ключа с полной настройкой.
    derive_key_argon2id(): упрощённая обёртка для Argon2id.
    generate_salt(): генерация криптостойкой соли.
"""

import hashlib
import logging
import secrets
import base64
from enum import Enum, auto
from typing import Final, Optional, Protocol, runtime_checkable, Union

try:
    import argon2  # type: ignore
except ImportError:
    raise ImportError(
        "argon2-cffi is required for Argon2id KDF (pip install argon2-cffi)"
    )

logger = logging.getLogger("security.crypto.kdf")
logger.addHandler(logging.NullHandler())

# ============================= Exceptions =====================================


from security.crypto.exceptions import (
    KDFParameterError,
    KDFAlgorithmError,
    KDFEntropyWarning,
)


# ============================= Enums & Constants ==============================


class KDFAlgorithm(Enum):
    """Supported Key Derivation Algorithms.

    ARGON2ID: Recommended. Memory-hard, resistant to GPU/ASIC attacks.
    PBKDF2_HMAC_SHA256: Legacy/interop.
    """

    ARGON2ID = auto()
    PBKDF2_HMAC_SHA256 = auto()


_SUPPORTED_ALGORITHMS: Final[set[KDFAlgorithm]] = {
    KDFAlgorithm.ARGON2ID,
    KDFAlgorithm.PBKDF2_HMAC_SHA256,
}

_MAX_INPUT_LENGTH: Final[int] = 4096  # Input length sanity limit

# ============================= Protocol =======================================


@runtime_checkable
class KdfProvider(Protocol):
    """Protocol interface for KDF providers (for DI/testing)."""

    def derive_key(self, secret: bytes, salt: bytes, length: int) -> bytes:
        """Derive key from secret and salt."""
        ...


# ============================= Utility Functions ==============================


def _wipe_sensitive(data: Optional[Union[bytes, bytearray]]) -> None:
    """Attempt to zero out sensitive data (best-effort in Python)."""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    if data is not None:
        del data


def generate_salt(length: int = 16) -> bytes:
    """Cryptographically secure salt generator.

    Args:
        length: Salt length in bytes (8-64 recommended).

    Returns:
        Random salt bytes.

    Raises:
        KDFParameterError: For invalid salt length.

    Example:
        >>> salt = generate_salt(16)
        >>> len(salt)
        16
    """
    if not (8 <= length <= 64):
        logger.warning("Salt length should be 8-64 bytes.")
        raise KDFParameterError("Salt length should be 8..64 bytes")
    salt = secrets.token_bytes(length)
    return salt


def recommend_entropy_warning(password: bytes, salt: bytes) -> None:
    """Check for low entropy (very short repeated or trivial input) to emit warning."""

    def entropy_estimate(data: bytes) -> float:
        # Not cryptographically rigorous; just for user convenience
        if len(set(data)) < 3 or len(data) < 8:
            return 0.0
        return len(set(data)) / len(data)

    if entropy_estimate(password) < 0.20:
        logger.warning(
            "Password likely has very low entropy. Use longer/semi-random secret."
        )
        raise KDFEntropyWarning(
            "Password likely weak; consider increasing length and complexity."
        )

    if entropy_estimate(salt) < 0.2:
        logger.warning(
            "Salt has low entropy; should be random bytes, not reused/constant."
        )


def validate_parameters(
    password: bytes,
    salt: bytes,
    length: int,
    iterations: Optional[int],
    algorithm: KDFAlgorithm,
    memory_cost: int = 2**16,
    parallelism: int = 2,
    time_cost: int = 2,
) -> None:
    """Validate input parameters for selected KDF.

    Args:
        password: Password/secret. Min 8, max 4096.
        salt: Salt. Min 8, max 64, not repeated.
        length: Output key length.
        iterations: PBKDF2 only.
        algorithm: Which KDF.
        memory_cost: Argon2id only.
        parallelism: Argon2id only.
        time_cost: Argon2id only.

    Raises:
        KDFParameterError, KDFAlgorithmError
    """
    if (
        not isinstance(password, bytes)
        or len(password) < 8
        or len(password) > _MAX_INPUT_LENGTH
    ):
        logger.warning("Password length should be 8..4096 bytes; got %d", len(password))
        raise KDFParameterError(
            "Password must be 8..4096 bytes, recommend >=16 and high entropy."
        )

    if not isinstance(salt, bytes) or len(salt) < 8 or len(salt) > 64:
        logger.warning("Salt length should be 8..64 bytes; got %d", len(salt))
        raise KDFParameterError("Salt length must be 8..64 bytes.")

    if not (16 <= length <= 64):
        logger.warning("Key length out of operational range: %d", length)
        raise KDFParameterError("Key length must be 16..64 bytes.")

    if algorithm == KDFAlgorithm.ARGON2ID:
        if not (1 <= time_cost <= 10):
            logger.warning("Argon2id time_cost must be 1..10; got %d", time_cost)
            raise KDFParameterError("Argon2id time_cost/iterations must be 1..10.")
        if not (2**14 <= memory_cost <= 2**19):
            logger.warning(
                "Argon2id memory_cost must be 16 KiB–512 MiB; got %d", memory_cost
            )
            raise KDFParameterError("Argon2id memory must be 16384..524288 bytes.")
        if not (1 <= parallelism <= 8):
            logger.warning("Argon2id parallelism must be 1..8; got %d", parallelism)
            raise KDFParameterError("Argon2id parallelism must be 1..8.")

    elif algorithm == KDFAlgorithm.PBKDF2_HMAC_SHA256:
        iter_rounds = iterations if iterations is not None else 100_000
        if not (10_000 <= iter_rounds <= 1_000_000):
            logger.warning(
                "PBKDF2 iterations must be 10,000..1,000,000; got %d", iter_rounds
            )
            raise KDFParameterError("PBKDF2 iterations must be 10,000..1,000,000.")

    else:
        logger.warning("Unsupported KDF algorithm: %s", algorithm)
        raise KDFAlgorithmError(f"Unsupported algorithm: {algorithm}")


# ============================= Main KDF Function ==============================


def derive_key(
    algorithm: KDFAlgorithm,
    password: bytes,
    salt: Optional[bytes] = None,
    length: int = 32,
    *,
    iterations: Optional[int] = None,  # PBKDF2: default 100_000 ; Argon2id: default 2
    memory_cost: int = 2**16,  # Argon2id only, default 65536 (64MiB)
    parallelism: int = 2,  # Argon2id only, default 2
    time_cost: int = 2,  # Argon2id only, default 2
    to_hex: bool = False,
    to_b64: bool = False,
) -> Union[bytes, str]:
    """Derive cryptographic key from password/salt with Argon2id or PBKDF2.

    Args:
        algorithm: KDF to use.
        password: Secret/password; must be strong and high entropy!
        salt: Salt; None = autogenerate cryptosecure salt.
        length: Key length, bytes (typ. 16..64).
        iterations: Rounds (PBKDF2 or Argon2id time_cost).
        memory_cost: Argon2id, KiB.
        parallelism: Argon2id, threads/lanes.
        time_cost: Argon2id time_cost ("iterations" in Argon2 terms).
        to_hex: Return hex string (for storage/export).
        to_b64: Return base64 string (for transport/API).

    Returns:
        Derived key, optionally encoded.

    Raises:
        KDFParameterError, KDFAlgorithmError, KDFEntropyWarning

    Example:
        >>> key = derive_key(
        ...     algorithm=KDFAlgorithm.ARGON2ID,
        ...     password=b"testpw",
        ...     salt=None,
        ...     length=32,
        ...     time_cost=2,
        ...     memory_cost=65536,
        ...     parallelism=2,
        ...     to_hex=True,
        ... )
        >>> isinstance(key, str) and len(key) == 64
        True
    """
    if salt is None:
        salt = generate_salt(16)

    validate_parameters(
        password,
        salt,
        length,
        iterations,
        algorithm,
        memory_cost,
        parallelism,
        time_cost,
    )

    recommend_entropy_warning(password, salt)

    logger.info(
        "Derive key: algorithm=%s, output_len=%d, time=%s, mem=%d, parallel=%d, hex=%s, b64=%s",
        algorithm.name,
        length,
        time_cost,
        memory_cost,
        parallelism,
        to_hex,
        to_b64,
    )

    try:
        if algorithm is KDFAlgorithm.ARGON2ID:
            ph = argon2.low_level.hash_secret_raw(
                secret=password,
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost // 1024,  # bytes to KiB
                parallelism=parallelism,
                hash_len=length,
                type=argon2.low_level.Type.ID,
            )
            key = ph

        elif algorithm is KDFAlgorithm.PBKDF2_HMAC_SHA256:
            iter_rounds = iterations if iterations is not None else 100_000
            key = hashlib.pbkdf2_hmac(
                "sha256", password, salt, iter_rounds, dklen=length
            )

        else:
            logger.error("Unsupported KDF algorithm: %s", algorithm)
            raise KDFAlgorithmError(f"Unsupported KDF algorithm: {algorithm}")

        # Serialize
        if to_hex:
            result: Union[bytes, str] = key.hex()
        elif to_b64:
            result = base64.b64encode(key).decode("ascii")
        else:
            result = key

        return result

    finally:
        # Zeroization best-effort
        _wipe_sensitive(password if isinstance(password, bytearray) else None)
        _wipe_sensitive(salt if isinstance(salt, bytearray) else None)


# ============================= Convenience Functions ==========================


def derive_key_argon2id(password: bytes, salt: bytes, length: int = 32) -> bytes:
    """Argon2id KDF - returns key of specified length (convenience wrapper).

    Args:
        password: Secret bytes.
        salt: Salt bytes.
        length: Output key length.

    Returns:
        Derived key bytes.
    """
    result = derive_key(
        algorithm=KDFAlgorithm.ARGON2ID,
        password=password,
        salt=salt,
        length=length,
        to_hex=False,
        to_b64=False,
    )
    if isinstance(result, str):
        # Should never happen
        raise AssertionError("KDF returned str: KDF misused with to_hex or to_b64")
    return result


# ============================= Public API ====================================

SUPPORTED_ALGORITHMS: Final[set[KDFAlgorithm]] = _SUPPORTED_ALGORITHMS

__all__ = [
    "KDFAlgorithm",
    "KdfProvider",
    "KDFParameterError",
    "KDFAlgorithmError",
    "KDFEntropyWarning",
    "SUPPORTED_ALGORITHMS",
    "derive_key",
    "derive_key_argon2id",
    "generate_salt",
]
