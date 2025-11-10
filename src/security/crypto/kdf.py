# -*- coding: utf-8 -*-
"""
RU: Провайдер KDF с PBKDF2-HMAC-SHA256 (обязателен) и опциональным Argon2id, с едиными правилами

EN: KDF provider with Argon2id (mandatory for production) and PBKDF2 (legacy/dev-only), using unified salt
generation (utils), strict parameter validation, and best-effort wiping of bytearray secrets.

⚠️ SECURITY POLICY: Argon2id is REQUIRED for production deployments.
PBKDF2 is available ONLY for:
    - for experimenting with this protocol
    - perhaps for formal compliance with some specifications
"""
from __future__ import annotations

import hashlib
import logging
from typing import Final, Optional, Union, cast

from security.crypto.exceptions import KDFAlgorithmError, KDFParameterError
from security.crypto.protocols import (
    Argon2idParams,
    KdfParams,
    KdfProtocol,
    PBKDF2Params,
)
from security.crypto.utils import generate_salt as _utils_generate_salt
from security.crypto.utils import zero_memory

_LOGGER: Final = logging.getLogger(__name__)

_MIN_SALT_LEN: Final[int] = 8
_MAX_SALT_LEN: Final[int] = 64
_MIN_OUT_LEN: Final[int] = 16
_MAX_OUT_LEN: Final[int] = 64
_MIN_PBKDF2_ITERS: Final[int] = 100_000
_ALLOWED_HASH: Final[str] = "sha256"


def generate_salt(length: int = 16) -> bytes:
    """
    Generate cryptographic salt via unified utils RNG.

    Args:
        length: salt length in bytes (8..64).

    Returns:
        Random salt bytes.

    Raises:
        KDFParameterError: if length out of valid range.
    """
    if length < _MIN_SALT_LEN or length > _MAX_SALT_LEN:
        raise KDFParameterError("Salt length must be between 8 and 64 bytes")
    try:
        salt: bytes = _utils_generate_salt(length)
        return salt
    except ValueError as e:
        raise KDFParameterError(str(e)) from e


class DefaultKdfProvider:
    """
    Key derivation function provider supporting PBKDF2-HMAC-SHA256 and Argon2id.

    Implements KdfProtocol interface (duck-typed Protocol):
      - derive_key(password, salt, length, *, params) -> bytes

    Examples:
        >>> kdf = DefaultKdfProvider()
        >>> params = make_pbkdf2_params(iterations=200_000)
        >>> key = kdf.derive_key("password", b"salt1234", 32, params=params)
        >>> assert len(key) == 32
    """

    __slots__ = ()

    def derive_key(
        self,
        password: Union[str, bytes, bytearray],
        salt: bytes,
        length: int,
        *,
        params: KdfParams,
    ) -> bytes:
        """
        Derive key from password and salt.

        Args:
            password: user password or secret (str/bytes/bytearray).
            salt: cryptographically secure random salt.
            length: desired output key length (16..64 bytes).
            params: algorithm-specific parameters (PBKDF2Params or Argon2idParams).

        Returns:
            Derived key bytes.

        Raises:
            KDFParameterError: on invalid parameters.
            KDFAlgorithmError: on algorithm failure.
        """
        if not isinstance(salt, (bytes, bytearray)):
            raise KDFParameterError("Salt must be bytes")
        if len(salt) < _MIN_SALT_LEN or len(salt) > _MAX_SALT_LEN:
            raise KDFParameterError("Salt length must be between 8 and 64 bytes")
        if length < _MIN_OUT_LEN or length > _MAX_OUT_LEN:
            raise KDFParameterError("Output length must be between 16 and 64 bytes")

        pw_mutable = isinstance(password, bytearray)
        try:
            if isinstance(password, str):
                pw_bytes = password.encode("utf-8")
            elif isinstance(password, (bytes, bytearray)):
                pw_bytes = bytes(password)
            else:
                raise KDFParameterError("Password must be str, bytes or bytearray")

            if isinstance(params, dict) and params.get("version") == "pbkdf2":
                pb = cast(PBKDF2Params, params)
                return self._derive_pbkdf2(pw_bytes, bytes(salt), length, pb)
            elif isinstance(params, dict) and params.get("version") == "argon2id":
                ap = cast(Argon2idParams, params)
                return self._derive_argon2id(pw_bytes, bytes(salt), length, ap)
            else:
                raise KDFAlgorithmError("Unsupported KDF version")
        finally:
            if pw_mutable and isinstance(password, bytearray):
                try:
                    zero_memory(password)
                except Exception:
                    pass

    def _derive_pbkdf2(
        self, pw: bytes, salt: bytes, length: int, params: PBKDF2Params
    ) -> bytes:
        """
        Derive key using PBKDF2-HMAC-SHA256.

        Args:
            pw: password bytes.
            salt: salt bytes.
            length: output length.
            params: PBKDF2 parameters.

        Returns:
            Derived key.

        Raises:
            KDFParameterError: on invalid parameters.
            KDFAlgorithmError: on derivation failure.
        """
        iterations = params.get("iterations", 0)
        hash_name = params.get("hash_name", "")
        if hash_name != _ALLOWED_HASH:
            raise KDFParameterError("PBKDF2 hash_name must be 'sha256'")
        if not isinstance(iterations, int) or iterations < _MIN_PBKDF2_ITERS:
            raise KDFParameterError(f"PBKDF2 iterations must be >= {_MIN_PBKDF2_ITERS}")
        try:
            dk: bytes = hashlib.pbkdf2_hmac(
                _ALLOWED_HASH, pw, salt, iterations, dklen=length
            )
            _LOGGER.debug("PBKDF2 derivation completed (iters=%d)", iterations)
            return dk
        except Exception as exc:
            _LOGGER.error("PBKDF2 derivation failed: %s", exc.__class__.__name__)
            raise KDFAlgorithmError("PBKDF2 failed") from exc

    def _derive_argon2id(
        self, pw: bytes, salt: bytes, length: int, params: Argon2idParams
    ) -> bytes:
        """
        Derive key using Argon2id.

        Args:
            pw: password bytes.
            salt: salt bytes.
            length: output length.
            params: Argon2id parameters.

        Returns:
            Derived key.

        Raises:
            KDFParameterError: on invalid parameters.
            KDFAlgorithmError: on derivation failure or if argon2-cffi unavailable.
        """
        try:
            from argon2.low_level import Type, hash_secret_raw
        except Exception as exc:  # pragma: no cover
            _LOGGER.warning("Argon2id not available: %s", exc.__class__.__name__)
            raise KDFAlgorithmError("Argon2id not available") from exc

        time_cost = params.get("time_cost", 0)
        memory_cost = params.get("memory_cost", 0)
        parallelism = params.get("parallelism", 0)

        if not (isinstance(time_cost, int) and time_cost >= 2):
            raise KDFParameterError("Argon2id time_cost must be >= 2")
        if not (isinstance(memory_cost, int) and memory_cost >= 64 * 1024):
            raise KDFParameterError("Argon2id memory_cost must be >= 65536 (KiB)")
        if not (isinstance(parallelism, int) and parallelism >= 1):
            raise KDFParameterError("Argon2id parallelism must be >= 1")

        try:
            dk: bytes = hash_secret_raw(
                secret=pw,
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=length,
                type=Type.ID,
                version=19,
            )
            _LOGGER.debug(
                "Argon2id derivation completed (t=%d, m=%d)", time_cost, memory_cost
            )
            return dk
        except Exception as exc:
            _LOGGER.error("Argon2id derivation failed: %s", exc.__class__.__name__)
            raise KDFAlgorithmError("Argon2id failed") from exc


# --- Public API surface ---

__all__ = [
    "DefaultKdfProvider",
    "generate_salt",
    "derive_key",
    "derive_key_argon2id",
    "make_pbkdf2_params",
    "make_argon2id_params",
]


def make_pbkdf2_params(
    *,
    iterations: int = 100_000,
    hash_name: str = "sha256",
) -> PBKDF2Params:
    """
    Construct PBKDF2 params dict compliant with KdfParams union.

    Args:
        iterations: number of PBKDF2 iterations (>= 100_000).
        hash_name: hash function name (only "sha256" supported).

    Returns:
        PBKDF2Params typed dict.
    """
    return cast(
        PBKDF2Params,
        {
            "version": "pbkdf2",
            "iterations": iterations,
            "hash_name": hash_name,
            "salt_len": 16,
        },
    )


def make_argon2id_params(
    *,
    time_cost: int = 2,
    memory_cost: int = 64 * 1024,
    parallelism: int = 1,
) -> Argon2idParams:
    """
    Construct Argon2id params dict compliant with KdfParams union.

    Args:
        time_cost: number of iterations (>= 2).
        memory_cost: memory usage in KiB (>= 65536).
        parallelism: number of parallel threads (>= 1).

    Returns:
        Argon2idParams typed dict.
    """
    return cast(
        Argon2idParams,
        {
            "version": "argon2id",
            "time_cost": time_cost,
            "memory_cost": memory_cost,
            "parallelism": parallelism,
            "salt_len": 16,
        },
    )


def derive_key(
    password: Union[str, bytes, bytearray],
    salt: bytes,
    length: int = 32,
    *,
    params: Optional[KdfParams] = None,
    provider: Optional[DefaultKdfProvider] = None,
) -> bytes:
    """
    High-level KDF API. If params is None, defaults to Argon2id with safe baseline settings.

    Args:
        password: user password or secret.
        salt: cryptographic salt.
        length: output key length in bytes.
        params: KDF parameters (defaults to Argon2id if None).
        provider: KDF provider instance (creates new if None).

    Returns:
        Derived key bytes.
    """
    if provider is None:
        provider = DefaultKdfProvider()
    if params is None:
        params = make_argon2id_params()
    return provider.derive_key(
        password=password, salt=salt, length=length, params=params
    )


def derive_key_argon2id(
    password: Union[str, bytes, bytearray],
    salt: bytes,
    length: int = 32,
    *,
    time_cost: int = 2,
    memory_cost: int = 64 * 1024,
    parallelism: int = 1,
    provider: Optional[DefaultKdfProvider] = None,
) -> bytes:
    """
    Convenience wrapper for Argon2id derivation with explicit tuning.

    Args:
        password: user password or secret.
        salt: cryptographic salt.
        length: output key length in bytes.
        time_cost: Argon2id time cost (>= 2).
        memory_cost: Argon2id memory in KiB (>= 65536).
        parallelism: Argon2id parallelism (>= 1).
        provider: KDF provider instance (creates new if None).

    Returns:
        Derived key bytes.
    """
    params = make_argon2id_params(
        time_cost=time_cost, memory_cost=memory_cost, parallelism=parallelism
    )
    return derive_key(
        password=password, salt=salt, length=length, params=params, provider=provider
    )
