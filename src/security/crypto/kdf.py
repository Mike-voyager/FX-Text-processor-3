# -*- coding: utf-8 -*-
"""
RU: Провайдер KDF с PBKDF2-HMAC-SHA256 (обязателен) и опциональным Argon2id, с едиными правилами
генерации соли (utils), строгой валидацией параметров и best-effort занулением bytearray‑секретов.

EN: KDF provider with PBKDF2‑HMAC‑SHA256 (mandatory) and optional Argon2id, using unified salt
generation (utils), strict parameter validation, and best-effort wiping of bytearray secrets.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Final, Union, cast

from security.crypto.exceptions import KDFAlgorithmError, KDFParameterError
from security.crypto.protocols import (
    KdfProtocol,
    KdfParams,
    Argon2idParams,
    PBKDF2Params,
)
from security.crypto.utils import generate_salt as _utils_generate_salt, zero_memory

_LOGGER: Final = logging.getLogger(__name__)

_MIN_SALT_LEN: Final[int] = 8
_MAX_SALT_LEN: Final[int] = 64
_MIN_OUT_LEN: Final[int] = 16
_MAX_OUT_LEN: Final[int] = 64
_MIN_PBKDF2_ITERS: Final[int] = 100_000
_ALLOWED_HASH: Final[str] = "sha256"


def generate_salt(length: int = 16) -> bytes:
    if length < _MIN_SALT_LEN or length > _MAX_SALT_LEN:
        raise KDFParameterError("Salt length must be between 8 and 64 bytes")
    try:
        return _utils_generate_salt(length)
    except ValueError as e:
        raise KDFParameterError(str(e)) from e


class DefaultKdfProvider(KdfProtocol):
    def derive_key(
        self,
        password: Union[str, bytes, bytearray],
        salt: bytes,
        length: int,
        *,
        params: KdfParams,
    ) -> bytes:
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
            if pw_mutable:
                try:
                    zero_memory(password)  # type: ignore[arg-type]
                except Exception:
                    pass

    def _derive_pbkdf2(
        self, pw: bytes, salt: bytes, length: int, params: PBKDF2Params
    ) -> bytes:
        iterations = params.get("iterations", 0)
        hash_name = params.get("hash_name", "")
        if hash_name != _ALLOWED_HASH:
            raise KDFParameterError("PBKDF2 hash_name must be 'sha256'")
        if not isinstance(iterations, int) or iterations < _MIN_PBKDF2_ITERS:
            raise KDFParameterError(f"PBKDF2 iterations must be >= {_MIN_PBKDF2_ITERS}")
        try:
            dk = hashlib.pbkdf2_hmac(_ALLOWED_HASH, pw, salt, iterations, dklen=length)
            _LOGGER.info("PBKDF2 derivation completed.")
            return dk
        except Exception as exc:
            _LOGGER.error("PBKDF2 derivation failed: %s", exc.__class__.__name__)
            raise KDFAlgorithmError("PBKDF2 failed") from exc

    def _derive_argon2id(
        self, pw: bytes, salt: bytes, length: int, params: Argon2idParams
    ) -> bytes:
        try:
            from argon2.low_level import hash_secret_raw, Type  # type: ignore[import]
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
            dk = hash_secret_raw(
                secret=pw,
                salt=salt,
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=length,
                type=Type.ID,
                version=19,  # Argon2 low-level version v=19 (v1.3) is fixed for determinism
            )
            _LOGGER.info("Argon2id derivation completed.")
            return dk
        except Exception as exc:
            _LOGGER.error("Argon2id derivation failed: %s", exc.__class__.__name__)
            raise KDFAlgorithmError("Argon2id failed") from exc


__all__ = ["DefaultKdfProvider", "generate_salt"]
