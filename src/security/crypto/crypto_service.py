# -*- coding: utf-8 -*-
"""
CryptoService (strict Argon2id profile).

- Prefers Argon2id for KDF/password hashing; PBKDF2 is available only by explicit configuration.
- Default signing algorithm: Ed25519. Optional: RSA-4096, ECDSA-P256 via config.
- No secrets are logged.
"""

from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass, field
from typing import Callable, Final, Optional, Union, cast

from security.crypto.protocols import (
    SymmetricCipherProtocol,
    SigningProtocol,
    KdfProtocol,
    HashingProtocol,
    KeyStoreProtocol,
    KdfParams,
    Argon2idParams,
    PBKDF2Params,
)
from security.crypto.symmetric import SymmetricCipher
from security.crypto.signatures import Ed25519Signer
from security.crypto.kdf import DefaultKdfProvider
from security.crypto.hashing import PasswordHasher
from security.crypto.secure_storage import FileEncryptedStorageBackend
from security.crypto.utils import generate_salt, set_secure_file_permissions
from security.crypto.exceptions import KDFAlgorithmError, HashSchemeError

LOGGER: Final = logging.getLogger(__name__)


class AsymmetricSignerAdapter(SigningProtocol):
    """
    Adapter to expose SigningProtocol over an AsymmetricKeyPair instance.

    Notes:
      - Context is ignored for asymmetric signers (kept for interface parity).
      - No secrets are logged.
    """

    __slots__ = ("_akp",)

    def __init__(self, akp: object) -> None:
        self._akp = akp

    def sign(self, data: bytes, *, context: bytes | None = None) -> bytes:
        return cast(bytes, getattr(self._akp, "sign")(data))

    def verify(
        self, data: bytes, signature: bytes, *, context: bytes | None = None
    ) -> bool:
        return bool(getattr(self._akp, "verify")(data, signature))

    def public_key(self, fmt: str = "raw") -> bytes | str:
        return cast(Union[bytes, str], getattr(self._akp, "public_key")(fmt=fmt))

    def get_fingerprint(self) -> str:
        return cast(str, getattr(self._akp, "get_fingerprint")())


@dataclass(slots=True)
class KdfPolicy:
    use_argon2id: bool = True
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 131_072  # KiB
    argon2_parallelism: int = 2
    pbkdf2_iterations: int = 200_000
    salt_len: int = 16


@dataclass(slots=True)
class HashingPolicy:
    scheme: str = "argon2id"  # "argon2id" | "pbkdf2"
    iterations: int = 200_000
    salt_len: int = 16


@dataclass(slots=True)
class ServiceConfig:
    signing_algorithm: str = "ed25519"  # "ed25519" | "rsa4096" | "ecdsa_p256"
    rsa_key_size: int = 4096
    kdf: KdfPolicy = field(default_factory=KdfPolicy)
    hashing: HashingPolicy = field(default_factory=HashingPolicy)
    pepper_provider: Optional[Callable[[], bytes]] = None
    pepper_version: Optional[str] = None


@dataclass(slots=True)
class CryptoService:
    """
    Unified cryptographic service façade.
    """

    symmetric: SymmetricCipherProtocol
    signer: SigningProtocol
    kdf: KdfProtocol
    hasher: HashingProtocol
    config: ServiceConfig

    @staticmethod
    def new_default(cfg: ServiceConfig | None = None) -> "CryptoService":
        """
        Create a default CryptoService according to config.

        Raises:
            HashSchemeError: If hashing scheme is argon2id but argon2 is unavailable.
            ValueError: If signing algorithm is not supported.
        """
        cfg = cfg or ServiceConfig()

        # Symmetric: hold concrete impl, expose as protocol for typing
        symmetric_impl = SymmetricCipher()
        symmetric: SymmetricCipherProtocol = cast(
            SymmetricCipherProtocol, symmetric_impl
        )

        # KDF provider
        kdf_provider: KdfProtocol = DefaultKdfProvider()

        # Hashing provider
        if cfg.hashing.scheme == "argon2id":
            try:
                __import__("argon2")
            except ImportError as e:
                LOGGER.error("Argon2 required for hashing but not available")
                raise HashSchemeError("Argon2id not available") from e
            hasher: HashingProtocol = PasswordHasher(
                scheme="argon2id",
                time_cost=2,
                memory_cost=65_536,
                parallelism=1,
                salt_len=cfg.hashing.salt_len,
                pepper_provider=cfg.pepper_provider,
                pepper_version=cfg.pepper_version,
            )
        elif cfg.hashing.scheme == "pbkdf2":
            hasher = PasswordHasher(
                scheme="pbkdf2",
                iterations=cfg.hashing.iterations,
                salt_len=cfg.hashing.salt_len,
                pepper_provider=cfg.pepper_provider,
                pepper_version=cfg.pepper_version,
            )
        else:
            raise HashSchemeError("Unsupported hashing scheme")

        # Signing provider
        if cfg.signing_algorithm == "ed25519":
            signer: SigningProtocol = cast(SigningProtocol, Ed25519Signer.generate())
        elif cfg.signing_algorithm in ("rsa4096", "ecdsa_p256"):
            from security.crypto.asymmetric import AsymmetricKeyPair

            akp = AsymmetricKeyPair.generate(
                cfg.signing_algorithm, key_size=cfg.rsa_key_size
            )
            signer = AsymmetricSignerAdapter(akp)
        else:
            raise ValueError("Unsupported signing algorithm")

        return CryptoService(symmetric, signer, kdf_provider, hasher, cfg)

    # ---- Password hashing façade ----

    def hash_password(self, password: str) -> str:
        return self.hasher.hash_password(password)

    def verify_password(self, password: str, hashed: str) -> bool:
        return self.hasher.verify_password(password, hashed)

    def needs_rehash(self, hashed: str) -> bool:
        return self.hasher.needs_rehash(hashed)

    # ---- Signing façade ----

    def sign(self, data: bytes, *, context: bytes | None = None) -> bytes:
        try:
            return self.signer.sign(data, context=context)  # type: ignore[arg-type]
        except TypeError:
            return cast(bytes, getattr(self.signer, "sign")(data))

    def verify(
        self, data: bytes, signature: bytes, *, context: bytes | None = None
    ) -> bool:
        try:
            return self.signer.verify(data, signature, context=context)  # type: ignore[arg-type]
        except TypeError:
            return bool(getattr(self.signer, "verify")(data, signature))

    # ---- Symmetric façade ----

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes | bytearray,
        *,
        aad: bytes | None = None,
        return_combined: bool = True,
    ) -> tuple[bytes, bytes] | tuple[bytes, bytes, bytes]:
        res = self.symmetric.encrypt(
            key, plaintext, aad=aad, return_combined=return_combined
        )
        return cast(tuple[bytes, bytes] | tuple[bytes, bytes, bytes], res)

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        *,
        aad: bytes | None = None,
        has_combined: bool = True,
        tag: bytes | None = None,
    ) -> bytes:
        res = self.symmetric.decrypt(
            key, nonce, data, aad=aad, has_combined=has_combined, tag=tag
        )
        return cast(bytes, res)

    # ---- Encrypted keystore factory ----

    def create_encrypted_keystore(
        self,
        *,
        filepath: str,
        password_provider: Callable[[], str],
        salt_path: str,
        key_len: int = 32,
    ) -> KeyStoreProtocol:
        salt = _load_or_create_salt(salt_path, self.config.kdf.salt_len)
        set_secure_file_permissions(salt_path)

        password = password_provider().encode("utf-8")

        # Apply pepper at KDF stage (separate from hashing policy)
        if self.config.pepper_provider is not None:
            import hashlib
            import hmac

            pepper = self.config.pepper_provider()
            password = hmac.new(pepper, password, hashlib.sha256).digest()

        params = self._select_kdf_params_strict()
        key = self.kdf.derive_key(password, salt, key_len, params=params)

        return FileEncryptedStorageBackend(filepath, self.symmetric, lambda: key)

    # ---- Internals ----

    def _select_kdf_params_strict(self) -> KdfParams:
        if self.config.kdf.use_argon2id:
            try:
                __import__("argon2")
            except ImportError as e:
                LOGGER.error("Argon2 required for KDF but not available")
                raise KDFAlgorithmError("Argon2 not available") from e
            return Argon2idParams(
                version="argon2id",
                time_cost=self.config.kdf.argon2_time_cost,
                memory_cost=self.config.kdf.argon2_memory_cost,
                parallelism=self.config.kdf.argon2_parallelism,
                salt_len=self.config.kdf.salt_len,
            )
        return PBKDF2Params(
            version="pbkdf2",
            hash_name="sha256",
            iterations=self.config.kdf.pbkdf2_iterations,
            salt_len=self.config.kdf.salt_len,
        )


# ---- Helpers ----


def _load_or_create_salt(path: str, length: int) -> bytes:
    if os.path.exists(path):
        data = _read_all(path)
        try:
            salt = base64.b64decode(data, validate=True)
            if len(salt) == length:
                return salt
        except Exception:
            if len(data) == length:
                return data
            LOGGER.error("Invalid salt format or length in %s", path)
            raise ValueError("Invalid salt format/length")
    salt = generate_salt(length)
    _write_all(path, base64.b64encode(salt))
    return salt


def _read_all(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _write_all(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


__all__ = [
    "CryptoService",
    "ServiceConfig",
    "KdfPolicy",
    "HashingPolicy",
    "_load_or_create_salt",
]
