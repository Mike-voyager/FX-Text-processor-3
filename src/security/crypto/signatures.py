# -*- coding: utf-8 -*-
"""
RU: Провайдер подписей Ed25519 с безопасной сериализацией ключей и DI‑совместимым API.

EN: Ed25519 signatures provider with safe key serialization and DI‑friendly API.

Security & design:
- No global state; instances are independent and thread-safe (cryptography backend is thread-safe).
- Secrets are never logged; only structural events.
- Private key material uses 32-byte seed (Ed25519) in memory; best-effort zeroization applies only to bytearray inputs.
- Optional 'context' performs deterministic domain separation via prehash: H = SHA-512("CTX:" + context + ":" + data),
  then sign/verify H instead of raw data. This does not implement Ed25519ph standard, but provides consistent separation.
- Context length is limited to 64 KB to prevent DoS attacks.

Public API (implements SigningProtocol):
- sign(data, *, context) -> bytes
- verify(data, signature, *, context) -> bool
- public_key(fmt="raw") -> bytes|str
- get_fingerprint() -> str

Key I/O helpers:
- generate(), from_private_bytes(), from_public_bytes()
- save_seed_encrypted(...), load_seed_encrypted(...)

Examples:
    >>> signer = Ed25519Signer.generate()
    >>> sig = signer.sign(b"hello")
    >>> assert signer.verify(b"hello", sig)
    >>> pub_hex = signer.public_key("hex")
    >>> fp = signer.get_fingerprint()
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import (
    TYPE_CHECKING,
    Callable,
    Final,
    Literal,
    Optional,
    Protocol,
    Union,
)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from security.crypto.exceptions import (
    SignatureError,
    SignatureGenerationError,
    SignatureVerificationError,
)
from security.crypto.utils import (
    generate_random_bytes,
    zero_memory,
)

if TYPE_CHECKING:
    # Optional: for documentation purposes; not required due to local Protocols below.
    from security.crypto.crypto_service import CryptoService  # noqa: F401

_LOGGER: Final = logging.getLogger(__name__)

BytesLike = Union[bytes, bytearray]
PubFmt = Literal["raw", "hex", "pem"]

# Security limits
_MAX_CONTEXT_LEN: Final[int] = 64 * 1024  # 64 KB reasonable limit to prevent DoS


class _KeystoreProto(Protocol):
    def save(self, name: str, data: bytes) -> None: ...
    def load(self, name: str) -> bytes: ...
    def delete(self, name: str) -> None: ...


class _CryptoServiceProto(Protocol):
    def create_encrypted_keystore(
        self,
        filepath: str,
        *,
        password_provider: Callable[[], Union[str, bytes, bytearray]],
        salt_path: str,
        key_len: int = 32,
    ) -> _KeystoreProto: ...


def _prehash_with_context(data: bytes, context: Optional[bytes]) -> bytes:
    """
    Apply domain separation via context prehashing.

    Args:
        data: message data to hash.
        context: optional domain separation context.

    Returns:
        Prehashed message (SHA-512 if context provided, otherwise original data).

    Raises:
        SignatureError: if context exceeds maximum length.
    """
    if context is None:
        return data

    if len(context) > _MAX_CONTEXT_LEN:
        raise SignatureError(f"Context too long (max {_MAX_CONTEXT_LEN} bytes)")

    h = hashlib.sha512()
    h.update(b"CTX:")
    h.update(context)
    h.update(b":")
    h.update(data)
    return h.digest()


@dataclass(frozen=True)
class _PublicKeyView:
    raw: bytes


class Ed25519Signer:
    """
    Ed25519 digital signature provider with context support.

    Implements SigningProtocol interface (duck-typed Protocol):
      - sign(data: bytes, *, context: Optional[bytes]) -> bytes
      - verify(data: bytes, signature: bytes, *, context: Optional[bytes]) -> bool
      - public_key(fmt: Literal["raw", "hex", "pem"]) -> Union[bytes, str]
      - get_fingerprint() -> str

    Examples:
        >>> signer = Ed25519Signer.generate()
        >>> sig = signer.sign(b"message", context=b"domain1")
        >>> assert signer.verify(b"message", sig, context=b"domain1")
        >>> assert not signer.verify(b"message", sig, context=b"domain2")
    """

    __slots__ = ("_priv", "_pub")

    def __init__(self, private_key: Optional[BytesLike] = None) -> None:
        self._priv: Optional[Ed25519PrivateKey] = None
        self._pub: Optional[_PublicKeyView] = None
        if private_key is None:
            return
        try:
            seed = bytes(private_key)
            if len(seed) != 32:
                raise ValueError("Ed25519 private seed must be 32 bytes")
            priv = Ed25519PrivateKey.from_private_bytes(seed)
            pub = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._priv = priv
            self._pub = _PublicKeyView(pub)
        except Exception as exc:
            _LOGGER.error("Ed25519 init failed: %s", exc.__class__.__name__)
            raise SignatureError("Invalid Ed25519 private key material") from exc
        finally:
            if isinstance(private_key, bytearray):
                try:
                    zero_memory(private_key)
                except Exception:
                    pass

    @classmethod
    def generate(cls) -> Ed25519Signer:
        seed = generate_random_bytes(32)
        return cls(seed)

    @classmethod
    def from_private_bytes(cls, seed32: BytesLike) -> Ed25519Signer:
        return cls(seed32)

    @classmethod
    def from_public_bytes(cls, pub32: bytes) -> Ed25519Signer:
        if not isinstance(pub32, (bytes, bytearray)) or len(pub32) != 32:
            raise SignatureError("Invalid Ed25519 public key length")
        obj = cls()
        try:
            Ed25519PublicKey.from_public_bytes(bytes(pub32))
            object.__setattr__(obj, "_pub", _PublicKeyView(bytes(pub32)))
        except Exception as exc:
            _LOGGER.error("Invalid public key: %s", exc.__class__.__name__)
            raise SignatureError("Invalid Ed25519 public key material") from exc
        return obj

    def sign(self, data: bytes, *, context: Optional[bytes] = None) -> bytes:
        if self._priv is None:
            raise SignatureGenerationError("No private key available")
        try:
            message = _prehash_with_context(data, context)
            return bytes(self._priv.sign(message))
        except Exception as exc:
            _LOGGER.error("Ed25519 sign failed: %s", exc.__class__.__name__)
            raise SignatureGenerationError("Signing failed") from exc

    def verify(
        self,
        data: bytes,
        signature: bytes,
        *,
        context: Optional[bytes] = None,
    ) -> bool:
        if self._pub is None:
            if self._priv is None:
                raise SignatureVerificationError("No public key available")
            pub_raw = self._priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._pub = _PublicKeyView(pub_raw)

        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            raise SignatureVerificationError("Invalid signature length")

        try:
            pub = Ed25519PublicKey.from_public_bytes(self._pub.raw)
            message = _prehash_with_context(data, context)
            pub.verify(bytes(signature), message)
            return True
        except Exception:
            return False

    def public_key(self, fmt: PubFmt = "raw") -> Union[bytes, str]:
        if self._pub is None:
            if self._priv is None:
                raise SignatureError("No public key available")
            pub_raw = self._priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._pub = _PublicKeyView(pub_raw)

        raw = self._pub.raw
        if fmt == "raw":
            return raw
        if fmt == "hex":
            return raw.hex()
        if fmt == "pem":
            pub = Ed25519PublicKey.from_public_bytes(raw)
            pem = pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return str(pem.decode("ascii"))
        raise ValueError("Unsupported public key format")

    def get_fingerprint(self) -> str:
        raw = self.public_key("raw")
        assert isinstance(raw, (bytes, bytearray))
        return hashlib.sha256(bytes(raw)).hexdigest()

    @staticmethod
    def save_seed_encrypted(
        keystore_path: str,
        salt_path: str,
        password_provider: Callable[[], Union[str, bytes, bytearray]],
        seed: bytes,
        *,
        crypto_service_factory: Callable[[], _CryptoServiceProto],
        item_name: str = "ed25519_seed",
    ) -> None:
        """
        Save 32-byte Ed25519 seed into encrypted keystore using AES-GCM key derived via Argon2id.
        """
        svc = crypto_service_factory()
        ks: _KeystoreProto = svc.create_encrypted_keystore(
            keystore_path,
            password_provider=password_provider,
            salt_path=salt_path,
            key_len=32,
        )
        ks.save(item_name, seed)

    @staticmethod
    def load_seed_encrypted(
        keystore_path: str,
        salt_path: str,
        password_provider: Callable[[], Union[str, bytes, bytearray]],
        *,
        crypto_service_factory: Callable[[], _CryptoServiceProto],
        item_name: str = "ed25519_seed",
    ) -> bytes:
        """
        Load 32-byte Ed25519 seed from encrypted keystore.
        """
        svc = crypto_service_factory()
        ks: _KeystoreProto = svc.create_encrypted_keystore(
            keystore_path,
            password_provider=password_provider,
            salt_path=salt_path,
            key_len=32,
        )
        return ks.load(item_name)


__all__ = ["Ed25519Signer"]
