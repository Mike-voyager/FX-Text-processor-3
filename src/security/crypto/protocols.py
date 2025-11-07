# -*- coding: utf-8 -*-
"""
RU: Протоколы (DI-контракты) для криптоподсистем: симметричное шифрование, подписи, KDF,
хранилище ключей и хэширование; согласованы c текущими реализациями и строгой типизацией.


EN: Dependency-injection Protocols for crypto subsystems: symmetric cipher, signatures,
KDF, keystore, and hashing; aligned with current implementations and strict typing.


Design notes:
- Protocols are @runtime_checkable to allow isinstance checks in tests.
- No Any and no global state; minimal method sets to reduce coupling.
- SymmetricCipherProtocol mirrors the combined/separate tag interface used by AES-GCM class.


References:
- Symmetric AES-GCM class and helpers for combined ciphertext+tag interface.  # see module symmetric
- Ed25519 signatures provider with sign/verify/public_key/fingerprint.        # see module signatures
- KDF API with Argon2id/PBKDF2 parameter sets and derive_key entry point.     # see module kdf
- Keystore backend contract used by secure storage.                            # see module secure_storage
- Hashing provider for password hashing/verification and rehash policy.        # see module hashing
"""


from __future__ import annotations

from typing import (
    Callable,
    Literal,
    Optional,
    Protocol,
    Tuple,
    TypedDict,
    Union,
    runtime_checkable,
)

BytesLike = Union[bytes, bytearray]


class Argon2idParams(TypedDict):
    """Argon2id parameters for KDF providers."""

    version: Literal["argon2id"]
    time_cost: int
    memory_cost: int
    parallelism: int
    salt_len: int


class PBKDF2Params(TypedDict):
    """PBKDF2-HMAC-SHA256 parameters for KDF providers."""

    version: Literal["pbkdf2"]
    iterations: int
    hash_name: Literal["sha256"]
    salt_len: int


KdfParams = Union[Argon2idParams, PBKDF2Params]


@runtime_checkable
class SymmetricCipherProtocol(Protocol):
    """AES-GCM like interface with combined and split tag handling."""

    def encrypt(
        self,
        key: bytes,
        plaintext: BytesLike,
        aad: Optional[bytes] = None,
        *,
        return_combined: bool = True,
    ) -> Union[Tuple[bytes, bytes], Tuple[bytes, bytes, bytes]]:
        """
        Encrypt data.


        Args:
            key: 32-byte key for AES-256-GCM.
            plaintext: message to encrypt; may be bytes or bytearray.
            aad: additional authenticated data.
            return_combined: if True, returns (nonce, ciphertext||tag), otherwise (nonce, ciphertext, tag).


        Returns:
            Either (nonce, combined) or (nonce, ciphertext, tag).
        """
        ...

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        aad: Optional[bytes] = None,
        *,
        has_combined: bool = True,
        tag: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt data.


        Args:
            key: 32-byte key for AES-256-GCM.
            nonce: 12-byte GCM nonce.
            data: ciphertext||tag if has_combined=True, else ciphertext.
            aad: additional authenticated data.
            has_combined: indicates whether `data` includes tag.
            tag: optional 16-byte tag when not using combined mode.


        Returns:
            Decrypted plaintext bytes.
        """
        ...


@runtime_checkable
class SigningProtocol(Protocol):
    """Digital signature provider (e.g., Ed25519)."""

    def sign(self, data: bytes, *, context: Optional[bytes] = None) -> bytes:
        """
        Produce a signature for the given data.


        Args:
            data: message to sign.
            context: optional domain separation/context bytes.


        Returns:
            Signature bytes.
        """
        ...

    def verify(
        self, data: bytes, signature: bytes, *, context: Optional[bytes] = None
    ) -> bool:
        """
        Verify a signature.


        Args:
            data: original message.
            signature: signature to verify.
            context: optional domain separation/context bytes.


        Returns:
            True if signature is valid, False otherwise.
        """
        ...

    def public_key(
        self, fmt: Literal["raw", "hex", "pem"] = "raw"
    ) -> Union[bytes, str]:
        """
        Export public key.


        Args:
            fmt: output format, one of "raw", "hex", "pem".


        Returns:
            Public key in selected format.
        """
        ...

    def get_fingerprint(self) -> str:
        """
        Return a stable public key fingerprint (e.g., hex-encoded SHA-256).


        Returns:
            Hex string fingerprint.
        """
        ...


@runtime_checkable
class KdfProtocol(Protocol):
    """Key derivation function provider (Argon2id, PBKDF2)."""

    def derive_key(
        self,
        password: Union[str, bytes, bytearray],
        salt: bytes,
        length: int,
        *,
        params: KdfParams,
    ) -> bytes:
        """
        Derive a symmetric key from a password and salt.


        Args:
            password: user password or secret.
            salt: cryptographically secure random salt.
            length: desired key length in bytes.
            params: algorithm-specific parameters.


        Returns:
            Derived key bytes of requested length.
        """
        ...


@runtime_checkable
class CryptoServiceProtocol(Protocol):
    def create_encrypted_keystore(
        self,
        filepath: str,
        *,
        password_provider: Callable[[], Union[str, bytes, bytearray]],
        salt_path: str,
        key_len: int = 32,
    ) -> KeyStoreProtocol: ...


@runtime_checkable
class KeyStoreProtocol(Protocol):
    """Key/value secure storage backend used by secure storage."""

    def save(self, name: str, data: bytes) -> None:
        """
        Persist an item by name.


        Args:
            name: item identifier.
            data: serialized bytes to store.
        """
        ...

    def load(self, name: str) -> bytes:
        """
        Load an item by name.


        Args:
            name: item identifier.


        Returns:
            Raw bytes previously stored.
        """
        ...

    def delete(self, name: str) -> None:
        """
        Delete an item by name.


        Args:
            name: item identifier.
        """
        ...


@runtime_checkable
class HashingProtocol(Protocol):
    """Password hashing provider."""

    def hash_password(self, password: str) -> str:
        """
        Hash a password for storage.


        Args:
            password: plaintext password.


        Returns:
            Encoded hash string containing algorithm parameters.
        """
        ...

    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify a password against a stored hash.


        Args:
            password: plaintext password.
            hashed: encoded hash string.


        Returns:
            True if the password matches, False otherwise.
        """
        ...

    def needs_rehash(self, hashed: str) -> bool:
        """
        Check whether the hash needs an upgrade (parameters changed).


        Args:
            hashed: encoded hash string.


        Returns:
            True if rehashing is recommended, False otherwise.
        """
        ...


__all__ = [
    "BytesLike",
    "Argon2idParams",
    "PBKDF2Params",
    "KdfParams",
    "SymmetricCipherProtocol",
    "SigningProtocol",
    "KdfProtocol",
    "KeyStoreProtocol",
    "CryptoServiceProtocol",
    "HashingProtocol",
]
