# -*- coding: utf-8 -*-
"""
Asymmetric crypto: Ed25519 (sign/verify), RSA (OAEP encrypt/decrypt, PSS sign/verify),
ECDSA P-256 (sign/verify); PEM import/export, safe logging, and immutable keypair wrapper.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Optional, Union, Callable, Dict, Mapping, Final

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding, ec
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

logger: Final = logging.getLogger("fxtext.security.asymmetric")

SUPPORTED_ALGORITHMS: Final[tuple[str, ...]] = ("ed25519", "rsa4096", "ecdsa_p256")
DEFAULT_RSA_KEYSIZE: Final[int] = 4096
SENSITIVE_KEYWORDS: Final[tuple[str, ...]] = (
    "password",
    "private",
    "pem",
    "secret",
    "token",
    "key",
)

__all__ = [
    "AsymmetricKeyPair",
    "UnsupportedAlgorithmError",
    "KeyFormatError",
    "AlgorithmFactory",
]


def _secure_log(msg: str, *args: Any) -> None:
    text = msg.lower() + "".join(str(a).lower() for a in args)
    if any(word in text for word in SENSITIVE_KEYWORDS):
        return
    logger.info(msg, *args)


class UnsupportedAlgorithmError(ValueError):
    """Unsupported asymmetric algorithm."""


class KeyFormatError(ValueError):
    """Key encoding/format error."""


def _rsa_oaep_overhead(hash_alg: hashes.HashAlgorithm = hashes.SHA256()) -> int:
    h = hash_alg.digest_size
    return 2 * h + 2


@dataclass(frozen=True)
class AsymmetricKeyPair:
    """
    Immutable wrapper for asymmetric key pairs.

    Example:
        >>> kp = AsymmetricKeyPair.generate("ed25519")
        >>> sig = kp.sign(b"hello")
        >>> assert kp.verify(b"hello", sig)
    """

    private_key: Union[
        ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, None
    ]
    public_key: Union[
        ed25519.Ed25519PublicKey, rsa.RSAPublicKey, ec.EllipticCurvePublicKey, None
    ]
    algorithm: str

    @staticmethod
    def generate(algorithm: str, key_size: Optional[int] = None) -> "AsymmetricKeyPair":
        _secure_log("Generating keypair: algorithm=%s", algorithm)
        if algorithm == "ed25519":
            priv = ed25519.Ed25519PrivateKey.generate()
            return AsymmetricKeyPair(priv, priv.public_key(), algorithm)
        if algorithm == "rsa4096":
            ks = key_size or DEFAULT_RSA_KEYSIZE
            if ks < 2048 or ks % 256 != 0:
                raise ValueError("RSA key_size must be >= 2048 and divisible by 256")
            priv = rsa.generate_private_key(public_exponent=65537, key_size=ks)
            return AsymmetricKeyPair(priv, priv.public_key(), algorithm)
        if algorithm == "ecdsa_p256":
            priv = ec.generate_private_key(ec.SECP256R1())
            return AsymmetricKeyPair(priv, priv.public_key(), algorithm)
        logger.error("Unsupported algorithm: %s", algorithm)
        raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")

    @staticmethod
    def from_private_bytes(
        data: bytes, algorithm: str, password: Optional[str] = None
    ) -> "AsymmetricKeyPair":
        _secure_log(
            "Loading private key: %s [pw=%s]",
            algorithm,
            "******" if password else "(none)",
        )
        if algorithm not in SUPPORTED_ALGORITHMS:
            logger.error("Unsupported algorithm: %s", algorithm)
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")
        pw = password.encode("utf-8") if password else None
        try:
            pk = serialization.load_pem_private_key(data, password=pw)
            if algorithm == "ed25519" and isinstance(pk, ed25519.Ed25519PrivateKey):
                return AsymmetricKeyPair(pk, pk.public_key(), algorithm)
            if algorithm == "rsa4096" and isinstance(pk, rsa.RSAPrivateKey):
                return AsymmetricKeyPair(pk, pk.public_key(), algorithm)
            if algorithm == "ecdsa_p256" and isinstance(pk, ec.EllipticCurvePrivateKey):
                return AsymmetricKeyPair(pk, pk.public_key(), algorithm)
            raise KeyFormatError("PEM does not match declared algorithm")
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            logger.error("Key import failed: %s (%s)", type(e).__name__, str(e))
            raise KeyFormatError(f"Failed to import private key: {e}") from e

    @staticmethod
    def from_public_bytes(data: bytes, algorithm: str) -> "AsymmetricKeyPair":
        if algorithm not in SUPPORTED_ALGORITHMS:
            logger.error("Unsupported algorithm: %s", algorithm)
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {algorithm}")
        try:
            pk = serialization.load_pem_public_key(data)
            if algorithm == "ed25519" and isinstance(pk, ed25519.Ed25519PublicKey):
                return AsymmetricKeyPair(None, pk, algorithm)
            if algorithm == "rsa4096" and isinstance(pk, rsa.RSAPublicKey):
                return AsymmetricKeyPair(None, pk, algorithm)
            if algorithm == "ecdsa_p256" and isinstance(pk, ec.EllipticCurvePublicKey):
                return AsymmetricKeyPair(None, pk, algorithm)
            raise KeyFormatError("PEM public key does not match declared algorithm")
        except (ValueError, TypeError, UnsupportedAlgorithm) as e:
            logger.error("Public key import failed: %s (%s)", type(e).__name__, str(e))
            raise KeyFormatError(f"Failed to import public key: {e}") from e

    def export_private_bytes(self, password: Optional[str] = None) -> bytes:
        if self.private_key is None:
            raise NotImplementedError("No private key present.")
        enc = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        )
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            enc,
        )

    def export_public_bytes(self) -> bytes:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, data: bytes) -> bytes:
        if self.private_key is None:
            raise NotImplementedError("No private key present.")
        if isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            return self.private_key.sign(data)
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return self.private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        if isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            return self.private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        raise UnsupportedAlgorithmError(f"Unsupported algorithm: {self.algorithm}")

    def verify(self, data: bytes, signature: bytes) -> bool:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        try:
            if isinstance(self.public_key, ed25519.Ed25519PublicKey):
                self.public_key.verify(signature, data)
                return True
            if isinstance(self.public_key, rsa.RSAPublicKey):
                self.public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True
            if isinstance(self.public_key, ec.EllipticCurvePublicKey):
                self.public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return True
            raise UnsupportedAlgorithmError(f"Unsupported algorithm: {self.algorithm}")
        except InvalidSignature:
            return False

    def encrypt(self, data: bytes) -> bytes:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        if isinstance(self.public_key, rsa.RSAPublicKey):
            overhead = _rsa_oaep_overhead()
            limit = self.public_key.key_size // 8 - overhead
            if len(data) > limit:
                raise ValueError(f"RSA plain length must be <= {limit} bytes for key")
            return self.public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        raise NotImplementedError(f"{self.algorithm} does not support encryption.")

    def decrypt(self, data: bytes) -> bytes:
        if self.private_key is None:
            raise NotImplementedError("No private key present.")
        if isinstance(self.private_key, rsa.RSAPrivateKey):
            return self.private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        raise NotImplementedError(f"{self.algorithm} does not support decryption.")

    def get_public_fingerprint(self) -> str:
        if self.public_key is None:
            raise NotImplementedError("No public key present.")
        return sha256(self.export_public_bytes()).hexdigest()

    def equals_public(self, other: object) -> bool:
        if not isinstance(other, AsymmetricKeyPair):
            return False
        return self.get_public_fingerprint() == other.get_public_fingerprint()


AlgorithmFactory: Dict[str, Callable[..., AsymmetricKeyPair]] = {
    "ed25519": lambda **_: AsymmetricKeyPair.generate("ed25519"),
    "rsa4096": lambda **kw: AsymmetricKeyPair.generate(
        "rsa4096", kw.get("key_size", DEFAULT_RSA_KEYSIZE)
    ),
    "ecdsa_p256": lambda **_: AsymmetricKeyPair.generate("ecdsa_p256"),
}
