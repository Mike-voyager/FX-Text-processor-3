# -*- coding: utf-8 -*-

"""
RU: Post-Quantum Cryptography - защита от квантовых компьютеров.
EN: Post-Quantum Cryptography - quantum-resistant algorithms.
"""

from __future__ import annotations

import logging
from typing import Final

from .exceptions import CryptoKeyError, SignatureError

_LOGGER: Final = logging.getLogger(__name__)

# Check availability
try:
    import oqs

    KYBER_AVAILABLE = True
    DILITHIUM_AVAILABLE = True
    _LOGGER.info("liboqs loaded successfully (version %s)", oqs.oqs_version())
except ImportError:
    KYBER_AVAILABLE = False
    DILITHIUM_AVAILABLE = False
    _LOGGER.warning("liboqs not available")


class KyberKEM:
    """Kyber-768 / ML-KEM-768 Key Encapsulation Mechanism (Post-Quantum)."""

    __slots__ = ("_public_key", "_secret_key", "_algorithm")

    _ALGORITHM_NAME: Final[str] = "ML-KEM-768"
    _ALGORITHM_FALLBACK: Final[str] = "Kyber768"

    def __init__(self, public_key: bytes, secret_key: bytes | None = None) -> None:
        if not KYBER_AVAILABLE:
            raise ImportError(
                "Kyber not available - install: pip install liboqs-python"
            )

        self._public_key = public_key
        self._secret_key = secret_key

        # Determine algorithm name
        try:
            with oqs.KeyEncapsulation(self._ALGORITHM_NAME):
                self._algorithm = self._ALGORITHM_NAME
        except oqs.MechanismNotSupportedError:
            self._algorithm = self._ALGORITHM_FALLBACK

    @classmethod
    def generate(cls) -> KyberKEM:
        """Generate new Kyber-768 keypair."""
        if not KYBER_AVAILABLE:
            raise ImportError("Kyber not available")

        # Try new name first
        try:
            algorithm = cls._ALGORITHM_NAME
            with oqs.KeyEncapsulation(algorithm) as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()
        except oqs.MechanismNotSupportedError:
            algorithm = cls._ALGORITHM_FALLBACK
            with oqs.KeyEncapsulation(algorithm) as kem:
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()

        instance = cls(public_key, secret_key)
        instance._algorithm = algorithm

        _LOGGER.info("Generated Kyber-768 keypair (algorithm: %s)", algorithm)
        return instance

    @classmethod
    def from_public_key(cls, public_key: bytes) -> KyberKEM:
        """Create encapsulation-only instance from public key."""
        return cls(public_key, None)

    def encapsulate(self) -> tuple[bytes, bytes]:
        """Encapsulate shared secret with public key."""
        if self._public_key is None:
            raise CryptoKeyError("No public key available")

        with oqs.KeyEncapsulation(self._algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(self._public_key)

        _LOGGER.debug("Kyber encapsulation successful")
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret with private key."""
        if self._secret_key is None:
            raise CryptoKeyError("No secret key available for decapsulation")

        if len(ciphertext) != 1088:
            raise ValueError("Kyber ciphertext must be 1088 bytes")

        with oqs.KeyEncapsulation(self._algorithm, secret_key=self._secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)

        _LOGGER.debug("Kyber decapsulation successful")
        return bytes(shared_secret)

    def export_public_key(self) -> bytes:
        """Export public key (1184 bytes)."""
        if self._public_key is None:
            raise CryptoKeyError("No public key available")
        return bytes(self._public_key)

    def export_secret_key(self) -> bytes:
        """Export secret key (~2400 bytes)."""
        if self._secret_key is None:
            raise CryptoKeyError("No secret key available")
        return bytes(self._secret_key)


class DilithiumSigner:
    """Dilithium-3 / ML-DSA-65 Digital Signature Algorithm (Post-Quantum)."""

    __slots__ = ("_public_key", "_secret_key", "_algorithm")

    _ALGORITHM_NAME: Final[str] = "ML-DSA-65"
    _ALGORITHM_FALLBACK: Final[str] = "Dilithium3"

    def __init__(self, public_key: bytes, secret_key: bytes | None = None) -> None:
        if not DILITHIUM_AVAILABLE:
            raise ImportError(
                "Dilithium not available - install: pip install liboqs-python"
            )

        self._public_key = public_key
        self._secret_key = secret_key

        # Determine algorithm name
        try:
            with oqs.Signature(self._ALGORITHM_NAME):
                self._algorithm = self._ALGORITHM_NAME
        except oqs.MechanismNotSupportedError:
            self._algorithm = self._ALGORITHM_FALLBACK

    @classmethod
    def generate(cls) -> DilithiumSigner:
        """Generate new Dilithium-3 keypair."""
        if not DILITHIUM_AVAILABLE:
            raise ImportError("Dilithium not available")

        # Try new name first
        try:
            algorithm = cls._ALGORITHM_NAME
            with oqs.Signature(algorithm) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()
        except oqs.MechanismNotSupportedError:
            algorithm = cls._ALGORITHM_FALLBACK
            with oqs.Signature(algorithm) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()

        instance = cls(public_key, secret_key)
        instance._algorithm = algorithm

        _LOGGER.info("Generated Dilithium-3 keypair (algorithm: %s)", algorithm)
        return instance

    @classmethod
    def from_public_key(cls, public_key: bytes) -> DilithiumSigner:
        """Create verification-only instance from public key."""
        return cls(public_key, None)

    def sign(self, message: bytes) -> bytes:
        """Sign message with Dilithium."""
        if self._secret_key is None:
            raise SignatureError("No secret key available for signing")

        with oqs.Signature(self._algorithm, secret_key=self._secret_key) as sig:
            signature = sig.sign(message)

        _LOGGER.debug("Dilithium signature generated (%d bytes)", len(signature))
        return bytes(signature)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify Dilithium signature."""
        if self._public_key is None:
            raise SignatureError("No public key available for verification")

        # Note: ML-DSA-65 signature size is 3309 bytes (Dilithium3 was 3293)
        expected_sig_size = 3309
        if len(signature) != expected_sig_size:
            _LOGGER.warning(
                "Invalid Dilithium signature length: %d (expected %d)",
                len(signature),
                expected_sig_size,
            )
            return False

        try:
            with oqs.Signature(self._algorithm) as sig:
                is_valid = sig.verify(message, signature, self._public_key)
            return bool(is_valid)
        except Exception as e:
            _LOGGER.debug("Dilithium verification failed: %s", e.__class__.__name__)
            return False

    def export_public_key(self) -> bytes:
        """Export public key (1952 bytes)."""
        if self._public_key is None:
            raise CryptoKeyError("No public key available")
        return bytes(self._public_key)

    def export_secret_key(self) -> bytes:
        """Export secret key (~4032 bytes for ML-DSA-65)."""
        if self._secret_key is None:
            raise CryptoKeyError("No secret key available")
        return bytes(self._secret_key)


def hybrid_kem_x25519_kyber(
    x25519_public: bytes, kyber_public: bytes
) -> tuple[bytes, bytes, bytes]:
    """Hybrid Key Exchange: X25519 + Kyber-768."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    if len(x25519_public) != 32:
        raise ValueError("X25519 public key must be 32 bytes")
    if len(kyber_public) != 1184:
        raise ValueError("Kyber public key must be 1184 bytes")

    # Classical ECDH
    x25519_private = x25519.X25519PrivateKey.generate()
    x25519_peer = x25519.X25519PublicKey.from_public_bytes(x25519_public)
    x25519_shared = x25519_private.exchange(x25519_peer)

    # PQC KEM
    kyber = KyberKEM.from_public_key(kyber_public)
    kyber_ct, kyber_shared = kyber.encapsulate()

    # Combine via HKDF
    combined_input = x25519_shared + kyber_shared
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b"hybrid-x25519-kyber768-v1",
    )
    combined_secret = hkdf.derive(combined_input)

    # Export ephemeral X25519 public key
    x25519_public_ephemeral = x25519_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    _LOGGER.info("Hybrid KEM completed (X25519 + Kyber-768)")
    return bytes(kyber_ct), bytes(x25519_public_ephemeral), bytes(combined_secret)


__all__ = [
    "KYBER_AVAILABLE",
    "DILITHIUM_AVAILABLE",
    "KyberKEM",
    "DilithiumSigner",
    "hybrid_kem_x25519_kyber",
]
