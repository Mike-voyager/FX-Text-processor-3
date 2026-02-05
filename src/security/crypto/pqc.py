# -*- coding: utf-8 -*-
"""
RU: Post-Quantum Cryptography - защита от квантовых компьютеров.
EN: Post-Quantum Cryptography - quantum-resistant algorithms.

Algorithms:
- Kyber-768: NIST ML-KEM (Key Encapsulation Mechanism)
- Dilithium-3: NIST ML-DSA (Digital Signature Algorithm)

Security:
- Kyber: ~192-bit quantum security
- Dilithium: ~192-bit quantum security
- Hybrid schemes with classical algorithms recommended
"""
from __future__ import annotations

import logging
from typing import Final, Optional, Tuple

from .exceptions import CryptoKeyError, SignatureError
from .utils import generate_random_bytes

_LOGGER: Final = logging.getLogger(__name__)

# Check availability
try:
    from pqcrypto.kem.kyber768 import (
        generate_keypair as kyber_generate,
        encrypt as kyber_encrypt,
        decrypt as kyber_decrypt
    )
    KYBER_AVAILABLE = True
except ImportError:
    KYBER_AVAILABLE = False
    _LOGGER.warning("Kyber not available - install: pip install pqcrypto")

try:
    from pqcrypto.sign.dilithium3 import (
        generate_keypair as dilithium_generate,
        sign as dilithium_sign,
        verify as dilithium_verify
    )
    DILITHIUM_AVAILABLE = True
except ImportError:
    DILITHIUM_AVAILABLE = False
    _LOGGER.warning("Dilithium not available - install: pip install pqcrypto")


class KyberKEM:
    """
    Kyber-768 Key Encapsulation Mechanism (Post-Quantum).
    
    Use for hybrid key exchange:
        classical_secret = X25519_exchange(...)
        pqc_secret = KyberKEM.encapsulate(kyber_pk)
        combined = HKDF(classical_secret + pqc_secret)
    
    Key sizes:
        Public key: 1184 bytes
        Secret key: 2400 bytes
        Ciphertext: 1088 bytes
        Shared secret: 32 bytes
    """
    
    __slots__ = ('_public_key', '_secret_key')
    
    def __init__(
        self, 
        public_key: bytes, 
        secret_key: Optional[bytes] = None
    ):
        if not KYBER_AVAILABLE:
            raise ImportError("Kyber not available")
        
        self._public_key = public_key
        self._secret_key = secret_key
    
    @classmethod
    def generate(cls) -> KyberKEM:
        """Generate new Kyber keypair."""
        if not KYBER_AVAILABLE:
            raise ImportError("Kyber not available")
        
        pk, sk = kyber_generate()
        _LOGGER.info("Generated Kyber-768 keypair")
        return cls(pk, sk)
    
    @classmethod
    def from_public_key(cls, public_key: bytes) -> KyberKEM:
        """Create encapsulation-only instance."""
        return cls(public_key, None)
    
    def encapsulate(self) -> Tuple[bytes, bytes]:
        """
        Encapsulate shared secret with public key.
        
        Returns:
            (ciphertext, shared_secret): 
                - ciphertext: 1088 bytes (send to recipient)
                - shared_secret: 32 bytes (use for encryption)
        
        Raises:
            CryptoKeyError: if public key unavailable.
        """
        if self._public_key is None:
            raise CryptoKeyError("No public key available")
        
        ciphertext, shared_secret = kyber_encrypt(self._public_key)
        _LOGGER.debug("Kyber encapsulation successful")
        return bytes(ciphertext), bytes(shared_secret)
    
    def decapsulate(self, ciphertext: bytes) -> bytes:
        """
        Decapsulate shared secret with private key.
        
        Args:
            ciphertext: 1088 bytes from encapsulate().
        
        Returns:
            shared_secret: 32 bytes.
        
        Raises:
            CryptoKeyError: if secret key unavailable.
        """
        if self._secret_key is None:
            raise CryptoKeyError("No secret key available for decapsulation")
        
        if len(ciphertext) != 1088:
            raise ValueError("Kyber ciphertext must be 1088 bytes")
        
        shared_secret = kyber_decrypt(self._secret_key, ciphertext)
        _LOGGER.debug("Kyber decapsulation successful")
        return bytes(shared_secret)
    
    def export_public_key(self) -> bytes:
        """Export public key (1184 bytes)."""
        if self._public_key is None:
            raise CryptoKeyError("No public key available")
        return bytes(self._public_key)
    
    def export_secret_key(self) -> bytes:
        """Export secret key (2400 bytes). Store securely!"""
        if self._secret_key is None:
            raise CryptoKeyError("No secret key available")
        return bytes(self._secret_key)


class DilithiumSigner:
    """
    Dilithium-3 Digital Signature Algorithm (Post-Quantum).
    
    Use for long-term signatures that must resist quantum attacks.
    
    Key sizes:
        Public key: 1952 bytes
        Secret key: 4000 bytes
        Signature: 3293 bytes
    """
    
    __slots__ = ('_public_key', '_secret_key')
    
    def __init__(
        self, 
        public_key: bytes, 
        secret_key: Optional[bytes] = None
    ):
        if not DILITHIUM_AVAILABLE:
            raise ImportError("Dilithium not available")
        
        self._public_key = public_key
        self._secret_key = secret_key
    
    @classmethod
    def generate(cls) -> DilithiumSigner:
        """Generate new Dilithium keypair."""
        if not DILITHIUM_AVAILABLE:
            raise ImportError("Dilithium not available")
        
        pk, sk = dilithium_generate()
        _LOGGER.info("Generated Dilithium-3 keypair")
        return cls(pk, sk)
    
    @classmethod
    def from_public_key(cls, public_key: bytes) -> DilithiumSigner:
        """Create verification-only instance."""
        return cls(public_key, None)
    
    def sign(self, message: bytes) -> bytes:
        """
        Sign message with Dilithium.
        
        Args:
            message: data to sign.
        
        Returns:
            signature: 3293 bytes.
        
        Raises:
            SignatureError: if secret key unavailable.
        """
        if self._secret_key is None:
            raise SignatureError("No secret key available for signing")
        
        signature = dilithium_sign(self._secret_key, message)
        _LOGGER.debug("Dilithium signature generated (%d bytes)", len(signature))
        return bytes(signature)
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """
        Verify Dilithium signature.
        
        Args:
            message: original message.
            signature: 3293-byte signature.
        
        Returns:
            True if valid, False otherwise.
        """
        if self._public_key is None:
            raise SignatureError("No public key available for verification")
        
        if len(signature) != 3293:
            _LOGGER.warning("Invalid Dilithium signature length: %d", len(signature))
            return False
        
        try:
            dilithium_verify(self._public_key, message, signature)
            return True
        except Exception as e:
            _LOGGER.debug("Dilithium verification failed: %s", e.__class__.__name__)
            return False
    
    def export_public_key(self) -> bytes:
        """Export public key (1952 bytes)."""
        if self._public_key is None:
            raise CryptoKeyError("No public key available")
        return bytes(self._public_key)
    
    def export_secret_key(self) -> bytes:
        """Export secret key (4000 bytes). Store securely!"""
        if self._secret_key is None:
            raise CryptoKeyError("No secret key available")
        return bytes(self._secret_key)


def hybrid_kem_x25519_kyber(
    x25519_public: bytes,
    kyber_public: bytes
) -> Tuple[bytes, bytes, bytes]:
    """
    Hybrid Key Exchange: X25519 + Kyber-768.
    
    Provides defense-in-depth:
    - If Kyber is broken by quantum computer: X25519 still protects
    - If X25519 is broken classically: Kyber still protects
    
    Args:
        x25519_public: 32-byte X25519 public key.
        kyber_public: 1184-byte Kyber public key.
    
    Returns:
        (kyber_ciphertext, x25519_ephemeral_public, combined_secret):
            - kyber_ciphertext: 1088 bytes (send to recipient)
            - x25519_ephemeral_public: 32 bytes (send to recipient)
            - combined_secret: 64 bytes (use for encryption key derivation)
    """
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    
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
        info=b"hybrid-x25519-kyber768-v1"
    )
    combined_secret = hkdf.derive(combined_input)
    
    x25519_public_ephemeral = x25519_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
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
