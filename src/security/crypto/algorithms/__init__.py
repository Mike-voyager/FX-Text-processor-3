"""
Криптографические алгоритмы: 46 реализаций.

Symmetric Ciphers (10):
    - AES-128-GCM, AES-256-GCM, AES-256-GCM-SIV
    - ChaCha20-Poly1305, XChaCha20-Poly1305
    - AES-256-SIV, AES-256-OCB
    - 3DES-EDE3, DES (legacy)
    - AES-256-CTR

Signature Algorithms (17):
    - Ed25519, Ed448
    - ECDSA-P256, ECDSA-P384, ECDSA-P521, ECDSA-secp256k1
    - RSA-PSS-2048, RSA-PSS-3072, RSA-PSS-4096
    - RSA-PKCS1v15 (legacy)
    - Dilithium2, Dilithium3, Dilithium5 (PQC)
    - FALCON-512, FALCON-1024 (PQC)
    - SPHINCS+-128s, SPHINCS+-256s (PQC)

Asymmetric Encryption (3):
    - RSA-OAEP-2048, RSA-OAEP-3072, RSA-OAEP-4096

Key Exchange (8):
    - X25519, X448
    - ECDH-P256, ECDH-P384, ECDH-P521
    - Kyber512, Kyber768, Kyber1024 (PQC)

Hash Functions (8):
    - SHA-256, SHA-384, SHA-512
    - SHA3-256, SHA3-512
    - BLAKE2b, BLAKE2s, BLAKE3

KDF (4):
    - Argon2id
    - PBKDF2-SHA256
    - Scrypt
    - HKDF-SHA256

Version: 1.0
Date: February 2026
"""

from __future__ import annotations

# Factory functions are defined in registry submodule
# This module provides convenient access to all algorithms

__all__: list[str] = [
    # Use AlgorithmRegistry for algorithm instantiation
    # See src.security.crypto.core.registry for factory methods
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-09"
