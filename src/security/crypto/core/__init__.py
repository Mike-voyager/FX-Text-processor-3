"""
Ядро криптографической подсистемы.

Components:
    - exceptions: Централизованные исключения
    - protocols: Protocol интерфейсы (SymmetricCipher, Signature, etc.)
    - registry: AlgorithmRegistry для 46 алгоритмов
    - metadata: Алгоритмические метаданные

Version: 1.0
Date: February 2026
"""

from __future__ import annotations

from src.security.crypto.core.exceptions import (
    # Algorithm
    AlgorithmError,
    AlgorithmInitializationError,
    AlgorithmNotAvailableError,
    AlgorithmNotFoundError,
    AlgorithmNotRegisteredError,
    AlgorithmNotSupportedError,
    # Base
    CryptoError,
    # Key
    CryptoKeyError,
    DecryptionError,
    DecryptionFailedError,
    DeviceCommunicationError,
    DeviceNotFoundError,
    DuplicateRegistrationError,
    # Encryption
    EncryptionError,
    EncryptionFailedError,
    # Hardware
    HardwareDeviceError,
    # Hash
    HashError,
    HashingFailedError,
    InvalidDigestError,
    InvalidInputError,
    InvalidKeyError,
    InvalidKeySizeError,
    InvalidNonceError,
    InvalidOutputError,
    InvalidParameterError,
    InvalidSignatureError,
    InvalidTagError,
    KeyDerivationError,
    KeyGenerationError,
    PINError,
    PlaintextTooLargeError,
    # Protocol
    ProtocolError,
    ProtocolMismatchError,
    ProtocolViolationError,
    # Registry
    RegistryError,
    # Signature
    SignatureError,
    SigningFailedError,
    SlotError,
    # Validation
    ValidationError,
    VerificationFailedError,
)
from src.security.crypto.core.metadata import AlgorithmMetadata
from src.security.crypto.core.protocols import (
    AsymmetricEncryptionProtocol,
    HardwareSigningProtocol,
    HashProtocol,
    KDFProtocol,
    KeyExchangeProtocol,
    KeyStoreProtocol,
    NonceManagerProtocol,
    SecureMemoryProtocol,
    SignatureProtocol,
    SymmetricCipherProtocol,
)
from src.security.crypto.core.registry import AlgorithmRegistry

__all__: list[str] = [
    # Exceptions
    "CryptoError",
    "AlgorithmError",
    "AlgorithmNotFoundError",
    "AlgorithmNotSupportedError",
    "AlgorithmNotAvailableError",
    "AlgorithmInitializationError",
    "CryptoKeyError",
    "InvalidKeyError",
    "InvalidKeySizeError",
    "KeyGenerationError",
    "KeyDerivationError",
    "EncryptionError",
    "EncryptionFailedError",
    "DecryptionError",
    "DecryptionFailedError",
    "InvalidNonceError",
    "InvalidTagError",
    "PlaintextTooLargeError",
    "SignatureError",
    "SigningFailedError",
    "VerificationFailedError",
    "InvalidSignatureError",
    "HashError",
    "HashingFailedError",
    "InvalidDigestError",
    "ProtocolError",
    "ProtocolMismatchError",
    "ProtocolViolationError",
    "RegistryError",
    "AlgorithmNotRegisteredError",
    "DuplicateRegistrationError",
    "ValidationError",
    "InvalidParameterError",
    "InvalidInputError",
    "InvalidOutputError",
    "HardwareDeviceError",
    "DeviceNotFoundError",
    "DeviceCommunicationError",
    "PINError",
    "SlotError",
    # Protocols
    "SymmetricCipherProtocol",
    "SignatureProtocol",
    "AsymmetricEncryptionProtocol",
    "KeyExchangeProtocol",
    "HashProtocol",
    "KDFProtocol",
    "NonceManagerProtocol",
    "SecureMemoryProtocol",
    "HardwareSigningProtocol",
    "KeyStoreProtocol",
    # Registry
    "AlgorithmRegistry",
    # Metadata
    "AlgorithmMetadata",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-02-09"
