"""
Модуль объединяет криптографические примитивы для использования в системах высокого уровня ESCP Text Editor.
Предназначение: Единая точка импорта для безопасного шифрования, KDF, хеширования и подписи с корпоративной типизацией.
EN: Top-level cryptography API for FX-Text-processor-3. Enterprise-grade entrypoint for encryption, KDF, hashing, signatures.
All exports are type-annotated, thoroughly validated, and integrate audit/logging hooks.
"""

from .symmetric import SymmetricCipher, auditentropy, encrypt_aes_gcm, decrypt_aes_gcm
from .asymmetric import (
    AsymmetricKeyPair,
    load_public_key,
    import_public_key_pem,
    KeyFormatError,
    UnsupportedAlgorithmError,
    AlgorithmFactory,
    SUPPORTED_ALGORITHMS,
)
from .signatures import (
    Ed25519Signer,
    Ed25519Verifier,
    SignatureError,
)
from security.crypto.kdf import (
    derive_key,
    derive_key_argon2id,
    KDFParameterError,
    KDFAlgorithmError,
    KDFEntropyWarning,
    KDFAlgorithm,
    SUPPORTEDALGORITHMS as SUPPORTED_KDF_ALGORITHMS,
)
from .hashing import (
    hash_password,
    verify_password,
    needs_rehash,
    get_hash_scheme,
    HashScheme,
    legacy_verify_password,
    add_audit,
)

all = [
    # Symmetric encryption
    "SymmetricCipher",
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    "audit_entropy",
    # Asymmetric
    "AsymmetricKeyPair",
    "load_public_key",
    "import_public_key_pem",
    "KeyFormatError",
    "UnsupportedAlgorithmError",
    "AlgorithmFactory",
    "SUPPORTED_ALGORITHMS",
    # Signatures
    "Ed25519Signer",
    "Ed25519Verifier",
    "SignatureError",
    # KDF
    "derive_key",
    "derive_key_argon2id",
    "KDFParameterError",
    "KDFAlgorithmError",
    "KDFEntropyWarning",
    "KDFAlgorithm",
    "SUPPORTED_KDF_ALGORITHMS",
    # Hashing
    "hash_password",
    "verify_password",
    "needs_rehash",
    "get_hash_scheme",
    "HashScheme",
    "legacy_verify_password",
    "add_audit",
]
"""
Example: Encrypt, derive and sign a document
from security.crypto import SymmetricCipher, derive_key, Ed25519Signer
key = derive_key('argon2id', password='secret', salt=b'xyz')
cipher = SymmetricCipher(key)
ct, nonce, tag = cipher.encrypt(b'Sensitive data')
signer = Ed25519Signer(private_key_bytes)
signature = signer.sign(ct)
Log and audit
add_audit("doc_encrypted", userid="user-1", context={"nonce": nonce.hex()})
"""
