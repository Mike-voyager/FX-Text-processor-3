import pytest

# Проверяем все публичные алиасы и классы:
from security.crypto import (
    SymmetricCipher,
    Ed25519Signer,
    Ed25519Verifier,
    AsymmetricKeyPair,
    derive_key,
    SUPPORTED_KDF_ALGORITHMS,
    SUPPORTED_ALGORITHMS,
    hash_password,
    verify_password,
    add_audit,
    KDFAlgorithm,
    HashScheme,
)


def test_basic_imports() -> None:
    # Проверяем, что все объекты импортируются и типов ожидаемых
    assert SymmetricCipher is not None
    assert Ed25519Signer is not None
    assert Ed25519Verifier is not None
    assert AsymmetricKeyPair is not None
    assert derive_key is not None
    assert SUPPORTED_ALGORITHMS
    assert SUPPORTED_KDF_ALGORITHMS
    assert hash_password is not None
    assert verify_password is not None
    assert add_audit is not None
    assert KDFAlgorithm.ARGON2ID in SUPPORTED_KDF_ALGORITHMS
    assert type(HashScheme.ARGON2ID.value) == str


def test_supported_algorithms_alias_type() -> None:
    # Проверка типов алиасов
    assert isinstance(SUPPORTED_KDF_ALGORITHMS, set)
    assert all(isinstance(a, KDFAlgorithm) for a in SUPPORTED_KDF_ALGORITHMS)
    assert isinstance(SUPPORTED_ALGORITHMS, tuple) or isinstance(SUPPORTED_ALGORITHMS, set)


def test_example_usage_create_cipher_and_signer() -> None:
    key = SymmetricCipher.generate_key()
    nonce = SymmetricCipher.generate_nonce()
    ct = SymmetricCipher.encrypt(b"testdata", key, nonce)
    assert isinstance(ct, bytes)
