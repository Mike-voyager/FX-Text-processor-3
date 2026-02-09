from __future__ import annotations

import importlib
from typing import Type

import pytest

from src.security.crypto import exceptions as exc


def test_hierarchy_relationships() -> None:
    # Базовый класс для всех ошибок
    assert issubclass(exc.EncryptionError, exc.CryptoError)
    assert issubclass(exc.DecryptionError, exc.CryptoError)
    assert issubclass(exc.SignatureError, exc.CryptoError)
    assert issubclass(exc.CryptoKeyError, exc.CryptoError)
    assert issubclass(exc.KdfError, exc.CryptoError)
    assert issubclass(exc.HashingError, exc.CryptoError)
    assert issubclass(exc.StorageError, exc.CryptoError)

    # Подклассы подписи
    assert issubclass(exc.SignatureGenerationError, exc.SignatureError)
    assert issubclass(exc.SignatureVerificationError, exc.SignatureError)
    assert issubclass(exc.InvalidSignatureError, exc.SignatureVerificationError)

    # Подклассы KDF
    assert issubclass(exc.KDFParameterError, exc.KdfError)
    assert issubclass(exc.KDFAlgorithmError, exc.KdfError)

    # Подклассы ключей
    assert issubclass(exc.KeyNotFoundError, exc.CryptoKeyError)
    assert issubclass(exc.KeyGenerationError, exc.CryptoKeyError)
    assert issubclass(exc.InvalidKeyError, exc.CryptoKeyError)
    assert issubclass(exc.KeyRotationError, exc.CryptoKeyError)

    # Подклассы хранилища
    assert issubclass(exc.StorageReadError, exc.StorageError)
    assert issubclass(exc.StorageWriteError, exc.StorageError)


def test_cryptoerror_cause_and_message() -> None:
    root = ValueError("root-cause")
    e = exc.CryptoError("top", cause=root)
    # __cause__ установлен и сообщение сохраняется
    assert e.__cause__ is root
    assert str(e) == "top"


def test_raise_from_sets_cause_preserved() -> None:
    try:
        try:
            raise RuntimeError("low")
        except RuntimeError as low:
            raise exc.EncryptionError("enc", cause=low) from low
    except exc.EncryptionError as high:
        # Причина доступна как __cause__
        assert isinstance(high, exc.CryptoError)
        assert isinstance(high.__cause__, RuntimeError)
        assert str(high) == "enc"


def test_all_exports_present_and_are_classes() -> None:
    mod = importlib.import_module("src.security.crypto.exceptions")
    exported = getattr(mod, "__all__", None)
    assert isinstance(exported, list) and exported, "__all__ must be a non-empty list"

    for name in exported:
        assert hasattr(mod, name), f"{name} not found in module"
        attr = getattr(mod, name)
        assert isinstance(attr, type), f"{name} must be a class"


def test_no_builtin_keyerror_shadow() -> None:
    # Убедимся, что CryptoKeyError не конфликтует с built-in KeyError
    assert exc.CryptoKeyError is not KeyError
    assert not issubclass(exc.CryptoKeyError, KeyError)


@pytest.mark.parametrize(
    "err_type,msg",
    [
        (exc.EncryptionError, "encryption failed"),
        (exc.DecryptionError, "decryption failed"),
        (exc.SignatureGenerationError, "signing failed"),
        (exc.SignatureVerificationError, "verification failed"),
        (exc.InvalidSignatureError, "invalid signature"),
        (exc.KeyNotFoundError, "key not found"),
        (exc.KeyGenerationError, "key generation"),
        (exc.InvalidKeyError, "invalid key"),
        (exc.KeyRotationError, "rotation failed"),
        (exc.KDFParameterError, "bad kdf params"),
        (exc.KDFAlgorithmError, "kdf unsupported"),
        (exc.HashSchemeError, "bad scheme"),
        (exc.StorageReadError, "read failed"),
        (exc.StorageWriteError, "write failed"),
    ],
)
def test_instantiation_and_str(err_type: Type[Exception], msg: str) -> None:
    e = err_type(msg)
    # Все исключения должны быть инстансами CryptoError и сохранять сообщение
    assert isinstance(e, exc.CryptoError)
    assert str(e) == msg


def test_signature_invalid_is_caught_by_higher_parents() -> None:
    try:
        raise exc.InvalidSignatureError("bad")
    except exc.SignatureVerificationError:
        caught = True
    else:
        caught = False
    assert caught is True
