import pytest

from security.crypto.symmetric import SymmetricCipher, _entropy_mixer, _zeroize


def test_generate_key_and_nonce_type_and_length() -> None:
    key = SymmetricCipher.generate_key()
    nonce = SymmetricCipher.generate_nonce()
    assert isinstance(key, bytes)
    assert isinstance(nonce, bytes)
    assert len(key) == SymmetricCipher.KEY_LENGTH
    assert len(nonce) == SymmetricCipher.NONCE_LENGTH


def test_validate_key_and_nonce() -> None:
    key = SymmetricCipher.generate_key()
    nonce = SymmetricCipher.generate_nonce()
    SymmetricCipher.validate_key(key)
    SymmetricCipher.validate_nonce(nonce)
    with pytest.raises(TypeError):
        SymmetricCipher.validate_key(123)  # type: ignore
    with pytest.raises(ValueError):
        SymmetricCipher.validate_key(b"x" * 31)
    with pytest.raises(TypeError):
        SymmetricCipher.validate_nonce(456)  # type: ignore
    with pytest.raises(ValueError):
        SymmetricCipher.validate_nonce(b"x" * 9)


def test_validate_aad() -> None:
    SymmetricCipher.validate_aad(None)
    SymmetricCipher.validate_aad(b"aad")
    with pytest.raises(TypeError):
        SymmetricCipher.validate_aad(123)  # type: ignore


def test_entropy_mixer_and_audit() -> None:
    b = _entropy_mixer(16)
    assert isinstance(b, bytes)
    assert len(b) == 16


def test_encrypt_decrypt_roundtrip() -> None:
    key = SymmetricCipher.generate_key()
    nonce = SymmetricCipher.generate_nonce()
    data = b"payload"
    ct = SymmetricCipher.encrypt(data, key, nonce)
    pt = SymmetricCipher.decrypt(ct, key, nonce)
    assert pt == data


def test_encrypt_decrypt_with_aad() -> None:
    key = SymmetricCipher.generate_key()
    nonce = SymmetricCipher.generate_nonce()
    aad = b"hdrmeta"
    data = b"important!"
    ct = SymmetricCipher.encrypt(data, key, nonce, associated_data=aad)
    pt = SymmetricCipher.decrypt(ct, key, nonce, associated_data=aad)
    assert pt == data
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        SymmetricCipher.decrypt(ct, key, nonce, associated_data=b"not_aad")


def test_encrypt_validation_errors() -> None:
    key = SymmetricCipher.generate_key()
    nonce = SymmetricCipher.generate_nonce()
    with pytest.raises(TypeError):
        SymmetricCipher.encrypt("notbytes", key, nonce)  # type: ignore
    with pytest.raises(TypeError):
        SymmetricCipher.encrypt(b"x", 123, nonce)  # type: ignore
    with pytest.raises(TypeError):
        SymmetricCipher.encrypt(b"x", key, "nonstr")  # type: ignore
    with pytest.raises(TypeError):
        SymmetricCipher.encrypt(b"x", key, nonce, associated_data=object())  # type: ignore


def test_decrypt_validation_errors() -> None:
    key = SymmetricCipher.generate_key()
    nonce = SymmetricCipher.generate_nonce()
    ct = SymmetricCipher.encrypt(b"aaaa", key, nonce)
    with pytest.raises(TypeError):
        SymmetricCipher.decrypt(1234, key, nonce)  # type: ignore
    with pytest.raises(ValueError):
        SymmetricCipher.decrypt(b"", key, nonce)
    with pytest.raises(TypeError):
        SymmetricCipher.decrypt(ct, 123, nonce)  # type: ignore
    with pytest.raises(TypeError):
        SymmetricCipher.decrypt(ct, key, object())  # type: ignore
    with pytest.raises(TypeError):
        SymmetricCipher.decrypt(ct, key, nonce, associated_data=object())  # type: ignore


def test_encrypt_decrypt_tampered() -> None:
    key = SymmetricCipher.generate_key()
    nonce = SymmetricCipher.generate_nonce()
    ct = SymmetricCipher.encrypt(b"top secret", key, nonce)
    tampered = bytes([c ^ 0x12 for c in ct])
    from cryptography.exceptions import InvalidTag

    with pytest.raises(InvalidTag):
        SymmetricCipher.decrypt(tampered, key, nonce)


def test_decrypt_exception_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    # Monkeypatch Cipher to forcibly raise generic Exception
    key = SymmetricCipher.generate_key()
    nonce = SymmetricCipher.generate_nonce()
    ct = SymmetricCipher.encrypt(b"xyzt", key, nonce)
    import security.crypto.symmetric as symmod

    class DummyCipher:
        def __init__(self, *a: object, **k: object) -> None:
            raise ZeroDivisionError("Coverage hack")

    monkeypatch.setattr(symmod, "Cipher", DummyCipher)
    with pytest.raises(ZeroDivisionError):
        SymmetricCipher.decrypt(ct, key, nonce)


def test_audit_entropy_ok() -> None:
    from security.crypto import symmetric

    # валидное значение
    symmetric._audit_entropy(b"\xaa\xbb\xcc\x01\x02\x03\x04")
    # низкая энтропия
    with pytest.raises(ValueError):
        symmetric._audit_entropy(b"\x00" * 16)
    with pytest.raises(ValueError):
        symmetric._audit_entropy(b"")


def test_diagnose_rng(monkeypatch: pytest.MonkeyPatch) -> None:
    from security.crypto import symmetric

    # тест удачного вызова (os.urandom всегда есть)
    symmetric._diagnose_rng()
    # эмулируем отсутствие os.urandom
    monkeypatch.setattr(symmetric.os, "urandom", lambda n: None)
    with pytest.raises(RuntimeError):
        symmetric._diagnose_rng()


def test_entropy_mixer_calls_diagnose(monkeypatch: pytest.MonkeyPatch) -> None:
    from security.crypto import symmetric

    called = {}

    def fake_diag() -> None:
        called["trig"] = True

    monkeypatch.setattr(symmetric, "_diagnose_rng", fake_diag)
    monkeypatch.setattr(symmetric, "_audit_entropy", lambda d: None)
    result = symmetric._entropy_mixer(8)
    assert isinstance(result, bytes) and called["trig"]


def test_zeroize_none() -> None:
    from security.crypto import symmetric

    symmetric._zeroize(None)  # Должно не вызывать ошибку


def test_audit_entropy_empty_and_low_entropy() -> None:
    from security.crypto import symmetric

    with pytest.raises(ValueError):
        symmetric._audit_entropy(b"")  # пустой поток
    with pytest.raises(ValueError):
        symmetric._audit_entropy(b"\x00" * 40)
    with pytest.raises(ValueError):
        symmetric._audit_entropy(b"\xff" * 40)


def test_encrypt_fails_on_validate(monkeypatch: pytest.MonkeyPatch) -> None:
    from security.crypto import symmetric

    monkeypatch.setattr(
        symmetric.SymmetricCipher,
        "validate_key",
        lambda k: (_ for _ in ()).throw(ValueError("fail!")),
    )
    with pytest.raises(ValueError):
        symmetric.SymmetricCipher.encrypt(b"x", b"x" * 32, b"x" * 12)


def test_zeroize_python_none_or_not_bytearray() -> None:
    from security.crypto import symmetric

    symmetric._zeroize(None)
    symmetric._zeroize(123)  # type: ignore


def test_zeroize_full_branch() -> None:
    from security.crypto import symmetric

    ba = bytearray(b"x" * 10)
    symmetric._zeroize(ba)  # покрывает for + del data ветку полностью
    assert all(x == 0 for x in ba)


def test_encrypt_decrypt_bytearray_zeroize_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    from security.crypto import symmetric

    monkeypatch.setattr(symmetric.SymmetricCipher, "validate_key", lambda k: None)
    monkeypatch.setattr(symmetric.SymmetricCipher, "validate_nonce", lambda n: None)

    ba_key = bytearray(b"\x01" * 32)
    ba_nonce = bytearray(b"\x02" * 12)
    ct = symmetric.SymmetricCipher.encrypt(b"top_secret", ba_key, ba_nonce)
    assert all(b == 0 for b in ba_key)
    assert all(b == 0 for b in ba_nonce)

    # Новые ключ/nonce для decrypt, также bytearray
    ba_key2 = bytearray(b"\x03" * 32)
    ba_nonce2 = bytearray(b"\x04" * 12)
    ct2 = symmetric.SymmetricCipher.encrypt(b"test_payload", ba_key2, ba_nonce2)
    import cryptography.exceptions

    monkeypatch.setattr(symmetric.SymmetricCipher, "validate_key", lambda k: None)
    monkeypatch.setattr(symmetric.SymmetricCipher, "validate_nonce", lambda n: None)
    # На этот раз подаём валидный по длине ct2, но ключ/nonce — bytearray
    with pytest.raises(cryptography.exceptions.InvalidTag):
        symmetric.SymmetricCipher.decrypt(ct2, ba_key2, ba_nonce2)
    assert all(b == 0 for b in ba_key2)
    assert all(b == 0 for b in ba_nonce2)
