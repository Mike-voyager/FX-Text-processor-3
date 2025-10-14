import pytest
from typing import cast
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
from _pytest.logging import LogCaptureFixture
from src.security.crypto.asymmetric import (
    _validate_keypair,
    AsymmetricKeyPair,
    KeyFormatError,
    UnsupportedAlgorithmError,
)


from src.security.crypto.asymmetric import (
    AsymmetricKeyPair,
    load_public_key,
    import_public_key_pem,
    KeyFormatError,
    UnsupportedAlgorithmError,
    AlgorithmFactory,
    _rsa_oaep_overhead,
    SUPPORTED_ALGORITHMS,
)

TEST_DATA = b"Hello, secure world!"
BAD_DATA = b"not the same"
TEST_PASSWORD = "securepw123"


def test_ed25519_sign_verify_cycle() -> None:
    kp = AsymmetricKeyPair.generate("ed25519")
    msg = TEST_DATA
    sig = kp.sign(msg)
    assert kp.verify(msg, sig)
    assert not kp.verify(BAD_DATA, sig)
    pem = kp.export_private_bytes()
    kp2 = AsymmetricKeyPair.from_private_bytes(pem, "ed25519")
    assert kp2.verify(msg, sig)
    assert kp2.equals_public(kp)
    pub_bytes = kp.export_public_bytes()
    pub_kp = load_public_key(pub_bytes, "ed25519")
    assert pub_kp.verify(msg, sig)
    assert pub_kp.private_key is None
    assert pub_kp.public_key is not None


def test_rsa_sign_verify_encrypt_decrypt() -> None:
    kp = AsymmetricKeyPair.generate("rsa4096")
    msg = TEST_DATA
    sig = kp.sign(msg)
    assert kp.verify(msg, sig)
    assert not kp.verify(BAD_DATA, sig)
    ct = kp.encrypt(msg)
    assert kp.decrypt(ct) == msg
    pem = kp.export_private_bytes(TEST_PASSWORD)
    kp2 = AsymmetricKeyPair.from_private_bytes(pem, "rsa4096", TEST_PASSWORD)
    assert kp2.verify(msg, sig)
    ct2 = kp2.encrypt(msg)
    assert kp2.decrypt(ct2) == msg
    pub_bytes = kp.export_public_bytes()
    pub_kp = load_public_key(pub_bytes, "rsa4096")
    assert pub_kp.verify(msg, sig)
    with pytest.raises(NotImplementedError):
        pub_kp.decrypt(ct)
    with pytest.raises(NotImplementedError):
        pub_kp.export_private_bytes()


def test_ecdsa_p256_sign_verify() -> None:
    kp = AsymmetricKeyPair.generate("ecdsa_p256")
    msg = TEST_DATA
    sig = kp.sign(msg)
    assert kp.verify(msg, sig)
    assert not kp.verify(BAD_DATA, sig)
    pem = kp.export_private_bytes()
    kp2 = AsymmetricKeyPair.from_private_bytes(pem, "ecdsa_p256")
    assert kp2.verify(msg, sig)
    assert kp2.equals_public(kp)


def test_fingerprint_and_equals() -> None:
    kp1 = AsymmetricKeyPair.generate("ed25519")
    kp2 = AsymmetricKeyPair.generate("ed25519")
    assert not kp1.equals_public(kp2)
    pem = kp1.export_public_bytes()
    kp1pub = load_public_key(pem, "ed25519")
    assert kp1.equals_public(kp1pub)


def test_rsa_too_long_encrypt() -> None:
    kp = AsymmetricKeyPair.generate("rsa4096")
    assert kp.public_key is not None
    assert isinstance(kp.public_key, rsa.RSAPublicKey)
    max_len = kp.public_key.key_size // 8 - _rsa_oaep_overhead()
    kp.encrypt(b"x" * max_len)
    with pytest.raises(ValueError):
        kp.encrypt(b"x" * (max_len + 1))


def test_error_no_private_for_sign_or_decrypt() -> None:
    kp = AsymmetricKeyPair.generate("ed25519")
    pub = load_public_key(kp.export_public_bytes(), "ed25519")
    with pytest.raises(NotImplementedError):
        pub.sign(TEST_DATA)
    with pytest.raises(NotImplementedError):
        pub.export_private_bytes()
    r_kp = AsymmetricKeyPair.generate("rsa4096")
    pub_r = load_public_key(r_kp.export_public_bytes(), "rsa4096")
    with pytest.raises(NotImplementedError):
        pub_r.decrypt(b"data")
    ec_kp = AsymmetricKeyPair.generate("ecdsa_p256")
    pub_ec = load_public_key(ec_kp.export_public_bytes(), "ecdsa_p256")
    with pytest.raises(NotImplementedError):
        pub_ec.sign(TEST_DATA)
    with pytest.raises(NotImplementedError):
        pub_ec.export_private_bytes()


def test_unsupported_algorithm_and_key_type() -> None:
    # Unknown algo for generate
    with pytest.raises(UnsupportedAlgorithmError):
        AsymmetricKeyPair.generate("undefined_algo")
    # Unknown algo for from_private_bytes (fast check before parse)
    with pytest.raises(UnsupportedAlgorithmError):
        AsymmetricKeyPair.from_private_bytes(b"not a key", "undefined_algo")
    # KeyFormatError when parse fails
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_private_bytes(b"not a pem", "ed25519")
    with pytest.raises(KeyFormatError):
        load_public_key(b"bad pem", "ed25519")
    ed_kp = AsymmetricKeyPair.generate("ed25519")
    with pytest.raises(KeyFormatError):
        load_public_key(ed_kp.export_public_bytes(), "rsa4096")
    with pytest.raises(KeyFormatError):
        import_public_key_pem(
            "-----BEGIN PUBLIC KEY-----\nxxxx\n-----END PUBLIC KEY-----"
        )
    # from_public_bytes: unknown algo
    with pytest.raises(UnsupportedAlgorithmError):
        AsymmetricKeyPair.from_public_bytes(b"1234", "bad_algo")


def test_algorithm_factory_dispatch() -> None:
    kp_ed = AlgorithmFactory["ed25519"]()
    assert isinstance(kp_ed.private_key, ed25519.Ed25519PrivateKey)
    kp_rsa = AlgorithmFactory["rsa4096"](key_size=4096)
    assert isinstance(kp_rsa.private_key, rsa.RSAPrivateKey)
    kp_ec = AlgorithmFactory["ecdsa_p256"]()
    assert isinstance(kp_ec.private_key, ec.EllipticCurvePrivateKey)


def test_safe_log_and_sanitize_password(caplog: LogCaptureFixture) -> None:
    from src.security.crypto.asymmetric import _secure_log, _sanitize_password

    _secure_log("foo without secret", 123)
    _secure_log("pw", "password=404notfound")
    for r in caplog.records:
        assert "password" not in r.getMessage().lower()
    assert _sanitize_password(None) == "(none)"
    assert _sanitize_password("qwerty") == "******"


def test_repr_and_docstrings() -> None:
    """Additional: ensure no special methods break and docstrings present."""
    kp = AsymmetricKeyPair.generate("ed25519")
    assert isinstance(kp.__doc__, str)
    assert isinstance(str(kp), str)
    assert isinstance(repr(kp), str)
    assert kp.__class__.__name__ == "AsymmetricKeyPair"


def test_unreachable_defensive_raise_private_bytes() -> None:
    # These should always raise NotImplementedError, but test the unreachable branch:
    kp = AsymmetricKeyPair(None, None, "ed25519")
    with pytest.raises(NotImplementedError):
        kp.export_private_bytes()
    with pytest.raises(NotImplementedError):
        kp.sign(TEST_DATA)
    with pytest.raises(NotImplementedError):
        kp.decrypt(b"xxx")
    with pytest.raises(NotImplementedError):
        kp.get_public_fingerprint()


def test_unreachable_defensive_raise_public_bytes() -> None:
    kp = AsymmetricKeyPair(None, None, "ed25519")
    with pytest.raises(NotImplementedError):
        kp.export_public_bytes()


def test_fail_fast_kp_validation() -> None:
    # Broken state: private_key present, public_key is None
    with pytest.raises(KeyFormatError):
        _validate_keypair(object(), None)


def test_factory_supported_algorithms() -> None:
    # Just to make sure SUPPORTED_ALGORITHMS covers expected set
    for algo in SUPPORTED_ALGORITHMS:
        kp = AsymmetricKeyPair.generate(algo)
        assert isinstance(kp, AsymmetricKeyPair)


def test_ed25519_invalid_key_material() -> None:
    # Попытка создать пару из мусорных байт — должен быть KeyFormatError
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_private_bytes(b"\x00" * 10, "ed25519")
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_public_bytes(b"\x01" * 5, "ed25519")


def test_rsa_invalid_key_material() -> None:
    # Нарушение структуры — неправильный размер PEM/DER
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_private_bytes(b"badkey", "rsa4096")
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_public_bytes(b"badpub", "rsa4096")


def test_ecdsa_invalid_key_material() -> None:
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_private_bytes(b"xxx", "ecdsa_p256")
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_public_bytes(b"yyy", "ecdsa_p256")


def test_algorithm_factory_invalid() -> None:
    # попытка вызвать генератор с неправильными аргументами/размерами
    with pytest.raises(TypeError):
        from src.security.crypto.asymmetric import AlgorithmFactory

        AlgorithmFactory["rsa4096"]("not_expected_argument")
    # Отсутствующий алгоритм
    with pytest.raises(KeyError):
        AlgorithmFactory["unknown_algo"]()


def test_sign_with_none_message() -> None:
    # Проверить реакцию на None вместо данных (ValueError или TypeError)
    kp = AsymmetricKeyPair.generate("ed25519")
    with pytest.raises(Exception):
        kp.sign(None)  # type: ignore


def test_empty_export_public_private_bytes() -> None:
    # Если в объекте нет ключей — всегда NotImplemented
    kp = AsymmetricKeyPair(None, None, "abc")
    with pytest.raises(NotImplementedError):
        kp.export_private_bytes()
    with pytest.raises(NotImplementedError):
        kp.export_public_bytes()


def test_encrypt_with_no_public() -> None:
    # Попытка криптовать без public_key
    kp = AsymmetricKeyPair(None, None, "rsa4096")
    with pytest.raises(NotImplementedError):
        kp.encrypt(b"msg")


def test_decrypt_with_no_private() -> None:
    # Попытка декриптовать без private_key
    kp = AsymmetricKeyPair(None, None, "rsa4096")
    with pytest.raises(NotImplementedError):
        kp.decrypt(b"msg")


def test_sign_wrong_type() -> None:
    # Однако sign не всегда обязан принимать только bytes
    kp = AsymmetricKeyPair.generate("ed25519")
    with pytest.raises(Exception):
        kp.sign(1234)  # type: ignore


def test_equals_public_edge() -> None:
    # equals_public с явно неправильным типом "key"
    kp = AsymmetricKeyPair.generate("ed25519")
    assert not kp.equals_public("not_a_key")  # type: ignore


def test_repr_empty_obj() -> None:
    # repr для полностью пустого объекта (оба ключа None)
    kp = AsymmetricKeyPair(None, None, "xxx")
    string = repr(kp)
    assert "AsymmetricKeyPair" in string


def test_raise_on_unsupported_usage() -> None:
    # create, sign, decrypt на неподдерживаемом алгоритме
    for algo in ["unknown", "badalgo"]:
        with pytest.raises(UnsupportedAlgorithmError):
            AsymmetricKeyPair.generate(algo)
        with pytest.raises(UnsupportedAlgorithmError):
            AsymmetricKeyPair.from_public_bytes(b"x", algo)


# 1. Битые, пустые, невалидные форматы ключей (все алгоритмы)
@pytest.mark.parametrize("algo", ["ed25519", "rsa4096", "ecdsa_p256"])
def test_from_private_bytes_bad_formats(algo: str) -> None:
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_private_bytes(b"corrupt", algo)
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_private_bytes(b"", algo)
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_private_bytes(None, algo)  # type: ignore


@pytest.mark.parametrize("algo", ["ed25519", "rsa4096", "ecdsa_p256"])
def test_from_public_bytes_bad_formats(algo: str) -> None:
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_public_bytes(b"junk", algo)
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_public_bytes(b"", algo)
    with pytest.raises(KeyFormatError):
        AsymmetricKeyPair.from_public_bytes(None, algo)  # type: ignore


def test_import_public_key_pem_bad() -> None:
    with pytest.raises(KeyFormatError):
        import_public_key_pem("bad_pem")
    with pytest.raises(KeyFormatError):
        import_public_key_pem("")


# 2. Фабрика: несуществующие алгоритмы, плохие аргументы
def test_algorithm_factory_keyerror() -> None:
    from src.security.crypto.asymmetric import AlgorithmFactory

    with pytest.raises(KeyError):
        AlgorithmFactory["notalgo"]()


# 3. Encrypt/decrypt/sign на пустых/битых AsymmetricKeyPair
def test_broken_pair_all_methods() -> None:
    kp = AsymmetricKeyPair(None, None, "ed25519")
    with pytest.raises(NotImplementedError):
        kp.sign(b"msg")
    with pytest.raises(NotImplementedError):
        kp.decrypt(b"encdat")
    with pytest.raises(NotImplementedError):
        kp.export_private_bytes()
    with pytest.raises(NotImplementedError):
        kp.export_public_bytes()
    with pytest.raises(NotImplementedError):
        kp.get_public_fingerprint()


# 4. Exception-branch на public_key=None/private_key=None для RSA/ECDSA
@pytest.mark.parametrize("algo", ["rsa4096", "ecdsa_p256"])
def test_sign_with_public_only(algo: str) -> None:
    kp = AsymmetricKeyPair(None, None, algo)
    with pytest.raises(NotImplementedError):
        kp.sign(b"abc")
    with pytest.raises(NotImplementedError):
        kp.decrypt(b"xyz")


# 5. Bad types для equals_public и fingerprint
def test_equals_public_with_wrong_type() -> None:
    kp = AsymmetricKeyPair.generate("ed25519")
    assert kp.equals_public(object()) is False
    assert kp.equals_public("wrong") is False


# 6. Unsupported algorithm error branch
def test_unsupported_algo_all_methods() -> None:
    with pytest.raises(UnsupportedAlgorithmError):
        AsymmetricKeyPair.generate("made_up_algo")
    with pytest.raises(UnsupportedAlgorithmError):
        AsymmetricKeyPair.from_private_bytes(b"x", "made_up_algo")
    with pytest.raises(UnsupportedAlgorithmError):
        AsymmetricKeyPair.from_public_bytes(b"x", "made_up_algo")


# 7. Проверка unreachable/unhandled branch при загрузке неправильных ключей
def test_load_public_key_mismatch() -> None:
    kp = AsymmetricKeyPair.generate("ed25519")
    with pytest.raises(KeyFormatError):
        load_public_key(kp.export_public_bytes(), "rsa4096")  # bytes от ed25519 как rsa
    kp2 = AsymmetricKeyPair.generate("rsa4096")
    with pytest.raises(KeyFormatError):
        load_public_key(kp2.export_public_bytes(), "ecdsa_p256")


# 8. Экспорт с паролем: некорректные параметры/тип пароля
def test_private_export_wrong_password_type() -> None:
    kp = AsymmetricKeyPair.generate("rsa4096")
    # Если реализовано строго: password должен быть str/bytes, все остальное — ошибка
    with pytest.raises(Exception):
        kp.export_private_bytes(1234)  # type: ignore


# 9. Странные входные (None вместо bytes)
def test_sign_none_message() -> None:
    kp = AsymmetricKeyPair.generate("ed25519")
    with pytest.raises(Exception):
        kp.sign(None)  # type: ignore


# 10. Проверка bidirectional equals_public для None-полей
def test_equals_public_with_broken_obj() -> None:
    kp = AsymmetricKeyPair(None, None, "ed25519")
    kp2 = AsymmetricKeyPair.generate("ed25519")
    with pytest.raises(NotImplementedError):
        kp.equals_public(kp2)


# 11. get_public_fingerprint edge
def test_get_public_fingerprint_unreachable() -> None:
    kp = AsymmetricKeyPair(None, None, "ed25519")
    with pytest.raises(NotImplementedError):
        kp.get_public_fingerprint()
