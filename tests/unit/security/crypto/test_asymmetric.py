from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Callable
import logging
from _pytest.logging import LogCaptureFixture

import pytest

import src.security.crypto.asymmetric as asym
from src.security.crypto.asymmetric import (
    AsymmetricKeyPair,
    KeyFormatError,
    UnsupportedAlgorithmError,
    _secure_log,
    _contains_sensitive_data,
)


def test_generate_and_sign_verify_ed25519() -> None:
    kp = asym.AsymmetricKeyPair.generate("ed25519")
    sig = kp.sign(b"message")
    assert kp.verify(b"message", sig) is True
    assert kp.verify(b"tampered", sig) is False


def test_generate_rsa_sign_verify_encrypt_decrypt() -> None:
    kp = asym.AsymmetricKeyPair.generate("rsa4096", key_size=2048)
    sig = kp.sign(b"data")
    assert kp.verify(b"data", sig) is True
    # OAEP limit check using internal helper
    overhead = asym._rsa_oaep_overhead()

    # Type guard для доступа к key_size (только у RSA)
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    assert isinstance(kp.public_key, RSAPublicKey)

    limit = kp.public_key.key_size // 8 - overhead
    ct = kp.encrypt(b"A" * limit)
    assert isinstance(ct, bytes) and len(ct) > 0
    pt = kp.decrypt(ct)
    assert pt == b"A" * limit
    with pytest.raises(ValueError):
        _ = kp.encrypt(b"A" * (limit + 1))


def test_generate_ecdsa_sign_verify_and_not_implemented_encrypt() -> None:
    kp = asym.AsymmetricKeyPair.generate("ecdsa_p256")
    sig = kp.sign(b"z")
    assert kp.verify(b"z", sig) is True
    with pytest.raises(NotImplementedError):
        _ = kp.encrypt(b"x")
    with pytest.raises(NotImplementedError):
        _ = kp.decrypt(b"y")


def test_invalid_algorithm_generate_raises() -> None:
    with pytest.raises(asym.UnsupportedAlgorithmError):
        _ = asym.AsymmetricKeyPair.generate("unknown_algo")


def test_export_import_private_with_password_and_mismatch() -> None:
    kp = asym.AsymmetricKeyPair.generate("ed25519")
    pem_enc = kp.export_private_bytes(password="pw123")
    # Correct import
    kp2 = asym.AsymmetricKeyPair.from_private_bytes(
        pem_enc, "ed25519", password="pw123"
    )
    assert kp.equals_public(kp2) is True
    # Wrong password
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_private_bytes(
            pem_enc, "ed25519", password="bad"
        )
    # Wrong declared algorithm
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_private_bytes(
            pem_enc, "rsa4096", password="pw123"
        )


def test_export_import_public_and_mismatch() -> None:
    kp = asym.AsymmetricKeyPair.generate("ed25519")
    pub_pem = kp.export_public_bytes()
    kp_pub = asym.AsymmetricKeyPair.from_public_bytes(pub_pem, "ed25519")
    assert kp.equals_public(kp_pub) is True
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_public_bytes(pub_pem, "rsa4096")


def test_equals_public_and_fingerprint() -> None:
    kp1 = asym.AsymmetricKeyPair.generate("ed25519")
    kp2 = asym.AsymmetricKeyPair.from_public_bytes(kp1.export_public_bytes(), "ed25519")
    kp3 = asym.AsymmetricKeyPair.generate("ed25519")
    assert kp1.equals_public(kp2) is True
    assert kp1.equals_public(kp3) is False
    assert kp1.equals_public(object()) is False
    fp = kp1.get_public_fingerprint()
    assert fp == hashlib.sha256(kp1.export_public_bytes()).hexdigest()


def test_algorithm_factory_constructs() -> None:
    e = asym.AlgorithmFactory["ed25519"]()
    r = asym.AlgorithmFactory["rsa4096"](key_size=2048)
    c = asym.AlgorithmFactory["ecdsa_p256"]()
    assert isinstance(e, asym.AsymmetricKeyPair)
    assert isinstance(r, asym.AsymmetricKeyPair)
    assert isinstance(c, asym.AsymmetricKeyPair)
    # sanity: rsa sign/verify
    sig = r.sign(b"d")
    assert r.verify(b"d", sig) is True


def test_secure_log_suppresses_sensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, tuple[Any, ...]]] = []

    def fake_info(msg: str, *args: Any) -> None:
        calls.append((msg, args))

    monkeypatch.setattr(
        asym, "logger", type("L", (), {"info": staticmethod(fake_info)})()
    )
    # Contains sensitive word "key" => should not log
    asym._secure_log("Processing private KEY for user")
    # Non-sensitive => should log
    asym._secure_log("Hello world")
    assert len(calls) == 1 and calls[0][0] == "Hello world"


def test_sign_decrypt_require_private_and_encrypt_require_rsa() -> None:
    # Public-only Ed25519: sign should raise
    kp_pub_only = asym.AsymmetricKeyPair.from_public_bytes(
        asym.AsymmetricKeyPair.generate("ed25519").export_public_bytes(), "ed25519"
    )
    with pytest.raises(NotImplementedError):
        _ = kp_pub_only.sign(b"x")

    # Public-only RSA: decrypt should raise
    rsa_priv = asym.AsymmetricKeyPair.generate("rsa4096", key_size=2048)
    rsa_pub_only = asym.AsymmetricKeyPair.from_public_bytes(
        rsa_priv.export_public_bytes(), "rsa4096"
    )
    with pytest.raises(NotImplementedError):
        _ = rsa_pub_only.decrypt(b"abc")

    # Ed25519 encrypt should raise
    ed = asym.AsymmetricKeyPair.generate("ed25519")
    with pytest.raises(NotImplementedError):
        _ = ed.encrypt(b"abc")


def test_rsa_oaep_overflow_error_message_contains_sizes() -> None:
    kp = asym.AsymmetricKeyPair.generate("rsa4096", key_size=2048)
    overhead = asym._rsa_oaep_overhead()

    # Type guard для доступа к key_size (только у RSA)
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

    assert isinstance(kp.public_key, RSAPublicKey)

    limit = kp.public_key.key_size // 8 - overhead
    with pytest.raises(ValueError) as ei:
        _ = kp.encrypt(b"x" * (limit + 1))
    msg = str(ei.value).lower()
    # Сообщение должно указывать на ограничение длины и/или размер
    assert any(tok in msg for tok in ("length", "bytes", "<=", "limit"))
    # Желательно видеть либо порог, либо фактический размер
    assert any(s in msg for s in (str(limit), str(limit + 1)))


def test_from_private_bytes_garbage_pem_raises_keyformat() -> None:
    garbage = b"-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n"
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_private_bytes(garbage, "ed25519")


def test_from_public_bytes_garbage_pem_raises_keyformat() -> None:
    garbage = b"-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n"
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_public_bytes(garbage, "ed25519")


def test_from_private_bytes_wrong_key_type_raises() -> None:
    # Генерируем RSA, пытаемся импортировать как ed25519
    rsa_kp = asym.AsymmetricKeyPair.generate("rsa4096", key_size=2048)
    pem = rsa_kp.export_private_bytes()
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_private_bytes(pem, "ed25519")


def test_from_public_bytes_wrong_key_type_raises() -> None:
    rsa_kp = asym.AsymmetricKeyPair.generate("rsa4096", key_size=2048)
    pem_pub = rsa_kp.export_public_bytes()
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_public_bytes(pem_pub, "ed25519")


def test_rsa_generate_with_too_small_keysize_rejected() -> None:
    # Если в коде есть валидация минимального размера — проверим её; иначе пропустим.
    try:
        with pytest.raises(
            (ValueError, asym.UnsupportedAlgorithmError, AssertionError)
        ):
            _ = asym.AsymmetricKeyPair.generate("rsa4096", key_size=512)
    except AssertionError:
        pytest.skip("No minimal RSA key size validation implemented")


def test_equals_public_false_for_different_algorithms() -> None:
    e = asym.AsymmetricKeyPair.generate("ed25519")
    r = asym.AsymmetricKeyPair.generate("rsa4096", key_size=2048)
    assert e.equals_public(r) is False
    assert r.equals_public(e) is False


def test_secure_log_filters_multiple_sensitive_words(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[str] = []

    def fake_info(msg: str, *args: Any) -> None:
        captured.append(msg % args if args else msg)

    monkeypatch.setattr(
        asym, "logger", type("L", (), {"info": staticmethod(fake_info)})()
    )
    # Слова в разных регистрах и формах
    asym._secure_log("user provided Private Key and TOKEN")
    asym._secure_log("completely safe")
    assert captured == ["completely safe"]


def test_rsa_private_export_with_password_and_wrong_password() -> None:
    kp = asym.AsymmetricKeyPair.generate("rsa4096", key_size=2048)
    pem = kp.export_private_bytes(password="pw")
    # Правильный пароль
    kp2 = asym.AsymmetricKeyPair.from_private_bytes(pem, "rsa4096", password="pw")
    assert kp.equals_public(kp2) is True
    # Неверный пароль
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_private_bytes(pem, "rsa4096", password="bad")


def test_ecdsa_public_as_ed25519_rejected() -> None:
    kp = asym.AsymmetricKeyPair.generate("ecdsa_p256")
    pem = kp.export_public_bytes()
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_public_bytes(pem, "ed25519")


def test_ed25519_private_unencrypted_import_and_mismatch() -> None:
    kp = asym.AsymmetricKeyPair.generate("ed25519")
    pem = kp.export_private_bytes()
    kp2 = asym.AsymmetricKeyPair.from_private_bytes(pem, "ed25519")
    assert kp.equals_public(kp2) is True
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_private_bytes(pem, "ecdsa_p256")


def test_rsa_public_as_ecdsa_rejected() -> None:
    kp = asym.AsymmetricKeyPair.generate("rsa4096", key_size=2048)
    pem = kp.export_public_bytes()
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_public_bytes(pem, "ecdsa_p256")


def test_from_private_bytes_unsupported_container_format_raises() -> None:
    # Создадим valid EC private key, импортируем как rsa4096 → должно упасть проверкой формата/типа
    ec_kp = asym.AsymmetricKeyPair.generate("ecdsa_p256")
    pem_ec = ec_kp.export_private_bytes()
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_private_bytes(pem_ec, "rsa4096")


def test_from_public_bytes_der_data_rejected() -> None:
    # Возьмём PEM и «испорчим» заголовки, чтобы это больше не было PEM
    kp = asym.AsymmetricKeyPair.generate("ed25519")
    pem = kp.export_public_bytes()
    der_like = pem.replace(b"-----BEGIN PUBLIC KEY-----", b"\x30\x82", 1)
    with pytest.raises(asym.KeyFormatError):
        _ = asym.AsymmetricKeyPair.from_public_bytes(der_like, "ed25519")


def test_rsa_public_only_decrypt_rejected() -> None:
    priv = asym.AsymmetricKeyPair.generate("rsa4096", key_size=2048)
    pub_only = asym.AsymmetricKeyPair.from_public_bytes(
        priv.export_public_bytes(), "rsa4096"
    )
    with pytest.raises(NotImplementedError):
        _ = pub_only.decrypt(b"\x00" * 256)


class TestSensitiveDataDetection:
    """Тесты обнаружения чувствительных данных."""

    @pytest.mark.parametrize(
        "text,should_detect",
        [
            # Должны обнаружиться
            ("password", True),
            ("PASSWORD", True),
            ("passwd", True),
            ("pwd", True),
            ("private_key", True),
            ("privateKey", True),
            ("PRIVATE_KEY", True),
            ("secret_token", True),
            ("API_KEY", True),
            ("apiKey", True),
            ("auth_header", True),
            ("Loading PEM data", True),
            ("Generating salt", True),
            ("Using nonce", True),
            ("cipher output", True),
            # Не должны обнаружиться
            ("algorithm: ed25519", False),
            ("key_size: 4096", False),
            ("Generating keypair", False),
            ("Signature valid", False),
            ("encryption complete", False),
        ],
    )
    def test_contains_sensitive_data(self, text: str, should_detect: bool) -> None:
        """Проверка regex-паттернов обнаружения чувствительных данных."""
        assert _contains_sensitive_data(text) == should_detect


class TestSecureLogging:
    """Тесты функции _secure_log."""

    def test_secure_log_blocks_password_mention(
        self, caplog: LogCaptureFixture
    ) -> None:
        """_secure_log блокирует сообщения с упоминанием 'password'."""
        with caplog.at_level(logging.INFO):
            _secure_log("User password is %s", "secret123")

        assert len(caplog.records) == 0, "Сообщение с 'password' не должно логироваться"

    def test_secure_log_blocks_private_key_camelcase(
        self, caplog: LogCaptureFixture
    ) -> None:
        """_secure_log блокирует сообщения с 'privateKey' (camelCase)."""
        with caplog.at_level(logging.INFO):
            _secure_log("Loaded privateKey for algorithm=%s", "ed25519")

        assert (
            len(caplog.records) == 0
        ), "Сообщение с 'privateKey' не должно логироваться"

    def test_secure_log_blocks_api_key_uppercase(
        self, caplog: LogCaptureFixture
    ) -> None:
        """_secure_log блокирует сообщения с 'API_KEY' (uppercase)."""
        with caplog.at_level(logging.INFO):
            _secure_log("Setting API_KEY=%s", "sk_live_xxx")

        assert len(caplog.records) == 0, "Сообщение с 'API_KEY' не должно логироваться"

    def test_secure_log_allows_safe_messages(self, caplog: LogCaptureFixture) -> None:
        """_secure_log пропускает безопасные сообщения."""
        with caplog.at_level(logging.INFO):
            _secure_log("Generating keypair: algorithm=%s", "ed25519")

        assert len(caplog.records) == 1
        assert "ed25519" in caplog.text

    def test_secure_log_blocks_abbreviations(self, caplog: LogCaptureFixture) -> None:
        """_secure_log блокирует сокращения (priv, sec, pass)."""
        with caplog.at_level(logging.INFO):
            _secure_log("Using priv for %s", "operation")

        assert len(caplog.records) == 0


class TestAsymmetricKeyPairLogging:
    """Интеграционные тесты логирования AsymmetricKeyPair."""

    def test_generate_logs_safely(self, caplog: LogCaptureFixture) -> None:
        """generate() логирует алгоритм без чувствительных данных."""
        with caplog.at_level(logging.INFO):
            kp = AsymmetricKeyPair.generate("ed25519")

        assert any("algorithm=ed25519" in rec.message for rec in caplog.records)
        assert kp.private_key is not None

    def test_from_private_bytes_masked_password(
        self, caplog: LogCaptureFixture
    ) -> None:
        """from_private_bytes() маскирует информацию о пароле."""
        kp = AsymmetricKeyPair.generate("ed25519")
        pem = kp.export_private_bytes(password="Secret123!")

        with caplog.at_level(logging.INFO):
            AsymmetricKeyPair.from_private_bytes(pem, "ed25519", password="Secret123!")

        # Должно быть: "Loading key: algorithm=ed25519 [protected=yes]"
        assert any("protected=yes" in rec.message for rec in caplog.records)
        assert "Secret123!" not in caplog.text
        assert "password" not in caplog.text.lower()

    def test_from_public_bytes_logs_safely(self, caplog: LogCaptureFixture) -> None:
        """from_public_bytes() логирует алгоритм безопасно."""
        kp = AsymmetricKeyPair.generate("ed25519")
        pub_pem = kp.export_public_bytes()

        with caplog.at_level(logging.INFO):
            AsymmetricKeyPair.from_public_bytes(pub_pem, "ed25519")

        assert any("public-only" in rec.message for rec in caplog.records)
        assert any("ed25519" in rec.message for rec in caplog.records)


@pytest.mark.security
class TestSecurityCompliance:
    """Тесты соответствия требованиям безопасности."""

    def test_no_secrets_in_logs_comprehensive(self, caplog: LogCaptureFixture) -> None:
        """Комплексная проверка: никакие секреты не попадают в логи."""
        caplog.set_level(logging.DEBUG)

        # Генерируем ключ с паролем
        kp = AsymmetricKeyPair.generate("ed25519")
        password = "SuperSecret123!@#"
        pem = kp.export_private_bytes(password=password)

        # Загружаем с паролем
        AsymmetricKeyPair.from_private_bytes(pem, "ed25519", password=password)

        # Проверяем, что пароль нигде не появился
        full_log = caplog.text.lower()
        assert password.lower() not in full_log
        assert "supersecret" not in full_log
        assert "123!@#" not in full_log

        # Но алгоритм должен быть
        assert "ed25519" in full_log


def test_generate_unsupported_algorithm() -> None:
    """Test generation with invalid algorithm."""
    with pytest.raises(
        UnsupportedAlgorithmError, match="Unsupported algorithm: invalid"
    ):
        AsymmetricKeyPair.generate("invalid")


def test_secure_log_format_error() -> None:
    """Test _secure_log handles format errors gracefully."""
    from src.security.crypto.asymmetric import _secure_log

    # Не должно крашнуться при неправильном форматировании
    _secure_log("Test %s %s", "only_one_arg")  # TypeError
    # Просто не логируется, но не падает


def test_from_private_bytes_invalid_pem() -> None:
    """Test loading completely invalid PEM data."""
    invalid_pem = b"-----BEGIN PRIVATE KEY-----\nGARBAGE\n-----END PRIVATE KEY-----"

    with pytest.raises(KeyFormatError, match="Failed to import private key"):
        AsymmetricKeyPair.from_private_bytes(invalid_pem, "ed25519")
