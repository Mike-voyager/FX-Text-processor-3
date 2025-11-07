import sys
import types
import pytest
import threading
from typing import Any, Dict, List, Tuple, Iterator, cast, BinaryIO

import src.security.auth.totp_service as tots


class DummyManager:
    def __init__(self) -> None:
        self._factors: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    def setup_factor(self, user_id: str, ftype: str, **kwargs: Any) -> None:
        self._factors.setdefault(user_id, {}).setdefault(ftype, []).append(
            {
                "state": {
                    "secret": "SECRETSIGN",
                    "audit": [123],
                    "username": kwargs.get("username", ""),
                    "issuer": kwargs.get("issuer", ""),
                }
            }
        )

    def verify_factor(self, user_id: str, ftype: str, credential: str) -> bool:
        return credential == "goldcode"

    def remove_factor(self, user_id: str, ftype: str) -> None:
        if user_id in self._factors and ftype in self._factors[user_id]:
            self._factors[user_id].pop(ftype)


class DummyContext:
    def __init__(self, manager: DummyManager) -> None:
        self.mfa_manager = manager


class DummyPyotpTOTP:
    def __init__(self, secret: str) -> None:
        self.secret = secret
        self.last_code: str | None = None

    def verify(self, code: str) -> bool:
        self.last_code = code
        return code == "safeotp"

    def provisioning_uri(self, name: str, issuer_name: str) -> str:
        return f"otpauth://totp/{issuer_name}:{name}?secret={self.secret}&issuer={issuer_name}"


class DummyQr:
    def __init__(self, uri: str) -> None:
        self._uri = uri

    def save(self, buf: BinaryIO, fmt: str) -> None:
        buf.write(b"dummyqrcode")


@pytest.fixture(autouse=True)
def patch_context(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    mgr = DummyManager()
    ctx = DummyContext(mgr)
    monkeypatch.setattr(tots, "get_app_context", lambda: ctx)
    yield


@pytest.fixture(autouse=True)
def isolate_manager_lock(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(tots, "_manager_lock", threading.RLock())
    yield


@pytest.fixture
def patch_pyotp_qrcode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(tots, "pyotp", types.SimpleNamespace(TOTP=DummyPyotpTOTP))  # type: ignore
    monkeypatch.setattr(tots, "qrcode", types.SimpleNamespace(make=lambda uri: DummyQr(uri)))  # type: ignore
    yield


def test_setup_totp_for_user(patch_pyotp_qrcode: None) -> None:
    result = tots.setup_totp_for_user("alice", "alice_login", "ACorp")
    assert isinstance(result, dict)
    assert "secret" in result and "qr" in result and "uri" in result
    assert isinstance(result["qr"], bytes)


def test_setup_totp_for_user_default_issuer(patch_pyotp_qrcode: None) -> None:
    result = tots.setup_totp_for_user("bob", "bobuser")
    assert isinstance(result["uri"], str) and "FX Text Processor" in result["uri"]


def test_validate_totp_code() -> None:
    # "goldcode" тестирует положительный путь
    tots.setup_totp_for_user("u", "n")
    assert tots.validate_totp_code("u", "goldcode") is True
    assert tots.validate_totp_code("u", "other") is False


def test_remove_totp_for_user() -> None:
    tots.setup_totp_for_user("rem", "rlogin")
    tots.remove_totp_for_user("rem")
    assert tots.get_totp_status("rem") == {}


def test_get_totp_status_no_data() -> None:
    assert tots.get_totp_status("never") == {}


def test_get_totp_status_normal() -> None:
    tots.setup_totp_for_user("s", "log")
    st = tots.get_totp_status("s")
    assert isinstance(st, dict) and "secret" in st


def test_get_totp_audit() -> None:
    tots.setup_totp_for_user("aud", "n")
    result = tots.get_totp_audit("aud")
    assert isinstance(result, list) and 123 in result


def test_get_totp_audit_empty() -> None:
    assert tots.get_totp_audit("nouser") == []


def test_generate_totp_qr_uri(patch_pyotp_qrcode: None) -> None:
    tots.setup_totp_for_user("qruser", "qrlogin", "ISS")
    uri, qr = tots.generate_totp_qr_uri("qruser")
    assert "otpauth://" in uri
    assert qr == b"dummyqrcode"


def test_generate_totp_qr_uri_empty(patch_pyotp_qrcode: None) -> None:
    uri, qr = tots.generate_totp_qr_uri("unknown")
    assert isinstance(uri, str)
    assert isinstance(qr, bytes)


def test_get_totp_secret_for_storage_success(
    monkeypatch: pytest.MonkeyPatch,
    patch_pyotp_qrcode: None,  # если используется доп. фикстура для qrcode/pyotp — можно убрать
) -> None:
    # Подготавливаем фактор
    tots.setup_totp_for_user("sec", "secuser")
    # Патчим derive_key_argon2id
    monkeypatch.setattr(
        tots, "derive_key_argon2id", lambda pw, salt, length: b"retkey" * (length // 6)
    )

    # ---- КРИТИЧЕСКИЙ ПАТЧ ДЛЯ PYOTP (в sys.modules) ----
    class DummyPyotpTOTP:
        def __init__(self, secret: str) -> None:
            self.secret = secret

        def verify(self, code: str) -> bool:
            return code == "safeotp"

        def provisioning_uri(self, name: str, issuer_name: str) -> str:
            return "dummyuri"

    dummy_pyotp_mod = types.SimpleNamespace(TOTP=DummyPyotpTOTP)
    monkeypatch.setitem(sys.modules, "pyotp", dummy_pyotp_mod)
    # -----------------------
    secret = tots.get_totp_secret_for_storage("sec", "safeotp")
    assert b"retkey" in secret


def test_get_totp_secret_for_storage_invalid(
    monkeypatch: pytest.MonkeyPatch, patch_pyotp_qrcode: None
) -> None:
    tots.setup_totp_for_user("failu", "failuser")
    monkeypatch.setattr(
        tots, "derive_key_argon2id", lambda pw, salt, length: b"retkey" * (length // 6)
    )
    with pytest.raises(PermissionError):
        tots.get_totp_secret_for_storage("failu", "wrongotp")


def test_get_totp_secret_for_storage_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # Нет фактора/секрета
    with pytest.raises(PermissionError):
        tots.get_totp_secret_for_storage("foo", "any")
