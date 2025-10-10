# tests/unit/security/auth/test_totp_factor.py

import time
import pyotp
import pytest

from src.security.auth.second_method.totp import TotpFactor


def test_totp_setup_and_verify_default_secret() -> None:
    factor = TotpFactor()
    user_id = "alice"
    username = "testuser"
    issuer = "TestApp"
    state = factor.setup(user_id=user_id, username=username, issuer=issuer)
    assert "secret" in state
    secret = state["secret"]
    # Генерируем валидный код — должен пройти проверку
    code = pyotp.TOTP(secret).now()
    assert factor.verify(user_id, code, state)
    # Не валидный код — должен быть False
    assert not factor.verify(user_id, "123456", state)


def test_totp_setup_with_custom_secret() -> None:
    custom_secret = pyotp.random_base32()
    factor = TotpFactor()
    user_id = "bob"
    username = "testbob"
    issuer = "TestApp"
    state = factor.setup(user_id=user_id, secret=custom_secret, username=username, issuer=issuer)
    assert state["secret"] == custom_secret
    code = pyotp.TOTP(custom_secret).now()
    assert factor.verify(user_id, code, state)


def test_totp_time_window() -> None:
    factor = TotpFactor()
    user_id = "charlie"
    state = factor.setup(user_id)
    secret = state["secret"]
    totp = pyotp.TOTP(secret)
    # Выдаем код с прошлого временного окна (±30 сек)
    code_past = totp.at(int(time.time()) - 30)
    assert factor.verify(user_id, code_past, state)
    # Выдаем код с будущего окна (±30 сек)
    code_future = totp.at(int(time.time()) + 30)
    assert factor.verify(user_id, code_future, state)


def test_totp_missing_secret() -> None:
    factor = TotpFactor()
    user_id = "no_secret"
    state = {"issuer": "TestApp"}
    assert not factor.verify(user_id, "123456", state)


def test_remove_clears_secret_and_logs() -> None:
    factor = TotpFactor()
    s = factor.setup("user42")
    s["audit"] = []
    # должен быть secret
    assert "secret" in s
    factor.remove("user42", s)
    assert "secret" not in s
    assert any(a.get("action") == "remove" for a in s["audit"])


def test_audit_and_last_success_timestamp() -> None:
    factor = TotpFactor()
    s = factor.setup("userT")
    otp = pyotp.TOTP(s["secret"]).now()
    assert factor.verify("userT", otp, s) is True
    assert isinstance(s.get("last_success"), int)


def test_totp_remove_secret_and_audit() -> None:
    factor = TotpFactor()
    state = factor.setup("userY")
    state["audit"] = []
    factor.remove("userY", state)
    assert "secret" not in state
    assert any(a["action"] == "remove" for a in state["audit"])


def test_totp_last_success_written() -> None:
    factor = TotpFactor()
    state = factor.setup("userZ")
    otp = pyotp.TOTP(state["secret"]).now()
    assert factor.verify("userZ", otp, state) is True
    assert isinstance(state.get("last_success"), int)
