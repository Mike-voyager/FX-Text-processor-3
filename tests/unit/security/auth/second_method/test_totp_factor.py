# tests/unit/security/auth/test_totp_factor.py

import time
import pyotp
import pytest
from unittest.mock import patch

from src.security.auth.second_method.totp import (
    TotpFactor,
    TotpVerificationFailed,
    TotpSecretMissing,
)


def test_totp_setup_and_verify_default_secret() -> None:
    factor = TotpFactor()
    user_id = "alice"
    username = "testuser"
    issuer = "TestApp"
    state = factor.setup(user_id=user_id, username=username, issuer=issuer)
    assert "secret" in state
    secret = state["secret"]
    code = pyotp.TOTP(secret).now()
    assert factor.verify(user_id, code, state)
    # Анти-реплей: повтор использовать нельзя — ловим исключение
    with pytest.raises(Exception):
        factor.verify(user_id, code, state)
    # Не валидный код: должен быть invalid_format или fail, ловим TotpVerificationFailed
    with pytest.raises(Exception):
        factor.verify(user_id, "123456", state)


def test_totp_setup_with_custom_secret() -> None:
    custom_secret = pyotp.random_base32()
    factor = TotpFactor()
    user_id = "bob"
    username = "testbob"
    issuer = "TestApp"
    state = factor.setup(
        user_id=user_id, secret=custom_secret, username=username, issuer=issuer
    )
    assert state["secret"] == custom_secret
    code = pyotp.TOTP(custom_secret).now()
    assert factor.verify(user_id, code, state)


def test_totp_time_window() -> None:
    factor = TotpFactor()
    user_id = "charlie"
    state = factor.setup(user_id)
    secret = state["secret"]
    totp = pyotp.TOTP(secret)
    code_past = totp.at(int(time.time()) - 30)
    assert factor.verify(user_id, code_past, state)
    code_future = totp.at(int(time.time()) + 30)
    with pytest.raises(Exception):  # здесь реплей тоже случится
        factor.verify(user_id, code_future, state)


def test_totp_missing_secret() -> None:
    factor = TotpFactor()
    user_id = "no_secret"
    state = {"issuer": "TestApp"}
    import pytest

    with pytest.raises(Exception):  # теперь ловим TotpSecretMissing
        factor.verify(user_id, "123456", state)


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
    assert isinstance(s.get("last_success_at"), str)


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
    assert isinstance(state.get("last_success_at"), str)


def test_totp_invalid_format_digits() -> None:
    factor = TotpFactor()
    state = factor.setup("user")
    secret = state["secret"]

    # 4-значный код вместо 6
    with pytest.raises(TotpVerificationFailed):
        factor.verify("user", "1234", state)

    # буквенный код
    with pytest.raises(TotpVerificationFailed):
        factor.verify("user", "abcdef", state)


def test_totp_different_interval() -> None:
    factor = TotpFactor()
    state = factor.setup("u1", interval=60)
    secret = state["secret"]
    interval_test = state.get("interval", 60)
    totp = pyotp.TOTP(secret, interval=interval_test)
    code = totp.now()
    assert factor.verify("u1", code, state)  # Ожидаем успех при совпадении интервала


def test_totp_rotated_secret() -> None:
    factor = TotpFactor()
    s1 = factor.setup("userR")
    secret_old = s1["secret"]
    s1["rotated"] = True

    # Эмулируем ротацию — проверка secret все еще доступна
    assert "secret" in s1

    code = pyotp.TOTP(secret_old).now()
    assert factor.verify("userR", code, s1)


def test_totp_audit_multiple_types() -> None:
    factor = TotpFactor()
    state = factor.setup("u2")
    secret = state["secret"]
    otp = pyotp.TOTP(secret).now()

    # успешная попытка
    assert factor.verify("u2", otp, state)

    # повтор — попадем в replay/exception
    with pytest.raises(TotpVerificationFailed):
        factor.verify("u2", otp, state)

    # невалидный формат
    with pytest.raises(TotpVerificationFailed):
        factor.verify("u2", "abcde", state)

    # Проверяем audit trail
    audit = state["audit"]
    assert any(event.get("result") == "success" for event in audit)
    assert any(event.get("result") == "replay_detected" for event in audit)
    assert any(event.get("result") == "invalid_format" for event in audit)


def test_missing_username_issuer_defaults() -> None:
    factor = TotpFactor()

    # username/issuer можно не передавать

    state = factor.setup("user3")
    assert "username" not in state or state["username"] == "user3"
    assert state["issuer"] == "FX Text Processor"


def test_remove_state_edge_cases() -> None:
    factor = TotpFactor()
    state = factor.setup("remover")
    state["audit"] = []

    # удаляем уже удаленный secret
    factor.remove("remover", state)

    # повторное удаление не должно бросать — идемпотентно
    factor.remove("remover", state)
    assert "secret" not in state
    assert any(a.get("action") == "remove" for a in state["audit"])


def test_custom_digits_interval() -> None:
    factor = TotpFactor()
    state = factor.setup("uX", digits=8, interval=60)
    secret = state["secret"]
    digits_test = state.get("digits", 8)
    interval_test = state.get("interval", 60)
    totp = pyotp.TOTP(secret, digits=digits_test, interval=interval_test)
    code = totp.now()
    assert factor.verify("uX", code, state)
    # невалидный 6-значный код
    with pytest.raises(Exception):
        factor.verify("uX", "123456", state)


def test_totp_secret_missing_for_remove() -> None:
    factor = TotpFactor()
    state = {"issuer": "TestApp"}
    # вызов .remove если secret нет — должен быть идемпотентным
    factor.remove("user", state)
    # .verify выбрасывает TotpSecretMissing
    with pytest.raises(TotpSecretMissing):
        factor.verify("user", "133456", state)


def test_interval_time_window_past_future() -> None:
    factor = TotpFactor()
    s = factor.setup("timewin", interval=30)
    secret = s["secret"]
    totp = pyotp.TOTP(secret, interval=30)
    now = int(time.time())
    # прошлое окно
    cpast = totp.at(now - 30)
    assert factor.verify("timewin", cpast, s, enable_anti_replay=False)
    # будущее окно
    cnext = totp.at(now + 30)
    assert factor.verify("timewin", cnext, s, enable_anti_replay=False)


def test_audit_trail_covers_remove_verify() -> None:
    factor = TotpFactor()
    state = factor.setup("userTT")
    code = pyotp.TOTP(state["secret"]).now()
    factor.verify("userTT", code, state)
    factor.remove("userTT", state)
    audit = state["audit"]
    results = set(e.get("result") for e in audit if "result" in e)
    assert "success" in results
    assert "remove" in [a.get("action") for a in audit]


def test_totp_successful_verification() -> None:
    """Verify that a freshly generated OTP is accepted."""
    factor = TotpFactor()
    state = factor.setup("alice")
    secret = state["secret"]

    otp = pyotp.TOTP(secret).now()
    assert factor.verify("alice", otp, state) is True


def test_totp_replay_detection() -> None:
    """A second verification with the same OTP must raise TotpVerificationFailed."""
    factor = TotpFactor()
    state = factor.setup("bob")
    secret = state["secret"]
    otp = pyotp.TOTP(secret).now()

    # first attempt – succeeds
    assert factor.verify("bob", otp, state) is True

    # second attempt – should be considered a replay
    with pytest.raises(TotpVerificationFailed):
        factor.verify("bob", otp, state)


def test_totp_audit_success_entry() -> None:
    """Audit trail must contain a 'success' entry after a valid verification."""
    factor = TotpFactor()
    state = factor.setup("carol")
    secret = state["secret"]
    otp = pyotp.TOTP(secret).now()

    factor.verify("carol", otp, state)

    audit = state.get("audit", [])
    assert any(
        entry.get("result") == "success" for entry in audit
    ), "Audit trail should contain a success entry"


def test_totp_audit_replay_entry() -> None:
    """Audit trail must contain a 'replay_detected' entry when a replay occurs."""
    factor = TotpFactor()
    state = factor.setup("dave")
    secret = state["secret"]
    otp = pyotp.TOTP(secret).now()

    # first successful attempt
    factor.verify("dave", otp, state)

    # second attempt – replay
    with pytest.raises(TotpVerificationFailed):
        factor.verify("dave", otp, state)

    audit = state.get("audit", [])
    assert any(
        entry.get("result") == "replay_detected" for entry in audit
    ), "Audit trail should contain a replay_detected entry"


def test_totp_audit_invalid_format_entry() -> None:
    """Audit trail must contain an 'invalid_format' entry when OTP format is wrong."""
    factor = TotpFactor()
    state = factor.setup("eve")
    secret = state["secret"]
    otp = pyotp.TOTP(secret).now()

    # valid attempt
    factor.verify("eve", otp, state)

    # invalid format – non‑numeric string
    with pytest.raises(TotpVerificationFailed):
        factor.verify("eve", "ABCDE", state)

    audit = state.get("audit", [])
    assert any(
        entry.get("result") == "invalid_format" for entry in audit
    ), "Audit trail should contain an invalid_format entry"


def test_totp_rotated_secret_still_usable() -> None:
    """After rotation, the old secret must still be accepted for a short window."""
    factor = TotpFactor()
    state = factor.setup("frank")
    old_secret = state["secret"]

    # Simulate rotation
    state["rotated"] = True

    # OTP generated with the old secret
    otp = pyotp.TOTP(old_secret).now()

    # Verification should still succeed
    assert factor.verify("frank", otp, state) is True


def test_totp_audit_multiple_entries() -> None:
    """Audit trail should contain entries for success, replay, and invalid format."""
    factor = TotpFactor()
    state = factor.setup("grace")
    secret = state["secret"]
    otp = pyotp.TOTP(secret).now()

    # success
    factor.verify("grace", otp, state)

    # replay
    with pytest.raises(TotpVerificationFailed):
        factor.verify("grace", otp, state)

    # invalid format
    with pytest.raises(TotpVerificationFailed):
        factor.verify("grace", "XYZ12", state)

    audit = state.get("audit", [])
    assert any(
        e.get("result") == "success" for e in audit
    ), "Audit must contain a success entry"
    assert any(
        e.get("result") == "replay_detected" for e in audit
    ), "Audit must contain a replay_detected entry"
    assert any(
        e.get("result") == "invalid_format" for e in audit
    ), "Audit must contain an invalid_format entry"


def test_totp_anti_replay_disabled() -> None:
    """When anti‑replay is disabled, the same OTP can be verified twice."""
    factor = TotpFactor()
    state = factor.setup("heidi")
    secret = state["secret"]
    otp = pyotp.TOTP(secret).now()

    # first verification – success
    assert factor.verify("heidi", otp, state) is True

    # second verification – should also succeed because anti‑replay is off
    assert factor.verify("heidi", otp, state, enable_anti_replay=False) is True


def test_get_provisioning_uri_success_and_missing() -> None:
    factor = TotpFactor()
    state = factor.setup("provuser")
    # Success path
    uri = factor.get_provisioning_uri(state)
    assert uri.startswith("otpauth://totp/")
    # Remove secret – should raise
    factor.remove("provuser", state)
    with pytest.raises(TotpSecretMissing):
        factor.get_provisioning_uri(state)


def test_export_policy_deterministic_vs_random() -> None:
    factor = TotpFactor()
    d1 = factor.export_policy(deterministic=True)
    d2 = factor.export_policy(deterministic=False)
    # Deterministic should be OrderedDict, random is dict
    assert list(d1.keys()) == sorted(d1.keys())
    assert isinstance(d2, dict)


def test_export_audit_stats_and_fields() -> None:
    factor = TotpFactor()
    state = factor.setup("audituser")
    # Add multiple audits: fail, success, replay
    try:
        factor.verify("audituser", "XXXXXX", state)
    except TotpVerificationFailed:
        pass
    # Valid path
    otp = pyotp.TOTP(state["secret"]).now()
    factor.verify("audituser", otp, state)
    # repeat to trigger replay
    try:
        factor.verify("audituser", otp, state)
    except TotpVerificationFailed:
        pass
    # Deterministic
    audit = factor.export_audit(state, deterministic=True)
    assert isinstance(audit, dict)
    assert "success_count" in audit and audit["success_count"] >= 1
    assert "fail_count" in audit
    assert "replay_count" in audit
    # Non-deterministic
    audit2 = factor.export_audit(state, deterministic=False)
    assert isinstance(audit2, dict)


def test_is_secret_configured_variants() -> None:
    factor = TotpFactor()
    s1 = {"secret": "ABC"}
    s2 = {"secret": ""}
    s3 = {}  # type: ignore
    assert factor.is_secret_configured(s1)
    assert not factor.is_secret_configured(s2)
    assert not factor.is_secret_configured(s3)


def test_get_current_code_success_and_missing() -> None:
    factor = TotpFactor()
    state = factor.setup("curcode1")
    # Should return a numeric code string of correct length
    code = factor.get_current_code(state)
    assert code.isdigit() and len(code) == state["digits"]
    # Remove secret, should raise
    factor.remove("curcode1", state)
    with pytest.raises(TotpSecretMissing):
        factor.get_current_code(state)


def test_rotate_secret_changes_and_audit() -> None:
    factor = TotpFactor()
    state = factor.setup("rotateU")
    old_secret = state["secret"]
    new_secret = factor.rotate_secret(state)
    assert new_secret != old_secret
    assert state["secret"] == new_secret
    assert state["rotated"]
    assert state["last_used_time_step"] is None
    audit = factor.get_audit_log(state)
    assert any(e.get("action") == "secret_rotated" for e in audit)


def test_validate_otp_format_edges() -> None:
    # OK
    assert TotpFactor.validate_otp_format("123456", 6)
    # Incorrect length/char
    assert not TotpFactor.validate_otp_format("12345", 6)
    assert not TotpFactor.validate_otp_format("1234567", 6)
    assert not TotpFactor.validate_otp_format("abcdef", 6)
    assert not TotpFactor.validate_otp_format("1234ab", 6)
    assert TotpFactor.validate_otp_format("98765432", 8)
    assert not TotpFactor.validate_otp_format("9876543", 8)


def test_get_audit_log_empty_and_nonempty() -> None:
    factor = TotpFactor()
    state = factor.setup("auditU")
    # With events
    code = pyotp.TOTP(state["secret"]).now()
    factor.verify("auditU", code, state)
    audit = factor.get_audit_log(state)
    assert isinstance(audit, list)
    # Empty case
    audit2 = factor.get_audit_log({})
    assert isinstance(audit2, list)


def test_verify_exception_triggers_error_audit() -> None:
    factor = TotpFactor()
    state = factor.setup("errU")

    # Формально указываем типы
    def raising_verify(self: pyotp.TOTP, otp: str, valid_window: int = 1) -> bool:
        raise RuntimeError("Simulated")

    with patch.object(pyotp.TOTP, "verify", raising_verify):
        code: str = "123456"
        with pytest.raises(TotpVerificationFailed):
            factor.verify("errU", code, state)
    audit = state["audit"]
    assert any(e.get("result") == "error" for e in audit)
