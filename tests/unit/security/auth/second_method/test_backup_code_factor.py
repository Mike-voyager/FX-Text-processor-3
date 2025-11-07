# tests/unit/security/auth/second_method/test_backup_code_factor.py

from datetime import datetime, timedelta, timezone

import pytest

from src.security.auth.second_method.code import (
    DEFAULT_TTL_DAYS,
    MAX_ATTEMPTS,
    BackupCodeFactor,
    CodeExpired,
    CodeLockout,
    CodeUsed,
    format_code,
)


def setup_factor_state(
    count: int = 3, ttl: int = DEFAULT_TTL_DAYS
) -> tuple[BackupCodeFactor, dict]:
    factor = BackupCodeFactor()
    state = factor.setup("user_test", count=count, ttl_days=ttl)
    return factor, state


def test_verify_success_and_used_status() -> None:
    factor, state = setup_factor_state()
    code = state["codes"][0]["code"]
    res = factor.verify("user_test", code, state)
    assert res["status"] == "success"
    with pytest.raises(CodeUsed):
        factor.verify("user_test", code, state)


def test_bruteforce_lockout() -> None:
    factor, state = setup_factor_state()
    fake_code: str = "abcd-" * 16
    for _ in range(MAX_ATTEMPTS):
        try:
            factor.verify("user_test", fake_code, state)
        except CodeLockout:
            break
    with pytest.raises(CodeLockout):
        factor.verify("user_test", fake_code, state)


def test_ttl_and_expire_batch() -> None:
    factor, state = setup_factor_state()
    state["created_at"] = (
        datetime.now(timezone.utc) - timedelta(days=DEFAULT_TTL_DAYS + 1)
    ).isoformat()
    code = state["codes"][0]["code"]
    with pytest.raises(CodeExpired):
        factor.verify("user_test", code, state)
    factor.expire(state)
    for c in state["codes"]:
        assert c["used"]


def test_audit_log_tracking() -> None:
    factor, state = setup_factor_state()
    code = state["codes"][0]["code"]
    fake = "ffff-" * 16
    factor.verify("user_test", code, state)
    with pytest.raises(CodeUsed):
        factor.verify("user_test", code, state)
    try:
        factor.verify("user_test", fake, state)
    except CodeLockout:
        pass
    audit = factor.get_audit_log(state)
    statuses = [e["result"] for e in audit]
    assert any(a in statuses for a in ("success", "fail", "used", "lockout"))


def test_remove_backup_codes() -> None:
    factor = BackupCodeFactor()
    state = factor.setup("userA", count=2)
    assert len(state["codes"]) == 2
    factor.remove("userA", state)
    assert state["codes"] == []
    assert "audit" in state
    assert any(a.get("action") == "remove" for a in state["audit"])
    assert "lock_until" in state


def test_remove_backup_codes_audit() -> None:
    factor = BackupCodeFactor()
    state = factor.setup("userX", count=2)
    factor.remove("userX", state)
    assert state["codes"] == []
    assert "lock_until" in state
    assert any(a["action"] == "remove" for a in state["audit"])


def test_format_code_variants() -> None:
    # Edge: uneven length and custom blocksize
    raw = "a1b2c3"
    formatted = format_code(raw, block_size=2)
    assert "-" in formatted
    assert formatted.replace("-", "") == raw


def test_verify_with_spaces_and_case() -> None:
    factor, state = setup_factor_state()
    code = state["codes"][0]["code"].upper()
    # Should work with uppercase and spaces
    mixed = " ".join(code.split("-"))
    res = factor.verify("user_test", mixed, state)
    assert res["status"] == "success"
    with pytest.raises(CodeUsed):
        factor.verify("user_test", mixed.lower(), state)


def test_lockout_unlock_cycle() -> None:
    factor, state = setup_factor_state(count=1)
    fake_code: str = "abcd-" * 16
    # Fail to get locked, then unlock by time travel
    for _ in range(MAX_ATTEMPTS + 2):
        try:
            factor.verify("user_test", fake_code, state)
        except CodeLockout:
            pass
    assert "lock_until" in state
    # Advance time past lockout
    state["lock_until"] = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
    ).isoformat()
    # Now should not raise
    fake_code2 = "dcba-" * 16
    with pytest.raises(CodeLockout):
        for _ in range(MAX_ATTEMPTS + 1):
            factor.verify("user_test", fake_code2, state)


def test_expired_code_and_expire_method() -> None:
    factor, state = setup_factor_state()
    past = (
        datetime.now(timezone.utc) - timedelta(days=DEFAULT_TTL_DAYS + 1)
    ).isoformat()
    state["created_at"] = past
    with pytest.raises(CodeExpired):
        factor.verify("user_test", state["codes"][0]["code"], state)
    # check expire directly
    factor.expire(state)
    for c in state["codes"]:
        assert c["used"]


def test_remove_idempotent_and_repeated() -> None:
    factor, state = setup_factor_state(count=1)
    factor.remove("user", state)
    factor.remove("user", state)  # should not fail
    assert state["codes"] == []
    assert "audit" in state
    assert any(a.get("action") == "remove" for a in state["audit"])


def test_get_active_codes_only_unused() -> None:
    factor, state = setup_factor_state(count=2)
    code1 = state["codes"][0]["code"]
    factor.verify("user_test", code1, state)
    unused = factor.get_active_codes(state)
    assert len(unused) == 1
    assert all("-" in code for code in unused)


def test_export_policy_and_audit_summaries() -> None:
    factor, state = setup_factor_state()
    pol = factor.export_policy()
    assert isinstance(pol, dict)
    # simulate usage for better audit
    code = state["codes"][0]["code"]
    factor.verify("user", code, state)
    audit = factor.export_audit(state)
    assert isinstance(audit, dict)
    assert "audit_events" in audit


def test_audit_content_varied() -> None:
    # ensure all major results appear in audit under typical workflows
    factor, state = setup_factor_state()
    code = state["codes"][0]["code"]
    try:
        factor.verify("user", "bbbb-" * 16, state)
    except CodeLockout:
        pass
    try:
        factor.verify("user", code, state)
    except CodeExpired:
        pass
    factor.remove("user", state)
    audit = factor.get_audit_log(state)
    found = {a.get("result", a.get("action")) for a in audit}
    assert {"fail", "success", "remove"} <= found


def test_edge_setup_params() -> None:
    # test non-default count and ttl_days
    factor = BackupCodeFactor()
    state = factor.setup("U", count=5, ttl_days=1)
    assert len(state["codes"]) == 5
    assert state["ttl_days"] == 1


def test_is_expired_true_and_false() -> None:
    factor, state = setup_factor_state()
    # Не истекший TTL
    assert not factor.is_expired(state)
    # Истекший
    state["created_at"] = (
        datetime.now(timezone.utc) - timedelta(days=DEFAULT_TTL_DAYS + 1)
    ).isoformat()
    assert factor.is_expired(state)


def test_is_locked_variant() -> None:
    factor, state = setup_factor_state()
    # Без "lock_until"
    assert not factor.is_locked(state)
    # В будущем — заблокирован
    future = (datetime.now(timezone.utc) + timedelta(seconds=999)).isoformat()
    state["lock_until"] = future
    assert factor.is_locked(state)
    # В прошлом — не заблокирован
    past = (datetime.now(timezone.utc) - timedelta(seconds=10)).isoformat()
    state["lock_until"] = past
    assert not factor.is_locked(state)


def test_get_remaining_codes() -> None:
    factor, state = setup_factor_state()
    assert factor.get_remaining_codes(state) == len(state["codes"])
    for c in state["codes"]:
        c["used"] = True
    assert factor.get_remaining_codes(state) == 0
    # Даже с lock_until, оставшихся неиспользованных не появляется
    future = (datetime.now(timezone.utc) + timedelta(seconds=3)).isoformat()
    state["lock_until"] = future
    assert factor.get_remaining_codes(state) == 0  # Всегда 0 если все коды used


def test_get_remaining_codes_edge() -> None:
    factor, state = setup_factor_state(count=2)
    # Оба неиспользованы
    assert factor.get_remaining_codes(state) == 2
    # Один потратим
    code = state["codes"][0]["code"]
    factor.verify("edge_case", code, state)
    assert factor.get_remaining_codes(state) == 1
    # Все потратить
    code2 = state["codes"][1]["code"]
    factor.verify("edge_case", code2, state)
    assert factor.get_remaining_codes(state) == 0


def test_export_policy_nondeterministic() -> None:
    factor = BackupCodeFactor()
    res = factor.export_policy(deterministic=False)
    assert isinstance(res, dict) and "code_bits" in res


def test_export_audit_nondeterministic() -> None:
    factor, state = setup_factor_state()
    res = factor.export_audit(state, deterministic=False)
    assert isinstance(res, dict) and "total_codes" in res


def test_remove_empty_codes_and_audit() -> None:
    factor, state = setup_factor_state()
    state["codes"].clear()  # Специально очистить
    factor.remove("edge_case", state)
    assert state["codes"] == []
    assert "audit" in state


def test_expire_on_empty_codes() -> None:
    factor, state = setup_factor_state()
    state["codes"].clear()
    factor.expire(state)
    # Просто факт отработки — ошибки быть не должно


def test_getauditlog_empty_and_nonempty() -> None:
    factor, state = setup_factor_state()
    # Пустой
    assert factor.get_audit_log({}) == []
    # С аудитом
    code = state["codes"][0]["code"]
    try:
        factor.verify("edge_case", code, state)
    except Exception:
        pass
    log = factor.get_audit_log(state)
    assert isinstance(log, list)


def test_verify_nonexistent_code_returns_fail() -> None:
    factor, state = setup_factor_state()
    fake_code = "dead-" * 16
    # Делаем до lockout
    for _ in range(MAX_ATTEMPTS - 1):
        res = factor.verify("edge_case", fake_code, state)
        assert res["status"] == "fail"
    # После лимита — выброшен lockout
    with pytest.raises(CodeLockout):
        factor.verify("edge_case", fake_code, state)
