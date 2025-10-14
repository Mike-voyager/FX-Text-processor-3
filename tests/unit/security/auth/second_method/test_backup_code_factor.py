# tests/unit/security/auth/second_method/test_backup_code_factor.py

import time
import pytest
from src.security.auth.second_method.code import (
    BackupCodeFactor,
    format_code,
    CODE_BITS,
    MAX_ATTEMPTS,
    LOCK_SECONDS,
    DEFAULT_TTL,
)


def test_format_code_blocks() -> None:
    raw: str = "a1b2c3d4" * 8  # 64 символа
    formatted: str = format_code(raw)
    blocks = formatted.split("-")
    assert len(blocks) == 16
    assert all(len(block) == 4 for block in blocks)
    assert formatted.replace("-", "") == raw


def setup_factor_state(
    count: int = 3, ttl: int = DEFAULT_TTL
) -> tuple[BackupCodeFactor, dict]:
    factor = BackupCodeFactor()
    state = factor.setup("user_test", count=count, ttl_seconds=ttl)
    return factor, state


def test_generate_and_active_codes() -> None:
    factor, state = setup_factor_state()
    active = factor.get_active_codes(state)  # это List[str]
    assert len(active) == 3
    for code in active:
        assert "-" in code
        assert len(code.replace("-", "")) == CODE_BITS // 4


def test_verify_success_and_used_status() -> None:
    factor, state = setup_factor_state()
    code = state["codes"][0]["code"]
    res = factor.verify("user_test", code, state)
    assert res["status"] == "success"
    res2 = factor.verify("user_test", code, state)
    assert res2["status"] == "used"


def test_bruteforce_lockout() -> None:
    factor, state = setup_factor_state()
    fake_code: str = "abcd-" * 16
    for i in range(MAX_ATTEMPTS):
        result = factor.verify("user_test", fake_code, state)
        assert result["status"] in ["fail", "lockout"]
    result = factor.verify("user_test", fake_code, state)
    assert result["status"] == "lockout"


def test_ttl_and_expire_batch() -> None:
    factor, state = setup_factor_state()
    state["created"] = int(time.time()) - DEFAULT_TTL - 1000
    code = state["codes"][0]["code"]
    res = factor.verify("user_test", code, state)
    assert res["status"] == "expired"
    factor.expire(state)
    for c in state["codes"]:
        assert c["used"]


def test_audit_log_tracking() -> None:
    factor, state = setup_factor_state()
    code = state["codes"][0]["code"]
    fake = "ffff-" * 16
    factor.verify("user_test", code, state)
    factor.verify("user_test", fake, state)
    factor.verify("user_test", code, state)
    audit = factor.get_audit_log(state)
    statuses = [e["result"] for e in audit]
    assert "success" in statuses
    assert "fail" in statuses
    assert "used" in statuses


def test_remove_backup_codes() -> None:
    factor = BackupCodeFactor()
    # Стартовое состояние: 2 кода не использовано, есть audit
    state = factor.setup("userA", count=2)
    assert len(state["codes"]) == 2
    factor.remove("userA", state)
    assert state["codes"] == []
    assert "audit" in state
    assert any(a.get("action") == "remove" for a in state["audit"])
    assert state["lockuntil"] > 0


def test_remove_backup_codes_audit() -> None:
    factor = BackupCodeFactor()
    state = factor.setup("userX", count=2)
    factor.remove("userX", state)
    assert state["codes"] == []
    assert state["lockuntil"] > 0
    assert any(a["action"] == "remove" for a in state["audit"])
