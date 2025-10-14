import os
import pytest
import logging
import asyncio
from types import SimpleNamespace
from typing import Any

from src.security.auth.password import (
    PasswordHasher,
    MfaEvent,
    is_valid_password,
    MAX_FAILED_ATTEMPTS,
)

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


class MfaSpy:
    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []

    def __call__(self, event: str, user_id: str, metadata: dict[str, Any]) -> None:
        self.events.append((event, user_id, metadata))


def make_hasher(
    mfa_callback: Any = None,
    pepper: bytes | None = None,
    pepper_old: bytes | None = None,
    kdf: Any = None,
) -> PasswordHasher:
    return PasswordHasher(
        pepper=pepper,
        pepper_old=pepper_old,
        mfa_callback=mfa_callback,
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        kdf=kdf,
    )


@pytest.mark.parametrize(
    "pw, expect",
    [
        ("Qwerty1!", True),
        ("Short7!", False),
        ("nouppercase123", False),
        ("NOLOWERCASE123", False),
        ("NoSpecials123", False),
        ("qwerty123", False),
        ("$$$$$$$$$$$$", False),
        ("AaBbCcDd", False),
        ("12345678", False),
        ("ValidPass1!", True),
        ("p@SSw0rd2023#", True),
    ],
)
def test_is_valid_password_policy(pw: str, expect: bool) -> None:
    assert is_valid_password(pw) is expect


def test_generate_salt_length_entropy() -> None:
    hasher = make_hasher()
    s = hasher.generate_salt(16)
    assert isinstance(s, bytes) and len(s) == 16
    s2 = hasher.generate_salt(32)
    assert len(s2) == 32
    assert s != s2


def test_hash_and_verify_password_minimal() -> None:
    h = make_hasher()
    pw = "Qwerty123!"
    salt = h.generate_salt()
    hashed = h.hash_password(pw, salt, user_id="alice")
    assert h.verify_password(pw, hashed, user_id="alice")
    assert not h.verify_password("wrongQwerty!1", hashed, user_id="alice")


def test_hash_password_policy_violation() -> None:
    h = make_hasher()
    for bad_pw in ("short", "password", "qwerty123", "NOLOWERCASE123"):
        with pytest.raises(ValueError):
            h.hash_password(bad_pw, h.generate_salt(), user_id="test")


def test_verify_password_too_many_attempts_lockout() -> None:
    mfa = MfaSpy()
    h = make_hasher(mfa_callback=mfa)
    pw = "ValidPass1!"
    hashed = h.hash_password(pw, h.generate_salt(), user_id="user1")
    for i in range(MAX_FAILED_ATTEMPTS):
        assert not h.verify_password("wrong" + str(i), hashed, user_id="user1")
    assert not h.verify_password("wrongagain!", hashed, user_id="user1")
    h._attempts["user1"] = 0
    assert h.verify_password(pw, hashed, user_id="user1")
    found_lockout = any(ev[0] == MfaEvent.PASSWORD_LOCKOUT for ev in mfa.events)
    assert found_lockout


def test_hash_and_verify_with_pepper_rotation(monkeypatch: Any) -> None:
    os.environ["FX_TEXT_PW_PEPPER"] = "mainpeppers3cr3t"
    os.environ["FX_TEXT_PW_PEPPER.old"] = "oldsecret"
    h = PasswordHasher(mfa_callback=None)
    pw = "ValidPass1!"
    salt = h.generate_salt()
    hashed = h.hash_password(pw, salt, user_id="peppertest")
    assert h.verify_password(pw, hashed, user_id="peppertest")
    h2 = PasswordHasher(pepper=b"wrong", pepper_old=None)
    assert not h2.verify_password(pw, hashed, user_id="peppertest")
    del os.environ["FX_TEXT_PW_PEPPER"]
    del os.environ["FX_TEXT_PW_PEPPER.old"]


def test_needs_rehash_and_update(monkeypatch: Any) -> None:
    h = make_hasher()
    pw = "ValidPass1!"
    salt = h.generate_salt()
    hashed = h.hash_password(pw, salt, user_id="updatetest")
    h2 = PasswordHasher(time_cost=4, memory_cost=262144, parallelism=4)
    assert h2.needs_rehash(hashed, user_id="updatetest")
    new_hash = h2.update_password(pw, hashed, user_id="updatetest")
    assert h2.verify_password(pw, new_hash, user_id="updatetest")


def test_export_policy_and_audit() -> None:
    mfa = MfaSpy()
    h = make_hasher(mfa_callback=mfa)
    p = h.export_policy()
    assert isinstance(p, dict)
    for k in ("algo", "min_password_length", "thread_safe", "lockout_threshold"):
        assert k in p
    audit = h.export_audit("not_a_user")
    assert audit["user_id"] == "not_a_user"
    assert "timestamp" in audit


def test_async_hash_and_verify() -> None:
    h = make_hasher()
    pw = "AsyncGoodPass1!"
    salt = h.generate_salt()

    async def check() -> None:
        hashed = await h.hash_password_async(pw, salt, user_id="async")
        assert isinstance(hashed, str)
        ok = await h.verify_password_async(pw, hashed, user_id="async")
        assert ok
        fail = await h.verify_password_async("NopeNotRight", hashed, user_id="async")
        assert not fail

    asyncio.run(check())


def test_zero_memory_bytearray_sideeffect() -> None:
    from src.security.auth.password import zero_memory

    ba = bytearray(b"secretdata")
    zero_memory(ba)
    assert all(b == 0 for b in ba)


def test_shutdown_threadpool() -> None:
    h = make_hasher()
    h.shutdown()
    h.shutdown()


def test_parse_hash_malformed() -> None:
    h = make_hasher()
    bad_hashes = ["", "no_delimiters", "v1:argon2id$XYZ"]
    for bad in bad_hashes:
        with pytest.raises(ValueError):
            h._parse_hash(bad)


def test_mfa_callback_alert_capture() -> None:
    spy = MfaSpy()
    h = make_hasher(mfa_callback=spy)
    assert not h.verify_password("Goodpass1!", "badformattedhash", user_id="mfauser")
    events = [ev[0] for ev in spy.events]
    assert MfaEvent.ALERT in events


def test_hash_format_version_change(monkeypatch: Any) -> None:
    h = make_hasher()
    pw = "Vers1onGoodpass!"
    salt = h.generate_salt()
    hashed = h.hash_password(pw, salt, user_id="vchange")
    import src.security.auth.password as mod

    object.__setattr__(mod, "_HASH_FORMAT_VERSION", "v2")
    assert h.needs_rehash(hashed, user_id="vchange")
    object.__setattr__(mod, "_HASH_FORMAT_VERSION", "v1")


def test_generate_salt_short_error() -> None:
    h = make_hasher()
    with pytest.raises(ValueError):
        h.hash_password("ValidPass1!", b"x", user_id="shortsalt")


def test_mfa_callback_error_handling(caplog: Any) -> None:
    # Test branch with exception in mfa_callback
    class BadCallback:
        def __call__(self, event: str, user_id: str, metadata: dict[str, Any]) -> None:
            raise RuntimeError("CallbackFail!")

    h = make_hasher(mfa_callback=BadCallback())
    with caplog.at_level(logging.ERROR):
        # Should log error but not crash
        h._fire_mfa(MfaEvent.PASSWORD_VERIFY_SUCCESS, "erruser")
        assert "MFA callback error" in caplog.text


def test_shutdown_without_pool(monkeypatch: Any) -> None:
    from src.security.auth.password import _thread_pool
    import src.security.auth.password as mod

    # Ensure the pool is None
    object.__setattr__(mod, "_thread_pool", None)
    h = make_hasher()
    h.shutdown()  # Should not raise


def test_hash_password_kdf_error(monkeypatch: Any) -> None:
    class BadKDF:
        def hash(self, mix: str) -> str:
            raise RuntimeError("kdf error!")

    h = make_hasher(kdf=BadKDF())
    salt = h.generate_salt()
    with pytest.raises(RuntimeError):
        h.hash_password("ValidPass1!", salt, user_id="badkdf")


def test_verify_password_kdf_error(monkeypatch: Any) -> None:
    class BadKDF:
        def hash(self, mix: str) -> str:
            # Просто возвращаем валидную строку, чтобы не упасть на hash
            return "argon2id$dummy$hash"

        def verify(self, argon_hash: str, mix: str) -> None:
            raise RuntimeError("verify error!")

    h = make_hasher(kdf=BadKDF())
    salt = h.generate_salt()
    # Хеш успешно создаётся
    hashed = h.hash_password("ValidPass1!", salt, user_id="badkdf")
    # Ошибка возникает именно в verify
    assert not h.verify_password("ValidPass1!", hashed, user_id="badkdf")


def test_zeroize_all_secrets() -> None:
    """Test that zeroize_all_secrets clears all sensitive data."""
    hasher = PasswordHasher(pepper=b"test_pepper_secret")

    # Create some data
    salt = hasher.generate_salt()
    hashed = hasher.hash_password("TestPass!123", salt, "user1")

    # Verify it works before zeroize
    assert hasher.verify_password("TestPass!123", hashed, "user1")

    # Track some failed attempts
    hasher._attempts["user1"] = 3

    # Zeroize
    hasher.zeroize_all_secrets()

    # Check pepper is cleared
    assert hasher.pepper is None

    # Check attempts cleared
    assert len(hasher._attempts) == 0


def test_zeroize_with_old_pepper() -> None:
    """Test zeroize clears both current and old pepper."""
    hasher = PasswordHasher(pepper=b"new_pepper")

    # Manually set old pepper using object.__setattr__ (frozen dataclass)
    object.__setattr__(hasher, "pepper_old", b"old_pepper")

    hasher.zeroize_all_secrets()

    assert hasher.pepper is None
    assert hasher.pepper_old is None


def test_hasher_context_manager() -> None:
    """Test using PasswordHasher as context manager."""
    with PasswordHasher(pepper=b"context_pepper") as hasher:
        salt = hasher.generate_salt()
        hashed = hasher.hash_password("CtxPass!123", salt, "ctx_user")
        assert hasher.verify_password("CtxPass!123", hashed, "ctx_user")

    # After exit, should be cleaned up
    assert hasher.pepper is None


def test_zeroize_idempotent() -> None:
    """Test that calling zeroize multiple times is safe."""
    hasher = PasswordHasher(pepper=b"test_pepper")

    hasher.zeroize_all_secrets()
    # Should not raise exception
    hasher.zeroize_all_secrets()

    assert hasher.pepper is None


def test_zeroize_clears_thread_pool() -> None:
    """Test that zeroize also shuts down thread pool."""
    hasher = PasswordHasher(pepper=b"pool_test")

    # Create some work to potentially initialize thread pool
    salt = hasher.generate_salt()
    hasher.hash_password("PoolTest!123", salt, "pool_user")

    # Zeroize should shutdown pool and clear secrets
    hasher.zeroize_all_secrets()

    # Verify secrets are cleared
    assert hasher.pepper is None

    # Shutdown should be idempotent - calling again shouldn't raise
    hasher.shutdown()


def test_hasher_without_pepper() -> None:
    """Test zeroize works even without pepper."""
    hasher = PasswordHasher()  # No pepper

    salt = hasher.generate_salt()
    hashed = hasher.hash_password("Nopepper!123", salt, "no_pepper_user")

    # Should not raise exception
    hasher.zeroize_all_secrets()

    assert hasher.pepper is None
