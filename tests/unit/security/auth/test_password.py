import asyncio
import logging
import os
from types import SimpleNamespace
from typing import Any

import pytest
from src.security.auth.password import (
    MAX_FAILED_ATTEMPTS,
    MfaEvent,
    PasswordHasher,
    is_valid_password,
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
    import src.security.auth.password as mod
    from src.security.auth.password import _thread_pool

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


# ==================== NEW TESTS FOR MISSING COVERAGE ====================


@pytest.mark.security
def test_get_thread_pool_creates_and_reuses() -> None:
    """get_thread_pool создаёт пул при первом вызове и возвращает тот же объект.

    Проверяет двойную проверку с блокировкой (double-checked locking).
    """
    import src.security.auth.password as mod
    from src.security.auth.password import get_thread_pool

    # Arrange: сбросить пул для чистого теста
    with mod._thread_pool_lock:
        mod._thread_pool = None

    # Act: первый вызов создаёт пул
    pool1 = get_thread_pool()
    # Второй вызов должен вернуть тот же объект (ветка "уже создан")
    pool2 = get_thread_pool()

    # Assert
    assert pool1 is pool2
    assert pool1 is not None


@pytest.mark.security
def test_run_with_timeout_success() -> None:
    """run_with_timeout успешно выполняет функцию и возвращает результат.

    Проверяет основной путь без таймаута.
    """
    from src.security.auth.password import run_with_timeout

    # Arrange / Act
    result = run_with_timeout(lambda: 42, timeout=10.0)

    # Assert
    assert result == 42


@pytest.mark.security
def test_run_with_timeout_raises_on_timeout() -> None:
    """run_with_timeout поднимает InternalError при превышении таймаута.

    Проверяет ветку FuturesTimeout → InternalError.
    """
    import time

    from src.security.auth.password import InternalError, run_with_timeout

    # Arrange: функция, которая спит дольше таймаута
    def slow_func() -> int:
        time.sleep(5)
        return 1

    # Act / Assert
    with pytest.raises(InternalError, match="timed out"):
        run_with_timeout(slow_func, timeout=0.05)


@pytest.mark.security
def test_is_valid_password_non_string_returns_false() -> None:
    """is_valid_password возвращает False для не-строкового ввода.

    Проверяет защиту от передачи типа, отличного от str.
    """
    # Arrange / Act / Assert
    assert is_valid_password(12345678) is False  # type: ignore[arg-type]


@pytest.mark.security
def test_is_valid_password_exceeds_dos_limit() -> None:
    """is_valid_password возвращает False для пароля длиннее DOS-лимита.

    Проверяет ветку len(password) > _MAX_INPUT_LENGTH.
    """
    from src.security.auth.password import _MAX_INPUT_LENGTH

    # Arrange: пароль длиннее абсолютного лимита
    huge_password = "A1!" + "x" * (_MAX_INPUT_LENGTH + 1)

    # Act / Assert
    assert is_valid_password(huge_password) is False


@pytest.mark.security
def test_is_valid_password_exceeds_max_length() -> None:
    """is_valid_password возвращает False для пароля длиннее max_length.

    Проверяет ветку not (min_length <= len(password) <= max_length).
    """
    from src.security.auth.password import _MAX_PASSWORD_LENGTH

    # Arrange: пароль на один символ длиннее max_length, но короче DOS-лимита
    long_password = "Aa1!" + "x" * _MAX_PASSWORD_LENGTH

    # Act / Assert
    assert is_valid_password(long_password) is False


@pytest.mark.security
def test_is_valid_password_blacklist_case_insensitive() -> None:
    """is_valid_password возвращает False для пароля из чёрного списка.

    Проверяет регистронезависимую проверку по blacklist.
    """
    # Arrange: пароль, который есть в blacklist в нижнем регистре
    blacklisted = {"badpassword1"}

    # Act / Assert
    assert is_valid_password("BADPASSWORD1", blacklist=blacklisted) is False


@pytest.mark.security
def test_is_valid_password_no_alpha_returns_false() -> None:
    """is_valid_password возвращает False при отсутствии буквенных символов.

    Проверяет ветку not any(c.isalpha() for c in password).
    """
    # Arrange: пароль из цифр и спецсимволов без букв
    no_alpha = "12345678!@#$%^&*"

    # Act / Assert
    assert is_valid_password(no_alpha) is False


@pytest.mark.security
def test_get_pepper_only_current_no_old() -> None:
    """get_pepper возвращает текущий pepper и None при отсутствии старого.

    Проверяет ветку без .old переменной окружения.
    """
    import os

    from src.security.auth.password import _PEPPER_ENV_VAR, get_pepper

    # Arrange
    os.environ[_PEPPER_ENV_VAR] = "currentpepper"
    os.environ.pop(_PEPPER_ENV_VAR + ".old", None)

    try:
        # Act
        current, old = get_pepper()

        # Assert
        assert current == b"currentpepper"
        assert old is None
    finally:
        del os.environ[_PEPPER_ENV_VAR]


@pytest.mark.security
def test_get_pepper_returns_none_when_not_set() -> None:
    """get_pepper возвращает (None, None) если переменная окружения не задана.

    Проверяет ветку v is None → return None, None.
    """
    import os

    from src.security.auth.password import _PEPPER_ENV_VAR, get_pepper

    # Arrange: убедиться, что переменная не задана
    os.environ.pop(_PEPPER_ENV_VAR, None)
    os.environ.pop(_PEPPER_ENV_VAR + ".old", None)

    # Act
    current, old = get_pepper()

    # Assert
    assert current is None
    assert old is None


@pytest.mark.security
def test_zero_memory_readonly_memoryview_no_error() -> None:
    """zero_memory не падает при попытке обнулить неизменяемый memoryview.

    Проверяет ветку memoryview с readonly=True — исключение перехватывается.
    """
    from src.security.auth.password import zero_memory

    # Arrange: bytes создаёт readonly memoryview
    data = b"secret"
    mv = memoryview(data)
    assert mv.readonly

    # Act / Assert: не должно бросить исключение
    zero_memory(mv)


@pytest.mark.security
def test_zero_memory_writable_memoryview() -> None:
    """zero_memory обнуляет writable memoryview.

    Проверяет ветку memoryview and not buf.readonly → обнуление.
    """
    from src.security.auth.password import zero_memory

    # Arrange: bytearray создаёт writable memoryview
    ba = bytearray(b"topsecret")
    mv = memoryview(ba)
    assert not mv.readonly

    # Act
    zero_memory(mv)

    # Assert
    assert all(b == 0 for b in ba)


@pytest.mark.security
def test_require_pepper_raises_when_missing() -> None:
    """PasswordHasher с require_pepper=True бросает PolicyViolation без pepper.

    Проверяет ветку require_pepper and pepper is None → PolicyViolation.
    """
    from src.security.auth.password import PolicyViolation

    # Arrange / Act / Assert
    with pytest.raises(PolicyViolation, match="Pepper is required"):
        PasswordHasher(require_pepper=True, pepper=None)


@pytest.mark.security
def test_mix_password_too_long_raises_policy_violation() -> None:
    """_mix_password бросает PolicyViolation для слишком длинного пароля.

    Проверяет ветку len(password) > _MAX_INPUT_LENGTH внутри _mix_password.
    """
    from src.security.auth.password import _MAX_INPUT_LENGTH, PolicyViolation

    # Arrange
    h = make_hasher()
    huge_password = "x" * (_MAX_INPUT_LENGTH + 1)
    salt = h.generate_salt()

    # Act / Assert
    with pytest.raises(PolicyViolation, match="too long"):
        h._mix_password(huge_password, salt)


@pytest.mark.security
def test_accept_pepper_old_no_rotated_at_returns_true() -> None:
    """_accept_pepper_old возвращает True если pepper_old задан и нет временной метки ротации.

    Проверяет ветку pepper_old is set, pepper_rotated_at is None → True.
    """
    from datetime import timezone

    # Arrange: задать old pepper явно, убрать временную метку ротации
    h = PasswordHasher(
        pepper=b"new",
        pepper_old=b"old",
        pepper_rotated_at=None,
    )
    # Убрать автоматически выставленную метку ротации
    object.__setattr__(h, "pepper_rotated_at", None)

    # Act
    result = h._accept_pepper_old()

    # Assert
    assert result is True


@pytest.mark.security
def test_accept_pepper_old_expired_rotation_returns_false() -> None:
    """_accept_pepper_old возвращает False если срок ротации истёк.

    Проверяет ветку _now() - pepper_rotated_at > timedelta(days=...) → False.
    """
    from datetime import datetime, timedelta, timezone

    # Arrange: ротация была 60 дней назад, лимит 30 дней
    old_rotation = datetime.now(timezone.utc) - timedelta(days=60)
    h = PasswordHasher(
        pepper=b"new",
        pepper_old=b"old",
        pepper_rotation_days=30,
    )
    object.__setattr__(h, "pepper_rotated_at", old_rotation)

    # Act
    result = h._accept_pepper_old()

    # Assert
    assert result is False


@pytest.mark.security
def test_needs_rehash_invalid_hash_returns_true() -> None:
    """needs_rehash возвращает True для некорректной хеш-строки.

    Проверяет ветку except InvalidHashFormat → return True.
    """
    # Arrange
    h = make_hasher()

    # Act
    result = h.needs_rehash("not_a_valid_hash_at_all", user_id="user")

    # Assert
    assert result is True


@pytest.mark.security
def test_needs_rehash_internal_error_returns_true() -> None:
    """needs_rehash возвращает True при внутренней ошибке KDF.

    Проверяет ветку except Exception → return True (conservative).
    """

    # Arrange: KDF.check_needs_rehash бросает неожиданное исключение
    class BrokenKDF:
        def hash(self, mix: str) -> str:
            return "argon2id$stub$stub"

        def verify(self, h: str, m: str) -> None:
            pass

        def check_needs_rehash(self, argon_hash: str) -> bool:
            raise RuntimeError("KDF exploded")

    h = make_hasher(kdf=BrokenKDF())
    pw = "ValidPass1!"
    salt = h.generate_salt()
    hashed = h.hash_password(pw, salt, user_id="brkd")

    # Act
    result = h.needs_rehash(hashed, user_id="brkd")

    # Assert
    assert result is True


@pytest.mark.security
def test_update_password_fails_wrong_password() -> None:
    """update_password бросает PolicyViolation при неверном текущем пароле.

    Проверяет ветку verify_password → False → PolicyViolation.
    """
    from src.security.auth.password import PolicyViolation

    # Arrange
    h = make_hasher()
    pw = "CorrectPass1!"
    hashed = h.hash_password(pw, h.generate_salt(), user_id="upd")

    # Act / Assert
    with pytest.raises(PolicyViolation, match="verification failed"):
        h.update_password("WrongPass1!", hashed, user_id="upd")


@pytest.mark.security
def test_update_password_no_rehash_returns_same_hash() -> None:
    """update_password возвращает тот же хеш если rehash не нужен.

    Проверяет ветку needs_rehash → False → return hashed.
    """

    # Arrange: KDF.check_needs_rehash всегда возвращает False
    class StableKDF:
        def hash(self, mix: str) -> str:
            from argon2 import PasswordHasher as _A2

            return _A2(time_cost=2, memory_cost=65536, parallelism=2).hash(mix)

        def verify(self, argon_hash: str, mix: str) -> None:
            from argon2 import PasswordHasher as _A2

            _A2().verify(argon_hash, mix)

        def check_needs_rehash(self, argon_hash: str) -> bool:
            return False

    h = make_hasher(kdf=StableKDF())
    pw = "StablePass1!"
    hashed = h.hash_password(pw, h.generate_salt(), user_id="stable")

    # Act
    result = h.update_password(pw, hashed, user_id="stable")

    # Assert: хеш не изменился
    assert result == hashed


@pytest.mark.security
def test_async_update_password() -> None:
    """update_password_async корректно оборачивает синхронную версию.

    Проверяет ветки update_password_async (строки 513-516).
    """

    # Arrange
    h = make_hasher()
    pw = "AsyncUpdate1!"
    hashed = h.hash_password(pw, h.generate_salt(), user_id="asyncupd")

    async def run() -> str:
        return await h.update_password_async(pw, hashed, user_id="asyncupd")

    # Act
    new_hash = asyncio.run(run())

    # Assert
    assert isinstance(new_hash, str)
    assert h.verify_password(pw, new_hash, user_id="asyncupd")


@pytest.mark.security
def test_static_is_valid_password_method() -> None:
    """PasswordHasher.is_valid_password корректно делегирует в модульную функцию.

    Проверяет строку 521 — статический метод с внутренним blacklist.
    """
    # Arrange / Act / Assert
    assert PasswordHasher.is_valid_password("GoodPass1!") is True
    assert PasswordHasher.is_valid_password("password") is False


@pytest.mark.security
def test_export_policy_non_deterministic() -> None:
    """export_policy(deterministic=False) возвращает обычный dict, не OrderedDict.

    Проверяет ветку deterministic=False → return data (строка 550).
    """
    from collections import OrderedDict

    # Arrange
    h = make_hasher()

    # Act
    policy = h.export_policy(deterministic=False)

    # Assert: обычный dict, а не OrderedDict
    assert isinstance(policy, dict)
    assert not isinstance(policy, OrderedDict)
    assert "algo" in policy


@pytest.mark.security
def test_export_audit_non_deterministic() -> None:
    """export_audit(deterministic=False) возвращает обычный dict.

    Проверяет ветку deterministic=False внутри export_audit (строка 561).
    """
    from collections import OrderedDict

    # Arrange
    h = make_hasher()

    # Act
    audit = h.export_audit("u42", deterministic=False)

    # Assert: обычный dict
    assert isinstance(audit, dict)
    assert not isinstance(audit, OrderedDict)
    assert audit["user_id"] == "u42"


@pytest.mark.security
def test_rate_limited_blocks_duplicate_event() -> None:
    """_rate_limited возвращает True при повторном вызове в пределах лимита.

    Проверяет ветку now_ts - last < _MFA_RATE_LIMIT_SEC → True.
    """
    from src.security.auth.password import _rate_limited

    # Arrange: первый вызов — регистрирует событие
    result_first = _rate_limited("rateuser", "test_event")

    # Act: второй вызов немедленно — должен быть заблокирован
    result_second = _rate_limited("rateuser", "test_event")

    # Assert
    assert result_first is False  # первый вызов не блокируется
    assert result_second is True  # второй блокируется


@pytest.mark.security
def test_verify_password_track_attempts_false_no_lockout() -> None:
    """verify_password с track_attempts=False не накапливает попытки и не блокирует.

    Проверяет ветку track_attempts=False при неверном пароле.
    """
    # Arrange
    h = make_hasher()
    pw = "TrackOff1!"
    hashed = h.hash_password(pw, h.generate_salt(), user_id="notrack")

    # Act: намеренно много неверных попыток без трекинга
    for _ in range(MAX_FAILED_ATTEMPTS + 5):
        result = h.verify_password("BadPass1!", hashed, user_id="notrack", track_attempts=False)
        assert result is False

    # Assert: после этого правильный пароль всё ещё работает
    assert h.verify_password(pw, hashed, user_id="notrack", track_attempts=False) is True


@pytest.mark.security
def test_verify_password_lockout_returns_false_not_raises() -> None:
    """verify_password возвращает False (не исключение) при lockout без track_attempts.

    Проверяет строки 396-403: заблокированный user_id возвращает False.
    """
    # Arrange: вручную выставить количество попыток выше лимита
    h = make_hasher()
    pw = "LockCheck1!"
    hashed = h.hash_password(pw, h.generate_salt(), user_id="lockchk")
    h._attempts["lockchk"] = MAX_FAILED_ATTEMPTS

    # Act: с track_attempts=True — возврат False, не исключение
    result = h.verify_password("any", hashed, user_id="lockchk", track_attempts=True)

    # Assert
    assert result is False


@pytest.mark.security
def test_verify_password_succeeds_after_reset_attempts() -> None:
    """reset_attempts снимает блокировку и позволяет успешную аутентификацию.

    Проверяет взаимодействие reset_attempts + verify_password (строки 424-426).
    """
    # Arrange
    h = make_hasher()
    pw = "ResetMe1!"
    hashed = h.hash_password(pw, h.generate_salt(), user_id="rst")
    h._attempts["rst"] = MAX_FAILED_ATTEMPTS  # заблокировать вручную

    # Act
    h.reset_attempts("rst")
    result = h.verify_password(pw, hashed, user_id="rst")

    # Assert
    assert result is True


@pytest.mark.security
def test_parse_hash_non_string_raises_invalid_format() -> None:
    """_parse_hash бросает InvalidHashFormat для не-строкового значения.

    Проверяет ветку not isinstance(hashed, str) (строки 311-316).
    """
    from src.security.auth.password import InvalidHashFormat

    # Arrange
    h = make_hasher()

    # Act / Assert
    with pytest.raises(InvalidHashFormat):
        h._parse_hash(None)  # type: ignore[arg-type]


@pytest.mark.security
def test_generate_salt_too_short_raises() -> None:
    """generate_salt бросает PolicyViolation для длины < 8.

    Проверяет ветку length < 8 (строка 336).
    """
    from src.security.auth.password import PolicyViolation

    # Arrange
    h = make_hasher()

    # Act / Assert
    with pytest.raises(PolicyViolation, match="Salt length"):
        h.generate_salt(length=4)


@pytest.mark.security
def test_hash_password_auto_generates_salt() -> None:
    """hash_password без явно переданной соли генерирует соль автоматически.

    Проверяет ветку salt is None → salt = self.generate_salt() (строки 353-354).
    """
    # Arrange
    h = make_hasher()
    pw = "AutoSalt1!"

    # Act: передаём salt=None явно
    hashed = h.hash_password(pw, salt=None, user_id="autosalt")

    # Assert: хеш корректен
    assert isinstance(hashed, str)
    assert h.verify_password(pw, hashed, user_id="autosalt")


@pytest.mark.security
def test_fire_mfa_skips_when_rate_limited() -> None:
    """_fire_mfa не вызывает callback при rate limiting.

    Проверяет ветку _rate_limited → True → return (строка 293).
    """
    import time

    from src.security.auth.password import _MFA_RATE_LIMIT_SEC, _last_mfa_emit, _last_mfa_lock

    # Arrange: заставить rate limiter считать, что событие только что было отправлено
    spy = MfaSpy()
    h = make_hasher(mfa_callback=spy)

    # Выставляем временную метку "прямо сейчас" для конкретного события
    key = ("ratelimiteduser", MfaEvent.PASSWORD_HASHED)
    with _last_mfa_lock:
        _last_mfa_emit[key] = time.time()

    # Act: fire должен быть пропущен
    h._fire_mfa(MfaEvent.PASSWORD_HASHED, "ratelimiteduser")

    # Assert: callback не был вызван
    assert len(spy.events) == 0
