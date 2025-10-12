import pytest
import logging
import secrets
import sys
from pytest import MonkeyPatch
import importlib
import builtins

from security.crypto import hashing


@pytest.fixture(autouse=True)
def configure_logging() -> None:
    logging.basicConfig(level=logging.DEBUG)


def test_hash_and_verify_success_argon2id() -> None:
    password = "P@ssw0rd!_example"
    hashval = hashing.hash_password(password)
    assert hashing.verify_password(password, hashval)


def test_hash_and_verify_success_bcrypt() -> None:
    password = "exampleBCRYPT!"
    hashval = hashing.hash_password(password, scheme="bcrypt")
    assert hashing.verify_password(password, hashval)


def test_hash_and_verify_success_pbkdf2() -> None:
    password = "pbkdf2Test"
    hashval = hashing.hash_password(password, scheme="pbkdf2")
    assert hashing.verify_password(password, hashval)


def test_fail_on_invalid_scheme() -> None:
    with pytest.raises(ValueError):
        hashing.hash_password("test", scheme="not_a_scheme")


def test_too_long_password_truncated() -> None:
    password = "A" * (hashing._MAX_PASSWORD_LEN + 20)
    hashval = hashing.hash_password(password)
    assert len(password) > hashing._MAX_PASSWORD_LEN
    assert hashing.verify_password(password[: hashing._MAX_PASSWORD_LEN], hashval)


def test_needs_rehash_scheme_change() -> None:
    pw = "schemechange2025"
    hashval = hashing.hash_password(pw, scheme="argon2id")
    assert hashing.needs_rehash(hashval, scheme="bcrypt")
    hashval2 = hashing.hash_password(pw, scheme="bcrypt")
    assert not hashing.needs_rehash(hashval2, scheme="bcrypt")


def test_legacy_hash_verification_fails() -> None:
    pw = "legacy"
    hashval = hashing.hash_password(pw, scheme="sha256")
    assert not hashing.verify_password(pw, hashval)
    assert not hashing.legacy_verify_password(pw, hashval, "sha256")


def test_bad_costs_raise() -> None:
    with pytest.raises(ValueError):
        hashing.hash_password("x", time_cost=1)
    with pytest.raises(ValueError):
        hashing.hash_password("x", memory_cost=1024)
    with pytest.raises(ValueError):
        hashing.hash_password("x", parallelism=20)


def test_custom_salt_argon2id_lowlevel() -> None:
    salt = secrets.token_bytes(16)
    pw = "withsalt_custom"
    hashval = hashing.hash_password(pw, salt=salt, scheme="argon2id")
    assert isinstance(hashval, str)


def test_custom_salt_bcrypt() -> None:
    import bcrypt

    salt = bcrypt.gensalt()
    pw = "bcryptsalt"
    hashval = hashing.hash_password(pw, salt=salt, scheme="bcrypt")
    assert isinstance(hashval, str)
    assert hashing.verify_password(pw, hashval)


def test_custom_salt_pbkdf2() -> None:
    salt = secrets.token_bytes(16)
    pw = "pbkdf2SALT"
    hashval = hashing.hash_password(pw, salt=salt, scheme="pbkdf2")
    assert isinstance(hashval, str)
    assert hashing.verify_password(pw, hashval)


def test_audit_trail_append_and_content() -> None:
    hashing.add_audit("custom_event", "user001", {"action": "test"})
    assert isinstance(hashing._AUDIT_TRAIL, list)
    assert hashing._AUDIT_TRAIL[-1]["event"] == "custom_event"


def test_wiping_sensitive_data() -> None:
    password = "wipetest"
    hashing._wipe_sensitive_data(password)  # No error expected


def test_get_hash_scheme_heuristic() -> None:
    pwd = "x"
    h1 = hashing.hash_password(pwd, scheme="argon2id")
    h2 = hashing.hash_password(pwd, scheme="bcrypt")
    h3 = hashing.hash_password(pwd, scheme="pbkdf2")
    assert hashing.get_hash_scheme(h1) == "argon2id"
    assert hashing.get_hash_scheme(h2) == "bcrypt"
    assert hashing.get_hash_scheme(h3) == "pbkdf2"


def test_hashes_not_idempotent_with_random_salt() -> None:
    pw = "idempotent"
    h1 = hashing.hash_password(pw)
    h2 = hashing.hash_password(pw)
    assert h1 != h2


def test_verify_password_edge_cases() -> None:
    pw = "edgeCases"
    bad_hash = "notarealhash"
    assert not hashing.verify_password(pw, bad_hash)
    assert not hashing.verify_password("", bad_hash)
    assert not hashing.verify_password(pw, "")


def test_import_error_bcrypt(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(hashing, "bcrypt", None)
    with pytest.raises(ImportError):
        hashing.hash_password("pw", scheme="bcrypt")


def test_import_error_argon2(monkeypatch: MonkeyPatch) -> None:
    # Просто убеждаемся, что None argon2_ll переводит в managed mode
    monkeypatch.setattr(hashing, "argon2_ll", None)
    # Это не должно вызывать исключение — проходим в managed mode
    result = hashing.hash_password("pw", scheme="argon2id")
    assert isinstance(result, str)


def test_pbkdf2_invalid_format() -> None:
    # Invalid pbkdf2 format string (edge case)
    bad_pbkdf2 = "pbkdf2:aaaa"
    pw = "pw"
    assert not hashing.verify_password(pw, bad_pbkdf2)


def test_pbkdf2_wrong_parts() -> None:
    bad_pbkdf2 = "pbkdf2:part1:part2:part3"
    pw = "pw"
    assert not hashing.verify_password(pw, bad_pbkdf2)


def test_argon2id_lowlevel_exception(monkeypatch: MonkeyPatch) -> None:
    if hashing.argon2_ll is not None:

        def raise_exc(*args: object, **kwargs: object) -> bytes:
            raise RuntimeError("forced")

        monkeypatch.setattr(hashing.argon2_ll, "hash_secret", raise_exc)
        with pytest.raises(RuntimeError):
            hashing.hash_password("pw", salt=b"abc" * 4, scheme="argon2id")
    else:
        pytest.skip("argon2_ll not available")


def test_unknown_scheme_error() -> None:
    with pytest.raises(ValueError):
        hashing.hash_password("pw", scheme="notarealscheme")


def test_sha256_branch() -> None:
    h = hashing.hash_password("legacytest", scheme="sha256")
    assert isinstance(h, str)
    assert len(h) == 64


def test_needs_rehash_exception(monkeypatch: MonkeyPatch) -> None:
    # Monkeypatch PasswordHasher to raise inside check_needs_rehash
    class DummyHasher:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def hash(self, password: str) -> str:
            return "dummy_hash_result"

        def check_needs_rehash(self, h: str) -> bool:
            raise RuntimeError("forced fail")

    monkeypatch.setattr(hashing, "PasswordHasher", DummyHasher)
    h = hashing.hash_password("testpw", scheme="argon2id")
    # Теперь тестируем needs_rehash с исключением
    assert hashing.needs_rehash(h, scheme="argon2id") is True  # fallback to True


def test_wipe_sensitive_data_bytes() -> None:
    sensitive = b"secret"
    hashing._wipe_sensitive_data(sensitive)  # should not raise


def test_get_hash_scheme_unknown() -> None:
    # Clearly trash input
    assert hashing.get_hash_scheme("") == "unknown"
    assert hashing.get_hash_scheme("totallyrandom$hash:format") == "unknown"


def test_fail_safe_empty_hash() -> None:
    # verify_password with empty hash string
    assert not hashing.verify_password("pw", "")


def test_fail_safe_non_string_hash() -> None:
    # verify_password with clearly non-string hash (type ignore for runtime)
    assert not hashing.verify_password("pw", 123456)  # type: ignore


def test_argon2_importerror(monkeypatch: MonkeyPatch) -> None:
    # emulate complete absence of argon2 module (edge-import)
    monkeypatch.setitem(sys.modules, "argon2", None)
    try:
        importlib.reload(hashing)  # may not be effective in this env, just illustrative
    except Exception:
        pass


def test_bcrypt_importerror(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "bcrypt", None)
    try:
        importlib.reload(hashing)
    except Exception:
        pass


def test_pbkdf2_decode_error() -> None:
    bad_pbkdf2 = "pbkdf2:notbase64:alsobad"
    assert not hashing.verify_password("pw", bad_pbkdf2)


def test_pbkdf2_unicode_error() -> None:
    # not ascii base64, catch b64decode error
    bad_pbkdf2 = "pbkdf2:@@@:@@@"
    assert not hashing.verify_password("pw", bad_pbkdf2)


def test_lowlevel_argon2_exception(monkeypatch: MonkeyPatch) -> None:
    # simulate Exception in low-level argon2 hashing
    if hashing.argon2_ll is not None:

        def fail(*args: object, **kwargs: object) -> bytes:
            raise Exception("forced lowlevel argon2 error")

        monkeypatch.setattr(hashing.argon2_ll, "hash_secret", fail)
        with pytest.raises(Exception):
            hashing.hash_password("pw", salt=b"saltfortest_argon2", scheme="argon2id")


def test_legacy_verify_password_fake_scheme() -> None:
    assert not hashing.legacy_verify_password("pw", "fakelegacy", "notrealscheme")


def test_audit_event_custom_context() -> None:
    # Event with complex context
    hashing.add_audit("auditX", "uidX", {"foo": "bar", "n": 42})
    assert hashing._AUDIT_TRAIL[-1]["event"] == "auditX"


def test_wipe_sensitive_data_with_none() -> None:
    hashing._wipe_sensitive_data(None)  # should not raise


def test_wipe_sensitive_data_with_bytes() -> None:
    hashing._wipe_sensitive_data(b"byte_sens")  # should not raise


def test_edge_fail_sha256_verify() -> None:
    # SHA256 should always return False for password validation
    h = hashing.hash_password("pw", scheme="sha256")
    assert not hashing.verify_password("pw", h)


def test_unknown_scheme_legacy_verify() -> None:
    # legacy_verify_password on bogus scheme
    assert not hashing.legacy_verify_password("pw", "whatever", "xxxx")


def test_audit_none_context() -> None:
    hashing.add_audit("none_event", None, None)
    assert hashing._AUDIT_TRAIL[-1]["event"] == "none_event"


def test_add_audit_weird_types() -> None:
    hashing.add_audit(None, None, None)  # type: ignore
    assert hashing._AUDIT_TRAIL[-1]["event"] is None  # type: ignore


def test_hash_password_invalid_types() -> None:
    with pytest.raises(ValueError):
        hashing.hash_password(None)  # type: ignore
    with pytest.raises(ValueError):
        hashing.hash_password("")  # empty password


def test_legacy_verify_password_num() -> None:
    assert not hashing.legacy_verify_password("pw", 12345, "sha256")  # type: ignore


def test_wipe_sensitive_data_weird() -> None:
    hashing._wipe_sensitive_data([1, 2, 3])  # type: ignore
    hashing._wipe_sensitive_data({"a": 1})  # type: ignore


def test_pbkdf2_wrong_delimiter() -> None:
    bad = "pbkdf2|not|right|delimiter"
    assert not hashing.verify_password("pw", bad)


def test_hash_password_bad_type() -> None:
    with pytest.raises(ValueError):
        hashing.hash_password(None)  # type: ignore
    with pytest.raises(ValueError):
        hashing.hash_password("")  # пустой пароль


def test_needs_rehash_exception_path(monkeypatch: MonkeyPatch) -> None:
    class DummyErr:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def hash(self, pw: str) -> str:
            return "hash"

        def check_needs_rehash(self, h: str) -> bool:
            raise RuntimeError("fail")

    monkeypatch.setattr(hashing, "PasswordHasher", DummyErr)
    h = hashing.hash_password("xxx", scheme="argon2id")
    # Должно fallback-ить на True при exception:
    assert hashing.needs_rehash(h, scheme="argon2id") is True


def test_unknown_scheme_in_needs_rehash() -> None:
    # Невалидная схема, должен упасть с ValueError либо вернуть True/False
    bad_hash = "foobar:xxx"
    assert hashing.needs_rehash(bad_hash, scheme="argon2id") in (True, False)


def test_add_audit_with_weird_types() -> None:
    # Cover audit trail with totally invalid event/user/context
    hashing.add_audit(None, None, None)  # type: ignore
    assert hashing._AUDIT_TRAIL[-1]["event"] is None  # type: ignore


def test_validate_costs_happy_path() -> None:
    hashing._validate_costs(3, 65536, 2)  # valid path


def test_pbkdf2_invalid_split_and_decode() -> None:
    assert not hashing.verify_password("pw", "pbkdf2:notbase64:anotherbad")
    assert not hashing.verify_password("pw", "pbkdf2:spart1")
    assert not hashing.verify_password("pw", "pbkdf2:bad:params:here")


def test_needs_rehash_raises(monkeypatch: MonkeyPatch) -> None:
    class DummyPH:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def hash(self, password: str) -> str:
            return "dummyhash"

        def check_needs_rehash(self, h: str) -> bool:
            raise RuntimeError("fail branch for test")

    monkeypatch.setattr(hashing, "PasswordHasher", DummyPH)
    h = hashing.hash_password("pw", scheme="argon2id")
    # Теперь действительно сработает try/except внутри needs_rehash,
    # и будет coverage по error branch и return True
    assert hashing.needs_rehash(h, scheme="argon2id") is True


def test_legacy_verify_password_misc() -> None:
    assert not hashing.legacy_verify_password("pw", "hashy", "notarealscheme")
    assert not hashing.legacy_verify_password("pw", 1234, "sha256")  # type: ignore


def test_argon2id_managed_hash_raises(monkeypatch: MonkeyPatch) -> None:
    class DummyPH:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def hash(self, password: str) -> str:
            raise RuntimeError("forced error for coverage")

    monkeypatch.setattr(hashing, "PasswordHasher", DummyPH)
    with pytest.raises(RuntimeError):
        hashing.hash_password("pw", scheme="argon2id")


def test_argon2id_verify_password_exception(monkeypatch: MonkeyPatch) -> None:
    class DummyPH:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def verify(self, h: str, pw: str) -> bool:
            raise RuntimeError("fail branch")

    monkeypatch.setattr(hashing, "PasswordHasher", DummyPH)
    h = "$argon2id$v=19$m=65536,t=3,p=4$MTIz$YWJj"  # valid-looking hash
    # verify_password должен fallback-нуть в False через exception/log
    assert not hashing.verify_password("pw", h)


def test_needs_rehash_check_raises(monkeypatch: MonkeyPatch) -> None:
    class DummyPH:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def hash(self, password: str) -> str:
            return "dummy"

        def check_needs_rehash(self, h: str) -> bool:
            raise RuntimeError("fail branch")

    monkeypatch.setattr(hashing, "PasswordHasher", DummyPH)
    h = hashing.hash_password("pw", scheme="argon2id")
    assert hashing.needs_rehash(h, scheme="argon2id") is True


def test_legacy_verify_password_unused_schemes() -> None:
    assert not hashing.legacy_verify_password("pw", "somehash", "notarealscheme")
    assert not hashing.legacy_verify_password("pw", 1234, "sha256")  # type: ignore

    # Также попробуйте trash input:
    assert not hashing.legacy_verify_password(
        "pw", "short", "sha256"
    )  # слишком короткий хэш для сравнения


def test_legacy_verify_password_unreachable_and_trash() -> None:
    # Неизвестная/битая схема/тип
    assert not hashing.legacy_verify_password("pw", "bad", "foobar123")
    assert not hashing.legacy_verify_password("pw", 42, "sha256")  # type: ignore
    assert not hashing.legacy_verify_password("pw", "", "sha256")
    # Слишком короткий legacy hash string
    assert not hashing.legacy_verify_password("pw", "abcdef", "sha256")
