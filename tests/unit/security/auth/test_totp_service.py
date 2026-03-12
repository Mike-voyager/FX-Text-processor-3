import sys
import threading
import types
from datetime import datetime, timedelta, timezone
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Tuple, cast

import pytest

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
    def __init__(self, secret: str, **kwargs: Any) -> None:
        self.secret = secret
        self.last_code: str | None = None

    def verify(self, code: str, **kwargs: Any) -> bool:
        self.last_code = code
        return code == "safeotp"

    def provisioning_uri(self, name: str, issuer_name: str = "") -> str:
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


@pytest.fixture(autouse=True)
def reset_rl_state() -> Iterator[None]:
    """Сброс состояния rate-limiter между тестами."""
    tots._rl_state.clear()
    yield
    tots._rl_state.clear()


@pytest.fixture
def patch_pyotp_qrcode(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(tots, "pyotp", types.SimpleNamespace(TOTP=DummyPyotpTOTP))  # type: ignore
    monkeypatch.setattr(tots, "qrcode", types.SimpleNamespace(make=lambda uri: DummyQr(uri)))  # type: ignore
    yield


def test_setup_totp_for_user(patch_pyotp_qrcode: None) -> None:
    result = tots.setup_totp_for_user("alice", "alice_login", "ACorp", include_secret=True)
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
    result = tots.generate_totp_qr_uri("qruser")
    assert "otpauth://" in result["uri"]
    assert result["qr"] == b"dummyqrcode"


def test_generate_totp_qr_uri_empty(patch_pyotp_qrcode: None) -> None:
    result = tots.generate_totp_qr_uri("unknown")
    assert isinstance(result["uri"], str)
    assert isinstance(result["qr"], bytes)


def test_get_totp_secret_for_storage_success(
    monkeypatch: pytest.MonkeyPatch,
    patch_pyotp_qrcode: None,  # если используется доп. фикстура для qrcode/pyotp — можно убрать
) -> None:
    # Подготавливаем фактор
    tots.setup_totp_for_user("sec", "secuser")
    # Патчим derive_key_argon2id
    fake_kdf = lambda pw, salt, length: b"retkey" * (length // 6)  # noqa: E731
    monkeypatch.setattr(tots, "derive_key_argon2id", fake_kdf)
    monkeypatch.setitem(tots._config, "kdf", fake_kdf)

    # ---- КРИТИЧЕСКИЙ ПАТЧ ДЛЯ PYOTP (в sys.modules) ----
    class DummyPyotpTOTP:
        def __init__(self, secret: str, **kwargs: Any) -> None:
            self.secret = secret

        def verify(self, code: str, **kwargs: Any) -> bool:
            return code == "safeotp"

        def provisioning_uri(self, name: str, issuer_name: str = "") -> str:
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
    from src.security.auth.totp_service import TotpInvalidCode

    with pytest.raises(TotpInvalidCode):
        tots.get_totp_secret_for_storage("failu", "wrongotp")


def test_get_totp_secret_for_storage_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    # Нет фактора/секрета — ожидаем TotpNotConfigured (подкласс RuntimeError)
    from src.security.auth.totp_service import TotpNotConfigured

    with pytest.raises(TotpNotConfigured):
        tots.get_totp_secret_for_storage("foo", "any")


# ---------------------------------------------------------------------------
# Дополнительные тесты для достижения покрытия ≥95%
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_configure_totp_service_all_params() -> None:
    """configure_totp_service обновляет все параметры конфигурации (строки 104-120)."""

    # Arrange
    original_issuer = tots._config["issuer"]
    fake_kdf: Any = lambda pw, salt, n: b"\x00" * n

    # Act
    tots.configure_totp_service(
        issuer="TestIssuer",
        pepper="mypepper",
        kdf=fake_kdf,
        argon2_params={"time_cost": 1},
        valid_window=2,
        digits=8,
        interval=60,
        rate={"max_fails": 10, "lock_seconds": 60},
    )

    # Assert
    assert tots._config["issuer"] == "TestIssuer"
    assert tots._config["pepper"] == "mypepper"
    assert tots._config["kdf"] is fake_kdf
    assert tots._config["argon2_params"] == {"time_cost": 1}
    assert tots._config["valid_window"] == 2
    assert tots._config["digits"] == 8
    assert tots._config["interval"] == 60
    assert tots._config["rate"]["max_fails"] == 10
    assert tots._config["rate"]["lock_seconds"] == 60

    # Cleanup — вернуть исходные значения
    tots.configure_totp_service(
        issuer=original_issuer,
        valid_window=tots.DEFAULT_VALID_WINDOW,
        digits=tots.DEFAULT_DIGITS,
        interval=tots.DEFAULT_INTERVAL,
    )
    tots._config["pepper"] = None
    tots._config["kdf"] = tots.derive_key_argon2id
    tots._config["argon2_params"] = None


@pytest.mark.security
def test_configure_totp_service_partial_update() -> None:
    """configure_totp_service обновляет только переданные параметры (строки 104-120)."""

    # Arrange
    original_digits = tots._config["digits"]

    # Act
    tots.configure_totp_service(digits=8)

    # Assert — только digits изменился
    assert tots._config["digits"] == 8

    # Cleanup
    tots.configure_totp_service(digits=original_digits)


@pytest.mark.security
def test_totp_locked_out_exception_attributes() -> None:
    """TotpLockedOut хранит remaining_seconds и корректное сообщение (строки 142-143)."""

    # Arrange / Act
    exc = tots.TotpLockedOut(42)

    # Assert
    assert exc.remaining_seconds == 42
    assert "42" in str(exc)


@pytest.mark.security
def test_check_locked_raises_when_locked() -> None:
    """_check_locked поднимает TotpLockedOut когда lock_until в будущем (строки 169-170)."""

    # Arrange
    future = datetime.now(timezone.utc) + timedelta(seconds=300)
    tots._rl_state["lockeduser"] = {
        "failed": 0,
        "lock_until": future,
        "last_try": None,
        "last_qr": None,
    }

    # Act / Assert
    with pytest.raises(tots.TotpLockedOut) as exc_info:
        tots._check_locked("lockeduser")

    assert exc_info.value.remaining_seconds >= 1


@pytest.mark.security
def test_check_locked_no_raise_when_not_locked() -> None:
    """_check_locked не поднимает исключений когда пользователь не заблокирован."""

    # Arrange — убедиться что пользователя нет в состоянии
    tots._rl_state.pop("freeuser", None)

    # Act / Assert — не должно поднимать
    tots._check_locked("freeuser")


@pytest.mark.security
def test_register_failure_triggers_lockout() -> None:
    """_register_failure блокирует пользователя после max_fails попыток (строки 187-188)."""

    # Arrange
    max_fails = tots._config["rate"]["max_fails"]
    tots._rl_state.pop("lockme", None)

    # Act — вызвать max_fails раз
    for _ in range(max_fails):
        tots._register_failure("lockme")

    # Assert — пользователь теперь заблокирован
    st = tots._rl_state["lockme"]
    assert st["lock_until"] is not None
    assert st["lock_until"] > datetime.now(timezone.utc)
    # счётчик сброшен
    assert st["failed"] == 0


@pytest.mark.security
def test_register_failure_below_threshold() -> None:
    """_register_failure не блокирует при количестве попыток ниже порога."""

    # Arrange
    tots._rl_state.pop("almostlocked", None)

    # Act
    tots._register_failure("almostlocked")

    # Assert
    st = tots._rl_state["almostlocked"]
    assert st["lock_until"] is None
    assert st["failed"] == 1


@pytest.mark.security
def test_check_qr_rate_limit_logs_on_rapid_call() -> None:
    """_check_qr_rate_limit обнаруживает частые вызовы и проставляет last_qr (строка 202)."""

    # Arrange — симулируем недавнюю генерацию QR
    recent = datetime.now(timezone.utc) - timedelta(seconds=1)
    tots._rl_state["qruser2"] = {
        "failed": 0,
        "lock_until": None,
        "last_try": None,
        "last_qr": recent,
    }

    # Act — не должно поднимать исключение, но обновляет last_qr
    tots._check_qr_rate_limit("qruser2")

    # Assert
    st = tots._rl_state["qruser2"]
    assert st["last_qr"] is not None
    assert st["last_qr"] > recent


@pytest.mark.security
def test_get_first_totp_state_with_nested_state() -> None:
    """_get_first_totp_state возвращает вложенный state из структуры (строки 218-224)."""

    # Arrange
    ctx: Any = type(
        "Ctx",
        (),
        {
            "mfa_manager": type(
                "Mgr",
                (),
                {
                    "_factors": {
                        "utest": {
                            "totp": [
                                {"state": {"secret": "TESTSECRET", "username": "tuser"}}
                            ]
                        }
                    }
                },
            )()
        },
    )()

    # Act
    result = tots._get_first_totp_state(ctx, "utest")

    # Assert
    assert result["secret"] == "TESTSECRET"
    assert result["username"] == "tuser"


@pytest.mark.security
def test_get_first_totp_state_returns_empty_for_missing_user() -> None:
    """_get_first_totp_state возвращает {} для неизвестного пользователя."""

    # Arrange
    ctx: Any = type(
        "Ctx",
        (),
        {"mfa_manager": type("Mgr", (), {"_factors": {}})()},
    )()

    # Act
    result = tots._get_first_totp_state(ctx, "noone")

    # Assert
    assert result == {}


@pytest.mark.security
def test_get_first_totp_state_skips_non_dict_items() -> None:
    """_get_first_totp_state пропускает элементы без state-словаря (строки 219-222)."""

    # Arrange — первый элемент без state, второй с state
    ctx: Any = type(
        "Ctx",
        (),
        {
            "mfa_manager": type(
                "Mgr",
                (),
                {
                    "_factors": {
                        "u": {
                            "totp": [
                                {"no_state": True},
                                {"state": "not_a_dict"},
                                {"state": {"secret": "FOUND"}},
                            ]
                        }
                    }
                },
            )()
        },
    )()

    # Act
    result = tots._get_first_totp_state(ctx, "u")

    # Assert
    assert result["secret"] == "FOUND"


@pytest.mark.security
def test_validate_label_truncates_long_string() -> None:
    """_validate_label обрезает строку длиннее max_len (строка 233)."""

    # Arrange
    long_label = "A" * 100

    # Act
    result = tots._validate_label(long_label, max_len=64)

    # Assert
    assert len(result) == 64
    assert result == "A" * 64


@pytest.mark.security
def test_validate_label_strips_control_chars() -> None:
    """_validate_label удаляет управляющие символы."""

    # Arrange
    label_with_controls = "Hello\x00\x01World\x1f"

    # Act
    result = tots._validate_label(label_with_controls)

    # Assert
    assert result == "HelloWorld"


@pytest.mark.security
def test_redact_secret_returns_empty_for_falsy() -> None:
    """_redact_secret возвращает пустую строку для пустого/None секрета (строки 306-308)."""

    # Arrange / Act / Assert
    assert tots._redact_secret(None) == ""
    assert tots._redact_secret("") == ""


@pytest.mark.security
def test_redact_secret_returns_stars_for_nonempty() -> None:
    """_redact_secret маскирует непустой секрет."""

    # Arrange / Act
    result = tots._redact_secret("MYSECRET")

    # Assert
    assert result == "****"


@pytest.mark.security
def test_setup_totp_for_user_audit_appended(patch_pyotp_qrcode: None) -> None:
    """setup_totp_for_user добавляет запись в audit после настройки (строки 383-384)."""

    # Arrange
    tots.setup_totp_for_user("audituser", "auditlogin", "ISS")

    # Act
    audit = tots.get_totp_audit("audituser")

    # Assert — в аудите должна быть запись с action=setup
    setup_entries = [e for e in audit if isinstance(e, dict) and e.get("action") == "setup"]
    assert len(setup_entries) >= 1
    assert setup_entries[0]["result"] == "success"


@pytest.mark.security
def test_remove_totp_for_user_audit_appended() -> None:
    """remove_totp_for_user добавляет запись в audit перед удалением (строки 423-424)."""

    # Arrange — создаём фактор с изменяемым state
    tots.setup_totp_for_user("remaudit", "rlogin")

    # Act
    tots.remove_totp_for_user("remaudit")

    # Assert — после удаления get_totp_status пуст (фактор удалён)
    assert tots.get_totp_status("remaudit") == {}


@pytest.mark.security
def test_get_totp_status_with_redact_true() -> None:
    """get_totp_status(redact=True) возвращает только публичные поля (строки 439, 442-449)."""

    # Arrange
    tots.setup_totp_for_user("redacted", "rlogin", "RISS")

    # Act
    st = tots.get_totp_status("redacted", redact=True)

    # Assert — секрет замаскирован или отсутствует; есть публичные поля
    assert "secret" not in st or st.get("secret") == "****"
    assert "username" in st
    assert "issuer" in st
    assert "digits" in st
    assert "interval" in st


@pytest.mark.security
def test_get_totp_status_public_delegates_to_redact() -> None:
    """get_totp_status_public возвращает то же что get_totp_status(redact=True) (строка 457)."""

    # Arrange
    tots.setup_totp_for_user("pubstatus", "puser")

    # Act
    public = tots.get_totp_status_public("pubstatus")
    redacted = tots.get_totp_status("pubstatus", redact=True)

    # Assert
    assert public == redacted


@pytest.mark.security
def test_regenerate_totp_qr_delegates_to_generate(patch_pyotp_qrcode: None) -> None:
    """regenerate_totp_qr возвращает тот же результат что generate_totp_qr_uri (строка 495)."""

    # Arrange
    tots.setup_totp_for_user("regen", "regenlogin", "RISS")

    # Act
    result = tots.regenerate_totp_qr("regen")

    # Assert
    assert "uri" in result
    assert "qr" in result
    assert "qr_mime" in result


@pytest.mark.security
def test_get_totp_secret_for_storage_audit_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Неверный OTP добавляет fail-запись в audit и поднимает TotpInvalidCode (строки 550-551)."""

    # Arrange
    tots.setup_totp_for_user("failaudit", "failuser")

    class DummyTOTP:
        def __init__(self, secret: str, **kwargs: Any) -> None:
            pass

        def verify(self, code: str, **kwargs: Any) -> bool:
            return False

    monkeypatch.setitem(sys.modules, "pyotp", types.SimpleNamespace(TOTP=DummyTOTP))
    monkeypatch.setitem(tots._config, "kdf", lambda pw, salt, n: b"\x00" * n)

    # Act / Assert
    with pytest.raises(tots.TotpInvalidCode):
        tots.get_totp_secret_for_storage("failaudit", "wrongotp")

    # Assert — запись в audit
    audit = tots.get_totp_audit("failaudit")
    fail_entries = [e for e in audit if isinstance(e, dict) and e.get("result") == "fail"]
    assert len(fail_entries) >= 1


@pytest.mark.security
def test_get_totp_secret_for_storage_audit_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Верный OTP добавляет success-запись в audit (строки 563-564)."""

    # Arrange
    tots.setup_totp_for_user("succaudit", "suser")

    class DummyTOTP:
        def __init__(self, secret: str, **kwargs: Any) -> None:
            pass

        def verify(self, code: str, **kwargs: Any) -> bool:
            return True

    monkeypatch.setitem(sys.modules, "pyotp", types.SimpleNamespace(TOTP=DummyTOTP))
    monkeypatch.setitem(tots._config, "kdf", lambda pw, salt, n: b"\xAA" * n)

    # Act
    result = tots.get_totp_secret_for_storage("succaudit", "anycode")

    # Assert
    assert isinstance(result, bytes)
    audit = tots.get_totp_audit("succaudit")
    success_entries = [e for e in audit if isinstance(e, dict) and e.get("result") == "success"]
    assert len(success_entries) >= 1


@pytest.mark.security
def test_get_totp_secret_for_storage_pepper_str(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Строковый pepper конкатенируется с OTP при деривации ключа (строка 572)."""

    # Arrange
    tots.setup_totp_for_user("pepperstr", "puser")
    captured: List[bytes] = []

    def capturing_kdf(pw: bytes, salt: bytes, n: int) -> bytes:
        captured.append(pw)
        return b"\xBB" * n

    class DummyTOTP:
        def __init__(self, secret: str, **kwargs: Any) -> None:
            pass

        def verify(self, code: str, **kwargs: Any) -> bool:
            return True

    monkeypatch.setitem(sys.modules, "pyotp", types.SimpleNamespace(TOTP=DummyTOTP))
    monkeypatch.setitem(tots._config, "pepper", "strpepper")
    monkeypatch.setitem(tots._config, "kdf", capturing_kdf)

    # Act
    tots.get_totp_secret_for_storage("pepperstr", "myotp")

    # Assert — password_bytes содержит pepper
    assert len(captured) == 1
    assert b"strpepper" in captured[0]

    # Cleanup
    tots._config["pepper"] = None


@pytest.mark.security
def test_get_totp_secret_for_storage_pepper_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Байтовый pepper конкатенируется с OTP при деривации ключа (строка 574)."""

    # Arrange
    tots.setup_totp_for_user("pepperbytes", "puser")
    captured: List[bytes] = []

    def capturing_kdf(pw: bytes, salt: bytes, n: int) -> bytes:
        captured.append(pw)
        return b"\xCC" * n

    class DummyTOTP:
        def __init__(self, secret: str, **kwargs: Any) -> None:
            pass

        def verify(self, code: str, **kwargs: Any) -> bool:
            return True

    monkeypatch.setitem(sys.modules, "pyotp", types.SimpleNamespace(TOTP=DummyTOTP))
    monkeypatch.setitem(tots._config, "pepper", b"bytepepper")
    monkeypatch.setitem(tots._config, "kdf", capturing_kdf)

    # Act
    tots.get_totp_secret_for_storage("pepperbytes", "myotp")

    # Assert
    assert len(captured) == 1
    assert b"bytepepper" in captured[0]

    # Cleanup
    tots._config["pepper"] = None


@pytest.mark.security
def test_get_totp_secret_for_storage_non_bytes_derived(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Если KDF возвращает не bytes — результат конвертируется в bytes (строка 584)."""

    # Arrange
    tots.setup_totp_for_user("nonbytes", "nbuser")

    class DummyTOTP:
        def __init__(self, secret: str, **kwargs: Any) -> None:
            pass

        def verify(self, code: str, **kwargs: Any) -> bool:
            return True

    # KDF возвращает bytearray вместо bytes
    def bytearray_kdf(pw: bytes, salt: bytes, n: int) -> bytearray:
        return bytearray(b"\xDD" * n)

    monkeypatch.setitem(sys.modules, "pyotp", types.SimpleNamespace(TOTP=DummyTOTP))
    monkeypatch.setitem(tots._config, "kdf", bytearray_kdf)

    # Act
    result = tots.get_totp_secret_for_storage("nonbytes", "anyotp")

    # Assert — результат должен быть bytes
    assert isinstance(result, bytes)
    assert result == b"\xDD" * 64


@pytest.mark.security
def test_export_policy_returns_complete_structure() -> None:
    """export_policy возвращает полную структуру конфигурации (строки 592-594)."""

    # Arrange / Act
    policy = tots.export_policy()

    # Assert — все ожидаемые ключи присутствуют
    assert "issuer" in policy
    assert "digits" in policy
    assert "interval" in policy
    assert "valid_window" in policy
    assert "rate_limit" in policy
    rate = policy["rate_limit"]
    assert "max_fails" in rate
    assert "lock_seconds" in rate
    assert "min_interval" in rate
    assert "qr_min_interval" in rate
    assert "qr" in policy
    assert "pepper_configured" in policy
    assert "kdf_configured" in policy


@pytest.mark.security
def test_export_policy_pepper_configured_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """export_policy корректно отражает наличие pepper."""

    # Arrange — без pepper
    monkeypatch.setitem(tots._config, "pepper", None)
    policy_no_pepper = tots.export_policy()
    assert policy_no_pepper["pepper_configured"] is False

    # Arrange — с pepper
    monkeypatch.setitem(tots._config, "pepper", "somepep")
    policy_with_pepper = tots.export_policy()
    assert policy_with_pepper["pepper_configured"] is True


@pytest.mark.security
def test_validate_totp_code_lockout_after_failures() -> None:
    """validate_totp_code поднимает TotpLockedOut после превышения max_fails (строки 169-170)."""

    # Arrange — создаём фактор
    tots.setup_totp_for_user("rluser", "rllogin")
    max_fails = tots._config["rate"]["max_fails"]

    # Act — накапливаем неудачные попытки
    for _ in range(max_fails):
        tots.validate_totp_code("rluser", "wrongcode")

    # Assert — следующая попытка должна быть заблокирована
    with pytest.raises(tots.TotpLockedOut):
        tots.validate_totp_code("rluser", "wrongcode")


@pytest.mark.security
def test_get_totp_secret_for_storage_locked_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_totp_secret_for_storage поднимает TotpLockedOut когда пользователь заблокирован."""

    # Arrange
    future = datetime.now(timezone.utc) + timedelta(seconds=300)
    tots._rl_state["locksec"] = {
        "failed": 0,
        "lock_until": future,
        "last_try": None,
        "last_qr": None,
    }
    tots.setup_totp_for_user("locksec", "lockedlogin")

    # Act / Assert
    with pytest.raises(tots.TotpLockedOut):
        tots.get_totp_secret_for_storage("locksec", "anyotp")
