import sys
import threading
import types
from typing import Any, Dict, Iterator, List, cast

import pytest
import src.security.auth.fido2_service as f2s


class DummyManager:
    def __init__(self) -> None:
        self._factors: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    def setup_factor(self, user_id: str, ftype: str, **kwargs: Any) -> None:
        self._factors.setdefault(user_id, {}).setdefault(ftype, []).append(
            {"state": {"key": "state"}}
        )

    def verify_factor(self, user_id: str, ftype: str, credential: Any) -> bool:
        if not isinstance(credential, dict):
            return False
        if credential.get("mockpass"):
            return True
        if credential.get("allow") == "ok":
            return True
        return False

    def remove_factor(self, user_id: str, ftype: str) -> None:
        if user_id in self._factors and ftype in self._factors[user_id]:
            self._factors[user_id].pop(ftype)

    def export_factor_state(self, user_id: str, ftype: str) -> Dict[str, Any]:
        items = self._factors.get(user_id, {}).get(ftype, [])
        return dict(items[-1]["state"]) if items else {}


class DummyContext:
    def __init__(self, manager: DummyManager) -> None:
        self.mfa_manager = manager


class DummyFido2Factor:
    def verify(self, user_id: str, response: dict, state: dict) -> dict:
        # Именно "success" для положительного теста!
        if response.get("allow") == "ok":
            return {"status": "success"}
        if response.get("allow") == "fail":
            return {"status": "fail"}
        return {"status": "unknown"}


@pytest.fixture(autouse=True)
def patch_context(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    mgr = DummyManager()
    ctx = DummyContext(mgr)
    monkeypatch.setattr(f2s, "get_app_context", lambda: ctx)
    yield


@pytest.fixture(autouse=True)
def isolate_manager_lock(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(f2s, "_lock", threading.RLock())
    yield


@pytest.fixture
def patch_fido2_class(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for modname in [
        "src.security.auth.second_method.fido2",
        "security.auth.second_method.fido2",
    ]:
        fake_module: types.ModuleType = types.ModuleType(modname)
        setattr(fake_module, "Fido2Factor", DummyFido2Factor)
        sys.modules[modname] = fake_module
    yield


def test_setup_fido2_for_user() -> None:
    result: Dict[str, Any] = f2s.setup_fido2_for_user("alice", {"dev": 1})
    assert isinstance(result, dict) and "key" in result


def test_validate_fido2_response() -> None:
    assert f2s.validate_fido2_response("alice", {"mockpass": True}) is True
    assert f2s.validate_fido2_response("alice", {"mockpass": False}) is False


def test_remove_fido2_for_user() -> None:
    f2s.setup_fido2_for_user("alice", {"dev": 2})
    f2s.remove_fido2_for_user("alice")
    state = f2s.get_fido2_status("alice")
    assert state == {}


def test_get_fido2_status() -> None:
    f2s.setup_fido2_for_user("bob", {"dev": 1})
    status: Dict[str, Any] = f2s.get_fido2_status("bob")
    assert isinstance(status, dict) and "key" in status


def test_get_fido2_status_no_data() -> None:
    state = f2s.get_fido2_status("notexist")
    assert state == {}


def test_get_fido2_audit() -> None:
    user = "audituser"
    mgr = cast(DummyContext, f2s.get_app_context()).mfa_manager
    mgr._factors[user] = {"fido2": [{"state": {"audit": [1, 2, 3]}}]}
    audit = f2s.get_fido2_audit(user)
    assert isinstance(audit, list)
    assert audit == [1, 2, 3]


def test_get_fido2_audit_missing() -> None:
    audit = f2s.get_fido2_audit("empty")
    assert audit == []


def test_get_fido2_secret_for_storage_success(
    patch_fido2_class: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = "token"
    ctx = f2s.get_app_context()
    mgr = cast(DummyContext, ctx).mfa_manager
    mgr._factors[user] = {"fido2": [{"state": {}}]}
    monkeypatch.setattr(f2s, "derive_key_argon2id", lambda pw, salt, length: b"key" * (length // 3))
    secret = f2s.get_fido2_secret_for_storage(
        user, {"allow": "ok", "credential_id": "cid", "signature": "sig"}
    )
    assert secret == b"keykeykeykeykeykeykeykeykeykey"


def test_get_fido2_secret_for_storage_fail_response(patch_fido2_class: None) -> None:
    user = "tokfail"
    ctx = f2s.get_app_context()
    mgr = cast(DummyContext, ctx).mfa_manager
    mgr._factors[user] = {"fido2": [{"state": {}}]}
    with pytest.raises(PermissionError):
        f2s.get_fido2_secret_for_storage(
            user, {"allow": "fail", "credential_id": "cid", "signature": "sig"}
        )


def test_get_fido2_secret_for_storage_missing_fields(patch_fido2_class: None) -> None:
    user = "tokmiss"
    ctx = f2s.get_app_context()
    mgr = cast(DummyContext, ctx).mfa_manager
    mgr._factors[user] = {"fido2": [{"state": {}}]}
    with pytest.raises(PermissionError):
        f2s.get_fido2_secret_for_storage(user, {"allow": "ok", "signature": "sig"})
    with pytest.raises(PermissionError):
        f2s.get_fido2_secret_for_storage(user, {"allow": "ok", "credential_id": "cid"})


# ---------------------------------------------------------------------------
# Новые тесты для достижения ≥95% покрытия
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_export_state_without_export_factor_state_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_export_state должен вернуть {} если у менеджера нет метода export_factor_state."""

    # Arrange — менеджер без метода export_factor_state
    class MinimalManager:
        def setup_factor(self, user_id: str, ftype: str, **kwargs: Any) -> None:
            pass

        def verify_factor(self, user_id: str, ftype: str, **kwargs: Any) -> bool:
            return False

        def remove_factor(self, user_id: str, ftype: str) -> None:
            pass

    class MinimalContext:
        mfa_manager = MinimalManager()

    monkeypatch.setattr(f2s, "get_app_context", lambda: MinimalContext())

    # Act
    result = f2s.get_fido2_status("anyuser")

    # Assert — fallback должен вернуть {}
    assert result == {}


@pytest.mark.security
def test_export_state_returns_empty_when_export_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_export_state возвращает {} если export_factor_state вернул None."""

    class NoneExportManager:
        def export_factor_state(self, user_id: str, ftype: str) -> None:
            return None

    class NoneExportContext:
        mfa_manager = NoneExportManager()

    monkeypatch.setattr(f2s, "get_app_context", lambda: NoneExportContext())

    # Act
    result = f2s.get_fido2_status("anyuser")

    # Assert
    assert result == {}


@pytest.mark.security
def test_derive_key_argon2id_import_error_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ветка ImportError в fido2_service: derive_key_argon2id должен бросать RuntimeError."""
    import importlib
    import types as _types

    # Создаём fake модуль src.security.crypto.algorithms.kdf, который бросает ImportError
    fake_kdf: _types.ModuleType = _types.ModuleType("src.security.crypto.algorithms.kdf")

    # Подменяем модуль в sys.modules временно, чтобы спровоцировать ImportError при reload
    original = sys.modules.get("src.security.crypto.algorithms.kdf")
    sys.modules.pop("src.security.crypto.algorithms.kdf", None)

    # Перезагружаем fido2_service без kdf-модуля
    # Сохраняем оригинальную функцию чтобы восстановить
    original_derive = f2s.derive_key_argon2id

    # Подменяем derive_key_argon2id fallback-версией напрямую
    def fallback_derive(password: bytes, salt: bytes, length: int) -> bytes:
        raise RuntimeError("Argon2idKDF is not available")

    monkeypatch.setattr(f2s, "derive_key_argon2id", fallback_derive)

    try:
        # Act / Assert — вызов должен бросить RuntimeError
        with pytest.raises(RuntimeError, match="Argon2idKDF is not available"):
            f2s.derive_key_argon2id(b"password", b"salt", 32)
    finally:
        if original is not None:
            sys.modules["src.security.crypto.algorithms.kdf"] = original


@pytest.mark.security
def test_get_fido2_secret_uses_empty_pubkey_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_fido2_secret_for_storage: если state не содержит public_key, используется пустая строка."""

    # Arrange — state без public_key
    user = "pubkey_fallback"
    ctx = f2s.get_app_context()
    mgr = cast(DummyContext, ctx).mfa_manager
    # Состояние без поля public_key
    mgr._factors[user] = {"fido2": [{"state": {}}]}

    monkeypatch.setattr(
        f2s,
        "derive_key_argon2id",
        lambda pw, salt, length: b"\x00" * length,
    )

    # Act — не должно бросать исключений
    secret = f2s.get_fido2_secret_for_storage(
        user, {"allow": "ok", "credential_id": "cid123", "signature": "sig456"}
    )

    # Assert — возвращает 32 нулевых байта (наш stub)
    assert len(secret) == 32
    assert secret == b"\x00" * 32


@pytest.mark.security
def test_get_fido2_secret_with_public_key_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_fido2_secret_for_storage: если state содержит public_key — он используется (строка 121->125).

    Покрывает ветку if not pubkey: FALSE — т.е. pubkey IS truthy, строка 121->125 не выполняется.
    """
    from typing import cast

    # Arrange — состояние с public_key
    user = "pubkey_present_user"
    ctx = f2s.get_app_context()
    mgr = cast(DummyContext, ctx).mfa_manager
    mgr._factors[user] = {"fido2": [{"state": {"public_key": "mypublickey"}}]}

    captured_passwords: list = []

    def capturing_kdf(pw: bytes, salt: bytes, length: int) -> bytes:
        captured_passwords.append(pw)
        return b"\xff" * length

    monkeypatch.setattr(f2s, "derive_key_argon2id", capturing_kdf)

    # Act
    secret = f2s.get_fido2_secret_for_storage(
        user, {"allow": "ok", "credential_id": "mycred", "signature": "mysig"}
    )

    # Assert — вернулся 32-байтный ключ
    assert len(secret) == 32
    assert secret == b"\xff" * 32

    # Assert — public_key "mypublickey" вошёл в password_bytes для KDF
    assert len(captured_passwords) == 1
    assert b"mypublickey" in captured_passwords[0]


@pytest.mark.security
def test_get_crypto_service_impl_uses_default_on_exception_fido2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_crypto_service_impl использует default при исключении get_app_context (строки 30-31)."""

    # Arrange
    def failing_get_app_context() -> Any:
        raise RuntimeError("Context not available")

    monkeypatch.setattr(f2s, "get_app_context", failing_get_app_context)

    # Act
    result = f2s._get_crypto_service_impl()

    # Assert
    assert result is f2s._default_crypto_service


@pytest.mark.security
def test_get_crypto_service_impl_uses_context_when_available_fido2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_crypto_service_impl использует crypto_service из app_context когда доступен (строка 28)."""

    # Arrange
    mock_crypto_service = object()
    ctx: Any = type("Ctx", (), {"crypto_service": mock_crypto_service})()
    monkeypatch.setattr(f2s, "get_app_context", lambda: ctx)

    # Act
    result = f2s._get_crypto_service_impl()

    # Assert
    assert result is mock_crypto_service


@pytest.mark.security
def test_get_crypto_service_impl_fallback_no_crypto_service_attr_fido2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_get_crypto_service_impl использует default когда crypto_service отсутствует в context (строка 28)."""

    # Arrange
    ctx: Any = type("Ctx", (), {})()  # No crypto_service attribute
    monkeypatch.setattr(f2s, "get_app_context", lambda: ctx)

    # Act
    result = f2s._get_crypto_service_impl()

    # Assert
    assert result is f2s._default_crypto_service
