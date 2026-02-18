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
        return bool(credential.get("mockpass", False))

    def remove_factor(self, user_id: str, ftype: str) -> None:
        if user_id in self._factors and ftype in self._factors[user_id]:
            self._factors[user_id].pop(ftype)


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
    monkeypatch.setattr(f2s, "_manager_lock", threading.RLock())
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
    monkeypatch.setattr(
        f2s, "derive_key_argon2id", lambda pw, salt, length: b"key" * (length // 3)
    )
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
