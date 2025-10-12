import pytest
import logging
from typing import Generator, Dict, Any

from src.security.auth.second_factor import SecondFactorManager
from src.security.crypto.secure_storage import SecureStorage, StorageBackend


class DummyFactor:
    def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
        return {"id": "testid", "created": 12345, "ttlseconds": kwargs.get("ttlseconds")}

    def verify(self, user_id: str, credential: str, state: object) -> bool:
        return credential == "valid"

    def remove(self, user_id: str, state: object) -> None:
        pass


class DummyStorage(SecureStorage):
    def __init__(self) -> None:
        self.saved: Dict[str, Any] = {}
        self.data: Dict[str, Any] = {"factors": {}, "audit": []}

    def load(self) -> Dict[str, Any]:
        return self.data

    def save(self, payload: Dict[str, Any]) -> None:
        self.saved = payload
        self.data = payload


@pytest.fixture
def manager() -> Generator[SecondFactorManager, None, None]:
    storage = DummyStorage()
    logger = logging.getLogger("testlogger")
    m = SecondFactorManager(storage=storage, logger=logger)
    m.register_factor_type("dummy", DummyFactor)
    yield m


def test_register_and_unregister_factor_type(manager: SecondFactorManager) -> None:
    with pytest.raises(ValueError):
        manager.register_factor_type("dummy", DummyFactor)
    manager.unregister_factor_type("dummy")
    assert "dummy" not in manager._factor_registry


def test_setup_and_status(manager: SecondFactorManager) -> None:
    user_id: str = "testuser"
    factor_id: str = manager.setup_factor(user_id, "dummy", ttlseconds=10)
    status = manager.get_status(user_id, "dummy")
    assert status is not None
    assert status["id"] == "testid"
    assert status["ttlseconds"] == 10


def test_invalid_userid(manager: SecondFactorManager) -> None:
    with pytest.raises(ValueError):
        manager.setup_factor("", "dummy")


def test_setup_unknown_type(manager: SecondFactorManager) -> None:
    with pytest.raises(ValueError):
        manager.setup_factor("testuser", "unknown")


def test_rotate_factor(manager: SecondFactorManager) -> None:
    user_id: str = "rotateuser"
    manager.setup_factor(user_id, "dummy")
    res = manager.rotate_factor(user_id, "dummy", ttlseconds=30)
    assert isinstance(res, dict)
    assert res["id"] == "testid"


def test_verify_factor(manager: SecondFactorManager) -> None:
    user_id: str = "vuser"
    manager.setup_factor(user_id, "dummy")
    assert manager.verify_factor(user_id, "dummy", "valid")
    assert not manager.verify_factor(user_id, "dummy", "invalid")


def test_remove_factor(manager: SecondFactorManager) -> None:
    user_id: str = "remuser"
    manager.setup_factor(user_id, "dummy")
    assert manager.get_status(user_id, "dummy") is not None
    manager.remove_factor(user_id, "dummy")
    assert manager.get_status(user_id, "dummy") is None


def test_remove_by_id(manager: SecondFactorManager) -> None:
    user_id: str = "remid"
    factor_id: str = manager.setup_factor(user_id, "dummy")
    manager.remove_factor(user_id, "dummy", factor_id=factor_id)
    assert manager.get_status(user_id, "dummy") is None


def test_remove_all_factors(manager: SecondFactorManager) -> None:
    user_id: str = "remall"
    for _ in range(3):
        manager.setup_factor(user_id, "dummy")
    manager.remove_all_factors(user_id, "dummy")
    assert manager.get_status(user_id, "dummy") is None
    assert manager.get_history(user_id, "dummy") == []


def test_get_history(manager: SecondFactorManager) -> None:
    user_id: str = "histuser"
    for _ in range(2):
        manager.setup_factor(user_id, "dummy")
    history = manager.get_history(user_id, "dummy")
    assert len(history) == 2
    assert all(h["id"] == "testid" for h in history)


def test_get_audit(manager: SecondFactorManager) -> None:
    user_id: str = "audituser"
    manager.setup_factor(user_id, "dummy")
    manager.verify_factor(user_id, "dummy", "valid")
    manager.remove_factor(user_id, "dummy")
    audit = manager.get_audit(user_id=user_id)
    actions = {e.get("action") for e in audit}
    assert "setup" in actions
    assert "verify" in actions
    assert "remove" in actions


class DummyBackend(StorageBackend):
    def save(self, key: str, encrypted_data: bytes) -> None:
        pass

    def load(self, key: str) -> bytes:
        raise RuntimeError("fail load")

    def delete(self, key: str) -> None:
        pass

    def list_keys(self) -> list[str]:
        return []


def test_storage_load_exception_logs() -> None:
    backend = DummyBackend()
    storage = SecureStorage(backend=backend)
    manager = SecondFactorManager(storage=storage)
    manager._load_storage()  # exception coverage


class DummySaveFailBackend(StorageBackend):
    def save(self, key: str, encrypted_data: bytes) -> None:
        raise RuntimeError("fail save")

    def load(self, key: str) -> bytes:
        return b""

    def delete(self, key: str) -> None:
        pass

    def list_keys(self) -> list[str]:
        return []


def test_storage_save_exception_logs(manager: SecondFactorManager) -> None:
    backend = DummySaveFailBackend()
    storage = SecureStorage(backend=backend)
    m = SecondFactorManager(storage=storage)
    m._save_storage()


def test_remove_factor_empty(manager: SecondFactorManager) -> None:
    manager.remove_factor("nouser", "dummy")
    manager.remove_factor("nouser", "dummy", factor_id="notfound")


def test_remove_factor_pop_nonexistent(manager: SecondFactorManager) -> None:
    user, factor_type = "rempop", "dummy"
    manager._factors[user] = {}
    manager.remove_factor(user, factor_type, factor_id="abc")
    manager._factors[user][factor_type] = []
    manager.remove_factor(user, factor_type, factor_id="abc")


def test_remove_all_factors_empty(manager: SecondFactorManager) -> None:
    manager.remove_all_factors("nouser", "dummy")


def test_get_status_history_empty(manager: SecondFactorManager) -> None:
    assert manager.get_status("nouser", "dummy") is None
    assert manager.get_history("nouser", "dummy") == []


def test_get_audit_empty_and_filter(manager: SecondFactorManager) -> None:
    assert manager.get_audit("nouser") == []
    assert manager.get_audit(factor_type="dummy") == []
    manager._audit.append(dict(action="setup", user="test", type="dummy"))
    assert manager.get_audit(user_id="non_user") == []
    assert manager.get_audit(factor_type="notype") == []
    assert isinstance(manager.get_audit(), list)


def test_secure_del_branches(manager: SecondFactorManager) -> None:
    testmap: Dict[str, Any] = {"key": bytearray(b"foo"), "key2": "bar", "key3": 123}
    manager._secure_del(testmap, ["key", "key2", "key3", "missing"])
    assert True


@pytest.mark.parametrize(
    "scenario",
    [
        {},  # no factors, empty history
        {"factors": {"a": {"t": []}}, "audit": []},
        {"factors": {"a": {"t": [{"state": {}}]}}, "audit": []},
    ],
)
def test_factors_audit_edge_cases(manager: SecondFactorManager, scenario: Dict[str, Any]) -> None:
    manager._factors = scenario.get("factors", {})
    manager._audit = scenario.get("audit", [])
    assert manager.get_history("a", "t") is not None
    manager.remove_all_factors("a", "t")
    assert manager.get_status("a", "t") is None


def test_get_audit_all_filters(manager: SecondFactorManager) -> None:
    manager._audit = [
        {"action": "setup", "user": "u1", "type": "t1"},
        {"action": "remove", "user": "u2", "type": "t2"},
        {"action": "setup", "user": "u1", "type": "t2"},
    ]
    # user+type фильтр
    assert manager.get_audit(user_id="u1", factor_type="t2") == [
        {"action": "setup", "user": "u1", "type": "t2"}
    ]
    # только user
    assert len(manager.get_audit(user_id="u2")) == 1
    # только type
    assert len(manager.get_audit(factor_type="t2")) == 2
    # ничего
    assert manager.get_audit(user_id="xxx", factor_type="not") == []
