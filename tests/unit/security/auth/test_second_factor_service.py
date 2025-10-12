import pytest
from typing import Any, Dict, List, Optional, Type, Iterator
import src.security.auth.second_factor_service as svc
from src.security.auth.second_factor_service import FactorStatus, AuditRecord


class DummyManager:
    def __init__(self) -> None:
        self.status: Dict[str, Any] = {"id": "testid", "created": 0, "ttlseconds": 100000}
        self.audit: List[Dict[str, Any]] = [{"action": "setup", "user": "u", "type": "t", "ts": 1}]
        self.verify_result = True

    def setup_factor(self, user_id: str, factor_type: str, **kwargs: Any) -> str:
        return "testid"

    def get_status(self, user_id: str, factor_type: str) -> Optional[Dict[str, Any]]:
        return self.status

    def verify_factor(
        self, user_id: str, factor_type: str, credential: Any, factor_id: Optional[str] = None
    ) -> bool:
        return self.verify_result

    def remove_factor(
        self, user_id: str, factor_type: str, factor_id: Optional[str] = None
    ) -> None:
        pass

    def rotate_factor(
        self, user_id: str, factor_type: str, **kwargs: Any
    ) -> Optional[Dict[str, Any]]:
        return self.status

    def get_audit(
        self, user_id: Optional[str] = None, factor_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return self.audit

    def register_factor_type(self, name: str, cls: Type[Any]) -> None:
        pass

    def unregister_factor_type(self, name: str) -> None:
        pass


@pytest.fixture(autouse=True)
def patch_manager(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(svc, "_manager", DummyManager())  # type: ignore
    yield


def test_setup_factor_ok() -> None:
    result: FactorStatus = svc.setup_factor("u", "t")
    assert result.get("valid") is True
    assert result.get("state", {}).get("id") == "testid"


def test_setup_factor_error() -> None:
    result: FactorStatus = svc.setup_factor("", "t")
    assert result.get("valid") is False
    assert "error" in result


def test_verify_factor_ok() -> None:
    result: FactorStatus = svc.verify_factor("u", "t", "cred")
    assert result.get("valid") is True
    assert "state" in result


def test_verify_factor_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    dm = DummyManager()
    dm.status = {"created": 1, "ttlseconds": 1}
    monkeypatch.setattr(svc, "_manager", dm)  # type: ignore
    result: FactorStatus = svc.verify_factor("u", "t", "cred")
    assert result.get("expired") is True
    assert result.get("valid") is False


def test_verify_factor_error() -> None:
    result: FactorStatus = svc.verify_factor("", "t", "cred")
    assert result.get("valid") is False
    assert "error" in result


def test_remove_factor_ok() -> None:
    result: FactorStatus = svc.remove_factor("u", "t")
    assert result.get("valid") is True


def test_remove_factor_error() -> None:
    result: FactorStatus = svc.remove_factor("", "t")
    assert result.get("valid") is False
    assert "error" in result


def test_rotate_factor_ok() -> None:
    result: FactorStatus = svc.rotate_factor("u", "t")
    assert result.get("valid") is True
    assert "state" in result


def test_rotate_factor_error() -> None:
    result: FactorStatus = svc.rotate_factor("", "t")
    assert result.get("valid") is False
    assert "error" in result


def test_get_factor_status_ok() -> None:
    result: FactorStatus = svc.get_factor_status("u", "t")
    assert result.get("valid") is True


def test_get_factor_status_error() -> None:
    result: FactorStatus = svc.get_factor_status("", "t")
    assert result.get("valid") is False
    assert "error" in result


def test_get_factor_audit_ok() -> None:
    result: List[AuditRecord] = svc.get_factor_audit("u", "t")
    assert isinstance(result, list)
    assert result and "action" in result[0]


def test_get_factor_audit_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenManager(DummyManager):
        def get_audit(
            self, user_id: Optional[str] = None, factor_type: Optional[str] = None
        ) -> List[Dict[str, Any]]:
            raise RuntimeError("fail!")

    monkeypatch.setattr(svc, "_manager", BrokenManager())  # type: ignore
    result: List[AuditRecord] = svc.get_factor_audit("u", "t")
    assert isinstance(result, list)
    assert result and "action" in result[0]
    assert "error" in result[0]


def test_register_unregister_factor_type_ok() -> None:
    result: FactorStatus = svc.register_factor_type("custom", DummyManager)
    assert result.get("valid") is True
    result2: FactorStatus = svc.unregister_factor_type("custom")
    assert result2.get("valid") is True


def test_register_factor_type_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken(DummyManager):
        def register_factor_type(self, name: str, cls: Type[Any]) -> None:
            raise RuntimeError("fail!")

    monkeypatch.setattr(svc, "_manager", Broken())  # type: ignore
    result: FactorStatus = svc.register_factor_type("err", DummyManager)
    assert result.get("valid") is False
    assert "error" in result


def test_unregister_factor_type_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken(DummyManager):
        def unregister_factor_type(self, name: str) -> None:
            raise RuntimeError("fail!")

    monkeypatch.setattr(svc, "_manager", Broken())  # type: ignore
    result: FactorStatus = svc.unregister_factor_type("err")
    assert result.get("valid") is False
    assert "error" in result


def test_log_and_return_error_direct() -> None:
    err = svc._log_and_return_error("fn", ValueError("fail!"))
    assert err.get("valid") is False
    msg = err.get("error")
    assert msg is not None and "fail!" in msg


def test_get_factor_audit_error_default_params(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenManager(DummyManager):
        def get_audit(
            self, user_id: Optional[str] = None, factor_type: Optional[str] = None
        ) -> List[Dict[str, Any]]:
            raise RuntimeError("fail!")

    monkeypatch.setattr(svc, "_manager", BrokenManager())  # type: ignore
    result: List[AuditRecord] = svc.get_factor_audit()
    assert isinstance(result, list)
    assert result and result[0].get("action") == "audit_exception"
    err_val = result[0].get("error")
    assert err_val is not None and "fail!" in err_val
