from typing import Any, Dict, Iterator, List, Optional, Type

import pytest
import src.security.auth.second_factor_service as svc
from src.security.auth.second_factor_service import AuditRecord, FactorStatus


class DummyManager:
    def __init__(self) -> None:
        self.status: Dict[str, Any] = {
            "id": "testid",
            "created": 0,
            "ttlseconds": 100000,
        }
        self.audit: List[Dict[str, Any]] = [{"action": "setup", "user": "u", "type": "t", "ts": 1}]
        self.verify_result = True

    def setup_factor(self, user_id: str, factor_type: str, **kwargs: Any) -> str:
        return "testid"

    def get_status(self, user_id: str, factor_type: str) -> Optional[Dict[str, Any]]:
        return self.status

    def verify_factor(
        self,
        user_id: str,
        factor_type: str,
        credential: Any,
        factor_id: Optional[str] = None,
    ) -> bool:
        return self.verify_result

    def remove_factor(
        self, user_id: str, factor_type: str, factor_id: Optional[str] = None
    ) -> None:
        pass

    def remove_all_factors(self, user_id: str, factor_type: str) -> None:
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


# ============================================================
# Новые тесты для покрытия недостающих строк (≥95%)
# ============================================================


@pytest.mark.security
def test_validate_input_empty_factor_type_raises() -> None:
    """_validate_input бросает ValueError при пустом factor_type."""
    # Act / Assert
    with pytest.raises(ValueError, match="factor_type must be a non-empty string"):
        svc._validate_input("valid_user", "")


@pytest.mark.security
def test_validate_input_whitespace_factor_type_raises() -> None:
    """_validate_input бросает ValueError при factor_type из пробелов."""
    # Act / Assert
    with pytest.raises(ValueError, match="factor_type must be a non-empty string"):
        svc._validate_input("valid_user", "   ")


@pytest.mark.security
def test_validate_input_none_factor_type_ok() -> None:
    """_validate_input не бросает исключение, если factor_type is None."""
    # Act — None считается допустимым (фильтрация не нужна)
    svc._validate_input("valid_user", None)


@pytest.mark.security
def test_get_factor_status_no_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_factor_status возвращает ошибку, если get_status вернул None."""

    class EmptyStatusManager(DummyManager):
        def get_status(self, user_id: str, factor_type: str) -> Optional[Dict[str, Any]]:
            return None

    monkeypatch.setattr(svc, "_manager", EmptyStatusManager())  # type: ignore
    # Act
    result: FactorStatus = svc.get_factor_status("u", "t")
    # Assert
    assert result.get("valid") is False
    assert result.get("error") == "no status"


@pytest.mark.security
def test_setup_factor_with_empty_factor_type_returns_error() -> None:
    """setup_factor возвращает FactorStatus с ошибкой при пустом factor_type."""
    # Act
    result: FactorStatus = svc.setup_factor("user", "")
    # Assert
    assert result.get("valid") is False
    assert "error" in result


@pytest.mark.security
def test_remove_factor_with_factor_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """remove_factor передаёт factor_id в менеджер без ошибок."""

    class TrackingManager(DummyManager):
        def __init__(self) -> None:
            super().__init__()
            self.last_factor_id: Optional[str] = None

        def remove_factor(
            self, user_id: str, factor_type: str, factor_id: Optional[str] = None
        ) -> None:
            self.last_factor_id = factor_id

    tm = TrackingManager()
    monkeypatch.setattr(svc, "_manager", tm)  # type: ignore
    # Act
    result: FactorStatus = svc.remove_factor("u", "t", factor_id="some-id")
    # Assert
    assert result.get("valid") is True
    assert tm.last_factor_id == "some-id"


@pytest.mark.security
def test_verify_factor_with_factor_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """verify_factor передаёт factor_id в менеджер корректно."""

    class TrackingManager(DummyManager):
        def __init__(self) -> None:
            super().__init__()
            self.last_factor_id: Optional[str] = None

        def verify_factor(
            self,
            user_id: str,
            factor_type: str,
            credential: Any,
            factor_id: Optional[str] = None,
        ) -> bool:
            self.last_factor_id = factor_id
            return True

    tm = TrackingManager()
    monkeypatch.setattr(svc, "_manager", tm)  # type: ignore
    # Act
    result: FactorStatus = svc.verify_factor("u", "t", "cred", factor_id="fid-123")
    # Assert
    assert result.get("valid") is True
    assert tm.last_factor_id == "fid-123"


@pytest.mark.security
def test_rotate_factor_with_kwargs(monkeypatch: pytest.MonkeyPatch) -> None:
    """rotate_factor передаёт kwargs в менеджер и возвращает валидный статус."""

    class TrackingManager(DummyManager):
        def __init__(self) -> None:
            super().__init__()
            self.got_kwargs: Dict[str, Any] = {}

        def setup_factor(self, user_id: str, factor_type: str, **kwargs: Any) -> str:
            self.got_kwargs = dict(kwargs)
            return "new-id"

    tm = TrackingManager()
    monkeypatch.setattr(svc, "_manager", tm)  # type: ignore
    # Act
    result: FactorStatus = svc.rotate_factor("u", "t", ttlseconds=60)
    # Assert
    assert result.get("valid") is True
    assert tm.got_kwargs.get("ttlseconds") == 60
