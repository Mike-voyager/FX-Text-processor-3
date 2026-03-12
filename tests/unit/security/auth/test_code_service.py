import threading
from typing import Any, Dict, Iterator, List, Optional, cast
from unittest.mock import patch

import pytest
import src.security.auth.code_service as codes


class DummyManager:
    def __init__(self) -> None:
        self._factors: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    def setup_factor(self, user_id: str, ftype: str, **kwargs: Any) -> None:
        codes_lst = [{"code": f"C-{i}", "used": False} for i in range(kwargs.get("count", 1))]
        self._factors.setdefault(user_id, {}).setdefault(ftype, []).append(
            {
                "state": {
                    "codes": codes_lst,
                    "audit": [999],
                    "ttl": kwargs.get("ttlseconds", 10),
                }
            }
        )

    def verify_factor(self, user_id: str, ftype: str, credential: str) -> bool:
        return credential == "safe"

    def remove_factor(self, user_id: str, ftype: str) -> None:
        if user_id in self._factors and ftype in self._factors[user_id]:
            self._factors[user_id].pop(ftype)

    def export_factor_state(self, user_id: str, ftype: str) -> Optional[Dict[str, Any]]:
        """Экспорт состояния фактора для _export_state()."""
        entries = self._factors.get(user_id, {}).get(ftype, [])
        if not entries:
            return None
        return entries[-1]["state"]


class DummyContext:
    def __init__(self, manager: DummyManager) -> None:
        self.mfa_manager = manager


@pytest.fixture(autouse=True)
def patch_context(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    mgr = DummyManager()
    ctx = DummyContext(mgr)
    monkeypatch.setattr(codes, "get_app_context", lambda: ctx)
    yield


@pytest.fixture(autouse=True)
def isolate_lock(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(codes, "_lock", threading.RLock())
    yield


def test_issue_backup_codes_for_user() -> None:
    result = codes.issue_backup_codes_for_user("u1", count=3, ttlsec=600)
    assert isinstance(result, dict)
    assert "codes" in result
    assert isinstance(result["codes"], list)
    assert len(result["codes"]) == 3
    assert all(isinstance(x, dict) and "code" in x for x in result["codes"])


def test_issue_backup_codes_invalid_ttl() -> None:
    result = codes.issue_backup_codes_for_user("u1", count=3, ttlsec=12)
    assert isinstance(result, dict)
    assert "error" in result


def test_validate_backup_code_for_user_success() -> None:
    codes.issue_backup_codes_for_user("vuser", count=2, ttlsec=600)
    assert codes.validate_backup_code_for_user("vuser", "safe") is True
    assert codes.validate_backup_code_for_user("vuser", "wrong") is False


def test_partial_revoke_backup_code() -> None:
    codes.issue_backup_codes_for_user("pr", count=1, ttlsec=600)
    assert codes.partial_revoke_backup_code("pr", "safe") is True
    assert codes.partial_revoke_backup_code("pr", "wrong") is False


def test_remove_backup_codes_for_user() -> None:
    codes.issue_backup_codes_for_user("rmu", count=1, ttlsec=600)
    codes.remove_backup_codes_for_user("rmu")
    st = codes.get_backup_codes_status("rmu")
    assert st.get("remaining", 0) == 0
    assert st.get("consumed", 0) == 0


def test_get_backup_codes_status() -> None:
    codes.issue_backup_codes_for_user("s1", count=2, ttlsec=600)
    st = codes.get_backup_codes_status("s1")
    assert isinstance(st, dict)
    assert "remaining" in st
    assert "audit" in st


def test_get_backup_codes_status_empty() -> None:
    st = codes.get_backup_codes_status("none")
    assert isinstance(st, dict)
    assert st.get("remaining", 0) == 0
    assert st.get("consumed", 0) == 0


def test_get_backup_codes_audit() -> None:
    codes.issue_backup_codes_for_user("auser", count=2, ttlsec=600)
    aud = codes.get_backup_codes_audit("auser")
    assert isinstance(aud, list)
    assert 999 in aud


def test_get_backup_codes_audit_empty() -> None:
    assert codes.get_backup_codes_audit("unknown") == []


def test_get_backup_code_secret_for_storage_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codes.issue_backup_codes_for_user("sec", count=1, ttlsec=600)

    class FakeKDF:
        def derive_key(self, password: bytes, salt: bytes, key_length: int = 32) -> bytes:
            return b"k" * key_length

    monkeypatch.setattr(codes, "Argon2idKDF", FakeKDF)
    secret = codes.get_backup_code_secret_for_storage("sec", "safe")
    assert isinstance(secret, bytes)
    assert secret == b"k" * 32


def test_get_backup_code_secret_for_storage_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codes.issue_backup_codes_for_user("failuser", count=1, ttlsec=600)

    class FakeKDF:
        def derive_key(self, password: bytes, salt: bytes, key_length: int = 32) -> bytes:
            return b"k" * key_length

    monkeypatch.setattr(codes, "Argon2idKDF", FakeKDF)
    with pytest.raises(PermissionError):
        codes.get_backup_code_secret_for_storage("failuser", "notvalid")


# ---------------------------------------------------------------------------
# Дополнительные тесты для достижения покрытия ≥95%
# ---------------------------------------------------------------------------


@pytest.mark.security
def test_export_state_without_export_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_export_state возвращает {} если у менеджера нет export_factor_state (строка 40)."""

    # Arrange
    class MinimalManager:
        """Менеджер без метода export_factor_state."""

        pass

    ctx: Any = type("Ctx", (), {"mfa_manager": MinimalManager()})()
    monkeypatch.setattr(codes, "get_app_context", lambda: ctx)

    # Act
    result = codes._export_state("anyuser")

    # Assert
    assert result == {}


@pytest.mark.security
def test_issue_backup_codes_invalid_user_id_empty() -> None:
    """issue_backup_codes_for_user возвращает ошибку при пустом user_id (строка 51)."""

    # Arrange / Act
    result = codes.issue_backup_codes_for_user("", count=3, ttlsec=600)

    # Assert
    assert "error" in result
    assert "user_id" in (result.get("error") or "")


@pytest.mark.security
def test_issue_backup_codes_invalid_user_id_whitespace() -> None:
    """issue_backup_codes_for_user возвращает ошибку при пробельном user_id (строка 51)."""

    # Arrange / Act
    result = codes.issue_backup_codes_for_user("   ", count=3, ttlsec=600)

    # Assert
    assert "error" in result


@pytest.mark.security
def test_issue_backup_codes_invalid_count_zero() -> None:
    """issue_backup_codes_for_user возвращает ошибку при count=0 (строка 53)."""

    # Arrange / Act
    result = codes.issue_backup_codes_for_user("u1", count=0, ttlsec=600)

    # Assert
    assert "error" in result
    assert "count" in (result.get("error") or "")


@pytest.mark.security
def test_issue_backup_codes_invalid_count_too_large() -> None:
    """issue_backup_codes_for_user возвращает ошибку при count>20 (строка 53)."""

    # Arrange / Act
    result = codes.issue_backup_codes_for_user("u1", count=21, ttlsec=600)

    # Assert
    assert "error" in result


@pytest.mark.security
def test_issue_backup_codes_exception_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Исключение в setup_factor обрабатывается и возвращает error (строки 75-81)."""

    # Arrange
    class BrokenManager:
        def setup_factor(self, user_id: str, ftype: str, **kwargs: Any) -> None:
            raise RuntimeError("storage exploded")

        def export_factor_state(self, user_id: str, ftype: str) -> None:
            return None

    ctx: Any = type("Ctx", (), {"mfa_manager": BrokenManager()})()
    monkeypatch.setattr(codes, "get_app_context", lambda: ctx)

    # Act
    result = codes.issue_backup_codes_for_user("u1", count=3, ttlsec=600)

    # Assert
    assert "error" in result
    assert "storage exploded" in (result.get("error") or "")


@pytest.mark.security
def test_validate_backup_code_invalid_user_id() -> None:
    """validate_backup_code_for_user возвращает False при пустом user_id (строка 90)."""

    # Arrange / Act / Assert
    assert codes.validate_backup_code_for_user("", "somecode") is False


@pytest.mark.security
def test_validate_backup_code_invalid_user_id_whitespace() -> None:
    """validate_backup_code_for_user возвращает False при пробельном user_id (строка 90)."""

    # Arrange / Act / Assert
    assert codes.validate_backup_code_for_user("  ", "somecode") is False


@pytest.mark.security
def test_validate_backup_code_invalid_code_empty() -> None:
    """validate_backup_code_for_user возвращает False при пустом коде (строка 92)."""

    # Arrange / Act / Assert
    assert codes.validate_backup_code_for_user("user1", "") is False


@pytest.mark.security
def test_validate_backup_code_invalid_code_whitespace() -> None:
    """validate_backup_code_for_user возвращает False при пробельном коде (строка 92)."""

    # Arrange / Act / Assert
    assert codes.validate_backup_code_for_user("user1", "   ") is False


@pytest.mark.security
def test_validate_backup_code_exception_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Исключение в verify_factor обрабатывается и возвращает False (строки 101-107)."""

    # Arrange
    class BrokenManager:
        def verify_factor(self, user_id: str, ftype: str, credential: str) -> bool:
            raise RuntimeError("verify exploded")

    ctx: Any = type("Ctx", (), {"mfa_manager": BrokenManager()})()
    monkeypatch.setattr(codes, "get_app_context", lambda: ctx)

    # Act
    result = codes.validate_backup_code_for_user("user1", "anycode")

    # Assert
    assert result is False


@pytest.mark.security
def test_remove_backup_codes_invalid_user_id() -> None:
    """remove_backup_codes_for_user ничего не делает при пустом user_id (строка 115)."""

    # Arrange / Act — не должно бросать исключение
    codes.remove_backup_codes_for_user("")
    codes.remove_backup_codes_for_user("   ")


@pytest.mark.security
def test_remove_backup_codes_exception_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Исключение в remove_factor обрабатывается без проброса (строки 122-123)."""

    # Arrange
    class BrokenManager:
        def remove_factor(self, user_id: str, ftype: str) -> None:
            raise RuntimeError("remove failed")

    ctx: Any = type("Ctx", (), {"mfa_manager": BrokenManager()})()
    monkeypatch.setattr(codes, "get_app_context", lambda: ctx)

    # Act — не должно бросать исключение
    codes.remove_backup_codes_for_user("user1")


@pytest.mark.security
def test_get_backup_codes_status_invalid_user_id() -> None:
    """get_backup_codes_status возвращает ошибку при пустом user_id (строка 143)."""

    # Arrange / Act
    result = codes.get_backup_codes_status("")

    # Assert
    assert "error" in result
    assert "user_id" in (result.get("error") or "")


@pytest.mark.security
def test_get_backup_codes_status_exception_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Исключение в _export_state обрабатывается и возвращает error (строки 154-160)."""

    # Arrange
    def bad_export(user_id: str) -> None:
        raise RuntimeError("state exploded")

    monkeypatch.setattr(codes, "_export_state", bad_export)

    # Act
    result = codes.get_backup_codes_status("user1")

    # Assert
    assert "error" in result
    assert "state exploded" in (result.get("error") or "")


@pytest.mark.security
def test_get_backup_codes_audit_invalid_user_id() -> None:
    """get_backup_codes_audit возвращает [] при пустом user_id (строка 168)."""

    # Arrange / Act / Assert
    assert codes.get_backup_codes_audit("") == []
    assert codes.get_backup_codes_audit("   ") == []


@pytest.mark.security
def test_get_backup_codes_audit_exception_handler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Исключение в _export_state обрабатывается и возвращает [] (строки 176-182)."""

    # Arrange
    def bad_export(user_id: str) -> None:
        raise RuntimeError("audit exploded")

    monkeypatch.setattr(codes, "_export_state", bad_export)

    # Act
    result = codes.get_backup_codes_audit("user1")

    # Assert
    assert result == []


@pytest.mark.security
def test_get_backup_code_secret_invalid_user_id() -> None:
    """get_backup_code_secret_for_storage поднимает PermissionError при пустом user_id (строка 191)."""

    # Arrange / Act / Assert
    with pytest.raises(PermissionError, match="Invalid user_id"):
        codes.get_backup_code_secret_for_storage("", "somecode")


@pytest.mark.security
def test_get_backup_code_secret_invalid_code_empty() -> None:
    """get_backup_code_secret_for_storage поднимает PermissionError при пустом коде (строка 193)."""

    # Arrange / Act / Assert
    with pytest.raises(PermissionError, match="Invalid backup code"):
        codes.get_backup_code_secret_for_storage("user1", "")


@pytest.mark.security
def test_get_backup_code_secret_invalid_code_whitespace() -> None:
    """get_backup_code_secret_for_storage поднимает PermissionError при пробельном коде (строка 193)."""

    # Arrange / Act / Assert
    with pytest.raises(PermissionError, match="Invalid backup code"):
        codes.get_backup_code_secret_for_storage("user1", "   ")


@pytest.mark.security
def test_export_state_returns_empty_dict_when_export_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_export_state возвращает {} если export_factor_state вернул None (строка 39)."""

    # Arrange
    class ManagerWithNoneExport:
        def export_factor_state(self, user_id: str, ftype: str) -> Optional[Dict[str, Any]]:
            return None

    ctx: Any = type("Ctx", (), {"mfa_manager": ManagerWithNoneExport()})()
    monkeypatch.setattr(codes, "get_app_context", lambda: ctx)

    # Act
    result = codes._export_state("anyuser")

    # Assert
    assert result == {}
