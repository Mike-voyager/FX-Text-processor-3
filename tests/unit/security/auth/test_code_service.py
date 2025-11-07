import pytest
import threading
from typing import Any, Dict, List, Iterator, cast

import security.auth.code_service as codes


class DummyManager:
    def __init__(self) -> None:
        self._factors: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

    def setup_factor(self, user_id: str, ftype: str, **kwargs: Any) -> None:
        codes_lst = [
            {"code": f"C-{i}", "used": False} for i in range(kwargs.get("count", 1))
        ]
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
        # Имитация — только "safe" считается валидным кодом
        return credential == "safe"

    def remove_factor(self, user_id: str, ftype: str) -> None:
        if user_id in self._factors and ftype in self._factors[user_id]:
            self._factors[user_id].pop(ftype)


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
def isolate_manager_lock(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(codes, "_manager_lock", threading.RLock())
    yield


def test_issue_backup_codes_for_user() -> None:
    codes_list = codes.issue_backup_codes_for_user("u1", count=3, ttlsec=12)
    assert isinstance(codes_list, list)
    assert len(codes_list) == 3
    assert all(isinstance(x, dict) and "code" in x for x in codes_list)


def test_validate_backup_code_for_user_success() -> None:
    codes.issue_backup_codes_for_user("vuser", count=2)
    assert codes.validate_backup_code_for_user("vuser", "safe") is True
    assert codes.validate_backup_code_for_user("vuser", "wrong") is False


def test_partial_revoke_backup_code() -> None:
    codes.issue_backup_codes_for_user("pr", count=1)
    assert codes.partial_revoke_backup_code("pr", "safe") is True
    assert codes.partial_revoke_backup_code("pr", "wrong") is False


def test_remove_backup_codes_for_user() -> None:
    codes.issue_backup_codes_for_user("rmu", count=1)
    codes.remove_backup_codes_for_user("rmu")
    assert codes.get_backup_codes_status("rmu") == {}


def test_get_backup_codes_status() -> None:
    codes.issue_backup_codes_for_user("s1", count=2, ttlsec=66)
    st = codes.get_backup_codes_status("s1")
    assert isinstance(st, dict)
    assert "codes" in st and isinstance(st["codes"], list)


def test_get_backup_codes_status_empty() -> None:
    assert codes.get_backup_codes_status("none") == {}


def test_get_backup_codes_audit() -> None:
    codes.issue_backup_codes_for_user("auser", count=2)
    aud = codes.get_backup_codes_audit("auser")
    assert isinstance(aud, list)
    assert 999 in aud


def test_get_backup_codes_audit_empty() -> None:
    assert codes.get_backup_codes_audit("unknown") == []


def test_get_backup_code_secret_for_storage_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codes.issue_backup_codes_for_user("sec", count=1)
    # Патчим derive_key_argon2id чтобы он возвращал видимую строку
    monkeypatch.setattr(
        codes, "derive_key_argon2id", lambda pw, salt, length: b"k" * length
    )
    secret = codes.get_backup_code_secret_for_storage("sec", "safe")
    assert isinstance(secret, bytes)
    assert secret.startswith(b"k")


def test_get_backup_code_secret_for_storage_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codes.issue_backup_codes_for_user("failuser", count=1)
    monkeypatch.setattr(
        codes, "derive_key_argon2id", lambda pw, salt, length: b"k" * length
    )
    with pytest.raises(PermissionError):
        codes.get_backup_code_secret_for_storage("failuser", "notvalid")
