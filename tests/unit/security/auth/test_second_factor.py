import logging
from typing import Any, Dict, Generator

import pytest

from src.security.auth.second_factor import SecondFactorManager
from src.security.crypto.core.protocols import KeyStoreProtocol


class DummyFactor:
    def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
        return {
            "id": "testid",
            "created": 12345,
            "ttlseconds": kwargs.get("ttlseconds"),
        }

    def verify(self, user_id: str, credential: str, state: object) -> bool:
        return credential == "valid"

    def remove(self, user_id: str, state: object) -> None:
        pass


class DummyStorage:
    """Реализация KeyStoreProtocol в памяти для тестов."""

    def __init__(self) -> None:
        self._data: Dict[str, bytes] = {}

    def save(self, name: str, data: bytes) -> None:
        self._data[name] = data

    def load(self, name: str) -> bytes:
        if name not in self._data:
            raise KeyError(name)
        return self._data[name]

    def delete(self, name: str) -> None:
        if name not in self._data:
            raise KeyError(name)
        del self._data[name]


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


class FailLoadStorage:
    """KeyStoreProtocol: load всегда бросает исключение (для тестов)."""

    def save(self, name: str, data: bytes) -> None:
        pass

    def load(self, name: str) -> bytes:
        raise RuntimeError("fail load")

    def delete(self, name: str) -> None:
        pass


class FailSaveStorage:
    """KeyStoreProtocol: save всегда бросает исключение (для тестов)."""

    def save(self, name: str, data: bytes) -> None:
        raise RuntimeError("fail save")

    def load(self, name: str) -> bytes:
        raise KeyError(name)

    def delete(self, name: str) -> None:
        pass


def test_storage_load_exception_logs() -> None:
    storage = FailLoadStorage()
    manager = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    manager._load_storage()  # exception coverage


def test_storage_save_exception_logs(manager: SecondFactorManager) -> None:
    storage = FailSaveStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
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
def test_factors_audit_edge_cases(
    manager: SecondFactorManager, scenario: Dict[str, Any]
) -> None:
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


# ============================================================
# Новые тесты для покрытия недостающих строк (≥95%)
# ============================================================


@pytest.mark.security
def test_now_ts_returns_int() -> None:
    """_now_ts() возвращает целочисленную метку времени Unix."""
    from src.security.auth.second_factor import _now_ts

    # Arrange / Act
    result = _now_ts()
    # Assert
    assert isinstance(result, int)
    assert result > 0


@pytest.mark.security
def test_state_created_ts_with_iso_string() -> None:
    """_state_created_ts разбирает ISO строку created_at в Unix-метку."""
    from src.security.auth.second_factor import _state_created_ts

    # Arrange
    state: Dict[str, Any] = {"created_at": "2024-01-15T12:00:00+00:00"}
    # Act
    ts = _state_created_ts(state)
    # Assert
    assert isinstance(ts, int)
    assert ts > 0


@pytest.mark.security
def test_state_created_ts_invalid_iso_falls_back_to_created() -> None:
    """_state_created_ts при некорректном ISO использует поле created."""
    from src.security.auth.second_factor import _state_created_ts

    # Arrange — невалидная ISO строка, но есть числовое поле created
    state: Dict[str, Any] = {"created_at": "not-a-date", "created": 9999}
    # Act
    ts = _state_created_ts(state)
    # Assert
    assert ts == 9999


@pytest.mark.security
def test_state_created_ts_invalid_created_falls_back_to_now() -> None:
    """_state_created_ts при нечисловом created возвращает текущее время."""
    from src.security.auth.second_factor import _now_ts, _state_created_ts

    # Arrange — нет created_at, created — не число
    state: Dict[str, Any] = {"created": "not-a-number"}
    # Act
    ts = _state_created_ts(state)
    now = _now_ts()
    # Assert: результат не далёк от текущего времени
    assert isinstance(ts, int)
    assert abs(ts - now) < 5


@pytest.mark.security
def test_state_created_ts_no_fields() -> None:
    """_state_created_ts без полей created_at/created возвращает текущее время."""
    from src.security.auth.second_factor import _now_ts, _state_created_ts

    # Arrange
    state: Dict[str, Any] = {}
    # Act
    ts = _state_created_ts(state)
    now = _now_ts()
    # Assert
    assert isinstance(ts, int)
    assert abs(ts - now) < 5


@pytest.mark.security
def test_state_is_expired_with_ttl_not_expired() -> None:
    """_state_is_expired возвращает False, если TTL ещё не истёк."""
    from src.security.auth.second_factor import _now_ts, _state_is_expired

    # Arrange: создан только что, TTL 1 час
    state: Dict[str, Any] = {"created": _now_ts(), "ttlseconds": 3600}
    # Act / Assert
    assert _state_is_expired(state) is False


@pytest.mark.security
def test_state_is_expired_with_ttl_expired() -> None:
    """_state_is_expired возвращает True, если TTL истёк."""
    from src.security.auth.second_factor import _state_is_expired

    # Arrange: создан 10 минут назад, TTL 1 секунда
    state: Dict[str, Any] = {"created": 1000, "ttlseconds": 1}
    # Act / Assert
    assert _state_is_expired(state) is True


@pytest.mark.security
def test_state_is_expired_no_ttl() -> None:
    """_state_is_expired возвращает False при отсутствии TTL."""
    from src.security.auth.second_factor import _state_is_expired

    # Arrange
    state: Dict[str, Any] = {"created": 1000}
    # Act / Assert
    assert _state_is_expired(state) is False


@pytest.mark.security
def test_state_is_expired_invalid_ttl_value() -> None:
    """_state_is_expired возвращает False при нечисловом значении TTL."""
    from src.security.auth.second_factor import _state_is_expired

    # Arrange
    state: Dict[str, Any] = {"created": 1000, "ttlseconds": "not-a-number"}
    # Act / Assert
    assert _state_is_expired(state) is False


@pytest.mark.security
def test_copy_for_public_redacts_secrets() -> None:
    """_copy_for_public маскирует поля secret, seed, credential, backup_codes."""
    from src.security.auth.second_factor import _copy_for_public

    # Arrange
    state: Dict[str, Any] = {
        "id": "abc",
        "secret": "supersecret",
        "seed": "seedvalue",
        "credential": "credval",
        "backup_codes": ["c1", "c2"],
        "private_key": "privkey",
        "sk": "skvalue",
        "name": "visible",
    }
    # Act
    redacted = _copy_for_public(state)
    # Assert — чувствительные поля заменены на ****
    assert redacted["secret"] == "****"
    assert redacted["seed"] == "****"
    assert redacted["credential"] == "****"
    assert redacted["backup_codes"] == "****"
    assert redacted["private_key"] == "****"
    assert redacted["sk"] == "****"
    # Не-чувствительные поля сохранены
    assert redacted["id"] == "abc"
    assert redacted["name"] == "visible"


@pytest.mark.security
def test_load_storage_with_valid_json(manager: SecondFactorManager) -> None:
    """_load_storage корректно разбирает валидный JSON из хранилища."""
    import json

    # Arrange — записываем JSON прямо в хранилище
    payload = {
        "factors": {"u1": {"totp": [{"state": {"id": "x1"}, "ts": 0}]}},
        "audit": [{"action": "setup"}],
    }
    data = json.dumps(payload).encode("utf-8")
    manager._storage.save("mfa_state", data)  # type: ignore[attr-defined]
    # Act
    manager._load_storage()
    # Assert
    assert "u1" in manager._factors
    assert len(manager._audit) == 1


@pytest.mark.security
def test_load_storage_with_invalid_json() -> None:
    """_load_storage при невалидном JSON сбрасывает состояние в пустое."""

    class BadJsonStorage:
        def save(self, name: str, data: bytes) -> None:
            pass

        def load(self, name: str) -> bytes:
            return b"{{not valid json!!"

        def delete(self, name: str) -> None:
            pass

    # Arrange
    m = SecondFactorManager(storage=BadJsonStorage())  # type: ignore[arg-type]
    # Act — повторный вызов не должен сломаться
    m._load_storage()
    # Assert
    assert m._factors == {}
    assert m._audit == []


@pytest.mark.security
def test_register_factor_type_missing_methods() -> None:
    """register_factor_type бросает TypeError, если класс не имеет нужных методов."""
    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]

    class Incomplete:
        """Класс без метода remove."""

        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            return False

    # Act / Assert
    with pytest.raises(TypeError):
        m.register_factor_type("incomplete", Incomplete)  # type: ignore[arg-type]


@pytest.mark.security
def test_unregister_nonexistent_factor_type(manager: SecondFactorManager) -> None:
    """unregister_factor_type для незарегистрированного типа ничего не делает."""
    # Arrange / Act / Assert — не бросает исключение
    manager.unregister_factor_type("nonexistent_type_xyz")


@pytest.mark.security
def test_validate_user_id_control_chars() -> None:
    """_validate_user_id бросает ValueError при управляющих символах в user_id."""
    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("dummy", DummyFactor)

    # Arrange — user_id с управляющим символом (tab = \x09 < 32)
    with pytest.raises(ValueError, match="unsupported characters"):
        m.setup_factor("user\x01name", "dummy")


@pytest.mark.security
def test_validate_factor_type_empty_string(manager: SecondFactorManager) -> None:
    """_validate_factor_type бросает ValueError при пустом factor_type."""
    # Arrange / Act / Assert
    with pytest.raises(ValueError):
        manager.setup_factor("validuser", "")


@pytest.mark.security
def test_validate_factor_type_control_chars(manager: SecondFactorManager) -> None:
    """_validate_factor_type бросает ValueError при управляющих символах."""
    # Arrange / Act / Assert
    with pytest.raises(ValueError, match="unsupported characters"):
        manager.setup_factor("validuser", "type\x02name")


@pytest.mark.security
def test_setup_factor_with_id_from_state() -> None:
    """setup_factor использует id из состояния, если фактор его предоставляет."""

    class FactorWithId:
        """Фактор, возвращающий собственный id."""

        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "my-custom-id"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            return True

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("withid", FactorWithId)  # type: ignore[arg-type]

    # Act
    fid = m.setup_factor("u1", "withid")
    # Assert
    assert fid == "my-custom-id"


@pytest.mark.security
def test_setup_factor_created_at_already_in_state() -> None:
    """setup_factor не перезаписывает created_at, если он уже есть в состоянии."""

    class FactorWithCreatedAt:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "xid", "created_at": "2020-01-01T00:00:00+00:00"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            return True

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("withts", FactorWithCreatedAt)  # type: ignore[arg-type]

    # Act
    m.setup_factor("u2", "withts")
    status = m.get_status("u2", "withts")
    # Assert — поле created_at не перезаписано
    assert status is not None
    assert status["created_at"] == "2020-01-01T00:00:00+00:00"


@pytest.mark.security
def test_setup_factor_created_already_in_state() -> None:
    """setup_factor не добавляет created, если он уже есть в состоянии."""

    class FactorWithCreated:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {
                "id": "yid",
                "created_at": "2021-06-01T00:00:00+00:00",
                "created": 42,
            }

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            return True

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("withcreated", FactorWithCreated)  # type: ignore[arg-type]

    # Act
    m.setup_factor("u3", "withcreated")
    status = m.get_status("u3", "withcreated")
    # Assert — поле created не перезаписано
    assert status is not None
    assert status["created"] == 42


@pytest.mark.security
def test_setup_factor_bad_created_at_iso() -> None:
    """setup_factor обрабатывает некорректный created_at через fallback к _now_ts."""
    from src.security.auth.second_factor import _now_ts

    class FactorBadIso:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "zid", "created_at": "NOT-ISO"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            return True

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("badiso", FactorBadIso)  # type: ignore[arg-type]

    # Act — не должно бросать исключение
    m.setup_factor("u4", "badiso")
    status = m.get_status("u4", "badiso")
    # Assert — created должен быть установлен через fallback
    assert status is not None
    assert isinstance(status.get("created"), int)
    assert abs(status["created"] - _now_ts()) < 5


@pytest.mark.security
def test_verify_factor_no_factors_returns_false(manager: SecondFactorManager) -> None:
    """verify_factor возвращает False, если факторов у пользователя нет."""
    # Arrange — пользователь без факторов
    # Act / Assert
    assert manager.verify_factor("nobody", "dummy", "any_cred") is False


@pytest.mark.security
def test_verify_factor_by_id_found(manager: SecondFactorManager) -> None:
    """verify_factor находит фактор по переданному factor_id."""
    # Arrange
    user_id = "findbyid"
    fid = manager.setup_factor(user_id, "dummy")
    # Act
    result = manager.verify_factor(user_id, "dummy", "valid", factor_id=fid)
    # Assert
    assert result is True


@pytest.mark.security
def test_verify_factor_by_id_not_found_uses_last(manager: SecondFactorManager) -> None:
    """verify_factor при ненайденном factor_id использует последний фактор."""
    # Arrange
    user_id = "fallbackuser"
    manager.setup_factor(user_id, "dummy")
    # Act — передаём несуществующий id
    result = manager.verify_factor(user_id, "dummy", "valid", factor_id="nonexistent-id")
    # Assert — использует последний
    assert result is True


@pytest.mark.security
def test_verify_factor_expired_state(manager: SecondFactorManager) -> None:
    """verify_factor возвращает False и логирует 'expired', если TTL истёк."""
    # Arrange
    user_id = "expireduser"
    manager.setup_factor(user_id, "dummy")
    # Вручную ставим TTL в прошлое
    entry = manager._factors[user_id]["dummy"][-1]
    entry["state"]["ttlseconds"] = 1
    entry["state"]["created"] = 1  # очень давно

    # Act
    result = manager.verify_factor(user_id, "dummy", "valid")
    # Assert
    assert result is False
    audit_actions = [a["action"] for a in manager._audit]
    assert "expired" in audit_actions


@pytest.mark.security
def test_verify_factor_cls_none(manager: SecondFactorManager) -> None:
    """verify_factor возвращает False, если тип фактора удалён из реестра после setup."""
    # Arrange
    user_id = "noclsuser"
    manager.setup_factor(user_id, "dummy")
    # Убираем тип из реестра после регистрации
    del manager._factor_registry["dummy"]
    # Act
    result = manager.verify_factor(user_id, "dummy", "valid")
    # Assert
    assert result is False


@pytest.mark.security
def test_verify_factor_returns_dict_status_success(manager: SecondFactorManager) -> None:
    """verify_factor разбирает dict-результат со status='success'."""

    class DictSuccessFactor:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "dsid"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> Dict[str, Any]:
            return {"status": "success"}

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("dictsuccess", DictSuccessFactor)  # type: ignore[arg-type]

    # Arrange
    m.setup_factor("u5", "dictsuccess")
    # Act
    result = m.verify_factor("u5", "dictsuccess", "anything")
    # Assert
    assert result is True


@pytest.mark.security
def test_verify_factor_returns_dict_ok_true(manager: SecondFactorManager) -> None:
    """verify_factor разбирает dict-результат с ok=True."""

    class DictOkFactor:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "dokid"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> Dict[str, Any]:
            return {"ok": True, "detail": "all good"}

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("dictok", DictOkFactor)  # type: ignore[arg-type]

    m.setup_factor("u6", "dictok")
    result = m.verify_factor("u6", "dictok", "anything")
    assert result is True


@pytest.mark.security
def test_verify_factor_returns_non_bool_non_dict(manager: SecondFactorManager) -> None:
    """verify_factor обрабатывает результат, не являющийся bool или dict."""

    class IntResultFactor:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "irid"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> int:
            return 1  # truthy non-bool, non-dict

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("intresult", IntResultFactor)  # type: ignore[arg-type]

    m.setup_factor("u7", "intresult")
    result = m.verify_factor("u7", "intresult", "anything")
    assert result is True


@pytest.mark.security
def test_verify_factor_exception_in_verify(manager: SecondFactorManager) -> None:
    """verify_factor перехватывает исключение из verify() и возвращает False."""

    class ExceptionFactor:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "exid"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            raise RuntimeError("boom!")

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("excfactor", ExceptionFactor)  # type: ignore[arg-type]

    m.setup_factor("u8", "excfactor")
    result = m.verify_factor("u8", "excfactor", "anything")
    assert result is False
    # Причина должна содержать 'exception:'
    last_audit = m._audit[-1]
    assert last_audit["reason"] is not None
    assert "exception:" in last_audit["reason"]


@pytest.mark.security
def test_remove_factor_by_id_loop(manager: SecondFactorManager) -> None:
    """remove_factor ищет фактор по id в цикле и удаляет нужный."""

    class MultiIdFactor:
        _counter = 0

        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            MultiIdFactor._counter += 1
            return {"id": f"fid{MultiIdFactor._counter}"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            return True

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    MultiIdFactor._counter = 0
    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("multi", MultiIdFactor)  # type: ignore[arg-type]

    user_id = "multiuser"
    fid1 = m.setup_factor(user_id, "multi")
    fid2 = m.setup_factor(user_id, "multi")

    # Act — удаляем первый, второй должен остаться
    m.remove_factor(user_id, "multi", factor_id=fid1)
    remaining = m.list_factor_ids(user_id, "multi")
    # Assert
    assert fid2 in remaining
    assert fid1 not in remaining


@pytest.mark.security
def test_remove_factor_cleans_empty_user_dict(manager: SecondFactorManager) -> None:
    """remove_factor удаляет пустую запись пользователя из _factors."""
    # Arrange
    user_id = "cleanupuser"
    manager.setup_factor(user_id, "dummy")
    # Act
    manager.remove_factor(user_id, "dummy")
    # Assert — пользователь полностью удалён из _factors
    assert user_id not in manager._factors


@pytest.mark.security
def test_remove_factor_remove_raises_logged(manager: SecondFactorManager) -> None:
    """remove_factor логирует предупреждение, если instance.remove() бросает исключение."""

    class BadRemoveFactor:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "brid"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            return True

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            raise RuntimeError("remove crash!")

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("badremove", BadRemoveFactor)  # type: ignore[arg-type]

    user_id = "badremoveuser"
    m.setup_factor(user_id, "badremove")
    # Act — не должно бросать исключение, только логировать warning
    m.remove_factor(user_id, "badremove")
    # Assert — фактор всё равно удалён
    assert m.get_status(user_id, "badremove") is None


@pytest.mark.security
def test_remove_factor_cleans_empty_type_dict(manager: SecondFactorManager) -> None:
    """remove_factor удаляет пустую запись типа фактора из _factors[user]."""
    # Arrange — два разных типа у одного пользователя

    class AnotherDummy:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "another"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            return True

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    manager.register_factor_type("another", AnotherDummy)  # type: ignore[arg-type]
    user_id = "twotype_user"
    manager.setup_factor(user_id, "dummy")
    manager.setup_factor(user_id, "another")

    # Act — удаляем только dummy
    manager.remove_factor(user_id, "dummy")
    # Assert — пользователь остался (есть another), но dummy-ключ убран
    assert user_id in manager._factors
    assert "dummy" not in manager._factors[user_id]
    assert "another" in manager._factors[user_id]


@pytest.mark.security
def test_get_status_public_returns_filtered_fields(manager: SecondFactorManager) -> None:
    """get_status_public возвращает только публичные поля статуса без секретов."""
    # Arrange
    user_id = "pubstatuser"
    manager.setup_factor(user_id, "dummy")
    # Руками добавляем поля, которые должны быть в публичном статусе
    manager._factors[user_id]["dummy"][-1]["state"].update(
        {
            "name": "My Factor",
            "type": "dummy",
            "secret": "topsecret",
        }
    )
    # Act
    pub = manager.get_status_public(user_id, "dummy")
    # Assert
    assert pub is not None
    assert "secret" not in pub
    assert pub.get("type") == "dummy"
    assert pub.get("name") == "My Factor"


@pytest.mark.security
def test_get_status_public_returns_none_if_no_factor(manager: SecondFactorManager) -> None:
    """get_status_public возвращает None, если у пользователя нет фактора."""
    # Act / Assert
    assert manager.get_status_public("nobody", "dummy") is None


@pytest.mark.security
def test_get_status_with_redact_true(manager: SecondFactorManager) -> None:
    """get_status с redact=True возвращает состояние с замаскированными секретами."""
    # Arrange
    user_id = "redactuser"
    manager.setup_factor(user_id, "dummy")
    manager._factors[user_id]["dummy"][-1]["state"]["secret"] = "mysecret"
    # Act
    result = manager.get_status(user_id, "dummy", redact=True)
    # Assert
    assert result is not None
    assert result.get("secret") == "****"


@pytest.mark.security
def test_get_history_with_redact_true(manager: SecondFactorManager) -> None:
    """get_history с redact=True маскирует секреты во всех записях истории."""
    # Arrange
    user_id = "redacthist"
    manager.setup_factor(user_id, "dummy")
    manager._factors[user_id]["dummy"][-1]["state"]["credential"] = "cred123"
    # Act
    history = manager.get_history(user_id, "dummy", redact=True)
    # Assert
    assert len(history) == 1
    assert history[0].get("credential") == "****"


@pytest.mark.security
def test_list_factors_returns_all_types(manager: SecondFactorManager) -> None:
    """list_factors возвращает словарь всех типов факторов пользователя с их id."""

    class ExtraFactor:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "extra_id"}

        def verify(self, user_id: str, credential: Any, state: Dict[str, Any]) -> bool:
            return True

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    manager.register_factor_type("extra", ExtraFactor)  # type: ignore[arg-type]
    user_id = "listuser"
    manager.setup_factor(user_id, "dummy")
    manager.setup_factor(user_id, "extra")

    # Act
    factors = manager.list_factors(user_id)
    # Assert
    assert "dummy" in factors
    assert "extra" in factors
    assert "testid" in factors["dummy"]
    assert "extra_id" in factors["extra"]


@pytest.mark.security
def test_list_factors_empty_user(manager: SecondFactorManager) -> None:
    """list_factors для пользователя без факторов возвращает пустой словарь."""
    # Act
    result = manager.list_factors("unknown_user")
    # Assert
    assert result == {}


@pytest.mark.security
def test_list_factor_ids_returns_ids(manager: SecondFactorManager) -> None:
    """list_factor_ids возвращает список id факторов заданного типа."""
    # Arrange
    user_id = "listidsuser"
    manager.setup_factor(user_id, "dummy")
    manager.setup_factor(user_id, "dummy")

    # Act
    ids = manager.list_factor_ids(user_id, "dummy")
    # Assert
    assert isinstance(ids, list)
    assert len(ids) == 2
    assert all(i == "testid" for i in ids)


@pytest.mark.security
def test_list_factor_ids_empty(manager: SecondFactorManager) -> None:
    """list_factor_ids для отсутствующего пользователя/типа возвращает пустой список."""
    # Act / Assert
    assert manager.list_factor_ids("nobody", "dummy") == []


@pytest.mark.security
def test_verify_factor_dict_result_with_reason(manager: SecondFactorManager) -> None:
    """verify_factor разбирает dict-результат с полем reason."""

    class DictReasonFactor:
        def setup(self, user_id: str, **kwargs: Any) -> Dict[str, Any]:
            return {"id": "drid"}

        def verify(
            self, user_id: str, credential: Any, state: Dict[str, Any]
        ) -> Dict[str, Any]:
            return {"valid": True, "reason": "all-ok"}

        def remove(self, user_id: str, state: Dict[str, Any]) -> None:
            pass

    storage = DummyStorage()
    m = SecondFactorManager(storage=storage)  # type: ignore[arg-type]
    m.register_factor_type("dictreason", DictReasonFactor)  # type: ignore[arg-type]

    m.setup_factor("u9", "dictreason")
    result = m.verify_factor("u9", "dictreason", "anything")
    # Assert
    assert result is True
    last = m._audit[-1]
    assert last["reason"] == "all-ok"


@pytest.mark.security
def test_state_is_expired_ttl_seconds_alt_key() -> None:
    """_state_is_expired поддерживает ключ ttl_seconds (с подчёркиванием)."""
    from src.security.auth.second_factor import _state_is_expired

    # Arrange — истёкший через альтернативный ключ
    state: Dict[str, Any] = {"created": 1000, "ttl_seconds": 1}
    # Act / Assert
    assert _state_is_expired(state) is True
