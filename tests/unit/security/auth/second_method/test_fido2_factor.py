from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import pytest

from src.security.auth.second_method.fido2 import (
    CredentialMismatch,
    DeviceNotFound,
    Fido2Factor,
    SignatureVerificationFailed,
)


def mk_device_info(
    cid: str = "cid1", pk: str = "pk1", name: str = "YubiKey 5"
) -> Dict[str, Any]:
    return {
        "credential_id": cid,
        "public_key": pk,
        "name": name,
        "type": "yubikey",
    }


def mk_server_response(
    cid: str = "cid1",
    challenge: bytes = b"challenge",
    clientdata: str = "data",
    authdata: bytes = b"auth",
    sig: bytes = b"sig",
) -> Dict[str, Any]:
    return {
        "credential_id": cid,
        "challenge": challenge,
        "client_data_json": clientdata,
        "authenticator_data": authdata,
        "signature": sig,
        "rp": {"id": "localhost", "name": "FX Text Processor"},
        "user_handle": None,
    }


def setup_basic_state_with_device() -> Tuple[Fido2Factor, Dict[str, Any]]:
    factor = Fido2Factor()
    state = factor.setup("userX", device_info=mk_device_info())
    return factor, state


def test_setup_no_device_info() -> None:
    factor = Fido2Factor()
    state = factor.setup("userY")
    assert isinstance(state, dict)
    assert isinstance(state["devices"], list)
    # При отсутствии device_info ожидается 1 unknown device
    assert len(state["devices"]) == 1
    assert state["devices"][0]["type"] == "unknown"


def test_add_device_and_count() -> None:
    factor, state = setup_basic_state_with_device()
    assert len(factor.get_devices(state)) == 1
    assert factor.get_device_count(state) == 1

    # Add new device
    newdev = mk_device_info("cid2", "pk2", "WinHello")
    factor.add_device(state, newdev)
    devices = factor.get_devices(state)
    assert len(devices) == 2
    assert any(d["name"] == "WinHello" for d in devices)


def test_remove_device_by_credential() -> None:
    factor, state = setup_basic_state_with_device()
    # Remove existing
    res = factor.remove_device(state, "cid1")
    assert res
    assert factor.get_device_count(state) == 0
    # Remove non-existent
    res2 = factor.remove_device(state, "nonexistent")
    assert not res2


def test_remove_all_devices() -> None:
    factor, state = setup_basic_state_with_device()
    factor.add_device(state, mk_device_info("cid2", "pk2", "test"))
    factor.remove("userX", state)
    assert state["devices"] == []
    assert any(a.get("action") == "remove" for a in state["audit"])


def test_verify_success_path(monkeypatch: pytest.MonkeyPatch) -> None:
    factor, state = setup_basic_state_with_device()

    def dummy_authenticate_complete(*args: Any, **kwargs: Any) -> bool:
        return True

    monkeypatch.setattr(
        "fido2.server.Fido2Server.authenticate_complete",
        dummy_authenticate_complete,
    )
    response = mk_server_response("cid1")
    assert factor.verify("userX", response, state) is True
    audit = factor.get_audit_log(state)
    assert any(a.get("result") == "success" for a in audit)


def test_verify_no_devices() -> None:
    factor = Fido2Factor()
    state = factor.setup("userA")
    # Удаляем все devices (если "unknown" добавлен)
    state["devices"] = []
    with pytest.raises(DeviceNotFound):
        factor.verify("userA", mk_server_response(), state)


def test_verify_wrong_credential_id() -> None:
    factor, state = setup_basic_state_with_device()
    response = mk_server_response("wrong_cid")
    with pytest.raises(CredentialMismatch):
        factor.verify("userX", response, state)


def test_verify_signature_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    factor, state = setup_basic_state_with_device()

    def dummy_authenticate_complete(*args: Any, **kwargs: Any) -> None:
        raise Exception("Broken signature")

    monkeypatch.setattr(
        "fido2.server.Fido2Server.authenticate_complete",
        dummy_authenticate_complete,
    )
    response = mk_server_response("cid1")
    with pytest.raises(SignatureVerificationFailed):
        factor.verify("userX", response, state)
    audit = factor.get_audit_log(state)
    assert any(a.get("result") == "signature_fail" for a in audit)


def test_audit_and_policy_exports() -> None:
    factor, state = setup_basic_state_with_device()
    pol = factor.export_policy(deterministic=True)
    assert pol["default_rp_id"] == "localhost"
    audit = factor.export_audit(state)
    assert "device_count" in audit


def test_get_audit_log_empty() -> None:
    factor = Fido2Factor()
    state: Dict[str, Any] = {"devices": [], "audit": []}
    assert factor.get_audit_log(state) == []


def test_export_policy_nondeterministic() -> None:
    factor = Fido2Factor()
    res = factor.export_policy(deterministic=False)
    assert isinstance(res, dict) and res.get("multi_device_support", False)


def test_export_audit_nondeterministic() -> None:
    factor, state = setup_basic_state_with_device()
    res = factor.export_audit(state, deterministic=False)
    assert isinstance(res, dict) and "device_count" in res


def test_remove_device_empty() -> None:
    factor = Fido2Factor()
    state: Dict[str, Any] = {"devices": []}
    res = factor.remove_device(state, "doesnotexist")
    assert res is False
