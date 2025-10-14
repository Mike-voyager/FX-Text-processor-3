import pytest
from typing import Dict, Any
from src.security.auth.second_method.fido2 import Fido2Factor


def test_setup_and_remove() -> None:
    factor = Fido2Factor()
    device_info: Dict[str, Any] = {"credential_id": "ABC", "public_key": b"pk"}
    state: Dict[str, Any] = factor.setup("user1", device_info)
    assert state["devices"][0]["credential_id"] == "ABC"
    factor.remove("user1")  # remove всегда None


def test_verify_no_devices() -> None:
    factor = Fido2Factor()
    state: Dict[str, Any] = {"devices": []}
    response: Dict[str, Any] = {}
    result = factor.verify("user1", response, state)
    assert result["status"] == "fail"
    assert result["detail"] == "no_device"
    assert result["audit"][-1]["result"] == "device_not_found"


def test_verify_credential_id_mismatch() -> None:
    factor = Fido2Factor()
    state: Dict[str, Any] = factor.setup(
        "user1", {"credential_id": "A", "public_key": b"pk"}
    )
    response: Dict[str, Any] = {"credential_id": "B", "challenge": b"test"}
    result = factor.verify("user1", response, state)
    assert result["status"] == "fail"
    assert result["detail"] == "credential_id_mismatch"
    assert result["audit"][-1]["result"] == "credential_id_mismatch"


def test_verify_challenge_type_error() -> None:
    factor = Fido2Factor()
    state: Dict[str, Any] = factor.setup(
        "user1", {"credential_id": "A", "public_key": b"pk"}
    )
    response: Dict[str, Any] = {"credential_id": "A", "challenge": 12345}
    result = factor.verify("user1", response, state)
    assert result["status"] == "fail"
    assert "challenge must be str or bytes" in result.get("error", "")


def test_verify_missing_challenge() -> None:
    factor = Fido2Factor()
    state: Dict[str, Any] = factor.setup(
        "user1", {"credential_id": "A", "public_key": b"pk"}
    )
    response: Dict[str, Any] = {"credential_id": "A"}
    result = factor.verify("user1", response, state)
    assert result["status"] == "fail"
    assert "challenge required" in result.get("error", "")


def test_verify_success_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    factor = Fido2Factor()
    state: Dict[str, Any] = factor.setup(
        "user1", {"credential_id": "CRED", "public_key": b"pk"}
    )
    response: Dict[str, Any] = {
        "credential_id": "CRED",
        "challenge": b"challenge",
        "client_data_json": b"{}",
        "authenticator_data": b"\x00" * 32,
        "signature": b"\x01" * 64,
    }

    class MockServer:
        def authenticate_complete(self, *a: Any, **kw: Any) -> bool:
            return True

    monkeypatch.setattr("fido2.server.Fido2Server", lambda rp: MockServer())
    result = factor.verify("user1", response, state)
    assert result["status"] == "success"
    assert result["detail"] == "signature_valid"
    assert result["audit"][-1]["result"] == "success"


def test_setup_no_device_info() -> None:
    factor = Fido2Factor()
    state: Dict[str, Any] = factor.setup("user42")
    assert len(state["devices"]) == 1  # список с одним пустым dict
    assert state["devices"][0] == {}


def test_verify_signature_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    factor = Fido2Factor()
    state: Dict[str, Any] = factor.setup(
        "user1", {"credential_id": "ERR", "public_key": b"pk"}
    )
    response: Dict[str, Any] = {
        "credential_id": "ERR",
        "challenge": b"challenge",
        "client_data_json": b"{}",
        "authenticator_data": b"\x00" * 32,
        "signature": b"\x01" * 64,
    }

    class MockServer:
        def authenticate_complete(self, *a: Any, **kw: Any) -> bool:
            raise RuntimeError("signature failure")

    monkeypatch.setattr("fido2.server.Fido2Server", lambda rp: MockServer())
    result = factor.verify("user1", response, state)
    assert result["status"] == "fail"
    assert "signature failure" in result["error"]
