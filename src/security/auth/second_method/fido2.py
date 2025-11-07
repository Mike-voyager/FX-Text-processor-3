# -*- coding: utf-8 -*-
"""
Модуль: security/auth/second_method/fido2.py

RU: Production FIDO2/WebAuthn второй фактор для FX Text Processor 3.
    Поддержка YubiKey, Windows Hello, multi-device, audit trail и криптографической проверки.

EN: Enterprise-grade FIDO2/WebAuthn second factor with YubiKey, Windows Hello,
    multi-device support, audit trail, and cryptographic verification.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional, Final
from datetime import datetime, timezone
from collections import OrderedDict

__all__ = [
    "Fido2Factor",
    "DeviceNotFound",
    "CredentialMismatch",
    "SignatureVerificationFailed",
]

# ---- Constants ----
DEFAULT_RP_ID: Final[str] = "localhost"
DEFAULT_RP_NAME: Final[str] = "FX Text Processor"


# ---- Exceptions ----
class DeviceNotFound(ValueError):
    """No FIDO2 devices registered for user."""


class CredentialMismatch(ValueError):
    """Credential ID does not match any registered device."""


class SignatureVerificationFailed(RuntimeError):
    """FIDO2 signature verification failed."""


# ---- Helpers ----
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_str() -> str:
    return _now().isoformat()


class Fido2Factor:
    """
    FIDO2/WebAuthn second factor with multi-device support and audit trail.

    Features:
    - Multi-device management (YubiKey, Windows Hello, TouchID, etc.)
    - Cryptographic signature verification via fido2 library
    - Full audit trail of authentication attempts
    - Device metadata storage (name, type, registered_at)

    Example:
        >>> factor = Fido2Factor()
        >>> device = {"credential_id": "abc123", "public_key": "...", "name": "YubiKey 5"}
        >>> state = factor.setup("user123", device_info=device)
        >>> response = {"credential_id": "abc123", "challenge": b"...", ...}
        >>> result = factor.verify("user123", response, state)
    """

    def setup(
        self,
        user_id: str,
        device_info: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Register initial FIDO2 device for user.

        Args:
            user_id: User identifier
            device_info: Device metadata dict with keys:
                - credential_id: Unique credential identifier
                - public_key: Public key for signature verification
                - name: Human-readable device name (optional)
                - type: Device type (e.g., "yubikey", "windows_hello") (optional)
            **kwargs: Additional metadata

        Returns:
            State dict with devices, audit log, and timestamps

        Example:
            >>> device = {
            ...     "credential_id": "abc",
            ...     "public_key": "...",
            ...     "name": "YubiKey 5",
            ...     "type": "yubikey"
            ... }
            >>> state = factor.setup("alice", device_info=device)
        """
        created_at = _now_str()
        if device_info is None:
            device_info = {}

        device_info.setdefault("registered_at", created_at)
        device_info.setdefault("name", "Unnamed Device")
        device_info.setdefault("type", "unknown")

        return {
            "devices": [device_info],
            "audit": [],
            "created_at": created_at,
        }

    def remove(self, user_id: str, state: Dict[str, Any]) -> None:
        """
        Remove all FIDO2 devices and invalidate state.

        Args:
            user_id: User identifier
            state: Current factor state

        Side effects:
            - Clears all devices
            - Appends removal event to audit log
        """
        now_str = _now_str()
        state["devices"] = []
        state["audit"] = state.get("audit", [])
        state["audit"].append(
            {
                "action": "remove",
                "timestamp": now_str,
                "user_id": user_id,
            }
        )

    def verify(
        self,
        user_id: str,
        response: Dict[str, Any],
        state: Dict[str, Any],
    ) -> bool:
        """
        Verify FIDO2 authentication response.

        Args:
            user_id: User identifier
            response: Authentication response dict with keys:
                - credential_id: Credential ID from authenticator
                - challenge: Challenge bytes
                - client_data_json: Client data JSON
                - authenticator_data: Authenticator data bytes
                - signature: Signature bytes
                - rp: Relying party dict (optional)
                - user_handle: User handle (optional)
            state: Current factor state

        Returns:
            True if signature is valid

        Raises:
            DeviceNotFound: No devices registered
            CredentialMismatch: Credential ID not found in registered devices
            SignatureVerificationFailed: Invalid signature

        Example:
            >>> response = {
            ...     "credential_id": "abc",
            ...     "challenge": b"random_challenge",
            ...     "client_data_json": "...",
            ...     "authenticator_data": b"...",
            ...     "signature": b"..."
            ... }
            >>> factor.verify("alice", response, state)
            True
        """
        from fido2.server import Fido2Server
        from fido2.webauthn import (
            PublicKeyCredentialRequestOptions,
            PublicKeyCredentialDescriptor,
            PublicKeyCredentialType,
        )

        now_str = _now_str()
        audit = state.setdefault("audit", [])
        devices: List[Dict[str, Any]] = state.get("devices", [])

        if not devices:
            audit.append(
                {
                    "timestamp": now_str,
                    "result": "device_not_found",
                    "response": response,
                }
            )
            raise DeviceNotFound("No FIDO2 devices registered")

        # Find matching device
        res_cid: Optional[str] = response.get("credential_id")
        matched_device = None
        for dev in devices:
            expected_cid = dev.get("credential_id")
            if expected_cid and res_cid and str(res_cid) == str(expected_cid):
                matched_device = dev
                break

        if not matched_device:
            audit.append(
                {
                    "timestamp": now_str,
                    "result": "credential_id_mismatch",
                    "response": response,
                }
            )
            raise CredentialMismatch("Credential ID not found in registered devices")

        # Verify signature
        try:
            challenge = response.get("challenge")
            if challenge is None:
                raise ValueError("challenge required")
            if isinstance(challenge, str):
                challenge_bytes = challenge.encode("utf-8")
            elif isinstance(challenge, bytes):
                challenge_bytes = challenge
            else:
                raise TypeError("challenge must be str or bytes")

            rp = response.get("rp", {"id": DEFAULT_RP_ID, "name": DEFAULT_RP_NAME})

            cred_desc = PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=matched_device["credential_id"].encode("utf-8"),
            )

            options = PublicKeyCredentialRequestOptions(
                challenge=challenge_bytes,
                rp_id=rp["id"],
                allow_credentials=[cred_desc],
            )

            server = Fido2Server(rp)
            authentication_response = {
                "clientDataJSON": response["client_data_json"],
                "authenticatorData": response["authenticator_data"],
                "signature": response["signature"],
                "userHandle": response.get("user_handle"),
            }

            server.authenticate_complete(
                options,
                matched_device["credential_id"].encode("utf-8"),
                authentication_response,
            )

            audit.append(
                {
                    "timestamp": now_str,
                    "result": "success",
                    "device": matched_device.get("name", "unknown"),
                }
            )
            return True

        except Exception as e:
            audit.append(
                {
                    "timestamp": now_str,
                    "result": "signature_fail",
                    "error": str(e),
                    "response": response,
                }
            )
            raise SignatureVerificationFailed(
                f"Signature verification failed: {e}"
            ) from e

    def add_device(
        self,
        state: Dict[str, Any],
        device_info: Dict[str, Any],
    ) -> None:
        """
        Register additional FIDO2 device.

        Args:
            state: Current factor state
            device_info: Device metadata (credential_id, public_key, name, type)

        Side effects:
            - Appends device to devices list
            - Sets registered_at timestamp
        """
        device_info.setdefault("registered_at", _now_str())
        device_info.setdefault("name", "Unnamed Device")
        device_info.setdefault("type", "unknown")
        state.setdefault("devices", []).append(device_info)

    def remove_device(
        self,
        state: Dict[str, Any],
        credential_id: str,
    ) -> bool:
        """
        Remove specific FIDO2 device by credential ID.

        Args:
            state: Current factor state
            credential_id: Credential ID to remove

        Returns:
            True if device was found and removed, False otherwise
        """
        devices = state.get("devices", [])
        for i, dev in enumerate(devices):
            if dev.get("credential_id") == credential_id:
                devices.pop(i)
                state.setdefault("audit", []).append(
                    {
                        "timestamp": _now_str(),
                        "action": "device_removed",
                        "credential_id": credential_id,
                    }
                )
                return True
        return False

    def get_devices(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get list of registered devices.

        Args:
            state: Current factor state

        Returns:
            List of device metadata dicts
        """
        return list(state.get("devices", []))

    def get_device_count(self, state: Dict[str, Any]) -> int:
        """
        Get count of registered devices.

        Args:
            state: Current factor state

        Returns:
            Number of registered devices
        """
        return len(state.get("devices", []))

    def get_audit_log(self, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get full audit trail.

        Args:
            state: Current factor state

        Returns:
            List of audit events
        """
        return list(state.get("audit", []))

    def export_policy(self, deterministic: bool = True) -> Dict[str, Any]:
        """
        Export FIDO2 factor policy configuration.

        Args:
            deterministic: Return ordered dict for stable snapshots

        Returns:
            Policy dict with constants and configuration
        """
        data = {
            "default_rp_id": DEFAULT_RP_ID,
            "default_rp_name": DEFAULT_RP_NAME,
            "multi_device_support": True,
            "cryptographic_verification": True,
        }
        if deterministic:
            return OrderedDict(sorted(data.items(), key=lambda kv: kv[0]))
        return data

    def export_audit(
        self,
        state: Dict[str, Any],
        deterministic: bool = True,
    ) -> Dict[str, Any]:
        """
        Export audit summary for monitoring.

        Args:
            state: Current factor state
            deterministic: Return ordered dict

        Returns:
            Audit summary with device count and event count
        """
        data = {
            "device_count": self.get_device_count(state),
            "audit_events": len(state.get("audit", [])),
            "created_at": state.get("created_at"),
        }
        if deterministic:
            return OrderedDict(sorted(data.items(), key=lambda kv: kv[0]))
        return data
