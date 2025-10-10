# -*- coding: utf-8 -*-
"""
Модуль: second_method/fido2.py

Назначение: Production FIDO2/WebAuthn второй фактор для FX Text Processor 3.
- Поддержка YubiKey, Windows Hello, multi-device, audit trail и криптографической проверки.
"""

from typing import Dict, Any, List, Optional


class Fido2Factor:
    def setup(
        self, user_id: str, device_info: Optional[Dict[str, Any]] = None, **kwargs: Any
    ) -> Dict[str, Any]:
        if not device_info:
            device_info = {}
        return {"devices": [device_info], "audit": [], "created": kwargs.get("created", None)}

    def remove(self, user_id: str) -> None:
        pass

    def verify(
        self, user_id: str, response: Dict[str, Any], state: Dict[str, Any]
    ) -> Dict[str, Any]:
        from fido2.server import Fido2Server
        from fido2.webauthn import PublicKeyCredentialRequestOptions, PublicKeyCredentialDescriptor

        audit = state.setdefault("audit", [])
        devices: List[Dict[str, Any]] = state.get("devices", [])
        if not devices:
            audit.append({"result": "device_not_found", "response": response})
            return {"status": "fail", "detail": "no_device", "audit": audit}

        res_cid: Optional[str] = response.get("credential_id")
        matched_device = None
        for dev in devices:
            expected_cid = dev.get("credential_id")
            if expected_cid and res_cid and str(res_cid) == str(expected_cid):
                matched_device = dev
                break
        if not matched_device:
            audit.append({"result": "credential_id_mismatch", "response": response})
            return {"status": "fail", "detail": "credential_id_mismatch", "audit": audit}

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

            rp = response.get("rp", {"id": "localhost", "name": "FX Text Processor"})
            from fido2.webauthn import PublicKeyCredentialType

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
                "userHandle": response.get("user_handle", None),
            }
            server.authenticate_complete(
                options, matched_device["credential_id"].encode("utf-8"), authentication_response
            )
            audit.append({"result": "success", "response": response})
            return {"status": "success", "detail": "signature_valid", "audit": audit}
        except Exception as e:
            audit.append({"result": "signature_fail", "error": str(e), "response": response})
            return {"status": "fail", "detail": "signature_fail", "error": str(e), "audit": audit}
