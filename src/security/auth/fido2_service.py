# src/security/auth/fido2_service.py

from fido2.client import Fido2Client, WindowsClient
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from src.security.auth.second_factor import SecondFactorManager


def register_fido2_device(user_id, username, display_name):
    # 1: Detect device
    devices = list(CtapHidDevice.list_devices())
    if not devices:
        client = WindowsClient(origin="https://localhost")
    else:
        client = Fido2Client(devices[0], origin="https://localhost")
    rp = PublicKeyCredentialRpEntity(id="localhost", name="FX Text Processor")
    server = Fido2Server(rp)
    user_entity = PublicKeyCredentialUserEntity(
        id=user_id.encode(),
        name=username,
        display_name=display_name,
    )
    registration_data, state = server.register_begin(user=user_entity, credentials=[])
    result = client.make_credential(registration_data["publicKey"])
    auth_data = server.register_complete(
        state=state,
        client_data=result.client_data,
        attestation_object=result.attestation_object,
    )
    device_info = {
        "credential_id": auth_data.credential_data.credential_id.hex(),
        "public_key": auth_data.credential_data.public_key,
        "aaguid": auth_data.credential_data.aaguid.hex(),
    }
    mfa_manager = SecondFactorManager()
    mfa_manager.setup_factor(user_id, "fido2", device_info=device_info)
    return device_info


def authenticate_with_fido2(user_id):
    # Получаем устройcтво, запускаем проверку
    # (экземпляр SecondFactorManager должен быть инициализирован)
    # Затем вызываем manager.verify_factor(user_id, "fido2", response)
    # Response формируется через клиент get_assertion, как в python-fido2 примерах
    pass
