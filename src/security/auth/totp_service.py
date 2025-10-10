# src/security/auth/totp_service.py

import pyotp
import qrcode
import base64
from io import BytesIO

from src.security.auth.second_factor import SecondFactorManager


def generate_totp_secret() -> str:
    return base64.b32encode(pyotp.random_base32().encode()).decode()


def get_totp_provisioning_uri(
    secret: str, username: str, app_name: str = "FX Text Processor"
) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=app_name)


def generate_qr_code(data: str) -> bytes:
    img = qrcode.make(data)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


def setup_totp_for_user(user_id: str, username: str):
    secret = generate_totp_secret()
    mgr = SecondFactorManager()
    mgr.setup_factor(user_id, "totp", secret=secret)
    provisioning_uri = get_totp_provisioning_uri(secret, username)
    qr = generate_qr_code(provisioning_uri)
    return {"secret": secret, "qr": qr, "uri": provisioning_uri}
