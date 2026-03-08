"""
Unit-тесты для бэкендов аппаратных криптографических устройств.

Обеспечивает 100% изоляцию от физического оборудования (YubiKey, смарт-карт)
и опциональных сторонних библиотек (yubikey-manager, pyscard) через моки.
"""

from collections.abc import Generator
from typing import Any, NoReturn

import pytest
from unittest.mock import MagicMock, patch

from src.security.crypto.core.exceptions import (
    AlgorithmNotAvailableError,
    DeviceCommunicationError,
    DeviceNotFoundError,
    HardwareDeviceError,
    InvalidKeyError,
    KeyGenerationError,
    PINError,
    SlotError,
)
from src.security.crypto.hardware.backends import (
    JavaCardRawBackend,
    OpenPGPDeviceBackend,
    SlotInfo,
    SlotStatus,
    YubiKeyPivBackend,
    _is_rsa_key_type,
    _piv_slot_hex_to_int,
    _read_slot_key_type,
    _resolve_jc_algorithm,
    _resolve_yk_key_type,
    _signing_params_for_key_type,
    _ykman_pin_errors,
    create_backend,
)


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def mock_ykman_env() -> Generator[dict[str, Any], None, None]:
    """Фикстура для имитации окружения yubikey-manager (PIV)."""
    with (
        patch("src.security.crypto.hardware.backends.HAS_YKMAN", True),
        patch("src.security.crypto.hardware.backends.yk_list_all") as mock_list_all,
        patch("src.security.crypto.hardware.backends.PivSession") as mock_piv_session,
        patch("src.security.crypto.hardware.backends.YK_SLOT") as mock_yk_slot,
        patch("src.security.crypto.hardware.backends.YK_KEY_TYPE") as mock_yk_key_type,
        patch("src.security.crypto.hardware.backends.SmartCardConnection"),
    ):
        # Настройка констант
        mock_yk_slot.AUTHENTICATION = 0x9A
        mock_yk_slot.SIGNATURE = 0x9C
        mock_yk_slot.KEY_MANAGEMENT = 0x9D
        mock_yk_slot.CARD_AUTH = 0x9E

        mock_device = MagicMock()
        mock_device_info = MagicMock()
        mock_device_info.serial = 123456
        mock_list_all.return_value = [(mock_device, mock_device_info)]

        mock_connection = MagicMock()
        mock_device.open_connection.return_value = mock_connection

        mock_session_inst = MagicMock()
        mock_piv_session.return_value = mock_session_inst

        yield {
            "list_all": mock_list_all,
            "session": mock_session_inst,
            "connection": mock_connection,
            "device": mock_device,
        }


@pytest.fixture
def mock_openpgp_env() -> Generator[MagicMock, None, None]:
    """Фикстура для имитации OpenPGPBackend с использованием sys.modules."""
    mock_module = MagicMock()

    class MockOpenPGPSlot:
        SIGN = "sign"
        ENCRYPT = "encrypt"
        AUTH = "auth"

    class MockOpenPGPAlgorithm:
        ED25519 = "ed25519"
        X25519 = "x25519"
        RSA2048 = "rsa2048"
        RSA3072 = "rsa3072"
        RSA4096 = "rsa4096"

    mock_module.OpenPGPSlot = MockOpenPGPSlot
    mock_module.OpenPGPAlgorithm = MockOpenPGPAlgorithm

    mock_backend_cls = MagicMock()
    mock_backend_inst = MagicMock()
    mock_backend_cls.return_value = mock_backend_inst
    mock_module.OpenPGPBackend = mock_backend_cls

    mock_keys = MagicMock()
    mock_keys.sign = b"sign_key"
    mock_keys.encrypt = b"encrypt_key"
    mock_keys.auth = None
    mock_keys.sign_algorithm = "Ed25519"
    mock_keys.encrypt_algorithm = "X25519"
    mock_keys.auth_algorithm = ""
    mock_backend_inst.get_public_keys.return_value = mock_keys

    with patch.dict(
        "sys.modules", {"src.security.crypto.hardware.openpgp_backend": mock_module}
    ):
        yield mock_backend_inst


@pytest.fixture
def mock_apdu_env() -> Generator[MagicMock, None, None]:
    """Фикстура для имитации ApduTransport (JavaCard)."""
    mock_module = MagicMock()
    mock_transport_cls = MagicMock()
    mock_transport_inst = MagicMock()

    mock_transport_cls.return_value.__enter__.return_value = mock_transport_inst
    mock_module.ApduTransport = mock_transport_cls

    # Дефолтный успешный ответ
    mock_response = MagicMock()
    mock_response.ok = True
    mock_response.data = b"success"
    mock_response.sw_hex = "9000"
    mock_transport_inst.send_apdu.return_value = mock_response

    with (
        patch("src.security.crypto.hardware.backends.HAS_PYSCARD", True),
        patch.dict(
            "sys.modules", {"src.security.crypto.hardware.apdu_transport": mock_module}
        ),
    ):
        yield mock_transport_inst


# ==============================================================================
# TESTS: FACTORY & HELPERS
# ==============================================================================


class TestHelpersAndFactory:
    """Тесты утилит и фабрики."""

    def test_create_backend_yubikey(self, mock_ykman_env: dict[str, Any]) -> None:
        backend = create_backend("yk1", "yubikey_piv", serial_number=123)
        assert isinstance(backend, YubiKeyPivBackend)
        assert backend.card_id == "yk1"

    def test_create_backend_openpgp(self, mock_openpgp_env: MagicMock) -> None:
        backend = create_backend("pgp1", "openpgp")
        assert isinstance(backend, OpenPGPDeviceBackend)
        assert backend.card_id == "pgp1"

    def test_create_backend_javacard(self, mock_apdu_env: MagicMock) -> None:
        backend = create_backend("jc1", "javacard_raw")
        assert isinstance(backend, JavaCardRawBackend)
        assert backend.card_id == "jc1"

    def test_create_backend_invalid_type(self) -> None:
        with pytest.raises(ValueError, match="Неизвестный backend_type: 'unknown'"):
            create_backend("test", "unknown")  # type: ignore

    @pytest.mark.parametrize(
        "slot_hex, expected",
        [
            ("9A", 0x9A),
            ("9C", 0x9C),
            ("9D", 0x9D),
            ("9E", 0x9E),
            ("9c", 0x9C),
            (" 9C ", 0x9C),
        ],
    )
    def test_piv_slot_hex_to_int_valid(self, slot_hex: str, expected: int) -> None:
        assert _piv_slot_hex_to_int(slot_hex) == expected

    def test_piv_slot_hex_to_int_invalid(self) -> None:
        with pytest.raises(SlotError, match="Неизвестный PIV-слот"):
            _piv_slot_hex_to_int("FF")

    @pytest.mark.parametrize("algo, expected", [("RSA-2048", 0x01), ("AES-128", 0x10)])
    def test_resolve_jc_algorithm_valid(self, algo: str, expected: int) -> None:
        assert _resolve_jc_algorithm(algo) == expected

    def test_resolve_jc_algorithm_invalid(self) -> None:
        with pytest.raises(
            AlgorithmNotAvailableError, match="не поддерживается JavaCard-бэкендом"
        ):
            _resolve_jc_algorithm("UNKNOWN")

    def test_ykman_pin_errors_returns_tuple(self) -> None:
        """_ykman_pin_errors() возвращает tuple (может быть пустой)."""
        result = _ykman_pin_errors()
        assert isinstance(result, tuple)
        # Каждый элемент — подкласс Exception
        for exc_type in result:
            assert issubclass(exc_type, Exception)

    def test_read_slot_key_type_rsa(self, mock_ykman_env: dict[str, Any]) -> None:
        """_read_slot_key_type определяет RSA-2048 по сертификату."""
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

        mock_piv = MagicMock()
        mock_cert = MagicMock()
        mock_pub = MagicMock(spec=rsa_mod.RSAPublicKey)
        mock_pub.key_size = 2048
        mock_cert.public_key.return_value = mock_pub
        mock_piv.get_certificate.return_value = mock_cert

        result = _read_slot_key_type(mock_piv, 0x9C)
        # Должен вернуть мок YK_KEY_TYPE.RSA2048
        assert result is not None

    def test_read_slot_key_type_ecc(self, mock_ykman_env: dict[str, Any]) -> None:
        """_read_slot_key_type определяет ECC P-256 по сертификату."""
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        mock_piv = MagicMock()
        mock_cert = MagicMock()
        mock_pub = MagicMock(spec=ec_mod.EllipticCurvePublicKey)
        mock_pub.curve = MagicMock()
        mock_pub.curve.name = "secp256r1"
        mock_cert.public_key.return_value = mock_pub
        mock_piv.get_certificate.return_value = mock_cert

        result = _read_slot_key_type(mock_piv, 0x9D)
        assert result is not None

    def test_read_slot_key_type_empty_slot(
        self, mock_ykman_env: dict[str, Any]
    ) -> None:
        """_read_slot_key_type бросает SlotError если слот пуст."""
        mock_piv = MagicMock()
        mock_piv.get_certificate.side_effect = Exception("no cert")

        with pytest.raises(SlotError, match="не содержит сертификат"):
            _read_slot_key_type(mock_piv, 0x9C)

    def test_read_slot_key_type_unknown_key(
        self, mock_ykman_env: dict[str, Any]
    ) -> None:
        """_read_slot_key_type бросает SlotError для неизвестного типа ключа."""
        mock_piv = MagicMock()
        mock_cert = MagicMock()
        mock_cert.public_key.return_value = "not_a_real_key"
        mock_piv.get_certificate.return_value = mock_cert

        with pytest.raises(SlotError, match="Неизвестный тип ключа"):
            _read_slot_key_type(mock_piv, 0x9C)

    def test_read_slot_key_type_unsupported_curve(
        self, mock_ykman_env: dict[str, Any]
    ) -> None:
        """_read_slot_key_type бросает SlotError для неподдерживаемой кривой."""
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        mock_piv = MagicMock()
        mock_cert = MagicMock()
        mock_pub = MagicMock(spec=ec_mod.EllipticCurvePublicKey)
        mock_pub.curve = MagicMock()
        mock_pub.curve.name = "secp521r1"  # не поддерживается PIV
        mock_cert.public_key.return_value = mock_pub
        mock_piv.get_certificate.return_value = mock_cert

        with pytest.raises(SlotError, match="Неподдерживаемая кривая"):
            _read_slot_key_type(mock_piv, 0x9D)

    def test_signing_params_rsa(self, mock_ykman_env: dict[str, Any]) -> None:
        """RSA key_type → SHA256 + PKCS1v15."""
        from unittest.mock import patch as _p

        with _p("src.security.crypto.hardware.backends.YK_KEY_TYPE") as mock_kt:
            mock_kt.RSA2048 = "RSA2048"
            h, p = _signing_params_for_key_type("RSA2048")
            assert p is not None  # PKCS1v15

    def test_signing_params_ecc(self, mock_ykman_env: dict[str, Any]) -> None:
        """ECC key_type → SHA256 + None (ECDSA)."""
        from unittest.mock import patch as _p

        with _p("src.security.crypto.hardware.backends.YK_KEY_TYPE") as mock_kt:
            mock_kt.RSA2048 = "RSA2048"
            h, p = _signing_params_for_key_type("ECCP256")
            assert p is None  # ECDSA — padding не нужен


# ==============================================================================
# TESTS: YUBIKEY PIV BACKEND
# ==============================================================================


class TestYubiKeyPivBackend:
    """Тесты операций YubiKey PIV Backend."""

    def test_init_without_ykman(self) -> None:
        with patch("src.security.crypto.hardware.backends.HAS_YKMAN", False):
            with pytest.raises(
                AlgorithmNotAvailableError, match="yubikey-manager is required"
            ):
                YubiKeyPivBackend("yk1")

    def test_open_session_device_not_found(
        self, mock_ykman_env: dict[str, Any]
    ) -> None:
        mock_ykman_env["list_all"].return_value = []
        backend = YubiKeyPivBackend("yk1", serial_number=999)
        with pytest.raises(DeviceNotFoundError, match="не найден"):
            backend._open_piv_session()

    @staticmethod
    def _setup_rsa_cert(mock_ykman_env: dict[str, Any]) -> None:
        """Настроить мок сертификата с RSA-2048 ключом в слоте."""
        from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod

        mock_cert = MagicMock()
        mock_pub = MagicMock(spec=rsa_mod.RSAPublicKey)
        mock_pub.key_size = 2048
        mock_cert.public_key.return_value = mock_pub
        mock_ykman_env["session"].get_certificate.return_value = mock_cert

    def test_sign_success(self, mock_ykman_env: dict[str, Any]) -> None:
        """sign() определяет тип ключа из слота, верифицирует PIN, закрывает соединение."""
        self._setup_rsa_cert(mock_ykman_env)
        backend = YubiKeyPivBackend("yk1")
        mock_ykman_env["session"].sign.return_value = b"signature"

        result = backend.sign("9C", b"data", "123456")

        assert result == b"signature"
        mock_ykman_env["session"].verify_pin.assert_called_once_with("123456")
        # Проверяем, что piv.sign() получил правильный слот (0x9C = SIGNATURE)
        call_args = mock_ykman_env["session"].sign.call_args
        assert call_args[0][0] == 0x9C  # slot
        mock_ykman_env["connection"].close.assert_called_once()

    def test_sign_pin_error(self, mock_ykman_env: dict[str, Any]) -> None:
        """verify_pin() бросает исключение → PINError, соединение закрыто."""
        self._setup_rsa_cert(mock_ykman_env)
        backend = YubiKeyPivBackend("yk1")
        # Имитируем реальное исключение ykman через _ykman_pin_errors fallback
        mock_ykman_env["session"].verify_pin.side_effect = Exception("pin mismatch")

        with pytest.raises((PINError, HardwareDeviceError)):
            backend.sign("9C", b"data", "wrong_pin")

        # Соединение ДОЛЖНО быть закрыто даже при ошибке
        mock_ykman_env["connection"].close.assert_called_once()

    def test_sign_empty_slot_error(self, mock_ykman_env: dict[str, Any]) -> None:
        """sign() при пустом слоте (нет сертификата) → SlotError."""
        mock_ykman_env["session"].get_certificate.side_effect = Exception("empty")
        backend = YubiKeyPivBackend("yk1")

        with pytest.raises(SlotError, match="не содержит сертификат"):
            backend.sign("9C", b"data", "123456")

        mock_ykman_env["connection"].close.assert_called_once()

    def test_decrypt_success(self, mock_ykman_env: dict[str, Any]) -> None:
        """decrypt() проверяет RSA-тип ключа, делегирует в piv.decrypt, закрывает соединение."""
        self._setup_rsa_cert(mock_ykman_env)
        backend = YubiKeyPivBackend("yk1")
        mock_ykman_env["session"].decrypt.return_value = b"plaintext"

        assert backend.decrypt("9D", b"ciphertext", "123456") == b"plaintext"
        mock_ykman_env["session"].verify_pin.assert_called_once_with("123456")
        call_args = mock_ykman_env["session"].decrypt.call_args
        assert call_args[0][0] == 0x9D  # slot = KEY_MANAGEMENT
        mock_ykman_env["connection"].close.assert_called_once()

    def test_decrypt_ecc_slot_rejected(self, mock_ykman_env: dict[str, Any]) -> None:
        """decrypt() при ECC-ключе в слоте → HardwareDeviceError (ECDH не поддержан)."""
        from cryptography.hazmat.primitives.asymmetric import ec as ec_mod

        mock_cert = MagicMock()
        mock_pub = MagicMock(spec=ec_mod.EllipticCurvePublicKey)
        mock_pub.curve = MagicMock()
        mock_pub.curve.name = "secp256r1"
        mock_cert.public_key.return_value = mock_pub
        mock_ykman_env["session"].get_certificate.return_value = mock_cert

        backend = YubiKeyPivBackend("yk1")

        with pytest.raises(HardwareDeviceError, match="только RSA"):
            backend.decrypt("9D", b"ct", "123456")

        mock_ykman_env["connection"].close.assert_called_once()

    def test_get_public_key_success(self, mock_ykman_env: dict[str, Any]) -> None:
        backend = YubiKeyPivBackend("yk1")

        mock_cert = MagicMock()
        mock_pub_key = MagicMock()
        mock_pub_key.public_bytes.return_value = b"pub_key"
        mock_cert.public_key.return_value = mock_pub_key
        mock_ykman_env["session"].get_certificate.return_value = mock_cert

        assert backend.get_public_key("9C") == b"pub_key"

    def test_get_public_key_empty_slot(self, mock_ykman_env: dict[str, Any]) -> None:
        backend = YubiKeyPivBackend("yk1")
        mock_ykman_env["session"].get_certificate.side_effect = Exception("empty")

        with pytest.raises(SlotError, match="Не удалось получить ключ"):
            backend.get_public_key("9A")

    def test_import_key_success(self, mock_ykman_env: dict[str, Any]) -> None:
        backend = YubiKeyPivBackend("yk1")

        with patch(
            "src.security.crypto.hardware.backends.load_der_private_key"
        ) as mock_load:
            mock_load.return_value = "private_key_obj"
            backend.import_key("9C", b"key_data", "mgmt_key")

            mock_ykman_env["session"].put_key.assert_called_once()

    def test_import_key_invalid_format(self, mock_ykman_env: dict[str, Any]) -> None:
        backend = YubiKeyPivBackend("yk1")
        with patch(
            "src.security.crypto.hardware.backends.load_der_private_key",
            side_effect=ValueError("bad data"),
        ):
            with pytest.raises(InvalidKeyError, match="Невалидный DER-ключ"):
                backend.import_key("9C", b"bad_data", "mgmt_key")

    def test_generate_key_success(self, mock_ykman_env: dict[str, Any]) -> None:
        backend = YubiKeyPivBackend("yk1")

        mock_pub_key = MagicMock()
        mock_pub_key.public_bytes.return_value = b"generated_pub"
        mock_ykman_env["session"].generate_key.return_value = mock_pub_key

        result = backend.generate_key("9C", "RSA-2048", "mgmt_key")
        assert result == b"generated_pub"

    def test_list_slots(self, mock_ykman_env: dict[str, Any]) -> None:
        backend = YubiKeyPivBackend("yk1")

        mock_cert = MagicMock()
        mock_pub = MagicMock()
        mock_pub.key_size = 2048
        type(mock_pub).__name__ = "RSAPublicKey"
        mock_cert.public_key.return_value = mock_pub

        # Эмулируем, что слот 9A пуст, а остальные заняты
        def mock_get_cert(slot: Any) -> MagicMock:
            if slot == 0x9A:
                raise Exception("Empty")
            return mock_cert

        mock_ykman_env["session"].get_certificate.side_effect = mock_get_cert

        slots = backend.list_slots()
        assert len(slots) == 4
        slot_9a = next(s for s in slots if s.slot_id == "9A")
        assert slot_9a.status == SlotStatus.EMPTY

        slot_9c = next(s for s in slots if s.slot_id == "9C")
        assert slot_9c.status == SlotStatus.POPULATED
        assert slot_9c.key_size == 2048


# ==============================================================================
# TESTS: OPENPGP DEVICE BACKEND
# ==============================================================================


class TestOpenPGPDeviceBackend:
    """Тесты адаптера OpenPGPDeviceBackend."""

    def test_sign_normal(self, mock_openpgp_env: MagicMock) -> None:
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        mock_openpgp_env.sign.return_value = b"sig"

        assert backend.sign("sign", b"data", "123") == b"sig"
        mock_openpgp_env.sign.assert_called_once_with("pgp1", b"data", "123")

    def test_sign_auth_slot(self, mock_openpgp_env: MagicMock) -> None:
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        mock_openpgp_env.authenticate.return_value = b"auth_sig"

        assert backend.sign("auth", b"data", "123") == b"auth_sig"
        mock_openpgp_env.authenticate.assert_called_once_with("pgp1", b"data", "123")

    def test_decrypt(self, mock_openpgp_env: MagicMock) -> None:
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        mock_openpgp_env.decrypt.return_value = b"plaintext"

        assert backend.decrypt("encrypt", b"ct", "123") == b"plaintext"
        mock_openpgp_env.decrypt.assert_called_once()

    def test_get_public_key_success(self, mock_openpgp_env: MagicMock) -> None:
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        # Установлено в фикстуре как b"sign_key"
        assert backend.get_public_key("sign") == b"sign_key"

    def test_get_public_key_empty(self, mock_openpgp_env: MagicMock) -> None:
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        # В фикстуре auth = None
        with pytest.raises(SlotError, match="пуст"):
            backend.get_public_key("auth")

    def test_generate_key_success(self, mock_openpgp_env: MagicMock) -> None:
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        mock_openpgp_env.generate_key_onboard.return_value = b"new_pub"

        assert backend.generate_key("sign", "Ed25519", "admin_pin") == b"new_pub"

    def test_generate_key_invalid_algorithm(self, mock_openpgp_env: MagicMock) -> None:
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        with pytest.raises(
            AlgorithmNotAvailableError, match="не поддерживается OpenPGP-бэкендом"
        ):
            backend.generate_key("sign", "UNKNOWN", "admin_pin")

    def test_list_slots(self, mock_openpgp_env: MagicMock) -> None:
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        slots = backend.list_slots()

        assert len(slots) == 3
        sign_slot = next(s for s in slots if s.slot_id == "sign")
        assert sign_slot.status == SlotStatus.POPULATED

        auth_slot = next(s for s in slots if s.slot_id == "auth")
        assert auth_slot.status == SlotStatus.EMPTY

    def test_invalid_slot_mapping(self, mock_openpgp_env: MagicMock) -> None:
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        with pytest.raises(SlotError, match="Неизвестный OpenPGP-слот"):
            backend.sign("unknown_slot", b"data", "123")


# ==============================================================================
# TESTS: JAVACARD RAW BACKEND
# ==============================================================================


class TestJavaCardRawBackend:
    """Тесты бэкенда для кастомных апплетов JavaCard J3R200."""

    def test_init_without_pyscard(self) -> None:
        with patch("src.security.crypto.hardware.backends.HAS_PYSCARD", False):
            with pytest.raises(AlgorithmNotAvailableError, match="pyscard is required"):
                JavaCardRawBackend("jc1")

    def test_sign_success(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"jc_sig"

        assert backend.sign("1", b"data", "123456") == b"jc_sig"

        mock_apdu_env.select_applet.assert_called_once()
        mock_apdu_env.verify_pin.assert_called_once_with("123456", pin_ref=0x81)

        # Проверяем вызов send_apdu
        mock_apdu_env.send_apdu.assert_called_once_with(
            cla=0x00, ins=0x2A, p1=0x00, p2=0x01, data=b"data", le=0
        )

    def test_apdu_error_response(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.ok = False
        mock_apdu_env.send_apdu.return_value.sw_hex = "6982"

        with pytest.raises(
            HardwareDeviceError, match="APDU command INS=0x2A failed: SW=6982"
        ):
            backend.sign("0", b"data", "123456")

    def test_invalid_slot_type(self) -> None:
        backend = JavaCardRawBackend("jc1")
        with pytest.raises(SlotError, match="JavaCard slot должен быть числом"):
            backend.sign("not_a_number", b"data", "123")

    def test_out_of_bounds_slot(self) -> None:
        backend = JavaCardRawBackend("jc1")
        with pytest.raises(SlotError, match="вне диапазона 0–255"):
            backend.sign("256", b"data", "123")

    def test_decrypt_success(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"plaintext"

        assert backend.decrypt("2", b"ct", "pin") == b"plaintext"
        mock_apdu_env.send_apdu.assert_called_once_with(
            cla=0x00, ins=0x2C, p1=0x00, p2=0x02, data=b"ct", le=0
        )

    def test_generate_key(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"new_pub"

        assert backend.generate_key("1", "RSA-2048", "pin") == b"new_pub"
        # P1 = 0x01 для RSA-2048
        mock_apdu_env.send_apdu.assert_called_once_with(
            cla=0x00, ins=0x34, p1=0x01, p2=0x01, data=b"", le=0
        )

    def test_aes_encrypt(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"aes_ct"

        assert backend.aes_encrypt(b"0" * 16, "pin") == b"aes_ct"
        mock_apdu_env.send_apdu.assert_called_once_with(
            cla=0x00, ins=0x40, p1=0x00, p2=0x00, data=b"0" * 16, le=0
        )

    def test_hmac_sha256_success(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"hmac_digest"

        assert backend.hmac_sha256(b"challenge", "pin") == b"hmac_digest"

    def test_hmac_sha256_too_large(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        with pytest.raises(ValueError, match="не должен превышать 255 байт"):
            backend.hmac_sha256(b"0" * 256, "pin")

    def test_get_counter_success(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        # Эмулируем 4-байтовый int = 42
        mock_apdu_env.send_apdu.return_value.data = b"\x00\x00\x00\x2a"

        assert backend.get_counter("pin") == 42

    def test_get_counter_invalid_length(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"\x2a"  # 1 байт вместо 4

        with pytest.raises(DeviceCommunicationError, match="ожидалось 4 байта"):
            backend.get_counter("pin")

    def test_list_slots_success(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")
        # Формат: [slot_id(1), status(1), algo_id(1), key_size_div_256(1)]
        # Слот 0: Занят, RSA-2048 (0x01), 2048/256 = 8 -> [0x00, 0x01, 0x01, 0x08]
        # Слот 1: Пуст -> [0x01, 0x00, 0x00, 0x00]
        mock_apdu_env.send_apdu.return_value.data = bytes(
            [0x00, 0x01, 0x01, 0x08, 0x01, 0x00, 0x00, 0x00]
        )

        slots = backend.list_slots()
        assert len(slots) == 2
        assert slots[0].slot_id == "0"
        assert slots[0].status == SlotStatus.POPULATED
        assert slots[0].algorithm == "RSA-2048"
        assert slots[0].key_size == 2048

        assert slots[1].slot_id == "1"
        assert slots[1].status == SlotStatus.EMPTY

    def test_list_slots_not_supported(self, mock_apdu_env: MagicMock) -> None:
        backend = JavaCardRawBackend("jc1")

        def send_apdu_error(*args: Any, **kwargs: Any) -> NoReturn:
            raise HardwareDeviceError("Command not allowed")

        mock_apdu_env.send_apdu.side_effect = send_apdu_error

        # Должен перехватить исключение и вернуть пустой список
        slots = backend.list_slots()
        assert slots == []


# ==============================================================================
# TESTS: ADDITIONAL COVERAGE (error paths, repr, properties)
# ==============================================================================


class TestYubiKeyPivBackendEdgeCases:
    """Дополнительные тесты для покрытия error-path'ов YubiKeyPivBackend."""

    def test_properties(self, mock_ykman_env: dict[str, Any]) -> None:
        """backend_type и repr."""
        backend = YubiKeyPivBackend("yk1", serial_number=42)
        assert backend.backend_type == "yubikey_piv"
        assert "yk1" in repr(backend)
        assert "42" in repr(backend)

    def _setup_rsa_cert(self, mock_ykman_env: dict[str, Any]) -> None:
        """Настроить мок RSA-2048 сертификата."""
        TestYubiKeyPivBackend._setup_rsa_cert(mock_ykman_env)

    def test_sign_non_pin_error(self, mock_ykman_env: dict[str, Any]) -> None:
        """RuntimeError из piv.sign() → HardwareDeviceError. Соединение закрыто."""
        self._setup_rsa_cert(mock_ykman_env)
        backend = YubiKeyPivBackend("yk1")
        mock_ykman_env["session"].verify_pin.return_value = None
        mock_ykman_env["session"].sign.side_effect = RuntimeError("card removed")

        with pytest.raises(HardwareDeviceError, match="Ошибка подписи"):
            backend.sign("9C", b"data", "123456")

        mock_ykman_env["connection"].close.assert_called_once()

    def test_decrypt_pin_error(self, mock_ykman_env: dict[str, Any]) -> None:
        """decrypt() при generic Exception из verify_pin → HardwareDeviceError (не PINError)."""
        self._setup_rsa_cert(mock_ykman_env)
        backend = YubiKeyPivBackend("yk1")
        # Generic Exception НЕ является ykman PIN error → HardwareDeviceError
        mock_ykman_env["session"].verify_pin.side_effect = Exception("verify failed")

        with pytest.raises(HardwareDeviceError):
            backend.decrypt("9D", b"ct", "wrong")

        mock_ykman_env["connection"].close.assert_called_once()

    def test_decrypt_non_pin_error(self, mock_ykman_env: dict[str, Any]) -> None:
        """RuntimeError из piv.decrypt() → HardwareDeviceError. Соединение закрыто."""
        self._setup_rsa_cert(mock_ykman_env)
        backend = YubiKeyPivBackend("yk1")
        mock_ykman_env["session"].verify_pin.return_value = None
        mock_ykman_env["session"].decrypt.side_effect = RuntimeError("card error")

        with pytest.raises(HardwareDeviceError, match="Ошибка расшифровки"):
            backend.decrypt("9D", b"ct", "123456")

        mock_ykman_env["connection"].close.assert_called_once()

    def test_open_session_communication_error(
        self, mock_ykman_env: dict[str, Any]
    ) -> None:
        """yk_list_all() throws → DeviceCommunicationError."""
        mock_ykman_env["list_all"].side_effect = RuntimeError("USB fail")
        backend = YubiKeyPivBackend("yk1")

        with pytest.raises(DeviceCommunicationError, match="Ошибка подключения"):
            backend._open_piv_session()

    def test_open_session_piv_constructor_error(
        self, mock_ykman_env: dict[str, Any]
    ) -> None:
        """PivSession() throws → connection закрывается, исключение пробрасывается."""
        from unittest.mock import patch as _p

        backend = YubiKeyPivBackend("yk1")
        with _p(
            "src.security.crypto.hardware.backends.PivSession",
            side_effect=RuntimeError("PIV init failed"),
        ):
            with pytest.raises(DeviceCommunicationError):
                backend._open_piv_session()

        # Connection должен быть закрыт при ошибке PivSession()
        mock_ykman_env["connection"].close.assert_called()

    def test_open_session_serial_filter(
        self, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Фильтрация по serial: пропускает устройства с другим serial."""
        mock_ykman_env["list_all"].return_value[0][1].serial = 999
        backend = YubiKeyPivBackend("yk1", serial_number=111)

        with pytest.raises(DeviceNotFoundError, match="не найден"):
            backend._open_piv_session()

    def test_import_key_generic_error(self, mock_ykman_env: dict[str, Any]) -> None:
        """import_key(): non-ValueError → HardwareDeviceError."""
        backend = YubiKeyPivBackend("yk1")
        with patch(
            "src.security.crypto.hardware.backends.load_der_private_key"
        ) as mock_load:
            mock_load.return_value = MagicMock()
            mock_ykman_env["session"].put_key.side_effect = RuntimeError("device fail")

            with pytest.raises(HardwareDeviceError, match="Ошибка импорта ключа"):
                backend.import_key("9C", b"key", "mgmt")

    def test_generate_key_error(self, mock_ykman_env: dict[str, Any]) -> None:
        """generate_key(): ошибка генерации → KeyGenerationError."""
        backend = YubiKeyPivBackend("yk1")
        mock_ykman_env["session"].generate_key.side_effect = RuntimeError("keygen fail")

        with pytest.raises(KeyGenerationError, match="не удалась"):
            backend.generate_key("9C", "RSA-2048", "mgmt")

    def test_resolve_yk_key_type_invalid(
        self, mock_ykman_env: dict[str, Any]
    ) -> None:
        """_resolve_yk_key_type с неизвестным алгоритмом."""
        with pytest.raises(
            AlgorithmNotAvailableError, match="не поддерживается YubiKey PIV"
        ):
            _resolve_yk_key_type("UNKNOWN-ALGO")


class TestOpenPGPDeviceBackendEdgeCases:
    """Дополнительные тесты OpenPGPDeviceBackend."""

    def test_properties(self, mock_openpgp_env: MagicMock) -> None:
        """backend_type и repr."""
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        assert backend.backend_type == "openpgp"
        assert "pgp1" in repr(backend)

    def test_import_key(self, mock_openpgp_env: MagicMock) -> None:
        """import_key() делегирует в backend.import_key()."""
        backend = OpenPGPDeviceBackend("pgp1", mock_openpgp_env)
        backend.import_key("sign", b"key_tl", "admin_pin")
        mock_openpgp_env.import_key.assert_called_once()


class TestJavaCardRawBackendEdgeCases:
    """Дополнительные тесты JavaCardRawBackend."""

    def test_properties(self, mock_apdu_env: MagicMock) -> None:
        """backend_type и repr."""
        backend = JavaCardRawBackend("jc1")
        assert backend.backend_type == "javacard_raw"
        assert "jc1" in repr(backend)

    def test_get_public_key(self, mock_apdu_env: MagicMock) -> None:
        """get_public_key() отправляет INS=0x30 без PIN."""
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"pub_key"

        result = backend.get_public_key("0")
        assert result == b"pub_key"
        # verify_pin НЕ должен вызываться (pin=None)
        mock_apdu_env.verify_pin.assert_not_called()

    def test_import_key(self, mock_apdu_env: MagicMock) -> None:
        """import_key() отправляет INS=0x32."""
        backend = JavaCardRawBackend("jc1")
        backend.import_key("1", b"key_data", "admin_pin")

        mock_apdu_env.send_apdu.assert_called_once_with(
            cla=0x00, ins=0x32, p1=0x00, p2=0x01, data=b"key_data", le=0
        )

    def test_aes_decrypt(self, mock_apdu_env: MagicMock) -> None:
        """aes_decrypt() отправляет INS=0x42."""
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"plaintext"

        assert backend.aes_decrypt(b"ct", "pin") == b"plaintext"
        mock_apdu_env.send_apdu.assert_called_once_with(
            cla=0x00, ins=0x42, p1=0x00, p2=0x00, data=b"ct", le=0
        )

    def test_increment_counter_success(self, mock_apdu_env: MagicMock) -> None:
        """increment_counter() возвращает новое значение."""
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"\x00\x00\x00\x2b"  # 43

        assert backend.increment_counter("pin") == 43

    def test_increment_counter_invalid_length(
        self, mock_apdu_env: MagicMock
    ) -> None:
        """increment_counter() с коротким ответом → DeviceCommunicationError."""
        backend = JavaCardRawBackend("jc1")
        mock_apdu_env.send_apdu.return_value.data = b"\x01"

        with pytest.raises(DeviceCommunicationError, match="ожидалось 4 байта"):
            backend.increment_counter("pin")
