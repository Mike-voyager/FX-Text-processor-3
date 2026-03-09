# pyright: reportPrivateUsage=false
"""
Unit-тесты для менеджера аппаратных криптографических устройств.

Обеспечивает 100% изоляцию от физического оборудования (YubiKey, смарт-карт)
и опциональных сторонних библиотек (yubikey-manager, pyscard) через моки.
"""

from __future__ import annotations

import dataclasses
import threading
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
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
from src.security.crypto.hardware.hardware_crypto import (
    _ATR_DATABASE,
    PIV_VALID_SLOTS,
    CardProfile,
    DeviceCapabilities,
    ExternalKeypair,
    HardwareCryptoManager,
    SmartcardInfo,
    _detect_card_profile,
    _make_smartcard_capabilities,
    _make_yubikey_capabilities,
    _select_aid,
)

MODULE = "src.security.crypto.hardware.hardware_crypto"


# ==============================================================================
# MOCK EXCEPTIONS
# ==============================================================================


class MockCardConnectionException(Exception):
    """Имитация pyscard CardConnectionException."""


class MockNoCardException(Exception):
    """Имитация pyscard NoCardException."""


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def manager() -> HardwareCryptoManager:
    """Создать менеджер без зависимостей."""
    return HardwareCryptoManager()


@pytest.fixture
def mock_pyscard_env() -> Generator[dict[str, Any], None, None]:
    """Фикстура для имитации окружения pyscard."""
    with (
        patch(f"{MODULE}.has_pyscard", True),
        patch(f"{MODULE}.sc_readers") as mock_readers,
        patch(f"{MODULE}.CardConnectionException", MockCardConnectionException),
        patch(f"{MODULE}.NoCardException", MockNoCardException),
    ):
        reader = MagicMock()
        reader.__str__ = MagicMock(return_value="Test Reader 0")  # type: ignore[method-assign]

        conn = MagicMock()
        reader.createConnection.return_value = conn
        conn.getATR.return_value = [0x3B, 0x00]  # Unknown ATR

        mock_readers.return_value = [reader]

        yield {
            "readers": mock_readers,
            "reader": reader,
            "connection": conn,
        }


@pytest.fixture
def mock_ykman_env() -> Generator[dict[str, Any], None, None]:
    """Фикстура для имитации окружения yubikey-manager."""
    with (
        patch(f"{MODULE}.has_ykman", True),
        patch(f"{MODULE}.yk_list_all") as mock_list_all,
        patch(f"{MODULE}.PivSession") as mock_piv_session,
        patch(f"{MODULE}.YK_SLOT") as mock_yk_slot,
        patch(f"{MODULE}.YK_KEY_TYPE") as mock_yk_key_type,
        patch(f"{MODULE}.YK_CAPABILITY") as mock_yk_cap,
        patch(f"{MODULE}.YK_TRANSPORT") as mock_yk_transport,
    ):
        mock_yk_slot.AUTHENTICATION = 0x9A
        mock_yk_slot.SIGNATURE = 0x9C
        mock_yk_slot.KEY_MANAGEMENT = 0x9D
        mock_yk_slot.CARD_AUTH = 0x9E

        mock_yk_key_type.RSA2048 = "RSA2048"
        mock_yk_key_type.RSA3072 = "RSA3072"
        mock_yk_key_type.RSA4096 = "RSA4096"
        mock_yk_key_type.ECCP256 = "ECCP256"
        mock_yk_key_type.ECCP384 = "ECCP384"

        mock_yk_cap.PIV = 0x10
        mock_yk_cap.OPENPGP = 0x08
        mock_yk_cap.FIDO2 = 0x200
        mock_yk_cap.OATH = 0x20
        mock_yk_cap.OTP = 0x01

        mock_device = MagicMock()
        mock_device_info = MagicMock()
        mock_device_info.serial = 10620473
        mock_device_info.version = (5, 2, 4)
        mock_device_info.config = None

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
            "device_info": mock_device_info,
            "yk_slot": mock_yk_slot,
            "yk_key_type": mock_yk_key_type,
            "yk_capability": mock_yk_cap,
            "yk_transport": mock_yk_transport,
            "piv_session_cls": mock_piv_session,
        }


# ==============================================================================
# 1. TestDeviceCapabilities
# ==============================================================================


class TestDeviceCapabilities:
    """Тесты для dataclass DeviceCapabilities."""

    def test_defaults(self) -> None:
        """Все поля по умолчанию — пустые/False."""
        caps = DeviceCapabilities()
        assert caps.rsa_key_sizes == ()
        assert caps.ecc_curves == ()
        assert caps.ed25519_piv is False
        assert caps.can_generate_onboard is False

    def test_piv_algorithms_rsa_only(self) -> None:
        """PIV с RSA-2048."""
        caps = DeviceCapabilities(rsa_key_sizes=(2048,))
        assert caps.piv_algorithms == ("RSA-2048",)

    def test_piv_algorithms_rsa_and_ecc(self) -> None:
        """PIV с RSA + ECC."""
        caps = DeviceCapabilities(rsa_key_sizes=(2048,), ecc_curves=("P256", "P384"))
        assert caps.piv_algorithms == ("RSA-2048", "ECC-P256", "ECC-P384")

    def test_piv_algorithms_with_ed25519(self) -> None:
        """PIV с Ed25519 (FW 5.7+)."""
        caps = DeviceCapabilities(ed25519_piv=True)
        assert "Ed25519" in caps.piv_algorithms

    def test_piv_algorithms_with_x25519(self) -> None:
        """PIV с X25519 (FW 5.7+)."""
        caps = DeviceCapabilities(x25519_piv=True)
        assert "X25519" in caps.piv_algorithms

    def test_all_algorithms_deduplication(self) -> None:
        """Ed25519 через PIV и OpenPGP — без дубликатов."""
        caps = DeviceCapabilities(ed25519_piv=True, ed25519_openpgp=True)
        algos = caps.all_algorithms
        assert algos.count("Ed25519") == 1

    def test_all_algorithms_sorted(self) -> None:
        """all_algorithms возвращает отсортированный tuple."""
        caps = DeviceCapabilities(
            rsa_key_sizes=(2048,),
            ecc_curves=("P256",),
            ed25519_openpgp=True,
        )
        algos = caps.all_algorithms
        assert algos == tuple(sorted(algos))

    def test_all_algorithms_openpgp_only_ed25519(self) -> None:
        """Ed25519 только через OpenPGP — появляется в all, не в PIV."""
        caps = DeviceCapabilities(ed25519_openpgp=True, ed25519_piv=False)
        assert "Ed25519" in caps.all_algorithms
        assert "Ed25519" not in caps.piv_algorithms

    def test_frozen_dataclass(self) -> None:
        """DeviceCapabilities — frozen, нельзя менять поля."""
        caps = DeviceCapabilities()
        with pytest.raises(dataclasses.FrozenInstanceError):
            caps.ed25519_piv = True  # type: ignore[misc]

    def test_empty_algorithms(self) -> None:
        """Пустой DeviceCapabilities — пустые алгоритмы."""
        caps = DeviceCapabilities()
        assert caps.piv_algorithms == ()
        assert caps.all_algorithms == ()

    def test_full_capabilities(self) -> None:
        """Полный набор возможностей FW 5.7+."""
        caps = DeviceCapabilities(
            rsa_key_sizes=(2048, 3072, 4096),
            ecc_curves=("P256", "P384"),
            ed25519_piv=True,
            ed25519_openpgp=True,
            x25519_piv=True,
            x25519_openpgp=True,
        )
        piv = caps.piv_algorithms
        assert "RSA-2048" in piv
        assert "RSA-3072" in piv
        assert "RSA-4096" in piv
        assert "ECC-P256" in piv
        assert "ECC-P384" in piv
        assert "Ed25519" in piv
        assert "X25519" in piv


# ==============================================================================
# 2. TestMakeYubikeyCapabilities
# ==============================================================================


class TestMakeYubikeyCapabilities:
    """Тесты для _make_yubikey_capabilities()."""

    def test_fw_old_no_openpgp_ed25519(self) -> None:
        """FW < 5.2.3 — нет OpenPGP Ed25519."""
        caps = _make_yubikey_capabilities((5, 1, 0))
        assert caps.ed25519_openpgp is False
        assert caps.x25519_openpgp is False

    def test_fw_523_openpgp_ed25519(self) -> None:
        """FW 5.2.3 — OpenPGP Ed25519/X25519 есть, PIV нет."""
        caps = _make_yubikey_capabilities((5, 2, 3))
        assert caps.ed25519_openpgp is True
        assert caps.x25519_openpgp is True
        assert caps.ed25519_piv is False
        assert caps.x25519_piv is False

    def test_fw_524(self) -> None:
        """FW 5.2.4 — типичный YubiKey 5 NFC."""
        caps = _make_yubikey_capabilities((5, 2, 4))
        assert caps.rsa_key_sizes == (2048,)
        assert caps.ed25519_openpgp is True
        assert caps.ed25519_piv is False

    def test_fw_570_full(self) -> None:
        """FW 5.7.0+ — полный набор."""
        caps = _make_yubikey_capabilities((5, 7, 0))
        assert caps.rsa_key_sizes == (2048, 3072, 4096)
        assert caps.ed25519_piv is True
        assert caps.x25519_piv is True
        assert caps.ed25519_openpgp is True

    def test_fw_572(self) -> None:
        """FW 5.7.2 — новее 5.7.0, все фичи."""
        caps = _make_yubikey_capabilities((5, 7, 2))
        assert caps.ed25519_piv is True

    def test_always_has_common_features(self) -> None:
        """Все YubiKey поддерживают hmac_sha1, openpgp, oath, fido2."""
        for fw in [(5, 1, 0), (5, 2, 4), (5, 7, 0)]:
            caps = _make_yubikey_capabilities(fw)
            assert caps.hmac_sha1 is True
            assert caps.has_openpgp is True
            assert caps.has_oath is True
            assert caps.has_fido2 is True
            assert caps.can_generate_onboard is True


# ==============================================================================
# 3. TestCardProfile
# ==============================================================================


class TestCardProfile:
    """Тесты для dataclass CardProfile."""

    def test_defaults(self) -> None:
        """Значения по умолчанию."""
        profile = CardProfile(card_type="piv")
        assert profile.manufacturer == "Unknown"
        assert profile.chip == "Unknown"
        assert profile.detected_via == "name_fallback"

    def test_custom_values(self) -> None:
        """Создание с кастомными значениями."""
        profile = CardProfile(
            card_type="openpgp",
            manufacturer="NXP",
            chip="JCOP4 P71",
            detected_via="atr",
        )
        assert profile.card_type == "openpgp"
        assert profile.manufacturer == "NXP"

    def test_frozen(self) -> None:
        """CardProfile — frozen dataclass."""
        profile = CardProfile(card_type="piv")
        with pytest.raises(dataclasses.FrozenInstanceError):
            profile.card_type = "openpgp"  # type: ignore[misc]


# ==============================================================================
# 4. TestSelectAid
# ==============================================================================


class TestSelectAid:
    """Тесты для _select_aid()."""

    def test_sw_success(self) -> None:
        """SW=9000 → True."""
        conn = MagicMock()
        conn.transmit.return_value = ([], 0x90, 0x00)
        assert _select_aid(conn, b"\xa0\x00\x00\x03\x08") is True

    def test_sw_failure(self) -> None:
        """SW≠9000 → False."""
        conn = MagicMock()
        conn.transmit.return_value = ([], 0x6A, 0x82)
        assert _select_aid(conn, b"\xa0\x00\x00\x03\x08") is False

    def test_exception_returns_false(self) -> None:
        """Exception → False."""
        conn = MagicMock()
        conn.transmit.side_effect = Exception("Connection lost")
        assert _select_aid(conn, b"\xa0\x00\x00\x03\x08") is False

    def test_apdu_structure(self) -> None:
        """APDU корректно сформирован: CLA=00 INS=A4 P1=04 P2=00 Lc AID Le=00."""
        conn = MagicMock()
        conn.transmit.return_value = ([], 0x90, 0x00)
        aid = b"\xd2\x76\x00\x01\x24"
        _select_aid(conn, aid)
        apdu = conn.transmit.call_args[0][0]
        assert apdu[:4] == [0x00, 0xA4, 0x04, 0x00]
        assert apdu[4] == len(aid)
        assert apdu[-1] == 0x00


# ==============================================================================
# 5. TestDetectCardProfile
# ==============================================================================


class TestDetectCardProfile:
    """Тесты для _detect_card_profile()."""

    def test_atr_match(self) -> None:
        """ATR из базы → точный профиль."""
        reader = MagicMock()
        conn = MagicMock()
        reader.createConnection.return_value = conn
        # Используем первый ATR из базы
        first_atr = next(iter(_ATR_DATABASE.keys()))
        conn.getATR.return_value = list(first_atr)
        conn.connect.return_value = None

        profile = _detect_card_profile(reader, "Test Reader")
        assert profile.detected_via == "atr"
        assert profile == _ATR_DATABASE[first_atr]

    def test_atr_miss_openpgp_aid(self) -> None:
        """ATR не в базе, OpenPGP AID → openpgp profile."""
        reader = MagicMock()
        conn = MagicMock()
        reader.createConnection.return_value = conn
        conn.getATR.return_value = [0xFF, 0xFF]  # Unknown ATR
        conn.connect.return_value = None
        # Первый transmit (OpenPGP AID) → success
        conn.transmit.return_value = ([], 0x90, 0x00)

        profile = _detect_card_profile(reader, "Test Reader")
        assert profile.card_type == "openpgp"
        assert profile.detected_via == "aid_openpgp"

    def test_atr_miss_piv_aid(self) -> None:
        """ATR не в базе, OpenPGP fail, PIV AID → piv profile."""
        reader = MagicMock()
        conn = MagicMock()
        reader.createConnection.return_value = conn
        conn.getATR.return_value = [0xFF, 0xFF]
        conn.connect.return_value = None
        # Первый transmit (OpenPGP) → fail, второй (PIV) → success
        conn.transmit.side_effect = [
            ([], 0x6A, 0x82),
            ([], 0x90, 0x00),
        ]

        profile = _detect_card_profile(reader, "Test Reader")
        assert profile.card_type == "piv"
        assert profile.detected_via == "aid_piv"

    def test_name_fallback_piv(self) -> None:
        """Все методы детекции провалились → name fallback."""
        reader = MagicMock()
        conn = MagicMock()
        reader.createConnection.return_value = conn
        conn.getATR.return_value = [0xFF, 0xFF]
        conn.connect.return_value = None
        conn.transmit.return_value = ([], 0x6A, 0x82)

        profile = _detect_card_profile(reader, "Generic Reader")
        assert profile.detected_via == "name_fallback"
        assert profile.card_type == "piv"

    def test_name_fallback_openpgp(self) -> None:
        """Имя ридера содержит 'openpgp' → card_type=openpgp."""
        reader = MagicMock()
        conn = MagicMock()
        reader.createConnection.return_value = conn
        conn.getATR.return_value = [0xFF, 0xFF]
        conn.connect.return_value = None
        conn.transmit.return_value = ([], 0x6A, 0x82)

        profile = _detect_card_profile(reader, "OpenPGP Smartcard Reader")
        assert profile.card_type == "openpgp"

    def test_no_card_exception(self) -> None:
        """NoCardException → conservative PIV profile."""
        reader = MagicMock()
        conn = MagicMock()
        reader.createConnection.return_value = conn
        with patch(f"{MODULE}.NoCardException", MockNoCardException):
            conn.connect.side_effect = MockNoCardException("No card")
            profile = _detect_card_profile(reader, "Empty Reader")
        assert profile.detected_via == "name_fallback"

    def test_generic_exception(self) -> None:
        """Неожиданная ошибка → conservative profile."""
        reader = MagicMock()
        conn = MagicMock()
        reader.createConnection.return_value = conn
        conn.connect.side_effect = RuntimeError("USB error")

        profile = _detect_card_profile(reader, "Broken Reader")
        assert profile.detected_via == "name_fallback"

    def test_disconnect_always_called(self) -> None:
        """finally: disconnect вызывается даже при ошибке."""
        reader = MagicMock()
        conn = MagicMock()
        reader.createConnection.return_value = conn
        conn.getATR.return_value = [0xFF, 0xFF]
        conn.connect.return_value = None
        conn.transmit.return_value = ([], 0x6A, 0x82)

        _detect_card_profile(reader, "Test")
        conn.disconnect.assert_called_once()

    def test_disconnect_failure_ignored(self) -> None:
        """Ошибка disconnect не поднимает исключение."""
        reader = MagicMock()
        conn = MagicMock()
        reader.createConnection.return_value = conn
        conn.getATR.return_value = [0xFF, 0xFF]
        conn.connect.return_value = None
        conn.transmit.return_value = ([], 0x6A, 0x82)
        conn.disconnect.side_effect = Exception("Disconnect failed")

        # Не поднимает исключение
        profile = _detect_card_profile(reader, "Test")
        assert profile is not None


# ==============================================================================
# 6. TestMakeSmartcardCapabilities
# ==============================================================================


class TestMakeSmartcardCapabilities:
    """Тесты для _make_smartcard_capabilities()."""

    def test_openpgp(self) -> None:
        """OpenPGP — полные возможности."""
        caps = _make_smartcard_capabilities("openpgp")
        assert caps.rsa_key_sizes == (2048, 3072, 4096)
        assert caps.ed25519_openpgp is True
        assert caps.x25519_openpgp is True
        assert caps.has_openpgp is True

    def test_piv(self) -> None:
        """PIV — conservative RSA-2048."""
        caps = _make_smartcard_capabilities("piv")
        assert caps.rsa_key_sizes == (2048,)
        assert caps.can_generate_onboard is False

    def test_yubikey_piv(self) -> None:
        """yubikey_piv → conservative PIV (без ATR)."""
        caps = _make_smartcard_capabilities("yubikey_piv")
        assert caps.rsa_key_sizes == (2048,)


# ==============================================================================
# 7. TestExternalKeypair
# ==============================================================================


class TestExternalKeypair:
    """Тесты для ExternalKeypair."""

    def test_init_with_bytearray(self) -> None:
        """Создание с bytearray — OK."""
        kp = ExternalKeypair(bytearray(b"\x01\x02\x03"), b"\x04\x05")
        assert kp.private_key_der == bytearray(b"\x01\x02\x03")
        assert kp.public_key_der == b"\x04\x05"
        assert kp._wiped is False

    def test_init_with_bytes_raises(self) -> None:
        """Создание с bytes → TypeError."""
        with pytest.raises(TypeError, match="bytearray"):
            ExternalKeypair(b"\x01\x02", b"\x03")  # type: ignore[arg-type]

    def test_wipe(self) -> None:
        """wipe() обнуляет приватный ключ."""
        kp = ExternalKeypair(bytearray(b"\x01\x02\x03"), b"\x04")
        kp.wipe()
        assert kp.private_key_der == bytearray(3)
        assert kp._wiped is True

    def test_wipe_idempotent(self) -> None:
        """Повторный wipe() безопасен."""
        kp = ExternalKeypair(bytearray(b"\x01\x02"), b"\x03")
        kp.wipe()
        kp.wipe()
        assert kp._wiped is True

    def test_context_manager_wipes(self) -> None:
        """Context manager вызывает wipe() при выходе."""
        kp = ExternalKeypair(bytearray(b"\x01\x02\x03"), b"\x04")
        with kp:
            assert kp._wiped is False
        assert kp._wiped is True
        assert kp.private_key_der == bytearray(3)

    def test_enter_returns_self(self) -> None:
        """__enter__ возвращает self."""
        kp = ExternalKeypair(bytearray(b"\x01"), b"\x02")
        with kp as entered:
            assert entered is kp

    def test_del_wipes(self) -> None:
        """__del__ обнуляет ключ."""
        kp = ExternalKeypair(bytearray(b"\x01\x02"), b"\x03")
        kp.__del__()
        assert kp._wiped is True

    def test_repr_active(self) -> None:
        """__repr__ для не-wiped keypair."""
        kp = ExternalKeypair(bytearray(b"\x01\x02\x03"), b"\x04\x05")
        r = repr(kp)
        assert "3B" in r
        assert "2B" in r

    def test_repr_wiped(self) -> None:
        """__repr__ для wiped keypair."""
        kp = ExternalKeypair(bytearray(b"\x01\x02\x03"), b"\x04\x05")
        kp.wipe()
        r = repr(kp)
        assert "wiped" in r

    def test_wipe_empty_bytearray(self) -> None:
        """wipe() пустого bytearray — безопасен."""
        kp = ExternalKeypair(bytearray(b""), b"\x01")
        kp.wipe()
        assert kp._wiped is False  # пустой — not self.private_key_der = False


# ==============================================================================
# 8. TestSmartcardInfo
# ==============================================================================


class TestSmartcardInfo:
    """Тесты для SmartcardInfo."""

    def test_valid_creation(self) -> None:
        """Создание с корректными данными."""
        info = SmartcardInfo(
            card_id="yubikey_123",
            card_type="yubikey_piv",
            key_generation="onboard",
        )
        assert info.card_id == "yubikey_123"
        assert info.requires_pin is True
        assert info.manufacturer == "Unknown"

    def test_empty_card_id_raises(self) -> None:
        """card_id="" → ValueError."""
        with pytest.raises(ValueError, match="не может быть пустым"):
            SmartcardInfo(card_id="", card_type="piv", key_generation="external")

    def test_spaces_card_id_raises(self) -> None:
        """card_id из пробелов → ValueError."""
        with pytest.raises(ValueError, match="не может быть пустым"):
            SmartcardInfo(card_id="   ", card_type="piv", key_generation="external")

    def test_long_card_id_raises(self) -> None:
        """card_id > 128 символов → ValueError."""
        with pytest.raises(ValueError, match="слишком длинный"):
            SmartcardInfo(
                card_id="x" * 129,
                card_type="piv",
                key_generation="external",
            )

    def test_max_length_card_id_ok(self) -> None:
        """card_id ровно 128 символов — OK."""
        info = SmartcardInfo(
            card_id="x" * 128,
            card_type="piv",
            key_generation="external",
        )
        assert len(info.card_id) == 128

    def test_frozen(self) -> None:
        """SmartcardInfo — frozen dataclass."""
        info = SmartcardInfo(
            card_id="test",
            card_type="piv",
            key_generation="external",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            info.card_id = "other"  # type: ignore[misc]


# ==============================================================================
# 9. TestHardwareCryptoManagerInit
# ==============================================================================


class TestHardwareCryptoManagerInit:
    """Тесты инициализации и базовых методов HardwareCryptoManager."""

    def test_init(self, manager: HardwareCryptoManager) -> None:
        """Менеджер инициализируется без ошибок."""
        assert manager._enum_cache is None
        assert isinstance(manager._global_lock, type(threading.RLock()))

    def test_repr(self, manager: HardwareCryptoManager) -> None:
        """__repr__ содержит статус зависимостей."""
        r = repr(manager)
        assert "HardwareCryptoManager(" in r
        assert "pyscard=" in r
        assert "ykman=" in r
        assert "tracked_devices=0" in r
        assert "cache=stale" in r

    def test_ensure_pyscard_without_pyscard(self, manager: HardwareCryptoManager) -> None:
        """_ensure_pyscard без pyscard → AlgorithmNotAvailableError."""
        with patch(f"{MODULE}.has_pyscard", False):
            with pytest.raises(AlgorithmNotAvailableError, match="pyscard"):
                manager._ensure_pyscard()

    def test_ensure_pyscard_with_pyscard(self, manager: HardwareCryptoManager) -> None:
        """_ensure_pyscard с pyscard → OK."""
        with patch(f"{MODULE}.has_pyscard", True):
            manager._ensure_pyscard()

    def test_ensure_ykman_without_ykman(self, manager: HardwareCryptoManager) -> None:
        """_ensure_ykman без ykman → AlgorithmNotAvailableError."""
        with patch(f"{MODULE}.has_ykman", False):
            with pytest.raises(AlgorithmNotAvailableError, match="yubikey-manager"):
                manager._ensure_ykman()

    def test_validate_piv_slot_valid(self) -> None:
        """Допустимые PIV-слоты."""
        for slot in PIV_VALID_SLOTS:
            HardwareCryptoManager._validate_piv_slot(slot)

    def test_validate_piv_slot_invalid(self) -> None:
        """Недопустимый слот → SlotError."""
        with pytest.raises(SlotError):
            HardwareCryptoManager._validate_piv_slot(0xFF)

    def test_get_device_lock_creates_new(self, manager: HardwareCryptoManager) -> None:
        """_get_device_lock создаёт RLock для нового устройства."""
        lock = manager._get_device_lock("device_1")
        assert isinstance(lock, type(threading.RLock()))

    def test_get_device_lock_reuses(self, manager: HardwareCryptoManager) -> None:
        """_get_device_lock возвращает тот же RLock для того же устройства."""
        lock1 = manager._get_device_lock("device_1")
        lock2 = manager._get_device_lock("device_1")
        assert lock1 is lock2


# ==============================================================================
# 10. TestListDevices
# ==============================================================================


class TestListDevices:
    """Тесты для list_devices() и кеширования."""

    def test_no_dependencies(self, manager: HardwareCryptoManager) -> None:
        """Без pyscard и ykman → пустой список."""
        with (
            patch(f"{MODULE}.has_pyscard", False),
            patch(f"{MODULE}.has_ykman", False),
        ):
            devices = manager.list_devices()
        assert devices == []

    def test_yubikey_enumeration(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """YubiKey enumeration через ykman."""
        with patch(f"{MODULE}.has_pyscard", False):
            devices = manager.list_devices()
        assert len(devices) == 1
        assert devices[0].card_id == "yubikey_10620473"
        assert devices[0].card_type == "yubikey_piv"
        assert devices[0].manufacturer == "Yubico"

    def test_smartcard_enumeration(
        self,
        manager: HardwareCryptoManager,
        mock_pyscard_env: dict[str, Any],
    ) -> None:
        """Smartcard enumeration через pyscard."""
        conn = mock_pyscard_env["connection"]
        conn.getATR.return_value = [0xFF, 0xFF]
        conn.transmit.return_value = ([], 0x6A, 0x82)

        with patch(f"{MODULE}.has_ykman", False):
            devices = manager.list_devices()
        assert len(devices) == 1
        assert devices[0].card_id.startswith("sc_")

    def test_cache_hit(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Второй вызов использует кеш."""
        with patch(f"{MODULE}.has_pyscard", False):
            manager.list_devices()
            manager.list_devices()
        mock_ykman_env["list_all"].assert_called_once()

    def test_cache_force_refresh(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """force_refresh игнорирует кеш."""
        with patch(f"{MODULE}.has_pyscard", False):
            manager.list_devices()
            manager.list_devices(force_refresh=True)
        assert mock_ykman_env["list_all"].call_count == 2

    def test_invalidate_cache(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """invalidate_cache → следующий вызов = USB-опрос."""
        with patch(f"{MODULE}.has_pyscard", False):
            manager.list_devices()
            manager.invalidate_cache()
            manager.list_devices()
        assert mock_ykman_env["list_all"].call_count == 2

    def test_strict_with_errors(self, manager: HardwareCryptoManager) -> None:
        """strict=True + ошибки → DeviceCommunicationError."""
        with (
            patch(f"{MODULE}.has_pyscard", False),
            patch(f"{MODULE}.has_ykman", True),
            patch(f"{MODULE}.yk_list_all", side_effect=RuntimeError("USB error")),
        ):
            with pytest.raises(DeviceCommunicationError):
                manager.list_devices(strict=True)

    def test_non_strict_with_errors(self, manager: HardwareCryptoManager) -> None:
        """strict=False + ошибки → пустой результат, без исключения."""
        with (
            patch(f"{MODULE}.has_pyscard", False),
            patch(f"{MODULE}.has_ykman", True),
            patch(f"{MODULE}.yk_list_all", side_effect=RuntimeError("USB error")),
        ):
            devices = manager.list_devices(strict=False)
        assert devices == []

    def test_returns_list_copy(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """list_devices возвращает копию списка."""
        with patch(f"{MODULE}.has_pyscard", False):
            d1 = manager.list_devices()
            d2 = manager.list_devices()
        assert d1 is not d2
        assert d1 == d2

    def test_sc_readers_exception(self, manager: HardwareCryptoManager) -> None:
        """PC/SC sc_readers() выбрасывает ошибку → errors + пустой список."""
        with (
            patch(f"{MODULE}.has_pyscard", True),
            patch(f"{MODULE}.sc_readers", side_effect=RuntimeError("pcsc error")),
            patch(f"{MODULE}.has_ykman", False),
        ):
            devices = manager.list_devices()
        assert devices == []

    def test_yubikey_fw_version_in_info(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Firmware version включена в SmartcardInfo."""
        with patch(f"{MODULE}.has_pyscard", False):
            devices = manager.list_devices()
        assert devices[0].firmware_version == "5.2.4"

    def test_strict_cached_errors(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """strict=True с кешированными ошибками → DeviceCommunicationError."""
        with (
            patch(f"{MODULE}.has_pyscard", True),
            patch(f"{MODULE}.sc_readers", side_effect=RuntimeError("pcsc")),
        ):
            # Первый вызов (non-strict) — заполняет кеш с ошибками
            manager.list_devices(strict=False)
            # Второй вызов (strict) — использует кеш, видит ошибки
            with pytest.raises(DeviceCommunicationError):
                manager.list_devices(strict=True)


# ==============================================================================
# 11. TestGetYubikeyProtocols
# ==============================================================================


class TestGetYubikeyProtocols:
    """Тесты для _get_yubikey_protocols()."""

    def test_yk_capability_none(self) -> None:
        """YK_CAPABILITY=None → fallback."""
        with (
            patch(f"{MODULE}.YK_CAPABILITY", None),
            patch(f"{MODULE}.YK_TRANSPORT", None),
        ):
            result = HardwareCryptoManager._get_yubikey_protocols(MagicMock())
        assert result == frozenset({"piv", "openpgp", "fido2", "oath", "otp"})

    def test_config_none(self) -> None:
        """config=None → fallback."""
        dev_info = MagicMock()
        dev_info.config = None
        with (
            patch(f"{MODULE}.YK_CAPABILITY", MagicMock()),
            patch(f"{MODULE}.YK_TRANSPORT", MagicMock()),
        ):
            result = HardwareCryptoManager._get_yubikey_protocols(dev_info)
        assert "piv" in result

    def test_empty_capabilities(self) -> None:
        """enabled_capabilities пустой → fallback."""
        dev_info = MagicMock()
        dev_info.config.enabled_capabilities = {}
        with (
            patch(f"{MODULE}.YK_CAPABILITY", MagicMock()),
            patch(f"{MODULE}.YK_TRANSPORT", MagicMock()),
        ):
            result = HardwareCryptoManager._get_yubikey_protocols(dev_info)
        assert result == frozenset({"piv", "openpgp", "fido2", "oath", "otp"})

    def test_normal_capabilities(self, mock_ykman_env: dict[str, Any]) -> None:
        """Нормальные capabilities → правильный frozenset."""
        dev_info = MagicMock()
        # USB capabilities: PIV(0x10) | OPENPGP(0x08) | FIDO2(0x200) | OATH(0x20) | OTP(0x01)
        dev_info.config.enabled_capabilities = {"USB": 0x10 | 0x08 | 0x200 | 0x20 | 0x01}
        result = HardwareCryptoManager._get_yubikey_protocols(dev_info)
        assert result == frozenset({"piv", "openpgp", "fido2", "oath", "otp"})

    def test_piv_only(self, mock_ykman_env: dict[str, Any]) -> None:
        """Только PIV → frozenset({'piv'})."""
        dev_info = MagicMock()
        dev_info.config.enabled_capabilities = {"USB": 0x10}
        result = HardwareCryptoManager._get_yubikey_protocols(dev_info)
        assert result == frozenset({"piv"})

    def test_attribute_error_fallback(self) -> None:
        """AttributeError → fallback."""
        dev_info = MagicMock()
        dev_info.config.enabled_capabilities = property(
            lambda self: (_ for _ in ()).throw(AttributeError)
        )
        with (
            patch(f"{MODULE}.YK_CAPABILITY", MagicMock()),
            patch(f"{MODULE}.YK_TRANSPORT", MagicMock()),
        ):
            result = HardwareCryptoManager._get_yubikey_protocols(dev_info)
        # Should fallback
        assert "piv" in result

    def test_unknown_bits_fallback(self, mock_ykman_env: dict[str, Any]) -> None:
        """Неизвестные биты → fallback."""
        dev_info = MagicMock()
        # Только неизвестные биты (0x8000)
        dev_info.config.enabled_capabilities = {"USB": 0x8000}
        result = HardwareCryptoManager._get_yubikey_protocols(dev_info)
        assert result == frozenset({"piv", "openpgp", "fido2", "oath", "otp"})


# ==============================================================================
# 12. TestGenerateKeypairExternal
# ==============================================================================


class TestGenerateKeypairExternal:
    """Тесты для generate_keypair_external()."""

    def test_rsa_2048(self, manager: HardwareCryptoManager) -> None:
        """RSA-2048 → ExternalKeypair с DER."""
        kp = manager.generate_keypair_external("RSA-2048")
        assert isinstance(kp, ExternalKeypair)
        assert len(kp.private_key_der) > 0
        assert len(kp.public_key_der) > 0
        kp.wipe()

    def test_rsa_3072(self, manager: HardwareCryptoManager) -> None:
        """RSA-3072 → ExternalKeypair."""
        kp = manager.generate_keypair_external("RSA-3072")
        assert isinstance(kp, ExternalKeypair)
        kp.wipe()

    def test_rsa_4096(self, manager: HardwareCryptoManager) -> None:
        """RSA-4096 → ExternalKeypair."""
        kp = manager.generate_keypair_external("RSA-4096")
        assert isinstance(kp, ExternalKeypair)
        kp.wipe()

    def test_ecc_p256(self, manager: HardwareCryptoManager) -> None:
        """ECC-P256 → ExternalKeypair."""
        kp = manager.generate_keypair_external("ECC-P256")
        assert isinstance(kp, ExternalKeypair)
        assert len(kp.private_key_der) > 0
        kp.wipe()

    def test_ecc_p384(self, manager: HardwareCryptoManager) -> None:
        """ECC-P384 → ExternalKeypair."""
        kp = manager.generate_keypair_external("ECC-P384")
        assert isinstance(kp, ExternalKeypair)
        kp.wipe()

    def test_rsa_default_size(self, manager: HardwareCryptoManager) -> None:
        """RSA без суффикса → default 2048."""
        kp = manager.generate_keypair_external("RSA")
        assert isinstance(kp, ExternalKeypair)
        kp.wipe()

    def test_rsa_invalid_size(self, manager: HardwareCryptoManager) -> None:
        """RSA-1024 → InvalidKeyError."""
        with pytest.raises(InvalidKeyError, match="1024"):
            manager.generate_keypair_external("RSA-1024")

    def test_unsupported_algorithm(self, manager: HardwareCryptoManager) -> None:
        """Неизвестный алгоритм → InvalidKeyError."""
        with pytest.raises(InvalidKeyError, match="Unsupported algorithm"):
            manager.generate_keypair_external("CHACHA20")

    def test_ecc_aliases(self, manager: HardwareCryptoManager) -> None:
        """Все алиасы ECC-P256."""
        for alias in ("ECC-P256", "ECC-P-256", "P-256", "P256"):
            kp = manager.generate_keypair_external(alias)
            assert isinstance(kp, ExternalKeypair)
            kp.wipe()

    def test_ecc_with_key_size_warning(
        self, manager: HardwareCryptoManager, caplog: pytest.LogCaptureFixture
    ) -> None:
        """ECC + key_size → warning, key_size игнорируется."""
        with caplog.at_level("WARNING"):
            kp = manager.generate_keypair_external("ECC-P256", key_size=4096)
        assert "ignored" in caplog.text.lower()
        kp.wipe()

    def test_case_insensitive(self, manager: HardwareCryptoManager) -> None:
        """Алгоритмы регистронезависимы."""
        kp = manager.generate_keypair_external("ecc-p256")
        assert isinstance(kp, ExternalKeypair)
        kp.wipe()

    def test_private_key_is_bytearray(self, manager: HardwareCryptoManager) -> None:
        """private_key_der — bytearray (для безопасного обнуления)."""
        kp = manager.generate_keypair_external("ECC-P256")
        assert isinstance(kp.private_key_der, bytearray)
        kp.wipe()


# ==============================================================================
# 13. TestGenerateKeypairOnboard
# ==============================================================================


class TestGenerateKeypairOnboard:
    """Тесты для generate_keypair_onboard()."""

    def test_ykman_not_available(self, manager: HardwareCryptoManager) -> None:
        """ykman не установлен → AlgorithmNotAvailableError."""
        with patch(f"{MODULE}.has_ykman", False):
            with pytest.raises(AlgorithmNotAvailableError):
                manager.generate_keypair_onboard("yubikey_123", 0x9A, "RSA-2048", "123456")

    def test_invalid_slot(self, manager: HardwareCryptoManager) -> None:
        """Недопустимый слот → SlotError."""
        with patch(f"{MODULE}.has_ykman", True):
            with pytest.raises(SlotError):
                manager.generate_keypair_onboard("yubikey_123", 0xFF, "RSA-2048", "123456")

    def test_fw_check_ed25519(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """FW < 5.7 + Ed25519 → AlgorithmNotAvailableError."""
        mock_ykman_env["device_info"].version = (5, 2, 4)
        with pytest.raises(AlgorithmNotAvailableError, match="5.7.0"):
            manager.generate_keypair_onboard("yubikey_10620473", 0x9A, "ED25519", "123456")

    def test_happy_path(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Happy path: генерация → public DER."""
        mock_pub_key = MagicMock()
        mock_pub_key.public_bytes.return_value = b"\x30\x59\x30\x13"
        mock_ykman_env["session"].generate_key.return_value = mock_pub_key

        result = manager.generate_keypair_onboard("yubikey_10620473", 0x9A, "ECC-P256", "123456")
        assert result == b"\x30\x59\x30\x13"
        mock_ykman_env["session"].verify_pin.assert_called_once_with("123456")

    def test_pin_error_reraise(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """PINError пробрасывается без оборачивания."""
        mock_ykman_env["session"].verify_pin.side_effect = PINError(
            device_id="yubikey_10620473", reason="Wrong PIN"
        )
        with pytest.raises(PINError):
            manager.generate_keypair_onboard("yubikey_10620473", 0x9A, "ECC-P256", "wrong")

    def test_generic_error_wrapped(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Generic exception → KeyGenerationError."""
        mock_ykman_env["session"].generate_key.side_effect = RuntimeError("HW fail")
        with pytest.raises(KeyGenerationError):
            manager.generate_keypair_onboard("yubikey_10620473", 0x9A, "ECC-P256", "123456")


# ==============================================================================
# 14. TestImportKeyToDevice
# ==============================================================================


class TestImportKeyToDevice:
    """Тесты для import_key_to_device()."""

    def test_ykman_not_available(self, manager: HardwareCryptoManager) -> None:
        """ykman не установлен → AlgorithmNotAvailableError."""
        with patch(f"{MODULE}.has_ykman", False):
            with pytest.raises(AlgorithmNotAvailableError):
                manager.import_key_to_device("yubikey_123", 0x9A, b"\x30", "123456")

    def test_invalid_slot(self, manager: HardwareCryptoManager) -> None:
        """Недопустимый слот → SlotError."""
        with patch(f"{MODULE}.has_ykman", True):
            with pytest.raises(SlotError):
                manager.import_key_to_device("yubikey_123", 0xFF, b"\x30", "123456")

    def test_happy_path_rsa(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Импорт RSA ключа — OK."""
        # Генерируем реальный RSA ключ для получения DER
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

        manager.import_key_to_device("yubikey_10620473", 0x9C, der, "123456")
        mock_ykman_env["session"].verify_pin.assert_called_once_with("123456")
        mock_ykman_env["session"].put_key.assert_called_once()

    def test_happy_path_ecc(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Импорт ECC ключа — OK."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        private_key = ec.generate_private_key(ec.SECP256R1())
        der = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

        manager.import_key_to_device("yubikey_10620473", 0x9C, der, "123456")
        mock_ykman_env["session"].put_key.assert_called_once()

    def test_invalid_der_raises(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Некорректный DER → InvalidKeyError."""
        with pytest.raises(InvalidKeyError, match="Invalid private key"):
            manager.import_key_to_device("yubikey_10620473", 0x9C, b"\x00\x01", "123456")

    def test_pin_error_reraise(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """PINError пробрасывается."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        private_key = ec.generate_private_key(ec.SECP256R1())
        der = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

        mock_ykman_env["session"].verify_pin.side_effect = PINError(
            device_id="test", reason="Wrong PIN"
        )
        with pytest.raises(PINError):
            manager.import_key_to_device("yubikey_10620473", 0x9C, der, "wrong")

    def test_generic_error_wrapped(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Generic exception → HardwareDeviceError."""
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        private_key = ec.generate_private_key(ec.SECP256R1())
        der = private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

        mock_ykman_env["session"].put_key.side_effect = RuntimeError("HW fail")
        with pytest.raises(HardwareDeviceError):
            manager.import_key_to_device("yubikey_10620473", 0x9C, der, "123456")


# ==============================================================================
# 15. TestSignWithDevice
# ==============================================================================


class TestSignWithDevice:
    """Тесты для sign_with_device()."""

    def test_ykman_not_available(self, manager: HardwareCryptoManager) -> None:
        """ykman не установлен → AlgorithmNotAvailableError."""
        with patch(f"{MODULE}.has_ykman", False):
            with pytest.raises(AlgorithmNotAvailableError):
                manager.sign_with_device("yubikey_123", 0x9C, b"data", "123456")

    def test_happy_path_rsa(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """RSA signing → SHA-256."""
        mock_pub_key = MagicMock(spec=rsa.RSAPublicKey)
        mock_metadata = MagicMock()
        mock_metadata.public_key = mock_pub_key
        mock_ykman_env["session"].get_slot_metadata.return_value = mock_metadata
        mock_ykman_env["session"].sign.return_value = b"\x30\x44"

        result = manager.sign_with_device("yubikey_10620473", 0x9C, b"data", "123456")
        assert result == b"\x30\x44"

    def test_happy_path_ecc_p384(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """ECC P-384 signing → SHA-384."""
        mock_pub_key = MagicMock(spec=ec.EllipticCurvePublicKey)
        mock_pub_key.curve = ec.SECP384R1()
        mock_metadata = MagicMock()
        mock_metadata.public_key = mock_pub_key
        mock_ykman_env["session"].get_slot_metadata.return_value = mock_metadata
        mock_ykman_env["session"].sign.return_value = b"\x30\x66"

        result = manager.sign_with_device("yubikey_10620473", 0x9C, b"data", "123456")
        assert result == b"\x30\x66"

    def test_unsupported_key_type(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Неподдерживаемый тип ключа → InvalidKeyError (через HardwareDeviceError)."""
        # MagicMock не является ни RSAPublicKey, ни EllipticCurvePublicKey
        mock_pub_key = MagicMock(name="Ed25519PublicKey")
        mock_metadata = MagicMock()
        mock_metadata.public_key = mock_pub_key
        mock_ykman_env["session"].get_slot_metadata.return_value = mock_metadata

        with pytest.raises((InvalidKeyError, HardwareDeviceError)):
            manager.sign_with_device("yubikey_10620473", 0x9C, b"data", "123456")

    def test_pin_error_reraise(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """PINError пробрасывается."""
        mock_ykman_env["session"].verify_pin.side_effect = PINError(
            device_id="test", reason="Wrong PIN"
        )
        with pytest.raises(PINError):
            manager.sign_with_device("yubikey_10620473", 0x9C, b"data", "wrong")

    def test_generic_error_wrapped(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Generic exception → HardwareDeviceError."""
        mock_pub_key = MagicMock(spec=rsa.RSAPublicKey)
        mock_metadata = MagicMock()
        mock_metadata.public_key = mock_pub_key
        mock_ykman_env["session"].get_slot_metadata.return_value = mock_metadata
        mock_ykman_env["session"].sign.side_effect = RuntimeError("HW fail")

        with pytest.raises(HardwareDeviceError):
            manager.sign_with_device("yubikey_10620473", 0x9C, b"data", "123456")


# ==============================================================================
# 16. TestDecryptWithDevice
# ==============================================================================


class TestDecryptWithDevice:
    """Тесты для decrypt_with_device()."""

    def test_ykman_not_available(self, manager: HardwareCryptoManager) -> None:
        """ykman не установлен → AlgorithmNotAvailableError."""
        with patch(f"{MODULE}.has_ykman", False):
            with pytest.raises(AlgorithmNotAvailableError):
                manager.decrypt_with_device("yubikey_123", 0x9D, b"ct", "123456")

    def test_happy_path_rsa(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """RSA-OAEP-SHA256 decryption."""
        mock_pub_key = MagicMock(spec=rsa.RSAPublicKey)
        mock_metadata = MagicMock()
        mock_metadata.public_key = mock_pub_key
        mock_ykman_env["session"].get_slot_metadata.return_value = mock_metadata
        mock_ykman_env["session"].decrypt.return_value = b"plaintext"

        result = manager.decrypt_with_device("yubikey_10620473", 0x9D, b"ciphertext", "123456")
        assert result == b"plaintext"

    def test_ecc_key_raises(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """ECC ключ → InvalidKeyError (нет прямой расшифровки)."""
        mock_pub_key = MagicMock(spec=ec.EllipticCurvePublicKey)
        mock_metadata = MagicMock()
        mock_metadata.public_key = mock_pub_key
        mock_ykman_env["session"].get_slot_metadata.return_value = mock_metadata

        with pytest.raises(InvalidKeyError, match="ECC"):
            manager.decrypt_with_device("yubikey_10620473", 0x9D, b"ciphertext", "123456")

    def test_pin_error_reraise(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """PINError пробрасывается."""
        mock_ykman_env["session"].verify_pin.side_effect = PINError(
            device_id="test", reason="Wrong PIN"
        )
        with pytest.raises(PINError):
            manager.decrypt_with_device("yubikey_10620473", 0x9D, b"ciphertext", "wrong")

    def test_generic_error_wrapped(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Generic exception → HardwareDeviceError."""
        mock_pub_key = MagicMock(spec=rsa.RSAPublicKey)
        mock_metadata = MagicMock()
        mock_metadata.public_key = mock_pub_key
        mock_ykman_env["session"].get_slot_metadata.return_value = mock_metadata
        mock_ykman_env["session"].decrypt.side_effect = RuntimeError("HW fail")

        with pytest.raises(HardwareDeviceError):
            manager.decrypt_with_device("yubikey_10620473", 0x9D, b"ciphertext", "123456")


# ==============================================================================
# 17. TestGetPublicKey
# ==============================================================================


class TestGetPublicKey:
    """Тесты для get_public_key()."""

    def test_ykman_not_available(self, manager: HardwareCryptoManager) -> None:
        """ykman не установлен → AlgorithmNotAvailableError."""
        with patch(f"{MODULE}.has_ykman", False):
            with pytest.raises(AlgorithmNotAvailableError):
                manager.get_public_key("yubikey_123", 0x9C)

    def test_happy_path(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Получение публичного ключа — OK."""
        mock_pub_key = MagicMock()
        mock_pub_key.public_bytes.return_value = b"\x30\x59"
        mock_metadata = MagicMock()
        mock_metadata.public_key = mock_pub_key
        mock_ykman_env["session"].get_slot_metadata.return_value = mock_metadata

        result = manager.get_public_key("yubikey_10620473", 0x9C)
        assert result == b"\x30\x59"

    def test_exception_wrapped_as_slot_error(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Exception → SlotError."""
        mock_ykman_env["session"].get_slot_metadata.side_effect = RuntimeError("No key")
        with pytest.raises(SlotError, match="Cannot read public key"):
            manager.get_public_key("yubikey_10620473", 0x9C)


# ==============================================================================
# 18. TestDeriveKeyFromDevice
# ==============================================================================


class TestDeriveKeyFromDevice:
    """Тесты для derive_key_from_device()."""

    def test_ykman_not_available(self, manager: HardwareCryptoManager) -> None:
        """ykman не установлен → AlgorithmNotAvailableError."""
        with patch(f"{MODULE}.has_ykman", False):
            with pytest.raises(AlgorithmNotAvailableError):
                manager.derive_key_from_device("yubikey_123", b"ch", "")

    def test_empty_challenge(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Пустой challenge → ValueError."""
        with pytest.raises(ValueError, match="не может быть пустым"):
            manager.derive_key_from_device("yubikey_10620473", b"", "")

    def test_challenge_too_long(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Challenge > 64 → ValueError."""
        with pytest.raises(ValueError, match="слишком длинный"):
            manager.derive_key_from_device("yubikey_10620473", b"x" * 65, "")

    def test_invalid_hmac_slot(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """hmac_slot не 1/2 → ValueError."""
        with pytest.raises(ValueError, match="1 или 2"):
            manager.derive_key_from_device("yubikey_10620473", b"challenge", "", hmac_slot=3)

    def test_pin_warning(
        self,
        manager: HardwareCryptoManager,
        mock_ykman_env: dict[str, Any],
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Непустой pin → warning."""
        # Мокаем yubikit.yubiotp чтобы избежать реального импорта
        mock_otp_session = MagicMock()
        mock_otp_session.calculate_hmac_sha1.return_value = b"\x00" * 20

        with (
            patch("yubikit.yubiotp.YubiOtpSession", return_value=mock_otp_session),
            patch("yubikit.yubiotp.SLOT") as mock_otp_slot,
            caplog.at_level("WARNING"),
        ):
            mock_otp_slot.ONE = 1
            mock_otp_slot.TWO = 2
            manager.derive_key_from_device("yubikey_10620473", b"challenge", "some_pin")
        assert "игнорируется" in caplog.text.lower() or "pin" in caplog.text.lower()

    def test_happy_path(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Happy path → 20 bytes."""
        mock_otp_session = MagicMock()
        mock_otp_session.calculate_hmac_sha1.return_value = b"\xab" * 20

        with (
            patch("yubikit.yubiotp.YubiOtpSession", return_value=mock_otp_session),
            patch("yubikit.yubiotp.SLOT") as mock_otp_slot,
        ):
            mock_otp_slot.ONE = 1
            mock_otp_slot.TWO = 2
            result = manager.derive_key_from_device("yubikey_10620473", b"challenge", "")
        assert result == b"\xab" * 20
        assert len(result) == 20

    def test_exception_wrapped(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Exception → HardwareDeviceError."""
        with (
            patch("yubikit.yubiotp.YubiOtpSession", side_effect=RuntimeError("fail")),
            patch("yubikit.yubiotp.SLOT"),
        ):
            with pytest.raises(HardwareDeviceError, match="HMAC-SHA1"):
                manager.derive_key_from_device("yubikey_10620473", b"challenge", "")


# ==============================================================================
# 19. TestGetDeviceInfo
# ==============================================================================


class TestGetDeviceInfo:
    """Тесты для get_device_info()."""

    def test_found(self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]) -> None:
        """Устройство найдено → SmartcardInfo."""
        with patch(f"{MODULE}.has_pyscard", False):
            info = manager.get_device_info("yubikey_10620473")
        assert info.card_id == "yubikey_10620473"

    def test_not_found(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Устройство не найдено → DeviceNotFoundError."""
        with patch(f"{MODULE}.has_pyscard", False):
            with pytest.raises(DeviceNotFoundError):
                manager.get_device_info("yubikey_99999999")


# ==============================================================================
# 20. TestInternalHelpers
# ==============================================================================


class TestInternalHelpers:
    """Тесты для внутренних методов."""

    def test_parse_fw_version_tuple(self) -> None:
        """Tuple FW version."""
        dev_info = MagicMock()
        dev_info.version = (5, 2, 4)
        assert HardwareCryptoManager._parse_fw_version(dev_info) == (5, 2, 4)

    def test_parse_fw_version_object(self) -> None:
        """Version object с major/minor/patch."""
        dev_info = MagicMock()
        dev_info.version.major = 5
        dev_info.version.minor = 7
        dev_info.version.patch = 2
        # version не является tuple
        dev_info.version.__class__ = type("Version", (), {})
        result = HardwareCryptoManager._parse_fw_version(dev_info)
        assert result == (5, 7, 2)

    def test_parse_fw_version_none(self) -> None:
        """version=None → (0,0,0)."""
        dev_info = MagicMock()
        dev_info.version = None
        assert HardwareCryptoManager._parse_fw_version(dev_info) == (0, 0, 0)

    def test_parse_fw_version_exception(self) -> None:
        """Exception → (0,0,0)."""
        dev_info = MagicMock()
        dev_info.version = property(lambda self: 1 / 0)
        # MagicMock не вызовет property, но мы тестируем через spec
        del dev_info.version
        assert HardwareCryptoManager._parse_fw_version(dev_info) == (0, 0, 0)

    def test_parse_fw_short_tuple(self) -> None:
        """Tuple < 3 элементов → (0,0,0)."""
        dev_info = MagicMock()
        dev_info.version = (5, 2)
        assert HardwareCryptoManager._parse_fw_version(dev_info) == (0, 0, 0)

    def test_resolve_yk_slot_all_valid(self, mock_ykman_env: dict[str, Any]) -> None:
        """Все 4 допустимых PIV-слота."""
        for slot in [0x9A, 0x9C, 0x9D, 0x9E]:
            result = HardwareCryptoManager._resolve_yk_slot(slot)
            assert result is not None

    def test_resolve_yk_slot_invalid(self, mock_ykman_env: dict[str, Any]) -> None:
        """Недопустимый слот → SlotError."""
        with pytest.raises(SlotError):
            HardwareCryptoManager._resolve_yk_slot(0xFF)

    def test_resolve_yk_slot_ykman_none(self) -> None:
        """YK_SLOT=None → SlotError."""
        with patch(f"{MODULE}.YK_SLOT", None):
            with pytest.raises(SlotError, match="not available"):
                HardwareCryptoManager._resolve_yk_slot(0x9A)

    def test_resolve_yk_key_type_all(self, mock_ykman_env: dict[str, Any]) -> None:
        """Все поддерживаемые алгоритмы."""
        for algo in [
            "RSA-2048",
            "RSA2048",
            "ECC-P256",
            "ECCP256",
            "P-256",
            "P256",
            "ECC-P384",
            "ECCP384",
            "P-384",
            "P384",
            "RSA-3072",
            "RSA3072",
            "RSA-4096",
            "RSA4096",
        ]:
            result = HardwareCryptoManager._resolve_yk_key_type(algo)
            assert result is not None

    def test_resolve_yk_key_type_invalid(self, mock_ykman_env: dict[str, Any]) -> None:
        """Неподдерживаемый алгоритм → InvalidKeyError."""
        with pytest.raises(InvalidKeyError, match="Unsupported"):
            HardwareCryptoManager._resolve_yk_key_type("CHACHA20")

    def test_resolve_yk_key_type_ykman_none(self) -> None:
        """YK_KEY_TYPE=None → InvalidKeyError."""
        with patch(f"{MODULE}.YK_KEY_TYPE", None):
            with pytest.raises(InvalidKeyError, match="not available"):
                HardwareCryptoManager._resolve_yk_key_type("RSA-2048")

    def test_get_hash_p384(self) -> None:
        """P-384 → SHA-384."""
        from cryptography.hazmat.primitives import hashes

        key = ec.generate_private_key(ec.SECP384R1()).public_key()
        h = HardwareCryptoManager._get_hash_for_key_type(key)
        assert isinstance(h, hashes.SHA384)

    def test_get_hash_p256(self) -> None:
        """P-256 → SHA-256."""
        from cryptography.hazmat.primitives import hashes

        key = ec.generate_private_key(ec.SECP256R1()).public_key()
        h = HardwareCryptoManager._get_hash_for_key_type(key)
        assert isinstance(h, hashes.SHA256)

    def test_get_hash_rsa(self) -> None:
        """RSA → SHA-256."""
        from cryptography.hazmat.primitives import hashes

        key = rsa.generate_private_key(65537, 2048).public_key()
        h = HardwareCryptoManager._get_hash_for_key_type(key)
        assert isinstance(h, hashes.SHA256)


# ==============================================================================
# 21. TestOpenYubikey
# ==============================================================================


class TestOpenYubikey:
    """Тесты для _open_yubikey()."""

    def test_device_not_found(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Неизвестный card_id → DeviceNotFoundError."""
        with pytest.raises(DeviceNotFoundError):
            with manager._open_yubikey("yubikey_unknown"):
                pass

    def test_yk_list_all_none(self, manager: HardwareCryptoManager) -> None:
        """yk_list_all=None → DeviceNotFoundError."""
        with patch(f"{MODULE}.yk_list_all", None):
            with pytest.raises(DeviceNotFoundError):
                with manager._open_yubikey("yubikey_123"):
                    pass

    def test_happy_path(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Happy path: подключение и закрытие."""
        with manager._open_yubikey("yubikey_10620473") as (conn, _info):
            assert conn is mock_ykman_env["connection"]
        mock_ykman_env["connection"].close.assert_called_once()

    def test_close_failure_ignored(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Ошибка close() не поднимает исключение."""
        mock_ykman_env["connection"].close.side_effect = Exception("Close failed")
        with manager._open_yubikey("yubikey_10620473") as (_conn, _info):
            pass
        # Не поднимает исключение

    def test_generic_error_wrapped(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """Generic exception → DeviceCommunicationError."""
        mock_ykman_env["device"].open_connection.side_effect = RuntimeError("USB")
        with pytest.raises(DeviceCommunicationError, match="Failed to connect"):
            with manager._open_yubikey("yubikey_10620473"):
                pass

    def test_passthrough_pin_error(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """PINError пробрасывается без оборачивания."""
        with pytest.raises(PINError):
            with manager._open_yubikey("yubikey_10620473"):
                raise PINError(device_id="test", reason="Wrong PIN")

    def test_passthrough_device_not_found(
        self, manager: HardwareCryptoManager, mock_ykman_env: dict[str, Any]
    ) -> None:
        """DeviceNotFoundError пробрасывается."""
        with pytest.raises(DeviceNotFoundError):
            with manager._open_yubikey("yubikey_10620473"):
                raise DeviceNotFoundError("yubikey_10620473")
