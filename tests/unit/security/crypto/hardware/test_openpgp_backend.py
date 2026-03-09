"""
Unit-тесты для src/security/crypto/hardware/openpgp_backend.py.

Покрытие: ≥90% строк и ветвей.
Все тесты изолированы — реального устройства не требуется.
ApduTransport мокируется через unittest.mock.

Markers:
    security — критичные тесты безопасности
    crypto   — криптографические операции
"""

from __future__ import annotations

import struct
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest
from src.security.crypto.core.exceptions import (
    AlgorithmNotAvailableError,
    DeviceCommunicationError,
    HardwareDeviceError,
    InvalidKeyError,
    KeyGenerationError,
    PINError,
)
from src.security.crypto.hardware.openpgp_backend import (
    _ALGO_ECDH,
    _ALGO_ED25519,
    _ALGO_RSA,
    _OID_ED25519,
    _OID_X25519,
    _PIN_ADMIN,
    _PIN_USER_OTHER,
    _PIN_USER_SIGN,
    _SW_PIN_BLOCKED,
    _SW_PIN_WRONG_MASK,
    _SW_SECURITY_NOT_SATISFIED,
    _SW_SUCCESS,
    OPENPGP_AID,
    OpenPGPAlgorithm,
    OpenPGPBackend,
    OpenPGPCardInfo,
    OpenPGPPublicKeys,
    OpenPGPSlot,
    _algo_name_from_attr,
    _build_algo_attr_ed25519,
    _build_algo_attr_for,
    _build_algo_attr_rsa,
    _build_algo_attr_x25519,
    _build_tlv,
    _check_sw,
    _extract_public_key_from_response,
    _parse_tlv,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CARD_ID = "sc_0_YubiKey 5 NFC 0"
USER_PIN = "123456"
ADMIN_PIN = "12345678"
ED25519_SEED = b"\xab" * 32
ED25519_PUB = b"\xcc" * 32
CHALLENGE = b"\x01\x02\x03\x04" * 8
SIGNATURE = b"\xde\xad" * 32
CIPHERTEXT = b"\xff" * 32
SHARED_SECRET = b"\x11" * 32


def _make_7f49_response(pub: bytes) -> bytes:
    """Build a minimal GENERATE KEY PAIR response with tag 7F49 → 86."""
    inner = _build_tlv(0x86, pub)
    return _build_tlv(0x7F49, inner)


def _apdu_resp(data: bytes = b"", sw: int = _SW_SUCCESS) -> MagicMock:
    """Создать мок ApduResponse с .data и .sw."""
    resp = MagicMock()
    resp.data = data
    resp.sw = sw
    resp.ok = sw == _SW_SUCCESS
    resp.sw_hex = f"{sw:04X}"
    return resp


@pytest.fixture
def backend() -> OpenPGPBackend:
    """Экземпляр OpenPGPBackend."""
    return OpenPGPBackend()


@pytest.fixture
def mock_transport() -> MagicMock:
    """
    Мок ApduTransport, совместимый с контекстным менеджером.
    По умолчанию VERIFY PIN → SW_SUCCESS; все send_apdu → ApduResponse(b"", 0x9000).
    """
    transport = MagicMock()
    transport.__enter__ = MagicMock(return_value=transport)
    transport.__exit__ = MagicMock(return_value=False)
    transport.send_apdu.return_value = _apdu_resp()
    return transport


# ---------------------------------------------------------------------------
# TLV UTILITIES
# ---------------------------------------------------------------------------


class TestBuildTlv:
    """Тесты _build_tlv."""

    def test_single_byte_tag_short_length(self) -> None:
        result = _build_tlv(0x86, b"\x00" * 3)
        assert result == bytes([0x86, 0x03, 0x00, 0x00, 0x00])

    def test_single_byte_tag_81_length(self) -> None:
        value = b"\xaa" * 200
        result = _build_tlv(0x6E, value)
        assert result[:3] == bytes([0x6E, 0x81, 200])
        assert result[3:] == value

    def test_single_byte_tag_82_length(self) -> None:
        value = b"\xbb" * 300
        result = _build_tlv(0x4D, value)
        assert result[0] == 0x4D
        assert result[1] == 0x82
        assert struct.unpack(">H", result[2:4])[0] == 300

    def test_two_byte_tag(self) -> None:
        result = _build_tlv(0x7F49, b"\x01\x02")
        assert result[:2] == bytes([0x7F, 0x49])

    def test_empty_value(self) -> None:
        result = _build_tlv(0xC1, b"")
        assert result == bytes([0xC1, 0x00])

    def test_roundtrip_with_parse_tlv(self) -> None:
        value = b"\xde\xad\xbe\xef"
        encoded = _build_tlv(0xC1, value)
        parsed = _parse_tlv(encoded)
        assert parsed[0xC1] == value


class TestParseTlv:
    """Тесты _parse_tlv."""

    def test_single_element(self) -> None:
        data = bytes.fromhex("C103010000")
        result = _parse_tlv(data)
        assert result[0xC1] == b"\x01\x00\x00"

    def test_multiple_elements(self) -> None:
        data = _build_tlv(0xC1, b"\x16") + _build_tlv(0xC2, b"\x12")
        result = _parse_tlv(data)
        assert result[0xC1] == b"\x16"
        assert result[0xC2] == b"\x12"

    def test_skip_padding_zeroes(self) -> None:
        data = bytes([0x00, 0x00]) + _build_tlv(0xC3, b"\x01")
        result = _parse_tlv(data)
        assert 0xC3 in result

    def test_two_byte_tag(self) -> None:
        inner = _build_tlv(0x86, ED25519_PUB)
        outer = _build_tlv(0x7F49, inner)
        parsed = _parse_tlv(outer)
        assert 0x7F49 in parsed

    def test_empty_input(self) -> None:
        assert _parse_tlv(b"") == {}

    def test_duplicate_tag_last_wins(self) -> None:
        data = _build_tlv(0xC1, b"\x01") + _build_tlv(0xC1, b"\x02")
        result = _parse_tlv(data)
        assert result[0xC1] == b"\x02"

    def test_81_length_encoding(self) -> None:
        value = b"\xaa" * 200
        encoded = _build_tlv(0xC1, value)
        result = _parse_tlv(encoded)
        assert result[0xC1] == value

    def test_82_length_encoding(self) -> None:
        value = b"\xbb" * 300
        encoded = _build_tlv(0x4D, value)
        result = _parse_tlv(encoded)
        assert result[0x4D] == value


# ---------------------------------------------------------------------------
# ALGORITHM ATTRIBUTE BUILDERS
# ---------------------------------------------------------------------------


class TestAlgoAttrBuilders:
    """Тесты функций _build_algo_attr_*."""

    def test_ed25519_starts_with_algo_id(self) -> None:
        attr = _build_algo_attr_ed25519()
        assert attr[0] == _ALGO_ED25519
        assert _OID_ED25519 in attr

    def test_x25519_starts_with_algo_id(self) -> None:
        attr = _build_algo_attr_x25519()
        assert attr[0] == _ALGO_ECDH
        assert _OID_X25519 in attr

    @pytest.mark.parametrize("key_size", [2048, 3072, 4096])
    def test_rsa_key_sizes(self, key_size: int) -> None:
        attr = _build_algo_attr_rsa(key_size)
        assert attr[0] == _ALGO_RSA
        assert struct.unpack(">H", attr[1:3])[0] == key_size

    def test_rsa_invalid_key_size_raises(self) -> None:
        with pytest.raises(InvalidKeyError, match="Неподдерживаемый размер"):
            _build_algo_attr_rsa(1024)

    @pytest.mark.parametrize(
        "algo,expected_name",
        [
            (OpenPGPAlgorithm.ED25519, "Ed25519"),
            (OpenPGPAlgorithm.X25519, "X25519"),
            (OpenPGPAlgorithm.RSA2048, "RSA-2048"),
            (OpenPGPAlgorithm.RSA3072, "RSA-3072"),
            (OpenPGPAlgorithm.RSA4096, "RSA-4096"),
        ],
    )
    def test_build_algo_attr_for_all_algorithms(
        self, algo: OpenPGPAlgorithm, expected_name: str
    ) -> None:
        attr = _build_algo_attr_for(algo)
        assert len(attr) > 0
        assert _algo_name_from_attr(attr) == expected_name


class TestAlgoNameFromAttr:
    """Тесты _algo_name_from_attr."""

    def test_ed25519(self) -> None:
        attr = bytes([_ALGO_ED25519]) + _OID_ED25519
        assert _algo_name_from_attr(attr) == "Ed25519"

    def test_x25519(self) -> None:
        attr = bytes([_ALGO_ECDH]) + _OID_X25519
        assert _algo_name_from_attr(attr) == "X25519"

    @pytest.mark.parametrize("key_size", [2048, 3072, 4096])
    def test_rsa(self, key_size: int) -> None:
        attr = _build_algo_attr_rsa(key_size)
        assert _algo_name_from_attr(attr) == f"RSA-{key_size}"

    def test_empty_returns_unknown(self) -> None:
        assert _algo_name_from_attr(b"") == "Unknown"

    def test_unknown_algo_id(self) -> None:
        result = _algo_name_from_attr(bytes([0xAA]))
        assert result.startswith("AlgoID-")


# ---------------------------------------------------------------------------
# CHECK SW
# ---------------------------------------------------------------------------


class TestCheckSw:
    """Тесты _check_sw."""

    def test_success_no_exception(self) -> None:
        _check_sw(_SW_SUCCESS, "test_op", CARD_ID)  # must not raise

    def test_pin_blocked_raises_pin_error(self) -> None:
        with pytest.raises(PINError, match="заблокирован"):
            _check_sw(_SW_PIN_BLOCKED, "test_op", CARD_ID)

    @pytest.mark.parametrize("retries", [0, 1, 2, 3])
    def test_wrong_pin_raises_with_retries(self, retries: int) -> None:
        sw = _SW_PIN_WRONG_MASK | retries
        with pytest.raises(PINError, match=str(retries)):
            _check_sw(sw, "test_op", CARD_ID)

    def test_security_not_satisfied(self) -> None:
        with pytest.raises(PINError, match="верификация"):
            _check_sw(_SW_SECURITY_NOT_SATISFIED, "test_op", CARD_ID)

    @pytest.mark.parametrize("bad_sw", [0x6A80, 0x6700, 0x6E00])
    def test_other_sw_raises_hardware_error(self, bad_sw: int) -> None:
        with pytest.raises(HardwareDeviceError, match="SW=0x"):
            _check_sw(bad_sw, "test_op", CARD_ID)


# ---------------------------------------------------------------------------
# EXTRACT PUBLIC KEY FROM RESPONSE
# ---------------------------------------------------------------------------


class TestExtractPublicKeyFromResponse:
    """Тесты _extract_public_key_from_response."""

    def test_valid_7f49_86_structure(self) -> None:
        response = _make_7f49_response(ED25519_PUB)
        result = _extract_public_key_from_response(response, OpenPGPSlot.SIGN)
        assert result == ED25519_PUB

    def test_flat_86_without_7f49(self) -> None:
        response = _build_tlv(0x86, ED25519_PUB)
        result = _extract_public_key_from_response(response, OpenPGPSlot.SIGN)
        assert result == ED25519_PUB

    def test_rsa_uses_81_tag(self) -> None:
        modulus = b"\xaa" * 256
        inner = _build_tlv(0x81, modulus)
        outer = _build_tlv(0x7F49, inner)
        result = _extract_public_key_from_response(outer, OpenPGPSlot.ENCRYPT)
        assert result == modulus

    def test_missing_key_material_raises(self) -> None:
        bad_response = _build_tlv(0xC1, b"\x01")
        with pytest.raises(DeviceCommunicationError, match="разобрать публичный ключ"):
            _extract_public_key_from_response(bad_response, OpenPGPSlot.SIGN)


# ---------------------------------------------------------------------------
# BUILD ECDH DECIPHER DATA
# ---------------------------------------------------------------------------


class TestBuildEcdhDecipherData:
    """Тесты OpenPGPBackend.build_ecdh_decipher_data."""

    def test_outer_tag_is_a6(self) -> None:
        data = OpenPGPBackend.build_ecdh_decipher_data(b"\x11" * 32)
        assert data[0] == 0xA6

    def test_contains_ephemeral_key(self) -> None:
        eph = b"\x22" * 32
        result = OpenPGPBackend.build_ecdh_decipher_data(eph)
        assert eph in result

    def test_nested_structure(self) -> None:
        eph = b"\x33" * 32
        outer = _parse_tlv(OpenPGPBackend.build_ecdh_decipher_data(eph))
        assert 0xA6 in outer
        inner = _parse_tlv(outer[0xA6])
        assert 0x7F49 in inner


# ---------------------------------------------------------------------------
# BUILD ED25519 PRIVATE KEY TL
# ---------------------------------------------------------------------------


class TestBuildEd25519PrivateKeyTl:
    """Тесты OpenPGPBackend.build_ed25519_private_key_tl."""

    def test_result_contains_seed(self) -> None:
        tl = OpenPGPBackend.build_ed25519_private_key_tl(ED25519_SEED, OpenPGPSlot.SIGN)
        assert ED25519_SEED in tl

    def test_sign_slot_crt_prefix(self) -> None:
        tl = OpenPGPBackend.build_ed25519_private_key_tl(ED25519_SEED, OpenPGPSlot.SIGN)
        assert tl[:2] == bytes([0xB6, 0x00])

    def test_encrypt_slot_crt_prefix(self) -> None:
        tl = OpenPGPBackend.build_ed25519_private_key_tl(ED25519_SEED, OpenPGPSlot.ENCRYPT)
        assert tl[:2] == bytes([0xB8, 0x00])

    def test_wrong_seed_length_raises(self) -> None:
        with pytest.raises(InvalidKeyError, match="32 байта"):
            OpenPGPBackend.build_ed25519_private_key_tl(b"\x00" * 16, OpenPGPSlot.SIGN)

    def test_private_key_tlv_tag_92(self) -> None:
        tl = OpenPGPBackend.build_ed25519_private_key_tl(ED25519_SEED, OpenPGPSlot.SIGN)
        # Skip CRT (2 bytes), then parse the rest
        rest = tl[2:]
        parsed = _parse_tlv(rest)
        assert 0x92 in parsed
        assert parsed[0x92] == ED25519_SEED


# ---------------------------------------------------------------------------
# BACKEND: SIGN
# ---------------------------------------------------------------------------


class TestOpenPGPBackendSign:
    """Тесты OpenPGPBackend.sign."""

    @pytest.mark.security
    def test_sign_returns_signature(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),  # VERIFY PIN
            _apdu_resp(SIGNATURE),  # PSO:CDS
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            result = backend.sign(CARD_ID, b"digest", USER_PIN)
        assert result == SIGNATURE

    @pytest.mark.security
    def test_sign_verifies_correct_pin_reference(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),
            _apdu_resp(SIGNATURE),
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            backend.sign(CARD_ID, b"data", USER_PIN)
        # First call is VERIFY PIN
        verify_call: Any = mock_transport.send_apdu.call_args_list[0]
        assert verify_call.kwargs.get("p2") == _PIN_USER_SIGN or (
            len(verify_call.args) > 3 and verify_call.args[3] == _PIN_USER_SIGN
        )

    @pytest.mark.security
    def test_sign_wrong_pin_raises_pin_error(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.return_value = _apdu_resp(b"", _SW_PIN_WRONG_MASK | 2)
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            with pytest.raises(PINError, match="2"):
                backend.sign(CARD_ID, b"data", "wrong")

    @pytest.mark.security
    def test_sign_selects_openpgp_aid(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),
            _apdu_resp(SIGNATURE),
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            backend.sign(CARD_ID, b"data", USER_PIN)
        mock_transport.select_applet.assert_called_once_with(OPENPGP_AID)


# ---------------------------------------------------------------------------
# BACKEND: DECRYPT
# ---------------------------------------------------------------------------


class TestOpenPGPBackendDecrypt:
    """Тесты OpenPGPBackend.decrypt."""

    def test_decrypt_returns_shared_secret(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),  # VERIFY PIN
            _apdu_resp(SHARED_SECRET),  # PSO:DEC
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            result = backend.decrypt(CARD_ID, CIPHERTEXT, USER_PIN)
        assert result == SHARED_SECRET

    def test_decrypt_uses_pin_ref_82(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),
            _apdu_resp(SHARED_SECRET),
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            backend.decrypt(CARD_ID, CIPHERTEXT, USER_PIN)
        # PIN VERIFY is first call; check P2 = 0x82
        first_call = mock_transport.send_apdu.call_args_list[0]
        p2_value = first_call.kwargs.get("p2") if first_call.kwargs else first_call.args[3]
        assert p2_value == _PIN_USER_OTHER


# ---------------------------------------------------------------------------
# BACKEND: AUTHENTICATE
# ---------------------------------------------------------------------------


class TestOpenPGPBackendAuthenticate:
    """Тесты OpenPGPBackend.authenticate."""

    def test_authenticate_returns_response(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        auth_response = b"\xca\xfe" * 32
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),
            _apdu_resp(auth_response),
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            result = backend.authenticate(CARD_ID, CHALLENGE, USER_PIN)
        assert result == auth_response

    @pytest.mark.security
    def test_authenticate_pin_blocked_raises(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.return_value = _apdu_resp(b"", _SW_PIN_BLOCKED)
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            with pytest.raises(PINError, match="заблокирован"):
                backend.authenticate(CARD_ID, CHALLENGE, USER_PIN)


# ---------------------------------------------------------------------------
# BACKEND: GET PUBLIC KEYS
# ---------------------------------------------------------------------------


class TestOpenPGPBackendGetPublicKeys:
    """Тесты OpenPGPBackend.get_public_keys."""

    def test_returns_openpgp_public_keys(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        ed25519_attr = _build_algo_attr_ed25519()
        pub_response = _make_7f49_response(ED25519_PUB)

        mock_transport.send_apdu.side_effect = [
            _apdu_resp(ed25519_attr),  # GET DATA C1 (sign algo)
            _apdu_resp(ed25519_attr),  # GET DATA C2 (enc algo)
            _apdu_resp(ed25519_attr),  # GET DATA C3 (auth algo)
            _apdu_resp(pub_response),  # GEN KEY PAIR P1=0x81 SIGN
            _apdu_resp(pub_response),  # GEN KEY PAIR P1=0x81 ENCRYPT
            _apdu_resp(pub_response),  # GEN KEY PAIR P1=0x81 AUTH
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            keys = backend.get_public_keys(CARD_ID)

        assert isinstance(keys, OpenPGPPublicKeys)
        assert keys.sign == ED25519_PUB
        assert keys.sign_algorithm == "Ed25519"
        assert keys.encrypt_algorithm == "Ed25519"

    def test_empty_slot_returns_empty_bytes(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(b"", 0x6A82),  # C1: slot not found
            _apdu_resp(b"", 0x6A82),  # C2
            _apdu_resp(b"", 0x6A82),  # C3
            _apdu_resp(b"", 0x6A82),  # SIGN pub
            _apdu_resp(b"", 0x6A82),  # ENC pub
            _apdu_resp(b"", 0x6A82),  # AUTH pub
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            keys = backend.get_public_keys(CARD_ID)
        assert keys.sign == b""
        assert keys.sign_algorithm == "Unknown"


# ---------------------------------------------------------------------------
# BACKEND: GET CARD INFO
# ---------------------------------------------------------------------------


class TestOpenPGPBackendGetCardInfo:
    """Тесты OpenPGPBackend.get_card_info."""

    def _build_app_related_data(self) -> bytes:
        """Build a minimal Application Related Data DO (0x6E) with AID."""
        # AID: RID(5)+app(1)+version(major=3,minor=4)+mfr(0x0006=Yubico)+serial(4)+RFU(2)
        aid = (
            bytes.fromhex("D276000124")  # RID
            + bytes([0x01])  # app
            + bytes([0x03, 0x04])  # version 3.4
            + bytes([0x00, 0x06])  # manufacturer Yubico (0x0006)
            + bytes([0x01, 0x23, 0x45, 0x67])  # serial
            + bytes([0x00, 0x00])  # RFU
        )
        aid_tlv = _build_tlv(0x4F, aid)
        return _build_tlv(0x6E, aid_tlv)

    def test_returns_card_info(self, backend: OpenPGPBackend, mock_transport: MagicMock) -> None:
        app_data = self._build_app_related_data()
        pw_status = bytes([0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03])
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(app_data),
            _apdu_resp(pw_status),
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            info = backend.get_card_info(CARD_ID)

        assert isinstance(info, OpenPGPCardInfo)
        assert info.card_id == CARD_ID
        assert info.pw1_remaining == 3
        assert info.pw3_remaining == 3

    def test_pw_status_failure_uses_defaults(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        app_data = self._build_app_related_data()
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(app_data),
            _apdu_resp(b"", 0x6A82),  # PW status not available
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            info = backend.get_card_info(CARD_ID)
        assert info.pw1_remaining == 3
        assert info.pw3_remaining == 3


# ---------------------------------------------------------------------------
# BACKEND: IMPORT KEY
# ---------------------------------------------------------------------------


class TestOpenPGPBackendImportKey:
    """Тесты OpenPGPBackend.import_key."""

    @pytest.mark.security
    def test_import_calls_put_data_odd(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),  # VERIFY Admin PIN
            _apdu_resp(),  # PUT DATA 4D
        ]
        tl = OpenPGPBackend.build_ed25519_private_key_tl(ED25519_SEED, OpenPGPSlot.SIGN)
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            backend.import_key(CARD_ID, OpenPGPSlot.SIGN, tl, ADMIN_PIN)

        # Second call is PUT DATA (INS=0xDB)
        second_call = mock_transport.send_apdu.call_args_list[1]
        ins_value = second_call.kwargs.get("ins") if second_call.kwargs else second_call.args[1]
        assert ins_value == 0xDB

    @pytest.mark.security
    def test_import_uses_admin_pin_ref(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),
            _apdu_resp(),
        ]
        tl = OpenPGPBackend.build_ed25519_private_key_tl(ED25519_SEED, OpenPGPSlot.SIGN)
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            backend.import_key(CARD_ID, OpenPGPSlot.SIGN, tl, ADMIN_PIN)
        first_call = mock_transport.send_apdu.call_args_list[0]
        p2 = first_call.kwargs.get("p2") if first_call.kwargs else first_call.args[3]
        assert p2 == _PIN_ADMIN


# ---------------------------------------------------------------------------
# BACKEND: GENERATE KEY ONBOARD
# ---------------------------------------------------------------------------


class TestOpenPGPBackendGenerateKeyOnboard:
    """Тесты OpenPGPBackend.generate_key_onboard."""

    @pytest.mark.crypto
    def test_generate_returns_public_key(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        pub_response = _make_7f49_response(ED25519_PUB)
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),  # VERIFY Admin PIN
            _apdu_resp(),  # PUT DATA algo attr
            _apdu_resp(pub_response),  # GENERATE KEY PAIR
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            pub = backend.generate_key_onboard(
                CARD_ID, OpenPGPSlot.SIGN, OpenPGPAlgorithm.ED25519, ADMIN_PIN
            )
        assert pub == ED25519_PUB

    @pytest.mark.crypto
    def test_generate_keygen_failure_raises_key_gen_error(
        self, backend: OpenPGPBackend, mock_transport: MagicMock
    ) -> None:
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),  # VERIFY
            _apdu_resp(),  # PUT DATA algo attr
            _apdu_resp(b"", 0x6985),  # GENERATE KEY PAIR → conditions not satisfied
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            with pytest.raises(KeyGenerationError, match="Генерация ключа"):
                backend.generate_key_onboard(
                    CARD_ID,
                    OpenPGPSlot.SIGN,
                    OpenPGPAlgorithm.ED25519,
                    ADMIN_PIN,
                )

    @pytest.mark.parametrize(
        "algorithm",
        [
            OpenPGPAlgorithm.ED25519,
            OpenPGPAlgorithm.X25519,
            OpenPGPAlgorithm.RSA2048,
            OpenPGPAlgorithm.RSA3072,
            OpenPGPAlgorithm.RSA4096,
        ],
    )
    def test_all_algorithms_accepted(
        self,
        algorithm: OpenPGPAlgorithm,
        backend: OpenPGPBackend,
        mock_transport: MagicMock,
    ) -> None:
        pub = b"\x04" + b"\xaa" * 64 if "RSA" in algorithm.value else ED25519_PUB
        pub_response = _make_7f49_response(pub)
        mock_transport.send_apdu.side_effect = [
            _apdu_resp(),
            _apdu_resp(),
            _apdu_resp(pub_response),
        ]
        with patch(
            "src.security.crypto.hardware.openpgp_backend.ApduTransport",
            return_value=mock_transport,
        ):
            result = backend.generate_key_onboard(CARD_ID, OpenPGPSlot.SIGN, algorithm, ADMIN_PIN)
        assert isinstance(result, bytes)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# ENUM AND DATACLASS SANITY
# ---------------------------------------------------------------------------


class TestEnumsAndDataclasses:
    """Базовые тесты перечислений и датаклассов."""

    def test_openpgp_slot_values(self) -> None:
        assert OpenPGPSlot.SIGN.value == "sign"
        assert OpenPGPSlot.ENCRYPT.value == "encrypt"
        assert OpenPGPSlot.AUTH.value == "auth"

    def test_openpgp_algorithm_values(self) -> None:
        assert OpenPGPAlgorithm.ED25519.value == "Ed25519"
        assert OpenPGPAlgorithm.X25519.value == "X25519"

    def test_openpgp_public_keys_defaults(self) -> None:
        keys = OpenPGPPublicKeys()
        assert keys.sign == b""
        assert keys.sign_algorithm == ""

    def test_openpgp_card_info_defaults(self) -> None:
        info = OpenPGPCardInfo(card_id="test")
        assert info.pw1_remaining == 3
        assert info.app_version == (0, 0)

    def test_openpgp_aid_constant(self) -> None:
        assert OPENPGP_AID == bytes.fromhex("D276000124")
