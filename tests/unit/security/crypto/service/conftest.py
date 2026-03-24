"""
Общие fixtures для тестов сервисного слоя криптографии.

Предоставляет:
- Fake-реализации протоколов (cipher, signer, hasher, kdf)
- Mock AlgorithmRegistry с предустановленными алгоритмами
- Готовые экземпляры CryptoService для каждого профиля
- Типовые данные для тестов
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    AlgorithmMetadata,
    FloppyFriendly,
    ImplementationStatus,
    SecurityLevel,
)
from src.security.crypto.core.protocols import (
    HashProtocol,
    KDFProtocol,
    KeyExchangeProtocol,
    SignatureProtocol,
    SymmetricCipherProtocol,
)
from src.security.crypto.service.crypto_service import CryptoService
from src.security.crypto.service.profiles import CryptoProfile

# ==============================================================================
# FAKE PROTOCOL IMPLEMENTATIONS
# ==============================================================================


class FakeCipher:
    """Детерминированный symmetric cipher для тестов."""

    NONCE = b"\x01" * 12
    TAG = b"\x02" * 16

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        aad: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        ciphertext = bytes(b ^ 0xFF for b in plaintext) + self.TAG
        return self.NONCE, ciphertext

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        return bytes(b ^ 0xFF for b in ciphertext[: -len(self.TAG)])


class FakeSigner:
    """Детерминированный signer для тестов (реализует SignatureProtocol)."""

    # Атрибуты-члены, необходимые для isinstance(x, SignatureProtocol)
    algorithm_name: str = "FakeSigner"
    signature_size: int = 64
    public_key_size: int = 32
    private_key_size: int = 32
    is_post_quantum: bool = False

    SIG_SIZE: int = 64
    PRIV_KEY: bytes = b"\xaa" * 32
    PUB_KEY: bytes = b"\xbb" * 32

    def generate_keypair(self) -> tuple[bytes, bytes]:
        return self.PRIV_KEY, self.PUB_KEY

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        msg_byte = bytes([sum(message) % 256])
        return (private_key[:1] + msg_byte) * (self.SIG_SIZE // 2)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        msg_byte = bytes([sum(message) % 256])
        expected_sig = (self.PRIV_KEY[:1] + msg_byte) * (self.SIG_SIZE // 2)
        return signature == expected_sig and public_key == self.PUB_KEY


class FakeHasher:
    """Детерминированный hasher для тестов."""

    DIGEST_SIZE = 32

    def hash(self, data: bytes) -> bytes:
        return bytes(sum(data) % 256 for _ in range(self.DIGEST_SIZE))


class FakeKDF:
    """Детерминированный KDF для тестов."""

    def derive_key(
        self,
        password: bytes,
        salt: bytes,
        *,
        key_length: int = 32,
    ) -> bytes:
        return (password[:1] + salt[:1]) * (key_length // 2) + b"\x00" * (key_length % 2)


class FakeKEX:
    """Fake key exchange для тестов generate_keypair."""

    PRIV_KEY = b"\xcc" * 32
    PUB_KEY = b"\xdd" * 32

    def generate_keypair(self) -> tuple[bytes, bytes]:
        return self.PRIV_KEY, self.PUB_KEY


# ==============================================================================
# METADATA FACTORIES
# ==============================================================================


def _make_sym_meta(algo_id: str = "fake-aes") -> AlgorithmMetadata:
    return AlgorithmMetadata(
        name=algo_id.upper(),
        category=AlgorithmCategory.SYMMETRIC_CIPHER,
        protocol_class=SymmetricCipherProtocol,
        library="hashlib",
        implementation_class="FakeCipher",
        security_level=SecurityLevel.STANDARD,
        floppy_friendly=FloppyFriendly.EXCELLENT,
        status=ImplementationStatus.STABLE,
        key_size=32,
        nonce_size=12,
        is_aead=True,
        description_ru="Тестовый симметричный шифр",
    )


def _make_sig_meta(algo_id: str = "fake-ed25519") -> AlgorithmMetadata:
    return AlgorithmMetadata(
        name=algo_id,
        category=AlgorithmCategory.SIGNATURE,
        protocol_class=SignatureProtocol,
        library="hashlib",
        implementation_class="FakeSigner",
        security_level=SecurityLevel.STANDARD,
        floppy_friendly=FloppyFriendly.EXCELLENT,
        status=ImplementationStatus.STABLE,
        public_key_size=32,
        private_key_size=32,
        signature_size=64,
        description_ru="Тестовый алгоритм подписи",
    )


def _make_hash_meta(algo_id: str = "fake-sha256") -> AlgorithmMetadata:
    return AlgorithmMetadata(
        name=algo_id.upper(),
        category=AlgorithmCategory.HASH,
        protocol_class=HashProtocol,
        library="hashlib",
        implementation_class="FakeHasher",
        security_level=SecurityLevel.STANDARD,
        floppy_friendly=FloppyFriendly.EXCELLENT,
        status=ImplementationStatus.STABLE,
        digest_size=32,
        description_ru="Тестовая хеш-функция",
    )


def _make_kdf_meta(algo_id: str = "fake-argon2id") -> AlgorithmMetadata:
    return AlgorithmMetadata(
        name=algo_id,
        category=AlgorithmCategory.KDF,
        protocol_class=KDFProtocol,
        library="hashlib",
        implementation_class="FakeKDF",
        security_level=SecurityLevel.STANDARD,
        floppy_friendly=FloppyFriendly.EXCELLENT,
        status=ImplementationStatus.STABLE,
        description_ru="Тестовый KDF",
    )


def _make_legacy_sym_meta() -> AlgorithmMetadata:
    return AlgorithmMetadata(
        name="FAKE-3DES",
        category=AlgorithmCategory.SYMMETRIC_CIPHER,
        protocol_class=SymmetricCipherProtocol,
        library="hashlib",
        implementation_class="FakeCipher",
        security_level=SecurityLevel.LEGACY,
        floppy_friendly=FloppyFriendly.EXCELLENT,
        status=ImplementationStatus.DEPRECATED,
        key_size=24,
        nonce_size=8,
        description_ru="Устаревший тестовый шифр",
    )


def _make_broken_meta() -> AlgorithmMetadata:
    return AlgorithmMetadata(
        name="FAKE-DES",
        category=AlgorithmCategory.SYMMETRIC_CIPHER,
        protocol_class=SymmetricCipherProtocol,
        library="hashlib",
        implementation_class="FakeCipher",
        security_level=SecurityLevel.BROKEN,
        floppy_friendly=FloppyFriendly.EXCELLENT,
        status=ImplementationStatus.DEPRECATED,
        key_size=8,
        nonce_size=8,
        description_ru="Взломанный тестовый шифр",
    )


# ==============================================================================
# MOCK REGISTRY FIXTURE
# ==============================================================================


@pytest.fixture
def mock_registry() -> MagicMock:
    """Mock AlgorithmRegistry с предустановленными fake-алгоритмами."""
    registry = MagicMock()

    _metadata: dict[str, AlgorithmMetadata] = {
        "fake-aes": _make_sym_meta("fake-aes"),
        "fake-ed25519": _make_sig_meta("fake-ed25519"),
        "fake-sha256": _make_hash_meta("fake-sha256"),
        "fake-argon2id": _make_kdf_meta("fake-argon2id"),
        "fake-3des": _make_legacy_sym_meta(),
        "fake-des": _make_broken_meta(),
    }
    _instances: dict[str, object] = {
        "fake-aes": FakeCipher(),
        "fake-ed25519": FakeSigner(),
        "fake-sha256": FakeHasher(),
        "fake-argon2id": FakeKDF(),
        "fake-3des": FakeCipher(),
        "fake-des": FakeCipher(),
    }

    registry.get_metadata.side_effect = lambda name: _metadata[name]
    registry.create.side_effect = lambda name: _instances[name]
    registry.list_algorithms.return_value = list(_metadata.values())
    registry.is_registered.side_effect = lambda name: name in _metadata

    return registry


# ==============================================================================
# PROFILE CONFIG OVERRIDE FIXTURE
# ==============================================================================


@pytest.fixture
def fake_profile_config() -> MagicMock:
    """ProfileConfig с fake-алгоритмами для использования вместе с mock_registry."""
    cfg = MagicMock()
    cfg.symmetric_algorithm = "fake-aes"
    cfg.signing_algorithm = "fake-ed25519"
    cfg.kex_algorithm = "fake-ed25519"
    cfg.hash_algorithm = "fake-sha256"
    cfg.kdf_algorithm = "fake-argon2id"
    cfg.asymmetric_algorithm = "fake-aes"
    cfg.algorithm_ids.return_value = {
        "symmetric": "fake-aes",
        "signing": "fake-ed25519",
        "kex": "fake-ed25519",
        "hash": "fake-sha256",
        "kdf": "fake-argon2id",
        "asymmetric": "fake-aes",
    }
    return cfg


@pytest.fixture
def service(mock_registry: MagicMock, fake_profile_config: MagicMock) -> CryptoService:
    """CryptoService с mock registry и fake profile config."""
    svc = CryptoService.__new__(CryptoService)
    svc.profile = CryptoProfile.STANDARD
    svc.config = fake_profile_config
    svc._registry = mock_registry
    svc._audit_log = None
    return svc


# ==============================================================================
# SAMPLE DATA
# ==============================================================================


@pytest.fixture
def plaintext() -> bytes:
    """Типичный тестовый plaintext."""
    return b"Secret document content for testing."


@pytest.fixture
def short_salt() -> bytes:
    """Слишком короткая соль (< 16 байт)."""
    return b"short"


@pytest.fixture
def valid_salt() -> bytes:
    """Валидная соль (32 байта)."""
    import os

    return os.urandom(32)
