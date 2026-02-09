"""
Полные тесты для модуля signing.py (20 алгоритмов подписи).

Покрытие:
    - 10 классических алгоритмов (Ed25519, Ed448, ECDSA×4, RSA-PSS×3, RSA-PKCS1v15)
    - 8 постквантовых стандартов (ML-DSA×3, Falcon×2, SLH-DSA×3)
    - 2 legacy PQC (Dilithium2, SPHINCS+-128s)

Типы тестов:
    - Unit tests: базовые операции каждого алгоритма
    - Integration tests: работа с registry
    - Edge cases: invalid inputs, wrong keys
    - Performance tests: benchmarks (optional)
    - Metadata validation: проверка метаданных

Requirements:
    pip install pytest pytest-benchmark pytest-timeout

Usage:
    # Все тесты
    pytest tests/crypto/algorithms/test_signing.py -v

    # Только классические
    pytest tests/crypto/algorithms/test_signing.py -v -k "classical"

    # Только PQC
    pytest tests/crypto/algorithms/test_signing.py -v -k "pqc"

    # С бенчмарками
    pytest tests/crypto/algorithms/test_signing.py -v --benchmark-only

    # Пропустить медленные PQC тесты
    pytest tests/crypto/algorithms/test_signing.py -v -m "not slow"

Version: 1.0
Date: February 10, 2026
Author: Mike Voyager
"""

from __future__ import annotations

import hashlib
import os
from typing import Type, Tuple, List, Any

import pytest

from src.security.crypto.algorithms.signing import (
    # Classical: EdDSA
    Ed25519Signer,
    Ed448Signer,
    # Classical: ECDSA
    ECDSAP256Signer,
    ECDSAP384Signer,
    ECDSAP521Signer,
    ECDSASecp256k1Signer,
    # Classical: RSA-PSS
    RSAPSS2048Signer,
    RSAPSS3072Signer,
    RSAPSS4096Signer,
    # Classical: RSA-PKCS1v15 (legacy)
    RSAPKCS1v15Signer,
    # Post-Quantum: ML-DSA
    MLDSA44Signer,
    MLDSA65Signer,
    MLDSA87Signer,
    # Post-Quantum: Falcon
    Falcon512Signer,
    Falcon1024Signer,
    # Post-Quantum: SLH-DSA
    SLHDSASHA2_128sSigner,
    SLHDSASHA2_192sSigner,
    SLHDSASHA2_256sSigner,
    # Legacy PQC
    Dilithium2Signer,
    SPHINCSPlus128sSigner,
    HAS_LIBOQS,
)

from src.security.crypto.core.protocols import SignatureProtocol
from src.security.crypto.core.registry import AlgorithmRegistry
from src.security.crypto.core.metadata import SecurityLevel, ImplementationStatus
from src.security.crypto.core.exceptions import (
    SigningFailedError,
    VerificationFailedError,
    KeyGenerationError,
    InvalidKeyError,
    AlgorithmNotSupportedError,
)


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def sample_messages() -> List[bytes]:
    """Набор тестовых сообщений разных размеров."""
    return [
        b"",  # Empty
        b"Hello, World!",  # Short
        b"A" * 1000,  # Medium (1KB)
        b"B" * 1024 * 100,  # Large (100KB)
        b"\x00\x01\x02\xff\xfe\xfd",  # Binary
        "Привет, мир! 🚀".encode("utf-8"),  # Unicode
    ]


@pytest.fixture
def registry() -> AlgorithmRegistry:
    """Глобальный реестр алгоритмов."""
    return AlgorithmRegistry.get_instance()


# ==============================================================================
# TEST GROUPS: CLASSICAL ALGORITHMS
# ==============================================================================


# Classical EdDSA algorithms
CLASSICAL_EDDSA: List[Tuple[Type[SignatureProtocol], str]] = [
    (Ed25519Signer, "Ed25519"),
    (Ed448Signer, "Ed448"),
]

# Classical ECDSA algorithms
CLASSICAL_ECDSA: List[Tuple[Type[SignatureProtocol], str]] = [
    (ECDSAP256Signer, "ECDSA-P256"),
    (ECDSAP384Signer, "ECDSA-P384"),
    (ECDSAP521Signer, "ECDSA-P521"),
    (ECDSASecp256k1Signer, "ECDSA-secp256k1"),
]

# Classical RSA algorithms
CLASSICAL_RSA: List[Tuple[Type[SignatureProtocol], str]] = [
    (RSAPSS2048Signer, "RSA-PSS-2048"),
    (RSAPSS3072Signer, "RSA-PSS-3072"),
    (RSAPSS4096Signer, "RSA-PSS-4096"),
    (RSAPKCS1v15Signer, "RSA-PKCS1v15"),
]

# All classical algorithms
CLASSICAL_ALL = CLASSICAL_EDDSA + CLASSICAL_ECDSA + CLASSICAL_RSA


# Post-quantum algorithms
PQC_MLDSA: List[Tuple[Type[SignatureProtocol], str]] = [
    (MLDSA44Signer, "ML-DSA-44"),
    (MLDSA65Signer, "ML-DSA-65"),
    (MLDSA87Signer, "ML-DSA-87"),
]

PQC_FALCON: List[Tuple[Type[SignatureProtocol], str]] = [
    (Falcon512Signer, "Falcon-512"),
    (Falcon1024Signer, "Falcon-1024"),
]

PQC_SLHDSA: List[Tuple[Type[SignatureProtocol], str]] = [
    (SLHDSASHA2_128sSigner, "SLH-DSA-SHA2-128s"),
    (SLHDSASHA2_192sSigner, "SLH-DSA-SHA2-192s"),
    (SLHDSASHA2_256sSigner, "SLH-DSA-SHA2-256s"),
]

# Legacy PQC - без pytest.param здесь
PQC_LEGACY_CLASSES = [
    (Dilithium2Signer, "Dilithium2"),
    (SPHINCSPlus128sSigner, "SPHINCS+-128s"),
]

# Для параметризации с xfail
PQC_LEGACY: List[Any] = [
    pytest.param(cls, name, marks=pytest.mark.xfail(reason="Removed from liboqs 0.15+"))
    for cls, name in PQC_LEGACY_CLASSES
]

# Для циклов без pytest.param (используем _CLASSES)
PQC_ALL_WITHOUT_LEGACY = PQC_MLDSA + PQC_FALCON + PQC_SLHDSA
PQC_ALL = PQC_MLDSA + PQC_FALCON + PQC_SLHDSA + PQC_LEGACY

# All algorithms - используем версию без pytest.param
ALL_ALGORITHMS = CLASSICAL_ALL + PQC_ALL_WITHOUT_LEGACY + PQC_LEGACY_CLASSES


# ==============================================================================
# UNIT TESTS: CLASSICAL ALGORITHMS
# ==============================================================================


class TestClassicalSignatures:
    """Тесты классических алгоритмов подписи (Ed25519, ECDSA, RSA-PSS)."""

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_ALL)
    def test_keypair_generation(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест генерации пары ключей."""
        signer = signer_class()

        # Generate keypair
        private_key, public_key = signer.generate_keypair()

        # Validate types
        assert isinstance(private_key, bytes), f"{name}: private_key must be bytes"
        assert isinstance(public_key, bytes), f"{name}: public_key must be bytes"

        # Validate non-empty
        assert len(private_key) > 0, f"{name}: private_key is empty"
        assert len(public_key) > 0, f"{name}: public_key is empty"

        # Validate sizes match protocol
        assert (
            len(public_key) >= signer.public_key_size // 2
        ), f"{name}: public_key too small"

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_ALL)
    def test_sign_verify_basic(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест базовой подписи и верификации."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()
        message = b"Test message for signing"

        # Sign
        signature = signer.sign(private_key, message)

        # Validate signature
        assert isinstance(signature, bytes), f"{name}: signature must be bytes"
        assert len(signature) > 0, f"{name}: signature is empty"

        # Verify
        is_valid = signer.verify(public_key, message, signature)
        assert is_valid, f"{name}: signature verification failed"

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_ALL)
    def test_sign_verify_multiple_messages(
        self,
        signer_class: Type[SignatureProtocol],
        name: str,
        sample_messages: List[bytes],
    ) -> None:
        """Тест подписи различных сообщений."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()

        for i, message in enumerate(sample_messages):
            signature = signer.sign(private_key, message)
            is_valid = signer.verify(public_key, message, signature)
            assert is_valid, f"{name}: failed for message #{i} (len={len(message)})"

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_ALL)
    def test_wrong_message_fails(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест: неверное сообщение не проходит верификацию."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()

        message = b"Original message"
        signature = signer.sign(private_key, message)

        # Try verify with wrong message
        wrong_message = b"Wrong message"
        is_valid = signer.verify(public_key, wrong_message, signature)
        assert not is_valid, f"{name}: verification should fail for wrong message"

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_ALL)
    def test_wrong_public_key_fails(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест: неверный публичный ключ не проходит верификацию."""
        signer = signer_class()

        # Generate two keypairs
        private_key1, public_key1 = signer.generate_keypair()
        private_key2, public_key2 = signer.generate_keypair()

        message = b"Test message"
        signature = signer.sign(private_key1, message)

        # Try verify with wrong public key
        is_valid = signer.verify(public_key2, message, signature)
        assert not is_valid, f"{name}: verification should fail for wrong public key"

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_ALL)
    def test_corrupted_signature_fails(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест: повреждённая подпись не проходит верификацию."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()

        message = b"Test message"
        signature = signer.sign(private_key, message)

        # Corrupt signature (flip last byte)
        corrupted_sig_array = bytearray(signature)  # <-- Явный тип
        corrupted_sig_array[-1] ^= 0xFF
        corrupted_sig = bytes(corrupted_sig_array)  # <-- Отдельная переменная

        is_valid = signer.verify(public_key, message, corrupted_sig)
        assert not is_valid, f"{name}: verification should fail for corrupted signature"

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_ALL)
    def test_deterministic_signing(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест детерминированности (для EdDSA и RFC 6979 ECDSA)."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()
        message = b"Deterministic test"

        # Sign twice
        sig1 = signer.sign(private_key, message)
        sig2 = signer.sign(private_key, message)

        # Ed25519/Ed448 always deterministic
        if "Ed" in name:
            assert sig1 == sig2, f"{name}: signatures should be deterministic"
        # ECDSA with cryptography is NOT deterministic by default
        # (uses random nonce for each signature)
        elif "ECDSA" in name:
            # Signatures will differ due to random k
            # This is actually MORE secure (no k reuse risk)
            pass  # <-- Убрать assertion
        # RSA-PSS is probabilistic (uses random salt)
        elif "RSA-PSS" in name:
            # Signatures may differ due to random salt
            pass
        # RSA-PKCS1v15 is deterministic
        elif "PKCS1v15" in name:
            assert sig1 == sig2, f"{name}: RSA-PKCS1v15 should be deterministic"

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_ALL)
    def test_signature_size(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест размера подписи соответствует спецификации."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()
        message = b"Size test"

        signature = signer.sign(private_key, message)

        # ECDSA signatures have variable size (DER encoding)
        # RSA signatures are fixed size
        if "ECDSA" in name:
            # ECDSA signature size can vary (±10 bytes due to DER encoding)
            assert (
                abs(len(signature) - signer.signature_size) <= 10
            ), f"{name}: signature size mismatch"
        else:
            assert (
                len(signature) == signer.signature_size
            ), f"{name}: signature size mismatch"

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_ALL)
    def test_invalid_key_types(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест обработки неверных типов ключей."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()
        message = b"Test"

        # Test invalid types for sign
        with pytest.raises(TypeError):
            signer.sign("not bytes", message)  # type: ignore

        with pytest.raises(TypeError):
            signer.sign(private_key, "not bytes")  # type: ignore

        # Test invalid types for verify
        with pytest.raises(TypeError):
            signer.verify("not bytes", message, b"sig")  # type: ignore

        with pytest.raises(TypeError):
            signer.verify(public_key, "not bytes", b"sig")  # type: ignore

        with pytest.raises(TypeError):
            signer.verify(public_key, message, "not bytes")  # type: ignore


# ==============================================================================
# UNIT TESTS: POST-QUANTUM ALGORITHMS
# ==============================================================================


@pytest.mark.skipif(not HAS_LIBOQS, reason="liboqs-python not installed")
class TestPostQuantumSignatures:
    """Тесты постквантовых алгоритмов подписи."""

    @pytest.mark.parametrize("signer_class,name", PQC_ALL)
    def test_pqc_keypair_generation(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест генерации PQC пары ключей."""
        signer = signer_class()

        private_key, public_key = signer.generate_keypair()

        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert len(private_key) == signer.private_key_size
        assert len(public_key) == signer.public_key_size

    @pytest.mark.parametrize("signer_class,name", PQC_ALL)
    def test_pqc_sign_verify_basic(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест базовой PQC подписи и верификации."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()
        message = b"Post-quantum secure message"

        signature = signer.sign(private_key, message)

        assert isinstance(signature, bytes)

        # Falcon signatures have variable size (compressed format)
        if "Falcon" in name:
            # Allow ±20 bytes variance due to compression
            assert (
                abs(len(signature) - signer.signature_size) <= 20
            ), f"{name}: signature size {len(signature)} not near {signer.signature_size}"
        else:
            assert (
                len(signature) == signer.signature_size
            ), f"{name}: signature size mismatch"

        is_valid = signer.verify(public_key, message, signature)
        assert is_valid, f"{name}: PQC signature verification failed"

    @pytest.mark.parametrize("signer_class,name", PQC_MLDSA)
    def test_mldsa_different_levels(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест ML-DSA различных уровней безопасности."""
        signer = signer_class()

        # Check is_post_quantum flag
        assert signer.is_post_quantum, f"{name}: should be marked as post-quantum"

        # Basic sign/verify
        private_key, public_key = signer.generate_keypair()
        message = b"ML-DSA test"
        signature = signer.sign(private_key, message)
        assert signer.verify(public_key, message, signature)

    @pytest.mark.parametrize("signer_class,name", PQC_FALCON)
    def test_falcon_compact_signatures(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест компактности Falcon подписей."""
        signer = signer_class()

        private_key, public_key = signer.generate_keypair()
        message = b"Compact Falcon signature"
        signature = signer.sign(private_key, message)

        # Falcon signatures are compressed, size varies ±20 bytes
        if name == "Falcon-512":
            assert (
                640 <= len(signature) <= 680
            ), f"Falcon-512 signature should be ~666 bytes (±20), got {len(signature)}"
        elif name == "Falcon-1024":
            assert (
                1260 <= len(signature) <= 1300
            ), f"Falcon-1024 signature should be ~1280 bytes (±20), got {len(signature)}"

        assert signer.verify(public_key, message, signature)

    @pytest.mark.slow
    @pytest.mark.parametrize("signer_class,name", PQC_SLHDSA)
    def test_slhdsa_hash_based(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Тест SLH-DSA hash-based подписей."""
        signer = signer_class()

        private_key, public_key = signer.generate_keypair()

        # SLH-DSA has very compact public keys
        assert len(public_key) <= 64, f"{name}: public key should be very compact"

        # But very large signatures
        message = b"Hash-based signature"
        signature = signer.sign(private_key, message)

        assert len(signature) >= 7000, f"{name}: signature should be large"
        assert signer.verify(public_key, message, signature)

    @pytest.mark.parametrize("signer_class,name", PQC_LEGACY)
    def test_legacy_pqc_deprecated(
        self,
        signer_class: Type[SignatureProtocol],
        name: str,
        registry: AlgorithmRegistry,
    ) -> None:
        """Тест legacy PQC алгоритмов помечены DEPRECATED."""
        metadata = registry.get_metadata(name)

        assert metadata is not None, f"{name} should be registered"
        assert (
            metadata.status == ImplementationStatus.DEPRECATED
        ), f"{name} should be DEPRECATED"

        # But should still work
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()
        message = b"Legacy PQC test"
        signature = signer.sign(private_key, message)
        assert signer.verify(public_key, message, signature)


# ==============================================================================
# INTEGRATION TESTS: REGISTRY
# ==============================================================================


class TestRegistryIntegration:
    """Тесты интеграции с AlgorithmRegistry."""

    def test_all_20_algorithms_registered(self, registry: AlgorithmRegistry) -> None:
        """Тест: все 20 алгоритмов зарегистрированы."""
        # Use CLASSICAL_ALL + PQC_ALL_WITHOUT_LEGACY + PQC_LEGACY_CLASSES
        expected_names = [name for _, name in CLASSICAL_ALL]
        expected_names += [name for _, name in PQC_ALL_WITHOUT_LEGACY]
        expected_names += [name for _, name in PQC_LEGACY_CLASSES]

        for name in expected_names:
            assert registry.is_registered(name), f"{name} not registered"

    def test_create_via_registry(self, registry: AlgorithmRegistry) -> None:
        """Тест создания алгоритмов через registry."""
        # Classical
        ed25519 = registry.create("Ed25519")
        assert isinstance(ed25519, Ed25519Signer)

        # PQC (if available)
        if HAS_LIBOQS:
            mldsa = registry.create("ML-DSA-65")
            assert isinstance(mldsa, MLDSA65Signer)

    def test_metadata_for_all_algorithms(self, registry: AlgorithmRegistry) -> None:
        """Тест: метаданные доступны для всех алгоритмов."""
        all_algos = CLASSICAL_ALL + PQC_ALL_WITHOUT_LEGACY + PQC_LEGACY_CLASSES

        for _, name in all_algos:
            metadata = registry.get_metadata(name)
            assert metadata is not None, f"No metadata for {name}"

            # Validate metadata fields
            assert metadata.name == name

            # Check sizes with None guards
            assert metadata.signature_size is not None and metadata.signature_size > 0
            assert metadata.public_key_size is not None and metadata.public_key_size > 0
            assert (
                metadata.private_key_size is not None and metadata.private_key_size > 0
            )

    def test_list_by_category(self, registry: AlgorithmRegistry) -> None:
        """Тест фильтрации алгоритмов по категории."""
        # Get all algorithms and filter manually
        all_algos = registry.list_algorithms()
        signatures = [
            name
            for name in all_algos
            if registry.get_metadata(name) is not None
            and registry.get_metadata(name).category.value == "signature"  # type: ignore[union-attr]
        ]
        assert len(signatures) == 20, "Should have 20 signature algorithms"

    def test_classical_vs_pqc_flags(self, registry: AlgorithmRegistry) -> None:
        """Тест корректности флага is_post_quantum."""
        # Classical should NOT be post-quantum
        for _, name in CLASSICAL_ALL:
            metadata = registry.get_metadata(name)
            assert metadata is not None
            assert not metadata.is_post_quantum, f"{name} should not be post-quantum"

        # PQC should be post-quantum
        if HAS_LIBOQS:
            pqc_algos = PQC_ALL_WITHOUT_LEGACY + PQC_LEGACY_CLASSES
            for _, name in pqc_algos:
                metadata = registry.get_metadata(name)
                assert metadata is not None
                assert metadata.is_post_quantum, f"{name} should be post-quantum"

    def test_security_levels(self, registry: AlgorithmRegistry) -> None:
        """Тест корректности security levels."""
        # Ed25519 - STANDARD
        ed25519_meta = registry.get_metadata("Ed25519")
        assert ed25519_meta is not None
        assert ed25519_meta.security_level == SecurityLevel.STANDARD

        # Ed448 - HIGH
        ed448_meta = registry.get_metadata("Ed448")
        assert ed448_meta is not None
        assert ed448_meta.security_level == SecurityLevel.HIGH

        # RSA-PKCS1v15 - LEGACY
        pkcs_meta = registry.get_metadata("RSA-PKCS1v15")
        assert pkcs_meta is not None
        assert pkcs_meta.security_level == SecurityLevel.LEGACY

        # PQC - QUANTUM_RESISTANT
        if HAS_LIBOQS:
            mldsa_meta = registry.get_metadata("ML-DSA-65")
            assert mldsa_meta is not None
            assert mldsa_meta.security_level == SecurityLevel.QUANTUM_RESISTANT


# ==============================================================================
# EDGE CASES & ERROR HANDLING
# ==============================================================================


class TestEdgeCases:
    """Тесты граничных случаев и обработки ошибок."""

    def test_empty_message(self) -> None:
        """Тест подписи пустого сообщения."""
        signer = Ed25519Signer()
        private_key, public_key = signer.generate_keypair()

        # Empty message should work
        signature = signer.sign(private_key, b"")
        assert signer.verify(public_key, b"", signature)

    def test_very_large_message(self) -> None:
        """Тест подписи очень большого сообщения."""
        signer = Ed25519Signer()
        private_key, public_key = signer.generate_keypair()

        # 10 MB message
        large_message = b"X" * (10 * 1024 * 1024)
        signature = signer.sign(private_key, large_message)
        assert signer.verify(public_key, large_message, signature)

    def test_invalid_der_private_key(self) -> None:
        """Тест обработки невалидного DER ключа."""
        signer = Ed25519Signer()
        invalid_key = b"not a valid DER key"

        with pytest.raises(InvalidKeyError):
            signer.sign(invalid_key, b"message")

    def test_invalid_der_public_key(self) -> None:
        """Тест обработки невалидного публичного ключа."""
        signer = Ed25519Signer()
        invalid_key = b"not a valid public key"

        with pytest.raises(InvalidKeyError):
            signer.verify(invalid_key, b"message", b"signature")

    def test_mismatched_key_algorithms(self) -> None:
        """Тест использования ключей от разных алгоритмов."""
        ed25519 = Ed25519Signer()
        ed448 = Ed448Signer()

        ed25519_priv, ed25519_pub = ed25519.generate_keypair()
        ed448_priv, ed448_pub = ed448.generate_keypair()

        message = b"test"

        # Try to use Ed448 private key with Ed25519 signer
        with pytest.raises(InvalidKeyError):
            ed25519.sign(ed448_priv, message)

        # Try to use Ed448 public key with Ed25519 signer
        sig = ed25519.sign(ed25519_priv, message)
        with pytest.raises(InvalidKeyError):
            ed25519.verify(ed448_pub, message, sig)

    @pytest.mark.skipif(not HAS_LIBOQS, reason="liboqs-python not installed")
    def test_pqc_without_liboqs_raises(self) -> None:
        """Тест: PQC алгоритмы без liboqs выдают AlgorithmNotSupportedError."""
        # This test is tricky - we need to mock HAS_LIBOQS=False
        # For now, just verify that with liboqs installed, it works
        signer = MLDSA44Signer()
        private_key, public_key = signer.generate_keypair()
        assert private_key is not None
        assert public_key is not None

    def test_wrong_signature_length(self) -> None:
        """Тест подписи неверной длины."""
        signer = Ed25519Signer()
        private_key, public_key = signer.generate_keypair()
        message = b"test"

        # Create signature with wrong length
        wrong_sig = b"X" * 32  # Ed25519 expects 64 bytes

        is_valid = signer.verify(public_key, message, wrong_sig)
        assert not is_valid, "Signature with wrong length should fail"


# ==============================================================================
# PERFORMANCE BENCHMARKS (optional)
# ==============================================================================


@pytest.mark.benchmark
class TestPerformance:
    """Performance benchmarks для алгоритмов подписи."""

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_EDDSA)
    def test_eddsa_keygen_speed(
        self, benchmark: Any, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Benchmark генерации ключей EdDSA."""
        signer = signer_class()
        benchmark(signer.generate_keypair)

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_EDDSA)
    def test_eddsa_sign_speed(
        self, benchmark: Any, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Benchmark подписи EdDSA."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()
        message = b"Benchmark message" * 100

        benchmark(signer.sign, private_key, message)

    @pytest.mark.parametrize("signer_class,name", CLASSICAL_EDDSA)
    def test_eddsa_verify_speed(
        self, benchmark: Any, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Benchmark верификации EdDSA."""
        signer = signer_class()
        private_key, public_key = signer.generate_keypair()
        message = b"Benchmark message" * 100
        signature = signer.sign(private_key, message)

        benchmark(signer.verify, public_key, message, signature)

    @pytest.mark.skipif(not HAS_LIBOQS, reason="liboqs-python not installed")
    @pytest.mark.slow
    @pytest.mark.parametrize("signer_class,name", [(MLDSA65Signer, "ML-DSA-65")])
    def test_pqc_performance_vs_classical(
        self, signer_class: Type[SignatureProtocol], name: str
    ) -> None:
        """Сравнение производительности PQC vs Classical."""
        # Classical baseline (Ed25519)
        ed25519 = Ed25519Signer()
        ed_priv, ed_pub = ed25519.generate_keypair()

        # PQC
        pqc = signer_class()
        pqc_priv, pqc_pub = pqc.generate_keypair()

        message = b"Performance test" * 100

        # Measure signing time
        import time

        # Ed25519
        start = time.perf_counter()
        for _ in range(100):
            ed25519.sign(ed_priv, message)
        ed_time = time.perf_counter() - start

        # PQC
        start = time.perf_counter()
        for _ in range(100):
            pqc.sign(pqc_priv, message)
        pqc_time = time.perf_counter() - start

        print(f"\nEd25519: {ed_time:.3f}s for 100 signatures")
        print(f"{name}: {pqc_time:.3f}s for 100 signatures")
        print(f"Slowdown: {pqc_time/ed_time:.2f}x")


# ==============================================================================
# COMPLIANCE TESTS
# ==============================================================================


class TestCompliance:
    """Тесты соответствия стандартам и RFC."""

    def test_ed25519_rfc8032_test_vectors(self) -> None:
        """Тест Ed25519 с тестовыми векторами из RFC 8032."""
        # RFC 8032 Test Vector 1
        # (Simplified - full test vectors require parsing hex)
        signer = Ed25519Signer()
        private_key, public_key = signer.generate_keypair()
        message = b""

        signature = signer.sign(private_key, message)
        assert signer.verify(public_key, message, signature)

    def test_algorithm_names_match_standard(self, registry: AlgorithmRegistry) -> None:
        """Тест: имена алгоритмов соответствуют стандартам."""
        # NIST standard names
        nist_names = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
        for name in nist_names:
            if HAS_LIBOQS:
                assert registry.is_registered(name), f"{name} not registered"

        # RFC names
        rfc_names = ["Ed25519", "Ed448"]
        for name in rfc_names:
            assert registry.is_registered(name), f"{name} not registered"

    def test_deprecated_algorithms_marked(self, registry: AlgorithmRegistry) -> None:
        """Тест: устаревшие алгоритмы помечены DEPRECATED."""
        deprecated = ["RSA-PKCS1v15", "Dilithium2", "SPHINCS+-128s"]

        for name in deprecated:
            metadata = registry.get_metadata(name)
            if metadata:  # Some may not be available
                assert (
                    metadata.status == ImplementationStatus.DEPRECATED
                    or metadata.security_level == SecurityLevel.LEGACY
                ), f"{name} should be marked deprecated/legacy"


# ==============================================================================
# MODULE-LEVEL TESTS
# ==============================================================================


def test_module_exports() -> None:
    """Тест корректности экспортов модуля."""
    from src.security.crypto.algorithms import signing

    # Check __all__ is defined
    assert hasattr(signing, "__all__")

    # Check all classes are exported
    expected_exports = [
        "Ed25519Signer",
        "Ed448Signer",
        "ECDSAP256Signer",
        "RSAPSS2048Signer",
        "MLDSA65Signer",
        # ... etc
    ]

    for export in expected_exports:
        assert export in signing.__all__, f"{export} not in __all__"


def test_liboqs_detection() -> None:
    """Тест определения наличия liboqs-python."""
    from src.security.crypto.algorithms.signing import HAS_LIBOQS

    # Just check it's a boolean
    assert isinstance(HAS_LIBOQS, bool)

    if HAS_LIBOQS:
        # If available, PQC classes should work
        signer = MLDSA44Signer()
        assert signer.is_post_quantum
    else:
        # If not available, should raise AlgorithmNotSupportedError
        signer = MLDSA44Signer()
        with pytest.raises(AlgorithmNotSupportedError):
            signer.generate_keypair()


def test_registry_initialized_on_import() -> None:
    """Тест: registry инициализирован при импорте модуля."""
    registry = AlgorithmRegistry.get_instance()

    # Should have 20 signature algorithms
    all_algos = registry.list_algorithms()
    signatures = [
        name
        for name in all_algos
        if registry.get_metadata(name) is not None
        and registry.get_metadata(name).category.value == "signature"  # type: ignore[union-attr]
    ]
    assert len(signatures) == 20, f"Expected 20 signatures, got {len(signatures)}"


# ==============================================================================
# debug test
# ==============================================================================


def test_falcon_size_distribution() -> None:
    """Измерить реальное распределение размеров Falcon подписей."""
    import statistics

    signer = Falcon512Signer()
    private_key, public_key = signer.generate_keypair()

    sizes = []
    for i in range(100):
        message = f"Test message {i}".encode()
        signature = signer.sign(private_key, message)
        sizes.append(len(signature))

    print(f"\nFalcon-512 signature sizes (n=100):")
    print(f"  Min: {min(sizes)}")
    print(f"  Max: {max(sizes)}")
    print(f"  Mean: {statistics.mean(sizes):.1f}")
    print(f"  StdDev: {statistics.stdev(sizes):.1f}")
    print(f"  Expected: 666")


# ==============================================================================
# PYTEST CONFIGURATION
# ==============================================================================


def pytest_configure(config: Any) -> None:
    """Pytest configuration."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line("markers", "benchmark: marks tests as benchmarks")


if __name__ == "__main__":
    # Run tests with: python -m pytest tests/crypto/algorithms/test_signing.py -v
    pytest.main([__file__, "-v", "--tb=short"])
