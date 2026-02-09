"""
Тесты для модуля key_exchange.py (Classical ECDH + Post-Quantum KEM).

Тестируемые алгоритмы:
Classical ECDH (5):
- X25519, X448 (RFC 7748)
- ECDH-P256, ECDH-P384, ECDH-P521 (NIST curves)

Post-Quantum KEM (3):
- ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203)

Покрытие:
- Генерация ключей
- Key exchange (ECDH)
- Encapsulation/Decapsulation (KEM)
- Валидация размеров ключей
- Обработка ошибок (invalid keys, corrupted data)
- Metadata и registry
- RFC 7748 test vectors (X25519, X448)
- Edge cases

Author: Mike Voyager
Date: February 10, 2026
"""

from __future__ import annotations

import pytest
from typing import Type, Any

from src.security.crypto.algorithms.key_exchange import (
    # Classical ECDH
    X25519KeyExchange,
    X448KeyExchange,
    ECDHP256KeyExchange,
    ECDHP384KeyExchange,
    ECDHP521KeyExchange,
    # Post-Quantum KEM
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    # Registry
    get_kex_algorithm,
    KEY_EXCHANGE_ALGORITHMS,
    ALL_METADATA,
    # Constants
    X25519_KEY_SIZE,
    X448_KEY_SIZE,
    MLKEM512_PUBLIC_KEY_SIZE,
    MLKEM512_PRIVATE_KEY_SIZE,
    MLKEM512_CIPHERTEXT_SIZE,
    MLKEM768_PUBLIC_KEY_SIZE,
    MLKEM768_PRIVATE_KEY_SIZE,
    MLKEM768_CIPHERTEXT_SIZE,
    MLKEM1024_PUBLIC_KEY_SIZE,
    MLKEM1024_PRIVATE_KEY_SIZE,
    MLKEM1024_CIPHERTEXT_SIZE,
    SHARED_SECRET_SIZE,
)
from src.security.crypto.core.protocols import KeyExchangeProtocol
from src.security.crypto.core.metadata import (
    AlgorithmCategory,
    SecurityLevel,
    FloppyFriendly,
    ImplementationStatus,
)
from src.security.crypto.core.exceptions import (
    KeyGenerationError,
    CryptoError,
    InvalidKeyError,
    AlgorithmNotSupportedError,
)

# Skip PQC tests if liboqs not available
try:
    import oqs

    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False

# Parametrize data: (class, name, key_size, expected_shared_secret_size)
CLASSICAL_ECDH_VARIANTS = [
    (X25519KeyExchange, "X25519", X25519_KEY_SIZE, SHARED_SECRET_SIZE),
    (
        X448KeyExchange,
        "X448",
        X448_KEY_SIZE,
        X448_KEY_SIZE,
    ),  # X448 uses 56-byte shared secret
    # ECDH P-curves use DER encoding, so key_size is approximate
    (ECDHP256KeyExchange, "ECDH-P256", None, SHARED_SECRET_SIZE),
    (ECDHP384KeyExchange, "ECDH-P384", None, 48),  # P-384 shared secret
    (ECDHP521KeyExchange, "ECDH-P521", None, 66),  # P-521 shared secret
]

PQC_KEM_VARIANTS = [
    (
        MLKEM512,
        "ML-KEM-512",
        MLKEM512_PUBLIC_KEY_SIZE,
        MLKEM512_PRIVATE_KEY_SIZE,
        MLKEM512_CIPHERTEXT_SIZE,
    ),
    (
        MLKEM768,
        "ML-KEM-768",
        MLKEM768_PUBLIC_KEY_SIZE,
        MLKEM768_PRIVATE_KEY_SIZE,
        MLKEM768_CIPHERTEXT_SIZE,
    ),
    (
        MLKEM1024,
        "ML-KEM-1024",
        MLKEM1024_PUBLIC_KEY_SIZE,
        MLKEM1024_PRIVATE_KEY_SIZE,
        MLKEM1024_CIPHERTEXT_SIZE,
    ),
]


# ==============================================================================
# TEST: CLASSICAL ECDH - BASIC FUNCTIONALITY
# ==============================================================================


class TestClassicalECDHBasics:
    """Базовые тесты для classical ECDH алгоритмов."""

    @pytest.mark.parametrize(
        "kex_class,name,key_size,shared_secret_size", CLASSICAL_ECDH_VARIANTS
    )
    def test_keypair_generation(
        self,
        kex_class: Type[KeyExchangeProtocol],
        name: str,
        key_size: int | None,
        shared_secret_size: int,
    ) -> None:
        """Тест генерации keypair для classical ECDH."""
        kex = kex_class()
        private_key, public_key = kex.generate_keypair()

        # Validate types
        assert isinstance(private_key, bytes), f"{name}: private_key должен быть bytes"
        assert isinstance(public_key, bytes), f"{name}: public_key должен быть bytes"

        # Validate sizes
        assert len(private_key) > 0, f"{name}: private_key пустой"
        assert len(public_key) > 0, f"{name}: public_key пустой"

        # For X25519/X448 (raw keys), check exact size
        if key_size is not None:
            assert (
                len(private_key) == key_size
            ), f"{name}: private_key should be {key_size} bytes"
            assert (
                len(public_key) == key_size
            ), f"{name}: public_key should be {key_size} bytes"

    @pytest.mark.parametrize(
        "kex_class,name,key_size,shared_secret_size", CLASSICAL_ECDH_VARIANTS
    )
    def test_key_exchange_basic(
        self,
        kex_class: Type[KeyExchangeProtocol],
        name: str,
        key_size: int | None,
        shared_secret_size: int,
    ) -> None:
        """Тест базового key exchange (Alice & Bob)."""
        kex = kex_class()

        # Alice generates keypair
        priv_alice, pub_alice = kex.generate_keypair()

        # Bob generates keypair
        priv_bob, pub_bob = kex.generate_keypair()

        # Alice derives shared secret using Bob's public key
        shared_alice = kex.derive_shared_secret(priv_alice, pub_bob)

        # Bob derives shared secret using Alice's public key
        shared_bob = kex.derive_shared_secret(priv_bob, pub_alice)

        # Shared secrets must match
        assert shared_alice == shared_bob, f"{name}: shared secrets don't match"

        # Validate shared secret size
        assert len(shared_alice) == shared_secret_size, (
            f"{name}: shared secret should be {shared_secret_size} bytes, "
            f"got {len(shared_alice)}"
        )

    @pytest.mark.parametrize(
        "kex_class,name,key_size,shared_secret_size", CLASSICAL_ECDH_VARIANTS
    )
    def test_multiple_exchanges(
        self,
        kex_class: Type[KeyExchangeProtocol],
        name: str,
        key_size: int | None,
        shared_secret_size: int,
    ) -> None:
        """Тест множественных key exchanges."""
        kex = kex_class()

        # Generate 3 keypairs
        keypairs = [kex.generate_keypair() for _ in range(3)]

        # Each pair should be able to derive shared secret
        for i in range(len(keypairs)):
            for j in range(i + 1, len(keypairs)):
                priv_i, pub_i = keypairs[i]
                priv_j, pub_j = keypairs[j]

                shared_i = kex.derive_shared_secret(priv_i, pub_j)
                shared_j = kex.derive_shared_secret(priv_j, pub_i)

                assert shared_i == shared_j, f"{name}: exchange {i}↔{j} failed"

    @pytest.mark.parametrize(
        "kex_class,name,key_size,shared_secret_size", CLASSICAL_ECDH_VARIANTS
    )
    def test_deterministic_shared_secret(
        self,
        kex_class: Type[KeyExchangeProtocol],
        name: str,
        key_size: int | None,
        shared_secret_size: int,
    ) -> None:
        """Тест что shared secret детерминирован (для одних ключей всегда одинаковый)."""
        kex = kex_class()

        priv_a, pub_a = kex.generate_keypair()
        priv_b, pub_b = kex.generate_keypair()

        # Derive shared secret multiple times
        shared1 = kex.derive_shared_secret(priv_a, pub_b)
        shared2 = kex.derive_shared_secret(priv_a, pub_b)
        shared3 = kex.derive_shared_secret(priv_a, pub_b)

        # All should be identical
        assert shared1 == shared2 == shared3, f"{name}: shared secret not deterministic"


# ==============================================================================
# TEST: CLASSICAL ECDH - ERROR HANDLING
# ==============================================================================


class TestClassicalECDHErrors:
    """Тесты обработки ошибок для classical ECDH."""

    @pytest.mark.parametrize(
        "kex_class,name,key_size,shared_secret_size", CLASSICAL_ECDH_VARIANTS
    )
    def test_invalid_private_key_type(
        self,
        kex_class: Type[KeyExchangeProtocol],
        name: str,
        key_size: int | None,
        shared_secret_size: int,
    ) -> None:
        """Тест что не-bytes private_key вызывает TypeError."""
        kex = kex_class()
        _, pub = kex.generate_keypair()

        with pytest.raises(TypeError) as exc_info:
            kex.derive_shared_secret("not bytes", pub)  # type: ignore[arg-type]

        assert "private_key" in str(exc_info.value).lower()

    @pytest.mark.parametrize(
        "kex_class,name,key_size,shared_secret_size", CLASSICAL_ECDH_VARIANTS
    )
    def test_invalid_public_key_type(
        self,
        kex_class: Type[KeyExchangeProtocol],
        name: str,
        key_size: int | None,
        shared_secret_size: int,
    ) -> None:
        """Тест что не-bytes peer_public_key вызывает TypeError."""
        kex = kex_class()
        priv, _ = kex.generate_keypair()

        with pytest.raises(TypeError) as exc_info:
            kex.derive_shared_secret(priv, "not bytes")  # type: ignore[arg-type]

        assert "public_key" in str(exc_info.value).lower()

    def test_x25519_invalid_key_size(self) -> None:
        """Тест что неверный размер ключа X25519 вызывает InvalidKeyError."""
        kex = X25519KeyExchange()
        priv, pub = kex.generate_keypair()

        # Wrong size keys
        wrong_priv = b"short"
        wrong_pub = b"also_short"

        with pytest.raises(InvalidKeyError):
            kex.derive_shared_secret(wrong_priv, pub)

        with pytest.raises(InvalidKeyError):
            kex.derive_shared_secret(priv, wrong_pub)

    def test_x448_invalid_key_size(self) -> None:
        """Тест что неверный размер ключа X448 вызывает InvalidKeyError."""
        kex = X448KeyExchange()
        priv, pub = kex.generate_keypair()

        wrong_priv = b"x" * 32  # X448 needs 56 bytes
        wrong_pub = b"y" * 32

        with pytest.raises(InvalidKeyError):
            kex.derive_shared_secret(wrong_priv, pub)

        with pytest.raises(InvalidKeyError):
            kex.derive_shared_secret(priv, wrong_pub)

    @pytest.mark.parametrize(
        "kex_class,name,key_size,shared_secret_size", CLASSICAL_ECDH_VARIANTS
    )
    def test_corrupted_keys(
        self,
        kex_class: Type[KeyExchangeProtocol],
        name: str,
        key_size: int | None,
        shared_secret_size: int,
    ) -> None:
        """Тест что испорченные ключи вызывают ошибку."""
        kex = kex_class()
        priv, pub = kex.generate_keypair()

        # Corrupt keys (random bytes)
        corrupted_priv = b"corrupted_private_key_data_invalid"
        corrupted_pub = b"corrupted_public_key_data_invalid"

        # Should raise InvalidKeyError or CryptoError
        with pytest.raises((InvalidKeyError, CryptoError)):
            kex.derive_shared_secret(corrupted_priv, pub)

        with pytest.raises((InvalidKeyError, CryptoError)):
            kex.derive_shared_secret(priv, corrupted_pub)


# ==============================================================================
# TEST: RFC 7748 TEST VECTORS (X25519, X448)
# ==============================================================================


class TestRFC7748Vectors:
    """Тесты с официальными test vectors из RFC 7748."""

    def test_x25519_rfc7748_vector1(self) -> None:
        """
        RFC 7748 Section 6.1 - X25519 test vector.

        Alice's private key:
          77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
        Alice's public key:
          8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a

        Bob's private key:
          5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
        Bob's public key:
          de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f

        Expected shared secret:
          4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
        """
        kex = X25519KeyExchange()

        # Alice's keys
        alice_priv = bytes.fromhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        )
        alice_pub = bytes.fromhex(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        )

        # Bob's keys
        bob_priv = bytes.fromhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        )
        bob_pub = bytes.fromhex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        )

        # Expected shared secret
        expected_shared = bytes.fromhex(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )

        # Compute shared secrets
        shared_alice = kex.derive_shared_secret(alice_priv, bob_pub)
        shared_bob = kex.derive_shared_secret(bob_priv, alice_pub)

        # Verify
        assert shared_alice == expected_shared, "Alice's shared secret mismatch"
        assert shared_bob == expected_shared, "Bob's shared secret mismatch"
        assert shared_alice == shared_bob

    def test_x448_rfc7748_vector1(self) -> None:
        """
        RFC 7748 Section 6.2 - X448 test vector.

        Alice's private key:
          9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d
          d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b
        Alice's public key:
          9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c
          22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0

        Bob's private key:
          1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d
          6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d
        Bob's public key:
          3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430
          27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609

        Expected shared secret:
          07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b
          b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d
        """
        kex = X448KeyExchange()

        # Alice's keys
        alice_priv = bytes.fromhex(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
            "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
        )
        alice_pub = bytes.fromhex(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
            "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        )

        # Bob's keys
        bob_priv = bytes.fromhex(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
            "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
        )
        bob_pub = bytes.fromhex(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
            "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
        )

        # Expected shared secret
        expected_shared = bytes.fromhex(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
            "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
        )

        # Compute shared secrets
        shared_alice = kex.derive_shared_secret(alice_priv, bob_pub)
        shared_bob = kex.derive_shared_secret(bob_priv, alice_pub)

        # Verify
        assert shared_alice == expected_shared, "Alice's shared secret mismatch"
        assert shared_bob == expected_shared, "Bob's shared secret mismatch"
        assert shared_alice == shared_bob


# ==============================================================================
# TEST: POST-QUANTUM KEM - BASIC FUNCTIONALITY
# ==============================================================================


@pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs-python not installed")
class TestPQCKEMBasics:
    """Базовые тесты для post-quantum KEM алгоритмов."""

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_keypair_generation(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест генерации keypair для PQC KEM."""
        kem = kem_class()
        private_key, public_key = kem.generate_keypair()  # type: ignore[attr-defined]

        # Validate types
        assert isinstance(private_key, bytes), f"{name}: private_key должен быть bytes"
        assert isinstance(public_key, bytes), f"{name}: public_key должен быть bytes"

        # Validate sizes
        assert (
            len(private_key) == priv_size
        ), f"{name}: private_key should be {priv_size} bytes, got {len(private_key)}"
        assert (
            len(public_key) == pub_size
        ), f"{name}: public_key should be {pub_size} bytes, got {len(public_key)}"

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_encapsulate_decapsulate(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест полного цикла encapsulate → decapsulate."""
        kem = kem_class()

        # Receiver (Bob) generates keypair
        priv_bob, pub_bob = kem.generate_keypair()  # type: ignore[attr-defined]

        # Sender (Alice) encapsulates
        ciphertext, shared_alice = kem.encapsulate(pub_bob)  # type: ignore[attr-defined]

        # Receiver (Bob) decapsulates
        shared_bob = kem.decapsulate(priv_bob, ciphertext)  # type: ignore[attr-defined]

        # Shared secrets must match
        assert shared_alice == shared_bob, f"{name}: shared secrets don't match"

        # Validate sizes
        assert (
            len(ciphertext) == ct_size
        ), f"{name}: ciphertext should be {ct_size} bytes, got {len(ciphertext)}"
        assert (
            len(shared_alice) == SHARED_SECRET_SIZE
        ), f"{name}: shared secret should be {SHARED_SECRET_SIZE} bytes"

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_multiple_encapsulations(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест что каждое encapsulation создаёт разный ciphertext."""
        kem = kem_class()

        priv, pub = kem.generate_keypair()  # type: ignore[attr-defined]

        # Encapsulate multiple times with same public key
        ct1, shared1 = kem.encapsulate(pub)  # type: ignore[attr-defined]
        ct2, shared2 = kem.encapsulate(pub)  # type: ignore[attr-defined]
        ct3, shared3 = kem.encapsulate(pub)  # type: ignore[attr-defined]

        # Ciphertexts должны быть разные (randomized)
        assert ct1 != ct2 != ct3, f"{name}: ciphertexts should be different"

        # Shared secrets должны быть разные
        assert (
            shared1 != shared2 != shared3
        ), f"{name}: shared secrets should be different"

        # But all должны decapsulate correctly
        assert kem.decapsulate(priv, ct1) == shared1  # type: ignore[attr-defined]
        assert kem.decapsulate(priv, ct2) == shared2  # type: ignore[attr-defined]
        assert kem.decapsulate(priv, ct3) == shared3  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_derive_shared_secret_compatibility(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест что derive_shared_secret работает (compatibility с KeyExchangeProtocol)."""
        kem = kem_class()

        priv, pub = kem.generate_keypair()  # type: ignore[attr-defined]

        # Use derive_shared_secret (compatibility method)
        shared = kem.derive_shared_secret(priv, pub)  # type: ignore[attr-defined]

        assert isinstance(shared, bytes)
        assert len(shared) == SHARED_SECRET_SIZE


# ==============================================================================
# TEST: POST-QUANTUM KEM - ERROR HANDLING
# ==============================================================================


@pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs-python not installed")
class TestPQCKEMErrors:
    """Тесты обработки ошибок для PQC KEM."""

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_invalid_public_key_type(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест что не-bytes public_key вызывает TypeError."""
        kem = kem_class()

        with pytest.raises(TypeError):
            kem.encapsulate("not bytes")  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_invalid_public_key_size(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест что неверный размер public_key вызывает InvalidKeyError."""
        kem = kem_class()

        wrong_pub = b"x" * (pub_size // 2)  # Wrong size

        with pytest.raises(InvalidKeyError):
            kem.encapsulate(wrong_pub)  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_invalid_private_key_type(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест что не-bytes private_key вызывает TypeError."""
        kem = kem_class()
        _, pub = kem.generate_keypair()  # type: ignore[attr-defined]
        ct, _ = kem.encapsulate(pub)  # type: ignore[attr-defined]

        with pytest.raises(TypeError):
            kem.decapsulate("not bytes", ct)  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_invalid_private_key_size(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест что неверный размер private_key вызывает InvalidKeyError."""
        kem = kem_class()
        _, pub = kem.generate_keypair()  # type: ignore[attr-defined]
        ct, _ = kem.encapsulate(pub)  # type: ignore[attr-defined]

        wrong_priv = b"x" * (priv_size // 2)  # Wrong size

        with pytest.raises(InvalidKeyError):
            kem.decapsulate(wrong_priv, ct)  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_invalid_ciphertext_type(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест что не-bytes ciphertext вызывает TypeError."""
        kem = kem_class()
        priv, _ = kem.generate_keypair()  # type: ignore[attr-defined]

        with pytest.raises(TypeError):
            kem.decapsulate(priv, "not bytes")  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_invalid_ciphertext_size(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест что неверный размер ciphertext вызывает InvalidKeyError."""
        kem = kem_class()
        priv, _ = kem.generate_keypair()  # type: ignore[attr-defined]

        wrong_ct = b"x" * (ct_size // 2)  # Wrong size

        with pytest.raises(InvalidKeyError):
            kem.decapsulate(priv, wrong_ct)  # type: ignore[attr-defined]

    @pytest.mark.parametrize(
        "kem_class,name,pub_size,priv_size,ct_size", PQC_KEM_VARIANTS
    )
    def test_wrong_private_key_decapsulation(
        self,
        kem_class: Type[object],
        name: str,
        pub_size: int,
        priv_size: int,
        ct_size: int,
    ) -> None:
        """Тест что decapsulation с неверным приватным ключом не вызывает ошибку, но даёт другой shared secret."""
        kem = kem_class()

        # Generate two keypairs
        priv1, pub1 = kem.generate_keypair()  # type: ignore[attr-defined]
        priv2, pub2 = kem.generate_keypair()  # type: ignore[attr-defined]

        # Encapsulate with pub1
        ct, shared_correct = kem.encapsulate(pub1)  # type: ignore[attr-defined]

        # Try to decapsulate with priv2 (wrong key)
        # KEM decapsulation может не fail, но даст неверный shared secret
        shared_wrong = kem.decapsulate(priv2, ct)  # type: ignore[attr-defined]

        # Shared secrets должны быть разные
        assert (
            shared_correct != shared_wrong
        ), f"{name}: decapsulation with wrong key should give different shared secret"


# ==============================================================================
# TEST: REGISTRY & METADATA
# ==============================================================================


class TestRegistry:
    """Тесты registry и metadata."""

    def test_all_algorithms_registered(self) -> None:
        """Тест что все 8 алгоритмов зарегистрированы."""
        assert len(KEY_EXCHANGE_ALGORITHMS) == 8, "Должно быть 8 KEX алгоритмов"

        expected_names = {
            "x25519",
            "x448",
            "ecdh-p256",
            "ecdh-p384",
            "ecdh-p521",
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
        }
        actual_names = set(KEY_EXCHANGE_ALGORITHMS.keys())

        assert (
            actual_names == expected_names
        ), f"Неверные имена алгоритмов: {actual_names}"

    def test_get_kex_algorithm(self) -> None:
        """Тест фабричной функции get_kex_algorithm."""
        # Classical ECDH
        for algo_id in ["x25519", "x448", "ecdh-p256", "ecdh-p384", "ecdh-p521"]:
            kex = get_kex_algorithm(algo_id)
            assert kex is not None
            assert hasattr(kex, "generate_keypair")
            assert hasattr(kex, "derive_shared_secret")

        # PQC KEM (skip if liboqs not available)
        if LIBOQS_AVAILABLE:
            for algo_id in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
                kem = get_kex_algorithm(algo_id)
                assert kem is not None
                assert hasattr(kem, "generate_keypair")
                assert hasattr(kem, "encapsulate")
                assert hasattr(kem, "decapsulate")

    def test_get_kex_algorithm_invalid(self) -> None:
        """Тест что несуществующий алгоритм вызывает KeyError."""
        with pytest.raises(KeyError) as exc_info:
            get_kex_algorithm("invalid-kex-999")

        assert "not found" in str(exc_info.value).lower()
        assert "invalid-kex-999" in str(exc_info.value)

    def test_metadata_count(self) -> None:
        """Тест что метаданные для всех 8 алгоритмов присутствуют."""
        assert len(ALL_METADATA) == 8, "Должно быть 8 metadata объектов"

    @pytest.mark.parametrize(
        "algo_id",
        [
            "x25519",
            "x448",
            "ecdh-p256",
            "ecdh-p384",
            "ecdh-p521",
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
        ],
    )
    def test_metadata_structure(self, algo_id: str) -> None:
        """Тест структуры metadata для каждого алгоритма."""
        _, metadata = KEY_EXCHANGE_ALGORITHMS[algo_id]

        assert metadata.category == AlgorithmCategory.KEY_EXCHANGE
        assert metadata.status == ImplementationStatus.STABLE
        assert metadata.key_size is not None
        assert len(metadata.description_ru) > 0
        assert len(metadata.description_en) > 0

    def test_metadata_classical_vs_pqc(self) -> None:
        """Тест что metadata корректно отличает classical от PQC."""
        # Classical should NOT be post-quantum
        for algo_id in ["x25519", "x448", "ecdh-p256", "ecdh-p384", "ecdh-p521"]:
            _, metadata = KEY_EXCHANGE_ALGORITHMS[algo_id]
            assert not metadata.is_post_quantum, f"{algo_id} should not be post-quantum"

        # PQC should be post-quantum
        for algo_id in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
            _, metadata = KEY_EXCHANGE_ALGORITHMS[algo_id]
            assert metadata.is_post_quantum, f"{algo_id} should be post-quantum"

    def test_metadata_floppy_friendly(self) -> None:
        """Тест что floppy_friendly флаги корректны."""
        # Classical ECDH: EXCELLENT (small keys)
        for algo_id in ["x25519", "x448", "ecdh-p256", "ecdh-p384", "ecdh-p521"]:
            _, metadata = KEY_EXCHANGE_ALGORITHMS[algo_id]
            assert metadata.floppy_friendly == FloppyFriendly.EXCELLENT

        # PQC KEM: POOR (large keys)
        for algo_id in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
            _, metadata = KEY_EXCHANGE_ALGORITHMS[algo_id]
            assert metadata.floppy_friendly == FloppyFriendly.POOR

    def test_metadata_libraries(self) -> None:
        """Тест что library requirements корректны."""
        # Classical ECDH uses cryptography
        for algo_id in ["x25519", "x448", "ecdh-p256", "ecdh-p384", "ecdh-p521"]:
            _, metadata = KEY_EXCHANGE_ALGORITHMS[algo_id]
            assert metadata.library == "cryptography"

        # PQC KEM uses liboqs
        for algo_id in ["ml-kem-512", "ml-kem-768", "ml-kem-1024"]:
            _, metadata = KEY_EXCHANGE_ALGORITHMS[algo_id]
            assert metadata.library == "liboqs-python"


# ==============================================================================
# TEST: EDGE CASES
# ==============================================================================


class TestEdgeCases:
    """Тесты edge cases."""

    def test_x25519_all_zero_shared_secret_prevention(self) -> None:
        """
        Тест что X25519 НЕ производит all-zero shared secret.

        Note: X25519 spec требует reject certain "low-order" points,
        но cryptography.io handle это автоматически.
        """
        kex = X25519KeyExchange()

        # Generate multiple keypairs
        for _ in range(10):
            priv_a, pub_a = kex.generate_keypair()
            priv_b, pub_b = kex.generate_keypair()

            shared = kex.derive_shared_secret(priv_a, pub_b)

            # Shared secret должен НЕ быть all zeros
            assert shared != b"\x00" * 32, "X25519 produced all-zero shared secret"

    def test_cross_instance_compatibility(self) -> None:
        """Тест что разные экземпляры одного класса совместимы."""
        kex1 = X25519KeyExchange()
        kex2 = X25519KeyExchange()

        priv_a, pub_a = kex1.generate_keypair()
        priv_b, pub_b = kex2.generate_keypair()

        # Keys from different instances should work together
        shared_a = kex1.derive_shared_secret(priv_a, pub_b)
        shared_b = kex2.derive_shared_secret(priv_b, pub_a)

        assert shared_a == shared_b

    @pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs-python not installed")
    def test_kem_ciphertext_uniqueness(self) -> None:
        """Тест что KEM ciphertext всегда уникален (даже для одного public key)."""
        kem = MLKEM768()

        _, pub = kem.generate_keypair()

        # Generate 100 ciphertexts with same public key
        ciphertexts = [kem.encapsulate(pub)[0] for _ in range(100)]

        # All should be unique
        assert len(set(ciphertexts)) == 100, "KEM ciphertexts should be unique"

    def test_sequential_keypair_uniqueness(self) -> None:
        """Тест что последовательные keypairs уникальны."""
        kex = X25519KeyExchange()

        keypairs = [kex.generate_keypair() for _ in range(20)]

        # All private keys unique
        private_keys = [kp[0] for kp in keypairs]
        assert len(set(private_keys)) == 20, "Private keys should be unique"

        # All public keys unique
        public_keys = [kp[1] for kp in keypairs]
        assert len(set(public_keys)) == 20, "Public keys should be unique"


# ==============================================================================
# TEST: PERFORMANCE (OPTIONAL BENCHMARKS)
# ==============================================================================


class TestPerformance:
    """Performance benchmarks (optional, может быть медленным)."""

    @pytest.mark.slow
    @pytest.mark.parametrize(
        "kex_class,name,key_size,shared_secret_size", CLASSICAL_ECDH_VARIANTS
    )
    def test_classical_keygen_performance(
        self,
        kex_class: Type[KeyExchangeProtocol],
        name: str,
        key_size: int | None,
        shared_secret_size: int,
        benchmark: Any,
    ) -> None:
        """Benchmark генерации ключей для classical ECDH."""
        kex = kex_class()

        def keygen() -> tuple[bytes, bytes]:
            return kex.generate_keypair()

        result = benchmark(keygen)
        assert len(result) == 2

    @pytest.mark.slow
    @pytest.mark.parametrize(
        "kex_class,name,key_size,shared_secret_size", CLASSICAL_ECDH_VARIANTS
    )
    def test_classical_exchange_performance(
        self,
        kex_class: Type[KeyExchangeProtocol],
        name: str,
        key_size: int | None,
        shared_secret_size: int,
        benchmark: Any,
    ) -> None:
        """Benchmark key exchange для classical ECDH."""
        kex = kex_class()
        priv, _ = kex.generate_keypair()
        _, peer_pub = kex.generate_keypair()

        result = benchmark(kex.derive_shared_secret, priv, peer_pub)
        assert len(result) == shared_secret_size


# ==============================================================================
# PYTEST CONFIGURATION
# ==============================================================================


def pytest_configure(config: Any) -> None:
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
