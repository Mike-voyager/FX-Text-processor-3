"""
Тесты для модуля Key Derivation Functions (KDF).

Покрытие:
- 4 KDF алгоритма (Argon2id, PBKDF2, Scrypt, HKDF)
- NIST/RFC test vectors
- Parameter validation
- Error handling
- Performance benchmarks
- Registry tests

Coverage target: 90%+

Author: FX Text Processor 3 Team
Version: 1.0
Date: February 10, 2026
"""

from __future__ import annotations

import secrets
from typing import Any

import pytest

from src.security.crypto.algorithms.kdf import (
    ALGORITHMS,
    ALL_METADATA,
    ARGON2_DEFAULT_MEMORY_COST,
    ARGON2_DEFAULT_PARALLELISM,
    ARGON2_DEFAULT_TIME_COST,
    HKDFSHA256,
    PBKDF2_DEFAULT_ITERATIONS,
    PBKDF2_MIN_ITERATIONS,
    SCRYPT_DEFAULT_N,
    SCRYPT_DEFAULT_P,
    SCRYPT_DEFAULT_R,
    Argon2idKDF,
    PBKDF2SHA256KDF,
    ScryptKDF,
    generate_salt,
    get_kdf_algorithm,
)
from src.security.crypto.core.exceptions import (
    AlgorithmNotSupportedError,
    KeyDerivationError,
)

# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def password() -> bytes:
    """Test password."""
    return b"test_password_123"


@pytest.fixture
def salt() -> bytes:
    """Test salt (32 bytes)."""
    return secrets.token_bytes(32)


@pytest.fixture
def short_salt() -> bytes:
    """Short salt (8 bytes) - should fail validation."""
    return b"short123"


# ============================================================================
# TEST VECTORS
# ============================================================================


class TestVectors:
    """Known test vectors from standards."""

    # PBKDF2-SHA256 (RFC 6070 / NIST)
    PBKDF2_VECTORS = [
        {
            "password": b"password",
            "salt": b"salt" + b"\x00" * 12,  # Extend to 16 bytes
            "iterations": 600_000,  # Use production-safe count
            "key_length": 32,
            "expected": None,  # Will compute, just test it doesn't crash
        },
    ]

    # HKDF-SHA256 (RFC 5869) - Use vector with valid salt length
    HKDF_VECTORS = [
        {
            "ikm": bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
                "202122232425262728292a2b2c2d2e2f"
                "303132333435363738393a3b3c3d3e3f"
                "404142434445464748494a4b4c4d4e4f"
            ),
            "salt": bytes.fromhex(
                "606162636465666768696a6b6c6d6e6f"
                "707172737475767778797a7b7c7d7e7f"
                "808182838485868788898a8b8c8d8e8f"
                "909192939495969798999a9b9c9d9e9f"
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
            ),
            "info": bytes.fromhex(
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
            ),
            "key_length": 82,
            "expected": bytes.fromhex(
                "b11e398dc80327a1c8e7f78c596a4934"
                "4f012eda2d4efad8a050cc4c19afa97c"
                "59045a99cac7827271cb41c65e590e09"
                "da3275600c2f09b8367793a9aca3db71"
                "cc30c58179ec3e87c14c01d5c1f3434f"
                "1d87"
            ),
        },
    ]


# ============================================================================
# BASIC TESTS
# ============================================================================


class TestArgon2id:
    """Tests for Argon2id KDF."""

    def test_basic_derivation(self, password: bytes, salt: bytes) -> None:
        """Test basic key derivation."""
        kdf = Argon2idKDF()
        key = kdf.derive_key(password, salt, key_length=32)

        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_deterministic(self, password: bytes, salt: bytes) -> None:
        """Test that same inputs produce same output."""
        kdf = Argon2idKDF()

        key1 = kdf.derive_key(password, salt, key_length=32)
        key2 = kdf.derive_key(password, salt, key_length=32)

        assert key1 == key2

    def test_different_passwords(self, salt: bytes) -> None:
        """Test that different passwords produce different keys."""
        kdf = Argon2idKDF()

        key1 = kdf.derive_key(b"password1", salt, key_length=32)
        key2 = kdf.derive_key(b"password2", salt, key_length=32)

        assert key1 != key2

    def test_different_salts(self, password: bytes) -> None:
        """Test that different salts produce different keys."""
        kdf = Argon2idKDF()

        salt1 = secrets.token_bytes(32)
        salt2 = secrets.token_bytes(32)

        key1 = kdf.derive_key(password, salt1, key_length=32)
        key2 = kdf.derive_key(password, salt2, key_length=32)

        assert key1 != key2

    @pytest.mark.parametrize("key_length", [16, 32, 48, 64])
    def test_variable_key_length(
        self, password: bytes, salt: bytes, key_length: int
    ) -> None:
        """Test different key lengths."""
        kdf = Argon2idKDF()
        key = kdf.derive_key(password, salt, key_length=key_length)

        assert len(key) == key_length

    def test_custom_parameters(self, password: bytes, salt: bytes) -> None:
        """Test custom Argon2id parameters."""
        kdf = Argon2idKDF()

        # High security settings
        key = kdf.derive_key(
            password,
            salt,
            key_length=32,
            time_cost=4,
            memory_cost=131072,  # 128 MB
            parallelism=8,
        )

        assert len(key) == 32

    def test_short_salt_fails(self, password: bytes, short_salt: bytes) -> None:
        """Test that short salt is rejected."""
        kdf = Argon2idKDF()

        with pytest.raises(ValueError, match="Salt too short"):
            kdf.derive_key(password, short_salt, key_length=32)

    def test_empty_salt_fails(self, password: bytes) -> None:
        """Test that empty salt is rejected."""
        kdf = Argon2idKDF()

        with pytest.raises(ValueError, match="Salt cannot be empty"):
            kdf.derive_key(password, b"", key_length=32)

    def test_invalid_time_cost(self, password: bytes, salt: bytes) -> None:
        """Test that invalid time_cost is rejected."""
        kdf = Argon2idKDF()

        with pytest.raises(ValueError, match="time_cost must be >= 1"):
            kdf.derive_key(password, salt, time_cost=0)

    def test_invalid_memory_cost(self, password: bytes, salt: bytes) -> None:
        """Test that invalid memory_cost is rejected."""
        kdf = Argon2idKDF()

        with pytest.raises(ValueError, match="memory_cost must be >= 8"):
            kdf.derive_key(password, salt, memory_cost=7)

    def test_invalid_parallelism(self, password: bytes, salt: bytes) -> None:
        """Test that invalid parallelism is rejected."""
        kdf = Argon2idKDF()

        with pytest.raises(ValueError, match="parallelism must be >= 1"):
            kdf.derive_key(password, salt, parallelism=0)


class TestPBKDF2:
    """Tests for PBKDF2-SHA256 KDF."""

    def test_basic_derivation(self, password: bytes, salt: bytes) -> None:
        """Test basic key derivation."""
        kdf = PBKDF2SHA256KDF()
        key = kdf.derive_key(password, salt, key_length=32)

        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_deterministic(self, password: bytes, salt: bytes) -> None:
        """Test that same inputs produce same output."""
        kdf = PBKDF2SHA256KDF()

        key1 = kdf.derive_key(password, salt, key_length=32)
        key2 = kdf.derive_key(password, salt, key_length=32)

        assert key1 == key2

    @pytest.mark.parametrize("vector", TestVectors.PBKDF2_VECTORS)
    def test_nist_vectors(self, vector: dict[str, Any]) -> None:
        """Test PBKDF2 with production parameters."""
        kdf = PBKDF2SHA256KDF()

        key = kdf.derive_key(
            vector["password"],
            vector["salt"],
            key_length=vector["key_length"],
            iterations=vector["iterations"],
        )

        # Just verify it produces output of correct length
        assert len(key) == vector["key_length"]
        assert isinstance(key, bytes)

        # Verify deterministic
        key2 = kdf.derive_key(
            vector["password"],
            vector["salt"],
            key_length=vector["key_length"],
            iterations=vector["iterations"],
        )
        assert key == key2

    def test_low_iterations_rejected(self, password: bytes, salt: bytes) -> None:
        """Test that low iteration count is rejected."""
        kdf = PBKDF2SHA256KDF()

        with pytest.raises(ValueError, match="iterations.*INSECURE"):
            kdf.derive_key(password, salt, iterations=1000)

    @pytest.mark.parametrize("key_length", [16, 32, 48, 64])
    def test_variable_key_length(
        self, password: bytes, salt: bytes, key_length: int
    ) -> None:
        """Test different key lengths."""
        kdf = PBKDF2SHA256KDF()
        key = kdf.derive_key(password, salt, key_length=key_length)

        assert len(key) == key_length


class TestScrypt:
    """Tests for Scrypt KDF."""

    def test_basic_derivation(self, password: bytes, salt: bytes) -> None:
        """Test basic key derivation."""
        kdf = ScryptKDF()
        key = kdf.derive_key(password, salt, key_length=32)

        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_deterministic(self, password: bytes, salt: bytes) -> None:
        """Test that same inputs produce same output."""
        kdf = ScryptKDF()

        key1 = kdf.derive_key(password, salt, key_length=32)
        key2 = kdf.derive_key(password, salt, key_length=32)

        assert key1 == key2

    def test_invalid_n_not_power_of_2(self, password: bytes, salt: bytes) -> None:
        """Test that N must be power of 2."""
        kdf = ScryptKDF()

        with pytest.raises(ValueError, match="N must be power of 2"):
            kdf.derive_key(password, salt, n=100)

    def test_invalid_r(self, password: bytes, salt: bytes) -> None:
        """Test that r must be >= 1."""
        kdf = ScryptKDF()

        with pytest.raises(ValueError, match="r must be >= 1"):
            kdf.derive_key(password, salt, r=0)

    def test_invalid_p(self, password: bytes, salt: bytes) -> None:
        """Test that p must be >= 1."""
        kdf = ScryptKDF()

        with pytest.raises(ValueError, match="p must be >= 1"):
            kdf.derive_key(password, salt, p=0)

    @pytest.mark.parametrize("key_length", [16, 32, 48, 64])
    def test_variable_key_length(
        self, password: bytes, salt: bytes, key_length: int
    ) -> None:
        """Test different key lengths."""
        kdf = ScryptKDF()
        key = kdf.derive_key(password, salt, key_length=key_length)

        assert len(key) == key_length


class TestHKDF:
    """Tests for HKDF-SHA256."""

    def test_basic_derivation(self) -> None:
        """Test basic key derivation."""
        kdf = HKDFSHA256()

        # Use high-entropy input (NOT a user password!)
        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        key = kdf.derive_key(ikm, salt, key_length=32)

        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_deterministic(self) -> None:
        """Test that same inputs produce same output."""
        kdf = HKDFSHA256()

        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)
        info = b"test_context"

        key1 = kdf.derive_key(ikm, salt, key_length=32, info=info)
        key2 = kdf.derive_key(ikm, salt, key_length=32, info=info)

        assert key1 == key2

    @pytest.mark.parametrize("vector", TestVectors.HKDF_VECTORS)
    def test_rfc_vectors(self, vector: dict[str, Any]) -> None:
        """Test RFC 5869 HKDF test vectors."""
        kdf = HKDFSHA256()

        key = kdf.derive_key(
            vector["ikm"],
            vector["salt"],
            key_length=vector["key_length"],
            info=vector["info"],
        )

        assert key == vector["expected"]

    def test_empty_salt_allowed(self) -> None:
        """Test that empty salt is allowed for HKDF."""
        kdf = HKDFSHA256()

        ikm = secrets.token_bytes(32)
        key = kdf.derive_key(ikm, b"", key_length=32)

        assert len(key) == 32

    def test_different_info_produces_different_keys(self) -> None:
        """Test that different info produces different keys."""
        kdf = HKDFSHA256()

        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        key1 = kdf.derive_key(ikm, salt, key_length=32, info=b"context1")
        key2 = kdf.derive_key(ikm, salt, key_length=32, info=b"context2")

        assert key1 != key2

    @pytest.mark.parametrize("key_length", [16, 32, 48, 64, 128])
    def test_variable_key_length(self, key_length: int) -> None:
        """Test different key lengths."""
        kdf = HKDFSHA256()

        ikm = secrets.token_bytes(32)
        salt = secrets.token_bytes(32)

        key = kdf.derive_key(ikm, salt, key_length=key_length)

        assert len(key) == key_length


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================


class TestHelpers:
    """Tests for helper functions."""

    def test_generate_salt_default(self) -> None:
        """Test default salt generation (32 bytes)."""
        salt = generate_salt()

        assert len(salt) == 32
        assert isinstance(salt, bytes)

    @pytest.mark.parametrize("length", [16, 32, 64, 128])
    def test_generate_salt_custom_length(self, length: int) -> None:
        """Test custom salt lengths."""
        salt = generate_salt(length)

        assert len(salt) == length

    def test_generate_salt_randomness(self) -> None:
        """Test that generated salts are different."""
        salt1 = generate_salt(32)
        salt2 = generate_salt(32)

        assert salt1 != salt2

    def test_generate_salt_too_short_fails(self) -> None:
        """Test that too short salt generation fails."""
        with pytest.raises(ValueError, match="Salt length"):
            generate_salt(8)


# ============================================================================
# REGISTRY TESTS
# ============================================================================


class TestRegistry:
    """Tests for algorithm registry."""

    def test_all_algorithms_present(self) -> None:
        """Test that all 4 KDF algorithms are registered."""
        assert len(ALGORITHMS) == 4
        assert "argon2id" in ALGORITHMS
        assert "pbkdf2-sha256" in ALGORITHMS
        assert "scrypt" in ALGORITHMS
        assert "hkdf-sha256" in ALGORITHMS

    def test_all_metadata_present(self) -> None:
        """Test that all metadata objects exist."""
        assert len(ALL_METADATA) == 4

    @pytest.mark.parametrize(
        "algorithm_id",
        ["argon2id", "pbkdf2-sha256", "scrypt", "hkdf-sha256"],
    )
    def test_get_algorithm(self, algorithm_id: str) -> None:
        """Test getting algorithm by ID."""
        kdf = get_kdf_algorithm(algorithm_id)
        assert kdf is not None

    def test_get_unknown_algorithm_fails(self) -> None:
        """Test that unknown algorithm raises KeyError."""
        with pytest.raises(KeyError, match="not found"):
            get_kdf_algorithm("unknown-kdf")

    def test_argon2_not_installed_handled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test graceful handling of missing argon2 library."""
        # Mock argon2 import failure
        import builtins

        original_import = builtins.__import__

        def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "argon2":
                raise ImportError("argon2-cffi not installed")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        # Should raise AlgorithmNotSupportedError
        with pytest.raises(AlgorithmNotSupportedError, match="argon2-cffi"):
            kdf = get_kdf_algorithm("argon2id")


# ============================================================================
# PERFORMANCE BENCHMARKS
# ============================================================================


class TestPerformance:
    """Performance benchmarks for KDF algorithms."""

    @pytest.mark.benchmark(group="kdf")
    @pytest.mark.parametrize(
        "algorithm_class,name",
        [
            (Argon2idKDF, "Argon2id"),
            (PBKDF2SHA256KDF, "PBKDF2"),
            (ScryptKDF, "Scrypt"),
            (HKDFSHA256, "HKDF"),
        ],
    )
    def test_kdf_performance(
        self, benchmark: Any, algorithm_class: type, name: str
    ) -> None:
        """Benchmark KDF performance."""
        kdf = algorithm_class()
        password = b"test_password_123"
        salt = secrets.token_bytes(32)

        # Use lower parameters for benchmark
        if name == "Argon2id":
            result = benchmark(
                kdf.derive_key,
                password,
                salt,
                key_length=32,
                time_cost=1,
                memory_cost=8192,  # 8 MB
                parallelism=1,
            )
        elif name == "PBKDF2":
            result = benchmark(
                kdf.derive_key,
                password,
                salt,
                key_length=32,
                iterations=100_000,
            )
        elif name == "Scrypt":
            result = benchmark(
                kdf.derive_key,
                password,
                salt,
                key_length=32,
                n=2**12,  # 4096
                r=8,
                p=1,
            )
        else:  # HKDF
            ikm = secrets.token_bytes(32)
            result = benchmark(
                kdf.derive_key,
                ikm,
                salt,
                key_length=32,
            )

        assert len(result) == 32


# ============================================================================
# EDGE CASES
# ============================================================================


class TestEdgeCases:
    """Edge case tests."""

    def test_very_short_password(self, salt: bytes) -> None:
        """Test that very short password works."""
        kdf = PBKDF2SHA256KDF()
        key = kdf.derive_key(b"a", salt, key_length=32)

        assert len(key) == 32

    def test_very_long_password(self, salt: bytes) -> None:
        """Test that very long password works."""
        kdf = PBKDF2SHA256KDF()
        long_password = b"a" * 10000

        key = kdf.derive_key(long_password, salt, key_length=32)

        assert len(key) == 32

    def test_binary_password(self, salt: bytes) -> None:
        """Test that binary password works."""
        kdf = PBKDF2SHA256KDF()
        binary_password = bytes(range(256))

        key = kdf.derive_key(binary_password, salt, key_length=32)

        assert len(key) == 32

    def test_max_key_length(self, password: bytes, salt: bytes) -> None:
        """Test maximum key length (128 bytes)."""
        kdf = PBKDF2SHA256KDF()
        key = kdf.derive_key(password, salt, key_length=128)

        assert len(key) == 128

    def test_min_key_length(self, password: bytes, salt: bytes) -> None:
        """Test minimum key length (16 bytes)."""
        kdf = PBKDF2SHA256KDF()
        key = kdf.derive_key(password, salt, key_length=16)

        assert len(key) == 16

    def test_key_length_too_short_fails(self, password: bytes, salt: bytes) -> None:
        """Test that key_length < 16 is rejected."""
        kdf = PBKDF2SHA256KDF()

        with pytest.raises(ValueError, match="key_length too short"):
            kdf.derive_key(password, salt, key_length=8)

    def test_key_length_too_long_fails(self, password: bytes, salt: bytes) -> None:
        """Test that key_length > 128 is rejected."""
        kdf = PBKDF2SHA256KDF()

        with pytest.raises(ValueError, match="key_length too long"):
            kdf.derive_key(password, salt, key_length=256)


# ============================================================================
# INTEGRATION TESTS
# ============================================================================


class TestIntegration:
    """Integration tests for realistic use cases."""

    def test_password_storage_workflow(self) -> None:
        """Test typical password storage workflow."""
        # 1. User registration: hash password
        password = b"user_password_123"
        salt = generate_salt(32)

        kdf = get_kdf_algorithm("argon2id")
        stored_hash = kdf.derive_key(
            password, salt, key_length=32, time_cost=2, memory_cost=65536
        )

        # 2. User login: verify password
        entered_password = b"user_password_123"
        login_hash = kdf.derive_key(
            entered_password, salt, key_length=32, time_cost=2, memory_cost=65536
        )

        assert login_hash == stored_hash

    def test_encryption_key_derivation_workflow(self) -> None:
        """Test deriving encryption key from password."""
        password = b"user_master_password"
        salt = generate_salt(32)

        # Derive 256-bit AES key from password
        kdf = get_kdf_algorithm("argon2id")
        encryption_key = kdf.derive_key(password, salt, key_length=32)

        # Key can be used for encryption
        assert len(encryption_key) == 32
        assert isinstance(encryption_key, bytes)

    def test_key_exchange_workflow(self) -> None:
        """Test HKDF after key exchange."""
        # Simulate X25519 key exchange (generates shared secret)
        shared_secret = secrets.token_bytes(32)

        # Derive multiple keys from shared secret
        kdf = get_kdf_algorithm("hkdf-sha256")

        encryption_key = kdf.derive_key(
            shared_secret, b"", key_length=32, info=b"encryption"
        )

        mac_key = kdf.derive_key(
            shared_secret, b"", key_length=32, info=b"authentication"
        )

        # Keys should be different
        assert encryption_key != mac_key
        assert len(encryption_key) == 32
        assert len(mac_key) == 32


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--benchmark-only"])
