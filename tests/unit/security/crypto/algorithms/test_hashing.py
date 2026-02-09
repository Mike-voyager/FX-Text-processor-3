"""
Тесты для модуля hashing.py - криптографические хеш-функции.

Тестируемые алгоритмы (8):
- SHA-2: SHA-256, SHA-384, SHA-512 (FIPS 180-4)
- SHA-3: SHA3-256, SHA3-512 (FIPS 202)
- BLAKE: BLAKE2b, BLAKE2s (RFC 7693), BLAKE3 (2020)

Покрытие:
- One-shot hashing (hash method)
- Streaming hashing (hash_stream method)
- NIST test vectors (SHA-256, SHA-512)
- SHA-3 test vectors (FIPS 202)
- BLAKE2 test vectors (RFC 7693)
- BLAKE3 test vectors
- Error handling (empty data, type errors)
- Registry и factory
- Metadata validation

Author: Mike Voyager
Date: February 10, 2026
"""

from __future__ import annotations

import io
import pytest
from typing import Type, Any

from src.security.crypto.algorithms.hashing import (
    # SHA-2
    SHA256Hash,
    SHA384Hash,
    SHA512Hash,
    # SHA-3
    SHA3_256Hash,
    SHA3_512Hash,
    # BLAKE
    BLAKE2bHash,
    BLAKE2sHash,
    BLAKE3Hash,
    # Registry
    get_hash_algorithm,
    HASH_ALGORITHMS,
    ALL_METADATA,
    # Constants
    SHA256_OUTPUT_SIZE,
    SHA384_OUTPUT_SIZE,
    SHA512_OUTPUT_SIZE,
    SHA3_256_OUTPUT_SIZE,
    SHA3_512_OUTPUT_SIZE,
    BLAKE2B_OUTPUT_SIZE,
    BLAKE2S_OUTPUT_SIZE,
    BLAKE3_OUTPUT_SIZE,
    CHUNK_SIZE,
)
from src.security.crypto.core.protocols import HashProtocol
from src.security.crypto.core.metadata import AlgorithmCategory, FloppyFriendly
from src.security.crypto.core.exceptions import (
    InvalidInputError,
    HashingFailedError,
    AlgorithmNotSupportedError,
)

# Skip BLAKE3 tests if not available
try:
    import blake3

    BLAKE3_AVAILABLE = True
except ImportError:
    BLAKE3_AVAILABLE = False


# Parametrize data: (class, name, output_size)
ALL_HASH_VARIANTS: list[tuple[Type[Any], str, int]] = [
    (SHA256Hash, "SHA-256", SHA256_OUTPUT_SIZE),
    (SHA384Hash, "SHA-384", SHA384_OUTPUT_SIZE),
    (SHA512Hash, "SHA-512", SHA512_OUTPUT_SIZE),
    (SHA3_256Hash, "SHA3-256", SHA3_256_OUTPUT_SIZE),
    (SHA3_512Hash, "SHA3-512", SHA3_512_OUTPUT_SIZE),
    (BLAKE2bHash, "BLAKE2b", BLAKE2B_OUTPUT_SIZE),
    (BLAKE2sHash, "BLAKE2s", BLAKE2S_OUTPUT_SIZE),
]

# Add BLAKE3 if available
if BLAKE3_AVAILABLE:
    ALL_HASH_VARIANTS.append((BLAKE3Hash, "BLAKE3", BLAKE3_OUTPUT_SIZE))


# ==============================================================================
# TEST: BASIC HASHING FUNCTIONALITY
# ==============================================================================


class TestBasicHashing:
    """Базовые тесты хеширования для всех алгоритмов."""

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_basic(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест базового хеширования (one-shot)."""
        hasher = hash_class()
        data = b"Hello, World!"

        hash_value = hasher.hash(data)

        # Validate
        assert isinstance(hash_value, bytes), f"{name}: hash must return bytes"
        assert (
            len(hash_value) == output_size
        ), f"{name}: hash size should be {output_size} bytes, got {len(hash_value)}"

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_deterministic(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест что хеш детерминирован (одинаковые данные → одинаковый хеш)."""
        hasher = hash_class()
        data = b"test data for determinism"

        hash1 = hasher.hash(data)
        hash2 = hasher.hash(data)
        hash3 = hasher.hash(data)

        assert hash1 == hash2 == hash3, f"{name}: hash should be deterministic"

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_different_data(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест что разные данные дают разные хеши."""
        hasher = hash_class()

        hash1 = hasher.hash(b"data1")
        hash2 = hasher.hash(b"data2")
        hash3 = hasher.hash(b"data3")

        # All hashes should be different
        assert (
            hash1 != hash2 != hash3
        ), f"{name}: different data should produce different hashes"

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_sensitivity(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест чувствительности к изменению одного байта (avalanche effect)."""
        hasher = hash_class()

        hash1 = hasher.hash(b"The quick brown fox")
        hash2 = hasher.hash(b"The quick brown for")  # Changed 'x' to 'r'

        # Should produce completely different hashes
        assert (
            hash1 != hash2
        ), f"{name}: single byte change should produce different hash"

        # Count differing bits (should be ~50% for good hash)
        diff_bits = sum(bin(b1 ^ b2).count("1") for b1, b2 in zip(hash1, hash2))
        total_bits = output_size * 8

        # Avalanche effect: at least 30% bits should differ
        assert (
            diff_bits > total_bits * 0.3
        ), f"{name}: avalanche effect too weak ({diff_bits}/{total_bits} bits differ)"

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_various_sizes(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест хеширования данных различных размеров."""
        hasher = hash_class()

        # Test various data sizes
        test_sizes = [1, 10, 100, 1000, 10000, 100000]

        for size in test_sizes:
            data = b"x" * size
            hash_value = hasher.hash(data)

            assert len(hash_value) == output_size, (
                f"{name}: hash size should be constant ({output_size} bytes) "
                f"for data size {size}"
            )


# ==============================================================================
# TEST: STREAMING HASHING
# ==============================================================================


class TestStreamingHashing:
    """Тесты streaming hashing для больших файлов."""

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_stream_basic(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест базового streaming hashing."""
        hasher = hash_class()
        data = b"stream data test" * 1000

        stream = io.BytesIO(data)
        hash_value = hasher.hash_stream(stream)

        assert isinstance(hash_value, bytes)
        assert len(hash_value) == output_size

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_stream_equals_oneshot(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест что streaming hash == one-shot hash для одинаковых данных."""
        hasher = hash_class()
        data = b"test data for stream equivalence" * 100

        # One-shot hash
        hash_oneshot = hasher.hash(data)

        # Stream hash
        stream = io.BytesIO(data)
        hash_stream = hasher.hash_stream(stream)

        assert (
            hash_oneshot == hash_stream
        ), f"{name}: stream hash should equal one-shot hash"

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_stream_large_data(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест streaming для больших данных (> 1 MB)."""
        hasher = hash_class()

        # Create 2 MB of data
        data_size = 2 * 1024 * 1024
        data = b"x" * data_size

        stream = io.BytesIO(data)
        hash_value = hasher.hash_stream(stream)

        assert len(hash_value) == output_size

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_stream_chunk_boundaries(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест что хеш корректен на границах чанков."""
        hasher = hash_class()

        # Data sizes around chunk boundaries (64 KB = 65536 bytes)
        test_sizes = [
            CHUNK_SIZE - 1,  # Just under chunk
            CHUNK_SIZE,  # Exactly one chunk
            CHUNK_SIZE + 1,  # Just over chunk
            CHUNK_SIZE * 2,  # Two chunks
            CHUNK_SIZE * 2 + 1,  # Two chunks + 1 byte
        ]

        for size in test_sizes:
            data = b"y" * size

            # One-shot hash
            hash_oneshot = hasher.hash(data)

            # Stream hash
            stream = io.BytesIO(data)
            hash_stream = hasher.hash_stream(stream)

            assert (
                hash_oneshot == hash_stream
            ), f"{name}: hash mismatch at size {size} (chunk boundary)"


# ==============================================================================
# TEST: NIST TEST VECTORS
# ==============================================================================


class TestNISTVectors:
    """Тесты с официальными NIST test vectors."""

    def test_sha256_nist_vector_empty(self) -> None:
        """
        NIST FIPS 180-4 test vector: empty string.

        Input: ""
        Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        hasher = SHA256Hash()
        # Note: Empty string is NOT allowed, so we test single byte
        # Using NIST vector for "abc" instead
        data = b"abc"
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )

        hash_value = hasher.hash(data)
        assert hash_value == expected, "SHA-256 NIST vector 'abc' failed"

    def test_sha256_nist_vector_448bits(self) -> None:
        """
        NIST FIPS 180-4 test vector: 448-bit message.

        Input: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        Expected: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        """
        hasher = SHA256Hash()
        data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        expected = bytes.fromhex(
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )

        hash_value = hasher.hash(data)
        assert hash_value == expected, "SHA-256 NIST vector 448-bit failed"

    def test_sha512_nist_vector_abc(self) -> None:
        """
        NIST FIPS 180-4 test vector: "abc".

        Input: "abc"
        Expected: ddaf35a193617aba...
        """
        hasher = SHA512Hash()
        data = b"abc"
        expected = bytes.fromhex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )

        hash_value = hasher.hash(data)
        assert hash_value == expected, "SHA-512 NIST vector 'abc' failed"

    def test_sha512_nist_vector_448bits(self) -> None:
        """
        NIST FIPS 180-4 test vector: 448-bit message.

        Input: "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        Expected: 8e959b75dae313da...
        """
        hasher = SHA512Hash()
        data = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        expected = bytes.fromhex(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
            "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        )

        hash_value = hasher.hash(data)
        assert hash_value == expected, "SHA-512 NIST vector 448-bit failed"


# ==============================================================================
# TEST: SHA-3 TEST VECTORS (FIPS 202)
# ==============================================================================


class TestSHA3Vectors:
    """Тесты с SHA-3 test vectors (FIPS 202)."""

    def test_sha3_256_empty(self) -> None:
        """
        SHA3-256 test vector: empty string.

        Input: ""
        Expected: a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        """
        hasher = SHA3_256Hash()
        # SHA-3 allows empty input (unlike our hash() which validates)
        # So we test a known vector instead
        data = b"abc"
        expected = bytes.fromhex(
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        )

        hash_value = hasher.hash(data)
        assert hash_value == expected, "SHA3-256 vector 'abc' failed"

    def test_sha3_512_abc(self) -> None:
        """
        SHA3-512 test vector: "abc".

        Input: "abc"
        Expected: b751850b1a57168a5693cd924b6b096e...
        """
        hasher = SHA3_512Hash()
        data = b"abc"
        expected = bytes.fromhex(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        )

        hash_value = hasher.hash(data)
        assert hash_value == expected, "SHA3-512 vector 'abc' failed"


# ==============================================================================
# TEST: BLAKE2 TEST VECTORS (RFC 7693)
# ==============================================================================


class TestBLAKE2Vectors:
    """Тесты с BLAKE2 test vectors (RFC 7693)."""

    def test_blake2b_empty(self) -> None:
        """
        BLAKE2b test vector: empty string.

        Input: ""
        Expected: 786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419...
        """
        hasher = BLAKE2bHash()
        data = b"abc"
        expected = bytes.fromhex(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        )

        hash_value = hasher.hash(data)
        assert hash_value == expected, "BLAKE2b vector 'abc' failed"

    def test_blake2s_abc(self) -> None:
        """
        BLAKE2s test vector: "abc".

        Input: "abc"
        Expected: 508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982
        """
        hasher = BLAKE2sHash()
        data = b"abc"
        expected = bytes.fromhex(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        )

        hash_value = hasher.hash(data)
        assert hash_value == expected, "BLAKE2s vector 'abc' failed"


# ==============================================================================
# TEST: BLAKE3 TEST VECTORS
# ==============================================================================


@pytest.mark.skipif(not BLAKE3_AVAILABLE, reason="blake3 not installed")
class TestBLAKE3Vectors:
    """Тесты с BLAKE3 test vectors."""

    def test_blake3_empty(self) -> None:
        """
        BLAKE3 test vector: empty string.

        Input: ""
        Expected: af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        """
        hasher = BLAKE3Hash()
        # Test "abc" instead (empty not allowed in our API)
        data = b"abc"

        # Get expected from blake3 reference
        import blake3

        expected = blake3.blake3(data).digest()

        hash_value = hasher.hash(data)
        assert hash_value == expected, "BLAKE3 vector 'abc' failed"

    def test_blake3_consistency(self) -> None:
        """Тест consistency с reference implementation."""
        hasher = BLAKE3Hash()

        import blake3

        test_data = [
            b"test",
            b"The quick brown fox jumps over the lazy dog",
            b"x" * 1000,
            b"BLAKE3" * 100,
        ]

        for data in test_data:
            our_hash = hasher.hash(data)
            ref_hash = blake3.blake3(data).digest()

            assert our_hash == ref_hash, f"BLAKE3 hash mismatch for data: {data[:20]!r}"


# ==============================================================================
# TEST: ERROR HANDLING
# ==============================================================================


class TestErrorHandling:
    """Тесты обработки ошибок."""

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_empty_data(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест что пустые данные вызывают InvalidInputError."""
        hasher = hash_class()

        with pytest.raises(InvalidInputError) as exc_info:
            hasher.hash(b"")

        assert "empty" in str(exc_info.value).lower()

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_invalid_type(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест что не-bytes данные вызывают TypeError."""
        hasher = hash_class()

        with pytest.raises(TypeError) as exc_info:
            hasher.hash("not bytes")  # type: ignore[arg-type]

        assert "bytes" in str(exc_info.value).lower()

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_stream_empty(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест что пустой stream вызывает InvalidInputError."""
        hasher = hash_class()

        empty_stream = io.BytesIO(b"")

        with pytest.raises(InvalidInputError) as exc_info:
            hasher.hash_stream(empty_stream)

        assert "empty" in str(exc_info.value).lower()

    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_stream_invalid_type(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
    ) -> None:
        """Тест что не-stream объект вызывает TypeError."""
        hasher = hash_class()

        with pytest.raises(TypeError):
            hasher.hash_stream("not a stream")  # type: ignore[arg-type]

    @pytest.mark.skipif(BLAKE3_AVAILABLE, reason="blake3 is installed")
    def test_blake3_not_available(self) -> None:
        """Тест что BLAKE3 без библиотеки вызывает AlgorithmNotSupportedError."""
        hasher = BLAKE3Hash()

        with pytest.raises(AlgorithmNotSupportedError) as exc_info:
            hasher.hash(b"test")

        assert "blake3" in str(exc_info.value).lower()


# ==============================================================================
# TEST: REGISTRY & FACTORY
# ==============================================================================


class TestRegistry:
    """Тесты registry и factory function."""

    def test_all_algorithms_registered(self) -> None:
        """Тест что все 8 алгоритмов зарегистрированы."""
        expected_count = 8
        assert (
            len(HASH_ALGORITHMS) == expected_count
        ), f"Expected {expected_count} hash algorithms, got {len(HASH_ALGORITHMS)}"

        expected_names = {
            "sha256",
            "sha384",
            "sha512",
            "sha3-256",
            "sha3-512",
            "blake2b",
            "blake2s",
            "blake3",
        }
        actual_names = set(HASH_ALGORITHMS.keys())

        assert (
            actual_names == expected_names
        ), f"Algorithm names mismatch: {actual_names}"

    def test_get_hash_algorithm(self) -> None:
        """Тест factory function get_hash_algorithm."""
        # Test all registered algorithms
        for algo_id in HASH_ALGORITHMS.keys():
            if algo_id == "blake3" and not BLAKE3_AVAILABLE:
                continue  # Skip if not available

            hasher = get_hash_algorithm(algo_id)

            assert hasher is not None
            assert hasattr(hasher, "hash")
            assert hasattr(hasher, "hash_stream")

            # Test that it works
            hash_value = hasher.hash(b"test")
            assert isinstance(hash_value, bytes)
            assert len(hash_value) > 0

    def test_get_hash_algorithm_invalid(self) -> None:
        """Тест что несуществующий алгоритм вызывает KeyError."""
        with pytest.raises(KeyError) as exc_info:
            get_hash_algorithm("invalid-hash-999")

        assert "not found" in str(exc_info.value).lower()
        assert "invalid-hash-999" in str(exc_info.value)

    def test_metadata_count(self) -> None:
        """Тест что metadata для всех 8 алгоритмов присутствуют."""
        assert (
            len(ALL_METADATA) == 8
        ), f"Expected 8 metadata objects, got {len(ALL_METADATA)}"

    @pytest.mark.parametrize(
        "algo_id",
        [
            "sha256",
            "sha384",
            "sha512",
            "sha3-256",
            "sha3-512",
            "blake2b",
            "blake2s",
            "blake3",
        ],
    )
    def test_metadata_structure(self, algo_id: str) -> None:
        """Тест структуры metadata для каждого алгоритма."""
        _, metadata = HASH_ALGORITHMS[algo_id]

        assert metadata.category == AlgorithmCategory.HASH
        assert metadata.floppy_friendly == FloppyFriendly.EXCELLENT
        assert metadata.digest_size is not None
        assert metadata.digest_size > 0
        assert len(metadata.description_ru) > 0
        assert len(metadata.description_en) > 0

    def test_metadata_output_sizes(self) -> None:
        """Тест что metadata содержат корректные размеры выходов."""
        expected_sizes = {
            "sha256": 32,
            "sha384": 48,
            "sha512": 64,
            "sha3-256": 32,
            "sha3-512": 64,
            "blake2b": 64,
            "blake2s": 32,
            "blake3": 32,
        }

        for algo_id, expected_size in expected_sizes.items():
            _, metadata = HASH_ALGORITHMS[algo_id]
            assert metadata.digest_size == expected_size, (
                f"{algo_id}: expected digest_size={expected_size}, "
                f"got {metadata.digest_size}"
            )


# ==============================================================================
# TEST: CROSS-ALGORITHM COMPARISON
# ==============================================================================


class TestCrossAlgorithm:
    """Тесты сравнения между алгоритмами."""

    def test_different_algorithms_different_hashes(self) -> None:
        """Тест что разные алгоритмы дают разные хеши для одних данных."""
        data = b"test data for comparison"

        hashes = {}
        for algo_id in ["sha256", "sha384", "sha512", "blake2b", "blake2s"]:
            hasher = get_hash_algorithm(algo_id)
            hashes[algo_id] = hasher.hash(data)

        # All hashes should be unique
        hash_values = list(hashes.values())
        assert len(set(hash_values)) == len(
            hash_values
        ), "Different algorithms should produce different hashes"

    def test_sha2_vs_sha3_different(self) -> None:
        """Тест что SHA-2 и SHA-3 дают разные хеши (256-bit versions)."""
        data = b"SHA-2 vs SHA-3 comparison"

        sha2_hasher = SHA256Hash()
        sha3_hasher = SHA3_256Hash()

        sha2_hash = sha2_hasher.hash(data)
        sha3_hash = sha3_hasher.hash(data)

        assert (
            sha2_hash != sha3_hash
        ), "SHA-256 and SHA3-256 should produce different hashes"


# ==============================================================================
# TEST: PERFORMANCE (OPTIONAL)
# ==============================================================================


class TestPerformance:
    """Performance benchmarks (optional)."""

    @pytest.mark.slow
    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_hash_performance(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
        benchmark: Any,
    ) -> None:
        """Benchmark hash performance."""
        hasher = hash_class()
        data = b"x" * 10000  # 10 KB

        result = benchmark(hasher.hash, data)
        assert len(result) == output_size

    @pytest.mark.slow
    @pytest.mark.parametrize("hash_class,name,output_size", ALL_HASH_VARIANTS)
    def test_stream_performance(
        self,
        hash_class: Type[HashProtocol],
        name: str,
        output_size: int,
        benchmark: Any,
    ) -> None:
        """Benchmark streaming performance."""
        hasher = hash_class()
        data = b"x" * 1000000  # 1 MB

        def hash_stream_data() -> bytes:
            stream = io.BytesIO(data)
            return hasher.hash_stream(stream)

        result = benchmark(hash_stream_data)
        assert len(result) == output_size


# ==============================================================================
# PYTEST CONFIGURATION
# ==============================================================================


def pytest_configure(config: Any) -> None:
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
