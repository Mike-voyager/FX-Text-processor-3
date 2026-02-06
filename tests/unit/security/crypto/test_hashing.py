# -*- coding: utf-8 -*-
"""
Тесты для hashing.py - криптографическое хеширование данных.
"""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from typing import Final

import pytest

from src.security.crypto.hashing import (
    BLAKE3_AVAILABLE,
    compute_hash,
    compute_hash_blake2b,
    compute_hash_sha256,
    compute_hash_sha3_256,
    hash_file,
    verify_file,
)

# Test vectors
TEST_DATA: Final = b"hello world"
SHA256_EXPECTED: Final = (
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
)
SHA3_256_EXPECTED: Final = (
    "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"
)


class TestComputeHashSHA256:
    """Тесты для compute_hash_sha256."""

    def test_sha256_basic(self) -> None:
        """Базовое хеширование SHA-256."""
        result = compute_hash_sha256(TEST_DATA)
        assert result == SHA256_EXPECTED
        assert len(result) == 64  # 256 bits = 64 hex chars

    def test_sha256_empty_bytes(self) -> None:
        """SHA-256 пустых данных."""
        result = compute_hash_sha256(b"")
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    @pytest.mark.parametrize(
        "data,expected_len",
        [
            (b"a", 64),
            (b"a" * 100, 64),
            (b"a" * 10000, 64),
        ],
    )
    def test_sha256_output_length(self, data: bytes, expected_len: int) -> None:
        """SHA-256 всегда возвращает 64 символа."""
        result = compute_hash_sha256(data)
        assert len(result) == expected_len


class TestComputeHashSHA3_256:
    """Тесты для compute_hash_sha3_256."""

    def test_sha3_256_basic(self) -> None:
        """Базовое хеширование SHA3-256."""
        result = compute_hash_sha3_256(TEST_DATA)
        assert result == SHA3_256_EXPECTED
        assert len(result) == 64

    def test_sha3_256_empty_bytes(self) -> None:
        """SHA3-256 пустых данных."""
        result = compute_hash_sha3_256(b"")
        expected = hashlib.sha3_256(b"").hexdigest()
        assert result == expected

    def test_sha3_256_deterministic(self) -> None:
        """SHA3-256 детерминирован."""
        data = b"test data 12345"
        result1 = compute_hash_sha3_256(data)
        result2 = compute_hash_sha3_256(data)
        assert result1 == result2


class TestComputeHashBLAKE2b:
    """Тесты для compute_hash_blake2b."""

    def test_blake2b_default_size(self) -> None:
        """BLAKE2b с размером по умолчанию (64 байта = 512 бит)."""
        result = compute_hash_blake2b(TEST_DATA)
        assert len(result) == 128  # 64 bytes * 2 hex chars

    @pytest.mark.parametrize(
        "digest_size,expected_hex_len",
        [
            (1, 2),
            (16, 32),
            (32, 64),
            (64, 128),
        ],
    )
    def test_blake2b_custom_digest_size(
        self, digest_size: int, expected_hex_len: int
    ) -> None:
        """BLAKE2b с разными размерами дайджеста."""
        result = compute_hash_blake2b(TEST_DATA, digest_size=digest_size)
        assert len(result) == expected_hex_len

    @pytest.mark.parametrize("invalid_size", [0, -1, 65, 100])
    def test_blake2b_invalid_digest_size_raises(self, invalid_size: int) -> None:
        """BLAKE2b выбрасывает ValueError на неверный digest_size."""
        with pytest.raises(ValueError, match="BLAKE2b digest_size must be 1-64 bytes"):
            compute_hash_blake2b(TEST_DATA, digest_size=invalid_size)

    def test_blake2b_deterministic(self) -> None:
        """BLAKE2b детерминирован."""
        result1 = compute_hash_blake2b(TEST_DATA, digest_size=32)
        result2 = compute_hash_blake2b(TEST_DATA, digest_size=32)
        assert result1 == result2


class TestComputeHash:
    """Тесты для универсальной функции compute_hash."""

    @pytest.mark.parametrize(
        "algorithm,expected",
        [
            ("sha256", SHA256_EXPECTED),
            ("sha3-256", SHA3_256_EXPECTED),
        ],
    )
    def test_compute_hash_algorithms(self, algorithm: str, expected: str) -> None:
        """compute_hash с разными алгоритмами."""
        result = compute_hash(TEST_DATA, algorithm=algorithm)
        assert result == expected

    def test_compute_hash_blake2b(self) -> None:
        """compute_hash с BLAKE2b."""
        result = compute_hash(TEST_DATA, algorithm="blake2b")
        assert len(result) == 128  # default 64 bytes

    def test_compute_hash_unsupported_algorithm_raises(self) -> None:
        """compute_hash выбрасывает ValueError на неподдерживаемый алгоритм."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_hash(TEST_DATA, algorithm="md5")

    def test_compute_hash_blake3_unavailable_raises(self) -> None:
        """compute_hash выбрасывает ValueError если BLAKE3 недоступен."""
        if not BLAKE3_AVAILABLE:
            with pytest.raises(ValueError, match="BLAKE3 not available"):
                compute_hash(TEST_DATA, algorithm="blake3")
        else:
            # Если доступен - должен работать
            result = compute_hash(TEST_DATA, algorithm="blake3")
            assert len(result) == 64  # BLAKE3 default 256 bits


class TestHashFile:
    """Тесты для hash_file - хеширование файлов."""

    def test_hash_file_sha256(self, tmp_path: Path) -> None:
        """Хеширование файла SHA-256."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(TEST_DATA)

        result = hash_file(str(test_file), algorithm="sha256")
        assert result == SHA256_EXPECTED

    def test_hash_file_sha3_256(self, tmp_path: Path) -> None:
        """Хеширование файла SHA3-256."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(TEST_DATA)

        result = hash_file(str(test_file), algorithm="sha3-256")
        assert result == SHA3_256_EXPECTED

    def test_hash_file_blake2b(self, tmp_path: Path) -> None:
        """Хеширование файла BLAKE2b."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(TEST_DATA)

        result = hash_file(str(test_file), algorithm="blake2b")
        assert len(result) == 128

    def test_hash_file_large_file_streaming(self, tmp_path: Path) -> None:
        """Хеширование большого файла (streaming)."""
        test_file = tmp_path / "large.bin"
        # Создаём файл 5MB
        large_data = b"A" * (5 * 1024 * 1024)
        test_file.write_bytes(large_data)

        result = hash_file(str(test_file), algorithm="sha256", chunk_size=1024 * 1024)
        expected = hashlib.sha256(large_data).hexdigest()
        assert result == expected

    def test_hash_file_empty_file(self, tmp_path: Path) -> None:
        """Хеширование пустого файла."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        result = hash_file(str(test_file), algorithm="sha256")
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_hash_file_unsupported_algorithm_raises(self, tmp_path: Path) -> None:
        """hash_file выбрасывает ValueError на неподдерживаемый алгоритм."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(TEST_DATA)

        with pytest.raises(ValueError, match="Unsupported algorithm"):
            hash_file(str(test_file), algorithm="md5")

    def test_hash_file_nonexistent_raises(self) -> None:
        """hash_file выбрасывает FileNotFoundError на несуществующий файл."""
        with pytest.raises(FileNotFoundError):
            hash_file("/nonexistent/file.txt", algorithm="sha256")


class TestVerifyFile:
    """Тесты для verify_file - проверка целостности файлов."""

    def test_verify_file_correct_hash(self, tmp_path: Path) -> None:
        """verify_file возвращает True для правильного хеша."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(TEST_DATA)

        assert verify_file(str(test_file), SHA256_EXPECTED, algorithm="sha256")

    def test_verify_file_wrong_hash(self, tmp_path: Path) -> None:
        """verify_file возвращает False для неправильного хеша."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(TEST_DATA)

        wrong_hash = "0" * 64
        assert not verify_file(str(test_file), wrong_hash, algorithm="sha256")

    def test_verify_file_case_insensitive(self, tmp_path: Path) -> None:
        """verify_file нечувствительна к регистру."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(TEST_DATA)

        upper_hash = SHA256_EXPECTED.upper()
        assert verify_file(str(test_file), upper_hash, algorithm="sha256")

    def test_verify_file_nonexistent_returns_false(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """verify_file возвращает False для несуществующего файла."""
        result = verify_file("/nonexistent/file.txt", "abc123", algorithm="sha256")
        assert result is False
        assert any(
            "File verification failed" in record.message for record in caplog.records
        )

    @pytest.mark.parametrize("algorithm", ["sha256", "sha3-256", "blake2b"])
    def test_verify_file_multiple_algorithms(
        self, tmp_path: Path, algorithm: str
    ) -> None:
        """verify_file работает с разными алгоритмами."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(TEST_DATA)

        # Вычисляем правильный хеш
        correct_hash = hash_file(str(test_file), algorithm=algorithm)
        assert verify_file(str(test_file), correct_hash, algorithm=algorithm)


class TestBLAKE3Integration:
    """Тесты интеграции с BLAKE3 (если доступен)."""

    @pytest.mark.skipif(not BLAKE3_AVAILABLE, reason="BLAKE3 not installed")
    def test_blake3_compute_hash(self) -> None:
        """BLAKE3 через compute_hash."""
        result = compute_hash(TEST_DATA, algorithm="blake3")
        assert len(result) == 64  # 256 bits

    @pytest.mark.skipif(not BLAKE3_AVAILABLE, reason="BLAKE3 not installed")
    def test_blake3_hash_file(self, tmp_path: Path) -> None:
        """BLAKE3 через hash_file."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(TEST_DATA)

        result = hash_file(str(test_file), algorithm="blake3")
        assert len(result) == 64


class TestEdgeCases:
    """Тесты граничных случаев."""

    @pytest.mark.parametrize("size", [0, 1, 255, 256, 1024, 1024 * 1024])
    def test_various_data_sizes(self, size: int) -> None:
        """Хеширование данных разных размеров."""
        data = b"X" * size
        result = compute_hash_sha256(data)
        assert len(result) == 64
        # Проверка детерминированности
        assert result == hashlib.sha256(data).hexdigest()

    def test_binary_data_with_null_bytes(self) -> None:
        """Хеширование бинарных данных с null-байтами."""
        data = b"\x00\x01\x02\xff\xfe\xfd"
        result = compute_hash_sha256(data)
        expected = hashlib.sha256(data).hexdigest()
        assert result == expected

    def test_unicode_data_encoding(self) -> None:
        """Хеширование Unicode требует явного кодирования."""
        text = "привет мир"
        # Хеш должен быть вычислен от UTF-8 байтов
        result = compute_hash_sha256(text.encode("utf-8"))
        expected = hashlib.sha256(text.encode("utf-8")).hexdigest()
        assert result == expected
