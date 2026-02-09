"""Tests for BLAKE3 hashing module."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.security.crypto.blake3_hash import (
    BLAKE3_AVAILABLE,
    blake3_derive_key,
    blake3_hash_file,
    compute_hash_blake3,
    hmac_blake3,
)

# Skip all tests if blake3 not installed
pytestmark = pytest.mark.skipif(not BLAKE3_AVAILABLE, reason="blake3 not installed")


class TestBlake3Hashing:
    """BLAKE3 hash computation tests."""

    def test_compute_hash_default_length(self) -> None:
        """Test default 32-byte hash."""
        hash_hex = compute_hash_blake3(b"hello")
        assert len(hash_hex) == 64
        assert isinstance(hash_hex, str)
        assert (
            hash_hex
            == "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f"
        )

    def test_compute_hash_custom_length(self) -> None:
        """Test custom output length."""
        hash_16 = compute_hash_blake3(b"hello", length=16)
        assert len(hash_16) == 32

        hash_64 = compute_hash_blake3(b"hello", length=64)
        assert len(hash_64) == 128

    def test_compute_hash_empty_input(self) -> None:
        """Test hashing empty bytes."""
        hash_empty = compute_hash_blake3(b"")
        assert len(hash_empty) == 64
        assert (
            hash_empty
            == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        )

    def test_compute_hash_deterministic(self) -> None:
        """Test deterministic output."""
        data = b"test data"
        hash1 = compute_hash_blake3(data)
        hash2 = compute_hash_blake3(data)
        assert hash1 == hash2


class TestBlake3KeyDerivation:
    """BLAKE3 key derivation tests."""

    def test_derive_key_different_contexts(self) -> None:
        """Test context separation."""
        master = b"\x00" * 32

        key1 = blake3_derive_key("context-1", master)
        key2 = blake3_derive_key("context-2", master)

        assert len(key1) == 32
        assert len(key2) == 32
        assert key1 != key2

    def test_derive_key_same_context_deterministic(self) -> None:
        """Test deterministic derivation."""
        master = b"secret-master-key"
        context = "encryption-key"

        key1 = blake3_derive_key(context, master)
        key2 = blake3_derive_key(context, master)

        assert key1 == key2

    def test_derive_key_custom_length(self) -> None:
        """Test custom key length."""
        master = b"master"

        key_16 = blake3_derive_key("test", master, length=16)
        key_64 = blake3_derive_key("test", master, length=64)

        assert len(key_16) == 16
        assert len(key_64) == 64


class TestBlake3MAC:
    """BLAKE3 MAC (keyed hashing) tests."""

    def test_hmac_blake3_basic(self) -> None:
        """Test basic MAC generation."""
        key = b"\x00" * 32
        message = b"test message"

        mac = hmac_blake3(key, message)
        assert len(mac) == 32
        assert isinstance(mac, bytes)

    def test_hmac_blake3_deterministic(self) -> None:
        """Test MAC determinism."""
        key = b"secret-key-123456789012345678901"
        assert len(key) == 32
        message = b"data"

        mac1 = hmac_blake3(key, message)
        mac2 = hmac_blake3(key, message)

        assert mac1 == mac2

    def test_hmac_blake3_different_keys(self) -> None:
        """Test key separation."""
        message = b"same message"

        key1 = b"key1" + b"\x00" * 28
        key2 = b"key2" + b"\x00" * 28

        mac1 = hmac_blake3(key1, message)
        mac2 = hmac_blake3(key2, message)

        assert mac1 != mac2

    def test_hmac_blake3_key_wrong_size(self) -> None:
        """Test key length validation."""
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            hmac_blake3(b"short", b"message")

        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            hmac_blake3(b"x" * 64, b"message")

        mac = hmac_blake3(b"x" * 32, b"message")
        assert isinstance(mac, bytes)

    def test_hmac_blake3_custom_length(self) -> None:
        """Test custom MAC length."""
        key = b"\xff" * 32
        message = b"data"

        mac_16 = hmac_blake3(key, message, length=16)
        mac_64 = hmac_blake3(key, message, length=64)

        assert len(mac_16) == 16
        assert len(mac_64) == 64


class TestBlake3FileHashing:
    """BLAKE3 file hashing tests."""

    def test_hash_file_small(self, tmp_path: Path) -> None:
        """Test hashing small file."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"hello world")

        file_hash = blake3_hash_file(str(test_file))
        direct_hash = compute_hash_blake3(b"hello world")
        assert file_hash == direct_hash

    def test_hash_file_empty(self, tmp_path: Path) -> None:
        """Test hashing empty file."""
        test_file = tmp_path / "empty.bin"
        test_file.write_bytes(b"")

        file_hash = blake3_hash_file(str(test_file))
        empty_hash = compute_hash_blake3(b"")
        assert file_hash == empty_hash

    def test_hash_file_large(self, tmp_path: Path) -> None:
        """Test hashing large file (streaming)."""
        test_file = tmp_path / "large.bin"
        chunk = b"A" * (1024 * 1024)
        test_file.write_bytes(chunk * 5)

        file_hash = blake3_hash_file(str(test_file), chunk_size=1024 * 1024)
        assert len(file_hash) == 64

        file_hash2 = blake3_hash_file(str(test_file))
        assert file_hash == file_hash2

    def test_hash_file_custom_chunk_size(self, tmp_path: Path) -> None:
        """Test custom chunk size."""
        test_file = tmp_path / "data.bin"
        test_file.write_bytes(b"x" * 10000)

        hash1 = blake3_hash_file(str(test_file), chunk_size=1024)
        hash2 = blake3_hash_file(str(test_file), chunk_size=4096)

        assert hash1 == hash2


class TestBlake3NotAvailable:
    """Tests when blake3 is not installed."""

    @pytest.mark.skipif(BLAKE3_AVAILABLE, reason="blake3 is installed")
    def test_compute_hash_raises_when_not_available(self) -> None:
        """Test ImportError when blake3 missing."""
        with pytest.raises(ImportError, match="blake3 not available"):
            compute_hash_blake3(b"data")

    @pytest.mark.skipif(BLAKE3_AVAILABLE, reason="blake3 is installed")
    def test_derive_key_raises_when_not_available(self) -> None:
        """Test ImportError for key derivation."""
        with pytest.raises(ImportError, match="blake3 not available"):
            blake3_derive_key("context", b"key")

    @pytest.mark.skipif(BLAKE3_AVAILABLE, reason="blake3 is installed")
    def test_hmac_raises_when_not_available(self) -> None:
        """Test ImportError for HMAC."""
        with pytest.raises(ImportError, match="blake3 not available"):
            hmac_blake3(b"k" * 32, b"msg")

    @pytest.mark.skipif(BLAKE3_AVAILABLE, reason="blake3 is installed")
    def test_hash_file_raises_when_not_available(self) -> None:
        """Test ImportError for file hashing."""
        with pytest.raises(ImportError, match="blake3 not available"):
            blake3_hash_file("/tmp/test")


class TestBlake3Performance:
    """Performance characteristic tests."""

    def test_large_data_hashing(self) -> None:
        """Test hashing large data without errors."""
        large_data = b"x" * (10 * 1024 * 1024)
        hash_result = compute_hash_blake3(large_data)
        assert len(hash_result) == 64

    def test_many_small_hashes(self) -> None:
        """Test many small hash operations."""
        for i in range(1000):
            data = f"message-{i}".encode()
            hash_result = compute_hash_blake3(data)
            assert len(hash_result) == 64


class TestBlake3NotAvailableMocked:
    """Tests for ImportError paths using mocking."""

    def test_compute_hash_when_module_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test compute_hash_blake3 when blake3 module is None."""
        import src.security.crypto.blake3_hash as b3

        # Mock blake3 as unavailable
        monkeypatch.setattr(b3, "BLAKE3_AVAILABLE", False)
        monkeypatch.setattr(b3, "blake3", None)

        with pytest.raises(ImportError, match="blake3 not available"):
            b3.compute_hash_blake3(b"data")

    def test_derive_key_when_module_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test blake3_derive_key when blake3 module is None."""
        import src.security.crypto.blake3_hash as b3

        monkeypatch.setattr(b3, "BLAKE3_AVAILABLE", False)
        monkeypatch.setattr(b3, "blake3", None)

        with pytest.raises(ImportError, match="blake3 not available"):
            b3.blake3_derive_key("context", b"key")

    def test_hmac_when_module_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test hmac_blake3 when blake3 module is None."""
        import src.security.crypto.blake3_hash as b3

        monkeypatch.setattr(b3, "BLAKE3_AVAILABLE", False)
        monkeypatch.setattr(b3, "blake3", None)

        with pytest.raises(ImportError, match="blake3 not available"):
            b3.hmac_blake3(b"k" * 32, b"message")

    def test_hash_file_when_module_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test blake3_hash_file when blake3 module is None."""
        import src.security.crypto.blake3_hash as b3

        monkeypatch.setattr(b3, "BLAKE3_AVAILABLE", False)
        monkeypatch.setattr(b3, "blake3", None)

        with pytest.raises(ImportError, match="blake3 not available"):
            b3.blake3_hash_file("/tmp/test")
