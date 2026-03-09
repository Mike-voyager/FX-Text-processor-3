"""
Тесты для модуля базовых криптографических утилит.

Покрытие:
- generate_key: корректный размер, size <= 0 → InvalidParameterError, случайность
- generate_salt: аналогично generate_key
- constant_time_compare: равные/неравные/разные длины
- NonceManager.generate_nonce: размер, size <= 0
- NonceManager.track_nonce: новый nonce, повтор → InvalidNonceError
- NonceManager.clear: конкретный key_id / все
- NonceManager.get_nonce_count: до и после track/clear
- SecureMemory.secure_zero: обнуление bytearray, TypeError для bytes
- SecureMemory.constant_time_compare: равные/неравные
- SecureMemory.secure_context: обнуление после выхода
- FloppyOptimizer.validate_file_size: в пределах / за пределами
- FloppyOptimizer.estimate_storage_size: реальная директория / несуществующая
- FloppyOptimizer.compress_keystore / decompress_keystore: roundtrip, битые данные
- FloppyOptimizer.cleanup_old_backups: удаление лишних .bak / пустая директория
- FloppyOptimizer.get_recommended_algorithms: известная / неизвестная категория

Coverage target: 95%+

Author: Mike Voyager
Version: 1.0
Date: March 10, 2026
"""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import os
from pathlib import Path

import pytest
from src.security.crypto.core.exceptions import (
    CryptoError,
    InvalidNonceError,
    InvalidParameterError,
    ValidationError,
)
from src.security.crypto.utilities.utils import (
    FloppyOptimizer,
    NonceManager,
    SecureMemory,
    constant_time_compare,
    generate_key,
    generate_salt,
)

# ==============================================================================
# generate_key
# ==============================================================================


class TestGenerateKey:
    def test_returns_correct_size(self) -> None:
        key = generate_key(32)
        assert len(key) == 32

    def test_various_sizes(self) -> None:
        for size in (1, 16, 24, 32, 64):
            assert len(generate_key(size)) == size

    def test_zero_size_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            generate_key(0)

    def test_negative_size_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            generate_key(-1)

    def test_returns_bytes(self) -> None:
        assert isinstance(generate_key(16), bytes)

    def test_different_each_call(self) -> None:
        k1 = generate_key(32)
        k2 = generate_key(32)
        assert k1 != k2


# ==============================================================================
# generate_salt
# ==============================================================================


class TestGenerateSalt:
    def test_default_size(self) -> None:
        salt = generate_salt()
        assert len(salt) == 32

    def test_custom_size(self) -> None:
        assert len(generate_salt(16)) == 16

    def test_zero_size_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            generate_salt(0)

    def test_negative_size_raises(self) -> None:
        with pytest.raises(InvalidParameterError):
            generate_salt(-5)

    def test_returns_bytes(self) -> None:
        assert isinstance(generate_salt(16), bytes)

    def test_different_each_call(self) -> None:
        s1 = generate_salt(32)
        s2 = generate_salt(32)
        assert s1 != s2


# ==============================================================================
# constant_time_compare
# ==============================================================================


class TestConstantTimeCompare:
    def test_equal(self) -> None:
        assert constant_time_compare(b"hello", b"hello") is True

    def test_not_equal(self) -> None:
        assert constant_time_compare(b"hello", b"world") is False

    def test_different_lengths(self) -> None:
        assert constant_time_compare(b"abc", b"abcd") is False

    def test_empty_equal(self) -> None:
        assert constant_time_compare(b"", b"") is True

    def test_empty_vs_nonempty(self) -> None:
        assert constant_time_compare(b"", b"x") is False


# ==============================================================================
# NonceManager
# ==============================================================================


class TestNonceManager:
    def test_generate_nonce_correct_size(self) -> None:
        manager = NonceManager()
        nonce = manager.generate_nonce(12)
        assert len(nonce) == 12

    def test_generate_nonce_24_bytes(self) -> None:
        manager = NonceManager()
        assert len(manager.generate_nonce(24)) == 24

    def test_generate_nonce_zero_raises(self) -> None:
        manager = NonceManager()
        with pytest.raises(InvalidParameterError):
            manager.generate_nonce(0)

    def test_generate_nonce_negative_raises(self) -> None:
        manager = NonceManager()
        with pytest.raises(InvalidParameterError):
            manager.generate_nonce(-1)

    def test_generate_nonce_random(self) -> None:
        manager = NonceManager()
        n1 = manager.generate_nonce(12)
        n2 = manager.generate_nonce(12)
        assert n1 != n2

    def test_track_nonce_first_time_ok(self) -> None:
        manager = NonceManager()
        nonce = manager.generate_nonce(12)
        manager.track_nonce("key1", nonce)  # should not raise

    def test_track_nonce_duplicate_raises(self) -> None:
        manager = NonceManager()
        nonce = b"\x00" * 12
        manager.track_nonce("key1", nonce)
        with pytest.raises(InvalidNonceError):
            manager.track_nonce("key1", nonce)

    def test_track_nonce_same_nonce_different_keys_ok(self) -> None:
        manager = NonceManager()
        nonce = b"\x00" * 12
        manager.track_nonce("key1", nonce)
        manager.track_nonce("key2", nonce)  # другой ключ — допустимо

    def test_get_nonce_count_initial(self) -> None:
        manager = NonceManager()
        assert manager.get_nonce_count("key1") == 0

    def test_get_nonce_count_after_track(self) -> None:
        manager = NonceManager()
        manager.track_nonce("key1", b"\x01" * 12)
        manager.track_nonce("key1", b"\x02" * 12)
        assert manager.get_nonce_count("key1") == 2

    def test_clear_specific_key(self) -> None:
        manager = NonceManager()
        manager.track_nonce("key1", b"\x01" * 12)
        manager.track_nonce("key2", b"\x01" * 12)
        manager.clear("key1")
        assert manager.get_nonce_count("key1") == 0
        assert manager.get_nonce_count("key2") == 1

    def test_clear_all(self) -> None:
        manager = NonceManager()
        manager.track_nonce("key1", b"\x01" * 12)
        manager.track_nonce("key2", b"\x02" * 12)
        manager.clear()
        assert manager.get_nonce_count("key1") == 0
        assert manager.get_nonce_count("key2") == 0

    def test_clear_nonexistent_key_ok(self) -> None:
        manager = NonceManager()
        manager.clear("nonexistent")  # should not raise

    def test_after_clear_nonce_can_be_reused(self) -> None:
        manager = NonceManager()
        nonce = b"\x00" * 12
        manager.track_nonce("key1", nonce)
        manager.clear("key1")
        manager.track_nonce("key1", nonce)  # повторное использование после очистки


# ==============================================================================
# SecureMemory
# ==============================================================================


class TestSecureMemory:
    def test_secure_zero_clears_bytearray(self) -> None:
        mem = SecureMemory()
        data = bytearray(os.urandom(32))
        mem.secure_zero(data)
        assert data == bytearray(32)

    def test_secure_zero_empty_bytearray(self) -> None:
        mem = SecureMemory()
        data = bytearray()
        mem.secure_zero(data)  # should not raise

    def test_secure_zero_raises_for_bytes(self) -> None:
        mem = SecureMemory()
        with pytest.raises(TypeError):
            mem.secure_zero(b"secret")  # type: ignore[arg-type]

    def test_secure_zero_raises_for_str(self) -> None:
        mem = SecureMemory()
        with pytest.raises(TypeError):
            mem.secure_zero("secret")  # type: ignore[arg-type]

    def test_constant_time_compare_equal(self) -> None:
        mem = SecureMemory()
        assert mem.constant_time_compare(b"tag", b"tag") is True

    def test_constant_time_compare_not_equal(self) -> None:
        mem = SecureMemory()
        assert mem.constant_time_compare(b"tag1", b"tag2") is False

    def test_secure_context_yields_copy(self) -> None:
        mem = SecureMemory()
        key = b"secret_key_data!"
        with mem.secure_context(key) as key_copy:
            assert bytes(key_copy) == key
            assert isinstance(key_copy, bytearray)

    def test_secure_context_zeroes_after_exit(self) -> None:
        mem = SecureMemory()
        key = b"secret_key_data!"
        with mem.secure_context(key) as key_copy:
            ref = key_copy
        assert ref == bytearray(len(key))

    def test_secure_context_zeroes_on_exception(self) -> None:
        mem = SecureMemory()
        key = b"secret_key_data!"
        ref = bytearray(len(key))
        try:
            with mem.secure_context(key) as key_copy:
                ref = key_copy
                raise RuntimeError("simulated error")
        except RuntimeError:
            pass
        assert ref == bytearray(len(key))


# ==============================================================================
# FloppyOptimizer
# ==============================================================================


class TestFloppyOptimizer:
    def test_default_init(self) -> None:
        optimizer = FloppyOptimizer()
        assert optimizer._config is not None

    def test_validate_file_size_within_limit(self) -> None:
        optimizer = FloppyOptimizer()
        # max_storage_size по умолчанию должен быть > 0
        assert optimizer.validate_file_size(1) is True

    def test_validate_file_size_zero(self) -> None:
        optimizer = FloppyOptimizer()
        assert optimizer.validate_file_size(0) is True

    def test_validate_file_size_exceeds(self) -> None:
        optimizer = FloppyOptimizer()
        # Размер заведомо больше любого floppy
        assert optimizer.validate_file_size(10 * 1024 * 1024 * 1024) is False

    def test_estimate_storage_size_existing_dir(self, tmp_path: Path) -> None:
        optimizer = FloppyOptimizer()
        (tmp_path / "file1.bin").write_bytes(b"A" * 100)
        (tmp_path / "file2.bin").write_bytes(b"B" * 200)
        total = optimizer.estimate_storage_size(tmp_path)
        assert total == 300

    def test_estimate_storage_size_empty_dir(self, tmp_path: Path) -> None:
        optimizer = FloppyOptimizer()
        assert optimizer.estimate_storage_size(tmp_path) == 0

    def test_estimate_storage_size_nonexistent_raises(self) -> None:
        optimizer = FloppyOptimizer()
        with pytest.raises(ValidationError):
            optimizer.estimate_storage_size(Path("/nonexistent/path/xyz"))

    def test_estimate_storage_size_nested(self, tmp_path: Path) -> None:
        optimizer = FloppyOptimizer()
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "file.bin").write_bytes(b"X" * 50)
        assert optimizer.estimate_storage_size(tmp_path) == 50

    def test_compress_decompress_roundtrip(self) -> None:
        optimizer = FloppyOptimizer()
        data = b"Hello, floppy!" * 100
        compressed = optimizer.compress_keystore(data)
        assert len(compressed) < len(data)
        decompressed = optimizer.decompress_keystore(compressed)
        assert decompressed == data

    def test_decompress_invalid_raises(self) -> None:
        optimizer = FloppyOptimizer()
        with pytest.raises(CryptoError):
            optimizer.decompress_keystore(b"not_valid_zlib_data")

    def test_cleanup_old_backups_removes_excess(self, tmp_path: Path) -> None:
        optimizer = FloppyOptimizer()
        max_count = optimizer._config.max_backup_count
        # Создаём max_count + 2 бэкапа с разными mtime
        for i in range(max_count + 2):
            f = tmp_path / f"backup_{i:03d}.bak"
            f.write_bytes(b"data")
            # Устанавливаем разные mtime через touch
            import time

            os.utime(f, (time.time() + i, time.time() + i))
        removed = optimizer.cleanup_old_backups(tmp_path)
        assert removed == 2
        remaining = list(tmp_path.glob("*.bak"))
        assert len(remaining) == max_count

    def test_cleanup_old_backups_empty_dir(self, tmp_path: Path) -> None:
        optimizer = FloppyOptimizer()
        assert optimizer.cleanup_old_backups(tmp_path) == 0

    def test_cleanup_old_backups_nonexistent_dir(self, tmp_path: Path) -> None:
        optimizer = FloppyOptimizer()
        result = optimizer.cleanup_old_backups(tmp_path / "nonexistent")
        assert result == 0

    def test_cleanup_ignores_non_bak_files(self, tmp_path: Path) -> None:
        optimizer = FloppyOptimizer()
        (tmp_path / "file.txt").write_bytes(b"text")
        (tmp_path / "file.enc").write_bytes(b"enc")
        removed = optimizer.cleanup_old_backups(tmp_path)
        assert removed == 0

    def test_get_recommended_algorithms_symmetric(self) -> None:
        optimizer = FloppyOptimizer()
        algos = optimizer.get_recommended_algorithms("symmetric")
        assert isinstance(algos, list)
        assert len(algos) > 0
        assert "aes-256-gcm" in algos

    def test_get_recommended_algorithms_signing(self) -> None:
        optimizer = FloppyOptimizer()
        algos = optimizer.get_recommended_algorithms("signing")
        assert "ed25519" in algos

    def test_get_recommended_algorithms_unknown_category(self) -> None:
        optimizer = FloppyOptimizer()
        algos = optimizer.get_recommended_algorithms("unknown_category")
        assert algos == []

    def test_get_recommended_algorithms_returns_copy(self) -> None:
        """Изменение возвращённого списка не влияет на внутреннее состояние."""
        optimizer = FloppyOptimizer()
        algos = optimizer.get_recommended_algorithms("symmetric")
        algos.clear()
        assert len(optimizer.get_recommended_algorithms("symmetric")) > 0
