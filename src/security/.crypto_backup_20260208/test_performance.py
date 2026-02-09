# -*- coding: utf-8 -*-
"""
Performance benchmarks for crypto operations.

Run with: pytest tests/unit/security/crypto/test_performance.py -v --benchmark
"""
import time
from typing import Callable

import pytest


def benchmark(func: Callable[[], None], iterations: int = 100) -> float:
    """
    Benchmark function execution time.

    Args:
        func: Function to benchmark (takes no args).
        iterations: Number of iterations.

    Returns:
        Average time per iteration in milliseconds.
    """
    start = time.perf_counter()
    for _ in range(iterations):
        func()
    elapsed = time.perf_counter() - start
    return (elapsed / iterations) * 1000  # Convert to ms


class TestPerformance:
    """Performance benchmarks for crypto operations."""

    def test_argon2id_performance(self) -> None:
        """Argon2id should complete in < 500ms for interactivity."""
        from .kdf import derive_key_argon2id, generate_salt

        password = "test-password-123"
        salt = generate_salt(16)

        def run() -> None:
            derive_key_argon2id(
                password,
                salt,
                length=32,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
            )

        avg_time = benchmark(run, iterations=5)
        print(f"\nArgon2id: {avg_time:.1f} ms/op")

        assert avg_time < 500, f"Argon2id too slow: {avg_time:.1f}ms > 500ms"

    def test_aes_gcm_performance(self) -> None:
        """AES-256-GCM encryption should be < 1ms for 1KB payload."""
        from .symmetric import decrypt_aes_gcm, encrypt_aes_gcm

        key = b"\x00" * 32
        plaintext = b"x" * 1024  # 1 KB

        def run_encrypt() -> None:
            encrypt_aes_gcm(key, plaintext)

        avg_time = benchmark(run_encrypt, iterations=1000)
        print(f"\nAES-256-GCM encrypt (1KB): {avg_time:.3f} ms/op")

        assert avg_time < 1.0, f"AES-GCM too slow: {avg_time:.3f}ms > 1ms"

        # Test decryption
        nonce, combined = encrypt_aes_gcm(key, plaintext)

        def run_decrypt() -> None:
            decrypt_aes_gcm(key, nonce, combined)

        avg_time = benchmark(run_decrypt, iterations=1000)
        print(f"AES-256-GCM decrypt (1KB): {avg_time:.3f} ms/op")

        assert avg_time < 1.0, f"AES-GCM decrypt too slow: {avg_time:.3f}ms > 1ms"

    def test_ed25519_performance(self) -> None:
        """Ed25519 signing should be < 1ms."""
        from .asymmetric import AsymmetricKeyPair

        kp = AsymmetricKeyPair.generate("ed25519")
        message = b"test-message-for-signing"

        def run_sign() -> None:
            kp.sign(message)

        avg_time = benchmark(run_sign, iterations=1000)
        print(f"\nEd25519 sign: {avg_time:.3f} ms/op")

        assert avg_time < 1.0, f"Ed25519 sign too slow: {avg_time:.3f}ms > 1ms"

        # Test verification
        signature = kp.sign(message)

        def run_verify() -> None:
            kp.verify(message, signature)

        avg_time = benchmark(run_verify, iterations=1000)
        print(f"Ed25519 verify: {avg_time:.3f} ms/op")

        assert avg_time < 1.0, f"Ed25519 verify too slow: {avg_time:.3f}ms > 1ms"

    def test_sha3_performance(self) -> None:
        """SHA3-256 hashing should be < 1ms for 10KB."""
        from .hashing import compute_hash

        data = b"x" * 10240  # 10 KB

        def run() -> None:
            compute_hash(data, algorithm="sha3-256")

        avg_time = benchmark(run, iterations=1000)
        print(f"\nSHA3-256 (10KB): {avg_time:.3f} ms/op")

        assert avg_time < 1.0, f"SHA3 too slow: {avg_time:.3f}ms > 1ms"

    def test_keystore_performance(self) -> None:
        """Keystore save/load should be < 10ms."""
        import tempfile
        from pathlib import Path

        from .secure_storage import FileEncryptedStorageBackend
        from .symmetric import SymmetricCipher

        with tempfile.NamedTemporaryFile(delete=False, suffix=".keystore") as tmp:
            tmp_path = tmp.name

        try:
            cipher = SymmetricCipher()
            key = b"\x00" * 32

            storage = FileEncryptedStorageBackend(
                filepath=tmp_path,
                cipher=cipher,  # type: ignore[arg-type]
                key_provider=lambda: key,
            )

            test_data = b"x" * 1024  # 1 KB

            def run_save() -> None:
                storage.save("test-key", test_data)

            avg_time = benchmark(run_save, iterations=100)
            print(f"\nKeystore save (1KB): {avg_time:.2f} ms/op")

            assert avg_time < 10.0, f"Keystore save too slow: {avg_time:.2f}ms > 10ms"

            def run_load() -> None:
                storage.load("test-key")

            avg_time = benchmark(run_load, iterations=100)
            print(f"Keystore load (1KB): {avg_time:.2f} ms/op")

            assert avg_time < 10.0, f"Keystore load too slow: {avg_time:.2f}ms > 10ms"

        finally:
            Path(tmp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
