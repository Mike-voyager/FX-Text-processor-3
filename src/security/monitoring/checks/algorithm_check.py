"""
Algorithm Check — проверка криптографических алгоритмов.

Проверяет:
- Доступность liboqs (post-quantum)
- Доступность pyscard (smartcard)
- Доступность криптографических примитивов

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.security.monitoring.exceptions import AlgorithmCheckError
from src.security.monitoring.models import HealthCheckResult, HealthCheckStatus

LOG = logging.getLogger(__name__)

# Обязательные алгоритмы (критические)
REQUIRED_ALGORITHMS = [
    "AES-256-GCM",
    "ChaCha20-Poly1305",
    "Ed25519",
    "SHA-256",
    "SHA3-256",
    "Argon2id",
]

# Опциональные алгоритмы (post-quantum)
OPTIONAL_ALGORITHMS = [
    "ML-DSA-65",
    "ML-KEM-768",
    "SLH-DSA",
]


@dataclass
class AlgorithmCheck:
    """
    Проверка доступности криптографических алгоритмов.

    Критическая проверка для криптографических операций.

    Attributes:
        name: Имя проверки (фиксированное: "algorithm")
        description: Описание проверки
        critical: True для обязательных алгоритмов
        required_algorithms: Список обязательных алгоритмов
        optional_algorithms: Список опциональных алгоритмов
        check_pqc: Проверять post-quantum алгоритмы

    Example:
        >>> check = AlgorithmCheck()
        >>> result = check.check()
        >>> if result.is_healthy:
        ...     print("All algorithms available")
    """

    name: str = "algorithm"
    description: str = "Cryptographic algorithm availability check"
    critical: bool = True
    required_algorithms: List[str] = None  # type: ignore[assignment]
    optional_algorithms: List[str] = None  # type: ignore[assignment]
    check_pqc: bool = True

    def __post_init__(self) -> None:
        """Инициализация после создания."""
        if self.required_algorithms is None:
            self.required_algorithms = list(REQUIRED_ALGORITHMS)
        if self.optional_algorithms is None:
            self.optional_algorithms = list(OPTIONAL_ALGORITHMS)

    def check(self) -> HealthCheckResult:
        """
        Выполнить проверку алгоритмов.

        Returns:
            HealthCheckResult с результатом проверки
        """
        start_ms = time.monotonic()

        try:
            details: Dict[str, Any] = {
                "required": {},
                "optional": {},
                "libraries": {},
            }

            warnings: List[str] = []
            errors: List[str] = []

            # Проверяем библиотеки
            libs_status = self._check_libraries()
            details["libraries"] = libs_status

            # Проверяем обязательные алгоритмы
            for alg in self.required_algorithms:
                alg_status = self._check_algorithm(alg)
                details["required"][alg] = alg_status

                if not alg_status["available"]:
                    errors.append(f"Required algorithm '{alg}' not available")
                elif alg_status.get("warning"):
                    warnings.append(alg_status["warning"])

            # Проверяем опциональные алгоритмы
            for alg in self.optional_algorithms:
                if not self.check_pqc:
                    continue

                alg_status = self._check_algorithm(alg)
                details["optional"][alg] = alg_status

                if not alg_status["available"]:
                    # Опциональные алгоритмы — предупреждение, не ошибка
                    warnings.append(f"Optional algorithm '{alg}' not available")

            elapsed_ms = int((time.monotonic() - start_ms) * 1000)

            # Определяем статус
            if errors:
                status = HealthCheckStatus.UNHEALTHY
                message = f"Missing required algorithms: {', '.join(errors)}"
            elif warnings:
                status = HealthCheckStatus.DEGRADED
                message = f"Algorithm check passed with warnings: {len(warnings)}"
            else:
                status = HealthCheckStatus.HEALTHY
                message = f"All {len(self.required_algorithms)} required algorithms available"

            return HealthCheckResult(
                check_name=self.name,
                status=status,
                message=message,
                duration_ms=elapsed_ms,
                details=details,
                warnings=warnings,
                error=errors[0] if errors else None,
            )

        except Exception as e:
            elapsed_ms = int((time.monotonic() - start_ms) * 1000)
            LOG.error("Algorithm check failed: %s", e)
            return HealthCheckResult.error_result(
                check_name=self.name,
                error=str(e),
                exception=type(e).__name__,
            )

    def _check_libraries(self) -> Dict[str, Any]:
        """
        Проверить доступность криптографических библиотек.

        Returns:
            Словарь со статусом библиотек
        """
        libs: Dict[str, Any] = {}

        # cryptography (обязательная)
        try:
            import cryptography
            from cryptography.hazmat.backends import default_backend

            libs["cryptography"] = {
                "available": True,
                "version": cryptography.__version__,
            }
        except ImportError:
            libs["cryptography"] = {
                "available": False,
                "error": "Not installed",
            }

        # liboqs (опциональная, для PQC)
        try:
            import liboqs

            libs["liboqs"] = {
                "available": True,
                "version": getattr(liboqs, "__version__", "unknown"),
            }
        except ImportError:
            libs["liboqs"] = {
                "available": False,
                "error": "Not installed (optional for PQC)",
            }

        # pyscard (опциональная, для smartcard)
        try:
            import smartcard

            libs["pyscard"] = {
                "available": True,
            }
        except ImportError:
            libs["pyscard"] = {
                "available": False,
                "error": "Not installed (optional for smartcard)",
            }

        # argon2 (обязательная для KDF)
        try:
            import argon2

            libs["argon2"] = {
                "available": True,
                "version": argon2.__version__,
            }
        except ImportError:
            libs["argon2"] = {
                "available": False,
                "error": "Not installed",
            }

        return libs

    def _check_algorithm(self, algorithm: str) -> Dict[str, Any]:
        """
        Проверить доступность конкретного алгоритма.

        Args:
            algorithm: Имя алгоритма

        Returns:
            Словарь со статусом алгоритма
        """
        status: Dict[str, Any] = {
            "algorithm": algorithm,
            "available": False,
        }

        try:
            if algorithm == "AES-256-GCM":
                status["available"] = self._check_aes_gcm()
            elif algorithm == "ChaCha20-Poly1305":
                status["available"] = self._check_chacha20()
            elif algorithm == "Ed25519":
                status["available"] = self._check_ed25519()
            elif algorithm == "SHA-256":
                status["available"] = self._check_sha256()
            elif algorithm == "SHA3-256":
                status["available"] = self._check_sha3_256()
            elif algorithm == "Argon2id":
                status["available"] = self._check_argon2id()
            elif algorithm == "ML-DSA-65":
                status["available"] = self._check_ml_dsa()
            elif algorithm == "ML-KEM-768":
                status["available"] = self._check_ml_kem()
            elif algorithm == "SLH-DSA":
                status["available"] = self._check_slh_dsa()
            else:
                status["warning"] = f"Unknown algorithm: {algorithm}"

        except Exception as e:
            status["error"] = str(e)

        return status

    def _check_aes_gcm(self) -> bool:
        """Проверка AES-256-GCM."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from secrets import token_bytes

            key = token_bytes(32)
            nonce = token_bytes(12)
            aesgcm = AESGCM(key)
            data = b"test"
            ct = aesgcm.encrypt(nonce, data, None)
            pt = aesgcm.decrypt(nonce, ct, None)
            return pt == data
        except Exception:
            return False

    def _check_chacha20(self) -> bool:
        """Проверка ChaCha20-Poly1305."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            from secrets import token_bytes

            key = token_bytes(32)
            nonce = token_bytes(12)
            chacha = ChaCha20Poly1305(key)
            data = b"test"
            ct = chacha.encrypt(nonce, data, None)
            pt = chacha.decrypt(nonce, ct, None)
            return pt == data
        except Exception:
            return False

    def _check_ed25519(self) -> bool:
        """Проверка Ed25519."""
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization

            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            data = b"test message"
            signature = private_key.sign(data)
            public_key.verify(signature, data)
            return True
        except Exception:
            return False

    def _check_sha256(self) -> bool:
        """Проверка SHA-256."""
        try:
            from cryptography.hazmat.primitives import hashes

            digest = hashes.Hash(hashes.SHA256())
            digest.update(b"test")
            result = digest.finalize()
            return len(result) == 32
        except Exception:
            return False

    def _check_sha3_256(self) -> bool:
        """Проверка SHA3-256."""
        try:
            from cryptography.hazmat.primitives import hashes

            digest = hashes.Hash(hashes.SHA3_256())
            digest.update(b"test")
            result = digest.finalize()
            return len(result) == 32
        except Exception:
            return False

    def _check_argon2id(self) -> bool:
        """Проверка Argon2id."""
        try:
            from argon2.low_level import hash_secret_raw, Type
            from secrets import token_bytes

            password = b"password"
            salt = token_bytes(16)
            hash_value = hash_secret_raw(
                password,
                salt,
                time_cost=1,
                memory_cost=8,
                parallelism=1,
                hash_len=32,
                type=Type.ID,
            )
            return len(hash_value) == 32
        except Exception:
            return False

    def _check_ml_dsa(self) -> bool:
        """Проверка ML-DSA-65 (Dilithium)."""
        try:
            import liboqs

            # liboqs использует "Dilithium3" для ML-DSA-65
            with liboqs.Signature("Dilithium3") as sig:
                public_key = sig.generate_keypair()
                signature = sig.sign(b"test message")
                result = sig.verify(b"test message", signature, public_key)
                return bool(result)
        except Exception:
            return False

    def _check_ml_kem(self) -> bool:
        """Проверка ML-KEM-768 (Kyber)."""
        try:
            import liboqs

            # liboqs использует "Kyber768" для ML-KEM-768
            with liboqs.KeyEncapsulation("Kyber768") as kem:
                public_key = kem.generate_keypair()
                ciphertext, shared_secret_enc = kem.encap_secret(public_key)
                shared_secret_dec = kem.decap_secret(ciphertext)
                return bool(shared_secret_enc == shared_secret_dec)
        except Exception:
            return False

    def _check_slh_dsa(self) -> bool:
        """Проверка SLH-DSA (SPHINCS+)."""
        try:
            import liboqs

            # SLH-DSA доступен в liboqs как "SPHINCS+-SHA2-128f-simple"
            with liboqs.Signature("SPHINCS+-SHA2-128f-simple") as sig:
                public_key = sig.generate_keypair()
                signature = sig.sign(b"test message")
                result = sig.verify(b"test message", signature, public_key)
                return bool(result)
        except Exception:
            return False


__all__: list[str] = [
    "AlgorithmCheck",
    "REQUIRED_ALGORITHMS",
    "OPTIONAL_ALGORITHMS",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-24"