"""
Хеширование и проверка паролей.

Безопасное хранение паролей с использованием Argon2id (основной)
или hashlib.scrypt (fallback). Оценка сложности пароля.

Example:
    >>> from src.security.crypto.utilities.passwords import PasswordHasher
    >>> hasher = PasswordHasher()
    >>> hashed = hasher.hash_password("MySecureP@ss123!")
    >>> hasher.verify_password("MySecureP@ss123!", hashed)
    True

Version: 1.0
Date: March 2, 2026
Priority: Phase 8 — Utilities
"""

from __future__ import annotations

import base64
import hashlib
import logging
import math
import os
import re
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Optional

from src.security.crypto.core.exceptions import (
    CryptoError,
    InvalidParameterError,
)

__all__: list[str] = [
    "PasswordStrength",
    "PasswordStrengthResult",
    "PasswordHasher",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-02"

logger = logging.getLogger(__name__)

# Проверяем наличие argon2-cffi
try:
    import argon2
    from argon2 import PasswordHasher as _Argon2Hasher
    from argon2.exceptions import (
        HashingError as _Argon2HashingError,
    )
    from argon2.exceptions import (
        VerificationError as _Argon2VerificationError,
    )
    from argon2.exceptions import (
        VerifyMismatchError as _Argon2MismatchError,
    )
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


# ==============================================================================
# COMMON PASSWORDS (top-50 для быстрой проверки)
# ==============================================================================

_COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "michael", "shadow", "123123", "654321", "superman",
    "qazwsx", "football", "password1", "password123",
    "batman", "login", "admin", "princess", "starwars",
    "hello", "charlie", "donald", "welcome", "passw0rd",
    "111111", "000000", "test", "pass", "access",
    "1234", "12345", "123456789", "1234567890", "qwerty123",
    "aa123456", "password1!", "p@ssword", "p@ssw0rd", "changeme",
})


# ==============================================================================
# PASSWORD STRENGTH
# ==============================================================================


class PasswordStrength(Enum):
    """Уровень сложности пароля."""

    WEAK = "weak"
    FAIR = "fair"
    STRONG = "strong"
    VERY_STRONG = "very_strong"


@dataclass(frozen=True)
class PasswordStrengthResult:
    """
    Результат оценки сложности пароля.

    Attributes:
        strength: Уровень сложности.
        score: Числовая оценка (0-100).
        feedback: Рекомендации по улучшению.
    """

    strength: PasswordStrength
    score: int
    feedback: List[str]


# ==============================================================================
# PASSWORD HASHER
# ==============================================================================


class PasswordHasher:
    """
    Хеширование и проверка паролей.

    Использует Argon2id (если argon2-cffi установлен) или hashlib.scrypt
    в качестве fallback. Оба варианта обеспечивают защиту от brute-force
    и GPU-атак.

    Example:
        >>> hasher = PasswordHasher()
        >>> hashed = hasher.hash_password("SecurePass123!")
        >>> hasher.verify_password("SecurePass123!", hashed)
        True
        >>> hasher.verify_password("wrong", hashed)
        False
    """

    # Argon2id параметры
    DEFAULT_TIME_COST: int = 3
    DEFAULT_MEMORY_COST: int = 65536  # 64 MB
    DEFAULT_PARALLELISM: int = 4
    DEFAULT_HASH_LENGTH: int = 32
    DEFAULT_SALT_LENGTH: int = 16

    # Scrypt fallback параметры
    SCRYPT_N: int = 2**14  # 16384
    SCRYPT_R: int = 8
    SCRYPT_P: int = 1
    SCRYPT_KEY_LENGTH: int = 32

    # Валидация
    MIN_PASSWORD_LENGTH: int = 8

    def __init__(
        self,
        time_cost: int = DEFAULT_TIME_COST,
        memory_cost: int = DEFAULT_MEMORY_COST,
        parallelism: int = DEFAULT_PARALLELISM,
        hash_length: int = DEFAULT_HASH_LENGTH,
        salt_length: int = DEFAULT_SALT_LENGTH,
    ) -> None:
        """
        Инициализация хешера.

        Args:
            time_cost: Количество итераций Argon2.
            memory_cost: Использование памяти в KB.
            parallelism: Степень параллелизма.
            hash_length: Длина выходного хеша.
            salt_length: Длина соли.
        """
        self._time_cost = time_cost
        self._memory_cost = memory_cost
        self._parallelism = parallelism
        self._hash_length = hash_length
        self._salt_length = salt_length
        self._argon2_hasher: Optional[Any] = None

        if HAS_ARGON2:
            self._argon2_hasher = _Argon2Hasher(
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=hash_length,
                salt_len=salt_length,
                type=argon2.Type.ID,
            )
            logger.debug("PasswordHasher: Argon2id backend")
        else:
            logger.info(
                "PasswordHasher: argon2-cffi not available, using scrypt fallback"
            )

    def hash_password(self, password: str) -> str:
        """
        Хеширование пароля.

        Args:
            password: Пароль для хеширования.

        Returns:
            Хеш в формате '$argon2id$...' или '$scrypt$...'.

        Raises:
            InvalidParameterError: Если пароль пустой.
            CryptoError: Если хеширование не удалось.
        """
        if not password:
            raise InvalidParameterError(
                parameter_name="password",
                reason="Пароль не может быть пустым",
            )

        if self._argon2_hasher is not None:
            return self._hash_argon2(password)
        return self._hash_scrypt(password)

    def verify_password(self, password: str, hash_str: str) -> bool:
        """
        Проверка пароля по хешу.

        Args:
            password: Пароль для проверки.
            hash_str: Хеш для сравнения.

        Returns:
            True если пароль совпадает.

        Raises:
            InvalidParameterError: Если пароль или хеш пустые.
        """
        if not password or not hash_str:
            raise InvalidParameterError(
                parameter_name="password" if not password else "hash_str",
                reason="Параметр не может быть пустым",
            )

        if hash_str.startswith("$scrypt$"):
            return self._verify_scrypt(password, hash_str)

        if hash_str.startswith("$argon2"):
            return self._verify_argon2(password, hash_str)

        raise InvalidParameterError(
            parameter_name="hash_str",
            reason="Неизвестный формат хеша",
        )

    def check_password_strength(self, password: str) -> PasswordStrengthResult:
        """
        Оценка сложности пароля.

        Проверяет длину, разнообразие символов, энтропию и наличие
        в списке распространённых паролей.

        Args:
            password: Пароль для оценки.

        Returns:
            Результат оценки с рекомендациями.
        """
        feedback: List[str] = []
        score = 0

        # Длина
        length = len(password)
        if length < 8:
            feedback.append("Пароль слишком короткий (минимум 8 символов)")
        elif length < 12:
            score += 15
        elif length < 16:
            score += 25
        else:
            score += 35

        # Разнообразие символов
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

        char_types = sum([has_lower, has_upper, has_digit, has_special])
        score += char_types * 10

        if not has_upper:
            feedback.append("Добавьте заглавные буквы")
        if not has_digit:
            feedback.append("Добавьте цифры")
        if not has_special:
            feedback.append("Добавьте специальные символы (!@#$%...)")

        # Энтропия
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32

        if charset_size > 0 and length > 0:
            entropy = length * math.log2(charset_size)
            if entropy >= 60:
                score += 25
            elif entropy >= 40:
                score += 15
            elif entropy >= 28:
                score += 5
            else:
                feedback.append("Низкая энтропия — увеличьте разнообразие")

        # Распространённые пароли
        if password.lower() in _COMMON_PASSWORDS:
            score = max(0, score - 50)
            feedback.append("Пароль в списке распространённых — смените его")

        # Повторяющиеся символы
        if re.search(r"(.)\1{2,}", password):
            score = max(0, score - 10)
            feedback.append("Избегайте повторяющихся символов")

        # Последовательности
        if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde|def)", password.lower()):
            score = max(0, score - 10)
            feedback.append("Избегайте последовательностей (123, abc...)")

        # Клэмп
        score = max(0, min(100, score))

        # Определение уровня
        if score >= 75:
            strength = PasswordStrength.VERY_STRONG
        elif score >= 50:
            strength = PasswordStrength.STRONG
        elif score >= 25:
            strength = PasswordStrength.FAIR
        else:
            strength = PasswordStrength.WEAK

        if not feedback:
            feedback.append("Пароль соответствует требованиям безопасности")

        return PasswordStrengthResult(
            strength=strength,
            score=score,
            feedback=feedback,
        )

    def needs_rehash(self, hash_str: str) -> bool:
        """
        Проверка актуальности параметров хеширования.

        Возвращает True если хеш создан с устаревшими параметрами
        и требует перехеширования.

        Args:
            hash_str: Хеш для проверки.

        Returns:
            True если требуется перехеширование.
        """
        if hash_str.startswith("$scrypt$"):
            # Scrypt всегда считается устаревшим при наличии Argon2
            return HAS_ARGON2

        if hash_str.startswith("$argon2") and self._argon2_hasher is not None:
            try:
                result: bool = self._argon2_hasher.check_needs_rehash(hash_str)
                return result
            except Exception:
                return True

        return False

    # --- Private: Argon2 ---

    def _hash_argon2(self, password: str) -> str:
        """Хеширование через Argon2id."""
        try:
            assert self._argon2_hasher is not None
            hashed: str = self._argon2_hasher.hash(password)
            return hashed
        except Exception as e:
            raise CryptoError(f"Argon2id hashing failed: {e}") from e

    def _verify_argon2(self, password: str, hash_str: str) -> bool:
        """Проверка через Argon2id."""
        if not HAS_ARGON2:
            raise CryptoError(
                "argon2-cffi required for Argon2 verification"
            )
        try:
            hasher = _Argon2Hasher()
            return hasher.verify(hash_str, password)
        except _Argon2MismatchError:
            return False
        except _Argon2VerificationError:
            return False
        except Exception as e:
            raise CryptoError(f"Argon2 verification failed: {e}") from e

    # --- Private: Scrypt fallback ---

    def _hash_scrypt(self, password: str) -> str:
        """Хеширование через hashlib.scrypt."""
        salt = os.urandom(self._salt_length)
        try:
            derived = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=self.SCRYPT_N,
                r=self.SCRYPT_R,
                p=self.SCRYPT_P,
                dklen=self.SCRYPT_KEY_LENGTH,
            )
        except Exception as e:
            raise CryptoError(f"Scrypt hashing failed: {e}") from e

        salt_b64 = base64.b64encode(salt).decode("ascii")
        hash_b64 = base64.b64encode(derived).decode("ascii")
        return (
            f"$scrypt$n={self.SCRYPT_N}$r={self.SCRYPT_R}"
            f"$p={self.SCRYPT_P}${salt_b64}${hash_b64}"
        )

    def _verify_scrypt(self, password: str, hash_str: str) -> bool:
        """Проверка через hashlib.scrypt."""
        try:
            parts = hash_str.split("$")
            # $scrypt$n=N$r=R$p=P$salt$hash
            if len(parts) != 7 or parts[1] != "scrypt":
                return False

            n = int(parts[2].split("=")[1])
            r = int(parts[3].split("=")[1])
            p = int(parts[4].split("=")[1])
            salt = base64.b64decode(parts[5])
            expected = base64.b64decode(parts[6])

            derived = hashlib.scrypt(
                password.encode("utf-8"),
                salt=salt,
                n=n,
                r=r,
                p=p,
                dklen=len(expected),
            )
            return secrets.compare_digest(derived, expected)
        except Exception:
            return False
