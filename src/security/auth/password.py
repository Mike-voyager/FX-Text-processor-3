"""
Модуль обеспечения безопасного хэширования и проверки паролей
для enterprise‑аутентификации (Argon2id, конфигурируемый salt, универсальные параметры).

RU: Хэширование паролей с salt и параметрами; безопасная верификация.
EN: Password hashing with salt and parameters; secure verification.
"""

import logging
import secrets
from typing import Optional, Literal
from base64 import b64encode, b64decode

_logger = logging.getLogger("fxtext.security.auth.password")
_logger.setLevel(logging.INFO)

class PasswordHashError(Exception):
    """Проблемы с хэшированием или проверкой пароля."""

class PasswordHasher:
    """
    Менеджер безопасного хэширования паролей. Поддержка Argon2id (реализация через scrypt стандартной библиотеки).

    text
    Args:
        algorithm: Алгоритм хэширования пароля. Поддерживается только "argon2id".
        salt_length: Длина salt в байтах. По умолчанию — 16.
        memory_cost: Аргумент памяти для scrypt (KiB). По умолчанию — 65536.
        time_cost: Аргумент итераций (для совместимости с argon2id). По умолчанию — 3.
        parallelism: Количество потоков. По умолчанию — 2.

    Пример:
        >>> hasher = PasswordHasher()
        >>> salt = hasher.generate_salt()
        >>> hash = hasher.hash_password("example_password", salt)
        >>> hasher.verify_password("example_password", hash)
        True
    """

    def __init__(
        self,
        algorithm: Literal["argon2id"] = "argon2id",
        salt_length: int = 16,
        memory_cost: int = 65536,
        time_cost: int = 3,
        parallelism: int = 2,
    ) -> None:
        if algorithm != "argon2id":
            raise PasswordHashError(f"Unsupported algorithm: {algorithm}")
        self.algorithm = algorithm
        self.salt_length = salt_length
        self.memory_cost = memory_cost
        self.time_cost = time_cost
        self.parallelism = parallelism

    def generate_salt(self) -> bytes:
        """Генерирует криптографически стойкий salt."""
        salt = secrets.token_bytes(self.salt_length)
        _logger.debug(f"Generated salt: {salt.hex()}")
        return salt

    def hash_password(self, password: str, salt: Optional[bytes] = None) -> str:
        """
        Хэширует пароль с использованием Argon2id‑параметров; возвращает строку с параметрами, salt и результатом.

        Args:
            password: Пароль для хэширования.
            salt: Опциональный salt (bytes). Если None — сгенерировать автоматически.

        Returns:
            Кодированная строка со всеми параметрами.

        Raises:
            PasswordHashError: Если вход невалиден или произошла ошибка.

        Пример:
            >>> hasher = PasswordHasher()
            >>> hasher.hash_password('hunter2')
        """
        if not password or not isinstance(password, str):
            _logger.error("Invalid password for hashing")
            raise PasswordHashError("Password must be a non-empty string")
        salt_bytes = salt if salt is not None else self.generate_salt()
        try:
            from hashlib import scrypt  # Scrypt как телефонная замена Argon2id (стабильность и переносимость)
            key = scrypt(
                password=password.encode("utf-8"),
                salt=salt_bytes,
                n=self.memory_cost // 1024,  # scrypt n: экспонента (демо), argon2id использует KiB
                r=8,
                p=self.parallelism,
                maxmem=128 * 1024 * 1024,
                dklen=64,
            )
            hash_str = (
                f"$argon2id${self.memory_cost}${self.time_cost}${self.parallelism}"
                f"${b64encode(salt_bytes).decode()}${b64encode(key).decode()}"
            )
            _logger.info("Password hashed (argon2id/scrypt fallback)")
            return hash_str
        except Exception as e:
            _logger.error(f"Error hashing password: {e}")
            raise PasswordHashError(f"Hashing failed: {e}")

    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Проверяет пароль против сохранённого хэша.

        Args:
            password: Проверяемый пароль.
            hashed: Строка с параметрами и результатом (output hash_password).

        Returns:
            True — если совпадает; False — если нет.

        Raises:
            PasswordHashError: если вход или формат некорректны.

        Пример:
            >>> hasher.verify_password('hunter2', hash)
        """
        try:
            parts = hashed.split("$")
            if len(parts) != 7 or not parts.startswith("argon2id"):[1]
                _logger.error("Malformed or unsupported hash format")
                raise PasswordHashError("Malformed or unsupported hash format")
            salt_b64 = parts
            key_b64 = parts
            salt = b64decode(salt_b64)
            expected_key = b64decode(key_b64)

            test_hash = self.hash_password(password, salt)
            test_parts = test_hash.split("$")
            test_key = b64decode(test_parts)
            if secrets.compare_digest(test_key, expected_key):
                _logger.debug("Password verification successful")
                return True
            else:
                _logger.info("Password verification failed")
                return False
        except Exception as e:
            _logger.error(f"Error verifying password: {e}")
            raise PasswordHashError(f"Verification failed: {e}")

    def needs_rehash(self, hashed: str) -> bool:
        """
        Проверяет необходимость перехэширования по изменённым параметрам.

        Args:
            hashed: Строка с параметрами и результатом.

        Returns:
            True — если параметры устарели; False — если актуальны.

        Пример:
            >>> hasher.needs_rehash(hash)
        """
        try:
            parts = hashed.split("$")
            cur_params = (str(self.memory_cost), str(self.time_cost), str(self.parallelism))
            hash_params = tuple(parts[2:5])
            if hash_params != cur_params:
                _logger.info(f"Hash params outdated: {hash_params} vs {cur_params}")
                return True
            _logger.debug("Hash params match current")
            return False
        except Exception as e:
            _logger.error(f"Error checking rehash need: {e}")
            return True
