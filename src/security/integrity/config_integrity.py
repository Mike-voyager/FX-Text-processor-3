"""
Проверка целостности конфигурационных файлов.

ConfigIntegrityChecker проверяет Ed25519 подпись конфигурационных
файлов (.fxsconfig) для защиты от несанкционированных изменений.

Security:
    - Ed25519 для подписи (быстрая, безопасная)
    - SHA3-256 для хеша конфигурации
    - Offline верификация без сети

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Final, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.security.integrity.exceptions import ConfigSignatureError
from src.security.integrity.models import ConfigSignatureResult

LOG = logging.getLogger(__name__)

# Имя файла с публичным ключом верификации
PUBLIC_KEY_FILE: Final[str] = ".config-pubkey"

# Расширение подписанных конфигураций
SIGNED_CONFIG_EXTENSION: Final[str] = ".fxsconfig"


class ConfigTamperedError(ConfigSignatureError):
    """Конфиг был изменён без подписи."""

    def __init__(self, message: str, *, config_path: Optional[str] = None) -> None:
        super().__init__(
            message,
            config_path=config_path,
            signature_algorithm="Ed25519",
        )


class ConfigIntegrityChecker:
    """Проверка целостности конфигурационного файла.

    Использует Ed25519 для верификации подписи конфигурации.
    Публичный ключ верификации передаётся в конструкторе
    или загружается из переменной окружения.

    Attributes:
        _public_key: Публичный ключ для верификации
        _config_path: Путь к конфигурационному файлу

    Example:
        >>> checker = ConfigIntegrityChecker(Path("config.fxsconfig"))
        >>> result = checker.verify_config()
        >>> if result.valid:
        ...     print("Конфигурация валидна")
        ... else:
        ...     print(f"Ошибка: {result.details}")
    """

    __slots__ = ("_config_path", "_public_key")

    def __init__(
        self,
        config_path: Path,
        master_public_key: bytes | None = None,
    ) -> None:
        """Инициализация проверяющего конфигурацию.

        Args:
            config_path: Путь к конфигурационному файлу
            master_public_key: Публичный ключ для верификации (32 байта raw или DER)

        Raises:
            ConfigSignatureError: Некорректный публичный ключ
        """
        self._config_path = config_path
        self._public_key = self._load_public_key(master_public_key)

    def _load_public_key(self, key_data: Optional[bytes]) -> Optional[Ed25519PublicKey]:
        """Загрузка публичного ключа Ed25519.

        Args:
            key_data: Сырые байты ключа (32 байта) или None

        Returns:
            Ed25519PublicKey или None если ключ не предоставлен

        Raises:
            ConfigSignatureError: Некорректный формат ключа
        """
        if key_data is None:
            # Пробуем загрузить из переменной окружения
            import os

            env_key = os.environ.get("CONFIG_PUBLIC_KEY")
            if env_key:
                try:
                    key_data = bytes.fromhex(env_key.strip())
                    LOG.debug("Загружен публичный ключ из переменной окружения")
                except ValueError:
                    LOG.warning("Некорректный ключ в переменной CONFIG_PUBLIC_KEY")

        if key_data is None:
            return None

        try:
            # Ed25519 публичный ключ — 32 байта
            if len(key_data) == 32:
                return Ed25519PublicKey.from_public_bytes(key_data)
            # Пробуем как DER-encoded SubjectPublicKeyInfo
            return serialization.load_der_public_key(key_data)
        except Exception as e:
            raise ConfigSignatureError(
                f"Некорректный публичный ключ: {e}",
                signature_algorithm="Ed25519",
            ) from e

    def _load_config(self) -> dict:
        """Загрузка конфига с безопасной проверкой.

        Выполняет JSON decode и базовую проверку на malicious patterns.

        Returns:
            Словарь с данными конфигурации

        Raises:
            ConfigSignatureError: Ошибка чтения или валидации
        """
        if not self._config_path.exists():
            raise ConfigSignatureError(
                f"Конфигурационный файл не найден: {self._config_path}",
                config_path=str(self._config_path),
            )

        try:
            content = self._config_path.read_text(encoding="utf-8")
        except OSError as e:
            raise ConfigSignatureError(
                f"Ошибка чтения конфигурации: {e}",
                config_path=str(self._config_path),
            ) from e

        # Базовая проверка на malicious patterns
        if "__import__" in content or "eval(" in content or "exec(" in content:
            raise ConfigSignatureError(
                "Обнаружены потенциально опасные конструкции в конфигурации",
                config_path=str(self._config_path),
            )

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ConfigSignatureError(
                f"Ошибка парсинга JSON: {e}",
                config_path=str(self._config_path),
            ) from e

        # Проверяем структуру подписанного конфига
        if not isinstance(data, dict):
            raise ConfigSignatureError(
                "Конфигурация должна быть JSON объектом",
                config_path=str(self._config_path),
            )

        return data

    def _normalize_config(self, config_data: dict) -> str:
        """Нормализация конфигурации для подписи/проверки.

        Использует canonical JSON с сортировкой ключей.

        Args:
            config_data: Данные конфигурации

        Returns:
            Нормализованная JSON строка
        """
        return json.dumps(config_data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def sign_config(
        self,
        config_data: dict,
        private_key: bytes,
    ) -> bytes:
        """Подпись конфигурации Ed25519.

        Сериализует конфиг в JSON, добавляет timestamp,
        создаёт Ed25519 подпись.

        Args:
            config_data: Данные конфигурации для подписи
            private_key: Приватный ключ Ed25519 (32 байта raw или DER)

        Returns:
            Подпись конфигурации (64 байта)

        Raises:
            ConfigSignatureError: Ошибка подписи
        """
        # Добавляем timestamp в метаданные
        from datetime import datetime, timezone

        if "_metadata" not in config_data:
            config_data["_metadata"] = {}
        config_data["_metadata"]["signed_at"] = datetime.now(timezone.utc).isoformat()

        # Нормализуем JSON
        config_str = self._normalize_config(config_data)
        config_bytes = config_str.encode("utf-8")

        # Вычисляем SHA3-256 хеш
        config_hash = hashlib.sha3_256(config_bytes).digest()

        # Загружаем приватный ключ
        try:
            if len(private_key) == 32:
                # Raw private key
                signing_key = Ed25519PrivateKey.from_private_bytes(private_key)
            else:
                # Пробуем как DER
                signing_key = serialization.load_der_private_key(private_key, password=None)
                if not isinstance(signing_key, Ed25519PrivateKey):
                    raise ConfigSignatureError(
                        "Приватный ключ должен быть Ed25519",
                        signature_algorithm="Ed25519",
                    )
        except Exception as e:
            raise ConfigSignatureError(
                f"Некорректный приватный ключ: {e}",
                signature_algorithm="Ed25519",
            ) from e

        # Подписываем хеш конфигурации
        try:
            signature = signing_key.sign(config_hash)
            LOG.debug("Конфигурация подписана, размер подписи: %d байт", len(signature))
            return signature
        except Exception as e:
            raise ConfigSignatureError(
                f"Ошибка подписи: {e}",
                signature_algorithm="Ed25519",
            ) from e

    def verify_config(self) -> ConfigSignatureResult:
        """Проверка подписи конфигурации.

        Загружает config.fxsconfig, проверяет Ed25519 подпись.

        Returns:
            ConfigSignatureResult с результатом проверки
        """
        # Загружаем конфигурацию
        try:
            data = self._load_config()
        except ConfigSignatureError as e:
            return ConfigSignatureResult(
                valid=False,
                tampered=False,
                details=e.message,
                metadata={"config_path": str(self._config_path)},
            )

        # Проверяем наличие подписи
        if "signature" not in data:
            return ConfigSignatureResult(
                valid=False,
                tampered=False,
                details="Конфигурация не содержит подписи",
                metadata={"config_path": str(self._config_path)},
            )

        signature_hex = data.get("signature")
        if not signature_hex:
            return ConfigSignatureResult(
                valid=False,
                tampered=False,
                details="Подпись отсутствует",
                metadata={"config_path": str(self._config_path)},
            )

        # Извлекаем конфигурацию (без подписи, метаданных подписи и служебных полей)
        excluded_fields = ("signature", "public_key_hint", "algorithm")
        config_data = {k: v for k, v in data.items() if k not in excluded_fields}
        config_str = self._normalize_config(config_data)
        config_hash = hashlib.sha3_256(config_str.encode("utf-8")).digest()

        # Декодируем подпись
        try:
            signature = bytes.fromhex(signature_hex)
        except ValueError:
            return ConfigSignatureResult(
                valid=False,
                tampered=False,
                details="Некорректный формат подписи (ожидается hex)",
                metadata={"config_path": str(self._config_path)},
            )

        # Проверяем наличие публичного ключа
        if self._public_key is None:
            return ConfigSignatureResult(
                valid=False,
                tampered=False,
                details="Публичный ключ верификации не задан",
                signer_key_id=data.get("public_key_hint"),
                metadata={"config_path": str(self._config_path)},
            )

        # Верифицируем подпись
        try:
            self._public_key.verify(signature, config_hash)
            LOG.info("Подпись конфигурации верифицирована: %s", self._config_path)
            return ConfigSignatureResult(
                valid=True,
                tampered=False,
                details="Подпись конфигурации действительна",
                signer_key_id=data.get("public_key_hint"),
                metadata={
                    "config_path": str(self._config_path),
                    "signed_at": config_data.get("_metadata", {}).get("signed_at"),
                },
            )
        except InvalidSignature:
            LOG.error("Подпись конфигурации недействительна: %s", self._config_path)
            return ConfigSignatureResult(
                valid=False,
                tampered=True,
                details="Подпись конфигурации недействительна — данные были изменены",
                signer_key_id=data.get("public_key_hint"),
                metadata={"config_path": str(self._config_path)},
            )
        except Exception as e:
            LOG.error("Ошибка верификации подписи: %s", e)
            return ConfigSignatureResult(
                valid=False,
                tampered=False,
                details=f"Ошибка верификации: {e}",
                signer_key_id=data.get("public_key_hint"),
                metadata={"config_path": str(self._config_path)},
            )

    def create_signed_config(
        self,
        config_data: dict,
        private_key: bytes,
        output_path: Optional[Path] = None,
    ) -> Path:
        """Создание подписанного конфигурационного файла.

        Args:
            config_data: Данные конфигурации
            private_key: Приватный ключ Ed25519
            output_path: Путь для сохранения (опционально)

        Returns:
            Путь к созданному файлу

        Raises:
            ConfigSignatureError: Ошибка создания
        """
        import copy

        # Получаем публичный ключ для hint
        public_key_hint = None
        if self._public_key:
            public_key_bytes = self._public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            public_key_hint = public_key_bytes[:8].hex()

        # Создаём копию для подписи (sign_config модифицирует dict in-place)
        config_for_signing = copy.deepcopy(config_data)

        # Создаём подпись
        signature = self.sign_config(config_for_signing, private_key)

        # Формируем подписанный конфиг (используем уже модифицированную копию)
        signed_config = config_for_signing
        signed_config["signature"] = signature.hex()
        signed_config["public_key_hint"] = public_key_hint
        signed_config["algorithm"] = "Ed25519"

        # Сохраняем
        save_path = output_path or self._config_path
        save_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            save_path.write_text(
                json.dumps(signed_config, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            LOG.info("Подписанная конфигурация сохранена: %s", save_path)
            return save_path
        except OSError as e:
            raise ConfigSignatureError(
                f"Ошибка записи конфигурации: {e}",
                config_path=str(save_path),
            ) from e

    @property
    def config_path(self) -> Path:
        """Путь к конфигурационному файлу."""
        return self._config_path

    @property
    def has_public_key(self) -> bool:
        """Проверка наличия публичного ключа."""
        return self._public_key is not None

    def __repr__(self) -> str:
        return (
            f"ConfigIntegrityChecker("
            f"config_path={self._config_path!r}, "
            f"has_public_key={self._public_key is not None})"
        )


__all__: list[str] = [
    "ConfigIntegrityChecker",
    "ConfigTamperedError",
    "PUBLIC_KEY_FILE",
    "SIGNED_CONFIG_EXTENSION",
]

__version__ = "1.0.0"
__author__ = "FX Text Processor Team"
__date__ = "2026-03-23"
