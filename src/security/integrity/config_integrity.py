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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Final, Optional

from src.security.crypto.algorithms.signing import Ed25519Signer
from src.security.integrity.exceptions import ConfigSignatureError
from src.security.integrity.models import (
    IntegrityCheckResult,
    IntegrityCheckType,
)

LOG = logging.getLogger(__name__)

# Имя файла с публичным ключом верификации
PUBLIC_KEY_FILE: Final[str] = ".config-pubkey"

# Расширение подписанных конфигураций
SIGNED_CONFIG_EXTENSION: Final[str] = ".fxsconfig"


@dataclass(frozen=True)
class SignedConfig:
    """
    Подписанная конфигурация.

    Attributes:
        config_path: Путь к конфигурационному файлу
        signature_path: Путь к файлу подписи (опционально)
        content: Содержимое конфигурации (JSON)
        signature: Подпись (hex)
        public_key_hint: Подсказка о публичном ключе (первые 8 байт, hex)
    """

    config_path: Path
    signature_path: Optional[Path]
    content: str
    signature: Optional[str]
    public_key_hint: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация в словарь."""
        return {
            "config_path": str(self.config_path),
            "signature_path": str(self.signature_path) if self.signature_path else None,
            "content_hash": hashlib.sha3_256(self.content.encode()).hexdigest()[:16] + "...",
            "signature": self.signature[:16] + "..." if self.signature else None,
            "public_key_hint": self.public_key_hint,
        }


class ConfigIntegrityChecker:
    """
    Проверка подписи конфигурационных файлов.

    Использует Ed25519 для верификации подписи конфигурации.
    Публичный ключ верификации хранится рядом с приложением
    или встраивается при сборке.

    Attributes:
        verification_key: Публичный ключ для верификации (bytes)
        algorithm: Алгоритм подписи (Ed25519)

    Example:
        >>> checker = ConfigIntegrityChecker(public_key)
        >>> result = checker.check_config(Path("config.fxsconfig"))
        >>> if result.passed:
        ...     print("Конфигурация валидна")
        ... else:
        ...     print(f"Ошибка: {result.error_message}")
    """

    __slots__ = ("_verification_key", "_signer", "_public_key_path")

    def __init__(
        self,
        verification_key: Optional[bytes] = None,
        public_key_path: Optional[Path] = None,
    ) -> None:
        """
        Инициализация проверяющего конфигурацию.

        Args:
            verification_key: Публичный ключ Ed25519 для верификации.
                             Если None, загружается из файла или переменной.
            public_key_path: Путь к файлу с публичным ключом.
                           По умолчанию .config-pubkey рядом с приложением.
        """
        self._public_key_path = public_key_path
        self._verification_key = verification_key or self._load_public_key()
        self._signer = Ed25519Signer()

    def _load_public_key(self) -> Optional[bytes]:
        """
        Загрузка публичного ключа из источника.

        Приоритет:
        1. Переменная окружения CONFIG_PUBLIC_KEY (hex)
        2. Файл .config-pubkey
        3. Встроенный ключ (для PyInstaller)

        Returns:
            Публичный ключ (DER-encoded или raw) или None

        Note:
            Ключ может быть:
            - Raw Ed25519 публичный ключ (32 байта)
            - DER-encoded публичный ключ (44 байта для Ed25519)
        """
        import os
        import sys

        # 1. Переменная окружения
        env_key = os.environ.get("CONFIG_PUBLIC_KEY")
        if env_key:
            try:
                key_bytes = bytes.fromhex(env_key.strip())
                # Принимаем raw (32) или DER-encoded ключи
                if len(key_bytes) >= 32:
                    LOG.debug("Загружен ключ из переменной окружения")
                    return key_bytes
                else:
                    LOG.warning("Ключ в CONFIG_PUBLIC_KEY слишком короткий: %d байт", len(key_bytes))
            except ValueError:
                LOG.warning("Некорректный ключ в переменной CONFIG_PUBLIC_KEY")

        # 2. Файл с публичным ключом
        key_path = self._public_key_path or self._find_public_key_file()
        if key_path and key_path.exists():
            try:
                key_hex = key_path.read_text(encoding="utf-8").strip()
                key_bytes = bytes.fromhex(key_hex)
                # Принимаем raw (32) или DER-encoded ключи
                if len(key_bytes) >= 32:
                    LOG.debug("Загружен ключ из файла: %s", key_path)
                    return key_bytes
                else:
                    LOG.warning("Ключ в файле слишком короткий: %d байт", len(key_bytes))
            except (ValueError, OSError) as e:
                LOG.warning("Ошибка чтения файла ключа: %s", e)

        # 3. Встроенный ключ (PyInstaller)
        if getattr(sys, "frozen", False):
            builtin_key = getattr(sys, "_MEI_CONFIG_PUBKEY", None)
            if builtin_key:
                try:
                    key_bytes = bytes.fromhex(builtin_key)
                    if len(key_bytes) >= 32:
                        LOG.debug("Загружен встроенный ключ")
                        return key_bytes
                except ValueError:
                    pass

        return None

    def _find_public_key_file(self) -> Optional[Path]:
        """Поиск файла с публичным ключом."""
        from pathlib import Path
        import sys

        # Рядом с исполняемым файлом
        if getattr(sys, "frozen", False):
            exe_dir = Path(sys.executable).parent
            key_file = exe_dir / PUBLIC_KEY_FILE
            if key_file.exists():
                return key_file

        # В текущей директории
        key_file = Path.cwd() / PUBLIC_KEY_FILE
        if key_file.exists():
            return key_file

        # В директории скрипта
        key_file = Path(__file__).parent.parent.parent.parent / PUBLIC_KEY_FILE
        if key_file.exists():
            return key_file

        return None

    def compute_config_hash(self, content: str) -> bytes:
        """
        Вычисление SHA3-256 хеша содержимого конфигурации.

        Args:
            content: Содержимое конфигурации (JSON строка)

        Returns:
            Хеш (32 байта)
        """
        return hashlib.sha3_256(content.encode("utf-8")).digest()

    def verify_signature(
        self,
        content: str,
        signature: bytes,
    ) -> bool:
        """
        Верификация подписи конфигурации.

        Args:
            content: Содержимое конфигурации
            signature: Подпись (64 байта для Ed25519)

        Returns:
            True если подпись валидна

        Raises:
            ConfigSignatureError: Публичный ключ не задан
        """
        if self._verification_key is None:
            raise ConfigSignatureError(
                "Публичный ключ верификации не задан",
                signature_algorithm="Ed25519",
            )

        # Вычисляем хеш содержимого
        content_hash = self.compute_config_hash(content)

        # Верифицируем подпись
        return self._signer.verify(
            public_key=self._verification_key,
            message=content_hash,
            signature=signature,
        )

    def load_signed_config(self, config_path: Path) -> SignedConfig:
        """
        Загрузка подписанной конфигурации.

        Формат файла:
        - JSON с полями: config, signature, public_key_hint

        Args:
            config_path: Путь к конфигурационному файлу

        Returns:
            SignedConfig с содержимым и подписью

        Raises:
            ConfigSignatureError: Ошибка чтения или парсинга
        """
        if not config_path.exists():
            raise ConfigSignatureError(
                f"Конфигурационный файл не найден: {config_path}",
                config_path=str(config_path),
            )

        try:
            content = config_path.read_text(encoding="utf-8")
        except OSError as e:
            raise ConfigSignatureError(
                f"Ошибка чтения конфигурации: {e}",
                config_path=str(config_path),
            ) from e

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ConfigSignatureError(
                f"Ошибка парсинга JSON: {e}",
                config_path=str(config_path),
            ) from e

        # Проверяем структуру
        if "config" not in data:
            raise ConfigSignatureError(
                "Отсутствует поле 'config' в конфигурации",
                config_path=str(config_path),
            )

        signature_hex = data.get("signature")
        signature = bytes.fromhex(signature_hex) if signature_hex else None

        # Извлекаем конфиг
        config_content = json.dumps(data["config"], ensure_ascii=False, sort_keys=True)

        return SignedConfig(
            config_path=config_path,
            signature_path=None,  # Встроенная подпись
            content=config_content,
            signature=signature_hex,
            public_key_hint=data.get("public_key_hint"),
        )

    def check_config(
        self,
        config_path: Path,
        *,
        verify_signature: bool = True,
    ) -> IntegrityCheckResult:
        """
        Проверка целостности конфигурационного файла.

        Args:
            config_path: Путь к конфигурационному файлу
            verify_signature: Проверять ли подпись (по умолчанию True)

        Returns:
            IntegrityCheckResult с результатом проверки

        Example:
            >>> result = checker.check_config(Path("app.fxsconfig"))
            >>> result.passed
            True
        """
        # Загружаем конфигурацию
        try:
            signed_config = self.load_signed_config(config_path)
        except ConfigSignatureError as e:
            return IntegrityCheckResult(
                check_type=IntegrityCheckType.CONFIG_FILE,
                passed=False,
                file_path=str(config_path),
                algorithm="Ed25519",
                error_message=e.message,
            )

        # Проверяем наличие подписи
        if verify_signature and not signed_config.signature:
            return IntegrityCheckResult(
                check_type=IntegrityCheckType.CONFIG_FILE,
                passed=False,
                file_path=str(config_path),
                algorithm="Ed25519",
                error_message="Конфигурация не подписана",
            )

        # Верифицируем подпись
        if verify_signature:
            if self._verification_key is None:
                return IntegrityCheckResult(
                    check_type=IntegrityCheckType.CONFIG_FILE,
                    passed=False,
                    file_path=str(config_path),
                    algorithm="Ed25519",
                    error_message="Публичный ключ верификации не задан",
                )

            try:
                signature_bytes = bytes.fromhex(signed_config.signature)  # type: ignore[arg-type]
                is_valid = self.verify_signature(signed_config.content, signature_bytes)
            except (ValueError, ConfigSignatureError) as e:
                return IntegrityCheckResult(
                    check_type=IntegrityCheckType.CONFIG_FILE,
                    passed=False,
                    file_path=str(config_path),
                    algorithm="Ed25519",
                    error_message=f"Ошибка верификации: {e}",
                )

            if not is_valid:
                LOG.error(
                    "Подпись конфигурации недействительна: %s",
                    config_path,
                )
                return IntegrityCheckResult(
                    check_type=IntegrityCheckType.CONFIG_FILE,
                    passed=False,
                    file_path=str(config_path),
                    algorithm="Ed25519",
                    signature_valid=False,
                    error_message="Подпись конфигурации недействительна",
                )

        # Успешная проверка
        content_hash = self.compute_config_hash(signed_config.content).hex()
        LOG.info("Конфигурация валидна: %s", config_path)

        return IntegrityCheckResult(
            check_type=IntegrityCheckType.CONFIG_FILE,
            passed=True,
            file_path=str(config_path),
            actual_hash=content_hash,
            signature_valid=True if verify_signature else None,
            algorithm="Ed25519",
        )

    def sign_config(
        self,
        config_path: Path,
        private_key: bytes,
        output_path: Optional[Path] = None,
    ) -> Path:
        """
        Подписание конфигурационного файла.

        Создаёт подписанный файл с полями config, signature, public_key_hint.

        Args:
            config_path: Путь к исходной конфигурации (JSON)
            private_key: Приватный ключ Ed25519 (DER-encoded)
            output_path: Путь для сохранения подписанной конфигурации.
                        По умолчанию config_path с расширением .fxsconfig

        Returns:
            Путь к подписанному файлу

        Raises:
            ConfigSignatureError: Ошибка чтения или подписи

        Note:
            Метод предназначен для использования при сборке,
            не в runtime приложении.
        """
        if not config_path.exists():
            raise ConfigSignatureError(
                f"Конфигурационный файл не найден: {config_path}",
                config_path=str(config_path),
            )

        try:
            content = config_path.read_text(encoding="utf-8")
            config_data = json.loads(content)
        except (OSError, json.JSONDecodeError) as e:
            raise ConfigSignatureError(
                f"Ошибка чтения конфигурации: {e}",
                config_path=str(config_path),
            ) from e

        # Нормализуем JSON
        config_str = json.dumps(config_data, ensure_ascii=False, sort_keys=True)
        config_hash = self.compute_config_hash(config_str)

        # Подписываем
        signature = self._signer.sign(private_key, config_hash)

        # Извлекаем публичный ключ из пары
        # Примечание: generate_keypair возвращает (private_der, public_der)
        # Для подписи мы используем приватный ключ
        # Публичный ключ берём из self._verification_key если он есть
        public_key_hint = None
        if self._verification_key:
            # Берём первые 8 байт публичного ключа
            public_key_hint = self._verification_key[:8].hex()

        # Формируем подписанный JSON
        signed_data = {
            "config": config_data,
            "signature": signature.hex(),
            "public_key_hint": public_key_hint,
            "algorithm": "Ed25519",
        }

        # Сохраняем
        save_path = output_path or config_path.with_suffix(SIGNED_CONFIG_EXTENSION)
        try:
            save_path.write_text(
                json.dumps(signed_data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            LOG.info("Конфигурация подписана: %s", save_path)
            return save_path
        except OSError as e:
            raise ConfigSignatureError(
                f"Ошибка записи подписанной конфигурации: {e}",
                config_path=str(save_path),
            ) from e

    @property
    def has_verification_key(self) -> bool:
        """Проверка наличия публичного ключа."""
        return self._verification_key is not None

    @property
    def verification_key_hint(self) -> Optional[str]:
        """Подсказка о публичном ключе (первые 8 байт, hex)."""
        if self._verification_key:
            return self._verification_key[:8].hex()
        return None

    def __repr__(self) -> str:
        return (
            f"ConfigIntegrityChecker("
            f"has_key={self._verification_key is not None}, "
            f"algorithm=Ed25519)"
        )


__all__: list[str] = [
    "ConfigIntegrityChecker",
    "SignedConfig",
    "PUBLIC_KEY_FILE",
    "SIGNED_CONFIG_EXTENSION",
]

__version__ = "1.0.0"
__author__ = "Mike Voyager"
__date__ = "2026-03-23"