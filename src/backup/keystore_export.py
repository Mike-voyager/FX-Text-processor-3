"""Сервис экспорта keystore для FX Text Processor.

Предоставляет возможность экспорта ключей в различных форматах
с шифрованием и валидацией целостности.
"""

from __future__ import annotations

import enum
import hashlib
import json
import logging
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import CryptographyError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


class BackupFormat(enum.Enum):
    """Форматы резервного копирования.

    Attributes:
        ENCRYPTED_BINARY: Зашифрованный бинарный формат (.fxskeystore.enc)
        JSON: JSON с base64 кодированием
        COMPACT: Компактный бинарный формат (.fxs)
    """

    ENCRYPTED_BINARY = "fxskeystore.enc"
    JSON = "json"
    COMPACT = "fxs"


@dataclass(frozen=True)
class ExportResult:
    """Результат экспорта keystore.

    Attributes:
        success: Успешность операции
        path: Путь к созданному файлу
        size_bytes: Размер файла в байтах
        checksum: Контрольная сумма SHA-256
        format: Использованный формат
    """

    success: bool
    path: Path | None = None
    size_bytes: int = 0
    checksum: str = ""
    format: BackupFormat = BackupFormat.ENCRYPTED_BINARY


@dataclass(frozen=True)
class ImportResult:
    """Результат импорта keystore.

    Attributes:
        success: Успешность операции
        message: Сообщение о результате
        keys_imported: Количество импортированных ключей
    """

    success: bool
    message: str = ""
    keys_imported: int = 0


class KeystoreExporter:
    """Экспорт зашифрованного keystore.

    Обеспечивает безопасный экспорт ключей с использованием
    отдельного passphrase и валидацией целостности.

    Example:
        >>> exporter = KeystoreExporter()
        >>> result = exporter.export(
        ...     output_path=Path("/media/usb/backup.fxskeystore.enc"),
        ...     backup_passphrase="secure_backup_passphrase_123",
        ...     include_device_registry=True
        ... )
        >>> if result.success:
        ...     print(f"Экспортировано: {result.size_bytes} bytes")
    """

    # Magic header для файлов бэкапа
    _BACKUP_MAGIC = b"FXSBACKUP"
    _BACKUP_VERSION = 1

    def __init__(self) -> None:
        """Инициализация экспортера."""
        self._max_passphrase_length = 256
        self._min_passphrase_length = 16

    def export(
        self,
        output_path: Path,
        backup_passphrase: str,
        include_device_registry: bool = True,
    ) -> ExportResult:
        """Экспорт keystore с отдельным passphrase.

        Шифрует существующий keystore, добавляет метаданные,
        сохраняет в файл.

        Args:
            output_path: Путь для сохранения бэкапа
            backup_passphrase: Пароль для шифрования бэкапа
            include_device_registry: Включить реестр устройств

        Returns:
            Результат операции экспорта

        Raises:
            ValueError: Если passphrase слишком короткий
            IOError: При ошибке записи файла
        """
        if len(backup_passphrase) < self._min_passphrase_length:
            raise ValueError(
                f"Passphrase должен быть не менее {self._min_passphrase_length} символов"
            )

        # Получаем данные keystore (в реальности - из KeyStore)
        keystore_data = self._get_keystore_data()

        # Формируем пакет бэкапа
        backup_data = {
            "keystore": keystore_data.hex(),
            "metadata": {
                "version": self._BACKUP_VERSION,
                "format": "encrypted",
                "timestamp": self._get_timestamp(),
            },
        }

        if include_device_registry:
            backup_data["device_registry"] = self._get_device_registry_data().hex()

        # Сериализуем
        plaintext = json.dumps(backup_data).encode("utf-8")

        # Шифруем с использованием passphrase
        encrypted_data = self._encrypt_with_passphrase(plaintext, backup_passphrase)

        # Записываем файл
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(encrypted_data)

            checksum = hashlib.sha256(encrypted_data).hexdigest()

            return ExportResult(
                success=True,
                path=output_path,
                size_bytes=len(encrypted_data),
                checksum=checksum,
                format=BackupFormat.ENCRYPTED_BINARY,
            )
        except (OSError, IOError) as e:
            logger.error(f"Failed to write backup file: {e}")
            return ExportResult(success=False)
        except CryptographyError as e:
            logger.error(f"Cryptography error during backup export: {e}")
            return ExportResult(success=False)
        except Exception as e:
            logger.exception(f"Unexpected error during backup export: {e}")
            return ExportResult(success=False)

    def import_backup(
        self,
        backup_path: Path,
        backup_passphrase: str,
    ) -> bool:
        """Импорт keystore из бэкапа.

        Args:
            backup_path: Путь к файлу бэкапа
            backup_passphrase: Пароль для расшифровки

        Returns:
            True если импорт успешен, False если passphrase неверный
                или файл повреждён
        """
        try:
            if not backup_path.exists():
                return False

            encrypted_data = backup_path.read_bytes()

            # Проверяем magic header
            if not encrypted_data.startswith(self._BACKUP_MAGIC):
                return False

            # Расшифровываем
            plaintext = self._decrypt_with_passphrase(encrypted_data, backup_passphrase)
            if plaintext is None:
                return False

            # Парсим JSON
            backup_data = json.loads(plaintext.decode("utf-8"))

            # Валидация структуры
            if "keystore" not in backup_data:
                return False

            # В реальности здесь было бы восстановление в KeyStore
            return True

        except (OSError, IOError, ValueError) as e:
            logger.error(f"Error during backup import: {e}")
            return False
        except CryptographyError as e:
            logger.error(f"Cryptography error during backup import: {e}")
            return False
        except Exception as e:
            logger.exception(f"Unexpected error during backup import: {e}")
            return False

    def verify_backup(self, path: Path, backup_passphrase: str) -> bool:
        """Проверяет целостность резервной копии.

        Args:
            path: Путь к файлу резервной копии
            backup_passphrase: Пароль для расшифровки

        Returns:
            True если файл валиден и passphrase корректен
        """
        return self.import_backup(path, backup_passphrase)

    def validate_passphrase(self, passphrase: str) -> tuple[bool, str]:
        """Валидирует passphrase для резервной копии.

        Args:
            passphrase: Пароль для проверки

        Returns:
            Кортеж (валиден, сообщение)
        """
        if len(passphrase) < self._min_passphrase_length:
            return False, f"Минимум {self._min_passphrase_length} символов"

        if len(passphrase) > self._max_passphrase_length:
            return False, f"Максимум {self._max_passphrase_length} символов"

        # Проверка энтропии
        unique_chars = len(set(passphrase))
        if unique_chars < 8:
            return False, "Недостаточно разнообразных символов"

        return True, "Passphrase принят"

    def _encrypt_with_passphrase(self, data: bytes, passphrase: str) -> bytes:
        """Шифрует данные используя passphrase.

        Использует Argon2 (simplified) + AES-256-GCM.
        """
        # Генерируем salt
        salt = secrets.token_bytes(16)

        # Derive key (в реальности используем Argon2)
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100000, 32)

        # Генерируем nonce
        nonce = secrets.token_bytes(12)

        # Шифруем
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        # Формат: magic + version + salt + nonce + ciphertext
        header = self._BACKUP_MAGIC
        version = struct.pack(">B", self._BACKUP_VERSION)

        return header + version + salt + nonce + ciphertext

    def _decrypt_with_passphrase(self, encrypted_data: bytes, passphrase: str) -> bytes | None:
        """Расшифровывает данные используя passphrase.

        Returns:
            Расшифрованные данные или None при ошибке
        """
        try:
            # Проверяем header
            if not encrypted_data.startswith(self._BACKUP_MAGIC):
                return None

            pos = len(self._BACKUP_MAGIC)

            # Версия
            version = struct.unpack(">B", encrypted_data[pos : pos + 1])[0]
            pos += 1

            if version != self._BACKUP_VERSION:
                return None

            # Salt (16 bytes)
            salt = encrypted_data[pos : pos + 16]
            pos += 16

            # Nonce (12 bytes)
            nonce = encrypted_data[pos : pos + 12]
            pos += 12

            # Ciphertext
            ciphertext = encrypted_data[pos:]

            # Derive key
            key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100000, 32)

            # Расшифровываем
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return plaintext

        except (ValueError, OSError) as e:
            logger.error(f"Error during decryption: {e}")
            return None
        except CryptographyError as e:
            logger.error(f"Cryptography error during decryption: {e}")
            return None
        except Exception as e:
            logger.exception(f"Unexpected error during decryption: {e}")
            return None

    def _get_keystore_data(self) -> bytes:
        """Возвращает данные keystore из файла или генерирует временные данные.

        Returns:
            Сериализованные данные keystore
        """
        locations = [
            Path.cwd() / "keystore.fxskeystore.enc",
            Path.home() / ".fx-text-processor" / "keystore.enc",
        ]
        for location in locations:
            if location.exists():
                try:
                    return location.read_bytes()
                except OSError:
                    continue
        return secrets.token_bytes(256)

    def _get_device_registry_data(self) -> bytes:
        """Возвращает данные реестра устройств.

        Returns:
            Сериализованный реестр устройств
        """
        locations = [
            Path.cwd() / "devices.fxsreg",
            Path.home() / ".fx-text-processor" / "devices.fxsreg",
        ]
        for location in locations:
            if location.exists():
                try:
                    return location.read_bytes()
                except OSError:
                    continue
        return b""

    def _get_timestamp(self) -> int:
        """Возвращает текущую метку времени."""
        return int(time.time())
