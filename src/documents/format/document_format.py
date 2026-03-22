"""Сериализация и десериализация документов.

Формат .fxsd (FX Super Document):
    - JSON с метаданными и содержимым документа
    - Незашифрованный, текстовый

Формат .fxsd.enc (FX Super Document Encrypted):
    - Binary с заголовком и зашифрованным payload
    - Структура: Magic(4) + Version(2) + Algorithm(2) + Salt(32) +
                Nonce(12-16) + PayloadLength(8) + EncryptedPayload + Tag(16)

Example:
    >>> from src.documents.format.document_format import DocumentFormat
    >>> from src.model.document import Document
    >>> doc = Document(title="Test")
    >>> fmt = DocumentFormat()
    >>> fmt.save(doc, Path("test.fxsd"))
    >>> loaded = fmt.load(Path("test.fxsd"))
"""

from __future__ import annotations

import gzip
import json
import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from src.model.document import Document
    from src.security.crypto.service.crypto_service import CryptoService

from src.security.crypto.service.crypto_service import EncryptedDocument

logger: Final = logging.getLogger(__name__)

# Magic bytes для зашифрованных файлов
_MAGIC_FXSD_ENC: Final[bytes] = b"FXSD"
_CURRENT_FORMAT_VERSION: Final[int] = 1

# Размеры полей заголовка
_MAGIC_SIZE: Final[int] = 4
_VERSION_SIZE: Final[int] = 2
_ALGORITHM_SIZE: Final[int] = 2
_SALT_SIZE: Final[int] = 32
_NONCE_SIZE: Final[int] = 12
_TAG_SIZE: Final[int] = 16
_PAYLOAD_LENGTH_SIZE: Final[int] = 8

_HEADER_SIZE: Final[int] = (
    _MAGIC_SIZE + _VERSION_SIZE + _ALGORITHM_SIZE + _SALT_SIZE + _NONCE_SIZE + _PAYLOAD_LENGTH_SIZE
)


@dataclass(frozen=True)
class DocumentFormatHeader:
    """Заголовок зашифрованного документа.

    Attributes:
        magic: Magic bytes (b"FXSD")
        version: Версия формата (uint16)
        algorithm_id: ID алгоритма шифрования (uint16)
        salt: Salt для KDF (32 bytes)
        nonce: Nonce для шифрования (12 bytes)
        payload_length: Длина зашифрованного payload (uint64)

    Example:
        >>> header = DocumentFormatHeader(
        ...     magic=b"FXSD",
        ...     version=1,
        ...     algorithm_id=1,  # AES-256-GCM
        ...     salt=os.urandom(32),
        ...     nonce=os.urandom(12),
        ...     payload_length=1024,
        ... )
    """

    magic: bytes
    version: int
    algorithm_id: int
    salt: bytes
    nonce: bytes
    payload_length: int

    def __post_init__(self) -> None:
        """Валидация заголовка."""
        if self.magic != _MAGIC_FXSD_ENC:
            raise ValueError(f"Invalid magic: {self.magic!r}, expected {_MAGIC_FXSD_ENC!r}")
        if self.version < 1:
            raise ValueError(f"Invalid version: {self.version}")
        if self.algorithm_id < 1:
            raise ValueError(f"Invalid algorithm_id: {self.algorithm_id}")
        if len(self.salt) != _SALT_SIZE:
            raise ValueError(f"Invalid salt size: {len(self.salt)}, expected {_SALT_SIZE}")
        if len(self.nonce) != _NONCE_SIZE:
            raise ValueError(f"Invalid nonce size: {len(self.nonce)}, expected {_NONCE_SIZE}")
        if self.payload_length < 0:
            raise ValueError(f"Invalid payload_length: {self.payload_length}")

    def to_bytes(self) -> bytes:
        """Сериализует заголовок в bytes.

        Returns:
            Байтовое представление заголовка
        """
        return struct.pack(
            f"<{_MAGIC_SIZE}sH H {_SALT_SIZE}s {_NONCE_SIZE}s Q",
            self.magic,
            self.version,
            self.algorithm_id,
            self.salt,
            self.nonce,
            self.payload_length,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "DocumentFormatHeader":
        """Десериализует заголовок из bytes.

        Args:
            data: Байтовое представление заголовка

        Returns:
            Экземпляр DocumentFormatHeader

        Raises:
            ValueError: Если данные некорректны
        """
        if len(data) < _HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} bytes, expected {_HEADER_SIZE}")

        magic = data[0:_MAGIC_SIZE]
        version = struct.unpack("<H", data[_MAGIC_SIZE : _MAGIC_SIZE + _VERSION_SIZE])[0]
        algorithm_id = struct.unpack(
            "<H", data[_MAGIC_SIZE + _VERSION_SIZE : _MAGIC_SIZE + _VERSION_SIZE + _ALGORITHM_SIZE]
        )[0]
        salt_start = _MAGIC_SIZE + _VERSION_SIZE + _ALGORITHM_SIZE
        salt = data[salt_start : salt_start + _SALT_SIZE]
        nonce_start = salt_start + _SALT_SIZE
        nonce = data[nonce_start : nonce_start + _NONCE_SIZE]
        length_start = nonce_start + _NONCE_SIZE
        payload_length = struct.unpack(
            "<Q", data[length_start : length_start + _PAYLOAD_LENGTH_SIZE]
        )[0]

        return cls(
            magic=magic,
            version=version,
            algorithm_id=algorithm_id,
            salt=salt,
            nonce=nonce,
            payload_length=payload_length,
        )

    @property
    def total_header_size(self) -> int:
        """Возвращает общий размер заголовка."""
        return _HEADER_SIZE


class DocumentFormat:
    """Сериализация и десериализация документов.

    Поддерживает два формата:
    - .fxsd: JSON (незашифрованный)
    - .fxsd.enc: Binary (зашифрованный AES-256-GCM)

    Example:
        >>> doc = Document(title="Invoice #123")
        >>> fmt = DocumentFormat()

        # Сохранение без шифрования
        >>> fmt.save(doc, Path("document.fxsd"))

        # Сохранение с шифрованием
        >>> fmt.save(doc, Path("document.fxsd.enc"), encrypt=True, crypto=crypto_service)

        # Загрузка (автоопределение формата)
        >>> loaded = fmt.load(Path("document.fxsd"), crypto=crypto_service)
    """

    def __init__(self, crypto: "CryptoService | None" = None) -> None:
        """Инициализирует формат документа.

        Args:
            crypto: Криптографический сервис (опционально)
        """
        self._crypto = crypto
        self._logger = logging.getLogger(__name__)

    def save(
        self,
        document: "Document",
        path: Path,
        *,
        encrypt: bool = False,
        crypto: "CryptoService | None" = None,
        key: bytes | None = None,
    ) -> bytes | None:
        """Сохраняет документ в файл.

        Args:
            document: Документ для сохранения
            path: Путь к файлу
            encrypt: Шифровать ли файл (требует crypto)
            crypto: Криптографический сервис (обязателен если encrypt=True)
            key: Ключ шифрования (опционально, если None — генерируется новый)

        Returns:
            Ключ шифрования (если encrypt=True и key=None), иначе None.
            Ключ необходим для расшифровки документа.

        Raises:
            ValueError: Если encrypt=True но crypto не предоставлен
            IOError: При ошибке записи файла

        Security:
            КРИТИЧЕСКИ: Возвращаемый ключ должен быть сохранён пользователем.
            Без ключа зашифрованный документ невозможно расшифровать.
        """
        if encrypt and crypto is None:
            raise ValueError("Crypto service required for encrypted save")

        # Сериализуем документ
        data = self._serialize(document)

        if encrypt:
            # crypto гарантированно не None после проверки выше
            assert crypto is not None
            generated_key = self._save_encrypted(data, path, crypto, key)
            self._logger.debug(f"Document saved to {path} (encrypted)")
            return generated_key
        else:
            self._save_plain(data, path)
            self._logger.debug(f"Document saved to {path}")
            return None

    def load(
        self,
        path: Path,
        *,
        crypto: "CryptoService | None" = None,
        key: bytes | None = None,
    ) -> "Document":
        """Загружает документ из файла.

        Автоматически определяет формат по расширению и содержимому.

        Args:
            path: Путь к файлу
            crypto: Криптографический сервис (обязателен для .fxsd.enc)
            key: Ключ расшифровки (обязателен для .fxsd.enc)

        Returns:
            Загруженный документ

        Raises:
            ValueError: Если файл зашифрован но crypto/key не предоставлен
            IOError: При ошибке чтения файла
            FormatError: Если формат файла некорректен
        """
        if not path.exists():
            raise FileNotFoundError(f"Document file not found: {path}")

        # Определяем формат по расширению
        is_encrypted = path.suffix == ".enc" or path.name.endswith(".fxsd.enc")

        if is_encrypted:
            if crypto is None:
                raise ValueError("Crypto service required for encrypted documents")
            if key is None:
                raise ValueError("Encryption key required for encrypted documents")
            data = self._load_encrypted(path, crypto, key)
        else:
            data = self._load_plain(path)

        document = self._deserialize(data)
        self._logger.debug(f"Document loaded from {path}")
        return document

    def _serialize(self, document: "Document") -> bytes:
        """Сериализует документ в bytes.

        Args:
            document: Документ для сериализации

        Returns:
            JSON bytes
        """
        data: dict[str, Any] = {
            "format_version": "1.0",
            "generator": "FXTextProcessor/3.0",
            "document": document.to_dict(),
        }
        return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")

    def _deserialize(self, data: bytes) -> "Document":
        """Десериализует документ из bytes.

        Args:
            data: JSON bytes

        Returns:
            Документ
        """
        from src.model.document import Document  # noqa: F401

        json_data = json.loads(data.decode("utf-8"))

        # Проверяем версию
        format_version = json_data.get("format_version", "1.0")
        if format_version != "1.0":
            # В будущем здесь будет миграция
            self._logger.warning(f"Document format version {format_version}, expected 1.0")

        return Document.from_dict(json_data["document"])

    def _save_plain(self, data: bytes, path: Path) -> None:
        """Сохраняет незашифрованные данные."""
        path.write_bytes(data)

    def _load_plain(self, path: Path) -> bytes:
        """Загружает незашифрованные данные."""
        return path.read_bytes()

    def _save_encrypted(
        self,
        data: bytes,
        path: Path,
        crypto: "CryptoService",
        key: bytes | None = None,
    ) -> bytes:
        """Сохраняет зашифрованные данные.

        Args:
            data: Исходные данные (JSON)
            path: Путь к файлу
            crypto: Криптографический сервис
            key: Ключ шифрования (опционально, если None — генерируется новый)

        Returns:
            Использованный ключ шифрования. КРИТИЧЕСКИ: ключ должен быть
            сохранён вызывающим кодом для последующей расшифровки.

        Security:
            Ключ должен быть безопасно сохранён пользователем.
            Потеря ключа означает невозможность расшифровки документа.
        """
        import os

        # Сжимаем данные
        compressed = gzip.compress(data, compresslevel=9)

        # Генерируем или используем переданный ключ
        if key is None:
            key = crypto.generate_symmetric_key()

        # Генерируем параметры шифрования
        salt = os.urandom(_SALT_SIZE)

        # Шифруем через crypto service
        encrypted: EncryptedDocument = crypto.encrypt_document(compressed, key)

        # Формируем заголовок
        header = DocumentFormatHeader(
            magic=_MAGIC_FXSD_ENC,
            version=_CURRENT_FORMAT_VERSION,
            algorithm_id=1,  # AES-256-GCM
            salt=salt,
            nonce=encrypted.nonce,
            payload_length=len(encrypted.ciphertext),
        )

        # Записываем файл
        with open(path, "wb") as f:
            f.write(header.to_bytes())
            f.write(encrypted.ciphertext)

        return key

    def _load_encrypted(
        self,
        path: Path,
        crypto: "CryptoService",
        key: bytes | None = None,
    ) -> bytes:
        """Загружает и расшифровывает данные.

        Args:
            path: Путь к файлу
            crypto: Криптографический сервис
            key: Ключ расшифровки (опционально, если None — требуется keystore)

        Returns:
            Расшифрованные JSON bytes

        Raises:
            ValueError: Если ключ не предоставлен и keystore не настроен
        """
        data = path.read_bytes()

        if len(data) < _HEADER_SIZE:
            raise ValueError(f"File too short: {len(data)} bytes")

        # Читаем заголовок
        header = DocumentFormatHeader.from_bytes(data[:_HEADER_SIZE])
        encrypted_data = data[_HEADER_SIZE:]

        if len(encrypted_data) != header.payload_length:
            raise ValueError(
                f"Payload size mismatch: {len(encrypted_data)} vs {header.payload_length}"
            )

        # Для расшифровки нужен ключ
        # TODO: Интеграция с keystore для получения ключа на основе salt
        if key is None:
            raise ValueError(
                "Encryption key required for decryption. "
                "Provide key parameter or configure keystore."
            )

        # Создаём EncryptedDocument для расшифровки
        encrypted_doc = EncryptedDocument(
            nonce=header.nonce,
            ciphertext=encrypted_data,
            algorithm_id="aes-256-gcm",  # AES-256-GCM
        )

        # Расшифровываем
        decrypted = crypto.decrypt_document(encrypted_doc, key)

        # Распаковываем gzip
        return gzip.decompress(decrypted)

    def get_format_info(self, path: Path) -> dict[str, Any]:
        """Возвращает информацию о формате файла.

        Args:
            path: Путь к файлу

        Returns:
            Словарь с информацией о формате
        """
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        is_encrypted = path.suffix == ".enc" or path.name.endswith(".fxsd.enc")

        if is_encrypted:
            data = path.read_bytes()
            if len(data) >= _HEADER_SIZE:
                try:
                    header = DocumentFormatHeader.from_bytes(data[:_HEADER_SIZE])
                    return {
                        "format": "encrypted",
                        "version": header.version,
                        "algorithm_id": header.algorithm_id,
                        "payload_size": header.payload_length,
                        "header_size": _HEADER_SIZE,
                    }
                except ValueError:
                    pass
            return {"format": "unknown_encrypted"}
        else:
            # Пробуем прочитать как JSON
            try:
                content = json.loads(path.read_bytes().decode("utf-8"))
                return {
                    "format": "plain",
                    "version": content.get("format_version", "unknown"),
                    "generator": content.get("generator", "unknown"),
                }
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {"format": "unknown_plain"}

    def is_encrypted_file(self, path: Path) -> bool:
        """Проверяет, является ли файл зашифрованным.

        Args:
            path: Путь к файлу

        Returns:
            True если файл зашифрован
        """
        if not path.exists():
            return False

        # Проверяем расширение
        if path.suffix == ".enc" or path.name.endswith(".fxsd.enc"):
            return True

        # Проверяем magic bytes
        try:
            with open(path, "rb") as f:
                magic = f.read(_MAGIC_SIZE)
            return magic == _MAGIC_FXSD_ENC
        except IOError:
            return False


class FormatError(Exception):
    """Ошибка формата документа."""

    pass


__all__ = [
    "DocumentFormat",
    "DocumentFormatHeader",
    "FormatError",
]
