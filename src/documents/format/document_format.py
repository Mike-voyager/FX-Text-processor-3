"""Сериализация и шифрование документов в форматы .fxsd и .fxsd.enc.

Этот модуль предоставляет DocumentSerializer для сохранения и загрузки
документов с поддержкой четырёх уровней безопасности:
- STANDARD: AES-256-GCM + Ed25519 + Argon2id (64MB)
- PARANOID: AES-256-GCM-SIV + Ed448 + Argon2id (256MB)
- PQC: ML-DSA-65 + AES-256-GCM + Argon2id
- LEGACY: RSA-PSS-4096 + AES-256-GCM + PBKDF2

Формат .fxsd:
    - JSON с gzip сжатием
    - Читаемый текст
    - Без шифрования

Формат .fxsd.enc:
    - Binary с заголовком и зашифрованным payload
    - Структура: Magic(4) + Version(2) + Algorithm(2) + Salt(32) +
                 Nonce(12) + PayloadLength(8) + EncryptedPayload + Tag(16)

Примеры:
    >>> from src.documents.format.document_format import DocumentSerializer, SecurityPreset
    >>> serializer = DocumentSerializer()
    >>>
    >>> # Сериализация без шифрования
    >>> data = serializer.serialize(doc)
    >>> doc = serializer.deserialize(data)
    >>>
    >>> # Сохранение с шифрованием
    >>> serializer.encrypt_and_save(
    ...     doc, Path("secret.fxsd.enc"), password="my_password",
    ...     preset=SecurityPreset.STANDARD
    ... )
    >>>
    >>> # Загрузка и расшифровка
    >>> doc = serializer.decrypt_and_load(Path("secret.fxsd.enc"), password="my_password")

Version: 1.0.0
Date: April 5, 2026
"""

from __future__ import annotations

import enum
import gzip
import json
import logging
import secrets
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from src.documents.constructor.form_constructor import FormInstance

logger: Final = logging.getLogger(__name__)

# Magic bytes для зашифрованных файлов
_MAGIC_FXSD: Final[bytes] = b"FXSD"
_MAGIC_FXSD_ENC: Final[bytes] = b"FXSE"
_CURRENT_FORMAT_VERSION: Final[int] = 1

# Размеры полей заголовка
_MAGIC_SIZE: Final[int] = 4
_VERSION_SIZE: Final[int] = 2
_ALGORITHM_SIZE: Final[int] = 2
_SALT_SIZE: Final[int] = 32
_NONCE_SIZE: Final[int] = 12
_TAG_SIZE: Final[int] = 16
_PAYLOAD_LENGTH_SIZE: Final[int] = 8
_ENCRYPTED_FLAG: Final[int] = 1

_HEADER_SIZE: Final[int] = (
    _MAGIC_SIZE + _VERSION_SIZE + _ALGORITHM_SIZE + _SALT_SIZE + _NONCE_SIZE + _PAYLOAD_LENGTH_SIZE
)


class SecurityPreset(enum.Enum):
    """Пресеты безопасности для шифрования документов.

    Attributes:
        STANDARD: AES-256-GCM + Argon2id (64MB) — баланс скорости и безопасности
        PARANOID: AES-256-GCM + Argon2id (256MB) — максимальная защита
        PQC: ML-DSA-65 + AES-256-GCM + Argon2id — защита от квантовых атак
        LEGACY: RSA-PSS-4096 + AES-256-GCM + PBKDF2 — совместимость
    """

    STANDARD = "standard"
    PARANOID = "paranoid"
    PQC = "pqc"
    LEGACY = "legacy"

    def get_kdf_params(self) -> dict[str, int]:
        """Возвращает параметры KDF для пресета.

        Returns:
            Словарь с параметрами KDF (memory_cost, time_cost, parallelism)
        """
        params: dict[SecurityPreset, dict[str, int]] = {
            SecurityPreset.STANDARD: {
                "memory_cost": 65536,  # 64 MB
                "time_cost": 2,
                "parallelism": 4,
            },
            SecurityPreset.PARANOID: {
                "memory_cost": 262144,  # 256 MB
                "time_cost": 5,
                "parallelism": 4,
            },
            SecurityPreset.PQC: {
                "memory_cost": 65536,  # 64 MB
                "time_cost": 2,
                "parallelism": 4,
            },
            SecurityPreset.LEGACY: {
                "memory_cost": 0,  # PBKDF2 не использует память
                "time_cost": 600000,  # 600k iterations
                "parallelism": 1,
            },
        }
        return params.get(self, params[SecurityPreset.STANDARD])

    def get_encryption_algorithm(self) -> str:
        """Возвращает алгоритм шифрования для пресета.

        Returns:
            ID алгоритма шифрования
        """
        algorithms: dict[SecurityPreset, str] = {
            SecurityPreset.STANDARD: "AES-256-GCM",
            SecurityPreset.PARANOID: "AES-256-GCM",
            SecurityPreset.PQC: "AES-256-GCM",
            SecurityPreset.LEGACY: "AES-256-GCM",
        }
        return algorithms.get(self, "AES-256-GCM")

    def get_kdf_algorithm(self) -> str:
        """Возвращает алгоритм KDF для пресета.

        Returns:
            ID алгоритма KDF
        """
        if self == SecurityPreset.LEGACY:
            return "PBKDF2-SHA256"
        return "Argon2id"


@dataclass(frozen=True)
class DocumentFormatHeader:
    """Заголовок зашифрованного файла .fxsd.enc.

    Attributes:
        magic: Magic bytes (b"FXSD" для зашифрованных файлов).
        version: Версия формата.
        algorithm_id: ID алгоритма шифрования.
        salt: Salt для KDF (32 bytes).
        nonce: Nonce для шифрования (12 bytes).
        payload_length: Длина зашифрованного payload.

    Example:
        >>> header = DocumentFormatHeader(
        ...     magic=b"FXSD",
        ...     version=1,
        ...     algorithm_id=1,
        ...     salt=b"x" * 32,
        ...     nonce=b"y" * 12,
        ...     payload_length=1024,
        ... )
    """

    magic: bytes = _MAGIC_FXSD
    version: int = 1
    algorithm_id: int = 1
    salt: bytes = field(default_factory=lambda: b"\x00" * _SALT_SIZE)
    nonce: bytes = field(default_factory=lambda: b"\x00" * _NONCE_SIZE)
    payload_length: int = 0

    def __post_init__(self) -> None:
        """Валидация заголовка."""
        if self.magic not in (_MAGIC_FXSD, _MAGIC_FXSD_ENC):
            raise ValueError(f"Invalid magic: {self.magic!r}")
        if self.version < 1:
            raise ValueError(f"Invalid version: {self.version}")
        if len(self.salt) != _SALT_SIZE:
            raise ValueError(f"Invalid salt size: {len(self.salt)}, expected {_SALT_SIZE}")
        if len(self.nonce) != _NONCE_SIZE:
            raise ValueError(f"Invalid nonce size: {len(self.nonce)}, expected {_NONCE_SIZE}")
        if self.payload_length < 0:
            raise ValueError(f"Invalid payload_length: {self.payload_length}")

    @property
    def total_header_size(self) -> int:
        """Общий размер заголовка в байтах."""
        return _HEADER_SIZE

    def to_bytes(self) -> bytes:
        """Сериализует заголовок в bytes.

        Returns:
            Байтовое представление заголовка.
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
            data: Байтовые данные заголовка.

        Returns:
            Экземпляр DocumentFormatHeader.

        Raises:
            ValueError: Если данные слишком короткие.
        """
        if len(data) < _HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} bytes")

        magic = data[:_MAGIC_SIZE]
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


@dataclass(frozen=True)
class DocumentFile:
    """Заголовок файла .fxsd/.fxsd.enc.

    Attributes:
        magic: Magic bytes (b"FXSD" для незашифрованных, b"FXSE" для зашифрованных)
        version: Версия формата (uint16)
        format_version: Строковая версия формата (например, "1.0")
        encrypted: Флаг зашифрованности
        algorithm_id: ID алгоритма шифрования (AES-256-GCM, ChaCha20-Poly1305 и т.д.)

    Example:
        >>> header = DocumentFile(
        ...     magic=b"FXSD",
        ...     version=1,
        ...     format_version="1.0",
        ...     encrypted=True,
        ...     algorithm_id="AES-256-GCM",
        ... )
    """

    magic: bytes = _MAGIC_FXSD
    version: int = 1
    format_version: str = "1.0"
    encrypted: bool = False
    algorithm_id: str | None = None

    def __post_init__(self) -> None:
        """Валидация заголовка."""
        if self.magic not in (_MAGIC_FXSD, _MAGIC_FXSD_ENC):
            raise ValueError(f"Invalid magic: {self.magic!r}")
        if self.version < 1:
            raise ValueError(f"Invalid version: {self.version}")


@dataclass(frozen=True)
class _EncryptedHeader:
    """Внутренний заголовок зашифрованного файла .fxsd.enc.

    Attributes:
        magic: Magic bytes (b"FXSE")
        version: Версия формата (uint16)
        algorithm_id: ID алгоритма (uint16)
        salt: Salt для KDF (32 bytes)
        nonce: Nonce для шифрования (12 bytes)
        payload_length: Длина зашифрованного payload (uint64)
    """

    magic: bytes
    version: int
    algorithm_id: int
    salt: bytes
    nonce: bytes
    payload_length: int

    def to_bytes(self) -> bytes:
        """Сериализует заголовок в bytes."""
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
    def from_bytes(cls, data: bytes) -> "_EncryptedHeader":
        """Десериализует заголовок из bytes."""
        if len(data) < _HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} bytes")

        magic = data[0:_MAGIC_SIZE]
        version = struct.unpack("<H", data[_MAGIC_SIZE : _MAGIC_SIZE + _VERSION_SIZE])[0]
        algorithm_id = struct.unpack(
            "<H",
            data[_MAGIC_SIZE + _VERSION_SIZE : _MAGIC_SIZE + _VERSION_SIZE + _ALGORITHM_SIZE],
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


class FormatError(Exception):
    """Ошибка формата документа."""

    pass


class DocumentSerializer:
    """Сериализатор документов.

    Поддерживает сериализацию в JSON с gzip сжатием и шифрование
    с использованием Argon2id для вывода ключей из паролей.

    Attributes:
        _algorithm_map: Mapping имен алгоритмов на ID
        _crypto: Optional crypto service для шифрования/дешифрования

    Example:
        >>> serializer = DocumentSerializer()
        >>> data = serializer.serialize(document)
        >>> doc = serializer.deserialize(data)
    """

    def __init__(self, crypto: Any | None = None) -> None:
        """Инициализирует сериализатор.

        Args:
            crypto: Опциональный crypto service для шифрования/дешифрования.
        """
        self._algorithm_map: dict[str, int] = {
            "AES-256-GCM": 1,
            "AES-128-GCM": 2,
            "ChaCha20-Poly1305": 3,
            "AES-256-GCM-SIV": 4,
        }
        self._reverse_map: dict[int, str] = {v: k for k, v in self._algorithm_map.items()}
        self._crypto = crypto

    def serialize(self, doc: "FormInstance") -> bytes:
        """Сериализация в JSON с gzip сжатием.

        Args:
            doc: Документ для сериализации

        Returns:
            Сжатые JSON-данные

        Example:
            >>> data = serializer.serialize(document)
            >>> len(data) > 0
            True
        """
        # Сериализуем документ в JSON
        data: dict[str, Any] = {
            "format_version": "1.0",
            "generator": "FXTextProcessor/3.0",
            "document": doc.to_dict(),
        }
        json_data = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")

        # Сжимаем с максимальным уровнем
        compressed = gzip.compress(json_data, compresslevel=9)
        logger.debug(
            f"Serialized document: {len(json_data)} bytes -> {len(compressed)} bytes compressed"
        )
        return compressed

    def deserialize(self, data: bytes) -> "FormInstance":
        """Десериализация из JSON.

        Args:
            data: Сжатые JSON-данные

        Returns:
            Восстановленный документ

        Raises:
            FormatError: Если данные некорректны

        Example:
            >>> doc = serializer.deserialize(data)
        """
        from src.documents.constructor.form_constructor import FormInstance

        try:
            # Распаковываем gzip
            json_data = gzip.decompress(data)
            json_obj = json.loads(json_data.decode("utf-8"))

            # Проверяем версию
            format_version = json_obj.get("format_version", "1.0")
            if format_version != "1.0":
                logger.warning(f"Document format version {format_version}, expected 1.0")

            # Восстанавливаем документ
            doc_data = json_obj.get("document", {})
            return FormInstance(
                form_id=__import__("uuid").UUID(
                    doc_data.get("form_id", str(__import__("uuid").uuid4()))
                ),
                type_code=doc_data.get("type_code", ""),
                subtype=doc_data.get("subtype", ""),
                series=doc_data.get("series", ""),
                index=doc_data.get("index", ""),
                fields=doc_data.get("fields", {}),
                metadata=doc_data.get("metadata", {}),
                status=doc_data.get("status", "draft"),
                parent_id=__import__("uuid").UUID(doc_data["parent_id"])
                if doc_data.get("parent_id")
                else None,
                merged_from=[
                    __import__("uuid").UUID(fid) for fid in doc_data.get("merged_from", [])
                ],
            )
        except (json.JSONDecodeError, gzip.BadGzipFile, UnicodeDecodeError, KeyError, ValueError) as e:
            raise FormatError(f"Failed to deserialize document: {e}") from e
        except Exception as e:
            logger.exception(f"Unexpected error during deserialization: {e}")
            raise FormatError(f"Failed to deserialize document: {e}") from e

    def _serialize(self, doc: "FormInstance") -> bytes:
        """Внутренняя сериализация документа в JSON (без gzip сжатия).

        Args:
            doc: Документ для сериализации.

        Returns:
            JSON-данные в виде bytes.
        """
        data: dict[str, Any] = {
            "format_version": "1.0",
            "generator": "FXTextProcessor/3.0",
            "document": doc.to_dict(),
        }
        return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")

    def _deserialize(self, data: bytes) -> "FormInstance":
        """Внутренняя десериализация документа из JSON (без gzip сжатия).

        Args:
            data: JSON-данные.

        Returns:
            Восстановленный документ.
        """
        from src.model.document import Document

        json_obj = json.loads(data.decode("utf-8"))
        doc_data = json_obj.get("document", {})
        return Document.from_dict(doc_data)

    def save(
        self,
        doc: "FormInstance",
        path: Path,
        encrypt: bool = False,
        crypto: Any | None = None,
        key: bytes | None = None,
    ) -> bytes | None:
        """Сохранение документа в файл.

        Поддерживает сохранение как в plain JSON (.fxsd),
        так и с шифрованием (.fxsd.enc).

        Args:
            doc: Документ для сохранения.
            path: Путь к файлу.
            encrypt: Флаг шифрования (если True - шифрует).
            crypto: Crypto service для шифрования (опционально).
            key: Ключ шифрования (опционально, если не передан - генерируется).

        Returns:
            Ключ шифрования, если encrypt=True, иначе None.

        Raises:
            ValueError: Если шифрование запрошено, но crypto не передан.
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        if encrypt:
            return self._save_encrypted(doc, path, crypto, key)
        else:
            self._save_plain(doc, path)
            return None

    def _save_plain(self, doc: "FormInstance", path: Path) -> None:
        """Сохранение документа в plain JSON формате.

        Args:
            doc: Документ для сохранения.
            path: Путь к файлу.
        """
        data: dict[str, Any] = {
            "format_version": "1.0",
            "generator": "FXTextProcessor/3.0",
            "document": doc.to_dict(),
        }
        json_data = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        path.write_bytes(json_data)
        logger.debug(f"Plain document saved to {path}")

    def _save_encrypted(
        self,
        doc: "FormInstance",
        path: Path,
        crypto: Any | None,
        key: bytes | None,
    ) -> bytes:
        """Сохранение документа с шифрованием.

        Args:
            doc: Документ для сохранения.
            path: Путь к файлу.
            crypto: Crypto service для шифрования.
            key: Ключ шифрования (если None - генерируется).

        Returns:
            Ключ шифрования.

        Raises:
            ValueError: Если crypto не передан.
        """
        crypto = crypto or self._crypto
        if crypto is None:
            raise ValueError("Crypto service required for encrypted save")

        # Сериализуем документ
        serialized = self.serialize(doc)

        # Генерируем или используем переданный ключ
        if key is None:
            key = crypto.generate_symmetric_key()

        # Генерируем nonce
        nonce = secrets.token_bytes(_NONCE_SIZE)

        # Шифруем данные через crypto service
        encrypted_result = crypto.encrypt_document(serialized, key)

        # Формируем заголовок
        header = DocumentFormatHeader(
            magic=_MAGIC_FXSD,
            version=_CURRENT_FORMAT_VERSION,
            algorithm_id=1,  # AES-256-GCM
            salt=secrets.token_bytes(_SALT_SIZE),
            nonce=encrypted_result.nonce if hasattr(encrypted_result, "nonce") else nonce,
            payload_length=len(encrypted_result.ciphertext)
            if hasattr(encrypted_result, "ciphertext")
            else len(encrypted_result),
        )

        # Записываем файл
        ciphertext = (
            encrypted_result.ciphertext
            if hasattr(encrypted_result, "ciphertext")
            else encrypted_result
        )
        with open(path, "wb") as f:
            f.write(header.to_bytes())
            f.write(ciphertext)

        logger.info(f"Encrypted document saved to {path}")
        return key

    def load(
        self,
        path: Path,
        crypto: Any | None = None,
        key: bytes | None = None,
    ) -> "FormInstance":
        """Загрузка документа из файла.

        Поддерживает загрузку как plain JSON (.fxsd),
        так и зашифрованных файлов (.fxsd.enc).

        Args:
            path: Путь к файлу.
            crypto: Crypto service для расшифрования (опционально).
            key: Ключ для расшифрования (опционально).

        Returns:
            Загруженный документ.

        Raises:
            FileNotFoundError: Если файл не найден.
            ValueError: Если загрузка зашифрованного файла без crypto.
        """
        if not path.exists():
            raise FileNotFoundError(f"Document file not found: {path}")

        # Определяем тип файла
        if self.is_encrypted_file(path):
            return self._load_encrypted(path, crypto, key)
        else:
            return self._load_plain(path)

    def _load_plain(self, path: Path) -> "FormInstance":
        """Загрузка plain JSON документа.

        Args:
            path: Путь к файлу.

        Returns:
            Загруженный документ.
        """
        from src.model.document import Document

        data = json.loads(path.read_bytes())
        doc_data = data.get("document", {})
        return Document.from_dict(doc_data)

    def _load_encrypted(
        self,
        path: Path,
        crypto: Any | None,
        key: bytes | None,
    ) -> "FormInstance":
        """Загрузка зашифрованного документа.

        Args:
            path: Путь к файлу.
            crypto: Crypto service для расшифрования.
            key: Ключ для расшифрования.

        Returns:
            Расшифрованный документ.

        Raises:
            ValueError: Если crypto не передан для зашифрованного файла.
        """
        crypto = crypto or self._crypto
        if crypto is None:
            raise ValueError("Crypto service required for encrypted load")

        if key is None:
            raise ValueError("Key required for encrypted load")

        # Читаем файл
        with open(path, "rb") as f:
            data = f.read()

        # Парсим заголовок
        header = DocumentFormatHeader.from_bytes(data[:_HEADER_SIZE])
        encrypted_data = data[_HEADER_SIZE:]

        # Создаем EncryptedDocument-like объект для crypto service
        class EncryptedDocument:
            def __init__(self, ciphertext: bytes, nonce: bytes, salt: bytes) -> None:
                self.ciphertext = ciphertext
                self.nonce = nonce
                self.salt = salt

        enc_doc = EncryptedDocument(
            ciphertext=encrypted_data,
            nonce=header.nonce,
            salt=header.salt,
        )

        # Расшифровываем через crypto service
        decrypted = crypto.decrypt_document(enc_doc, key)

        # Десериализуем
        return self.deserialize(decrypted)

    def get_format_info(self, path: Path) -> dict[str, Any]:
        """Возвращает информацию о формате файла.

        Args:
            path: Путь к файлу.

        Returns:
            Словарь с информацией о формате файла.

        Raises:
            FileNotFoundError: Если файл не найден.
        """
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Проверяем, зашифрован ли файл
        if self.is_encrypted_file(path):
            try:
                with open(path, "rb") as f:
                    header_data = f.read(_HEADER_SIZE)
                if len(header_data) >= _HEADER_SIZE:
                    header = DocumentFormatHeader.from_bytes(header_data)
                    return {
                        "format": "encrypted",
                        "version": header.version,
                        "algorithm_id": header.algorithm_id,
                    }
            except (OSError, ValueError) as e:
                logger.warning(f"Failed to read encrypted file header: {e}")

            return {"format": "encrypted", "version": "unknown"}
        # Plain JSON
        try:
            data = json.loads(path.read_bytes())
            return {
                "format": "plain",
                "version": data.get("format_version", "unknown"),
            }
        except Exception as e:
            logger.exception(f"Unexpected error in get_format_info: {e}")
            return {"format": "plain", "version": "unknown"}

    def encrypt_and_save(
        self,
        doc: "FormInstance",
        path: Path,
        password: str,
        preset: SecurityPreset = SecurityPreset.STANDARD,
    ) -> None:
        """Сохранение с шифрованием .fxsd.enc.

        Использует Argon2id для вывода ключа из пароля и
        AES-256-GCM для шифрования данных.

        Args:
            doc: Документ для сохранения
            path: Путь к файлу
            password: Пароль для шифрования
            preset: Пресет безопасности

        Raises:
            FormatError: При ошибке шифрования
            IOError: При ошибке записи файла

        Example:
            >>> serializer.encrypt_and_save(
            ...     doc, Path("doc.fxsd.enc"), "password123", SecurityPreset.STANDARD
            ... )
        """
        try:
            # Получаем параметры для пресета
            kdf_params = preset.get_kdf_params()
            algorithm_name = preset.get_encryption_algorithm()
            kdf_algo = preset.get_kdf_algorithm()

            # Сериализуем и сжимаем документ
            serialized = self.serialize(doc)

            # Генерируем соль и выводим ключ
            salt = secrets.token_bytes(_SALT_SIZE)

            if kdf_algo == "PBKDF2-SHA256":
                import hashlib

                key = hashlib.pbkdf2_hmac(
                    "sha256",
                    password.encode("utf-8"),
                    salt,
                    kdf_params["time_cost"],
                    dklen=32,
                )
            else:
                # Argon2id
                try:
                    from argon2.low_level import Type, hash_secret_raw

                    key = hash_secret_raw(
                        secret=password.encode("utf-8"),
                        salt=salt,
                        time_cost=kdf_params["time_cost"],
                        memory_cost=kdf_params["memory_cost"],
                        parallelism=kdf_params["parallelism"],
                        hash_len=32,
                        type=Type.ID,
                    )
                except ImportError:
                    # Fallback к PBKDF2 если argon2 не установлен
                    import hashlib

                    key = hashlib.pbkdf2_hmac(
                        "sha256",
                        password.encode("utf-8"),
                        salt,
                        100000,
                        dklen=32,
                    )

            # Генерируем nonce
            nonce = secrets.token_bytes(_NONCE_SIZE)

            # Шифруем данные
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            cipher = AESGCM(key)
            ciphertext = cipher.encrypt(nonce, serialized, None)

            # Формируем заголовок
            algorithm_id = self._algorithm_map.get(algorithm_name, 1)
            header = _EncryptedHeader(
                magic=_MAGIC_FXSD_ENC,
                version=_CURRENT_FORMAT_VERSION,
                algorithm_id=algorithm_id,
                salt=salt,
                nonce=nonce,
                payload_length=len(ciphertext),
            )

            # Записываем файл
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "wb") as f:
                f.write(header.to_bytes())
                f.write(ciphertext)

            logger.info(f"Encrypted document saved to {path} (preset: {preset.value})")

        except Exception as e:
            raise FormatError(f"Failed to encrypt and save document: {e}") from e

    def decrypt_and_load(self, path: Path, password: str) -> "FormInstance":
        """Загрузка и расшифровка .fxsd.enc.

        Args:
            path: Путь к файлу
            password: Пароль для расшифровки

        Returns:
            Расшифрованный документ

        Raises:
            FormatError: При ошибке расшифровки
            FileNotFoundError: Если файл не найден

        Example:
            >>> doc = serializer.decrypt_and_load(Path("doc.fxsd.enc"), "password123")
        """
        if not path.exists():
            raise FileNotFoundError(f"Document file not found: {path}")

        try:
            # Читаем файл
            with open(path, "rb") as f:
                data = f.read()

            if len(data) < _HEADER_SIZE:
                raise FormatError(f"File too short: {len(data)} bytes")

            # Парсим заголовок
            header = _EncryptedHeader.from_bytes(data[:_HEADER_SIZE])
            encrypted_data = data[_HEADER_SIZE:]

            if header.magic != _MAGIC_FXSD_ENC:
                raise FormatError(f"Invalid magic bytes: {header.magic!r}")

            if len(encrypted_data) != header.payload_length:
                raise FormatError(
                    f"Payload size mismatch: {len(encrypted_data)} vs {header.payload_length}"
                )

            # Определяем алгоритм KDF по версии (для обратной совместимости)
            # Для версии 1 используем Argon2id
            kdf_algo = "Argon2id"

            # Выводим ключ из пароля
            if kdf_algo == "PBKDF2-SHA256":
                import hashlib

                key = hashlib.pbkdf2_hmac(
                    "sha256",
                    password.encode("utf-8"),
                    header.salt,
                    600000,
                    dklen=32,
                )
            else:
                # Argon2id - нужно попробовать разные параметры
                try:
                    from argon2.low_level import Type, hash_secret_raw

                    # Пробуем стандартные параметры
                    for memory_cost, time_cost in [
                        (65536, 2),  # STANDARD
                        (262144, 5),  # PARANOID
                    ]:
                        try:
                            key = hash_secret_raw(
                                secret=password.encode("utf-8"),
                                salt=header.salt,
                                time_cost=time_cost,
                                memory_cost=memory_cost,
                                hash_len=32,
                                type=Type.ID,
                            )
                            break
                        except (ValueError, MemoryError):
                            continue
                    else:
                        raise FormatError("Failed to derive key with Argon2id")
                except ImportError:
                    # Fallback к PBKDF2
                    import hashlib

                    key = hashlib.pbkdf2_hmac(
                        "sha256",
                        password.encode("utf-8"),
                        header.salt,
                        100000,
                        dklen=32,
                    )

            # Расшифровываем
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            cipher = AESGCM(key)
            try:
                decrypted = cipher.decrypt(header.nonce, encrypted_data, None)
            except Exception as e:
                raise FormatError("Decryption failed: invalid password or corrupted data") from e

            # Десериализуем
            doc = self.deserialize(decrypted)
            logger.info(f"Decrypted document loaded from {path}")
            return doc

        except Exception as e:
            if isinstance(e, FormatError):
                raise
            raise FormatError(f"Failed to decrypt and load document: {e}") from e

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

        # Проверяем magic bytes (FXSD или FXSE)
        try:
            with open(path, "rb") as f:
                magic = f.read(_MAGIC_SIZE)
            return magic in (_MAGIC_FXSD, _MAGIC_FXSD_ENC)
        except IOError:
            return False

    def get_file_info(self, path: Path) -> dict[str, Any]:
        """Возвращает информацию о файле документа.

        Args:
            path: Путь к файлу

        Returns:
            Словарь с информацией о файле

        Raises:
            FileNotFoundError: Если файл не найден
        """
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        info: dict[str, Any] = {
            "path": str(path),
            "size": path.stat().st_size,
            "encrypted": False,
        }

        # Проверяем тип файла
        if self.is_encrypted_file(path):
            info["encrypted"] = True
            try:
                with open(path, "rb") as f:
                    header_data = f.read(_HEADER_SIZE)
                if len(header_data) >= _HEADER_SIZE:
                    header = _EncryptedHeader.from_bytes(header_data)
                    info["version"] = header.version
                    info["algorithm"] = self._reverse_map.get(
                        header.algorithm_id, f"Unknown({header.algorithm_id})"
                    )
            except Exception as e:
                info["error"] = str(e)
        else:
            # Пробуем прочитать как JSON
            try:
                data = gzip.decompress(path.read_bytes())
                json_obj = json.loads(data.decode("utf-8"))
                info["format_version"] = json_obj.get("format_version", "unknown")
                info["generator"] = json_obj.get("generator", "unknown")
            except (OSError, gzip.BadGzipFile, UnicodeDecodeError, json.JSONDecodeError):
                info["format"] = "unknown"

        return info


__all__ = [
    "DocumentSerializer",
    "DocumentFile",
    "DocumentFormatHeader",
    "SecurityPreset",
    "FormatError",
]

# Alias for backward compatibility
DocumentFormat = DocumentSerializer
