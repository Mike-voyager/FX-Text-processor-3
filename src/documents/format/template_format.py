"""Сериализация и десериализация шаблонов документов.

Формат .fxstpl (FX Super Template):
    - JSON с метаданными и схемой шаблона
    - Опционально подписан (detached signature .fxssig)
    - Опционально зашифрован (.fxstpl.enc)

Example:
    >>> from src.documents.format.template_format import TemplateFormat
    >>> from src.documents.types.type_schema import TypeSchema
    >>> schema = TypeSchema(fields=())
    >>> fmt = TemplateFormat()
    >>> fmt.save(schema, Path("template.fxstpl"))
    >>> loaded = fmt.load(Path("template.fxstpl"))
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
    from src.documents.types.type_schema import TypeSchema
    from src.security.crypto.service.crypto_service import CryptoService

from src.security.crypto.service.crypto_service import EncryptedDocument

logger: Final = logging.getLogger(__name__)

# Magic bytes для файлов шаблонов
_MAGIC_FXSTPL: Final[bytes] = b"FXST"
_MAGIC_FXSTPL_ENC: Final[bytes] = b"FXSE"
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
class TemplateFormatHeader:
    """Заголовок зашифрованного шаблона.

    Attributes:
        magic: Magic bytes (b"FXSE")
        version: Версия формата (uint16)
        algorithm_id: ID алгоритма шифрования (uint16)
        salt: Salt для KDF (32 bytes)
        nonce: Nonce для шифрования (12 bytes)
        payload_length: Длина зашифрованного payload (uint64)

    Example:
        >>> header = TemplateFormatHeader(
        ...     magic=b"FXSE",
        ...     version=1,
        ...     algorithm_id=1,
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
        if self.magic not in (_MAGIC_FXSTPL_ENC, _MAGIC_FXSTPL):
            raise ValueError(f"Invalid magic: {self.magic!r}")
        if self.version < 1:
            raise ValueError(f"Invalid version: {self.version}")
        if self.algorithm_id < 1:
            raise ValueError(f"Invalid algorithm_id: {self.algorithm_id}")
        if len(self.salt) != _SALT_SIZE:
            raise ValueError(f"Invalid salt size: {len(self.salt)}")
        if len(self.nonce) != _NONCE_SIZE:
            raise ValueError(f"Invalid nonce size: {len(self.nonce)}")
        if self.payload_length < 0:
            raise ValueError(f"Invalid payload_length: {self.payload_length}")

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
    def from_bytes(cls, data: bytes) -> "TemplateFormatHeader":
        """Десериализует заголовок из bytes."""
        if len(data) < _HEADER_SIZE:
            raise ValueError(f"Header too short: {len(data)} bytes")

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


class TemplateFormat:
    """Сериализация и десериализация шаблонов.

    Поддерживает три формата:
    - .fxstpl: JSON (незашифрованный, опционально подписан)
    - .fxstpl.enc: Binary (зашифрованный)
    - .fxssig: Detached signature

    Example:
        >>> from src.documents.types.type_schema import TypeSchema
        >>> schema = TypeSchema(fields=())
        >>> fmt = TemplateFormat()

        # Сохранение без шифрования
        >>> fmt.save(schema, Path("template.fxstpl"))

        # Сохранение с подписью
        >>> fmt.save(schema, Path("template.fxstpl"), sign=True, crypto=crypto)

        # Загрузка
        >>> loaded = fmt.load(Path("template.fxstpl"), crypto=crypto)
    """

    def __init__(self) -> None:
        """Инициализирует формат шаблона."""
        self._logger = logging.getLogger(__name__)

    def save(
        self,
        template: "TypeSchema",
        path: Path,
        *,
        encrypt: bool = False,
        sign: bool = False,
        crypto: "CryptoService | None" = None,
        private_key: bytes | None = None,
        public_key: bytes | None = None,
        key: bytes | None = None,
    ) -> bytes | None:
        """Сохраняет шаблон в файл.

        Args:
            template: Схема типа документа (TypeSchema)
            path: Путь к файлу
            encrypt: Шифровать ли файл (требует crypto)
            sign: Подписывать ли файл (требует crypto, private_key, public_key)
            crypto: Криптографический сервис (обязателен если encrypt=True или sign=True)
            private_key: Приватный ключ для подписи (обязателен если sign=True)
            public_key: Публичный ключ для сохранения в подписи (обязателен если sign=True)
            key: Ключ шифрования (опционально, если None — генерируется новый)

        Returns:
            Ключ шифрования (если encrypt=True и key=None), иначе None.
            Ключ необходим для расшифровки шаблона.

        Raises:
            ValueError: Если encrypt=True но crypto не предоставлен
            ValueError: Если sign=True но отсутствуют private_key или public_key
            IOError: При ошибке записи файла

        Security:
            КРИТИЧЕСКИ: Возвращаемый ключ должен быть сохранён пользователем.
            Без ключа зашифрованный шаблон невозможно расшифровать.
        """
        if encrypt and crypto is None:
            raise ValueError("Crypto service required for encrypted save")
        if sign and crypto is None:
            raise ValueError("Crypto service required for signed save")
        if sign and not private_key:
            raise ValueError("Private key required for signing")
        if sign and not public_key:
            raise ValueError("Public key required for signing")

        # Сериализуем шаблон
        data = self._serialize(template)

        # Создаём подпись до шифрования (если нужно)
        if sign and crypto and private_key and public_key:
            self._create_signature(data, path, crypto, private_key, public_key)

        if encrypt:
            # crypto гарантированно не None после проверок выше
            assert crypto is not None
            generated_key = self._save_encrypted(data, path, crypto, key)
            self._logger.debug(f"Template saved to {path} (encrypted)")
            return generated_key
        else:
            self._save_plain(data, path)
            self._logger.debug(f"Template saved to {path}")
            return None

    def load(
        self,
        path: Path,
        *,
        crypto: "CryptoService | None" = None,
        verify_sign: bool = False,
        key: bytes | None = None,
    ) -> "TypeSchema":
        """Загружает шаблон из файла.

        Автоматически определяет формат по расширению и содержимому.

        Args:
            path: Путь к файлу
            crypto: Криптографический сервис (обязателен для .fxstpl.enc и verify_sign=True)
            verify_sign: Проверять ли подпись при загрузке
            key: Ключ расшифровки (обязателен для .fxstpl.enc)

        Returns:
            Загруженная схема шаблона

        Raises:
            ValueError: Если файл зашифрован но crypto/key не предоставлен
            IOError: При ошибке чтения файла
            FormatError: Если формат файла некорректен
        """
        if not path.exists():
            raise FileNotFoundError(f"Template file not found: {path}")

        # Определяем формат по расширению
        is_encrypted = path.suffix == ".enc" or path.name.endswith(".fxstpl.enc")

        if is_encrypted:
            if crypto is None:
                raise ValueError("Crypto service required for encrypted templates")
            if key is None:
                raise ValueError("Encryption key required for encrypted templates")
            data = self._load_encrypted(path, crypto, key)
        else:
            data = self._load_plain(path)

        # Проверяем подпись если запрошено
        if verify_sign:
            sig_path = path.with_suffix(path.suffix + ".sig")
            if not sig_path.exists():
                sig_path = path.parent / (path.stem + ".fxssig")
            if sig_path.exists():
                if crypto is None:
                    raise ValueError("Crypto service required for signature verification")
                self._verify_signature(data, sig_path, crypto)
            else:
                self._logger.warning(f"Signature file not found for {path}")

        template = self._deserialize(data)
        self._logger.debug(f"Template loaded from {path}")
        return template

    def _serialize(self, template: "TypeSchema") -> bytes:
        """Сериализует шаблон в bytes.

        Args:
            template: Схема типа для сериализации

        Returns:
            JSON bytes
        """
        # Преобразуем TypeSchema в dict
        if hasattr(template, "to_dict"):
            template_dict = template.to_dict()
        else:
            # Fallback для случая когда to_dict не реализован
            template_dict = self._type_schema_to_dict(template)

        data: dict[str, Any] = {
            "format_version": "1.0",
            "generator": "FXTextProcessor/3.0",
            "template": template_dict,
        }
        return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")

    def _deserialize(self, data: bytes) -> "TypeSchema":
        """Десериализует шаблон из bytes.

        Args:
            data: JSON bytes

        Returns:
            TypeSchema
        """
        from src.documents.types.type_schema import TypeSchema  # noqa: F401

        json_data = json.loads(data.decode("utf-8"))

        # Проверяем версию
        format_version = json_data.get("format_version", "1.0")
        if format_version != "1.0":
            self._logger.warning(f"Template format version {format_version}, expected 1.0")

        # Восстанавливаем TypeSchema из dict
        template_dict = json_data["template"]
        return TypeSchema.from_dict(template_dict)

    def _type_schema_to_dict(self, template: "TypeSchema") -> dict[str, Any]:
        """Преобразует TypeSchema в словарь (fallback)."""
        return {
            "fields": [
                {
                    "field_id": f.field_id,
                    "field_type": f.field_type.value,
                    "label": f.label,
                    "label_i18n": f.label_i18n,
                    "required": f.required,
                    "default_value": f.default_value,
                    "validation_pattern": f.validation_pattern,
                    "max_length": f.max_length,
                    "options": list(f.options) if f.options else None,
                    "escp_variable": f.escp_variable,
                    "inherited_from": f.inherited_from,
                }
                for f in template.fields
            ],
            "version": template.version,
            "compatibility_version": template.compatibility_version,
            "deprecated_fields": list(template.deprecated_fields),
        }

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
            Потеря ключа означает невозможность расшифровки шаблона.
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
        header = TemplateFormatHeader(
            magic=_MAGIC_FXSTPL_ENC,
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
        header = TemplateFormatHeader.from_bytes(data[:_HEADER_SIZE])
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

    def _create_signature(
        self,
        data: bytes,
        path: Path,
        crypto: "CryptoService",
        private_key: bytes,
        public_key: bytes,
    ) -> None:
        """Создаёт detached signature для данных.

        Args:
            data: Данные для подписи
            path: Путь к оригинальному файлу (signature будет path + ".sig")
            crypto: Криптографический сервис
            private_key: Приватный ключ для подписи (DER/raw формат)
            public_key: Публичный ключ для сохранения в подписи (для верификации)

        Raises:
            ValueError: Если ключи не предоставлены
        """
        if not private_key:
            raise ValueError("Приватный ключ обязателен для подписи")
        if not public_key:
            raise ValueError("Публичный ключ обязателен для сохранения в подписи")

        # Создаём подпись
        signed_doc = crypto.sign_document(data, private_key)

        # Сохраняем в файл .fxssig
        sig_path = path.parent / (path.stem + ".fxssig")
        sig_data = {
            "format_version": "1.0",
            "algorithm_id": signed_doc.algorithm_id,
            "signature": signed_doc.signature.hex(),
            "public_key": public_key.hex(),
            "timestamp": json.dumps({}),
        }
        sig_path.write_bytes(json.dumps(sig_data, indent=2).encode("utf-8"))
        self._logger.debug(f"Signature saved to {sig_path}")

    def _verify_signature(
        self,
        data: bytes,
        sig_path: Path,
        crypto: "CryptoService",
    ) -> bool:
        """Проверяет подпись данных.

        Args:
            data: Данные для проверки
            sig_path: Путь к файлу подписи
            crypto: Криптографический сервис

        Returns:
            True если подпись валидна, False если нет или при ошибке

        Raises:
            ValueError: Если файл подписи некорректен (отсутствуют обязательные поля)
        """
        if not sig_path.exists():
            self._logger.warning(f"Signature file not found: {sig_path}")
            return False

        try:
            sig_data = json.loads(sig_path.read_bytes().decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._logger.error(f"Invalid signature file format: {e}")
            return False

        # Извлекаем обязательные поля
        signature_hex = sig_data.get("signature")
        public_key_hex = sig_data.get("public_key")
        algorithm_id = sig_data.get("algorithm_id", "Ed25519")

        if not signature_hex:
            self._logger.error("Signature file missing 'signature' field")
            return False
        if not public_key_hex:
            self._logger.error("Signature file missing 'public_key' field")
            return False

        try:
            signature = bytes.fromhex(signature_hex)
            public_key = bytes.fromhex(public_key_hex)
        except ValueError as e:
            self._logger.error(f"Invalid hex encoding in signature file: {e}")
            return False

        # Проверяем подпись через crypto service
        is_valid = crypto.verify_signature(data, signature, public_key, algorithm_id)

        if is_valid:
            self._logger.debug(f"Signature verified successfully for {sig_path}")
        else:
            self._logger.warning(f"Signature verification failed for {sig_path}")

        return is_valid

    def get_format_info(self, path: Path) -> dict[str, Any]:
        """Возвращает информацию о формате файла шаблона.

        Args:
            path: Путь к файлу

        Returns:
            Словарь с информацией о формате
        """
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        is_encrypted = path.suffix == ".enc" or path.name.endswith(".fxstpl.enc")

        if is_encrypted:
            data = path.read_bytes()
            if len(data) >= _HEADER_SIZE:
                try:
                    header = TemplateFormatHeader.from_bytes(data[:_HEADER_SIZE])
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
        if path.suffix == ".enc" or path.name.endswith(".fxstpl.enc"):
            return True

        # Проверяем magic bytes
        try:
            with open(path, "rb") as f:
                magic = f.read(_MAGIC_SIZE)
            return magic == _MAGIC_FXSTPL_ENC
        except IOError:
            return False

    def is_template_file(self, path: Path) -> bool:
        """Проверяет, является ли файл шаблоном FX Super.

        Args:
            path: Путь к файлу

        Returns:
            True если файл является валидным шаблоном
        """
        if not path.exists():
            return False

        # Проверяем расширение
        valid_extensions = (".fxstpl", ".fxstpl.enc")
        if not any(str(path).endswith(ext) for ext in valid_extensions):
            return False

        # Проверяем magic bytes для зашифрованных
        if self.is_encrypted_file(path):
            return True

        # Пробуем прочитать как JSON для незашифрованных
        try:
            content = json.loads(path.read_bytes().decode("utf-8"))
            return "template" in content and "format_version" in content
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False


class FormatError(Exception):
    """Ошибка формата шаблона."""

    pass


__all__ = [
    "TemplateFormat",
    "TemplateFormatHeader",
    "FormatError",
]
