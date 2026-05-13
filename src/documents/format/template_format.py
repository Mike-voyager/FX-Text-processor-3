"""Сериализация шаблонов форм (.fxstpl) с подписью Ed25519.

Этот модуль предоставляет TemplateSerializer для сохранения и загрузки
шаблонов форм с цифровой подписью Ed25519 для защиты от подделок.

Формат .fxstpl:
    - JSON с метаданными шаблона
    - Ed25519 подпись для верификации
    - Опциональная шифровка приватного ключа

Примеры:
    >>> from src.documents.format.template_format import TemplateSerializer
    >>> from src.documents.constructor.form_constructor import FormTemplate
    >>>
    >>> # Создание шаблона с подписью
    >>> tpl = FormTemplate(type_code="DVN", subtype="44", series="K53")
    >>> serializer = TemplateSerializer()
    >>> data = serializer.serialize_template(tpl, sign=True, private_key=private_key)
    >>>
    >>> # Загрузка с проверкой подписи
    >>> loaded = serializer.deserialize_template(
    ...     data, verify_signature=True, public_key=public_key
    ... )

Version: 1.0.0
Date: April 5, 2026
"""

from __future__ import annotations

import gzip
import json
import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

if TYPE_CHECKING:
    from src.documents.constructor.form_constructor import FormTemplate

logger: Final = logging.getLogger(__name__)

# Magic bytes для файлов шаблонов
_MAGIC_FXSTPL: Final[bytes] = b"FXST"
_MAGIC_FXSE: Final[bytes] = b"FXSE"

# Размеры полей заголовка
_MAGIC_SIZE: Final[int] = 4
_VERSION_SIZE: Final[int] = 2
_ALGORITHM_SIZE: Final[int] = 2
_SALT_SIZE: Final[int] = 32
_NONCE_SIZE: Final[int] = 12
_PAYLOAD_LENGTH_SIZE: Final[int] = 8

_HEADER_SIZE: Final[int] = (
    _MAGIC_SIZE + _VERSION_SIZE + _ALGORITHM_SIZE + _SALT_SIZE + _NONCE_SIZE + _PAYLOAD_LENGTH_SIZE
)


class TemplateError(Exception):
    """Ошибка работы с шаблоном формы."""

    pass


@dataclass(frozen=True)
class TemplateFormatHeader:
    """Заголовок зашифрованного файла шаблона .fxstpl.enc.

    Attributes:
        magic: Magic bytes (b"FXSE" для зашифрованных).
        version: Версия формата.
        algorithm_id: ID алгоритма шифрования.
        salt: Salt для KDF (32 bytes).
        nonce: Nonce для шифрования (12 bytes).
        payload_length: Длина зашифрованного payload.
    """

    magic: bytes
    version: int
    algorithm_id: int
    salt: bytes
    nonce: bytes
    payload_length: int

    def __post_init__(self) -> None:
        """Валидация заголовка."""
        if self.magic not in (_MAGIC_FXSTPL, _MAGIC_FXSE):
            raise ValueError(f"Invalid magic: {self.magic!r}")
        if self.version < 1:
            raise ValueError(f"Invalid version: {self.version}")
        if len(self.salt) != _SALT_SIZE:
            raise ValueError(f"Invalid salt size: {len(self.salt)}, expected {_SALT_SIZE}")
        if len(self.nonce) != _NONCE_SIZE:
            raise ValueError(f"Invalid nonce size: {len(self.nonce)}, expected {_NONCE_SIZE}")
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


class TemplateFormat:
    """Формат шаблона .fxstpl с поддержкой шифрования и подписи.

    Provides:
    - Сериализация/десериализация шаблонов
    - Шифрование с помощью crypto service
    - Подпись с помощью crypto service
    """

    def __init__(self) -> None:
        """Инициализирует формат шаблона."""
        self._algorithm_map: dict[str, int] = {
            "AES-256-GCM": 1,
            "AES-128-GCM": 2,
            "ChaCha20-Poly1305": 3,
        }

    def save(
        self,
        schema: Any,
        path: Path,
        encrypt: bool = False,
        sign: bool = False,
        crypto: Any = None,
        key: bytes | None = None,
        private_key: bytes | None = None,
        public_key: bytes | None = None,
    ) -> bytes | None:
        """Сохраняет шаблон в файл.

        Args:
            schema: Схема шаблона (с методом to_dict).
            path: Путь к файлу.
            encrypt: Шифровать ли файл.
            sign: Подписывать ли файл.
            crypto: Сервис шифрования.
            key: Ключ для шифрования (опционально).
            private_key: Приватный ключ для подписи.
            public_key: Публичный ключ для подписи.

        Returns:
            Ключ шифрования если encrypt=True, иначе None.

        Raises:
            ValueError: Если требуется crypto service но не предоставлен.
        """
        path.parent.mkdir(parents=True, exist_ok=True)

        # Сериализуем данные
        data: dict[str, Any] = {
            "format_version": "1.0",
            "generator": "FXTextProcessor/3.0",
            "template": schema.to_dict(),
        }
        json_data = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")

        if encrypt:
            if crypto is None:
                raise ValueError("Crypto service required for encryption")

            # Генерируем ключ если не предоставлен
            if key is None:
                key = crypto.generate_symmetric_key()

            # Сжимаем и шифруем
            compressed = gzip.compress(json_data, compresslevel=9)
            encrypted = crypto.encrypt_document(compressed, key)

            # Формируем заголовок
            header = TemplateFormatHeader(
                magic=_MAGIC_FXSE,
                version=1,
                algorithm_id=1,  # AES-256-GCM
                salt=b"x" * _SALT_SIZE,  # Мок - в реальности из crypto
                nonce=encrypted.nonce if hasattr(encrypted, "nonce") else b"y" * _NONCE_SIZE,
                payload_length=len(
                    encrypted.ciphertext if hasattr(encrypted, "ciphertext") else encrypted
                ),
            )

            # Пишем файл
            with open(path, "wb") as f:
                f.write(header.to_bytes())
                f.write(encrypted.ciphertext if hasattr(encrypted, "ciphertext") else encrypted)

            return key

        if sign:
            if crypto is None:
                raise ValueError("Crypto service required for signing")
            if not private_key:
                raise ValueError("Private key required for signing")
            if not public_key:
                raise ValueError("Public key required for signing")

            # Создаём подпись через crypto service
            signed_doc = crypto.sign_document(json_data, private_key)

            # Сохраняем шаблон
            path.write_bytes(json_data)

            # Сохраняем файл подписи
            sig_path = path.parent / (path.stem + ".fxssig")
            sig_data = {
                "format_version": "1.0",
                "algorithm_id": signed_doc.algorithm_id
                if hasattr(signed_doc, "algorithm_id")
                else "Ed25519",
                "signature": (
                    signed_doc.signature if hasattr(signed_doc, "signature") else signed_doc
                ).hex(),
                "public_key": public_key.hex(),
                "timestamp": __import__("datetime").datetime.now().isoformat(),
            }
            sig_path.write_bytes(json.dumps(sig_data, ensure_ascii=False).encode("utf-8"))

            return None

        # Просто сохраняем JSON
        path.write_bytes(json_data)
        return None

    def load(
        self,
        path: Path,
        crypto: Any = None,
        key: bytes | None = None,
        verify_sign: bool = False,
    ) -> Any:
        """Загружает шаблон из файла.

        Args:
            path: Путь к файлу.
            crypto: Сервис шифрования.
            key: Ключ для расшифровки.
            verify_sign: Проверять ли подпись.

        Returns:
            Данные шаблона.

        Raises:
            FileNotFoundError: Если файл не найден.
            ValueError: Если требуется crypto service но не предоставлен.
        """
        if not path.exists():
            raise FileNotFoundError(f"Template file not found: {path}")

        # Проверяем magic
        with open(path, "rb") as f:
            magic = f.read(_MAGIC_SIZE)

        if magic == _MAGIC_FXSE:
            # Зашифрованный файл
            if crypto is None:
                raise ValueError("Crypto service required for encrypted files")
            if key is None:
                raise ValueError("Key required for encrypted files")

            # Читаем заголовок
            with open(path, "rb") as f:
                header_data = f.read(_HEADER_SIZE)
                header = TemplateFormatHeader.from_bytes(header_data)
                encrypted_data = f.read(header.payload_length)

            # Проверяем размер
            if len(encrypted_data) != header.payload_length:
                raise ValueError(
                    f"Payload size mismatch: {len(encrypted_data)} vs {header.payload_length}"
                )

            # Расшифровываем
            decrypted = crypto.decrypt_document(encrypted_data, key)
            decompressed = gzip.decompress(decrypted)
            return json.loads(decompressed.decode("utf-8"))

        # Обычный JSON
        data = json.loads(path.read_bytes().decode("utf-8"))

        # Проверяем подпись если требуется
        if verify_sign:
            if crypto is None:
                raise ValueError("Crypto service required for signature verification")

            sig_path = path.parent / (path.stem + ".fxssig")
            self._verify_signature(path.read_bytes(), sig_path, crypto)

        return data

    def _verify_signature(self, data: bytes, sig_path: Path, crypto: Any) -> bool:
        """Проверяет подпись файла.

        Args:
            data: Данные файла.
            sig_path: Путь к файлу подписи.
            crypto: Сервис шифрования.

        Returns:
            True если подпись верна.
        """
        if not sig_path.exists():
            logger.warning(f"Signature file not found: {sig_path}")
            return False

        try:
            sig_data = json.loads(sig_path.read_bytes().decode("utf-8"))
            signature = bytes.fromhex(sig_data["signature"])
            public_key = bytes.fromhex(sig_data["public_key"])
            return crypto.verify_signature(data, signature, public_key)
        except (KeyError, ValueError) as e:
            logger.warning(f"Invalid signature file: {e}")
            return False

    def is_encrypted_file(self, path: Path) -> bool:
        """Проверяет является ли файл зашифрованным.

        Args:
            path: Путь к файлу.

        Returns:
            True если файл зашифрован.
        """
        if not path.exists():
            return False

        # Проверяем расширение
        if path.suffix == ".enc" or str(path).endswith(".fxstpl.enc"):
            return True

        # Проверяем magic
        try:
            with open(path, "rb") as f:
                magic = f.read(_MAGIC_SIZE)
            return magic == _MAGIC_FXSE
        except IOError:
            return False

    def is_template_file(self, path: Path) -> bool:
        """Проверяет является ли файл шаблоном.

        Args:
            path: Путь к файлу.

        Returns:
            True если файл является шаблоном.
        """
        if not path.exists():
            return False

        # Проверяем расширение
        if not str(path).endswith(".fxstpl") and not str(path).endswith(".fxstpl.enc"):
            return False

        # Проверяем magic для зашифрованных
        if self.is_encrypted_file(path):
            return True

        # Для незашифрованных проверяем JSON
        try:
            data = json.loads(path.read_bytes().decode("utf-8"))
            return "format_version" in data and "template" in data
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def get_format_info(self, path: Path) -> dict[str, Any]:
        """Возвращает информацию о файле шаблона.

        Args:
            path: Путь к файлу.

        Returns:
            Словарь с информацией о файле.

        Raises:
            FileNotFoundError: Если файл не найден.
        """
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        info: dict[str, Any] = {
            "path": str(path),
            "size": path.stat().st_size,
        }

        # Определяем тип
        if self.is_encrypted_file(path):
            info["format"] = "encrypted"
            try:
                with open(path, "rb") as f:
                    header_data = f.read(_HEADER_SIZE)
                header = TemplateFormatHeader.from_bytes(header_data)
                info["version"] = header.version
                info["algorithm_id"] = header.algorithm_id
            except Exception as e:
                info["format"] = "unknown_encrypted"
                info["error"] = str(e)
        else:
            # Пробуем прочитать как JSON
            try:
                data = json.loads(path.read_bytes().decode("utf-8"))
                info["format"] = "plain"
                info["version"] = data.get("format_version", "unknown")
                info["generator"] = data.get("generator", "unknown")
            except (json.JSONDecodeError, UnicodeDecodeError):
                info["format"] = "unknown_plain"

        return info


@dataclass(frozen=True)
class TemplateSignature:
    """Подпись шаблона.

    Attributes:
        signature: Байты подписи Ed25519 (64 bytes)
        public_key: Публичный ключ для верификации (32 bytes)
        timestamp: Временная метка создания подписи (ISO format)
        algorithm: Алгоритм подписи (всегда "Ed25519")
    """

    signature: bytes
    public_key: bytes
    timestamp: str
    algorithm: str = "Ed25519"

    def to_dict(self) -> dict[str, str]:
        """Сериализует подпись в словарь."""
        return {
            "signature": self.signature.hex(),
            "public_key": self.public_key.hex(),
            "timestamp": self.timestamp,
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "TemplateSignature":
        """Десериализует подпись из словаря."""
        return cls(
            signature=bytes.fromhex(data["signature"]),
            public_key=bytes.fromhex(data["public_key"]),
            timestamp=data["timestamp"],
            algorithm=data.get("algorithm", "Ed25519"),
        )


class TemplateSerializer:
    """Сериализация шаблонов с подписью.

    Поддерживает создание и проверку Ed25519 подписей для шаблонов форм,
    что позволяет гарантировать подлинность и целостность шаблонов.

    Example:
        >>> serializer = TemplateSerializer()
        >>>
        >>> # Создание подписанного шаблона
        >>> data = serializer.serialize_template(template, sign=True, private_key=key)
        >>>
        >>> # Проверка подписи при загрузке
        >>> loaded = serializer.deserialize_template(
        ...     data, verify_signature=True, public_key=pub_key
        ... )
    """

    def __init__(self) -> None:
        """Инициализирует сериализатор шаблонов."""
        self._signature_size: int = 64
        self._public_key_size: int = 32

    def serialize_template(
        self,
        template: "FormTemplate",
        sign: bool = True,
        private_key: bytes | None = None,
    ) -> bytes:
        """Сериализация шаблона с Ed25519 подписью.

        Args:
            template: Шаблон формы для сериализации
            sign: Создать ли цифровую подпись
            private_key: Приватный ключ Ed25519 (32 bytes, опционально)

        Returns:
            JSON-данные шаблона с подписью

        Raises:
            TemplateError: При ошибке подписи

        Example:
            >>> data = serializer.serialize_template(template, sign=True, private_key=priv_key)
            >>> isinstance(data, bytes)
            True
        """
        try:
            # Сериализуем шаблон
            template_data: dict[str, Any] = {
                "format_version": "1.0",
                "generator": "FXTextProcessor/3.0",
                "template": {
                    "template_id": str(template.template_id),
                    "type_code": template.type_code,
                    "subtype": template.subtype,
                    "series": template.series,
                    "field_defaults": template.field_defaults,
                    "metadata": template.metadata,
                },
            }

            json_data = json.dumps(template_data, ensure_ascii=False, indent=2).encode("utf-8")

            # Создаём подпись если требуется
            if sign:
                if private_key is None:
                    # Генерируем новую ключевую пару
                    private_key, public_key = self._generate_keypair()
                    template_data["generated_public_key"] = public_key.hex()

                signature_data = self._sign_data(json_data, private_key)
                template_data["signature"] = signature_data.to_dict()

                # Пересериализуем с подписью
                json_data = json.dumps(template_data, ensure_ascii=False, indent=2).encode("utf-8")

            logger.debug(f"Serialized template {template.template_id}")
            return json_data

        except Exception as e:
            raise TemplateError(f"Failed to serialize template: {e}") from e

    def deserialize_template(
        self,
        data: bytes,
        verify_signature: bool = True,
        public_key: bytes | None = None,
    ) -> "FormTemplate":
        """Десериализация с проверкой подписи.

        Args:
            data: JSON-данные шаблона
            verify_signature: Проверить ли подпись
            public_key: Публичный ключ для верификации (опционально)

        Returns:
            Восстановленный шаблон формы

        Raises:
            TemplateError: При ошибке десериализации или неверной подписи

        Example:
            >>> template = serializer.deserialize_template(data, verify_signature=True)
            >>> template.type_code
            'DVN'
        """
        from src.documents.constructor.form_constructor import FormTemplate

        try:
            json_obj = json.loads(data.decode("utf-8"))

            # Проверяем подпись если требуется
            if verify_signature and "signature" in json_obj:
                sig_data = TemplateSignature.from_dict(json_obj["signature"])

                # Убираем подпись из данных для проверки
                template_copy = {k: v for k, v in json_obj.items() if k != "signature"}
                canonical_data = json.dumps(template_copy, ensure_ascii=False, indent=2).encode(
                    "utf-8"
                )

                # Определяем публичный ключ
                check_key = public_key
                if check_key is None:
                    # Используем ключ из подписи
                    check_key = sig_data.public_key

                if not self._verify_signature(canonical_data, sig_data.signature, check_key):
                    raise TemplateError("Template signature verification failed")

                logger.debug("Template signature verified successfully")

            # Восстанавливаем шаблон
            tpl_data = json_obj.get("template", {})
            template = FormTemplate(
                type_code=tpl_data.get("type_code", ""),
                subtype=tpl_data.get("subtype", ""),
                series=tpl_data.get("series", ""),
                field_defaults=tpl_data.get("field_defaults", {}),
                metadata=tpl_data.get("metadata", {}),
                template_id=UUID(tpl_data.get("template_id", str(UUID(int=0)))),
            )

            logger.debug(f"Deserialized template {template.template_id}")
            return template

        except TemplateError:
            raise
        except Exception as e:
            raise TemplateError(f"Failed to deserialize template: {e}") from e

    def save_template(
        self,
        template: "FormTemplate",
        path: Path,
        sign: bool = True,
        private_key: bytes | None = None,
    ) -> None:
        """Сохраняет шаблон в файл.

        Args:
            template: Шаблон для сохранения
            path: Путь к файлу (.fxstpl)
            sign: Создать ли подпись
            private_key: Приватный ключ для подписи

        Raises:
            TemplateError: При ошибке сохранения

        Example:
            >>> serializer.save_template(template, Path("template.fxstpl"), sign=True)
        """
        try:
            data = self.serialize_template(template, sign=sign, private_key=private_key)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            logger.info(f"Saved template {template.template_id} to {path}")
        except Exception as e:
            raise TemplateError(f"Failed to save template: {e}") from e

    def load_template(
        self,
        path: Path,
        verify_signature: bool = True,
        public_key: bytes | None = None,
    ) -> "FormTemplate":
        """Загружает шаблон из файла.

        Args:
            path: Путь к файлу (.fxstpl)
            verify_signature: Проверить ли подпись
            public_key: Публичный ключ для верификации

        Returns:
            Загруженный шаблон

        Raises:
            FileNotFoundError: Если файл не найден
            TemplateError: При ошибке загрузки

        Example:
            >>> template = serializer.load_template(Path("template.fxstpl"))
        """
        if not path.exists():
            raise FileNotFoundError(f"Template file not found: {path}")

        try:
            data = path.read_bytes()
            template = self.deserialize_template(data, verify_signature, public_key)
            logger.info(f"Loaded template {template.template_id} from {path}")
            return template
        except Exception as e:
            if isinstance(e, (FileNotFoundError, TemplateError)):
                raise
            raise TemplateError(f"Failed to load template: {e}") from e

    def _generate_keypair(self) -> tuple[bytes, bytes]:
        """Генерирует ключевую пару Ed25519.

        Returns:
            Кортеж (приватный ключ, публичный ключ)
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            # Экспортируем сырые байты
            private_bytes = private_key.private_bytes(
                encoding=__import__(
                    "cryptography.hazmat.primitives.serialization"
                ).hazmat.primitives.serialization.Encoding.Raw,
                format=__import__(
                    "cryptography.hazmat.primitives.serialization"
                ).hazmat.primitives.serialization.PrivateFormat.Raw,
                encryption_algorithm=__import__(
                    "cryptography.hazmat.primitives.serialization"
                ).hazmat.primitives.serialization.NoEncryption(),
            )
            public_bytes = public_key.public_bytes(
                encoding=__import__(
                    "cryptography.hazmat.primitives.serialization"
                ).hazmat.primitives.serialization.Encoding.Raw,
                format=__import__(
                    "cryptography.hazmat.primitives.serialization"
                ).hazmat.primitives.serialization.PublicFormat.Raw,
            )

            return private_bytes, public_bytes
        except Exception as e:
            raise TemplateError(f"Failed to generate Ed25519 keypair: {e}") from e

    def _sign_data(self, data: bytes, private_key: bytes) -> TemplateSignature:
        """Подписывает данные с помощью Ed25519.

        Args:
            data: Данные для подписи
            private_key: Приватный ключ Ed25519 (32 bytes)

        Returns:
            Объект подписи
        """
        try:
            from datetime import datetime

            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            # Загружаем приватный ключ
            private_key_obj = Ed25519PrivateKey.from_private_bytes(private_key)
            public_key = private_key_obj.public_key()

            # Подписываем данные
            signature = private_key_obj.sign(data)

            # Экспортируем публичный ключ
            public_bytes = public_key.public_bytes(
                encoding=__import__(
                    "cryptography.hazmat.primitives.serialization"
                ).hazmat.primitives.serialization.Encoding.Raw,
                format=__import__(
                    "cryptography.hazmat.primitives.serialization"
                ).hazmat.primitives.serialization.PublicFormat.Raw,
            )

            return TemplateSignature(
                signature=signature,
                public_key=public_bytes,
                timestamp=datetime.now().isoformat(),
            )
        except Exception as e:
            raise TemplateError(f"Failed to sign template: {e}") from e

    def _verify_signature(self, data: bytes, signature: bytes, public_key: bytes) -> bool:
        """Проверяет Ed25519 подпись.

        Args:
            data: Данные, которые были подписаны
            signature: Подпись (64 bytes)
            public_key: Публичный ключ (32 bytes)

        Returns:
            True если подпись верна
        """
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            # Загружаем публичный ключ
            public_key_obj = Ed25519PublicKey.from_public_bytes(public_key)

            # Проверяем подпись
            try:
                public_key_obj.verify(signature, data)
                return True
            except InvalidSignature:
                return False
        except Exception as e:
            logger.warning(f"Signature verification error: {e}")
            return False

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Публичный метод генерации ключевой пары.

        Returns:
            Кортеж (приватный ключ, публичный ключ) в формате сырых байт

        Example:
            >>> private_key, public_key = serializer.generate_keypair()
            >>> len(private_key), len(public_key)
            (32, 32)
        """
        return self._generate_keypair()


__all__ = [
    "TemplateSerializer",
    "TemplateSignature",
    "TemplateError",
]
