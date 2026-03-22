"""Тесты для модуля document_format.

Покрытие:
- DocumentFormatHeader dataclass
- DocumentFormat сериализация/десериализация
- Шифрование/расшифрование (mock)
- get_format_info()
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from src.documents.format.document_format import (
    DocumentFormat,
    DocumentFormatHeader,
)


class TestDocumentFormatHeader:
    """Тесты для DocumentFormatHeader."""

    def test_create_valid_header(self) -> None:
        """Создание валидного заголовка."""
        header = DocumentFormatHeader(
            magic=b"FXSD",
            version=1,
            algorithm_id=1,
            salt=b"x" * 32,
            nonce=b"y" * 12,
            payload_length=1024,
        )
        assert header.magic == b"FXSD"
        assert header.version == 1

    def test_invalid_magic(self) -> None:
        """Невалидный magic вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid magic"):
            DocumentFormatHeader(
                magic=b"XXXX",
                version=1,
                algorithm_id=1,
                salt=b"x" * 32,
                nonce=b"y" * 12,
                payload_length=1024,
            )

    def test_invalid_version(self) -> None:
        """Невалидная версия вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid version"):
            DocumentFormatHeader(
                magic=b"FXSD",
                version=0,
                algorithm_id=1,
                salt=b"x" * 32,
                nonce=b"y" * 12,
                payload_length=1024,
            )

    def test_invalid_salt_size(self) -> None:
        """Неверный размер salt вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid salt size"):
            DocumentFormatHeader(
                magic=b"FXSD",
                version=1,
                algorithm_id=1,
                salt=b"x" * 16,  # Wrong size
                nonce=b"y" * 12,
                payload_length=1024,
            )

    def test_invalid_nonce_size(self) -> None:
        """Неверный размер nonce вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid nonce size"):
            DocumentFormatHeader(
                magic=b"FXSD",
                version=1,
                algorithm_id=1,
                salt=b"x" * 32,
                nonce=b"y" * 8,  # Wrong size
                payload_length=1024,
            )

    def test_invalid_payload_length(self) -> None:
        """Отрицательная длина payload вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid payload_length"):
            DocumentFormatHeader(
                magic=b"FXSD",
                version=1,
                algorithm_id=1,
                salt=b"x" * 32,
                nonce=b"y" * 12,
                payload_length=-1,
            )

    def test_to_bytes(self) -> None:
        """Сериализация в bytes."""
        header = DocumentFormatHeader(
            magic=b"FXSD",
            version=1,
            algorithm_id=1,
            salt=b"x" * 32,
            nonce=b"y" * 12,
            payload_length=1024,
        )
        data = header.to_bytes()
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_from_bytes(self) -> None:
        """Десериализация из bytes."""
        original = DocumentFormatHeader(
            magic=b"FXSD",
            version=1,
            algorithm_id=1,
            salt=b"x" * 32,
            nonce=b"y" * 12,
            payload_length=1024,
        )
        data = original.to_bytes()
        restored = DocumentFormatHeader.from_bytes(data)
        assert restored.magic == original.magic
        assert restored.version == original.version
        assert restored.payload_length == original.payload_length

    def test_from_bytes_too_short(self) -> None:
        """Короткие данные вызывают ValueError."""
        with pytest.raises(ValueError, match="Header too short"):
            DocumentFormatHeader.from_bytes(b"short")

    def test_header_size_property(self) -> None:
        """Свойство total_header_size."""
        header = DocumentFormatHeader(
            magic=b"FXSD",
            version=1,
            algorithm_id=1,
            salt=b"x" * 32,
            nonce=b"y" * 12,
            payload_length=1024,
        )
        assert header.total_header_size == 60  # 4+2+2+32+12+8


class TestDocumentFormatInit:
    """Тесты инициализации DocumentFormat."""

    def test_create_format(self) -> None:
        """Создание формата."""
        fmt = DocumentFormat()
        assert fmt is not None

    def test_create_with_crypto(self) -> None:
        """Создание с crypto сервисом."""
        mock_crypto = MagicMock()
        fmt = DocumentFormat(crypto=mock_crypto)
        assert fmt._crypto == mock_crypto


class TestSavePlain:
    """Тесты сохранения без шифрования."""

    @pytest.fixture
    def mock_document(self) -> MagicMock:
        """Мок документа."""
        doc = MagicMock()
        doc.to_dict.return_value = {"title": "Test", "content": "Data"}
        return doc

    def test_save_plain(self, tmp_path: Path, mock_document: MagicMock) -> None:
        """Сохранение без шифрования."""
        fmt = DocumentFormat()
        path = tmp_path / "test.fxsd"
        result = fmt.save(mock_document, path)
        assert path.exists()
        assert result is None  # Незашифрованный файл возвращает None

    def test_save_creates_json(self, tmp_path: Path, mock_document: MagicMock) -> None:
        """Создание JSON файла."""
        fmt = DocumentFormat()
        path = tmp_path / "test.fxsd"
        fmt.save(mock_document, path)
        content = json.loads(path.read_bytes())
        assert "format_version" in content
        assert "document" in content


class TestLoadPlain:
    """Тесты загрузки без шифрования."""

    def test_load_plain(self, tmp_path: Path) -> None:
        """Загрузка незашифрованного файла."""
        data = {
            "format_version": "1.0",
            "generator": "Test",
            "document": {"title": "Test", "sections": []},
        }
        path = tmp_path / "test.fxsd"
        path.write_bytes(json.dumps(data).encode())

        with patch("src.model.document.Document.from_dict") as mock_from_dict:
            mock_from_dict.return_value = MagicMock()
            fmt = DocumentFormat()
            fmt.load(path)
            mock_from_dict.assert_called_once()

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Файл не найден."""
        fmt = DocumentFormat()
        with pytest.raises(FileNotFoundError):
            fmt.load(tmp_path / "nonexistent.fxsd")


class TestGetFormatInfo:
    """Тесты метода get_format_info."""

    def test_plain_format_info(self, tmp_path: Path) -> None:
        """Информация о незашифрованном файле."""
        data = {
            "format_version": "1.0",
            "generator": "FXTextProcessor/3.0",
        }
        path = tmp_path / "test.fxsd"
        path.write_bytes(json.dumps(data).encode())

        fmt = DocumentFormat()
        info = fmt.get_format_info(path)
        assert info["format"] == "plain"
        assert info["version"] == "1.0"

    def test_encrypted_format_info(self, tmp_path: Path) -> None:
        """Информация о зашифрованном файле."""
        header = DocumentFormatHeader(
            magic=b"FXSD",
            version=1,
            algorithm_id=1,
            salt=b"x" * 32,
            nonce=b"y" * 12,
            payload_length=100,
        )
        path = tmp_path / "test.fxsd.enc"
        path.write_bytes(header.to_bytes() + b"payload")

        fmt = DocumentFormat()
        info = fmt.get_format_info(path)
        assert info["format"] == "encrypted"
        assert info["version"] == 1

    def test_file_not_found_raises(self, tmp_path: Path) -> None:
        """FileNotFoundError для несуществующего файла."""
        fmt = DocumentFormat()
        with pytest.raises(FileNotFoundError):
            fmt.get_format_info(tmp_path / "nonexistent")


class TestIsEncryptedFile:
    """Тесты метода is_encrypted_file."""

    def test_encrypted_by_extension(self, tmp_path: Path) -> None:
        """Определение по расширению."""
        path = tmp_path / "test.fxsd.enc"
        path.write_bytes(b"dummy")

        fmt = DocumentFormat()
        assert fmt.is_encrypted_file(path) is True

    def test_encrypted_by_magic(self, tmp_path: Path) -> None:
        """Определение по magic bytes."""
        path = tmp_path / "test.fxsd"
        path.write_bytes(b"FXSDrest")

        fmt = DocumentFormat()
        assert fmt.is_encrypted_file(path) is True

    def test_not_encrypted(self, tmp_path: Path) -> None:
        """Файл не зашифрован."""
        path = tmp_path / "test.fxsd"
        path.write_bytes(b'{"test": "data"}')

        fmt = DocumentFormat()
        assert fmt.is_encrypted_file(path) is False

    def test_nonexistent_returns_false(self, tmp_path: Path) -> None:
        """Несуществующий файл — False."""
        fmt = DocumentFormat()
        assert fmt.is_encrypted_file(tmp_path / "nonexistent") is False


class TestEncryptedSaveLoad:
    """Тесты шифрования и расшифрования."""

    def test_encrypted_save_requires_crypto(self, tmp_path: Path) -> None:
        """Сохранение с encrypt=True требует crypto."""
        fmt = DocumentFormat()
        mock_doc = MagicMock()
        mock_doc.to_dict.return_value = {}

        with pytest.raises(ValueError, match="Crypto service required"):
            fmt.save(mock_doc, tmp_path / "test.fxsd.enc", encrypt=True)

    def test_encrypted_load_requires_crypto(self, tmp_path: Path) -> None:
        """Загрузка зашифрованного требует crypto."""
        header = DocumentFormatHeader(
            magic=b"FXSD",
            version=1,
            algorithm_id=1,
            salt=b"x" * 32,
            nonce=b"y" * 12,
            payload_length=10,
        )
        path = tmp_path / "test.fxsd.enc"
        path.write_bytes(header.to_bytes() + b"0123456789")

        fmt = DocumentFormat()
        with pytest.raises(ValueError, match="Crypto service required"):
            fmt.load(path)


class TestSerializeDeserialize:
    """Тесты сериализации и десериализации."""

    @pytest.fixture
    def mock_document(self) -> MagicMock:
        """Мок документа."""
        doc = MagicMock()
        doc.to_dict.return_value = {"title": "Test", "content": "Data"}
        return doc

    def test_serialize_document(self, mock_document: MagicMock) -> None:
        """Сериализация документа."""
        fmt = DocumentFormat()
        data = fmt._serialize(mock_document)
        assert isinstance(data, bytes)
        assert b"format_version" in data
        assert b"document" in data

    def test_deserialize_document(self, tmp_path: Path) -> None:
        """Десериализация документа."""
        data = {
            "format_version": "1.0",
            "generator": "Test",
            "document": {"title": "Test", "sections": []},
        }
        fmt = DocumentFormat()
        json_bytes = json.dumps(data).encode()

        with patch("src.model.document.Document.from_dict") as mock_from_dict:
            mock_doc = MagicMock()
            mock_from_dict.return_value = mock_doc
            result = fmt._deserialize(json_bytes)
            assert result is not None


class TestEncryptedRoundTrip:
    """Тесты шифрования/дешифрования с моками."""

    def test_encrypted_round_trip(self, tmp_path: Path) -> None:
        """Полный цикл шифрования и дешифрования."""
        mock_doc = MagicMock()
        mock_doc.to_dict.return_value = {
            "title": "Test",
            "content": "Data",
            "sections": [],
        }

        mock_crypto = MagicMock()
        encrypted_result = MagicMock()
        encrypted_result.ciphertext = b"encrypted_data"
        encrypted_result.nonce = b"x" * 12
        mock_crypto.encrypt_document.return_value = encrypted_result

        # Ключ для шифрования/расшифрования
        key = b"test_key_32_bytes_for_aes_256_gcm!!"
        mock_crypto.generate_symmetric_key.return_value = key

        # Данные должны быть gzip-сжатыми
        json_data = json.dumps(
            {
                "format_version": "1.0",
                "generator": "Test",
                "document": {"title": "Test", "sections": []},
            }
        ).encode()
        # decrypt_document теперь принимает (EncryptedDocument, key)
        mock_crypto.decrypt_document.return_value = gzip.compress(json_data)

        fmt = DocumentFormat()
        path = tmp_path / "test.fxsd.enc"

        # Сохранение (ключ генерируется внутри)
        returned_key = fmt.save(mock_doc, path, encrypt=True, crypto=mock_crypto)
        assert path.exists()
        assert returned_key == key  # Ключ должен быть возвращён

        # Загрузка (ключ передаётся явно)
        mock_crypto.reset_mock()
        mock_crypto.decrypt_document.return_value = gzip.compress(json_data)

        with patch("src.model.document.Document") as mock_doc_class:
            mock_doc_class.from_dict.return_value = MagicMock()
            fmt.load(path, crypto=mock_crypto, key=key)

    def test_encrypted_save_returns_key(self, tmp_path: Path) -> None:
        """Сохранение с encrypt=True возвращает ключ шифрования."""
        mock_doc = MagicMock()
        mock_doc.to_dict.return_value = {"title": "Test"}

        mock_crypto = MagicMock()
        encrypted_result = MagicMock()
        encrypted_result.ciphertext = b"encrypted"
        encrypted_result.nonce = b"x" * 12
        mock_crypto.encrypt_document.return_value = encrypted_result

        generated_key = b"generated_key_32_bytes_for_aes_256!!"
        mock_crypto.generate_symmetric_key.return_value = generated_key

        fmt = DocumentFormat()
        path = tmp_path / "test.fxsd.enc"

        result = fmt.save(mock_doc, path, encrypt=True, crypto=mock_crypto)
        assert result == generated_key

    def test_encrypted_save_with_provided_key(self, tmp_path: Path) -> None:
        """Сохранение с переданным ключом возвращает тот же ключ."""
        mock_doc = MagicMock()
        mock_doc.to_dict.return_value = {"title": "Test"}

        mock_crypto = MagicMock()
        encrypted_result = MagicMock()
        encrypted_result.ciphertext = b"encrypted"
        encrypted_result.nonce = b"x" * 12
        mock_crypto.encrypt_document.return_value = encrypted_result

        provided_key = b"provided_key_32_bytes_for_aes_256_gcm!"

        fmt = DocumentFormat()
        path = tmp_path / "test.fxsd.enc"

        result = fmt.save(mock_doc, path, encrypt=True, crypto=mock_crypto, key=provided_key)
        assert result == provided_key
        # generate_symmetric_key не должен вызываться
        mock_crypto.generate_symmetric_key.assert_not_called()


class TestDocumentFormatHeaderValidation:
    """Тесты валидации заголовка."""

    def test_header_invalid_magic(self) -> None:
        """Неверный magic вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid magic"):
            DocumentFormatHeader(
                magic=b"XXXX",
                version=1,
                algorithm_id=1,
                salt=b"x" * 32,
                nonce=b"y" * 12,
                payload_length=100,
            )

    def test_header_invalid_version(self) -> None:
        """Неверная версия вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid version"):
            DocumentFormatHeader(
                magic=b"FXSD",
                version=0,
                algorithm_id=1,
                salt=b"x" * 32,
                nonce=b"y" * 12,
                payload_length=100,
            )

    def test_header_invalid_salt_size(self) -> None:
        """Неверный размер salt вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid salt size"):
            DocumentFormatHeader(
                magic=b"FXSD",
                version=1,
                algorithm_id=1,
                salt=b"x" * 16,  # Wrong size
                nonce=b"y" * 12,
                payload_length=100,
            )

    def test_header_invalid_nonce_size(self) -> None:
        """Неверный размер nonce вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid nonce size"):
            DocumentFormatHeader(
                magic=b"FXSD",
                version=1,
                algorithm_id=1,
                salt=b"x" * 32,
                nonce=b"y" * 8,  # Wrong size
                payload_length=100,
            )

    def test_header_invalid_payload(self) -> None:
        """Отрицательная длина payload вызывает ValueError."""
        with pytest.raises(ValueError, match="Invalid payload_length"):
            DocumentFormatHeader(
                magic=b"FXSD",
                version=1,
                algorithm_id=1,
                salt=b"x" * 32,
                nonce=b"y" * 12,
                payload_length=-1,
            )
