"""Интеграционные тесты для форматов документов и шаблонов.

Покрытие:
- Полный цикл save/load для документов
- Полный цикл save/load для шаблонов
- Шифрование/расшифровка (с моками CryptoService)
- Подпись/верификация (с моками CryptoService)
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Skip tests if dependencies not available
pytest.importorskip("src.documents.format.document_format")
pytest.importorskip("src.documents.format.template_format")


class TestDocumentFormatIntegration:
    """Интеграционные тесты для DocumentFormat."""

    def test_save_load_plain_document(self, tmp_path: Path) -> None:
        """Полный цикл save/load для незашифрованного документа."""
        from src.documents.format.document_format import DocumentFormat

        # Создаём мок документа
        mock_document = MagicMock()
        mock_document.to_dict.return_value = {
            "title": "Test Document",
            "content": "Test content",
            "fields": {"field1": "value1"},
        }

        # Сохраняем
        fmt = DocumentFormat()
        doc_path = tmp_path / "test.fxsd"
        fmt.save(mock_document, doc_path)

        # Проверяем что файл создан
        assert doc_path.exists()

        # Загружаем (нужен мок Document.from_dict)
        with patch("src.model.document.Document") as MockDocument:
            MockDocument.from_dict.return_value = MagicMock(title="Test Document")
            loaded = fmt.load(doc_path)
            assert loaded is not None

    def test_save_encrypted_requires_crypto(self, tmp_path: Path) -> None:
        """Шифрование требует crypto service."""
        from src.documents.format.document_format import DocumentFormat

        mock_document = MagicMock()
        mock_document.to_dict.return_value = {"title": "Test"}

        fmt = DocumentFormat()
        doc_path = tmp_path / "test.fxsd.enc"

        with pytest.raises(ValueError, match="Crypto service required"):
            fmt.save(mock_document, doc_path, encrypt=True)

    def test_load_encrypted_requires_crypto_and_key(self, tmp_path: Path) -> None:
        """Загрузка зашифрованного документа требует crypto и key."""
        from src.documents.format.document_format import (
            _MAGIC_FXSD_ENC,
            DocumentFormat,
            DocumentFormatHeader,
        )

        # Создаём фейковый зашифрованный файл
        header = DocumentFormatHeader(
            magic=_MAGIC_FXSD_ENC,
            version=1,
            algorithm_id=1,
            salt=os.urandom(32),
            nonce=os.urandom(12),
            payload_length=100,
        )
        enc_path = tmp_path / "test.fxsd.enc"
        enc_path.write_bytes(header.to_bytes() + b"0" * 100)

        fmt = DocumentFormat()

        # Без crypto
        with pytest.raises(ValueError, match="Crypto service required"):
            fmt.load(enc_path)

        # С crypto но без key
        mock_crypto = MagicMock()
        with pytest.raises(ValueError, match="Encryption key required"):
            fmt.load(enc_path, crypto=mock_crypto)

    def test_encrypted_roundtrip_with_mock(self, tmp_path: Path) -> None:
        """Полный цикл шифрования/расшифровки с моком CryptoService."""
        import gzip

        from src.documents.format.document_format import DocumentFormat
        from src.security.crypto.service.crypto_service import EncryptedDocument

        # Мокаем CryptoService
        mock_crypto = MagicMock()

        # Тестовые данные (сжатые gzip, как ожидает код)
        test_key = os.urandom(32)
        test_nonce = os.urandom(12)
        test_data = b'{"format_version": "1.0", "document": {"title": "Secret"}}'
        test_ciphertext = b"encrypted_data_here"

        # Настраиваем моки - decrypt должен вернуть сжатые данные
        mock_crypto.generate_symmetric_key.return_value = test_key
        mock_crypto.encrypt_document.return_value = EncryptedDocument(
            nonce=test_nonce,
            ciphertext=test_ciphertext,
            algorithm_id="aes-256-gcm",
        )
        # decrypt_document возвращает сжатые gzip данные
        mock_crypto.decrypt_document.return_value = gzip.compress(test_data, compresslevel=9)

        # Мокаем документ
        mock_document = MagicMock()
        mock_document.to_dict.return_value = {"title": "Secret Document"}

        # Сохраняем с шифрованием
        fmt = DocumentFormat()
        doc_path = tmp_path / "secret.fxsd.enc"
        returned_key = fmt.save(mock_document, doc_path, encrypt=True, crypto=mock_crypto)

        assert returned_key == test_key
        assert doc_path.exists()
        mock_crypto.encrypt_document.assert_called_once()

        # Загружаем
        with patch("src.model.document.Document") as MockDocument:
            MockDocument.from_dict.return_value = MagicMock(title="Secret Document")
            loaded = fmt.load(doc_path, crypto=mock_crypto, key=test_key)
            assert loaded is not None
            mock_crypto.decrypt_document.assert_called_once()


class TestTemplateFormatIntegration:
    """Интеграционные тесты для TemplateFormat."""

    def test_save_load_plain_template(self, tmp_path: Path) -> None:
        """Полный цикл save/load для незашифрованного шаблона."""
        from src.documents.format.template_format import TemplateFormat
        from src.documents.types.type_schema import TypeSchema

        # Создаём простую схему (используем правильный FieldType)
        schema = TypeSchema.from_dict({
            "fields": [
                {
                    "field_id": "title",
                    "field_type": "text_input",  # Правильный FieldType
                    "label": "Title",
                    "required": True,
                }
            ],
            "version": "1.0",
        })

        fmt = TemplateFormat()
        tpl_path = tmp_path / "template.fxstpl"

        # Сохраняем
        fmt.save(schema, tpl_path)

        # Проверяем
        assert tpl_path.exists()

        # Загружаем
        loaded = fmt.load(tpl_path)
        assert loaded is not None
        assert len(loaded.fields) == 1

    def test_encrypted_roundtrip_with_mock(self, tmp_path: Path) -> None:
        """Полный цикл шифрования/расшифровки шаблона с моком."""
        import gzip

        from src.documents.format.template_format import TemplateFormat
        from src.documents.types.type_schema import TypeSchema
        from src.security.crypto.service.crypto_service import EncryptedDocument

        # Мокаем CryptoService
        mock_crypto = MagicMock()

        # Тестовые данные (сжатые gzip)
        test_key = os.urandom(32)
        test_nonce = os.urandom(12)
        test_data = b'{"format_version": "1.0", "template": {"fields": [], "version": "1.0"}}'
        test_ciphertext = b"encrypted_template"

        # Настраиваем моки
        mock_crypto.generate_symmetric_key.return_value = test_key
        mock_crypto.encrypt_document.return_value = EncryptedDocument(
            nonce=test_nonce,
            ciphertext=test_ciphertext,
            algorithm_id="aes-256-gcm",
        )
        # decrypt_document возвращает сжатые gzip данные
        mock_crypto.decrypt_document.return_value = gzip.compress(test_data, compresslevel=9)

        # Создаём схему
        schema = TypeSchema.from_dict({
            "fields": [],
            "version": "1.0",
        })

        # Сохраняем с шифрованием
        fmt = TemplateFormat()
        tpl_path = tmp_path / "template.fxstpl.enc"
        returned_key = fmt.save(schema, tpl_path, encrypt=True, crypto=mock_crypto)

        assert returned_key == test_key
        assert tpl_path.exists()

        # Загружаем
        loaded = fmt.load(tpl_path, crypto=mock_crypto, key=test_key)
        assert loaded is not None

    def test_signed_roundtrip_with_mock(self, tmp_path: Path) -> None:
        """Полный цикл подписи/верификации с моком."""
        from src.documents.format.template_format import TemplateFormat
        from src.documents.types.type_schema import TypeSchema

        # Мокаем CryptoService
        mock_crypto = MagicMock()
        mock_crypto.sign_document.return_value = MagicMock(
            signature=b"test_signature",
            algorithm_id="Ed25519",
        )
        mock_crypto.verify_signature.return_value = True

        # Создаём схему (используем правильный FieldType)
        schema = TypeSchema.from_dict({
            "fields": [{"field_id": "test", "field_type": "text_input", "label": "Test"}],
            "version": "1.0",
        })

        # Сохраняем с подписью
        fmt = TemplateFormat()
        tpl_path = tmp_path / "signed.fxstpl"

        private_key = os.urandom(32)
        public_key = os.urandom(32)

        fmt.save(
            schema, tpl_path,
            sign=True,
            crypto=mock_crypto,
            private_key=private_key,
            public_key=public_key,
        )

        assert tpl_path.exists()

        # Проверяем что файл подписи создан
        sig_path = tpl_path.parent / (tpl_path.stem + ".fxssig")
        assert sig_path.exists()

        # Загружаем с верификацией
        loaded = fmt.load(tpl_path, verify_sign=True, crypto=mock_crypto)
        assert loaded is not None
        mock_crypto.verify_signature.assert_called()


class TestFormatSecurity:
    """Тесты безопасности форматов."""

    def test_encrypted_file_magic_validation(self, tmp_path: Path) -> None:
        """Валидация magic bytes для зашифрованных файлов."""
        from src.documents.format.document_format import (
            _MAGIC_FXSD_ENC,
            DocumentFormat,
            DocumentFormatHeader,
        )

        # Создаём файл с неверными magic bytes
        bad_file = tmp_path / "fake.fxsd.enc"
        bad_file.write_bytes(b"XXXX" + b"\x00" * 100)

        fmt = DocumentFormat()
        mock_crypto = MagicMock()

        with pytest.raises(ValueError, match="Invalid magic"):
            fmt.load(bad_file, crypto=mock_crypto, key=b"test_key")

    def test_payload_size_validation(self, tmp_path: Path) -> None:
        """Валидация размера payload."""
        from src.documents.format.document_format import (
            _MAGIC_FXSD_ENC,
            DocumentFormat,
            DocumentFormatHeader,
        )

        # Создаём заголовок с неверным размером payload
        header = DocumentFormatHeader(
            magic=_MAGIC_FXSD_ENC,
            version=1,
            algorithm_id=1,
            salt=os.urandom(32),
            nonce=os.urandom(12),
            payload_length=1000,  # Указываем 1000 байт
        )
        # Но записываем только 10 байт после заголовка
        bad_file = tmp_path / "truncated.fxsd.enc"
        bad_file.write_bytes(header.to_bytes() + b"0" * 10)

        fmt = DocumentFormat()
        mock_crypto = MagicMock()

        with pytest.raises(ValueError, match="Payload size mismatch"):
            fmt.load(bad_file, crypto=mock_crypto, key=b"test_key")

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Ошибка при отсутствии файла."""
        from src.documents.format.document_format import DocumentFormat

        fmt = DocumentFormat()
        nonexistent = tmp_path / "nonexistent.fxsd"

        with pytest.raises(FileNotFoundError):
            fmt.load(nonexistent)

    def test_get_format_info_encrypted(self, tmp_path: Path) -> None:
        """Получение информации о зашифрованном файле."""
        from src.documents.format.document_format import (
            _MAGIC_FXSD_ENC,
            DocumentFormat,
            DocumentFormatHeader,
        )

        # Создаём корректный зашифрованный файл
        header = DocumentFormatHeader(
            magic=_MAGIC_FXSD_ENC,
            version=1,
            algorithm_id=1,
            salt=os.urandom(32),
            nonce=os.urandom(12),
            payload_length=256,
        )
        enc_file = tmp_path / "doc.fxsd.enc"
        enc_file.write_bytes(header.to_bytes() + b"0" * 256)

        fmt = DocumentFormat()
        info = fmt.get_format_info(enc_file)

        assert info["format"] == "encrypted"
        assert info["version"] == 1
        assert info["algorithm_id"] == 1
        assert info["payload_size"] == 256

    def test_is_encrypted_file(self, tmp_path: Path) -> None:
        """Проверка является ли файл зашифрованным."""
        from src.documents.format.document_format import (
            _MAGIC_FXSD_ENC,
            DocumentFormat,
        )

        fmt = DocumentFormat()

        # По расширению
        enc_file = tmp_path / "doc.fxsd.enc"
        enc_file.write_bytes(_MAGIC_FXSD_ENC + b"\x00" * 100)
        assert fmt.is_encrypted_file(enc_file) is True

        # По magic bytes
        enc_file2 = tmp_path / "doc.fxsd"
        enc_file2.write_bytes(_MAGIC_FXSD_ENC + b"\x00" * 100)
        assert fmt.is_encrypted_file(enc_file2) is True

        # Обычный JSON
        plain_file = tmp_path / "doc.fxsd"
        plain_file.write_bytes(b'{"format_version": "1.0"}')
        assert fmt.is_encrypted_file(plain_file) is False


class TestTemplateFormatSecurity:
    """Тесты безопасности для TemplateFormat."""

    def test_signature_missing_fields(self, tmp_path: Path) -> None:
        """Ошибка при отсутствии полей в файле подписи."""
        from src.documents.format.template_format import TemplateFormat
        from src.documents.types.type_schema import TypeSchema

        # Создаём схему (используем правильный FieldType)
        schema = TypeSchema.from_dict({"fields": [], "version": "1.0"})

        # Сохраняем без подписи
        fmt = TemplateFormat()
        tpl_path = tmp_path / "template.fxstpl"
        fmt.save(schema, tpl_path)

        # Создаём некорректный файл подписи
        sig_path = tmp_path / "template.fxssig"
        sig_path.write_bytes(b'{"signature": "abc"}')  # Нет public_key

        mock_crypto = MagicMock()
        mock_crypto.verify_signature.return_value = False

        # Загружаем с верификацией - должно вернуть False
        result = fmt._verify_signature(b"test data", sig_path, mock_crypto)
        assert result is False

    def test_signature_invalid_hex(self, tmp_path: Path) -> None:
        """Ошибка при неверном hex-encoding в подписи."""
        from src.documents.format.template_format import TemplateFormat

        # Создаём файл подписи с неверным hex
        sig_path = tmp_path / "bad.fxssig"
        sig_path.write_bytes(b'{"signature": "not_hex!", "public_key": "abc123"}')

        mock_crypto = MagicMock()

        fmt = TemplateFormat()
        result = fmt._verify_signature(b"test data", sig_path, mock_crypto)
        assert result is False