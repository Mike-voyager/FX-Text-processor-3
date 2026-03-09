"""
Тесты для модуля зашифрованного хранилища ключей.

Покрытие:
- __init__: неверный размер master_key → InvalidParameterError
- __init__: создание нового хранилища / загрузка существующего
- store_key / retrieve_key: roundtrip, метаданные
- retrieve_key: ключ не найден → CryptoKeyError
- delete_key: удаление, ключ не найден → CryptoKeyError
- list_keys: пустой список, несколько ключей, сортировка
- has_key: наличие / отсутствие
- get_metadata: наличие, дефолтные метаданные, ключ не найден → CryptoKeyError
- export_keystore / import_keystore: roundtrip
- import_keystore: битые данные → DecryptionFailedError
- save / load / delete (KeyStoreProtocol)
- compress=True: roundtrip через сжатие
- Персистентность: сохранение на диск, загрузка новым экземпляром
- _decrypt_data: слишком короткие данные → DecryptionFailedError
- Thread-safety: concurrent store не выбрасывает исключений

Coverage target: 95%+

Author: Mike Voyager
Version: 1.0
Date: March 10, 2026
"""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import os
import threading
from pathlib import Path

import pytest
from src.security.crypto.core.exceptions import (
    CryptoKeyError,
    DecryptionFailedError,
    InvalidParameterError,
)
from src.security.crypto.utilities.secure_storage import SecureStorage

_MASTER_KEY = os.urandom(32)


def _storage(tmp_path: Path, *, compress: bool = False, key: bytes = _MASTER_KEY) -> SecureStorage:
    """Фабрика хранилища с уникальным файлом в tmp_path."""
    path = tmp_path / "keystore.enc"
    return SecureStorage(path, key, compress=compress)


# ==============================================================================
# __init__
# ==============================================================================


class TestSecureStorageInit:
    def test_wrong_master_key_size_raises(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidParameterError):
            SecureStorage(tmp_path / "ks.enc", b"\x00" * 16)  # 16 байт вместо 32

    def test_empty_master_key_raises(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidParameterError):
            SecureStorage(tmp_path / "ks.enc", b"")

    def test_correct_key_creates_storage(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        assert storage.list_keys() == []

    def test_new_file_not_created_until_write(self, tmp_path: Path) -> None:
        path = tmp_path / "ks.enc"
        _storage(tmp_path, key=os.urandom(32))
        # Файл не создаётся пока нет данных
        assert not path.exists()

    def test_loads_existing_file(self, tmp_path: Path) -> None:
        key = os.urandom(32)
        path = tmp_path / "ks.enc"
        s1 = SecureStorage(path, key)
        s1.store_key("my_key", b"\xaa" * 16)

        s2 = SecureStorage(path, key)
        assert s2.has_key("my_key")
        assert s2.retrieve_key("my_key") == b"\xaa" * 16


# ==============================================================================
# store_key / retrieve_key
# ==============================================================================


class TestStoreRetrieveKey:
    def test_roundtrip(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        data = os.urandom(32)
        storage.store_key("key1", data)
        assert storage.retrieve_key("key1") == data

    def test_retrieve_not_found_raises(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(CryptoKeyError):
            storage.retrieve_key("nonexistent")

    def test_overwrite_key(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.store_key("key1", b"\x01" * 16)
        storage.store_key("key1", b"\x02" * 16)
        assert storage.retrieve_key("key1") == b"\x02" * 16

    def test_store_with_metadata(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        meta = {"created": "2026-03-10", "algorithm": "aes-256-gcm"}
        storage.store_key("key1", b"\xbb" * 32, metadata=meta)
        stored_meta = storage.get_metadata("key1")
        assert stored_meta == meta

    def test_store_empty_key_data(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.store_key("empty", b"")
        assert storage.retrieve_key("empty") == b""

    def test_multiple_keys(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        for i in range(5):
            storage.store_key(f"key{i}", bytes([i]) * 16)
        for i in range(5):
            assert storage.retrieve_key(f"key{i}") == bytes([i]) * 16


# ==============================================================================
# delete_key
# ==============================================================================


class TestDeleteKey:
    def test_delete_existing(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.store_key("key1", b"\xcc" * 16)
        storage.delete_key("key1")
        assert not storage.has_key("key1")

    def test_delete_nonexistent_raises(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(CryptoKeyError):
            storage.delete_key("nonexistent")

    def test_delete_persists(self, tmp_path: Path) -> None:
        key = os.urandom(32)
        path = tmp_path / "ks.enc"
        s1 = SecureStorage(path, key)
        s1.store_key("key1", b"\xdd" * 16)
        s1.delete_key("key1")

        s2 = SecureStorage(path, key)
        assert not s2.has_key("key1")


# ==============================================================================
# list_keys / has_key
# ==============================================================================


class TestListHasKey:
    def test_list_empty(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        assert storage.list_keys() == []

    def test_list_sorted(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.store_key("zebra", b"z")
        storage.store_key("apple", b"a")
        storage.store_key("mango", b"m")
        assert storage.list_keys() == ["apple", "mango", "zebra"]

    def test_has_key_true(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.store_key("k", b"v")
        assert storage.has_key("k") is True

    def test_has_key_false(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        assert storage.has_key("missing") is False


# ==============================================================================
# get_metadata
# ==============================================================================


class TestGetMetadata:
    def test_default_empty_metadata(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.store_key("k", b"v")
        assert storage.get_metadata("k") == {}

    def test_metadata_roundtrip(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        meta = {"tag": "test", "version": 1}
        storage.store_key("k", b"v", metadata=meta)  # type: ignore[arg-type]
        assert storage.get_metadata("k")["tag"] == "test"

    def test_metadata_not_found_raises(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(CryptoKeyError):
            storage.get_metadata("nonexistent")

    def test_metadata_is_copy(self, tmp_path: Path) -> None:
        """Изменение возвращённых метаданных не влияет на хранилище."""
        storage = _storage(tmp_path)
        storage.store_key("k", b"v", metadata={"x": 1})
        meta = storage.get_metadata("k")
        meta["x"] = 999
        assert storage.get_metadata("k")["x"] == 1


# ==============================================================================
# export_keystore / import_keystore
# ==============================================================================


class TestExportImportKeystore:
    def test_export_empty_storage(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        data = storage.export_keystore()
        assert data == b""  # файл не создан

    def test_export_nonempty_returns_bytes(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.store_key("k", b"\xee" * 16)
        data = storage.export_keystore()
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_import_export_roundtrip(self, tmp_path: Path) -> None:
        key = os.urandom(32)
        path = tmp_path / "ks.enc"
        s1 = SecureStorage(path, key)
        s1.store_key("secret", b"\xff" * 32)
        exported = s1.export_keystore()

        path2 = tmp_path / "ks2.enc"
        s2 = SecureStorage(path2, key)
        s2.import_keystore(exported)
        assert s2.retrieve_key("secret") == b"\xff" * 32

    def test_import_corrupted_data_raises(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(DecryptionFailedError):
            storage.import_keystore(b"\x00" * 50)

    def test_import_too_short_raises(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(DecryptionFailedError):
            storage.import_keystore(b"\x00" * 10)


# ==============================================================================
# KeyStoreProtocol: save / load / delete
# ==============================================================================


class TestKeyStoreProtocol:
    def test_save_load(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.save("proto_key", b"\xaa" * 24)
        assert storage.load("proto_key") == b"\xaa" * 24

    def test_load_not_found_raises(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(CryptoKeyError):
            storage.load("missing")

    def test_delete_via_protocol(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.save("proto_key", b"\xbb" * 16)
        storage.delete("proto_key")
        assert not storage.has_key("proto_key")


# ==============================================================================
# compress=True
# ==============================================================================


class TestCompress:
    def test_compressed_roundtrip(self, tmp_path: Path) -> None:
        key = os.urandom(32)
        path = tmp_path / "ks_comp.enc"
        s1 = SecureStorage(path, key, compress=True)
        data = b"repeated_data_to_compress" * 100
        s1.store_key("comp_key", data)

        s2 = SecureStorage(path, key, compress=True)
        assert s2.retrieve_key("comp_key") == data

    def test_compressed_file_is_smaller(self, tmp_path: Path) -> None:
        key = os.urandom(32)
        data = b"aaaa" * 10000

        path_plain = tmp_path / "plain.enc"
        s_plain = SecureStorage(path_plain, key, compress=False)
        s_plain.store_key("k", data)

        path_comp = tmp_path / "comp.enc"
        s_comp = SecureStorage(path_comp, key, compress=True)
        s_comp.store_key("k", data)

        assert path_comp.stat().st_size < path_plain.stat().st_size


# ==============================================================================
# Персистентность
# ==============================================================================


class TestPersistence:
    def test_data_survives_new_instance(self, tmp_path: Path) -> None:
        key = os.urandom(32)
        path = tmp_path / "ks.enc"

        s1 = SecureStorage(path, key)
        s1.store_key("k1", b"\x11" * 16)
        s1.store_key("k2", b"\x22" * 32)

        s2 = SecureStorage(path, key)
        assert s2.retrieve_key("k1") == b"\x11" * 16
        assert s2.retrieve_key("k2") == b"\x22" * 32
        assert sorted(s2.list_keys()) == ["k1", "k2"]

    def test_wrong_key_raises_on_load(self, tmp_path: Path) -> None:
        path = tmp_path / "ks.enc"
        key1 = os.urandom(32)
        key2 = os.urandom(32)

        s1 = SecureStorage(path, key1)
        s1.store_key("k", b"\x33" * 16)

        with pytest.raises(DecryptionFailedError):
            SecureStorage(path, key2)


# ==============================================================================
# _load_from_disk edge cases
# ==============================================================================


class TestLoadFromDisk:
    def test_empty_file_results_in_empty_store(self, tmp_path: Path) -> None:
        """Пустой файл хранилища → пустой _store без ошибки."""
        key = os.urandom(32)
        path = tmp_path / "ks.enc"
        path.write_bytes(b"")
        storage = SecureStorage(path, key)
        assert storage.list_keys() == []

    def test_compress_true_loads_uncompressed_data_gracefully(self, tmp_path: Path) -> None:
        """compress=True при загрузке данных без сжатия — zlib.error подавляется."""
        key = os.urandom(32)
        path = tmp_path / "ks.enc"

        # Сохраняем без сжатия
        s1 = SecureStorage(path, key, compress=False)
        s1.store_key("k", b"\xaa" * 16)

        # Загружаем с compress=True — zlib.error должен быть подавлен
        s2 = SecureStorage(path, key, compress=True)
        assert s2.retrieve_key("k") == b"\xaa" * 16


# ==============================================================================
# _decrypt_data edge case
# ==============================================================================


class TestDecryptData:
    def test_too_short_data_raises(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        with pytest.raises(DecryptionFailedError):
            storage._decrypt_data(b"\x00" * 5)  # меньше nonce+tag


# ==============================================================================
# Thread safety
# ==============================================================================


class TestThreadSafety:
    def test_concurrent_store_no_crash(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        errors: list[Exception] = []

        def store_key(i: int) -> None:
            try:
                storage.store_key(f"key_{i}", os.urandom(16))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=store_key, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(storage.list_keys()) == 10

    def test_concurrent_read_no_crash(self, tmp_path: Path) -> None:
        storage = _storage(tmp_path)
        storage.store_key("shared", b"\xaa" * 16)
        errors: list[Exception] = []

        def read_key() -> None:
            try:
                storage.retrieve_key("shared")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=read_key) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
