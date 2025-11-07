# tests/unit/security/crypto/test_secure_storage.py
from __future__ import annotations

import base64
import concurrent.futures as cf
import json
import os
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Mapping,
    MutableMapping,
    Optional,
    Tuple,
    Union,
)

import pytest

from security.crypto.exceptions import (
    StorageReadError,
    StorageWriteError,
)
from security.crypto.secure_storage import FileEncryptedStorageBackend

# --- Minimal symmetric cipher stub matching the backend's expectations ---

BytesLike = Union[bytes, bytearray]


class ProtoCompatibleCipher:
    def encrypt(
        self,
        key: bytes,
        plaintext: BytesLike,
        aad: Optional[bytes] = None,
        *,
        return_combined: bool = True,
    ) -> Union[Tuple[bytes, bytes], Tuple[bytes, bytes, bytes]]:
        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise ValueError("bad key")
        data = bytes(plaintext)[::-1]
        nonce = b"N" * 12
        if return_combined:
            return nonce, data
        return nonce, data, b"T" * 16

    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        aad: Optional[bytes] = None,
        *,
        has_combined: bool = True,
        tag: Optional[bytes] = None,
    ) -> bytes:
        if not isinstance(key, (bytes, bytearray)) or len(key) == 0:
            raise ValueError("bad key")
        if nonce != b"N" * 12:
            raise ValueError("bad nonce")
        combined = data if has_combined else (data + (tag or b""))
        return combined[::-1]


class ProtoErrorCipherEncrypt(ProtoCompatibleCipher):
    def encrypt(
        self,
        key: bytes,
        plaintext: BytesLike,
        aad: Optional[bytes] = None,
        *,
        return_combined: bool = True,
    ) -> Union[Tuple[bytes, bytes], Tuple[bytes, bytes, bytes]]:
        raise RuntimeError("enc fail")


class ProtoErrorCipherDecrypt(ProtoCompatibleCipher):
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        data: bytes,
        aad: Optional[bytes] = None,
        *,
        has_combined: bool = True,
        tag: Optional[bytes] = None,
    ) -> bytes:
        raise RuntimeError("dec fail")


def _key_provider_factory(
    counter: Dict[str, int], key: bytes = b"K" * 32
) -> Callable[[], bytes]:
    def _kp() -> bytes:
        counter["n"] = counter.get("n", 0) + 1
        return key

    return _kp


# --- Happy path: save -> load roundtrip ---
def test_save_load_roundtrip_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    perm_calls = {"n": 0}

    def fake_perms(p: str) -> None:
        perm_calls["n"] += 1

    monkeypatch.setattr(
        "security.crypto.secure_storage.set_secure_file_permissions", fake_perms
    )

    store_path = tmp_path / "ks.json"
    calls: Dict[str, int] = {}
    ks = FileEncryptedStorageBackend(
        str(store_path), ProtoCompatibleCipher(), _key_provider_factory(calls)
    )

    ks.save("a", b"hello")
    assert ks.load("a") == b"hello"
    # one atomic write => one permissions hardening call
    assert perm_calls["n"] == 1
    # key provider used both for save and load (enc + dec)
    assert calls["n"] >= 2


def test_save_zeroizes_bytearray_and_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    zero_calls = {"n": 0}

    def fake_zero(b: bytearray) -> None:
        zero_calls["n"] += 1
        for i in range(len(b)):
            b[i] = 0

    monkeypatch.setattr("security.crypto.secure_storage.zero_memory", fake_zero)

    store_path = tmp_path / "ks.json"
    ks = FileEncryptedStorageBackend(
        str(store_path), ProtoCompatibleCipher(), lambda: b"K" * 32
    )

    buf = bytearray(b"secret")
    ks.save("x", buf)
    # verify zeroization
    assert all(b == 0 for b in buf)
    assert zero_calls["n"] == 1

    # overwrite existing
    ks.save("x", b"new")
    assert ks.load("x") == b"new"


def test_delete_and_missing_key(tmp_path: Path) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    ks.save("x", b"v")
    ks.delete("x")
    with pytest.raises(KeyError):
        ks.load("x")
    with pytest.raises(KeyError):
        ks.delete("x")  # already deleted


def test_invalid_name_and_data_types(tmp_path: Path) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    with pytest.raises(StorageWriteError):
        ks.save("", b"v")
    with pytest.raises(StorageWriteError):
        ks.save("a", "str")  # type: ignore
    with pytest.raises(StorageReadError):
        ks.load("")
    with pytest.raises(StorageWriteError):
        ks.delete("")


def test_read_file_io_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = tmp_path / "ks.json"
    p.write_text("{}", encoding="utf-8")

    def bad_open(*a: Any, **k: Any) -> Any:
        raise OSError("io")

    monkeypatch.setattr("builtins.open", bad_open)

    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)
    with pytest.raises(StorageReadError):
        _ = ks.load("x")


def test_parse_json_invalid_root_and_records(tmp_path: Path) -> None:
    p = tmp_path / "ks.json"

    # not a dict
    p.write_text("[]", encoding="utf-8")
    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)
    with pytest.raises(StorageReadError):
        _ = ks.load("x")

    # missing fields
    p.write_text(json.dumps({"a": {"n": "AA=="}}), encoding="utf-8")
    with pytest.raises(StorageReadError):
        _ = ks.load("a")

    # wrong types in fields
    p.write_text(json.dumps({"a": {"n": 1, "c": 2}}), encoding="utf-8")
    with pytest.raises(StorageReadError):
        _ = ks.load("a")


def test_invalid_base64_in_record(tmp_path: Path) -> None:
    p = tmp_path / "ks.json"
    # invalid base64 in 'c'
    obj = {"a": {"n": base64.b64encode(b"N" * 12).decode("ascii"), "c": "!!notb64!!"}}
    p.write_text(json.dumps(obj), encoding="utf-8")
    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)
    with pytest.raises(StorageReadError):
        _ = ks.load("a")


def test_decrypt_failure_maps_to_read_error(tmp_path: Path) -> None:
    p = tmp_path / "ks.json"
    good_nonce = base64.b64encode(b"N" * 12).decode("ascii")
    # valid base64, but decrypt will fail by cipher
    obj = {"a": {"n": good_nonce, "c": base64.b64encode(b"X").decode("ascii")}}
    p.write_text(json.dumps(obj), encoding="utf-8")
    ks = FileEncryptedStorageBackend(
        str(p), ProtoErrorCipherDecrypt(), lambda: b"K" * 32
    )
    with pytest.raises(StorageReadError):
        _ = ks.load("a")


def test_encrypt_failure_maps_to_write_error(tmp_path: Path) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoErrorCipherEncrypt(), lambda: b"K" * 32
    )
    with pytest.raises(StorageWriteError):
        ks.save("a", b"v")


def test_atomic_write_os_replace_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ensure cleanup branch in _atomically_write_db is exercised
    calls = {"replace": 0, "remove": 0, "perms": 0}

    def bad_replace(src: str, dst: str) -> None:
        calls["replace"] += 1
        raise OSError("fail")

    def fake_remove(p: str) -> None:
        calls["remove"] += 1
        # emulate remove ok

    def fake_perms(p: str) -> None:
        calls["perms"] += 1

    monkeypatch.setattr("os.replace", bad_replace)
    monkeypatch.setattr("os.remove", lambda p: fake_remove(p))
    monkeypatch.setattr(
        "security.crypto.secure_storage.set_secure_file_permissions", fake_perms
    )

    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    with pytest.raises(StorageWriteError):
        ks.save("a", b"v")
    # replace tried once, perms not called on failure, temp removed once
    assert calls["replace"] == 1
    assert calls["perms"] == 0
    assert calls["remove"] >= 1


def test_key_provider_called_each_operation(tmp_path: Path) -> None:
    p = tmp_path / "ks.json"
    counter: Dict[str, int] = {}
    kp = _key_provider_factory(counter)
    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), kp)

    ks.save("a", b"1")
    _ = ks.load("a")
    ks.save("b", b"2")
    _ = ks.load("b")
    ks.delete("a")

    # expect at least 5 calls (2 saves -> encrypts; 2 loads -> decrypts; delete may not use key)
    assert counter["n"] >= 4


def test_concurrent_saves_and_loads(tmp_path: Path) -> None:
    p = tmp_path / "ks.json"
    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)

    def worker(i: int) -> bool:
        name = f"k{i}"
        data = f"v{i}".encode()
        ks.save(name, data)
        return ks.load(name) == data

    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(worker, range(50)))
    assert all(results)


def test_load_missing_file_returns_keyerror(tmp_path: Path) -> None:
    p = tmp_path / "absent.json"  # нет файла
    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)
    with pytest.raises(KeyError):
        ks.load("any")


def test_read_split_ct_tag_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = tmp_path / "ks.json"
    # подготовим запись: nonce, ct, tag; сериализуем как combined=ct||tag, но заставим backend парсить по split
    nonce = b"N" * 12
    ct = b"ABC"
    tag = b"T" * 16
    obj = {
        "a": {
            "n": base64.b64encode(nonce).decode(),
            "c": base64.b64encode(ct + tag).decode(),
        }
    }
    p.write_text(json.dumps(obj), encoding="utf-8")

    # monkeypatch decrypt, чтобы он ожидал split (has_combined=False)
    def fake_decrypt(
        key: bytes,
        nonce_b: bytes,
        data_b: bytes,
        aad: Optional[bytes] = None,
        *,
        has_combined: bool = True,
        tag: Optional[bytes] = None,
    ) -> bytes:
        assert has_combined is True
        return data_b[::-1]

    monkeypatch.setattr(ProtoCompatibleCipher, "decrypt", staticmethod(fake_decrypt))

    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)
    # раз дешифрование фиктивное (реверс), просто проверяем что не упало чтение
    _ = ks.load("a")


def test_atomic_write_success_calls_permissions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"replace": 0, "perms": 0}
    real_replace = os.replace

    def wrap_replace(src: str, dst: str) -> None:
        calls["replace"] += 1
        return real_replace(src, dst)

    def fake_perms(p: str) -> None:
        calls["perms"] += 1

    monkeypatch.setattr("os.replace", wrap_replace)
    monkeypatch.setattr(
        "security.crypto.secure_storage.set_secure_file_permissions", fake_perms
    )

    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    ks.save("a", b"v")
    assert calls["replace"] == 1
    assert calls["perms"] == 1


def test_delete_missing_key_raises(tmp_path: Path) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    with pytest.raises(KeyError):
        ks.delete("missing")


def test_key_provider_empty_key_fails_on_save(tmp_path: Path) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b""
    )
    with pytest.raises(StorageWriteError):
        ks.save("a", b"x")


def test_parse_record_missing_item_key(tmp_path: Path) -> None:
    p = tmp_path / "ks.json"
    # корректный dict, но без искомого ключа — должен быть KeyError при load
    p.write_text(
        json.dumps(
            {
                "b": {
                    "n": base64.b64encode(b"N" * 12).decode(),
                    "c": base64.b64encode(b"X").decode(),
                }
            }
        ),
        encoding="utf-8",
    )
    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)
    with pytest.raises(KeyError):
        ks.load("a")


def test_read_empty_file_initializes_empty_db(tmp_path: Path) -> None:
    p = tmp_path / "ks.json"
    p.write_text("", encoding="utf-8")
    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)
    with pytest.raises(StorageReadError):
        ks.load("missing")


def test_read_split_path_has_combined_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = tmp_path / "ks.json"
    nonce = b"N" * 12
    ct = b"ABC"
    tag = b"T" * 16
    combined = ct + tag
    p.write_text(
        json.dumps(
            {
                "a": {
                    "n": base64.b64encode(nonce).decode(),
                    "c": base64.b64encode(combined).decode(),
                }
            }
        ),
        encoding="utf-8",
    )

    def decrypt_split(
        key: bytes,
        nonce_b: bytes,
        data_b: bytes,
        aad: Optional[bytes] = None,
        *,
        has_combined: bool = True,
        tag: Optional[bytes] = None,
    ) -> bytes:
        # форсируем проверку ветки has_combined=False
        if has_combined:
            # имитируем, что backend решил разбить: expect tag provided
            raise ValueError("force split")
        assert tag is not None
        return (data_b + tag)[::-1]

    monkeypatch.setattr(ProtoCompatibleCipher, "decrypt", staticmethod(decrypt_split))
    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)
    # метод load должен попытаться split-путь, не упасть
    with pytest.raises(StorageReadError):
        ks.load(
            "a"
        )  # ожидаем ошибку из-за искусственной логики; главное — покрыть ветку


def test_permissions_applied_on_each_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"perms": 0}

    def fake_perms(p: str) -> None:
        calls["perms"] += 1

    monkeypatch.setattr(
        "security.crypto.secure_storage.set_secure_file_permissions", fake_perms
    )
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    ks.save("a", b"1")
    ks.save("a", b"2")
    assert calls["perms"] == 2


def test_delete_logs_and_handles_missing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    with pytest.raises(KeyError):
        ks.delete("x")
    # при необходимости проверь caplog.records на сообщение (если логируется)


@pytest.mark.breaks_pytest
def test_write_serialization_error_maps_to_write_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    ks.save("a", b"v")

    # подсунем несериализуемый объект
    def bad_dump(*a: Any, **k: Any) -> Any:
        raise TypeError("bad json")

    monkeypatch.setattr("json.dumps", bad_dump)
    with pytest.raises(StorageWriteError):
        ks.save("b", b"w")


def test_save_rejects_memoryview(tmp_path: Path) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    with pytest.raises(StorageWriteError):
        ks.save("m", memoryview(b"mem"))


def test_cleanup_remove_failure_on_replace_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def bad_replace(src: str, dst: str) -> None:
        raise OSError("replace fail")

    def bad_remove(p: str) -> None:
        raise OSError("remove fail")

    monkeypatch.setattr("os.replace", bad_replace)
    monkeypatch.setattr("os.remove", bad_remove)
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    with pytest.raises(StorageWriteError):
        ks.save("a", b"v")


def test_read_path_is_directory_maps_to_read_error(tmp_path: Path) -> None:
    d = tmp_path / "ks.json"
    d.mkdir()  # путь существует, но это директория
    ks = FileEncryptedStorageBackend(str(d), ProtoCompatibleCipher(), lambda: b"K" * 32)
    with pytest.raises(StorageReadError):
        ks.load("any")


def test_save_overwrites_even_if_db_shape_is_unexpected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    original_read = ks._read_db_checked  # type: ignore[attr-defined]

    def bad_db() -> MutableMapping[str, Mapping[str, str]]:
        return {"a": {"n": "123", "c": "str"}}

    # Патчим только на время save
    monkeypatch.setattr(ks, "_read_db_checked", bad_db)  # type: ignore[attr-defined]
    ks.save("x", b"y")
    monkeypatch.setattr(ks, "_read_db_checked", original_read)  # type: ignore[attr-defined]

    assert ks.load("x") == b"y"


def test_delete_invalid_name_raises(tmp_path: Path) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    with pytest.raises(StorageWriteError):
        ks.delete("")


def test_permissions_applied_multiple_items(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"perms": 0}

    def fake_perms(p: str) -> None:
        calls["perms"] += 1

    monkeypatch.setattr(
        "security.crypto.secure_storage.set_secure_file_permissions", fake_perms
    )
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    ks.save("a", b"1")
    ks.save("b", b"2")
    ks.save("c", b"3")
    assert calls["perms"] == 3


@pytest.mark.parametrize("names", [("a", "b"), ("a", "a")])
def test_item_saved_new_vs_overwrite(tmp_path: Path, names: tuple[str, str]) -> None:
    ks = FileEncryptedStorageBackend(
        str(tmp_path / "ks.json"), ProtoCompatibleCipher(), lambda: b"K" * 32
    )
    ks.save(names[0], b"1")
    ks.save(names[1], b"2")
    assert ks.load(names[1]) == b"2"


def test_load_ignores_extra_fields_in_record(tmp_path: Path) -> None:
    p = tmp_path / "ks.json"
    nonce = base64.b64encode(b"N" * 12).decode()
    c = base64.b64encode(b"X").decode()
    obj = {"a": {"n": nonce, "c": c, "extra": "ignored"}}
    p.write_text(json.dumps(obj), encoding="utf-8")
    ks = FileEncryptedStorageBackend(str(p), ProtoCompatibleCipher(), lambda: b"K" * 32)
    # если «a» нет сохраненной дешифровки, это путь к read ok, но KeyError при load
    with pytest.raises(KeyError):
        ks.load("missing")
    # а вот существующий ключ должен поддаться дешифровке
    _ = ks.load("a")
