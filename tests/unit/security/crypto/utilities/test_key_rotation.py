"""
Тесты для модуля управления ротацией ключей.

Покрытие:
- KeyRotationStatus: создание, to_dict / from_dict (roundtrip, опциональные поля)
- KeyRotationManager.rotate_key: нормальный сценарий, авто-генерация ключа,
  ключ не найден, несовпадение длины, счётчик ротаций, next_rotation при
  включённой/выключенной авто-ротации
- KeyRotationManager.schedule_rotation: нормально, interval_days <= 0
- KeyRotationManager.get_rotation_status: с мета и без
- KeyRotationManager.list_due_for_rotation: просроченные / свежие / нет мета
- KeyRotationManager.get_key_age_days: по rotated_at, по created_at, нет мета,
  битое значение
- _load_rotation_meta: битый JSON, невалидный корень, UnicodeDecodeError
- _save_rotation_meta / _meta_key: прозрачно через другие методы

Coverage target: 95%+

Author: Mike Voyager
Version: 1.0
Date: March 10, 2026
"""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import json
import logging
import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import pytest
from src.security.crypto.core.exceptions import CryptoKeyError
from src.security.crypto.utilities.config import CryptoConfig
from src.security.crypto.utilities.key_rotation import (
    _ROTATION_META_PREFIX,  # noqa: PLC2701
    KeyRotationManager,
    KeyRotationStatus,
)

# ==============================================================================
# ВСПОМОГАТЕЛЬНЫЙ MOCK ХРАНИЛИЩА
# ==============================================================================

_NOW_ISO = "2026-03-10T12:00:00+00:00"


class _FakeStorage:
    """Простой in-memory mock SecureStorage."""

    def __init__(self) -> None:
        self._data: Dict[str, bytes] = {}

    def has_key(self, name: str) -> bool:
        return name in self._data

    def store_key(self, name: str, data: bytes, **_: Any) -> None:
        self._data[name] = data

    def retrieve_key(self, name: str) -> bytes:
        return self._data[name]

    def list_keys(self) -> List[str]:
        return list(self._data.keys())


def _storage_with_key(key_name: str, key_bytes: bytes = b"\x00" * 32) -> _FakeStorage:
    """Создаёт хранилище с одним ключом."""
    s = _FakeStorage()
    s.store_key(key_name, key_bytes)
    return s


def _storage_with_meta(
    key_name: str,
    meta: Dict[str, Any],
    key_bytes: bytes = b"\x00" * 32,
) -> _FakeStorage:
    """Хранилище с ключом и его метаданными ротации."""
    s = _storage_with_key(key_name, key_bytes)
    s.store_key(
        f"{_ROTATION_META_PREFIX}{key_name}",
        json.dumps(meta, separators=(",", ":")).encode(),
    )
    return s


def _default_config(auto: bool = True, interval: int = 90) -> CryptoConfig:
    return replace(
        CryptoConfig.default(),
        auto_rotation_enabled=auto,
        rotation_interval_days=interval,
    )


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture
def storage() -> _FakeStorage:
    return _FakeStorage()


@pytest.fixture
def manager(storage: _FakeStorage) -> KeyRotationManager:
    return KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]


# ==============================================================================
# KeyRotationStatus
# ==============================================================================


class TestKeyRotationStatus:
    def test_defaults(self) -> None:
        """Проверка значений по умолчанию."""
        status = KeyRotationStatus(key_id="k", created_at=_NOW_ISO)

        assert status.key_id == "k"
        assert status.created_at == _NOW_ISO
        assert status.rotated_at is None
        assert status.rotation_count == 0
        assert status.next_rotation is None

    def test_frozen(self) -> None:
        """Статус неизменяем."""
        status = KeyRotationStatus(key_id="k", created_at=_NOW_ISO)
        with pytest.raises((AttributeError, TypeError)):
            status.rotation_count = 999  # type: ignore[misc]

    def test_to_dict_all_fields(self) -> None:
        status = KeyRotationStatus(
            key_id="key-1",
            created_at="2026-01-01T00:00:00+00:00",
            rotated_at="2026-03-01T00:00:00+00:00",
            rotation_count=3,
            next_rotation="2026-06-01T00:00:00+00:00",
        )
        d = status.to_dict()

        assert d["key_id"] == "key-1"
        assert d["created_at"] == "2026-01-01T00:00:00+00:00"
        assert d["rotated_at"] == "2026-03-01T00:00:00+00:00"
        assert d["rotation_count"] == 3
        assert d["next_rotation"] == "2026-06-01T00:00:00+00:00"

    def test_to_dict_none_fields(self) -> None:
        """None-поля присутствуют в словаре."""
        status = KeyRotationStatus(key_id="k", created_at=_NOW_ISO)
        d = status.to_dict()

        assert "rotated_at" in d
        assert d["rotated_at"] is None
        assert "next_rotation" in d
        assert d["next_rotation"] is None

    def test_from_dict_roundtrip(self) -> None:
        original = KeyRotationStatus(
            key_id="k",
            created_at=_NOW_ISO,
            rotated_at="2026-02-01T00:00:00+00:00",
            rotation_count=5,
            next_rotation="2026-05-01T00:00:00+00:00",
        )
        restored = KeyRotationStatus.from_dict(original.to_dict())

        assert restored == original

    def test_from_dict_missing_optional(self) -> None:
        """from_dict работает без опциональных полей."""
        data = {"key_id": "k", "created_at": _NOW_ISO, "rotation_count": 0}
        status = KeyRotationStatus.from_dict(data)  # type: ignore[arg-type]

        assert status.rotated_at is None
        assert status.next_rotation is None

    @pytest.mark.parametrize(
        "count",
        [0, 1, 100],
        ids=["zero", "one", "many"],
    )
    def test_rotation_count_roundtrip(self, count: int) -> None:
        status = KeyRotationStatus(key_id="k", created_at=_NOW_ISO, rotation_count=count)
        assert KeyRotationStatus.from_dict(status.to_dict()).rotation_count == count


# ==============================================================================
# KeyRotationManager.rotate_key
# ==============================================================================


class TestRotateKey:
    def test_rotate_increments_counter(self) -> None:
        """Первая ротация даёт rotation_count=1."""
        storage = _storage_with_key("mykey", b"\xaa" * 32)
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        status = mgr.rotate_key("mykey", new_key=b"\xbb" * 32)

        assert status.rotation_count == 1
        assert status.key_id == "mykey"

    def test_rotate_replaces_key_in_storage(self) -> None:
        """Ключ в хранилище заменяется новым."""
        storage = _storage_with_key("mykey", b"\xaa" * 32)
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]
        new_key = b"\xcc" * 32

        mgr.rotate_key("mykey", new_key=new_key)

        assert storage.retrieve_key("mykey") == new_key

    def test_rotate_auto_generates_key_same_length(self) -> None:
        """Если new_key=None, генерируется ключ той же длины."""
        storage = _storage_with_key("k", b"\x00" * 16)
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        mgr.rotate_key("k")  # new_key=None

        assert len(storage.retrieve_key("k")) == 16

    def test_rotate_sets_rotated_at(self) -> None:
        storage = _storage_with_key("k")
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        status = mgr.rotate_key("k", b"\x11" * 32)

        assert status.rotated_at is not None
        dt = datetime.fromisoformat(status.rotated_at)
        assert dt.tzinfo is not None

    def test_rotate_preserves_created_at_from_meta(self) -> None:
        """created_at берётся из существующих метаданных."""
        original_created = "2026-01-01T00:00:00+00:00"
        storage = _storage_with_meta(
            "k",
            {"key_id": "k", "created_at": original_created, "rotation_count": 1},
        )
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        status = mgr.rotate_key("k", b"\x22" * 32)

        assert status.created_at == original_created

    def test_rotate_multiple_times_increments_counter(self) -> None:
        storage = _storage_with_key("k")
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        for i in range(1, 4):
            status = mgr.rotate_key("k", b"\xaa" * 32)
            assert status.rotation_count == i

    def test_rotate_key_not_found_raises(self) -> None:
        storage = _FakeStorage()
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        with pytest.raises(CryptoKeyError, match="mykey"):
            mgr.rotate_key("mykey", b"\x00" * 32)

    def test_rotate_wrong_length_raises(self) -> None:
        storage = _storage_with_key("k", b"\x00" * 32)
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="длина"):
            mgr.rotate_key("k", b"\x00" * 16)

    def test_rotate_sets_next_rotation_when_auto_enabled(self) -> None:
        storage = _storage_with_key("k")
        mgr = KeyRotationManager(storage, _default_config(auto=True, interval=30))  # type: ignore[arg-type]

        status = mgr.rotate_key("k", b"\x00" * 32)

        assert status.next_rotation is not None
        next_dt = datetime.fromisoformat(status.next_rotation)
        rotated_dt = datetime.fromisoformat(status.rotated_at)  # type: ignore[arg-type]
        delta = next_dt - rotated_dt
        assert 29 <= delta.days <= 30

    def test_rotate_no_next_rotation_when_auto_disabled(self) -> None:
        storage = _storage_with_key("k")
        mgr = KeyRotationManager(storage, _default_config(auto=False))  # type: ignore[arg-type]

        status = mgr.rotate_key("k", b"\x00" * 32)

        assert status.next_rotation is None

    def test_rotate_saves_meta_to_storage(self) -> None:
        """Метаданные ротации сохраняются в хранилище."""
        storage = _storage_with_key("k")
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        mgr.rotate_key("k", b"\x00" * 32)

        meta_key = f"{_ROTATION_META_PREFIX}k"
        assert storage.has_key(meta_key)
        raw = json.loads(storage.retrieve_key(meta_key))
        assert raw["key_id"] == "k"
        assert raw["rotation_count"] == 1

    def test_rotate_logs_info(self, caplog: pytest.LogCaptureFixture) -> None:
        storage = _storage_with_key("k")
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        with caplog.at_level(logging.INFO, logger="src.security.crypto.utilities.key_rotation"):
            mgr.rotate_key("k", b"\x00" * 32)

        assert any(
            "rotated" in r.message.lower() or "rotation" in r.message.lower()
            for r in caplog.records
        )


# ==============================================================================
# KeyRotationManager.schedule_rotation
# ==============================================================================


class TestScheduleRotation:
    def test_schedule_sets_next_rotation(self) -> None:
        storage = _FakeStorage()
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        mgr.schedule_rotation("k", 7)

        meta_key = f"{_ROTATION_META_PREFIX}k"
        assert storage.has_key(meta_key)
        raw = json.loads(storage.retrieve_key(meta_key))
        next_dt = datetime.fromisoformat(raw["next_rotation"])
        now = datetime.now(timezone.utc)
        delta = next_dt - now
        assert 6 <= delta.days <= 7

    def test_schedule_sets_key_id_and_created_at_if_absent(self) -> None:
        storage = _FakeStorage()
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        mgr.schedule_rotation("newkey", 30)

        raw = json.loads(storage.retrieve_key(f"{_ROTATION_META_PREFIX}newkey"))
        assert raw["key_id"] == "newkey"
        assert "created_at" in raw

    def test_schedule_preserves_existing_meta(self) -> None:
        """Существующие метаданные не затираются (только next_rotation обновляется)."""
        storage = _storage_with_meta(
            "k",
            {"key_id": "k", "created_at": "2026-01-01T00:00:00+00:00", "rotation_count": 3},
        )
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        mgr.schedule_rotation("k", 14)

        raw = json.loads(storage.retrieve_key(f"{_ROTATION_META_PREFIX}k"))
        assert raw.get("rotation_count") == 3
        assert raw.get("next_rotation") is not None

    @pytest.mark.parametrize("bad_interval", [0, -1, -100])
    def test_schedule_invalid_interval_raises(self, bad_interval: int) -> None:
        storage = _FakeStorage()
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="положительным"):
            mgr.schedule_rotation("k", bad_interval)


# ==============================================================================
# KeyRotationManager.get_rotation_status
# ==============================================================================


class TestGetRotationStatus:
    def test_returns_status_from_meta(self) -> None:
        meta = {
            "key_id": "k",
            "created_at": "2026-01-01T00:00:00+00:00",
            "rotated_at": "2026-02-01T00:00:00+00:00",
            "rotation_count": 2,
            "next_rotation": "2026-05-01T00:00:00+00:00",
        }
        storage = _storage_with_meta("k", meta)
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        status = mgr.get_rotation_status("k")

        assert status.key_id == "k"
        assert status.rotation_count == 2
        assert status.rotated_at == "2026-02-01T00:00:00+00:00"

    def test_returns_default_status_when_no_meta(self) -> None:
        """Без метаданных возвращается дефолтный статус."""
        storage = _FakeStorage()
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        status = mgr.get_rotation_status("absent")

        assert status.key_id == "absent"
        assert status.rotation_count == 0
        assert status.rotated_at is None


# ==============================================================================
# KeyRotationManager.list_due_for_rotation
# ==============================================================================


class TestListDueForRotation:
    def test_returns_overdue_keys(self) -> None:
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        storage = _storage_with_meta("overdue", {"key_id": "overdue", "next_rotation": past})
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        due = mgr.list_due_for_rotation()

        assert "overdue" in due

    def test_excludes_fresh_keys(self) -> None:
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        storage = _storage_with_meta("fresh", {"key_id": "fresh", "next_rotation": future})
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        due = mgr.list_due_for_rotation()

        assert "fresh" not in due

    def test_excludes_keys_without_next_rotation(self) -> None:
        storage = _storage_with_meta("k", {"key_id": "k", "rotation_count": 0})
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        due = mgr.list_due_for_rotation()

        assert "k" not in due

    def test_skips_meta_keys_themselves(self) -> None:
        """Ключи-метаданные не появляются в списке."""
        storage = _FakeStorage()
        meta_key = f"{_ROTATION_META_PREFIX}somekey"
        storage.store_key(meta_key, b"{}")
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        due = mgr.list_due_for_rotation()

        assert meta_key not in due

    def test_ignores_invalid_date_in_meta(self) -> None:
        """Битая дата в next_rotation не ломает метод."""
        storage = _storage_with_meta(
            "baddate", {"key_id": "baddate", "next_rotation": "not-a-date"}
        )
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        due = mgr.list_due_for_rotation()  # не должен падать

        assert "baddate" not in due

    def test_mixed_keys(self) -> None:
        """Только просроченные ключи в результате."""
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()

        storage = _FakeStorage()
        for key_name, next_rot in [("due1", past), ("due2", past), ("ok", future)]:
            storage.store_key(key_name, b"\x00" * 32)
            storage.store_key(
                f"{_ROTATION_META_PREFIX}{key_name}",
                json.dumps({"key_id": key_name, "next_rotation": next_rot}).encode(),
            )

        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]
        due = mgr.list_due_for_rotation()

        assert set(due) == {"due1", "due2"}


# ==============================================================================
# KeyRotationManager.get_key_age_days
# ==============================================================================


class TestGetKeyAgeDays:
    def test_age_by_rotated_at(self) -> None:
        """Возраст считается от последней ротации."""
        past = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        storage = _storage_with_meta("k", {"key_id": "k", "rotated_at": past, "created_at": past})
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        age = mgr.get_key_age_days("k")

        assert age == 5

    def test_age_by_created_at_when_no_rotated_at(self) -> None:
        past = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        storage = _storage_with_meta("k", {"key_id": "k", "created_at": past})
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        age = mgr.get_key_age_days("k")

        assert age == 10

    def test_zero_when_no_meta(self) -> None:
        storage = _FakeStorage()
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        assert mgr.get_key_age_days("absent") == 0

    def test_zero_for_fresh_key(self) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        storage = _storage_with_meta("k", {"key_id": "k", "rotated_at": now_iso})
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        assert mgr.get_key_age_days("k") == 0

    def test_zero_on_invalid_date(self) -> None:
        storage = _storage_with_meta("k", {"key_id": "k", "rotated_at": "not-a-date"})
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        assert mgr.get_key_age_days("k") == 0


# ==============================================================================
# _load_rotation_meta — граничные случаи
# ==============================================================================


class TestLoadRotationMeta:
    def test_empty_storage_returns_empty_dict(self, manager: KeyRotationManager) -> None:
        meta = manager._load_rotation_meta("nonexistent")
        assert meta == {}

    def test_invalid_json_returns_empty(
        self,
        manager: KeyRotationManager,
        storage: _FakeStorage,
    ) -> None:
        storage.store_key(f"{_ROTATION_META_PREFIX}bad", b"not-json!!")

        meta = manager._load_rotation_meta("bad")

        assert meta == {}

    def test_non_dict_json_returns_empty(
        self,
        manager: KeyRotationManager,
        storage: _FakeStorage,
    ) -> None:
        storage.store_key(f"{_ROTATION_META_PREFIX}bad", b"[1,2,3]")

        meta = manager._load_rotation_meta("bad")

        assert meta == {}

    def test_unicode_decode_error_returns_empty(
        self,
        manager: KeyRotationManager,
        storage: _FakeStorage,
    ) -> None:
        storage.store_key(f"{_ROTATION_META_PREFIX}bad", b"\xff\xfe bad bytes")

        meta = manager._load_rotation_meta("bad")

        assert meta == {}

    def test_partial_valid_fields_parsed(
        self,
        manager: KeyRotationManager,
        storage: _FakeStorage,
    ) -> None:
        """Только валидные поля попадают в мета."""
        raw = {
            "key_id": "k",
            "created_at": "2026-01-01T00:00:00+00:00",
            "rotation_count": 3,
            "unknown_field": "ignored",
        }
        storage.store_key(
            f"{_ROTATION_META_PREFIX}k",
            json.dumps(raw).encode(),
        )

        meta = manager._load_rotation_meta("k")

        assert meta["key_id"] == "k"
        assert meta["rotation_count"] == 3
        assert "unknown_field" not in meta

    def test_invalid_field_types_excluded(
        self,
        manager: KeyRotationManager,
        storage: _FakeStorage,
    ) -> None:
        """Поля с неверным типом не включаются."""
        raw = {"key_id": 12345, "rotation_count": "not-int", "created_at": 99}
        storage.store_key(
            f"{_ROTATION_META_PREFIX}k",
            json.dumps(raw).encode(),
        )

        meta = manager._load_rotation_meta("k")

        assert "key_id" not in meta
        assert "rotation_count" not in meta
        assert "created_at" not in meta

    def test_logs_warning_on_invalid_json(
        self,
        manager: KeyRotationManager,
        storage: _FakeStorage,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        storage.store_key(f"{_ROTATION_META_PREFIX}bad", b"{{invalid")

        with caplog.at_level(logging.WARNING, logger="src.security.crypto.utilities.key_rotation"):
            manager._load_rotation_meta("bad")

        assert any("bad" in r.message for r in caplog.records)


# ==============================================================================
# Интеграционный тест: full lifecycle
# ==============================================================================


class TestFullLifecycle:
    def test_rotate_then_status_then_age(self) -> None:
        """Полный цикл: ротация → статус → возраст."""
        storage = _storage_with_key("master", b"\xde\xad" * 16)
        config = _default_config(auto=True, interval=30)
        mgr = KeyRotationManager(storage, config)  # type: ignore[arg-type]

        rotated = mgr.rotate_key("master", b"\xbe\xef" * 16)
        assert rotated.rotation_count == 1

        status = mgr.get_rotation_status("master")
        assert status.rotation_count == 1
        assert status.rotated_at == rotated.rotated_at

        age = mgr.get_key_age_days("master")
        assert age == 0  # только что ротирован

    def test_schedule_then_list_due(self) -> None:
        """Расписание в прошлом → ключ в списке due."""
        storage = _storage_with_key("k")
        mgr = KeyRotationManager(storage, _default_config())  # type: ignore[arg-type]

        # Заглушаем past-дату напрямую через хранилище
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        storage.store_key(
            f"{_ROTATION_META_PREFIX}k",
            json.dumps({"key_id": "k", "next_rotation": past}).encode(),
        )

        due = mgr.list_due_for_rotation()
        assert "k" in due

    def test_default_config_used_when_none_passed(self) -> None:
        """Без явного config менеджер использует CryptoConfig.default()."""
        storage = _storage_with_key("k")
        mgr = KeyRotationManager(storage)  # type: ignore[arg-type]

        status = mgr.rotate_key("k", b"\x00" * 32)

        # CryptoConfig.default() имеет auto_rotation_enabled=True
        assert status.next_rotation is not None


# ==============================================================================
# Интеграционные тесты с реальным SecureStorage (без моков)
# ==============================================================================


@pytest.mark.integration
class TestKeyRotationWithRealStorage:
    """
    Тесты с реальным SecureStorage на диске.
    Проверяют, что метаданные ротации корректно сохраняются и загружаются.
    """

    @pytest.fixture
    def real_storage(self, tmp_path: Any) -> Any:
        from src.security.crypto.utilities.secure_storage import SecureStorage

        master_key = os.urandom(32)
        return SecureStorage(tmp_path / "keystore.enc", master_key)

    @pytest.fixture
    def real_manager(self, real_storage: Any) -> KeyRotationManager:
        return KeyRotationManager(real_storage, _default_config())

    def test_rotate_persists_meta_in_real_storage(
        self, real_storage: Any, real_manager: KeyRotationManager
    ) -> None:
        """После ротации метаданные сохраняются в реальном хранилище."""
        real_storage.store_key("k", b"\x00" * 32)

        status = real_manager.rotate_key("k", b"\x11" * 32)

        assert status.rotation_count == 1
        status2 = real_manager.get_rotation_status("k")
        assert status2.rotation_count == 1
        assert status2.rotated_at == status.rotated_at

    def test_meta_survives_second_manager_instance(self, tmp_path: Any) -> None:
        """Метаданные доступны из нового экземпляра менеджера с тем же файлом."""
        from src.security.crypto.utilities.secure_storage import SecureStorage

        master_key = os.urandom(32)
        path = tmp_path / "ks.enc"

        storage1 = SecureStorage(path, master_key)
        storage1.store_key("mykey", b"\xaa" * 32)
        mgr1 = KeyRotationManager(storage1, _default_config())
        mgr1.rotate_key("mykey", b"\xbb" * 32)

        storage2 = SecureStorage(path, master_key)
        mgr2 = KeyRotationManager(storage2, _default_config())
        status = mgr2.get_rotation_status("mykey")

        assert status.rotation_count == 1

    def test_list_due_with_real_storage(
        self, real_storage: Any, real_manager: KeyRotationManager
    ) -> None:
        """list_due_for_rotation работает с реальным хранилищем."""
        import json as _json

        real_storage.store_key("fresh", b"\x00" * 32)
        real_storage.store_key("old", b"\x00" * 32)

        real_manager.rotate_key("fresh", b"\x11" * 32)
        real_manager.rotate_key("old", b"\x22" * 32)

        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        real_storage.store_key(
            f"{_ROTATION_META_PREFIX}old",
            _json.dumps({"key_id": "old", "next_rotation": past}).encode(),
        )

        due = real_manager.list_due_for_rotation()
        assert "old" in due
        assert "fresh" not in due

    def test_key_replaced_in_real_storage_after_rotate(
        self, real_storage: Any, real_manager: KeyRotationManager
    ) -> None:
        """Реальный ключ в хранилище заменяется новым после rotate_key."""
        original = b"\xaa" * 32
        new_key = b"\xbb" * 32
        real_storage.store_key("target", original)

        real_manager.rotate_key("target", new_key)

        stored = real_storage.retrieve_key("target")
        assert stored == new_key
        assert stored != original
