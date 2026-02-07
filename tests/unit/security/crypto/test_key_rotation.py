from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from src.security.crypto.exceptions import KeyNotFoundError, KeyRotationError
from src.security.crypto.key_rotation import KeyMetadata, KeyRotationManager


def test_key_metadata_creation() -> None:
    """Test basic KeyMetadata creation."""
    meta = KeyMetadata(
        key_id="test-key-001",
        created_at=datetime.now(),
    )

    assert meta.key_id == "test-key-001"
    assert meta.encryptions_count == 0
    assert meta.max_operations == 2**31
    assert meta.rotated_from is None


def test_key_metadata_needs_rotation_by_age() -> None:
    """Test rotation trigger by age."""
    old_date = datetime.now() - timedelta(days=100)
    meta = KeyMetadata(
        key_id="old-key",
        created_at=old_date,
        max_age=timedelta(days=90),
    )

    assert meta.needs_rotation()


def test_key_metadata_needs_rotation_by_operations() -> None:
    """Test rotation trigger by operation count."""
    meta = KeyMetadata(
        key_id="busy-key",
        created_at=datetime.now(),
        max_operations=1000,
    )

    meta.increment_operations(1000)
    assert meta.needs_rotation()


def test_key_metadata_no_rotation_needed() -> None:
    """Test key that doesn't need rotation."""
    meta = KeyMetadata(
        key_id="fresh-key",
        created_at=datetime.now(),
        max_age=timedelta(days=90),
        max_operations=10000,
    )

    meta.increment_operations(100)
    assert not meta.needs_rotation()


def test_key_metadata_increment_operations() -> None:
    """Test operation counter increment."""
    meta = KeyMetadata(key_id="test", created_at=datetime.now())

    assert meta.encryptions_count == 0

    meta.increment_operations()
    assert meta.encryptions_count == 1

    meta.increment_operations(5)
    assert meta.encryptions_count == 6


def test_key_metadata_serialization() -> None:
    """Test to_dict/from_dict roundtrip."""
    original = KeyMetadata(
        key_id="test-serialize",
        created_at=datetime(2024, 1, 1, 12, 0, 0),
        encryptions_count=500,
        max_age=timedelta(days=60),
        max_operations=5000,
        rotated_from="old-key-123",
    )

    # Serialize
    data = original.to_dict()
    assert isinstance(data, dict)
    assert data["key_id"] == "test-serialize"
    assert data["encryptions_count"] == 500

    # Deserialize
    restored = KeyMetadata.from_dict(data)
    assert restored.key_id == original.key_id
    assert restored.encryptions_count == original.encryptions_count
    assert restored.max_operations == original.max_operations
    assert restored.rotated_from == original.rotated_from


def test_rotation_manager_create_key() -> None:
    """Test key creation in manager."""
    with tempfile.TemporaryDirectory() as tmpdir:
        metadata_path = Path(tmpdir) / "test_keys.json"
        manager = KeyRotationManager(str(metadata_path))

        meta = manager.create_key("key-001")

        assert meta.key_id == "key-001"
        assert meta.encryptions_count == 0
        assert metadata_path.exists()


def test_rotation_manager_create_duplicate_key_raises() -> None:
    """Test that creating duplicate key raises error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = KeyRotationManager(str(Path(tmpdir) / "keys.json"))

        manager.create_key("key-001")

        with pytest.raises(KeyRotationError, match="already exists"):
            manager.create_key("key-001")


def test_rotation_manager_get_key() -> None:
    """Test retrieving key metadata."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = KeyRotationManager(str(Path(tmpdir) / "keys.json"))

        manager.create_key("key-001")

        meta = manager.get_key("key-001")
        assert meta is not None
        assert meta.key_id == "key-001"

        # Non-existent key
        assert manager.get_key("nonexistent") is None


def test_rotation_manager_rotate_key() -> None:
    """Test key rotation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = KeyRotationManager(str(Path(tmpdir) / "keys.json"))

        old_meta = manager.create_key("key-2024")
        old_meta.increment_operations(1000)

        new_meta = manager.rotate_key("key-2024", "key-2025")

        assert new_meta.key_id == "key-2025"
        assert new_meta.rotated_from == "key-2024"
        assert new_meta.encryptions_count == 0  # Reset counter


def test_rotation_manager_rotate_nonexistent_key_raises() -> None:
    """Test rotating non-existent key raises error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = KeyRotationManager(str(Path(tmpdir) / "keys.json"))

        with pytest.raises(KeyNotFoundError):
            manager.rotate_key("nonexistent", "new-key")


def test_rotation_manager_increment_operations() -> None:
    """Test incrementing operations through manager."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = KeyRotationManager(str(Path(tmpdir) / "keys.json"))

        manager.create_key("key-001")

        manager.increment_operations("key-001", 10)

        meta = manager.get_key("key-001")
        assert meta is not None
        assert meta.encryptions_count == 10


def test_rotation_manager_increment_nonexistent_key_raises() -> None:
    """Test incrementing non-existent key raises error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = KeyRotationManager(str(Path(tmpdir) / "keys.json"))

        with pytest.raises(KeyNotFoundError):
            manager.increment_operations("nonexistent", 1)


def test_rotation_manager_check_all_keys() -> None:
    """Test checking rotation status for all keys."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = KeyRotationManager(str(Path(tmpdir) / "keys.json"))

        # Create fresh key
        manager.create_key("fresh-key", max_operations=10000)

        # Create key needing rotation
        old_key = manager.create_key("old-key", max_operations=100)
        old_key.increment_operations(100)

        results = manager.check_all_keys()

        assert results["fresh-key"] is False
        assert results["old-key"] is True


def test_rotation_manager_persistence() -> None:
    """Test metadata persistence across instances."""
    with tempfile.TemporaryDirectory() as tmpdir:
        metadata_path = Path(tmpdir) / "keys.json"

        # Create manager and add keys
        manager1 = KeyRotationManager(str(metadata_path))
        manager1.create_key("key-001")
        manager1.increment_operations("key-001", 500)

        # Create new manager instance (load from disk)
        manager2 = KeyRotationManager(str(metadata_path))

        meta = manager2.get_key("key-001")
        assert meta is not None
        assert meta.encryptions_count == 500


def test_rotation_manager_load_empty_file() -> None:
    """Test loading with no existing metadata file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # File doesn't exist
        manager = KeyRotationManager(str(Path(tmpdir) / "new_keys.json"))

        # Should start empty
        assert manager.get_key("any-key") is None
