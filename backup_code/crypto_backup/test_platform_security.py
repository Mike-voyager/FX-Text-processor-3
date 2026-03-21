# -*- coding: utf-8 -*-

"""
Tests for platform_security module.

Coverage:
- Memory locking (individual and full process)
- Core dump control
- Secure file deletion
- Platform capability detection
- Error handling and edge cases
"""

from __future__ import annotations

import logging
import ctypes
import errno
import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

from src.security.crypto import platform_security


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_file(tmp_path: Path) -> Path:
    """Create a temporary file with some content."""
    file_path = tmp_path / "test_file.bin"
    file_path.write_bytes(b"sensitive data" * 100)
    return file_path


@pytest.fixture
def empty_file(tmp_path: Path) -> Path:
    """Create an empty temporary file."""
    file_path = tmp_path / "empty.bin"
    file_path.touch()
    return file_path


@pytest.fixture
def symlink_file(tmp_path: Path) -> tuple[Path, Path]:
    """Create a file and a symlink to it."""
    target = tmp_path / "target.bin"
    target.write_bytes(b"secret")

    symlink = tmp_path / "link.bin"
    symlink.symlink_to(target)

    return symlink, target


# ============================================================================
# Platform Detection Tests
# ============================================================================


def test_platform_constants() -> None:
    """Test platform detection constants are booleans."""
    assert isinstance(platform_security.IS_POSIX, bool)
    assert isinstance(platform_security.IS_WINDOWS, bool)
    assert isinstance(platform_security.IS_LINUX, bool)
    assert isinstance(platform_security.IS_BSD, bool)


def test_get_platform_capabilities() -> None:
    """Test platform capability detection returns correct structure."""
    caps = platform_security.get_platform_capabilities()

    # Check all expected keys
    assert "memory_locking" in caps
    assert "memory_locking_all" in caps
    assert "core_dump_control" in caps
    assert "secure_deletion" in caps
    assert "platform" in caps
    assert "is_posix" in caps
    assert "is_windows" in caps
    assert "is_linux" in caps
    assert "is_bsd" in caps

    # Check types
    assert isinstance(caps["memory_locking"], bool)
    assert isinstance(caps["memory_locking_all"], bool)
    assert isinstance(caps["core_dump_control"], bool)
    assert isinstance(caps["secure_deletion"], bool)
    assert isinstance(caps["platform"], str)
    assert isinstance(caps["is_posix"], bool)

    # secure_deletion should always be True
    assert caps["secure_deletion"] is True


def test_platform_capabilities_consistency() -> None:
    """Test platform capabilities are consistent with actual platform."""
    caps = platform_security.get_platform_capabilities()

    if os.name == "posix":
        assert caps["is_posix"] is True
        assert caps["memory_locking"] is True
        assert caps["core_dump_control"] is True

    if sys.platform == "win32":
        assert caps["is_windows"] is True
        assert caps["memory_locking"] is False
        assert caps["core_dump_control"] is False


# ============================================================================
# _get_libc() Tests
# ============================================================================


def test_get_libc_success_linux(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test _get_libc loads libc.so.6 on Linux."""
    monkeypatch.setattr(platform_security, "IS_LINUX", True)
    monkeypatch.setattr(platform_security, "IS_BSD", False)

    mock_cdll = Mock(return_value=Mock())
    monkeypatch.setattr("ctypes.CDLL", mock_cdll)

    result = platform_security._get_libc()

    assert result is not None
    mock_cdll.assert_called_once_with("libc.so.6", use_errno=True)


def test_get_libc_success_bsd(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test _get_libc loads libc.so on BSD."""
    monkeypatch.setattr(platform_security, "IS_LINUX", False)
    monkeypatch.setattr(platform_security, "IS_BSD", True)

    mock_cdll = Mock(return_value=Mock())
    monkeypatch.setattr("ctypes.CDLL", mock_cdll)

    result = platform_security._get_libc()

    assert result is not None
    mock_cdll.assert_called_once_with("libc.so", use_errno=True)


def test_get_libc_failure_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test _get_libc returns None on OSError."""
    monkeypatch.setattr(platform_security, "IS_LINUX", True)
    monkeypatch.setattr(platform_security, "IS_BSD", False)

    def raise_oserror(*args: Any, **kwargs: Any) -> None:
        raise OSError("libc not found")

    monkeypatch.setattr("ctypes.CDLL", raise_oserror)

    result = platform_security._get_libc()
    assert result is None


def test_get_libc_unsupported_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test _get_libc returns None on unsupported platform."""
    monkeypatch.setattr(platform_security, "IS_LINUX", False)
    monkeypatch.setattr(platform_security, "IS_BSD", False)

    result = platform_security._get_libc()
    assert result is None


# ============================================================================
# _check_memory_lock_limits() Tests
# ============================================================================


def test_check_memory_lock_limits_non_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test memory limit check returns False on non-POSIX."""
    monkeypatch.setattr(platform_security, "IS_POSIX", False)

    result = platform_security._check_memory_lock_limits(1024)
    assert result is False


def test_check_memory_lock_limits_unlimited(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test memory limit check passes with unlimited limit."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_resource = Mock()
    mock_resource.getrlimit.return_value = (-1, -1)
    mock_resource.RLIMIT_MEMLOCK = 8
    mock_resource.RLIM_INFINITY = -1

    with patch.dict("sys.modules", {"resource": mock_resource}):
        result = platform_security._check_memory_lock_limits(1024 * 1024)

    assert result is True


def test_check_memory_lock_limits_sufficient(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test memory limit check passes when limit is sufficient."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_resource = Mock()
    mock_resource.getrlimit.return_value = (1024 * 1024, 1024 * 1024)
    mock_resource.RLIMIT_MEMLOCK = 8
    mock_resource.RLIM_INFINITY = -1

    with patch.dict("sys.modules", {"resource": mock_resource}):
        result = platform_security._check_memory_lock_limits(512)

    assert result is True


def test_check_memory_lock_limits_insufficient(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test memory limit check fails when limit is insufficient."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_resource = Mock()
    mock_resource.getrlimit.return_value = (1024, 1024)
    mock_resource.RLIMIT_MEMLOCK = 8
    mock_resource.RLIM_INFINITY = -1

    with patch.dict("sys.modules", {"resource": mock_resource}):
        result = platform_security._check_memory_lock_limits(2048)

    assert result is False


def test_check_memory_lock_limits_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test memory limit check returns True on exception (best effort)."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_resource = Mock()
    mock_resource.getrlimit.side_effect = Exception("getrlimit failed")
    mock_resource.RLIMIT_MEMLOCK = 8

    with patch.dict("sys.modules", {"resource": mock_resource}):
        result = platform_security._check_memory_lock_limits(1024)

    assert result is True  # Best effort on failure


# ============================================================================
# lock_memory() Tests
# ============================================================================


def test_lock_memory_non_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_memory returns False on non-POSIX systems."""
    monkeypatch.setattr(platform_security, "IS_POSIX", False)

    buffer = bytearray(32)
    result = platform_security.lock_memory(buffer)

    assert result is False


def test_lock_memory_invalid_type() -> None:
    """Test lock_memory returns False for non-bytearray."""
    result = platform_security.lock_memory(b"bytes")  # type: ignore[arg-type]
    assert result is False

    result = platform_security.lock_memory([1, 2, 3])  # type: ignore[arg-type]
    assert result is False


def test_lock_memory_empty_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_memory returns False for empty buffer."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    buffer = bytearray(0)
    result = platform_security.lock_memory(buffer)

    assert result is False


def test_lock_memory_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful memory locking."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)
    monkeypatch.setattr(platform_security, "IS_LINUX", True)

    # Mock libc
    mock_libc = Mock()
    mock_libc.mlock.return_value = 0

    def mock_get_libc() -> Mock:
        return mock_libc

    monkeypatch.setattr(platform_security, "_get_libc", mock_get_libc)

    # Mock limit check
    monkeypatch.setattr(platform_security, "_check_memory_lock_limits", lambda x: True)

    buffer = bytearray(32)
    result = platform_security.lock_memory(buffer)

    assert result is True
    mock_libc.mlock.assert_called_once()


def test_lock_memory_failure_mlock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_memory handles mlock failure."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)
    monkeypatch.setattr(platform_security, "IS_LINUX", True)

    # Mock libc with mlock failure
    mock_libc = Mock()
    mock_libc.mlock.return_value = -1

    def mock_get_libc() -> Mock:
        return mock_libc

    monkeypatch.setattr(platform_security, "_get_libc", mock_get_libc)
    monkeypatch.setattr(platform_security, "_check_memory_lock_limits", lambda x: True)
    monkeypatch.setattr("ctypes.get_errno", lambda: errno.EPERM)

    buffer = bytearray(32)
    result = platform_security.lock_memory(buffer)

    assert result is False


def test_lock_memory_no_libc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_memory handles missing libc."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)
    monkeypatch.setattr(platform_security, "_get_libc", lambda: None)
    monkeypatch.setattr(platform_security, "_check_memory_lock_limits", lambda x: True)

    buffer = bytearray(32)
    result = platform_security.lock_memory(buffer)

    assert result is False


def test_lock_memory_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_memory handles exceptions gracefully."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)
    monkeypatch.setattr(platform_security, "IS_LINUX", True)

    def mock_get_libc() -> Mock:
        raise RuntimeError("ctypes failure")

    monkeypatch.setattr(platform_security, "_get_libc", mock_get_libc)
    monkeypatch.setattr(platform_security, "_check_memory_lock_limits", lambda x: True)

    buffer = bytearray(32)
    result = platform_security.lock_memory(buffer)

    assert result is False


# ============================================================================
# unlock_memory() Tests
# ============================================================================


def test_unlock_memory_non_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test unlock_memory returns False on non-POSIX."""
    monkeypatch.setattr(platform_security, "IS_POSIX", False)

    buffer = bytearray(32)
    result = platform_security.unlock_memory(buffer)

    assert result is False


def test_unlock_memory_invalid_type() -> None:
    """Test unlock_memory returns False for non-bytearray."""
    result = platform_security.unlock_memory(b"bytes")  # type: ignore[arg-type]
    assert result is False


def test_unlock_memory_empty_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test unlock_memory returns False for empty buffer."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    buffer = bytearray(0)
    result = platform_security.unlock_memory(buffer)

    assert result is False


def test_unlock_memory_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful memory unlocking."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_libc = Mock()
    mock_libc.munlock.return_value = 0

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)

    buffer = bytearray(32)
    result = platform_security.unlock_memory(buffer)

    assert result is True
    mock_libc.munlock.assert_called_once()


def test_unlock_memory_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test unlock_memory handles munlock failure."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_libc = Mock()
    mock_libc.munlock.return_value = -1

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)
    monkeypatch.setattr("ctypes.get_errno", lambda: errno.EINVAL)

    buffer = bytearray(32)
    result = platform_security.unlock_memory(buffer)

    assert result is False


# ============================================================================
# lock_all_memory() Tests
# ============================================================================


def test_lock_all_memory_non_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_all_memory returns False on non-POSIX."""
    monkeypatch.setattr(platform_security, "IS_POSIX", False)

    result = platform_security.lock_all_memory()
    assert result is False


def test_lock_all_memory_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful mlockall."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_libc = Mock()
    mock_libc.mlockall.return_value = 0

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)

    result = platform_security.lock_all_memory()

    assert result is True
    mock_libc.mlockall.assert_called_once_with(3)  # MCL_CURRENT | MCL_FUTURE


def test_lock_all_memory_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_all_memory handles mlockall failure."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_libc = Mock()
    mock_libc.mlockall.return_value = -1

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)
    monkeypatch.setattr("ctypes.get_errno", lambda: errno.ENOMEM)

    result = platform_security.lock_all_memory()
    assert result is False


def test_lock_all_memory_no_libc(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_all_memory handles missing libc."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)
    monkeypatch.setattr(platform_security, "_get_libc", lambda: None)

    result = platform_security.lock_all_memory()
    assert result is False


# ============================================================================
# unlock_all_memory() Tests
# ============================================================================


def test_unlock_all_memory_non_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test unlock_all_memory returns False on non-POSIX."""
    monkeypatch.setattr(platform_security, "IS_POSIX", False)

    result = platform_security.unlock_all_memory()
    assert result is False


def test_unlock_all_memory_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful munlockall."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_libc = Mock()
    mock_libc.munlockall.return_value = 0

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)

    result = platform_security.unlock_all_memory()

    assert result is True
    mock_libc.munlockall.assert_called_once()


def test_unlock_all_memory_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test unlock_all_memory handles munlockall failure."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_libc = Mock()
    mock_libc.munlockall.return_value = -1

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)

    result = platform_security.unlock_all_memory()
    assert result is False


# ============================================================================
# disable_core_dumps() Tests
# ============================================================================


def test_disable_core_dumps_non_posix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test disable_core_dumps returns False on non-POSIX."""
    monkeypatch.setattr(platform_security, "IS_POSIX", False)

    result = platform_security.disable_core_dumps()
    assert result is False


def test_disable_core_dumps_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test successful core dump disabling."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_resource = Mock()
    mock_resource.RLIMIT_CORE = 4

    with patch.dict("sys.modules", {"resource": mock_resource}):
        result = platform_security.disable_core_dumps()

    assert result is True
    mock_resource.setrlimit.assert_called_once_with(4, (0, 0))


def test_disable_core_dumps_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test disable_core_dumps handles setrlimit failure."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_resource = Mock()
    mock_resource.RLIMIT_CORE = 4
    mock_resource.setrlimit.side_effect = OSError("Permission denied")

    with patch.dict("sys.modules", {"resource": mock_resource}):
        result = platform_security.disable_core_dumps()

    assert result is False


# ============================================================================
# secure_delete_file() Tests
# ============================================================================


def test_secure_delete_file_success(temp_file: Path) -> None:
    """Test successful file deletion with overwrite."""
    assert temp_file.exists()

    result = platform_security.secure_delete_file(str(temp_file))

    assert result is True
    assert not temp_file.exists()


def test_secure_delete_file_nonexistent() -> None:
    """Test secure_delete_file handles nonexistent file."""
    result = platform_security.secure_delete_file("/nonexistent/file.bin")
    assert result is False


def test_secure_delete_file_symlink(symlink_file: tuple[Path, Path]) -> None:
    """Test secure_delete_file refuses to delete symlink."""
    symlink, target = symlink_file

    result = platform_security.secure_delete_file(str(symlink))

    assert result is False
    assert symlink.exists()  # Symlink not deleted
    assert target.exists()  # Target not deleted


def test_secure_delete_file_empty(empty_file: Path) -> None:
    """Test secure_delete_file handles empty file."""
    assert empty_file.exists()
    assert empty_file.stat().st_size == 0

    result = platform_security.secure_delete_file(str(empty_file))

    assert result is True
    assert not empty_file.exists()


def test_secure_delete_file_custom_passes(temp_file: Path) -> None:
    """Test secure_delete_file with custom number of passes."""
    result = platform_security.secure_delete_file(str(temp_file), passes=5)

    assert result is True
    assert not temp_file.exists()


def test_secure_delete_file_read_only(temp_file: Path) -> None:
    """Test secure_delete_file handles read-only file."""
    # Make file read-only
    temp_file.chmod(0o444)

    result = platform_security.secure_delete_file(str(temp_file))

    # Should fail due to lack of write permission
    assert result is False
    assert temp_file.exists()

    # Cleanup
    temp_file.chmod(0o644)
    temp_file.unlink()


def test_secure_delete_file_open_fails(
    temp_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test secure_delete_file handles open failure."""
    original_open = os.open

    def mock_open(*args: Any, **kwargs: Any) -> int:
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr("os.open", mock_open)

    result = platform_security.secure_delete_file(str(temp_file))

    assert result is False


def test_secure_delete_file_write_fails(
    temp_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test secure_delete_file handles write failure."""
    original_urandom = os.urandom

    call_count = {"value": 0}

    def mock_urandom(n: int) -> bytes:
        call_count["value"] += 1
        if call_count["value"] > 1:
            raise OSError("Disk full")
        return original_urandom(n)

    monkeypatch.setattr("os.urandom", mock_urandom)

    result = platform_security.secure_delete_file(str(temp_file), passes=3)

    assert result is False
    assert temp_file.exists()  # File should still exist


def test_secure_delete_file_unlink_fails(
    temp_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test secure_delete_file handles unlink failure."""
    original_unlink = Path.unlink

    def mock_unlink(self: Path, *args: Any, **kwargs: Any) -> None:
        raise OSError("Cannot unlink")

    monkeypatch.setattr(Path, "unlink", mock_unlink)

    result = platform_security.secure_delete_file(str(temp_file))

    assert result is False


# ============================================================================
# initialize_platform_security() Tests
# ============================================================================


def test_initialize_platform_security_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test initialize_platform_security with default settings."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    # Mock functions
    disable_called = {"value": False}
    lock_all_called = {"value": False}

    def mock_disable() -> bool:
        disable_called["value"] = True
        return True

    def mock_lock_all() -> bool:
        lock_all_called["value"] = True
        return True

    monkeypatch.setattr(platform_security, "disable_core_dumps", mock_disable)
    monkeypatch.setattr(platform_security, "lock_all_memory", mock_lock_all)

    # Call with default (lock_all=False)
    platform_security.initialize_platform_security()

    assert disable_called["value"] is True
    assert lock_all_called["value"] is False  # Should not be called


def test_initialize_platform_security_lock_all(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test initialize_platform_security with lock_all=True."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    disable_called = {"value": False}
    lock_all_called = {"value": False}

    def mock_disable() -> bool:
        disable_called["value"] = True
        return True

    def mock_lock_all() -> bool:
        lock_all_called["value"] = True
        return True

    monkeypatch.setattr(platform_security, "disable_core_dumps", mock_disable)
    monkeypatch.setattr(platform_security, "lock_all_memory", mock_lock_all)

    # Call with lock_all=True
    platform_security.initialize_platform_security(lock_all=True)

    assert disable_called["value"] is True
    assert lock_all_called["value"] is True  # Should be called


def test_initialize_platform_security_non_posix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test initialize_platform_security on non-POSIX system."""
    monkeypatch.setattr(platform_security, "IS_POSIX", False)

    # Should not crash
    platform_security.initialize_platform_security()


def test_initialize_platform_security_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test initialize_platform_security handles failures gracefully."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    # Mock functions to return False (failure)
    monkeypatch.setattr(platform_security, "disable_core_dumps", lambda: False)
    monkeypatch.setattr(platform_security, "lock_all_memory", lambda: False)

    # Should not crash even if operations fail
    platform_security.initialize_platform_security(lock_all=True)


# ============================================================================
# Integration Tests
# ============================================================================


def test_lock_unlock_cycle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test full lock/unlock cycle."""
    if not platform_security.IS_POSIX:
        pytest.skip("Memory locking only on POSIX")

    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    # Mock libc
    mock_libc = Mock()
    mock_libc.mlock.return_value = 0
    mock_libc.munlock.return_value = 0

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)
    monkeypatch.setattr(platform_security, "_check_memory_lock_limits", lambda x: True)

    buffer = bytearray(b"secret" * 100)

    # Lock
    assert platform_security.lock_memory(buffer) is True

    # Use buffer
    buffer[:6] = b"public"

    # Unlock
    assert platform_security.unlock_memory(buffer) is True


def test_multiple_buffers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test locking multiple buffers."""
    if not platform_security.IS_POSIX:
        pytest.skip("Memory locking only on POSIX")

    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_libc = Mock()
    mock_libc.mlock.return_value = 0

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)
    monkeypatch.setattr(platform_security, "_check_memory_lock_limits", lambda x: True)

    buffers = [bytearray(32) for _ in range(5)]

    # Lock all
    for buf in buffers:
        assert platform_security.lock_memory(buf) is True

    assert mock_libc.mlock.call_count == 5


def test_secure_delete_workflow(tmp_path: Path) -> None:
    """Test complete secure deletion workflow."""
    # Create sensitive file
    secret_file = tmp_path / "secret.key"
    secret_file.write_bytes(b"very secret key material" * 100)

    assert secret_file.exists()
    original_size = secret_file.stat().st_size
    assert original_size > 0

    # Securely delete
    result = platform_security.secure_delete_file(str(secret_file), passes=3)

    assert result is True
    assert not secret_file.exists()


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================


def test_lock_memory_very_large_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test locking a very large buffer fails due to limits."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    # Mock limit check to fail
    monkeypatch.setattr(platform_security, "_check_memory_lock_limits", lambda x: False)

    large_buffer = bytearray(100 * 1024 * 1024)  # 100 MB
    result = platform_security.lock_memory(large_buffer)

    assert result is False


def test_secure_delete_directory(tmp_path: Path) -> None:
    """Test secure_delete_file handles directory."""
    directory = tmp_path / "testdir"
    directory.mkdir()

    result = platform_security.secure_delete_file(str(directory))

    # Should fail (directories cannot be opened in r+b mode)
    assert result is False
    assert directory.exists()


def test_secure_delete_special_characters(tmp_path: Path) -> None:
    """Test secure_delete_file with special characters in filename."""
    special_file = tmp_path / "file with spaces & 特殊字符.bin"
    special_file.write_bytes(b"data")

    result = platform_security.secure_delete_file(str(special_file))

    assert result is True
    assert not special_file.exists()


# ============================================================================
# Module Exports
# ============================================================================


def test_module_exports() -> None:
    """Test module exports correct public API."""
    expected_exports = {
        "lock_memory",
        "unlock_memory",
        "lock_all_memory",
        "unlock_all_memory",
        "disable_core_dumps",
        "secure_delete_file",
        "get_platform_capabilities",
        "initialize_platform_security",
    }

    assert set(platform_security.__all__) == expected_exports


# ============================================================================
# Additional Coverage Tests for Missing Lines
# ============================================================================


def test_get_libc_bsd_variant(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test _get_libc on BSD variant (for BSD-specific path)."""
    monkeypatch.setattr(platform_security, "IS_LINUX", False)
    monkeypatch.setattr(platform_security, "IS_BSD", True)

    mock_cdll = Mock(return_value=Mock())
    monkeypatch.setattr("ctypes.CDLL", mock_cdll)

    result = platform_security._get_libc()

    assert result is not None
    mock_cdll.assert_called_once_with("libc.so", use_errno=True)


def test_lock_memory_bsd_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_memory on BSD system."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)
    monkeypatch.setattr(platform_security, "IS_LINUX", False)
    monkeypatch.setattr(platform_security, "IS_BSD", True)

    mock_libc = Mock()
    mock_libc.mlock.return_value = 0

    def mock_get_libc() -> Mock:
        return mock_libc

    monkeypatch.setattr(platform_security, "_get_libc", mock_get_libc)
    monkeypatch.setattr(platform_security, "_check_memory_lock_limits", lambda x: True)

    buffer = bytearray(32)
    result = platform_security.lock_memory(buffer)

    assert result is True


def test_check_memory_lock_limits_rlim_infinity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test memory limit check with RLIM_INFINITY constant."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_resource = Mock()
    # Use RLIM_INFINITY constant
    RLIM_INFINITY = 2**63 - 1
    mock_resource.getrlimit.return_value = (RLIM_INFINITY, RLIM_INFINITY)
    mock_resource.RLIMIT_MEMLOCK = 8
    mock_resource.RLIM_INFINITY = RLIM_INFINITY

    with patch.dict("sys.modules", {"resource": mock_resource}):
        result = platform_security._check_memory_lock_limits(1024 * 1024 * 1024)

    assert result is True


def test_secure_delete_file_eloop_error(
    temp_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test secure_delete_file handles ELOOP error from os.open."""
    original_open = os.open

    def mock_open(path: str, flags: int, *args: Any, **kwargs: Any) -> int:
        err = OSError("Too many levels of symbolic links")
        err.errno = errno.ELOOP
        raise err

    monkeypatch.setattr("os.open", mock_open)

    result = platform_security.secure_delete_file(str(temp_file))

    assert result is False
    assert temp_file.exists()


def test_secure_delete_file_other_oserror(
    temp_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test secure_delete_file handles other OSError from os.open."""

    def mock_open(path: str, flags: int, *args: Any, **kwargs: Any) -> int:
        err = OSError("Device not ready")
        err.errno = errno.EIO
        raise err

    monkeypatch.setattr("os.open", mock_open)

    result = platform_security.secure_delete_file(str(temp_file))

    assert result is False


def test_lock_memory_errno_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_memory handles errno=0 case."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)
    monkeypatch.setattr(platform_security, "IS_LINUX", True)

    mock_libc = Mock()
    mock_libc.mlock.return_value = -1

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)
    monkeypatch.setattr(platform_security, "_check_memory_lock_limits", lambda x: True)
    monkeypatch.setattr("ctypes.get_errno", lambda: 0)  # errno is 0

    buffer = bytearray(32)
    result = platform_security.lock_memory(buffer)

    assert result is False


def test_unlock_memory_errno_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test unlock_memory handles errno=0 case."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_libc = Mock()
    mock_libc.munlock.return_value = -1

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)
    monkeypatch.setattr("ctypes.get_errno", lambda: 0)  # errno is 0

    buffer = bytearray(32)
    result = platform_security.unlock_memory(buffer)

    assert result is False


def test_lock_all_memory_errno_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test lock_all_memory errno=0 path."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    mock_libc = Mock()
    mock_libc.mlockall.return_value = -1

    monkeypatch.setattr(platform_security, "_get_libc", lambda: mock_libc)
    monkeypatch.setattr("ctypes.get_errno", lambda: 0)

    result = platform_security.lock_all_memory()

    assert result is False


def test_initialize_disable_core_dumps_success_logging(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test initialize logs success message for core dumps."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    monkeypatch.setattr(platform_security, "disable_core_dumps", lambda: True)
    monkeypatch.setattr(platform_security, "lock_all_memory", lambda: False)

    with caplog.at_level(logging.INFO):
        platform_security.initialize_platform_security(lock_all=False)

    # Check that success message is logged
    assert any(
        "Core dumps disabled successfully" in record.message
        for record in caplog.records
    )


def test_initialize_lock_all_memory_failure_logging(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test initialize logs warning when lock_all_memory fails."""
    monkeypatch.setattr(platform_security, "IS_POSIX", True)

    monkeypatch.setattr(platform_security, "disable_core_dumps", lambda: True)
    monkeypatch.setattr(platform_security, "lock_all_memory", lambda: False)

    with caplog.at_level(logging.WARNING):
        platform_security.initialize_platform_security(lock_all=True)

    # Check warning is logged
    assert any(
        "Failed to lock all memory" in record.message for record in caplog.records
    )
