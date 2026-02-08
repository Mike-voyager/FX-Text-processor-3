# -*- coding: utf-8 -*-

"""
RU: Платформенные механизмы безопасности - защита памяти и core dumps.
EN: Platform-specific security mechanisms - memory protection and core dump control.

Features:
- Memory locking (Linux/BSD only) - individual buffers and entire process
- Core dump disabling
- Best-effort file deletion (see security warnings)
- Platform capability detection

Security Warnings:
    secure_delete_file() is NOT secure on:
    - SSD/NVMe (wear leveling)
    - Journaling filesystems (ext4, XFS)
    - Copy-on-write filesystems (Btrfs, ZFS)
    - Any filesystem with snapshots
    Use full-disk encryption for real protection!
"""

from __future__ import annotations

import ctypes
import errno
import logging
import os
import platform
import sys
from pathlib import Path
from typing import Final

_LOGGER: Final = logging.getLogger(__name__)

# Platform detection
IS_POSIX = os.name == "posix"
IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_BSD = "bsd" in sys.platform.lower()


def _get_libc() -> ctypes.CDLL | None:
    """
    Get libc handle for current platform.

    Returns:
        libc CDLL object or None if unavailable.
    """
    try:
        if IS_LINUX:
            return ctypes.CDLL("libc.so.6", use_errno=True)
        elif IS_BSD:
            return ctypes.CDLL("libc.so", use_errno=True)
        return None
    except OSError as e:
        _LOGGER.debug("Failed to load libc: %s", e)
        return None


def _check_memory_lock_limits(size: int) -> bool:
    """
    Check if we can lock the requested memory size.

    Args:
        size: Number of bytes to lock.

    Returns:
        True if within limits, False otherwise.
    """
    if not IS_POSIX:
        return False

    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)

        # RLIMIT_INFINITY
        if soft == -1 or soft == resource.RLIM_INFINITY:
            return True

        if size > soft:
            _LOGGER.warning(
                "Requested lock size %d exceeds RLIMIT_MEMLOCK soft limit %d",
                size,
                soft,
            )
            return False

        return True

    except Exception as e:
        _LOGGER.debug("Failed to check memory limits: %s", e)
        return True  # Best effort


def lock_memory(buffer: bytearray) -> bool:
    """
    Lock memory pages to prevent swapping to disk (POSIX only).

    Uses mlock(2) system call to lock pages in RAM.
    Requires CAP_IPC_LOCK capability or sufficient RLIMIT_MEMLOCK.

    Args:
        buffer: Mutable bytearray to lock. Must not be empty.

    Returns:
        True if successfully locked, False otherwise.

    Security:
        - Prevents secrets from being written to swap
        - Does NOT protect against hibernation/suspend
        - Does NOT protect against memory dumps by root
        - Does NOT protect against cold boot attacks

    Examples:
        >>> key = bytearray(b"\\x00" * 32)
        >>> if lock_memory(key):
        ...     print("Memory locked successfully")
        ... else:
        ...     print("Memory locking unavailable")
    """
    if not IS_POSIX:
        _LOGGER.debug("Memory locking only available on POSIX systems")
        return False

    if not isinstance(buffer, bytearray):
        _LOGGER.warning("lock_memory requires bytearray, got %s", type(buffer))
        return False

    if len(buffer) == 0:
        _LOGGER.debug("Cannot lock empty buffer")
        return False

    # Check limits before attempting
    if not _check_memory_lock_limits(len(buffer)):
        return False

    try:
        libc = _get_libc()
        if libc is None:
            _LOGGER.debug("libc unavailable")
            return False

        # Get buffer address
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        size = len(buffer)

        # Call mlock(2)
        result: int = libc.mlock(addr, size)

        if result == 0:
            _LOGGER.debug("Locked %d bytes in memory", size)
            return True
        else:
            errno_val = ctypes.get_errno()
            _LOGGER.warning(
                "mlock failed: errno %d (%s)",
                errno_val,
                os.strerror(errno_val) if errno_val > 0 else "unknown",
            )
            return False

    except Exception as e:
        _LOGGER.debug("Memory locking failed: %s", e)
        return False


def unlock_memory(buffer: bytearray) -> bool:
    """
    Unlock previously locked memory pages.

    Args:
        buffer: Bytearray to unlock. Must match previously locked buffer.

    Returns:
        True if successfully unlocked, False otherwise.

    Examples:
        >>> key = bytearray(b"\\x00" * 32)
        >>> lock_memory(key)
        >>> # ... use key ...
        >>> unlock_memory(key)
    """
    if not IS_POSIX or not isinstance(buffer, bytearray):
        return False

    if len(buffer) == 0:
        return False

    try:
        libc = _get_libc()
        if libc is None:
            return False

        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        size = len(buffer)

        result: int = libc.munlock(addr, size)

        if result != 0:
            errno_val = ctypes.get_errno()
            _LOGGER.debug(
                "munlock failed: errno %d (%s)",
                errno_val,
                os.strerror(errno_val) if errno_val > 0 else "unknown",
            )

        return result == 0

    except Exception as e:
        _LOGGER.debug("Memory unlocking failed: %s", e)
        return False


def lock_all_memory() -> bool:
    """
    Lock all current and future process memory pages (POSIX only).

    Uses mlockall(MCL_CURRENT | MCL_FUTURE) to lock entire process memory.
    This is more secure than individual buffer locking but requires
    higher RLIMIT_MEMLOCK and may consume significant resources.

    Requires:
        - CAP_IPC_LOCK capability OR
        - Sufficient RLIMIT_MEMLOCK (typically requires root)

    Returns:
        True if successfully locked all memory.

    Security:
        - Prevents ALL process memory from swapping
        - Includes future allocations (heap, stack)
        - May impact performance due to no swapping
        - Still vulnerable to hibernation/cold boot attacks

    Examples:
        >>> # At application startup (requires elevated privileges)
        >>> if lock_all_memory():
        ...     print("All process memory locked")
    """
    if not IS_POSIX:
        _LOGGER.debug("mlockall only available on POSIX systems")
        return False

    try:
        libc = _get_libc()
        if libc is None:
            return False

        # MCL_CURRENT = lock all current pages
        # MCL_FUTURE = lock all future pages
        MCL_CURRENT = 1
        MCL_FUTURE = 2

        result: int = libc.mlockall(MCL_CURRENT | MCL_FUTURE)

        if result == 0:
            _LOGGER.info("Locked all process memory")
            return True
        else:
            errno_val = ctypes.get_errno()
            _LOGGER.warning(
                "mlockall failed: errno %d (%s)",
                errno_val,
                os.strerror(errno_val) if errno_val > 0 else "unknown",
            )
            return False

    except Exception as e:
        _LOGGER.debug("mlockall failed: %s", e)
        return False


def unlock_all_memory() -> bool:
    """
    Unlock all process memory pages.

    Returns:
        True if successfully unlocked.

    Examples:
        >>> unlock_all_memory()  # Usually not needed - done at process exit
    """
    if not IS_POSIX:
        return False

    try:
        libc = _get_libc()
        if libc is None:
            return False

        result: int = libc.munlockall()
        return result == 0

    except Exception:
        return False


def disable_core_dumps() -> bool:
    """
    Disable core dumps to prevent secret leakage.

    Sets RLIMIT_CORE to 0 (POSIX only). This prevents the kernel
    from writing process memory to disk on crash.

    Returns:
        True if successfully disabled.

    Security:
        - Call this at application startup before loading secrets
        - Does NOT prevent memory dumps via /proc/<pid>/mem (root only)
        - Does NOT prevent ptrace() attachment (requires PR_SET_DUMPABLE)
        - Does NOT prevent hibernation dumps

    Examples:
        >>> # At application startup
        >>> if disable_core_dumps():
        ...     print("Core dumps disabled")
    """
    if not IS_POSIX:
        _LOGGER.debug("Core dump control only available on POSIX")
        return False

    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _LOGGER.info("Core dumps disabled")
        return True

    except Exception as e:
        _LOGGER.warning("Failed to disable core dumps: %s", e)
        return False


def secure_delete_file(filepath: str, passes: int = 3) -> bool:
    """
    Best-effort file deletion with overwrite (NOT cryptographically secure).

    ⚠️  SECURITY WARNING ⚠️
    This function is NOT secure on modern storage:
        - SSD/NVMe: Wear leveling redirects writes
        - Journaling FS: Old data remains in journal
        - CoW filesystems: Copy-on-write preserves old data
        - Snapshots: Data remains in snapshots
        - TRIM/discard: Not guaranteed to erase data

    This provides defense-in-depth ONLY. Real protection requires:
        1. Full-disk encryption (LUKS, BitLocker, FileVault)
        2. Secure key erasure
        3. Physical destruction of media

    Args:
        filepath: Path to file to delete. Must not be a symlink.
        passes: Number of overwrite passes (default 3).

    Returns:
        True if file was overwritten and deleted.

    Raises:
        No exceptions - returns False on any error.

    Examples:
        >>> # Delete temporary key file (best effort only!)
        >>> secure_delete_file("temp_key.bin")
        True
    """
    try:
        path = Path(filepath)

        # Security: Refuse to follow symlinks
        if path.is_symlink():
            _LOGGER.error("Refusing to delete symlink: %s", filepath)
            return False

        if not path.exists():
            _LOGGER.warning("File not found: %s", filepath)
            return False

        # Get file size
        file_size = path.stat().st_size

        if file_size == 0:
            # Just delete empty files
            path.unlink()
            _LOGGER.debug("Deleted empty file: %s", filepath)
            return True

        # Open with O_NOFOLLOW to prevent TOCTOU symlink attacks
        try:
            fd = os.open(
                str(path),
                os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError as e:
            if e.errno == errno.ELOOP:
                _LOGGER.error("Detected symlink during open: %s", filepath)
            else:
                _LOGGER.error("Failed to open file: %s", e)
            return False

        # Overwrite with random data
        try:
            with os.fdopen(fd, "r+b", closefd=True) as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
        except Exception as e:
            _LOGGER.error("Failed to overwrite file: %s", e)
            # fd will be closed by context manager
            return False

        # Remove file
        try:
            path.unlink()
            _LOGGER.debug("Securely deleted: %s (%d passes)", filepath, passes)
            return True
        except OSError as e:
            _LOGGER.error("Failed to unlink file: %s", e)
            return False

    except Exception as e:
        _LOGGER.error("Secure delete failed: %s", e)
        return False


def get_platform_capabilities() -> dict[str, bool | str]:
    """
    Detect available platform security features.

    Returns:
        Dictionary with capability flags and platform info:
        - memory_locking: Individual buffer locking available
        - memory_locking_all: Full process memory locking available
        - core_dump_control: Core dump disabling available
        - secure_deletion: Best-effort file deletion available
        - platform: Platform name (Linux, Windows, Darwin, etc.)
        - is_posix: POSIX-compatible system
        - is_windows: Windows system
        - is_linux: Linux system
        - is_bsd: BSD system

    Examples:
        >>> caps = get_platform_capabilities()
        >>> if caps['memory_locking']:
        ...     print("Memory locking available")
        >>> print(f"Platform: {caps['platform']}")
    """
    return {
        "memory_locking": IS_POSIX,
        "memory_locking_all": IS_POSIX,
        "core_dump_control": IS_POSIX,
        "secure_deletion": True,  # Best-effort on all platforms
        "platform": platform.system(),
        "is_posix": IS_POSIX,
        "is_windows": IS_WINDOWS,
        "is_linux": IS_LINUX,
        "is_bsd": IS_BSD,
    }


def initialize_platform_security(lock_all: bool = False) -> None:
    """
    Initialize platform security features at startup.

    Performs:
        - Core dump disabling (if available)
        - Optional full process memory locking
        - Capability detection and logging

    Args:
        lock_all: If True, lock all process memory (requires privileges).
                 Default False - use individual buffer locking instead.

    Call this once at application startup:
        >>> from src.security.crypto.platform_security import initialize_platform_security
        >>> initialize_platform_security()

    For high-security applications (requires elevated privileges):
        >>> initialize_platform_security(lock_all=True)
    """
    caps = get_platform_capabilities()

    _LOGGER.info("Platform: %s", caps["platform"])
    _LOGGER.info("Memory locking: %s", caps["memory_locking"])
    _LOGGER.info("Memory locking (full): %s", caps["memory_locking_all"])

    # Disable core dumps
    if caps["core_dump_control"]:
        if disable_core_dumps():
            _LOGGER.info("Core dumps disabled successfully")
        else:
            _LOGGER.warning("Failed to disable core dumps")

    # Lock all memory if requested
    if lock_all and caps["memory_locking_all"]:
        if lock_all_memory():
            _LOGGER.info("All process memory locked")
        else:
            _LOGGER.warning("Failed to lock all memory - requires elevated privileges")

    # Warnings
    if not caps["memory_locking"]:
        _LOGGER.warning("Memory locking unavailable - secrets may be swapped to disk")

    if not caps["core_dump_control"]:
        _LOGGER.warning("Core dump control unavailable - secrets may leak on crash")


__all__ = [
    "lock_memory",
    "unlock_memory",
    "lock_all_memory",
    "unlock_all_memory",
    "disable_core_dumps",
    "secure_delete_file",
    "get_platform_capabilities",
    "initialize_platform_security",
]
