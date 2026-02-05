# -*- coding: utf-8 -*-
"""
RU: Платформенные механизмы безопасности - защита памяти и core dumps.
EN: Platform-specific security mechanisms - memory protection and core dump control.

Features:
- Memory locking (Linux/BSD only)
- Core dump disabling
- Secure file deletion
- Platform capability detection
"""
from __future__ import annotations

import ctypes
import logging
import os
import platform
import sys
from typing import Final, Optional

_LOGGER: Final = logging.getLogger(__name__)

# Platform detection
IS_POSIX = os.name == 'posix'
IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')
IS_BSD = 'bsd' in sys.platform.lower()


def lock_memory(buffer: bytearray) -> bool:
    """
    Lock memory pages to prevent swapping to disk (POSIX only).
    
    Uses mlock(2) system call to lock pages in RAM.
    Requires CAP_IPC_LOCK capability or sufficient RLIMIT_MEMLOCK.
    
    Args:
        buffer: mutable bytearray to lock.
    
    Returns:
        True if successfully locked, False otherwise.
    
    Security:
        - Prevents secrets from being written to swap
        - Does NOT protect against hibernation/suspend
        - Does NOT protect against memory dumps by root
    
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
    
    try:
        # Get libc
        if IS_LINUX:
            libc = ctypes.CDLL('libc.so.6')
        elif IS_BSD:
            libc = ctypes.CDLL('libc.so')
        else:
            _LOGGER.debug("Unsupported POSIX variant for mlock")
            return False
        
        # Get buffer address
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        size = len(buffer)
        
        # Call mlock(2)
        result = libc.mlock(addr, size)
        
        if result == 0:
            _LOGGER.debug("Locked %d bytes in memory", size)
            return True
        else:
            _LOGGER.warning("mlock failed with code %d", result)
            return False
    
    except Exception as e:
        _LOGGER.debug("Memory locking failed: %s", e)
        return False


def unlock_memory(buffer: bytearray) -> bool:
    """
    Unlock previously locked memory pages.
    
    Args:
        buffer: bytearray to unlock.
    
    Returns:
        True if successfully unlocked.
    """
    if not IS_POSIX or not isinstance(buffer, bytearray):
        return False
    
    try:
        if IS_LINUX:
            libc = ctypes.CDLL('libc.so.6')
        elif IS_BSD:
            libc = ctypes.CDLL('libc.so')
        else:
            return False
        
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        size = len(buffer)
        
        result = libc.munlock(addr, size)
        return result == 0
    
    except Exception:
        return False


def disable_core_dumps() -> bool:
    """
    Disable core dumps to prevent secret leakage.
    
    Sets RLIMIT_CORE to 0 (POSIX only).
    
    Returns:
        True if successfully disabled.
    
    Security:
        Call this at application startup to prevent core dumps
        from writing sensitive memory contents to disk.
    
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
    Securely delete file by overwriting before removal.
    
    Args:
        filepath: path to file to delete.
        passes: number of overwrite passes (default 3).
    
    Returns:
        True if successfully deleted.
    
    Security:
        - Not effective on SSD/flash storage (wear leveling)
        - Not effective on CoW filesystems (btrfs, ZFS)
        - Not effective on journaling filesystems
        - Use disk encryption for real protection!
    
    Examples:
        >>> secure_delete_file("temp_key.bin")
        True
    """
    import os
    from pathlib import Path
    
    try:
        path = Path(filepath)
        
        if not path.exists():
            _LOGGER.warning("File not found: %s", filepath)
            return False
        
        file_size = path.stat().st_size
        
        # Overwrite with random data
        with open(path, 'r+b') as f:
            for i in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        # Remove file
        path.unlink()
        _LOGGER.debug("Securely deleted: %s", filepath)
        return True
    
    except Exception as e:
        _LOGGER.error("Secure delete failed: %s", e)
        return False


def get_platform_capabilities() -> dict[str, bool]:
    """
    Detect available platform security features.
    
    Returns:
        Dictionary of capability flags.
    
    Examples:
        >>> caps = get_platform_capabilities()
        >>> if caps['memory_locking']:
        ...     print("Memory locking available")
    """
    return {
        'memory_locking': IS_POSIX,
        'core_dump_control': IS_POSIX,
        'secure_deletion': True,  # Best-effort on all platforms
        'platform': platform.system(),
        'is_posix': IS_POSIX,
        'is_windows': IS_WINDOWS,
        'is_linux': IS_LINUX,
        'is_bsd': IS_BSD,
    }


def initialize_platform_security() -> None:
    """
    Initialize platform security features at startup.
    
    Performs:
        - Core dump disabling (if available)
        - Capability detection and logging
    
    Call this once at application startup:
        >>> from src.security.crypto.platform_security import initialize_platform_security
        >>> initialize_platform_security()
    """
    caps = get_platform_capabilities()
    
    _LOGGER.info("Platform: %s", caps['platform'])
    _LOGGER.info("Memory locking: %s", caps['memory_locking'])
    
    if caps['core_dump_control']:
        disable_core_dumps()
    
    if not caps['memory_locking']:
        _LOGGER.warning(
            "Memory locking unavailable - secrets may be swapped to disk"
        )


__all__ = [
    "lock_memory",
    "unlock_memory",
    "disable_core_dumps",
    "secure_delete_file",
    "get_platform_capabilities",
    "initialize_platform_security",
]
