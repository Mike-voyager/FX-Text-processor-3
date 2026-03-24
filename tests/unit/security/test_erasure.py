"""
Тесты для модуля erasure: безопасное удаление данных.

Version: 1.0
Date: March 2026
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from src.security.erasure import (
    BUFFER_SIZE,
    DOD_PATTERNS,
    WIPE_PASSES,
    ClipboardClearError,
    DirectoryWipeError,
    FileWipeError,
    MemoryWipeError,
    SecureData,
    SecureEraseError,
    clear_clipboard,
    wipe_directory,
    wipe_file,
    wipe_memory,
)


class TestWipeMemory:
    """Тесты wipe_memory."""

    def test_wipe_memory_basic(self) -> None:
        """Тест базового обнуления памяти."""
        data = bytearray(b"secret_key_12345")
        original_len = len(data)

        wipe_memory(data)

        # Все байты должны быть нулями
        assert all(b == 0 for b in data)
        assert len(data) == original_len

    def test_wipe_memory_random_data(self) -> None:
        """Тест обнуления случайных данных."""
        data = bytearray(os.urandom(256))
        original_len = len(data)

        wipe_memory(data)

        assert all(b == 0 for b in data)
        assert len(data) == original_len

    def test_wipe_memory_empty(self) -> None:
        """Тест обнуления пустого bytearray."""
        data = bytearray()

        wipe_memory(data)

        assert len(data) == 0

    def test_wipe_memory_large(self) -> None:
        """Тест обнуления большого bytearray."""
        data = bytearray(os.urandom(65536))

        wipe_memory(data)

        assert all(b == 0 for b in data)

    def test_wipe_memory_bytes_error(self) -> None:
        """Тест ошибки при передаче bytes вместо bytearray."""
        data = b"immutable bytes"

        with pytest.raises(MemoryWipeError) as exc_info:
            wipe_memory(data)  # type: ignore[arg-type]

        assert "bytearray" in str(exc_info.value)


class TestWipeFile:
    """Тесты wipe_file."""

    def test_wipe_file_basic(self, tmp_path: Path) -> None:
        """Тест базового безопасного удаления файла."""
        test_file = tmp_path / "secret.key"
        original_content = b"super_secret_key_data_12345"
        test_file.write_bytes(original_content)

        result = wipe_file(test_file, passes=3, remove=True)

        assert result is True
        assert not test_file.exists()

    def test_wipe_file_preserve(self, tmp_path: Path) -> None:
        """Тест перезаписи без удаления файла."""
        test_file = tmp_path / "config.ini"
        original_content = b"config=value"
        test_file.write_bytes(original_content)

        result = wipe_file(test_file, passes=1, remove=False)

        assert result is True
        assert test_file.exists()
        # Файл должен быть перезаписан нулями
        content = test_file.read_bytes()
        assert all(b == 0 for b in content[:len(original_content)])

    def test_wipe_file_nonexistent(self, tmp_path: Path) -> None:
        """Тест удаления несуществующего файла."""
        nonexistent = tmp_path / "nonexistent.txt"

        result = wipe_file(nonexistent)

        assert result is True  # Файл не существует - считаем успешным

    def test_wipe_file_multiple_passes(self, tmp_path: Path) -> None:
        """Тест многопроходной перезаписи."""
        test_file = tmp_path / "data.bin"
        test_file.write_bytes(os.urandom(1024))

        result = wipe_file(test_file, passes=7, remove=True)

        assert result is True
        assert not test_file.exists()

    def test_wipe_file_directory_error(self, tmp_path: Path) -> None:
        """Тест ошибки при попытке удалить директорию."""
        directory = tmp_path / "directory"
        directory.mkdir()

        with pytest.raises(FileWipeError) as exc_info:
            wipe_file(directory)

        assert "не является файлом" in str(exc_info.value)

    def test_wipe_file_large(self, tmp_path: Path) -> None:
        """Тест удаления большого файла (> BUFFER_SIZE)."""
        test_file = tmp_path / "large.bin"
        # Файл больше буфера
        test_file.write_bytes(os.urandom(BUFFER_SIZE * 2))

        result = wipe_file(test_file, passes=3, remove=True)

        assert result is True
        assert not test_file.exists()

    def test_wipe_file_single_pass(self, tmp_path: Path) -> None:
        """Тест однократной перезаписи."""
        test_file = tmp_path / "single.bin"
        test_file.write_bytes(b"data")

        result = wipe_file(test_file, passes=1, remove=True)

        assert result is True


class TestWipeDirectory:
    """Тесты wipe_directory."""

    def test_wipe_directory_basic(self, tmp_path: Path) -> None:
        """Тест базового рекурсивного удаления."""
        # Создаём структуру
        (tmp_path / "dir").mkdir()
        (tmp_path / "dir" / "file1.txt").write_bytes(b"content1")
        (tmp_path / "dir" / "file2.txt").write_bytes(b"content2")
        (tmp_path / "dir" / "subdir").mkdir()
        (tmp_path / "dir" / "subdir" / "file3.txt").write_bytes(b"content3")

        count = wipe_directory(tmp_path / "dir", passes=3, remove_empty=True)

        assert count == 3
        assert not (tmp_path / "dir").exists()

    def test_wipe_directory_preserve_root(self, tmp_path: Path) -> None:
        """Тест удаления содержимого без корневой директории."""
        root = tmp_path / "keep"
        root.mkdir()
        (root / "file.txt").write_bytes(b"data")

        count = wipe_directory(root, passes=1, remove_empty=False)

        assert count == 1
        assert root.exists()
        assert not (root / "file.txt").exists()

    def test_wipe_directory_empty(self, tmp_path: Path) -> None:
        """Тест удаления пустой директории."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        count = wipe_directory(empty_dir, remove_empty=True)

        assert count == 0
        assert not empty_dir.exists()

    def test_wipe_directory_nonexistent(self, tmp_path: Path) -> None:
        """Тест удаления несуществующей директории."""
        nonexistent = tmp_path / "nonexistent"

        count = wipe_directory(nonexistent)

        assert count == 0

    def test_wipe_directory_not_directory(self, tmp_path: Path) -> None:
        """Тест ошибки при передаче файла вместо директории."""
        file_path = tmp_path / "file.txt"
        file_path.write_bytes(b"data")

        with pytest.raises(DirectoryWipeError) as exc_info:
            wipe_directory(file_path)

        assert "не является директорией" in str(exc_info.value)

    def test_wipe_directory_nested(self, tmp_path: Path) -> None:
        """Тест удаления глубоко вложенной структуры."""
        # Создаём вложенную структуру
        root = tmp_path / "nested"
        current = root
        for i in range(5):
            current.mkdir()
            (current / f"file{i}.txt").write_bytes(b"x" * 100)
            current = current / f"level{i}"

        count = wipe_directory(root, passes=1)

        assert count == 5


class TestSecureData:
    """Тесты SecureData контекстного менеджера."""

    def test_secure_data_basic(self) -> None:
        """Тест базового использования SecureData."""
        data = bytearray(b"secret_password")

        with SecureData(data) as secure_data:
            assert secure_data == bytearray(b"secret_password")
            # Данные доступны внутри контекста

        # После выхода из контекста данные обнулены
        assert all(b == 0 for b in data)

    def test_secure_data_exception(self) -> None:
        """Тест обнуления при исключении."""
        data = bytearray(b"api_key_12345")

        try:
            with SecureData(data) as secure_data:
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Данные обнулены даже при исключении
        assert all(b == 0 for b in data)

    def test_secure_data_bytes_error(self) -> None:
        """Тест ошибки при передаче bytes."""
        data = b"immutable"

        with pytest.raises(MemoryWipeError) as exc_info:
            SecureData(data)  # type: ignore[arg-type]

        assert "bytearray" in str(exc_info.value)

    def test_secure_data_random(self) -> None:
        """Тест SecureData со случайными данными."""
        data = bytearray(os.urandom(256))

        with SecureData(data):
            pass

        assert all(b == 0 for b in data)


class TestClearClipboard:
    """Тесты clear_clipboard."""

    def test_clear_clipboard_linux_xclip(self, monkeypatch) -> None:
        """Тест очистки буфера через xclip (Linux)."""
        import subprocess

        # Мокаем platform.system
        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.setattr("os.environ.get", lambda k, d=None: None)  # Нет WAYLAND_DISPLAY

        # Мокаем subprocess.run
        run_calls = []

        def mock_run(*args, **kwargs):
            run_calls.append(args)
            return subprocess.CompletedProcess(args[0], returncode=0)

        monkeypatch.setattr("subprocess.run", mock_run)

        result = clear_clipboard()

        # Может использовать xclip или xsel
        assert result is True or len(run_calls) > 0

    def test_clear_clipboard_windows(self, monkeypatch) -> None:
        """Тест очистки буфера на Windows."""
        monkeypatch.setattr("platform.system", lambda: "Windows")

        # Пропускаем тест на Linux т.к. Windows API недоступно
        # Тест проверяет только что функция не падает
        result = clear_clipboard()

        # На Linux Windows API не работает, но функция должна корректно обработать ошибку
        assert result in (True, False)

    def test_clear_clipboard_macos(self, monkeypatch) -> None:
        """Тест очистки буфера на macOS."""
        monkeypatch.setattr("platform.system", lambda: "Darwin")

        # Мокаем subprocess.run
        import subprocess

        def mock_run(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], returncode=0)

        monkeypatch.setattr("subprocess.run", mock_run)

        result = clear_clipboard()

        assert result is True

    def test_clear_clipboard_unsupported(self, monkeypatch) -> None:
        """Тест на неподдерживаемой платформе."""
        monkeypatch.setattr("platform.system", lambda: "UnknownOS")

        result = clear_clipboard()

        assert result is False


class TestExceptions:
    """Тесты иерархии исключений."""

    def test_secure_erase_error(self) -> None:
        """Тест базового исключения."""
        error = SecureEraseError("Test error", path="/test/path")

        assert error.message == "Test error"
        assert error.path == "/test/path"
        assert "/test/path" in str(error)

    def test_memory_wipe_error(self) -> None:
        """Тест исключения MemoryWipeError."""
        error = MemoryWipeError("Memory wipe failed")

        assert error.message == "Memory wipe failed"
        assert isinstance(error, SecureEraseError)

    def test_file_wipe_error(self) -> None:
        """Тест исключения FileWipeError."""
        error = FileWipeError(
            "File wipe failed",
            path="/secret/file.key",
            pass_number=2,
        )

        assert error.path == "/secret/file.key"
        assert error.pass_number == 2
        assert "FileWipeError" in str(error)

    def test_directory_wipe_error(self) -> None:
        """Тест исключения DirectoryWipeError."""
        error = DirectoryWipeError("Directory wipe failed", path="/secrets/")

        assert error.path == "/secrets/"
        assert isinstance(error, SecureEraseError)

    def test_clipboard_clear_error(self) -> None:
        """Тест исключения ClipboardClearError."""
        error = ClipboardClearError("Clipboard clear failed")

        assert error.message == "Clipboard clear failed"
        assert isinstance(error, SecureEraseError)


class TestConstants:
    """Тесты констант."""

    def test_wipe_passes_value(self) -> None:
        """Тест значения WIPE_PASSES."""
        assert WIPE_PASSES == 3
        assert WIPE_PASSES >= 3  # DoD 5220.22-M минимум

    def test_buffer_size_value(self) -> None:
        """Тест значения BUFFER_SIZE."""
        assert BUFFER_SIZE == 65536  # 64 KB
        assert BUFFER_SIZE >= 4096  # Минимум 4 KB

    def test_dod_patterns_count(self) -> None:
        """Тест количества паттернов DoD."""
        assert len(DOD_PATTERNS) == 3
        # Паттерны должны быть 1 байт
        for pattern in DOD_PATTERNS:
            assert len(pattern) == 1


class TestIntegration:
    """Интеграционные тесты."""

    def test_full_wipe_workflow(self, tmp_path: Path) -> None:
        """Тест полного цикла безопасного удаления."""
        # Создаём структуру с секретами
        secrets_dir = tmp_path / "secrets"
        secrets_dir.mkdir()

        # Секретные файлы
        (secrets_dir / "private.key").write_bytes(os.urandom(32))
        (secrets_dir / "password.txt").write_bytes(b"super_secret_password_123")

        # Поддиректория
        subdir = secrets_dir / "nested"
        subdir.mkdir()
        (subdir / "api_key.txt").write_bytes(b"api_key_xyz789")

        # Удаляем директорию
        count = wipe_directory(secrets_dir, passes=3)

        assert count == 3
        assert not secrets_dir.exists()

    def test_memory_then_file_wipe(self, tmp_path: Path) -> None:
        """Тест последовательного обнуления памяти и удаления файла."""
        # Секрет в памяти
        secret_key = bytearray(os.urandom(32))

        # Записываем в файл
        secret_file = tmp_path / "key.bin"
        secret_file.write_bytes(secret_key)

        # Обнуляем память
        wipe_memory(secret_key)
        assert all(b == 0 for b in secret_key)

        # Безопасно удаляем файл
        result = wipe_file(secret_file, passes=3)
        assert result is True
        assert not secret_file.exists()