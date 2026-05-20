"""Файловое хранилище пользователей для FX Text Processor 3.

Реализация UserStorage на основе JSON-файла.
Пароли хранятся в виде Argon2id-хешей — открытые пароли
в файл не попадают.

Модель безопасности (двухфазная):
    Pre-auth:  хеш пароля (Argon2id, необратим) доступен для проверки.
               Файл 0600 — только владелец может читать.
    Post-auth: обратимые секреты (ключи, TOTP-семена) хранятся
               в SecureStorage (AES-256-GCM).

Директория ~/.fx-text-processor/ создаётся с правами 0700.

Version: 1.1
Date: May 2026
"""

from __future__ import annotations

import json
import logging
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.security.auth.password_service import PASSWORD_HISTORY_LENGTH

logger = logging.getLogger(__name__)

# Путь по умолчанию: ~/.fx-text-processor/users.json
_DEFAULT_DIR = Path.home() / ".fx-text-processor"
_DEFAULT_FILE = _DEFAULT_DIR / "users.json"

_STORAGE_VERSION = 1


class JsonUserStorage:
    """Файловое хранилище пользователей на основе JSON.

    Сохраняет данные на диск атомарно (tmp + replace).
    Пароли хранятся как Argon2id-хеши — открытые пароли
    никогда не попадают в файл.

    Attributes:
        _path: Путь к JSON-файлу.
        _data: Кэшированные данные.
        _dirty: Флаг наличия несохранённых изменений.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        """Инициализирует файловое хранилище.

        Args:
            path: Путь к JSON-файлу. Если None, используется
                  ~/.fx-text-processor/users.json.
        """
        self._path = path if path is not None else _DEFAULT_FILE
        self._data: Dict[str, Any] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        """Загружает данные из файла."""
        if not self._path.exists():
            self._data = {
                "version": _STORAGE_VERSION,
                "hashes": {},
                "history": {},
                "created_at": {},
                "temp_flags": {},
            }
            return

        try:
            raw = self._path.read_text(encoding="utf-8")
            self._data = json.loads(raw)
            for key in ("hashes", "history", "created_at", "temp_flags"):
                self._data.setdefault(key, {})
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Не удалось загрузить %s: %s", self._path, exc)
            self._data = {
                "version": _STORAGE_VERSION,
                "hashes": {},
                "history": {},
                "created_at": {},
                "temp_flags": {},
            }

    def _flush(self) -> None:
        """Сохраняет данные на диск, если есть изменения."""
        if not self._dirty:
            return
        self._dirty = False
        self._write_to_disk()

    def _write_to_disk(self) -> None:
        """Атомарная запись в файл с правами 0600."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Права на директорию: 0700
            dir_stat = self._path.parent.stat()
            if dir_stat.st_mode & 0o077:
                os.chmod(self._path.parent, stat.S_IRWXU)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(self._data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
            tmp.replace(self._path)
        except OSError as exc:
            logger.error("Не удалось сохранить %s: %s", self._path, exc)

    def _mark_dirty(self) -> None:
        """Помечает данные как изменённые."""
        self._dirty = True

    # --- UserStorage Protocol ---

    def get_password_hash(self, user_id: str) -> Optional[str]:
        return str(v) if (v := self._data["hashes"].get(user_id)) is not None else None

    def set_password_hash(self, user_id: str, password_hash: str) -> None:
        self._data["hashes"][user_id] = password_hash
        self._mark_dirty()
        # Обновляем историю и дату создания без промежуточных flush
        hist = self._data["history"].setdefault(user_id, [])
        hist.append(password_hash)
        if len(hist) > PASSWORD_HISTORY_LENGTH:
            self._data["history"][user_id] = hist[-PASSWORD_HISTORY_LENGTH:]
        self._data["created_at"][user_id] = datetime.now(timezone.utc).isoformat()
        self._flush()

    def user_exists(self, user_id: str) -> bool:
        return user_id in self._data["hashes"]

    def get_password_history(self, user_id: str, limit: int = PASSWORD_HISTORY_LENGTH) -> List[str]:
        return list(self._data["history"].get(user_id, [])[-limit:])

    def add_password_to_history(self, user_id: str, password_hash: str) -> None:
        hist = self._data["history"].setdefault(user_id, [])
        hist.append(password_hash)
        if len(hist) > PASSWORD_HISTORY_LENGTH:
            self._data["history"][user_id] = hist[-PASSWORD_HISTORY_LENGTH:]
        self._mark_dirty()
        self._flush()

    def get_password_created_at(self, user_id: str) -> Optional[datetime]:
        iso = self._data["created_at"].get(user_id)
        if iso is None:
            return None
        try:
            return datetime.fromisoformat(iso)
        except (ValueError, TypeError):
            return None

    def set_password_created_at(self, user_id: str, timestamp: datetime) -> None:
        self._data["created_at"][user_id] = timestamp.isoformat()
        self._mark_dirty()
        self._flush()

    def is_temporary_password(self, user_id: str) -> bool:
        return bool(self._data["temp_flags"].get(user_id, False))

    def set_temporary_flag(self, user_id: str, is_temp: bool) -> None:
        self._data["temp_flags"][user_id] = is_temp
        self._mark_dirty()
        self._flush()

    def user_ids(self) -> List[str]:
        return list(self._data["hashes"].keys())


__all__: list[str] = ["JsonUserStorage"]
