"""Сервис буфера обмена.

Управляет операциями Copy/Cut/Paste для текста и объектов.
Поддерживает множественные форматы (plain text, rich text, objects).

Module: src/services/clipboard_service.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from src.model.paragraph import Paragraph
    from src.model.run import Run

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Типы данных буфера
# ---------------------------------------------------------------------------


class ClipboardFormat(Enum):
    """Форматы данных в буфере обмена."""

    TEXT = "text/plain"
    HTML = "text/html"
    RTF = "text/rtf"
    PARAGRAPHS = "application/x-fx-paragraphs"
    RUNS = "application/x-fx-runs"


@dataclass(frozen=True)
class ClipboardData:
    """Данные в буфере обмена.

    Attrs:
        format: Формат данных
        content: Содержимое (строка или объект)
        source_document_id: ID документа-источника (optional)
        timestamp: Время копирования
        metadata: Дополнительные метаданные
    """

    format: ClipboardFormat
    content: Any
    source_document_id: Optional[UUID] = None
    timestamp: float = field(default_factory=lambda: 0.0)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClipboardEntry:
    """Запись в истории буфера обмена.

    Attrs:
        data: Данные буфера
        description: Описание для UI
        is_pinned: Закреплена ли запись
    """

    data: ClipboardData
    description: str = ""
    is_pinned: bool = False


# ---------------------------------------------------------------------------
# Результаты операций
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CopyResult:
    """Результат операции копирования.

    Attrs:
        success: True при успехе
        content: Скопированное содержимое (для preview)
        error: Сообщение об ошибке или None
    """

    success: bool
    content: Optional[str] = None
    error: Optional[str] = None


@dataclass(frozen=True)
class PasteResult:
    """Результат операции вставки.

    Attrs:
        success: True при успехе
        inserted_count: Количество вставленных элементов
        error: Сообщение об ошибке или None
    """

    success: bool
    inserted_count: int = 0
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Протоколы
# ---------------------------------------------------------------------------


class ClipboardBackendProtocol(Protocol):
    """Протокол бэкенда буфера обмена (системный clipboard)."""

    def get_text(self) -> Optional[str]:
        """Получает текст из системного буфера."""
        ...

    def set_text(self, text: str) -> bool:
        """Устанавливает текст в системный буфер."""
        ...

    def get_formats(self) -> List[str]:
        """Возвращает доступные форматы в буфере."""
        ...

    def get_data(self, format: str) -> Optional[bytes]:
        """Получает данные в указанном формате."""
        ...

    def set_data(self, format: str, data: bytes) -> bool:
        """Устанавливает данные в указанном формате."""
        ...


# ---------------------------------------------------------------------------
# PyperclipBackend
# ---------------------------------------------------------------------------


class PyperclipBackend:
    """Бэкенд буфера обмена на основе pyperclip.

    Поддерживает Linux (с xclip/xsel fallback), Windows, macOS.
    """

    def __init__(self) -> None:
        """Инициализирует pyperclip бэкенд."""
        try:
            import pyperclip

            self._pyperclip = pyperclip
        except ImportError:
            # Fallback для Linux без pyperclip - пробуем subprocess
            self._pyperclip = None
            self._fallback_cmd = self._detect_linux_clipboard()

    def _detect_linux_clipboard(self) -> Optional[str]:
        """Определяет доступную команду clipboard на Linux.

        Returns:
            Команда для clipboard или None.
        """
        import shutil

        if shutil.which("xclip"):
            return "xclip"
        if shutil.which("xsel"):
            return "xsel"
        return None

    def _fallback_get_text(self) -> Optional[str]:
        """Fallback получения текста через subprocess."""
        import subprocess

        if self._fallback_cmd == "xclip":
            try:
                result = subprocess.run(
                    ["xclip", "-selection", "clipboard", "-o"],
                    capture_output=True,
                    text=True,
                    timeout=1,
                )
                return result.stdout if result.returncode == 0 else None
            except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError) as e:
                logger.debug("xclip subprocess failed: %s", e)
                return None
        elif self._fallback_cmd == "xsel":
            try:
                result = subprocess.run(
                    ["xsel", "--clipboard", "--output"],
                    capture_output=True,
                    text=True,
                    timeout=1,
                )
                return result.stdout if result.returncode == 0 else None
            except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError) as e:
                logger.debug("xsel subprocess failed: %s", e)
                return None
        return None

    def _fallback_set_text(self, text: str) -> bool:
        """Fallback установки текста через subprocess."""
        import subprocess

        if self._fallback_cmd == "xclip":
            try:
                result = subprocess.run(
                    ["xclip", "-selection", "clipboard"],
                    input=text,
                    capture_output=True,
                    text=True,
                    timeout=1,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError) as e:
                logger.debug("xclip subprocess failed: %s", e)
                return False
        elif self._fallback_cmd == "xsel":
            try:
                result = subprocess.run(
                    ["xsel", "--clipboard", "--input"],
                    input=text,
                    capture_output=True,
                    text=True,
                    timeout=1,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, OSError, subprocess.SubprocessError) as e:
                logger.debug("xsel subprocess failed: %s", e)
                return False
        return False

    def get_text(self) -> Optional[str]:
        """Получает текст из системного буфера.

        Returns:
            Текст из буфера или None при ошибке.
        """
        try:
            if self._pyperclip:
                result = self._pyperclip.paste()
                return str(result) if result is not None else None
            return self._fallback_get_text()
        except (OSError, TypeError, pyperclip.PyperclipException) as e:
            logger.debug("Clipboard get_text failed: %s", e)
            return None

    def set_text(self, text: str) -> bool:
        """Устанавливает текст в системный буфер.

        Args:
            text: Текст для копирования.

        Returns:
            True при успехе.
        """
        try:
            if self._pyperclip:
                self._pyperclip.copy(text)
                return True
            return self._fallback_set_text(text)
        except (OSError, TypeError, pyperclip.PyperclipException) as e:
            logger.debug("Clipboard set_text failed: %s", e)
            return False

    def get_formats(self) -> List[str]:
        """Возвращает доступные форматы в буфере.

        Returns:
            Список поддерживаемых MIME-типов.
        """
        return ["text/plain"]

    def get_data(self, format: str) -> Optional[bytes]:
        """Получает данные в указанном формате.

        Args:
            format: MIME-тип формата.

        Returns:
            Данные как bytes или None.
        """
        if format == "text/plain":
            text = self.get_text()
            return text.encode("utf-8") if text else None
        return None

    def set_data(self, format: str, data: bytes) -> bool:
        """Устанавливает данные в указанном формате.

        Args:
            format: MIME-тип формата.
            data: Данные как bytes.

        Returns:
            True при успехе.
        """
        if format == "text/plain":
            try:
                text = data.decode("utf-8", errors="replace")
                return self.set_text(text)
            except (UnicodeDecodeError, TypeError) as e:
                logger.debug("Data decode failed: %s", e)
                return False
        return False


# ---------------------------------------------------------------------------
# ClipboardService
# ---------------------------------------------------------------------------


class ClipboardService:
    """Сервис буфера обмена.

    Управляет операциями Copy/Cut/Paste:
    - Копирование текста, параграфов, runs
    - Интеграция с системным буфером обмена
    - История копирований (clipboard history)
    - Множественные форматы

    Пример:
        >>> clipboard = ClipboardService()
        >>> result = clipboard.copy_text("Hello, World!")
        >>> if result.success:
        ...     text = clipboard.paste_text()
    """

    def __init__(
        self,
        backend: Optional[ClipboardBackendProtocol] = None,
        history_size: int = 20,
    ) -> None:
        """Инициализирует сервис буфера обмена.

        Args:
            backend: Бэкенд для системного буфера (optional)
            history_size: Размер истории копирований
        """
        self._backend = backend
        self._history_size = history_size
        self._history: List[ClipboardEntry] = []
        self._current: Optional[ClipboardData] = None

    # ---------- Свойства ----------

    @property
    def has_content(self) -> bool:
        """Проверяет наличие содержимого в буфере."""
        return self._current is not None

    @property
    def current_format(self) -> Optional[ClipboardFormat]:
        """Возвращает формат текущего содержимого."""
        if self._current is None:
            return None
        return self._current.format

    @property
    def history_count(self) -> int:
        """Возвращает количество записей в истории."""
        return len(self._history)

    # ---------- Операции с текстом ----------

    def copy_text(
        self,
        text: str,
        source_document_id: Optional[UUID] = None,
    ) -> CopyResult:
        """Копирует текст в буфер обмена.

        Args:
            text: Текст для копирования
            source_document_id: ID документа-источника (optional)

        Returns:
            CopyResult с результатом операции
        """
        if not text:
            return CopyResult(success=False, error="Пустой текст")

        import time

        data = ClipboardData(
            format=ClipboardFormat.TEXT,
            content=text,
            source_document_id=source_document_id,
            timestamp=time.time(),
        )

        self._current = data
        self._add_to_history(data, f"Текст ({len(text)} символов)")

        # Синхронизация с системным буфером
        if self._backend:
            self._backend.set_text(text)

        logger.debug("Скопирован текст: %d символов", len(text))
        return CopyResult(success=True, content=text)

    def paste_text(self) -> Optional[str]:
        """Вставляет текст из буфера обмена.

        Returns:
            Текст или None если буфер пуст
        """
        # Сначала проверяем внутренний буфер
        if self._current is not None and self._current.format == ClipboardFormat.TEXT:
            return str(self._current.content)

        # Затем системный буфер
        if self._backend:
            text = self._backend.get_text()
            if text:
                return text

        return None

    # ---------- Операции с параграфами ----------

    def copy_paragraphs(
        self,
        paragraphs: List["Paragraph"],
        source_document_id: Optional[UUID] = None,
    ) -> CopyResult:
        """Копирует параграфы в буфер обмена.

        Args:
            paragraphs: Список параграфов для копирования
            source_document_id: ID документа-источника

        Returns:
            CopyResult с результатом операции
        """
        if not paragraphs:
            return CopyResult(success=False, error="Пустой список параграфов")

        import time

        # Сериализуем параграфы
        content = self._serialize_paragraphs(paragraphs)

        data = ClipboardData(
            format=ClipboardFormat.PARAGRAPHS,
            content=content,
            source_document_id=source_document_id,
            timestamp=time.time(),
            metadata={"count": len(paragraphs)},
        )

        self._current = data
        description = f"Параграфы ({len(paragraphs)})"
        self._add_to_history(data, description)

        # Также копируем как текст
        text = self._paragraphs_to_text(paragraphs)
        if self._backend:
            self._backend.set_text(text)

        logger.debug("Скопировано параграфов: %d", len(paragraphs))
        return CopyResult(success=True, content=text)

    def paste_paragraphs(self) -> Optional[List["Paragraph"]]:
        """Вставляет параграфы из буфера обмена.

        Returns:
            Список параграфов или None если буфер пуст
        """
        if self._current is None:
            return None

        if self._current.format != ClipboardFormat.PARAGRAPHS:
            return None

        content = self._current.content
        return self._deserialize_paragraphs(content)

    # ---------- Операции с runs ----------

    def copy_runs(
        self,
        runs: List["Run"],
        source_document_id: Optional[UUID] = None,
    ) -> CopyResult:
        """Копирует runs в буфер обмена.

        Args:
            runs: Список runs для копирования
            source_document_id: ID документа-источника

        Returns:
            CopyResult с результатом операции
        """
        if not runs:
            return CopyResult(success=False, error="Пустой список runs")

        import time

        content = self._serialize_runs(runs)

        data = ClipboardData(
            format=ClipboardFormat.RUNS,
            content=content,
            source_document_id=source_document_id,
            timestamp=time.time(),
            metadata={"count": len(runs)},
        )

        self._current = data
        self._add_to_history(data, f"Runs ({len(runs)})")

        # Текстовое представление
        text = "".join(run.text for run in runs if hasattr(run, "text"))
        if self._backend:
            self._backend.set_text(text)

        logger.debug("Скопировано runs: %d", len(runs))
        return CopyResult(success=True, content=text)

    def paste_runs(self) -> Optional[List["Run"]]:
        """Вставляет runs из буфера обмена.

        Returns:
            Список runs или None если буфер пуст
        """
        if self._current is None:
            return None

        if self._current.format != ClipboardFormat.RUNS:
            return None

        return self._deserialize_runs(self._current.content)

    # ---------- Операции Cut ----------

    def cut_text(
        self,
        text: str,
        source_document_id: Optional[UUID] = None,
    ) -> CopyResult:
        """Вырезает текст (copy + delete).

        Args:
            text: Текст для вырезания
            source_document_id: ID документа-источника

        Returns:
            CopyResult с результатом операции

        Note:
            Удаление текста из документа должно выполняться вызывающим кодом.
        """
        return self.copy_text(text, source_document_id)

    # ---------- История ----------

    def get_history(self, limit: int = 10) -> List[ClipboardEntry]:
        """Возвращает историю копирований.

        Args:
            limit: Максимум записей

        Returns:
            Список записей истории (последние сначала)
        """
        return list(reversed(self._history[-limit:]))

    def get_pinned(self) -> List[ClipboardEntry]:
        """Возвращает закреплённые записи.

        Returns:
            Список закреплённых записей
        """
        return [entry for entry in self._history if entry.is_pinned]

    def pin_entry(self, index: int) -> bool:
        """Закрепляет запись в истории.

        Args:
            index: Индекс записи (от конца списка)

        Returns:
            True если запись найдена и закреплена
        """
        if 0 <= index < len(self._history):
            self._history[index].is_pinned = True
            return True
        return False

    def unpin_entry(self, index: int) -> bool:
        """Открепляет запись.

        Args:
            index: Индекс записи

        Returns:
            True если запись найдена и откреплена
        """
        if 0 <= index < len(self._history):
            self._history[index].is_pinned = False
            return True
        return False

    def clear_history(self) -> int:
        """Очищает историю (кроме закреплённых).

        Returns:
            Количество удалённых записей
        """
        pinned = [e for e in self._history if e.is_pinned]
        count = len(self._history) - len(pinned)
        self._history = pinned
        return count

    def clear_all(self) -> None:
        """Очищает буфер и историю."""
        self._current = None
        self._history.clear()
        logger.debug("Буфер обмена очищен")

    # ---------- Внутренние методы ----------

    def _add_to_history(self, data: ClipboardData, description: str) -> None:
        """Добавляет запись в историю.

        Args:
            data: Данные буфера
            description: Описание для UI
        """
        entry = ClipboardEntry(data=data, description=description)

        # Проверяем дубликаты
        for existing in self._history:
            if existing.data.format == data.format and existing.data.content == data.content:
                # Обновляем timestamp и перемещаем в конец
                self._history.remove(existing)
                self._history.append(existing)
                return

        self._history.append(entry)

        # Ограничиваем размер (кроме закреплённых)
        while len(self._history) > self._history_size:
            for i, entry in enumerate(self._history):
                if not entry.is_pinned:
                    self._history.pop(i)
                    break

    def _serialize_paragraphs(self, paragraphs: List["Paragraph"]) -> Dict[str, Any]:
        """Сериализует параграфы в словарь.

        Args:
            paragraphs: Список параграфов

        Returns:
            Сериализованные данные
        """
        return {
            "type": "paragraphs",
            "count": len(paragraphs),
            "data": [p.to_dict() for p in paragraphs],
        }

    def _deserialize_paragraphs(self, data: Dict[str, Any]) -> List["Paragraph"]:
        """Десериализует параграфы из словаря.

        Args:
            data: Сериализованные данные

        Returns:
            Список параграфов
        """
        from src.model.paragraph import Paragraph
        items = data.get("data", [])
        return [Paragraph.from_dict(item) for item in items]

    def _serialize_runs(self, runs: List["Run"]) -> Dict[str, Any]:
        """Сериализует runs в словарь."""
        return {
            "type": "runs",
            "count": len(runs),
            "data": [r.to_dict() for r in runs],
        }

    def _deserialize_runs(self, data: Dict[str, Any]) -> List["Run"]:
        """Десериализует runs из словаря."""
        from src.model.run import Run
        items = data.get("data", [])
        return [Run.from_dict(item) for item in items]

    def _paragraphs_to_text(self, paragraphs: List["Paragraph"]) -> str:
        """Конвертирует параграфы в текст.

        Args:
            paragraphs: Список параграфов

        Returns:
            Текстовое представление
        """
        texts = []
        for para in paragraphs:
            if hasattr(para, "get_text"):
                texts.append(para.get_text())
            elif hasattr(para, "runs"):
                texts.append("".join(r.text for r in para.runs if hasattr(r, "text")))
        return "\n\n".join(texts)


__all__ = [
    "ClipboardService",
    "PyperclipBackend",
    "ClipboardData",
    "ClipboardEntry",
    "ClipboardFormat",
    "CopyResult",
    "PasteResult",
    "ClipboardBackendProtocol",
]
