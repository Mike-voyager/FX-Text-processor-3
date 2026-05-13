"""Сервис истории команд (Undo/Redo).

Реализует паттерн Command для отмены/повтора операций над документом.
Отделяет бизнес-логику истории от модели.

Module: src/services/command_history_service.py
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generic, List, Optional, Protocol, TypeVar
from uuid import UUID

logger = logging.getLogger(__name__)

# Тип команды
CommandT = TypeVar("CommandT")


# ---------------------------------------------------------------------------
# Протокол команды
# ---------------------------------------------------------------------------


class CommandProtocol(Protocol):
    """Протокол команды для Undo/Redo.

    Каждая операция должна реализовывать:
    - execute: Выполнить операцию
    - undo: Отменить операцию
    - description: Описание для UI
    """

    def execute(self) -> Any:
        """Выполняет команду.

        Returns:
            Результат выполнения
        """
        ...

    def undo(self) -> Any:
        """Отменяет команду.

        Returns:
            Результат отмены
        """
        ...

    @property
    def description(self) -> str:
        """Описание команды для UI."""
        ...


# ---------------------------------------------------------------------------
# Результаты операций
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HistoryResult(Generic[CommandT]):
    """Результат операции истории.

    Attrs:
        success: True при успехе
        result: Результат команды
        error: Сообщение об ошибке или None
    """

    success: bool
    result: Optional[CommandT] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Группировка команд по слову
# ---------------------------------------------------------------------------


@dataclass
class TextEditCommand:
    """Команда редактирования текста для группировки по слову.

    Attrs:
        command_type: Тип команды ("insert", "delete")
        position: Позиция в документе
        text: Текст (для insert)
        length: Длина (для delete)
        timestamp: Время создания
    """

    command_type: str  # "insert" или "delete"
    position: int  # Позиция в тексте (индекс символа)
    text: str = ""  # Текст для вставки
    length: int = 0  # Длина для удаления
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class CombinedTextCommand:
    """Объединённая команда для нескольких текстовых операций.

    Используется для группировки по слову или действию.
    """

    commands: List[TextEditCommand] = field(default_factory=list)
    description: str = "Текстовая операция"

    def execute(self, callback: Optional[Callable[[TextEditCommand], None]] = None) -> None:
        """Выполняет все команды в последовательности.

        Args:
            callback: Опциональный callback для каждой команды,
                чтобы верхний уровень мог обновить DocumentView.
        """
        for cmd in self.commands:
            if callback:
                try:
                    callback(cmd)
                except Exception as exc:
                    logger.debug("execute callback error: %s", exc)

    def undo(self, callback: Optional[Callable[[TextEditCommand], None]] = None) -> None:
        """Отменяет все команды в обратной последовательности.

        Args:
            callback: Опциональный callback для каждой команды,
                чтобы верхний уровень мог обновить DocumentView.
        """
        for cmd in reversed(self.commands):
            if callback:
                try:
                    callback(cmd)
                except Exception as exc:
                    logger.debug("undo callback error: %s", exc)


class WordCommandGrouper:
    """Группировщик команд по слову.

    Объединяет последовательные вставки символов слова в одну команду.
    Разделители (пробел, знаки препинания) завершают группировку.
    Пауза более 2 секунд также завершает группировку.

    Пример:
        >>> grouper = WordCommandGrouper()
        >>> grouper.add_insert(0, "п")      # Начало слова
        >>> grouper.add_insert(1, "р")      # Продолжение слова
        >>> grouper.add_insert(2, "и")      # Продолжение слова
        >>> grouper.flush()                 # Слово завершено
        # Результат: одна команда "при"
    """

    # Время ожидания для разрыва группы (секунды)
    WORD_TIMEOUT_SECONDS: int = 2
    # Максимальный размер буфера (защита от OOM)
    MAX_BUFFER_SIZE: int = 1000

    def __init__(self) -> None:
        """Инициализирует группировщик."""
        self._buffer: List[TextEditCommand] = []
        self._last_action_time: Optional[datetime] = None
        self._current_word: str = ""

    def _ensure_buffer_size(self) -> None:
        """Проверяет и ограничивает размер буфера."""
        if len(self._buffer) >= self.MAX_BUFFER_SIZE:
            # При превышении лимита принудительно сбрасываем буфер
            logger.warning(
                f"WordCommandGrouper buffer exceeded {self.MAX_BUFFER_SIZE}, forcing flush"
            )
            self.flush()

    def add_insert(self, position: int, text: str) -> Optional[CombinedTextCommand]:
        """Добавляет вставку текста.

        Args:
            position: Позиция вставки
            text: Вставляемый текст

        Returns:
            CombinedTextCommand если группа завершена, иначе None
        """
        # Проверяем размер буфера перед добавлением
        self._ensure_buffer_size()
        """Добавляет вставку текста.

        Args:
            position: Позиция вставки
            text: Вставляемый текст

        Returns:
            CombinedTextCommand если группа завершена, иначе None
        """
        now = datetime.now()

        # Проверяем таймаут
        if self._last_action_time is not None:
            elapsed = (now - self._last_action_time).total_seconds()
            if elapsed > self.WORD_TIMEOUT_SECONDS:
                # Прошло больше 2 секунд - завершаем текущую группу
                return self.flush()

        # Проверяем, является ли текст частью слова
        if self._is_word_character(text):
            # Добавляем в буфер слова
            cmd = TextEditCommand(
                command_type="insert",
                position=position,
                text=text,
                timestamp=now,
            )
            self._buffer.append(cmd)
            self._current_word += text
            self._last_action_time = now
            return None
        else:
            # Это разделитель - завершаем текущее слово
            result = self.flush()
            # Создаём отдельную команду для разделителя
            separator_cmd = TextEditCommand(
                command_type="insert",
                position=position,
                text=text,
                timestamp=now,
            )
            self._buffer.append(separator_cmd)
            self._last_action_time = now
            # Возвращаем результат flush + сигнализируем о разделителе
            if result is not None:
                return result
            return self.flush()

    def add_delete(self, position: int, length: int) -> Optional[CombinedTextCommand]:
        """Добавляет удаление текста.

        Удаление всегда завершает текущую группу слова.

        Args:
            position: Позиция удаления
            length: Длина удаляемого текста

        Returns:
            CombinedTextCommand если была группа, иначе None
        """
        # Удаление всегда завершает группировку
        result = self.flush()

        now = datetime.now()
        cmd = TextEditCommand(
            command_type="delete",
            position=position,
            length=length,
            timestamp=now,
        )
        self._buffer.append(cmd)
        self._last_action_time = now

        if result is not None:
            return result
        return self.flush()

    def _is_word_character(self, text: str) -> bool:
        """Проверяет, является ли текст частью слова.

        Args:
            text: Текст для проверки

        Returns:
            True если все символы - буквы/цифры/подчёркивание
        """
        if not text:
            return False
        return all(c.isalnum() or c == "_" for c in text)

    def flush(self) -> Optional[CombinedTextCommand]:
        """Завершает группировку и возвращает объединённую команду.

        Returns:
            CombinedTextCommand если есть что группировать, иначе None
        """
        if not self._buffer:
            return None

        # Объединяем все команды в одну
        desc = f"Ввод '{self._current_word}'" if self._current_word else "Текстовая операция"
        combined = CombinedTextCommand(
            commands=list(self._buffer),
            description=desc,
        )

        # Очищаем буфер
        self._buffer.clear()
        self._current_word = ""
        self._last_action_time = None

        return combined

    def is_empty(self) -> bool:
        """Проверяет, пуст ли буфер группировки."""
        return len(self._buffer) == 0

    def get_pending_word(self) -> str:
        """Возвращает текущее накапливаемое слово."""
        return self._current_word


# ---------------------------------------------------------------------------
# История команд
# ---------------------------------------------------------------------------


@dataclass
class CommandHistory:
    """История команд для одного документа.

    Хранит два стека: выполненные команды (undo stack)
    и отменённые команды (redo stack).
    Поддерживает группировку по слову для текстовых операций.

    Attrs:
        document_id: ID документа
        undo_stack: Стек выполненных команд
        redo_stack: Стек отменённых команд
        max_size: Максимальный размер истории
        word_grouper: Группировщик команд по слову
    """

    document_id: UUID
    undo_stack: List[CommandProtocol] = field(default_factory=list)
    redo_stack: List[CommandProtocol] = field(default_factory=list)
    max_size: int = 100
    _word_grouper: WordCommandGrouper = field(default_factory=WordCommandGrouper, repr=False)

    def can_undo(self) -> bool:
        """Проверяет возможность отмены."""
        return len(self.undo_stack) > 0

    def can_redo(self) -> bool:
        """Проверяет возможность повтора."""
        return len(self.redo_stack) > 0

    def push(self, command: CommandProtocol) -> None:
        """Добавляет команду в историю.

        Очищает redo stack при добавлении новой команды.
        Завершает текущую группировку по слову.

        Args:
            command: Выполненная команда
        """
        # Завершаем группировку по слову перед добавлением обычной команды
        self._flush_word_group()

        self.undo_stack.append(command)
        self.redo_stack.clear()

        # Ограничение размера
        if len(self.undo_stack) > self.max_size:
            self.undo_stack.pop(0)

    def add_text_insert(self, position: int, text: str) -> None:
        """Добавляет вставку текста с группировкой по слову.

        Args:
            position: Позиция вставки
            text: Вставляемый текст
        """
        # Передаём в группировщик
        combined = self._word_grouper.add_insert(position, text)

        # Если группировщик вернул объединённую команду, добавляем её в историю
        if combined is not None:
            self.undo_stack.append(combined)
            self.redo_stack.clear()

            # Ограничение размера
            if len(self.undo_stack) > self.max_size:
                self.undo_stack.pop(0)

    def add_text_delete(self, position: int, length: int) -> None:
        """Добавляет удаление текста (завершает группировку по слову).

        Args:
            position: Позиция удаления
            length: Длина удаляемого текста
        """
        combined = self._word_grouper.add_delete(position, length)

        if combined is not None:
            self.undo_stack.append(combined)
            self.redo_stack.clear()

            # Ограничение размера
            if len(self.undo_stack) > self.max_size:
                self.undo_stack.pop(0)

    def _flush_word_group(self) -> None:
        """Завершает группировку по слову и добавляет в историю."""
        combined = self._word_grouper.flush()
        if combined is not None:
            self.undo_stack.append(combined)
            self.redo_stack.clear()

            if len(self.undo_stack) > self.max_size:
                self.undo_stack.pop(0)

    def get_pending_word(self) -> str:
        """Возвращает текущее накапливаемое слово."""
        return self._word_grouper.get_pending_word()

    def pop_undo(self) -> Optional[CommandProtocol]:
        """Извлекает команду из undo стека.

        Завершает группировку по слову перед отменой.

        Returns:
            Команда для отмены или None
        """
        # Завершаем группировку по слову перед отменой
        self._flush_word_group()

        if self.undo_stack:
            return self.undo_stack.pop()
        return None

    def pop_redo(self) -> Optional[CommandProtocol]:
        """Извлекает команду из redo стека.

        Returns:
            Команда для повтора или None
        """
        if self.redo_stack:
            return self.redo_stack.pop()
        return None

    def push_redo(self, command: CommandProtocol) -> None:
        """Добавляет команду в redo стек.

        Args:
            command: Отменённая команда
        """
        self.redo_stack.append(command)

    def push_undo(self, command: CommandProtocol) -> None:
        """Добавляет команду обратно в undo стек после undo.

        Args:
            command: Команда после отмены
        """
        self.undo_stack.append(command)

    def clear(self) -> None:
        """Очищает историю."""
        self.undo_stack.clear()
        self.redo_stack.clear()

    @property
    def undo_count(self) -> int:
        """Количество команд в undo стеке."""
        return len(self.undo_stack)

    @property
    def redo_count(self) -> int:
        """Количество команд в redo стеке."""
        return len(self.redo_stack)

    def get_undo_descriptions(self, limit: int = 10) -> List[str]:
        """Возвращает описания команд для отмены.

        Args:
            limit: Максимум описаний

        Returns:
            Список описаний (последние сначала)
        """
        descriptions = [cmd.description for cmd in reversed(self.undo_stack)]
        return descriptions[:limit]

    def get_redo_descriptions(self, limit: int = 10) -> List[str]:
        """Возвращает описания команд для повтора.

        Args:
            limit: Максимум описаний

        Returns:
            Список описаний (последние сначала)
        """
        descriptions = [cmd.description for cmd in reversed(self.redo_stack)]
        return descriptions[:limit]


# ---------------------------------------------------------------------------
# CommandHistoryService
# ---------------------------------------------------------------------------


class CommandHistoryService:
    """Сервис управления историей команд.

    Управляет историей для нескольких документов (MDI).
    Предоставляет API для:
    - Регистрации команд
    - Undo/Redo
    - Получения истории

    Пример:
        >>> history = CommandHistoryService()
        >>> history.register(document_id, InsertTextCommand(...))
        >>> history.can_undo(document_id)
        True
        >>> history.undo(document_id)
    """

    def __init__(
        self,
        max_history_per_document: int = 100,
        max_documents: int = 50,
    ) -> None:
        """Инициализирует сервис истории.

        Args:
            max_history_per_document: Максимум команд в истории на документ
            max_documents: Максимум документов с историей
        """
        self._max_history = max_history_per_document
        self._max_documents = max_documents
        self._histories: dict[UUID, CommandHistory] = {}

    # ---------- Управление документами ----------

    def create_history(self, document_id: UUID) -> CommandHistory:
        """Создаёт историю для документа.

        Args:
            document_id: Идентификатор документа

        Returns:
            Созданная история
        """
        if document_id in self._histories:
            return self._histories[document_id]

        if len(self._histories) >= self._max_documents:
            # Удаляем старейшую историю
            oldest_id = next(iter(self._histories))
            del self._histories[oldest_id]
            logger.debug("Удалена история для документа %s (limite)", oldest_id)

        history = CommandHistory(
            document_id=document_id,
            max_size=self._max_history,
        )
        self._histories[document_id] = history
        logger.debug("Создана история для документа %s", document_id)
        return history

    def remove_history(self, document_id: UUID) -> None:
        """Удаляет историю документа.

        Args:
            document_id: Идентификатор документа
        """
        if document_id in self._histories:
            del self._histories[document_id]
            logger.debug("Удалена история для документа %s", document_id)

    def get_history(self, document_id: UUID) -> Optional[CommandHistory]:
        """Возвращает историю документа.

        Args:
            document_id: Идентификатор документа

        Returns:
            История или None
        """
        return self._histories.get(document_id)

    # ---------- Выполнение команд ----------

    def execute(
        self,
        document_id: UUID,
        command: CommandProtocol,
    ) -> HistoryResult[Any]:
        """Выполняет команду и добавляет в историю.

        Args:
            document_id: Идентификатор документа
            command: Команда для выполнения

        Returns:
            HistoryResult с результатом выполнения
        """
        # Создаём историю если нет
        history = self.get_history(document_id)
        if history is None:
            history = self.create_history(document_id)

        try:
            result = command.execute()
            history.push(command)
            logger.debug(
                "Выполнена команда '%s' для документа %s",
                command.description,
                document_id,
            )
            return HistoryResult(success=True, result=result)

        except Exception as exc:
            error = f"Ошибка выполнения команды: {exc}"
            logger.error(error, exc_info=True)
            return HistoryResult(success=False, error=error)

    def add_text_insert(
        self,
        document_id: UUID,
        position: int,
        text: str,
    ) -> None:
        """Добавляет вставку текста с группировкой по слову.

        Символы слова группируются в одну команду.
        Разделители завершают группировку.
        Пауза > 2 секунд также завершает группировку.

        Args:
            document_id: Идентификатор документа
            position: Позиция вставки
            text: Вставляемый текст
        """
        history = self.get_history(document_id)
        if history is None:
            history = self.create_history(document_id)

        history.add_text_insert(position, text)
        logger.debug(
            "Добавлена вставка '%s' в позицию %d для документа %s",
            text,
            position,
            document_id,
        )

    def add_text_delete(
        self,
        document_id: UUID,
        position: int,
        length: int,
    ) -> None:
        """Добавляет удаление текста (завершает группировку по слову).

        Args:
            document_id: Идентификатор документа
            position: Позиция удаления
            length: Длина удаляемого текста
        """
        history = self.get_history(document_id)
        if history is None:
            history = self.create_history(document_id)

        history.add_text_delete(position, length)
        logger.debug(
            "Добавлено удаление %d символов в позиции %d для документа %s",
            length,
            position,
            document_id,
        )

    def get_pending_word(self, document_id: UUID) -> str:
        """Возвращает текущее накапливаемое слово.

        Args:
            document_id: Идентификатор документа

        Returns:
            Текущее слово (если есть)
        """
        history = self._histories.get(document_id)
        if history is None:
            return ""
        return history.get_pending_word()

    # ---------- Undo/Redo ----------

    def can_undo(self, document_id: UUID) -> bool:
        """Проверяет возможность отмены.

        Args:
            document_id: Идентификатор документа

        Returns:
            True если можно отменить
        """
        history = self._histories.get(document_id)
        return history.can_undo() if history else False

    def can_redo(self, document_id: UUID) -> bool:
        """Проверяет возможность повтора.

        Args:
            document_id: Идентификатор документа

        Returns:
            True если можно повторить
        """
        history = self._histories.get(document_id)
        return history.can_redo() if history else False

    def undo(self, document_id: UUID) -> HistoryResult[Any]:
        """Отменяет последнюю команду.

        Args:
            document_id: Идентификатор документа

        Returns:
            HistoryResult с результатом отмены
        """
        history = self._histories.get(document_id)
        if history is None:
            return HistoryResult(success=False, error="История не найдена")

        command = history.pop_undo()
        if command is None:
            return HistoryResult(success=False, error="Нечего отменять")

        try:
            result = command.undo()
            history.push_redo(command)
            logger.info(
                "Отменена команда '%s' для документа %s",
                command.description,
                document_id,
            )
            return HistoryResult(success=True, result=result)

        except Exception as exc:
            # Возвращаем команду в стек
            history.push_undo(command)
            error = f"Ошибка отмены команды: {exc}"
            logger.error(error, exc_info=True)
            return HistoryResult(success=False, error=error)

    def redo(self, document_id: UUID) -> HistoryResult[Any]:
        """Повторяет отменённую команду.

        Args:
            document_id: Идентификатор документа

        Returns:
            HistoryResult с результатом повтора
        """
        history = self._histories.get(document_id)
        if history is None:
            return HistoryResult(success=False, error="История не найдена")

        command = history.pop_redo()
        if command is None:
            return HistoryResult(success=False, error="Нечего повторять")

        try:
            result = command.execute()
            history.push_undo(command)
            logger.info(
                "Повторена команда '%s' для документа %s",
                command.description,
                document_id,
            )
            return HistoryResult(success=True, result=result)

        except Exception as exc:
            # Возвращаем команду в redo стек
            history.push_redo(command)
            error = f"Ошибка повтора команды: {exc}"
            logger.error(error, exc_info=True)
            return HistoryResult(success=False, error=error)

    # ---------- Информация о состоянии ----------

    def get_undo_count(self, document_id: UUID) -> int:
        """Возвращает количество команд для отмены.

        Args:
            document_id: Идентификатор документа

        Returns:
            Количество команд
        """
        history = self._histories.get(document_id)
        return history.undo_count if history else 0

    def get_redo_count(self, document_id: UUID) -> int:
        """Возвращает количество команд для повтора.

        Args:
            document_id: Идентификатор документа

        Returns:
            Количество команд
        """
        history = self._histories.get(document_id)
        return history.redo_count if history else 0

    def get_undo_descriptions(
        self,
        document_id: UUID,
        limit: int = 10,
    ) -> List[str]:
        """Возвращает описания команд для отмены.

        Args:
            document_id: Идентификатор документа
            limit: Максимум описаний

        Returns:
            Список описаний
        """
        history = self._histories.get(document_id)
        if history is None:
            return []
        return history.get_undo_descriptions(limit)

    def get_redo_descriptions(
        self,
        document_id: UUID,
        limit: int = 10,
    ) -> List[str]:
        """Возвращает описания команд для повтора.

        Args:
            document_id: Идентификатор документа
            limit: Максимум описаний

        Returns:
            Список описаний
        """
        history = self._histories.get(document_id)
        if history is None:
            return []
        return history.get_redo_descriptions(limit)

    def clear(self, document_id: UUID) -> None:
        """Очищает историю документа.

        Args:
            document_id: Идентификатор документа
        """
        history = self._histories.get(document_id)
        if history:
            history.clear()
            logger.debug("Очищена история для документа %s", document_id)

    def clear_all(self) -> None:
        """Очищает все истории."""
        self._histories.clear()
        logger.debug("Очищены все истории")


__all__ = [
    "CommandHistoryService",
    "CommandHistory",
    "CommandProtocol",
    "HistoryResult",
    "TextEditCommand",
    "CombinedTextCommand",
    "WordCommandGrouper",
]
