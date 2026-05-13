"""Тесты CommandHistoryService.

Module: tests/unit/services/test_command_history_service.py
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import pytest

from src.services.command_history_service import (
    CommandHistory,
    CommandHistoryService,
    CommandProtocol,
    HistoryResult,
)


# ---------------------------------------------------------------------------
# Моки команд
# ---------------------------------------------------------------------------


@dataclass
class MockCommand(CommandProtocol):
    """Мок команды для тестов."""

    description_text: str = "Test command"
    execute_result: str = "executed"
    undo_result: str = "undone"
    execute_calls: int = 0
    undo_calls: int = 0
    should_fail: bool = False

    def execute(self) -> Any:
        """Выполняет команду."""
        if self.should_fail:
            raise RuntimeError("Execute failed")
        self.execute_calls += 1
        return self.execute_result

    def undo(self) -> Any:
        """Отменяет команду."""
        if self.should_fail:
            raise RuntimeError("Undo failed")
        self.undo_calls += 1
        return self.undo_result

    @property
    def description(self) -> str:
        """Описание команды."""
        return self.description_text


# ---------------------------------------------------------------------------
# Фикстуры
# ---------------------------------------------------------------------------


@pytest.fixture
def history() -> CommandHistory:
    """История команд."""
    return CommandHistory(document_id=uuid4(), max_size=10)


@pytest.fixture
def service() -> CommandHistoryService:
    """Сервис истории команд."""
    return CommandHistoryService(max_history_per_document=10, max_documents=5)


# ---------------------------------------------------------------------------
# Тесты CommandHistory
# ---------------------------------------------------------------------------


class TestCommandHistory:
    """Тесты истории команд."""

    def test_push_command(self, history: CommandHistory) -> None:
        """Тест добавления команды."""
        cmd = MockCommand(description_text="Insert text")

        history.push(cmd)

        assert history.can_undo()
        assert not history.can_redo()
        assert history.undo_count == 1

    def test_push_clears_redo_stack(self, history: CommandHistory) -> None:
        """Тест очистки redo стека при новой команде."""
        cmd1 = MockCommand(description_text="Command 1")
        cmd2 = MockCommand(description_text="Command 2")

        history.push(cmd1)
        history.pop_undo()
        history.push_redo(cmd1)

        assert history.can_redo()

        history.push(cmd2)
        assert not history.can_redo()

    def test_pop_undo(self, history: CommandHistory) -> None:
        """Тест извлечения из undo стека."""
        cmd1 = MockCommand(description_text="Command 1")
        cmd2 = MockCommand(description_text="Command 2")

        history.push(cmd1)
        history.push(cmd2)

        popped = history.pop_undo()
        assert popped == cmd2
        assert history.undo_count == 1

    def test_pop_redo(self, history: CommandHistory) -> None:
        """Тест извлечения из redo стека."""
        cmd = MockCommand()

        history.push_redo(cmd)
        assert history.can_redo()

        popped = history.pop_redo()
        assert popped == cmd
        assert not history.can_redo()

    def test_max_size_limit(self) -> None:
        """Тест ограничения размера истории."""
        history = CommandHistory(document_id=uuid4(), max_size=3)

        for i in range(5):
            history.push(MockCommand(description_text=f"Command {i}"))

        # Должно быть только 3 последние команды
        assert history.undo_count == 3
        descriptions = history.get_undo_descriptions()
        assert len(descriptions) == 3

    def test_get_descriptions(self, history: CommandHistory) -> None:
        """Тест получения описаний."""
        for i in range(5):
            history.push(MockCommand(description_text=f"Command {i}"))

        descriptions = history.get_undo_descriptions(limit=3)
        assert descriptions == ["Command 4", "Command 3", "Command 2"]

    def test_clear(self, history: CommandHistory) -> None:
        """Тест очистки истории."""
        history.push(MockCommand())
        history.push_redo(MockCommand())

        history.clear()

        assert not history.can_undo()
        assert not history.can_redo()
        assert history.undo_count == 0
        assert history.redo_count == 0


# ---------------------------------------------------------------------------
# Тесты CommandHistoryService
# ---------------------------------------------------------------------------


class TestCommandHistoryService:
    """Тесты сервиса истории команд."""

    def test_create_history(self, service: CommandHistoryService) -> None:
        """Тест создания истории."""
        doc_id = uuid4()
        history = service.create_history(doc_id)

        assert history is not None
        assert history.document_id == doc_id

    def test_get_history(self, service: CommandHistoryService) -> None:
        """Тест получения истории."""
        doc_id = uuid4()
        service.create_history(doc_id)

        history = service.get_history(doc_id)

        assert history is not None
        assert history.document_id == doc_id

    def test_remove_history(self, service: CommandHistoryService) -> None:
        """Тест удаления истории."""
        doc_id = uuid4()
        service.create_history(doc_id)

        service.remove_history(doc_id)

        assert service.get_history(doc_id) is None

    def test_execute_command(self, service: CommandHistoryService) -> None:
        """Тест выполнения команды."""
        doc_id = uuid4()
        cmd = MockCommand(description_text="Insert text")

        result = service.execute(doc_id, cmd)

        assert result.success
        assert result.result == "executed"
        assert cmd.execute_calls == 1
        assert service.can_undo(doc_id)
        assert not service.can_redo(doc_id)

    def test_execute_creates_history(self, service: CommandHistoryService) -> None:
        """Тест автоматического создания истории."""
        doc_id = uuid4()
        cmd = MockCommand()

        result = service.execute(doc_id, cmd)

        assert result.success
        assert service.get_history(doc_id) is not None

    def test_undo(self, service: CommandHistoryService) -> None:
        """Тест отмены команды."""
        doc_id = uuid4()
        cmd = MockCommand()
        service.execute(doc_id, cmd)

        result = service.undo(doc_id)

        assert result.success
        assert result.result == "undone"
        assert cmd.undo_calls == 1
        assert not service.can_undo(doc_id)
        assert service.can_redo(doc_id)

    def test_redo(self, service: CommandHistoryService) -> None:
        """Тест повтора команды."""
        doc_id = uuid4()
        cmd = MockCommand()
        service.execute(doc_id, cmd)
        service.undo(doc_id)

        result = service.redo(doc_id)

        assert result.success
        assert result.result == "executed"
        assert cmd.execute_calls == 2  # execute + redo
        assert service.can_undo(doc_id)
        assert not service.can_redo(doc_id)

    def test_undo_nothing(self, service: CommandHistoryService) -> None:
        """Тест отмены при пустой истории."""
        doc_id = uuid4()

        result = service.undo(doc_id)

        assert not result.success
        assert "не найдена" in (result.error or "").lower()

    def test_redo_nothing(self, service: CommandHistoryService) -> None:
        """Тест повтора при пустом redo стеке."""
        doc_id = uuid4()
        cmd = MockCommand()
        service.execute(doc_id, cmd)

        result = service.redo(doc_id)

        assert not result.success
        assert "нечего" in (result.error or "").lower()

    def test_execute_error(self, service: CommandHistoryService) -> None:
        """Тест ошибки выполнения команды."""
        doc_id = uuid4()
        cmd = MockCommand(should_fail=True)

        result = service.execute(doc_id, cmd)

        assert not result.success
        assert "ошибка" in (result.error or "").lower()

    def test_undo_error(self, service: CommandHistoryService) -> None:
        """Тест ошибки отмены команды."""
        doc_id = uuid4()
        cmd = MockCommand(should_fail=True)
        service.execute(doc_id, cmd)

        # Убираем should_fail для execute, но оставляем для undo
        cmd.should_fail = False
        service.execute(doc_id, cmd)
        cmd.should_fail = True

        result = service.undo(doc_id)

        assert not result.success

    def test_multiple_documents(self, service: CommandHistoryService) -> None:
        """Тест истории для нескольких документов."""
        doc_id1 = uuid4()
        doc_id2 = uuid4()

        service.execute(doc_id1, MockCommand(description_text="Doc 1 - Command 1"))
        service.execute(doc_id1, MockCommand(description_text="Doc 1 - Command 2"))
        service.execute(doc_id2, MockCommand(description_text="Doc 2 - Command 1"))

        assert service.get_undo_count(doc_id1) == 2
        assert service.get_undo_count(doc_id2) == 1

    def test_max_documents_limit(self) -> None:
        """Тест ограничения количества документов с историей."""
        service = CommandHistoryService(max_history_per_document=10, max_documents=2)

        # Создаём истории для 3 документов
        doc_id1 = uuid4()
        doc_id2 = uuid4()
        doc_id3 = uuid4()

        service.create_history(doc_id1)
        service.create_history(doc_id2)
        # При создании третьей, первая должна быть удалена
        service.create_history(doc_id3)

        assert service.get_history(doc_id1) is None
        assert service.get_history(doc_id2) is not None
        assert service.get_history(doc_id3) is not None

    def test_get_descriptions(self, service: CommandHistoryService) -> None:
        """Тест получения описаний."""
        doc_id = uuid4()
        for i in range(5):
            service.execute(doc_id, MockCommand(description_text=f"Command {i}"))

        undo_descs = service.get_undo_descriptions(doc_id, limit=3)
        assert len(undo_descs) == 3
        assert undo_descs == ["Command 4", "Command 3", "Command 2"]

    def test_clear(self, service: CommandHistoryService) -> None:
        """Тест очистки истории документа."""
        doc_id = uuid4()
        for i in range(3):
            service.execute(doc_id, MockCommand(description_text=f"Command {i}"))

        service.clear(doc_id)

        assert not service.can_undo(doc_id)
        assert not service.can_redo(doc_id)

    def test_clear_all(self, service: CommandHistoryService) -> None:
        """Тест очистки всех историй."""
        doc_id1 = uuid4()
        doc_id2 = uuid4()
        service.execute(doc_id1, MockCommand())
        service.execute(doc_id2, MockCommand())

        service.clear_all()

        assert service.get_history(doc_id1) is None
        assert service.get_history(doc_id2) is None


# ---------------------------------------------------------------------------
# Тесты интеграции
# ---------------------------------------------------------------------------


class TestIntegration:
    """Интеграционные тесты."""

    def test_full_undo_redo_cycle(self, service: CommandHistoryService) -> None:
        """Тест полного цикла undo/redo."""
        doc_id = uuid4()

        # Выполняем команды
        cmd1 = MockCommand(description_text="Insert 'A'")
        cmd2 = MockCommand(description_text="Insert 'B'")
        cmd3 = MockCommand(description_text="Delete 'A'")

        service.execute(doc_id, cmd1)
        service.execute(doc_id, cmd2)
        service.execute(doc_id, cmd3)

        # Проверяем состояние
        assert service.can_undo(doc_id)
        assert not service.can_redo(doc_id)
        assert service.get_undo_count(doc_id) == 3

        # Отменяем все
        service.undo(doc_id)  # undo cmd3
        service.undo(doc_id)  # undo cmd2
        service.undo(doc_id)  # undo cmd1

        assert not service.can_undo(doc_id)
        assert service.can_redo(doc_id)
        assert service.get_redo_count(doc_id) == 3

        # Повторяем все
        service.redo(doc_id)
        service.redo(doc_id)
        service.redo(doc_id)

        assert service.can_undo(doc_id)
        assert not service.can_redo(doc_id)

    def test_new_command_clears_redo(self, service: CommandHistoryService) -> None:
        """Тест очистки redo при новой команде."""
        doc_id = uuid4()

        service.execute(doc_id, MockCommand(description_text="Cmd 1"))
        service.execute(doc_id, MockCommand(description_text="Cmd 2"))
        service.undo(doc_id)

        assert service.can_redo(doc_id)

        # Новая команда очищает redo
        service.execute(doc_id, MockCommand(description_text="Cmd 3"))

        assert not service.can_redo(doc_id)
        assert service.get_undo_count(doc_id) == 2


# ---------------------------------------------------------------------------
# Тесты группировки по слову (WordCommandGrouper)
# ---------------------------------------------------------------------------


class TestWordCommandGrouper:
    """Тесты группировки команд по слову."""

    def test_is_word_character(self) -> None:
        """Тест определения символов слова."""
        from src.services.command_history_service import WordCommandGrouper

        grouper = WordCommandGrouper()

        assert grouper._is_word_character("a")
        assert grouper._is_word_character("A")
        assert grouper._is_word_character("0")
        assert grouper._is_word_character("_")
        assert not grouper._is_word_character(" ")
        assert not grouper._is_word_character(".")
        assert not grouper._is_word_character(",")
        assert not grouper._is_word_character("\n")

    def test_group_word_characters(self) -> None:
        """Тест группировки символов слова."""
        from src.services.command_history_service import WordCommandGrouper

        grouper = WordCommandGrouper()

        # Вводим слово "привет"
        result1 = grouper.add_insert(0, "п")
        result2 = grouper.add_insert(1, "р")
        result3 = grouper.add_insert(2, "и")
        result4 = grouper.add_insert(3, "в")
        result5 = grouper.add_insert(4, "е")
        result6 = grouper.add_insert(5, "т")

        # Пока разделителя нет, команды накапливаются
        assert result1 is None
        assert result2 is None
        assert result3 is None
        assert result4 is None
        assert result5 is None
        assert result6 is None

        # Проверяем накапливаемое слово
        assert grouper.get_pending_word() == "привет"

    def test_separator_flushes_group(self) -> None:
        """Тест разделителя, завершающего группировку."""
        from src.services.command_history_service import WordCommandGrouper, CombinedTextCommand

        grouper = WordCommandGrouper()

        # Вводим "привет "
        grouper.add_insert(0, "п")
        grouper.add_insert(1, "р")
        grouper.add_insert(2, "и")

        # Пробел завершает группировку (только слово, без разделителя)
        result = grouper.add_insert(3, " ")

        assert result is not None
        assert isinstance(result, CombinedTextCommand)
        assert result.description == "Ввод 'при'"
        assert len(result.commands) == 3  # п, р, и (разделитель отдельно)

    def test_flush_completes_group(self) -> None:
        """Тест явного завершения группировки."""
        from src.services.command_history_service import WordCommandGrouper, CombinedTextCommand

        grouper = WordCommandGrouper()

        # Вводим слово
        grouper.add_insert(0, "w")
        grouper.add_insert(1, "o")
        grouper.add_insert(2, "r")
        grouper.add_insert(3, "d")

        # Явно завершаем группировку
        result = grouper.flush()

        assert result is not None
        assert isinstance(result, CombinedTextCommand)
        assert result.description == "Ввод 'word'"
        assert len(result.commands) == 4

    def test_delete_flushes_group(self) -> None:
        """Тест удаления, завершающего группировку."""
        from src.services.command_history_service import WordCommandGrouper, CombinedTextCommand

        grouper = WordCommandGrouper()

        # Вводим слово
        grouper.add_insert(0, "t")
        grouper.add_insert(1, "e")
        grouper.add_insert(2, "s")

        # Удаление завершает группировку (только слово)
        result = grouper.add_delete(3, 1)

        assert result is not None
        assert isinstance(result, CombinedTextCommand)
        # Возвращается только слово (3 команды), удаление добавляется отдельно
        assert len(result.commands) == 3

    def test_empty_flush_returns_none(self) -> None:
        """Тест flush с пустым буфером."""
        from src.services.command_history_service import WordCommandGrouper

        grouper = WordCommandGrouper()

        result = grouper.flush()

        assert result is None

    def test_is_empty(self) -> None:
        """Тест проверки пустоты буфера."""
        from src.services.command_history_service import WordCommandGrouper

        grouper = WordCommandGrouper()

        assert grouper.is_empty()

        grouper.add_insert(0, "a")
        assert not grouper.is_empty()

        grouper.flush()
        assert grouper.is_empty()


class TestCommandHistoryWordGrouping:
    """Тесты интеграции группировки по слову с CommandHistory."""

    def test_add_text_insert_groups_by_word(self) -> None:
        """Тест группировки вставки текста."""
        history = CommandHistory(document_id=uuid4(), max_size=10)

        # Вводим слово
        history.add_text_insert(0, "h")
        history.add_text_insert(1, "e")
        history.add_text_insert(2, "l")
        history.add_text_insert(3, "l")
        history.add_text_insert(4, "o")

        # Пока группировка не завершена, в стеке ничего нет
        assert history.undo_count == 0

        # Завершаем группировку
        history.add_text_insert(5, " ")

        # Теперь есть одна команда
        assert history.undo_count == 1

    def test_undo_flushes_word_group(self) -> None:
        """Тест отмены с завершением группировки."""
        history = CommandHistory(document_id=uuid4(), max_size=10)

        # Вводим слово
        history.add_text_insert(0, "t")
        history.add_text_insert(1, "e")
        history.add_text_insert(2, "s")
        history.add_text_insert(3, "t")

        # Отмена должна завершить группировку и отменить
        command = history.pop_undo()

        assert command is not None
        assert history.undo_count == 0

    def test_regular_push_flushes_word_group(self) -> None:
        """Тест обычной команды, завершающей группировку."""
        history = CommandHistory(document_id=uuid4(), max_size=10)

        # Вводим слово
        history.add_text_insert(0, "a")
        history.add_text_insert(1, "b")

        assert history.undo_count == 0

        # Обычная команда завершает группировку
        history.push(MockCommand(description_text="Format"))

        # Две команды: ввод слова + обычная
        assert history.undo_count == 2


class TestCommandHistoryServiceWordGrouping:
    """Тесты группировки по слову в сервисе."""

    def test_add_text_insert_service(self) -> None:
        """Тест вставки текста через сервис."""
        service = CommandHistoryService()
        doc_id = uuid4()

        service.add_text_insert(doc_id, 0, "w")
        service.add_text_insert(doc_id, 1, "o")
        service.add_text_insert(doc_id, 2, "r")
        service.add_text_insert(doc_id, 3, "d")

        assert service.get_undo_count(doc_id) == 0

        # Разделитель завершает группировку
        service.add_text_insert(doc_id, 4, " ")

        assert service.get_undo_count(doc_id) == 1

    def test_get_pending_word(self) -> None:
        """Тест получения текущего слова."""
        service = CommandHistoryService()
        doc_id = uuid4()

        assert service.get_pending_word(doc_id) == ""

        service.add_text_insert(doc_id, 0, "t")
        service.add_text_insert(doc_id, 1, "e")
        service.add_text_insert(doc_id, 2, "s")

        assert service.get_pending_word(doc_id) == "tes"

        service.add_text_insert(doc_id, 3, "t")
        assert service.get_pending_word(doc_id) == "test"

    def test_undo_with_pending_word(self) -> None:
        """Тест отмены с накапливающимся словом."""
        service = CommandHistoryService()
        doc_id = uuid4()

        service.add_text_insert(doc_id, 0, "a")
        service.add_text_insert(doc_id, 1, "b")
        service.add_text_insert(doc_id, 2, "c")

        assert service.get_undo_count(doc_id) == 0

        # Отмена завершает группировку и отменяет слово
        result = service.undo(doc_id)

        # После flush появляется команда, которую можно отменить
        assert result.success
        # Команда была добавлена в историю и тут же извлечена для undo
        assert service.get_undo_count(doc_id) == 0

    def test_multiple_words(self) -> None:
        """Тест нескольких слов подряд."""
        service = CommandHistoryService()
        doc_id = uuid4()

        # "hello world "
        service.add_text_insert(doc_id, 0, "h")
        service.add_text_insert(doc_id, 1, "e")
        service.add_text_insert(doc_id, 2, "l")
        service.add_text_insert(doc_id, 3, "l")
        service.add_text_insert(doc_id, 4, "o")
        service.add_text_insert(doc_id, 5, " ")

        service.add_text_insert(doc_id, 6, "w")
        service.add_text_insert(doc_id, 7, "o")
        service.add_text_insert(doc_id, 8, "r")
        service.add_text_insert(doc_id, 9, "l")
        service.add_text_insert(doc_id, 10, "d")
        service.add_text_insert(doc_id, 11, " ")

        # Две команды: "hello " и "world "
        assert service.get_undo_count(doc_id) == 2