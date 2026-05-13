"""Unit-тесты для WindowManager сервиса.

Проверяет:
- Регистрация окон с генерацией UUID
- Ограничение максимального количества окон (MAX_WINDOWS=50)
- Отслеживание модальных окон
- Управление Z-order (bring_to_front)
- Минимизация и восстановление окон
- Закрытие всех окон кроме главного (session lock)
- Перенос документов между окнами
- Получение списка окон с сортировкой

Coverage target: ≥90%
"""

from __future__ import annotations

import tkinter as tk
import uuid
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest

# WindowManager будет импортирован из предполагаемого расположения
# Если сервис ещё не реализован, импорт вызовет ошибку
pytest.importorskip("src.gui.services.window_manager", reason="WindowManager not implemented yet")

from src.gui.services.window_manager import MAX_WINDOWS, WindowManager, WindowInfo


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def mock_root() -> Generator[tk.Tk, None, None]:
    """Создаёт mock root окно для тестов.

    Returns:
        Tk root window в скрытом состоянии.
    """
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def window_manager(mock_root: tk.Tk) -> WindowManager:
    """Создаёт экземпляр WindowManager для тестов.

    Args:
        mock_root: Корневое окно приложения.

    Returns:
        Инициализированный WindowManager.
    """
    return WindowManager(root=mock_root)


@pytest.fixture
def sample_window(mock_root: tk.Tk) -> Generator[tk.Toplevel, None, None]:
    """Создаёт sample Toplevel окно для тестов.

    Args:
        mock_root: Корневое окно приложения.

    Yields:
        Toplevel окно для тестирования.
    """
    window = tk.Toplevel(mock_root)
    window.withdraw()
    yield window
    try:
        window.destroy()
    except tk.TclError:
        pass


@pytest.fixture
def sample_window_2(mock_root: tk.Tk) -> Generator[tk.Toplevel, None, None]:
    """Создаёт второе sample Toplevel окно для тестов.

    Args:
        mock_root: Корневое окно приложения.

    Yields:
        Второе Toplevel окно для тестирования.
    """
    window = tk.Toplevel(mock_root)
    window.withdraw()
    yield window
    try:
        window.destroy()
    except tk.TclError:
        pass


# =============================================================================
# TEST: Window Registration
# =============================================================================


@pytest.mark.gui
class TestWindowRegistration:
    """Тесты регистрации окон в WindowManager."""

    def test_register_window_returns_valid_id(
        self,
        window_manager: WindowManager,
        sample_window: tk.Toplevel,
    ) -> None:
        """register_window возвращает валидный UUID.

        Проверяет, что ID соответствует формату UUID v4.
        """
        window_id = window_manager.register_window(sample_window)

        assert isinstance(window_id, str)
        # Проверяем, что строка является валидным UUID
        try:
            uuid.UUID(window_id)
            is_valid_uuid = True
        except ValueError:
            is_valid_uuid = False
        assert is_valid_uuid, f"Window ID {window_id} is not a valid UUID"

    def test_register_window_increments_count(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """register_window увеличивает счётчик зарегистрированных окон.

        Проверяет, что количество окон увеличивается при каждой регистрации.
        """
        initial_count = len(window_manager.get_window_list())

        # Регистрируем несколько окон
        windows: list[tk.Toplevel] = []
        for _ in range(3):
            win = tk.Toplevel(mock_root)
            win.withdraw()
            windows.append(win)
            window_manager.register_window(win)

        final_count = len(window_manager.get_window_list())
        assert final_count == initial_count + 3

        # Cleanup
        for win in windows:
            try:
                win.destroy()
            except tk.TclError:
                pass

    def test_register_window_enforces_max_limit(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """register_window применяет ограничение MAX_WINDOWS=50.

        Проверяет, что при попытке регистрации 51-го окна
        возникает RuntimeError.
        """
        windows: list[tk.Toplevel] = []

        # Регистрируем максимальное количество окон
        for i in range(MAX_WINDOWS):
            win = tk.Toplevel(mock_root)
            win.withdraw()
            windows.append(win)
            window_manager.register_window(win)

        assert len(window_manager.get_window_list()) == MAX_WINDOWS

        # Попытка регистрации 51-го окна должна вызвать ошибку
        extra_window = tk.Toplevel(mock_root)
        extra_window.withdraw()

        with pytest.raises(RuntimeError, match="Maximum window limit"):
            window_manager.register_window(extra_window)

        # Cleanup
        try:
            extra_window.destroy()
        except tk.TclError:
            pass
        for win in windows:
            try:
                win.destroy()
            except tk.TclError:
                pass

    def test_register_window_tracks_modal_flag(
        self,
        window_manager: WindowManager,
        sample_window: tk.Toplevel,
    ) -> None:
        """register_window корректно отслеживает флаг is_modal.

        Проверяет, что модальное окно помечается соответствующим флагом.
        """
        # Регистрируем немодальное окно
        non_modal_id = window_manager.register_window(sample_window, is_modal=False)
        # Регистрируем модальное окно
        modal_window = tk.Toplevel(window_manager._root)
        modal_window.withdraw()
        modal_id = window_manager.register_window(modal_window, is_modal=True)

        # Получаем информацию об окнах
        non_modal_info = window_manager.get_window_info(non_modal_id)
        modal_info = window_manager.get_window_info(modal_id)

        assert non_modal_info is not None
        assert modal_info is not None
        assert non_modal_info.is_modal is False
        assert modal_info.is_modal is True

        # Cleanup
        try:
            modal_window.destroy()
        except tk.TclError:
            pass


# =============================================================================
# TEST: Window Unregistration
# =============================================================================


@pytest.mark.gui
class TestWindowUnregistration:
    """Тесты отмены регистрации окон."""

    def test_unregister_window_removes_from_registry(
        self,
        window_manager: WindowManager,
        sample_window: tk.Toplevel,
    ) -> None:
        """unregister_window удаляет окно из реестра.

        Проверяет, что после отмены регистрации окно
        больше не доступно через get_window.
        """
        window_id = window_manager.register_window(sample_window)
        assert window_manager.get_window(window_id) is not None

        window_manager.unregister_window(window_id)

        assert window_manager.get_window(window_id) is None

    def test_unregister_window_updates_list(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """unregister_window обновляет список окон.

        Проверяет, что список окон корректно обновляется
        после удаления окна из реестра.
        """
        # Создаём и регистрируем несколько окон
        windows: list[tk.Toplevel] = []
        window_ids: list[str] = []
        for _ in range(3):
            win = tk.Toplevel(mock_root)
            win.withdraw()
            windows.append(win)
            wid = window_manager.register_window(win)
            window_ids.append(wid)

        initial_count = len(window_manager.get_window_list())
        assert initial_count == 3

        # Отменяем регистрацию одного окна
        window_manager.unregister_window(window_ids[1])

        final_count = len(window_manager.get_window_list())
        assert final_count == 2

        # Проверяем, что оставшиеся окна всё ещё в списке
        remaining_ids = [info.window_id for info in window_manager.get_window_list()]
        assert window_ids[0] in remaining_ids
        assert window_ids[1] not in remaining_ids
        assert window_ids[2] in remaining_ids

        # Cleanup
        for win in windows:
            try:
                win.destroy()
            except tk.TclError:
                pass

    def test_unregister_nonexistent_window_raises_error(
        self,
        window_manager: WindowManager,
    ) -> None:
        """unregister_window вызывает ValueError для несуществующего окна.

        Проверяет, что попытка отменить регистрацию несуществующего
        окна приводит к возникновению исключения.
        """
        fake_id = str(uuid.uuid4())

        with pytest.raises(ValueError, match="Window not found"):
            window_manager.unregister_window(fake_id)


# =============================================================================
# TEST: Window Operations
# =============================================================================


@pytest.mark.gui
class TestWindowOperations:
    """Тесты операций с окнами."""

    def test_get_window_returns_toplevel(
        self,
        window_manager: WindowManager,
        sample_window: tk.Toplevel,
    ) -> None:
        """get_window возвращает зарегистрированное Toplevel окно.

        Проверяет, что метод возвращает корректный объект окна
        по его идентификатору.
        """
        window_id = window_manager.register_window(sample_window)
        retrieved_window = window_manager.get_window(window_id)

        assert retrieved_window is sample_window
        assert isinstance(retrieved_window, tk.Toplevel)

    def test_get_window_returns_none_for_invalid_id(
        self,
        window_manager: WindowManager,
    ) -> None:
        """get_window возвращает None для невалидного ID.

        Проверяет, что метод корректно обрабатывает
        запросы с несуществующими ID.
        """
        fake_id = str(uuid.uuid4())
        result = window_manager.get_window(fake_id)

        assert result is None

    def test_bring_to_front_changes_z_order(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """bring_to_front изменяет Z-order окна.

        Проверяет, что окно перемещается на передний план
        и обновляется его порядок в списке.
        """
        # Создаём и регистрируем несколько окон
        windows: list[tk.Toplevel] = []
        window_ids: list[str] = []
        for i in range(3):
            win = tk.Toplevel(mock_root)
            win.withdraw()
            windows.append(win)
            wid = window_manager.register_window(win)
            window_ids.append(wid)

        # Первое окно должно быть внизу списка
        initial_list = window_manager.get_window_list()
        assert initial_list[0].window_id == window_ids[0]

        # Перемещаем первое окно на передний план
        window_manager.bring_to_front(window_ids[0])

        # Теперь первое окно должно быть наверху
        updated_list = window_manager.get_window_list()
        assert updated_list[-1].window_id == window_ids[0]

        # Cleanup
        for win in windows:
            try:
                win.destroy()
            except tk.TclError:
                pass

    def test_minimize_all_windows(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """minimize_all сворачивает все окна.

        Проверяет, что все зарегистрированные окна
        переходят в свёрнутое состояние.
        """
        # Создаём и регистрируем несколько окон
        windows: list[tk.Toplevel] = []
        for _ in range(3):
            win = tk.Toplevel(mock_root)
            win.withdraw()
            windows.append(win)
            window_manager.register_window(win)

        # Мокаем метод iconify для проверки
        for win in windows:
            win.iconify = MagicMock()  # type: ignore[method-assign]

        window_manager.minimize_all()

        # Проверяем, что iconify был вызван для каждого окна
        for win in windows:
            win.iconify.assert_called_once()  # type: ignore[attr-defined]

        # Cleanup
        for win in windows:
            try:
                win.destroy()
            except tk.TclError:
                pass

    def test_restore_all_windows(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """restore_all восстанавливает все окна.

        Проверяет, что все зарегистрированные окна
        восстанавливаются из свёрнутого состояния.
        """
        # Создаём и регистрируем несколько окон
        windows: list[tk.Toplevel] = []
        for _ in range(3):
            win = tk.Toplevel(mock_root)
            win.withdraw()
            windows.append(win)
            window_manager.register_window(win)

        # Мокаем метод deiconify для проверки
        for win in windows:
            win.deiconify = MagicMock()  # type: ignore[method-assign]

        window_manager.restore_all()

        # Проверяем, что deiconify был вызван для каждого окна
        for win in windows:
            win.deiconify.assert_called_once()  # type: ignore[attr-defined]

        # Cleanup
        for win in windows:
            try:
                win.destroy()
            except tk.TclError:
                pass


# =============================================================================
# TEST: Session Lock
# =============================================================================


@pytest.mark.gui
class TestSessionLock:
    """Тесты блокировки сессии (закрытие окон кроме главного)."""

    def test_close_all_except_main_closes_dialogs(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """close_all_except_main закрывает диалоговые окна.

        Проверяет, что все диалоги и вспомогательные окна
        закрываются при вызове метода.
        """
        # Создаём главное окно (первое зарегистрированное)
        main_window = tk.Toplevel(mock_root)
        main_window.withdraw()
        main_id = window_manager.register_window(main_window, is_main=True)

        # Создаём диалоговые окна
        dialogs: list[tk.Toplevel] = []
        for _ in range(3):
            dialog = tk.Toplevel(mock_root)
            dialog.withdraw()
            dialogs.append(dialog)
            window_manager.register_window(dialog, is_modal=True)

        # Мокаем метод destroy для диалогов
        for dialog in dialogs:
            dialog.destroy = MagicMock()  # type: ignore[method-assign]

        # Вызываем закрытие всех окон кроме главного
        window_manager.close_all_except_main()

        # Проверяем, что destroy был вызван для диалогов
        for dialog in dialogs:
            dialog.destroy.assert_called_once()  # type: ignore[attr-defined]

        # Cleanup
        try:
            main_window.destroy()
        except tk.TclError:
            pass

    def test_close_all_except_main_preserves_main(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """close_all_except_main сохраняет главное окно.

        Проверяет, что главное окно остаётся открытым
        после вызова метода.
        """
        # Создаём главное окно
        main_window = tk.Toplevel(mock_root)
        main_window.withdraw()
        main_id = window_manager.register_window(main_window, is_main=True)

        # Создаём диалог
        dialog = tk.Toplevel(mock_root)
        dialog.withdraw()
        window_manager.register_window(dialog)

        # Мокаем метод destroy для главного окна (не должен вызываться)
        main_window.destroy = MagicMock()  # type: ignore[method-assign]

        # Вызываем закрытие
        window_manager.close_all_except_main()

        # Проверяем, что destroy НЕ был вызван для главного окна
        main_window.destroy.assert_not_called()  # type: ignore[attr-defined]

        # Проверяем, что главное окно всё ещё в реестре
        assert window_manager.get_window(main_id) is not None

        # Cleanup
        try:
            main_window.destroy()
        except tk.TclError:
            pass
        try:
            dialog.destroy()
        except tk.TclError:
            pass


# =============================================================================
# TEST: Document Transfer
# =============================================================================


@pytest.mark.gui
class TestDocumentTransfer:
    """Тесты переноса документов между окнами."""

    def test_transfer_document_moves_doc_id(
        self,
        window_manager: WindowManager,
        sample_window: tk.Toplevel,
        sample_window_2: tk.Toplevel,
    ) -> None:
        """transfer_document перемещает документ между окнами.

        Проверяет, что идентификатор документа корректно
        переносится от одного окна к другому.
        """
        # Регистрируем оба окна
        window_id_1 = window_manager.register_window(sample_window)
        window_id_2 = window_manager.register_window(sample_window_2)

        # Назначаем документ первому окну
        doc_id = "doc-123-abc"
        window_manager.assign_document(window_id_1, doc_id)

        # Переносим документ во второе окно
        result = window_manager.transfer_document(window_id_1, window_id_2, doc_id)

        assert result is True

        # Проверяем, что документ теперь у второго окна
        info_1 = window_manager.get_window_info(window_id_1)
        info_2 = window_manager.get_window_info(window_id_2)

        assert info_1 is not None
        assert info_2 is not None
        assert doc_id not in info_1.documents
        assert doc_id in info_2.documents

    def test_transfer_document_returns_false_for_invalid_window(
        self,
        window_manager: WindowManager,
        sample_window: tk.Toplevel,
    ) -> None:
        """transfer_document возвращает False для невалидного окна.

        Проверяет, что метод корректно обрабатывает
        попытку переноса в несуществующее окно.
        """
        window_id = window_manager.register_window(sample_window)
        fake_id = str(uuid.uuid4())
        doc_id = "doc-123-abc"

        # Пытаемся перенести в несуществующее окно
        result = window_manager.transfer_document(window_id, fake_id, doc_id)

        assert result is False

    def test_transfer_document_updates_window_info(
        self,
        window_manager: WindowManager,
        sample_window: tk.Toplevel,
        sample_window_2: tk.Toplevel,
    ) -> None:
        """transfer_document обновляет информацию об окнах.

        Проверяет, что после переноса информация об обоих
        окнах корректно обновлена.
        """
        # Регистрируем окна
        window_id_1 = window_manager.register_window(sample_window)
        window_id_2 = window_manager.register_window(sample_window_2)

        # Назначаем документы первому окну
        doc_ids = ["doc-1", "doc-2", "doc-3"]
        for doc_id in doc_ids:
            window_manager.assign_document(window_id_1, doc_id)

        # Переносим один документ
        window_manager.transfer_document(window_id_1, window_id_2, "doc-2")

        # Проверяем обновлённую информацию
        info_1 = window_manager.get_window_info(window_id_1)
        info_2 = window_manager.get_window_info(window_id_2)

        assert info_1 is not None
        assert info_2 is not None
        assert info_1.documents == ["doc-1", "doc-3"]
        assert info_2.documents == ["doc-2"]


# =============================================================================
# TEST: Window List
# =============================================================================


@pytest.mark.gui
class TestWindowList:
    """Тесты получения списка окон."""

    def test_get_window_list_returns_all_windows(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """get_window_list возвращает все зарегистрированные окна.

        Проверяет, что метод возвращает полный список
        зарегистрированных окон.
        """
        # Регистрируем несколько окон
        windows: list[tk.Toplevel] = []
        expected_ids: set[str] = set()
        for _ in range(5):
            win = tk.Toplevel(mock_root)
            win.withdraw()
            windows.append(win)
            wid = window_manager.register_window(win)
            expected_ids.add(wid)

        window_list = window_manager.get_window_list()
        actual_ids = {info.window_id for info in window_list}

        assert len(window_list) == 5
        assert actual_ids == expected_ids

        # Cleanup
        for win in windows:
            try:
                win.destroy()
            except tk.TclError:
                pass

    def test_get_window_list_is_sorted_by_z_order(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """get_window_list возвращает окна, отсортированные по Z-order.

        Проверяет, что список отсортирован от окна с
        наименьшим Z-order к окну с наибольшим (снизу вверх).
        """
        # Создаём и регистрируем окна в определённом порядке
        windows: list[tk.Toplevel] = []
        window_ids: list[str] = []
        for i in range(4):
            win = tk.Toplevel(mock_root)
            win.withdraw()
            windows.append(win)
            wid = window_manager.register_window(win)
            window_ids.append(wid)

        # Изначально список должен быть в порядке создания
        initial_list = window_manager.get_window_list()
        initial_order = [info.window_id for info in initial_list]
        assert initial_order == window_ids

        # Перемещаем второе окно на передний план
        window_manager.bring_to_front(window_ids[1])

        # Теперь второе окно должно быть последним
        updated_list = window_manager.get_window_list()
        updated_order = [info.window_id for info in updated_list]
        assert updated_order[-1] == window_ids[1]

        # Cleanup
        for win in windows:
            try:
                win.destroy()
            except tk.TclError:
                pass


# =============================================================================
# TEST: Additional Edge Cases
# =============================================================================


@pytest.mark.gui
class TestEdgeCases:
    """Дополнительные тесты граничных случаев."""

    def test_register_same_window_twice(
        self,
        window_manager: WindowManager,
        sample_window: tk.Toplevel,
    ) -> None:
        """register_window дважды для одного окна обновляет регистрацию.

        Проверяет поведение при повторной регистрации того же окна.
        """
        # Регистрируем окно первый раз
        id1 = window_manager.register_window(sample_window)
        # Регистрируем то же окно второй раз
        id2 = window_manager.register_window(sample_window)

        # ID должны совпадать (та же регистрация)
        assert id1 == id2

        # Должно быть только одно окно в списке
        assert len(window_manager.get_window_list()) == 1

    def test_window_info_contains_metadata(
        self,
        window_manager: WindowManager,
        sample_window: tk.Toplevel,
    ) -> None:
        """WindowInfo содержит корректные метаданные окна.

        Проверяет, что информация об окне включает все необходимые поля.
        """
        window_id = window_manager.register_window(sample_window, is_modal=True)
        info = window_manager.get_window_info(window_id)

        assert info is not None
        assert info.window_id == window_id
        assert info.window is sample_window
        assert info.is_modal is True
        assert info.z_order >= 0
        assert isinstance(info.documents, list)

    def test_clear_all_windows(
        self,
        window_manager: WindowManager,
        mock_root: tk.Tk,
    ) -> None:
        """clear_all удаляет все окна из реестра.

        Проверяет метод полной очистки реестра окон.
        """
        # Создаём несколько окон
        windows: list[tk.Toplevel] = []
        for _ in range(3):
            win = tk.Toplevel(mock_root)
            win.withdraw()
            windows.append(win)
            window_manager.register_window(win)

        assert len(window_manager.get_window_list()) == 3

        # Очищаем реестр (без уничтожения окон)
        window_manager.clear_all()

        assert len(window_manager.get_window_list()) == 0

        # Cleanup
        for win in windows:
            try:
                win.destroy()
            except tk.TclError:
                pass
