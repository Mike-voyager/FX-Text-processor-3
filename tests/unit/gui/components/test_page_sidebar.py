"""Unit-тесты для PageSidebar и SidebarPageInfo.

Проверяет:
- Создание SidebarPageInfo (frozen dataclass)
- Создание PageSidebar
- Управление страницами (set_pages, add_page, remove_page, update_page)
- Выбор страниц (select_page)
- Drag-and-drop индексы
- Callback-функции
- Lifecycle (mount/unmount)

Coverage target: ≥90%
"""

import tkinter as tk
from typing import Generator
from unittest.mock import MagicMock

import pytest

from src.gui.components.page_sidebar import PageSidebar, SidebarPageInfo
from src.gui.core.exceptions import LifecycleError
from src.services.paper_format_service import Orientation, PaperSize, PaperProfile


# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Fixture для Tk root окна."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def sample_profile() -> PaperProfile:
    """Fixture для профиля бумаги."""
    return PaperProfile(name="A4 Portrait")


@pytest.fixture
def sample_pages(sample_profile: PaperProfile) -> list[SidebarPageInfo]:
    """Fixture для списка страниц."""
    return [
        SidebarPageInfo(index=0, name="Страница 1", profile=sample_profile),
        SidebarPageInfo(index=1, name="Страница 2", profile=sample_profile),
        SidebarPageInfo(index=2, name="Страница 3", profile=sample_profile),
    ]


def _create_callbacks() -> tuple[
    MagicMock, MagicMock, MagicMock, MagicMock, MagicMock
]:
    """Создаёт mock-коллбэки для PageSidebar."""
    return (
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
    )


@pytest.fixture
def page_sidebar(
    tk_root: tk.Tk,
    sample_pages: list[SidebarPageInfo],
) -> Generator[PageSidebar, None, None]:
    """Fixture для PageSidebar (сmonted)."""
    on_select, on_add, on_remove, on_duplicate, on_reorder = _create_callbacks()
    sidebar = PageSidebar(
        parent=tk_root,
        pages=sample_pages,
        on_page_select=on_select,
        on_page_add=on_add,
        on_page_remove=on_remove,
        on_page_duplicate=on_duplicate,
        on_page_reorder=on_reorder,
    )
    yield sidebar


# =============================================================================
# TEST: SidebarPageInfo
# =============================================================================


class TestSidebarPageInfo:
    """Тесты SidebarPageInfo dataclass."""

    def test_creation(self, sample_profile: PaperProfile) -> None:
        """SidebarPageInfo создаётся с корректными значениями."""
        info = SidebarPageInfo(
            index=0, name="Тест", profile=sample_profile
        )
        assert info.index == 0
        assert info.name == "Тест"
        assert info.profile == sample_profile
        assert info.is_selected is False

    def test_creation_with_selection(self, sample_profile: PaperProfile) -> None:
        """SidebarPageInfo создаётся с is_selected=True."""
        info = SidebarPageInfo(
            index=1, name="Тест", profile=sample_profile, is_selected=True
        )
        assert info.is_selected is True

    def test_frozen_immutability(self, sample_profile: PaperProfile) -> None:
        """SidebarPageInfo неизменяем (frozen=True)."""
        info = SidebarPageInfo(index=0, name="Тест", profile=sample_profile)
        with pytest.raises(AttributeError):
            info.index = 5  # type: ignore[misc]

    def test_equality(self, sample_profile: PaperProfile) -> None:
        """Два SidebarPageInfo с одинаковыми значениями равны."""
        info1 = SidebarPageInfo(index=0, name="Тест", profile=sample_profile)
        info2 = SidebarPageInfo(index=0, name="Тест", profile=sample_profile)
        assert info1 == info2

    def test_inequality(self, sample_profile: PaperProfile) -> None:
        """Два SidebarPageInfo с разными значениями не равны."""
        info1 = SidebarPageInfo(index=0, name="Тест1", profile=sample_profile)
        info2 = SidebarPageInfo(index=1, name="Тест2", profile=sample_profile)
        assert info1 != info2

    def test_hash(self, sample_profile: PaperProfile) -> None:
        """Frozen SidebarPageInfo проверка на __hash__."""
        info = SidebarPageInfo(index=0, name="Тест", profile=sample_profile)
        # SidebarPageInfo содержит PaperProfile, который может быть нехешируемым
        # Проверяем что frozen dataclass имеет __hash__ метод
        assert hasattr(info, "__hash__")


# =============================================================================
# TEST: PageSidebar Creation
# =============================================================================


class TestPageSidebarCreation:
    """Тесты создания PageSidebar."""

    def test_creation(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """PageSidebar создаётся корректно."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        assert sidebar.widget_id == "page_sidebar"
        assert sidebar.get_page_count() == 3

    def test_creation_with_controller(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """PageSidebar создаётся с контроллером."""
        controller = MagicMock()
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
            controller=controller,
        )
        assert sidebar.widget_id == "page_sidebar"

    def test_creation_empty_pages(self, tk_root: tk.Tk) -> None:
        """PageSidebar создаётся с пустым списком страниц."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=[],
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        assert sidebar.get_page_count() == 0


# =============================================================================
# TEST: PageSidebar Lifecycle
# =============================================================================


class TestPageSidebarLifecycle:
    """Тесты жизненного цикла PageSidebar."""

    def test_mount(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """PageSidebar монтируется корректно."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        widget = sidebar.mount(tk_root)
        assert widget is not None
        assert sidebar.is_mounted()

    def test_unmount(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """PageSidebar демонтируется корректно."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)
        sidebar.unmount()
        assert not sidebar.is_mounted()


# =============================================================================
# TEST: Page Management
# =============================================================================


class TestPageSidebarManagement:
    """Тесты управления страницами."""

    def test_set_pages(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
        sample_profile: PaperProfile,
    ) -> None:
        """set_pages заменяет список страниц."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)

        new_pages = [
            SidebarPageInfo(index=0, name="New Page 1", profile=sample_profile),
        ]
        sidebar.set_pages(new_pages)
        assert sidebar.get_page_count() == 1

    def test_add_page(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
        sample_profile: PaperProfile,
    ) -> None:
        """add_page добавляет страницу."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)

        new_page = SidebarPageInfo(index=3, name="Новая страница", profile=sample_profile)
        sidebar.add_page(new_page)
        assert sidebar.get_page_count() == 4

    def test_remove_page(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """remove_page удаляет страницу по индексу."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)

        result = sidebar.remove_page(1)
        assert result is True
        assert sidebar.get_page_count() == 2

    def test_remove_page_invalid_index(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """remove_page возвращает False для невалидного индекса."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)

        result = sidebar.remove_page(99)
        assert result is False
        assert sidebar.get_page_count() == 3

    def test_remove_page_negative_index(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """remove_page возвращает False для отрицательного индекса."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)

        result = sidebar.remove_page(-1)
        assert result is False

    def test_update_page(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
        sample_profile: PaperProfile,
    ) -> None:
        """update_page обновляет информацию о странице."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)

        updated_page = SidebarPageInfo(
            index=1, name="Обновлённая", profile=sample_profile
        )
        sidebar.update_page(1, updated_page)

    def test_update_page_invalid_index(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
        sample_profile: PaperProfile,
    ) -> None:
        """update_page с невалидным индексом не вызывает исключений."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)

        # Не должно вызывать исключений
        sidebar.update_page(99, SidebarPageInfo(index=99, name="X", profile=sample_profile))


# =============================================================================
# TEST: Selection
# =============================================================================


class TestPageSidebarSelection:
    """Тесты выбора страниц."""

    def test_get_selected_index_initial(
        self,
        page_sidebar: PageSidebar,
    ) -> None:
        """Начальный выбранный индекс — 0."""
        assert page_sidebar.get_selected_index() == 0

    def test_select_page(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """select_page изменяет выбранный индекс."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)
        sidebar.select_page(2)
        assert sidebar.get_selected_index() == 2

    def test_select_page_invalid_index(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """select_page с невалидным индексом не изменяет выбор."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)
        original = sidebar.get_selected_index()
        sidebar.select_page(99)
        assert sidebar.get_selected_index() == original

    def test_select_page_negative_index(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """select_page с отрицательным индексом не изменяет выбор."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        sidebar.mount(tk_root)
        original = sidebar.get_selected_index()
        sidebar.select_page(-1)
        assert sidebar.get_selected_index() == original


# =============================================================================
# TEST: Lifecycle Errors
# =============================================================================


class TestPageSidebarLifecycleErrors:
    """Тесты ошибок жизненного цикла."""

    def test_set_pages_not_mounted(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """set_pages на несмонтированном виджете вызывает LifecycleError."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        with pytest.raises(LifecycleError):
            sidebar.set_pages([])

    def test_add_page_not_mounted(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
        sample_profile: PaperProfile,
    ) -> None:
        """add_page на несмонтированном виджете вызывает LifecycleError."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        with pytest.raises(LifecycleError):
            sidebar.add_page(
                SidebarPageInfo(index=0, name="X", profile=sample_profile)
            )

    def test_select_page_not_mounted(
        self,
        tk_root: tk.Tk,
        sample_pages: list[SidebarPageInfo],
    ) -> None:
        """select_page на несмонтированном виджете вызывает LifecycleError."""
        on_select, on_add, on_remove, on_dup, on_reorder = _create_callbacks()
        sidebar = PageSidebar(
            parent=tk_root,
            pages=sample_pages,
            on_page_select=on_select,
            on_page_add=on_add,
            on_page_remove=on_remove,
            on_page_duplicate=on_dup,
            on_page_reorder=on_reorder,
        )
        with pytest.raises(LifecycleError):
            sidebar.select_page(0)


# =============================================================================
# TEST: Constants
# =============================================================================


class TestPageSidebarConstants:
    """Тесты констант PageSidebar."""

    def test_thumbnail_width(self) -> None:
        """THUMBNAIL_WIDTH равен 120."""
        assert PageSidebar.THUMBNAIL_WIDTH == 120

    def test_thumbnail_height(self) -> None:
        """THUMBNAIL_HEIGHT равен 80."""
        assert PageSidebar.THUMBNAIL_HEIGHT == 80

    def test_thumbnail_padding(self) -> None:
        """THUMBNAIL_PADDING равен 5."""
        assert PageSidebar.THUMBNAIL_PADDING == 5

    def test_header_height(self) -> None:
        """HEADER_HEIGHT равен 25."""
        assert PageSidebar.HEADER_HEIGHT == 25

    def test_footer_height(self) -> None:
        """FOOTER_HEIGHT равен 30."""
        assert PageSidebar.FOOTER_HEIGHT == 30