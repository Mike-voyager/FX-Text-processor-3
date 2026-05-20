# -*- coding: utf-8 -*-
"""Тесты для DesignerPage (Form Designer types).

Тестирует создание dataclass, immutability, defaults
и работу с полями страницы.

Version: 1.0
"""

from __future__ import annotations

from typing import Any, Generator
from unittest.mock import MagicMock

import pytest

TKINTER_AVAILABLE = False
DesignerPage: Any = None
try:
    import tkinter as tk

    from src.gui.form_designer.types import DesignerPage
    from src.services.paper_format_service import PaperProfile

    TKINTER_AVAILABLE = True
except (ImportError, AttributeError, OSError, RuntimeError):
    pass


pytestmark = pytest.mark.skipif(
    not TKINTER_AVAILABLE,
    reason="Tkinter недоступен",
)


@pytest.fixture
def root() -> Generator[tk.Tk, None, None]:
    """Создаёт Tk root для тестов."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()


@pytest.fixture
def mock_profile() -> MagicMock:
    """Создаёт mock PaperProfile."""
    profile = MagicMock(spec=PaperProfile)
    profile.name = "a4_tractor"
    return profile


class TestDesignerPage:
    """Тесты для DesignerPage dataclass."""

    def test_creation_with_required_fields(
        self,
        root: tk.Tk,
        mock_profile: MagicMock,
    ) -> None:
        """Тест создания страницы с обязательными полями."""
        canvas = MagicMock()
        frame = tk.Frame(root)

        page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=canvas,
            frame=frame,
        )

        assert page.index == 0
        assert page.profile is mock_profile
        assert page.canvas is canvas
        assert page.frame is frame

    def test_default_fields_empty(
        self,
        root: tk.Tk,
        mock_profile: MagicMock,
    ) -> None:
        """Тест что fields по умолчанию пустой список."""
        canvas = MagicMock()
        frame = tk.Frame(root)

        page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=canvas,
            frame=frame,
        )

        assert page.fields == []

    def test_default_page_break_id_none(
        self,
        root: tk.Tk,
        mock_profile: MagicMock,
    ) -> None:
        """Тест что page_break_id по умолчанию None."""
        canvas = MagicMock()
        frame = tk.Frame(root)

        page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=canvas,
            frame=frame,
        )

        assert page.page_break_id is None

    def test_with_page_break_id(
        self,
        root: tk.Tk,
        mock_profile: MagicMock,
    ) -> None:
        """Тест создания страницы с page_break_id."""
        canvas = MagicMock()
        frame = tk.Frame(root)

        page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=canvas,
            frame=frame,
            page_break_id=42,
        )

        assert page.page_break_id == 42

    def test_with_fields(
        self,
        root: tk.Tk,
        mock_profile: MagicMock,
    ) -> None:
        """Тест создания страницы с полями."""
        canvas = MagicMock()
        frame = tk.Frame(root)
        field_widget = MagicMock()

        page = DesignerPage(
            index=1,
            profile=mock_profile,
            canvas=canvas,
            frame=frame,
            fields=[field_widget],
        )

        assert len(page.fields) == 1
        assert page.fields[0] is field_widget

    def test_frozen_immutable(
        self,
        root: tk.Tk,
        mock_profile: MagicMock,
    ) -> None:
        """Тест что DesignerPage immutable (frozen=True)."""
        canvas = MagicMock()
        frame = tk.Frame(root)

        page = DesignerPage(
            index=0,
            profile=mock_profile,
            canvas=canvas,
            frame=frame,
        )

        with pytest.raises(AttributeError):
            page.index = 1  # type: ignore[misc]

    def test_equality_same_values(
        self,
        root: tk.Tk,
        mock_profile: MagicMock,
    ) -> None:
        """Тест равенства страниц с одинаковыми значениями."""
        canvas = MagicMock()
        frame1 = tk.Frame(root)
        frame2 = tk.Frame(root)

        page1 = DesignerPage(index=0, profile=mock_profile, canvas=canvas, frame=frame1)
        page2 = DesignerPage(index=0, profile=mock_profile, canvas=canvas, frame=frame2)

        # frozen dataclasses: __eq__ сравнивает по значениям полей
        # frame — другой объект, поэтому страницы не равны
        assert page1 != page2

    def test_different_index(
        self,
        root: tk.Tk,
        mock_profile: MagicMock,
    ) -> None:
        """Тест что страницы с разным индексом не равны."""
        canvas = MagicMock()
        frame = tk.Frame(root)

        page0 = DesignerPage(index=0, profile=mock_profile, canvas=canvas, frame=frame)
        page1 = DesignerPage(index=1, profile=mock_profile, canvas=canvas, frame=frame)

        assert page0 != page1

    def test_repr_contains_index(
        self,
        root: tk.Tk,
        mock_profile: MagicMock,
    ) -> None:
        """Тест что repr содержит индекс страницы."""
        canvas = MagicMock()
        frame = tk.Frame(root)

        page = DesignerPage(index=5, profile=mock_profile, canvas=canvas, frame=frame)

        repr_str = repr(page)
        assert "DesignerPage" in repr_str
        assert "index=5" in repr_str

    def test_all_exported(self) -> None:
        """Тест что __all__ содержит DesignerPage."""
        from src.gui.form_designer import types as types_mod

        assert "DesignerPage" in types_mod.__all__