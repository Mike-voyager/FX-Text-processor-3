"""Панель инструментов для работы с бумагой.

Placeholder — модуль будет реализован в Phase 7.

Version: 0.1
Date: May 2026
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from typing import Optional

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol
from src.services.paper_format_service import Orientation, PaperSize


@dataclass(frozen=True)
class PaperConfig:
    """Конфигурация бумаги (placeholder).

    Attributes:
        paper_size: Размер бумаги.
        cpi: Символов на дюйм.
        line_spacing: Межстрочный интервал.
        paper_source: Источник бумаги.
        width_mm: Ширина бумаги в мм.
        height_mm: Высота бумаги в мм.
        top_margin_mm: Верхнее поле в мм.
        bottom_margin_mm: Нижнее поле в мм.
        left_margin_mm: Левое поле в мм.
        right_margin_mm: Правое поле в мм.
        orientation: Ориентация.
        skip_perforation: Пропускать перфорацию.
        perforation_enabled: Перфорация включена.
        perforation_margin_mm: Отступ перфорации в мм.
        paper_form_type: Тип бумажной формы.
    """

    paper_size: PaperSize = PaperSize.A4
    cpi: int = 10
    line_spacing: str = "1/6"
    paper_source: str = "auto"
    width_mm: float = 210.0
    height_mm: float = 297.0
    top_margin_mm: float = 10.0
    bottom_margin_mm: float = 10.0
    left_margin_mm: float = 10.0
    right_margin_mm: float = 10.0
    orientation: Orientation = Orientation.PORTRAIT
    skip_perforation: bool = False
    perforation_enabled: bool = False
    perforation_margin_mm: float = 0.0
    paper_form_type: str = "custom"


class PaperToolbar(BaseWidget):
    """Панель инструментов для работы с бумагой (placeholder).

    Attributes:
        widget_id: Уникальный идентификатор виджета.
    """

    def __init__(
        self,
        widget_id: str = "paper_toolbar",
        controller: Optional[ControllerProtocol] = None,
    ) -> None:
        """Инициализация панели.

        Args:
            widget_id: Идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
        """
        super().__init__(widget_id=widget_id, controller=controller)

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт placeholder виджет.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный Frame виджет.
        """
        return tk.Frame(parent)


__all__ = [
    "PaperConfig",
    "PaperToolbar",
]
