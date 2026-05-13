"""Data classes for Form Designer.

Module: src/gui/form_designer/types.py
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field
from typing import Optional

from src.gui.renderers.form_canvas import FormCanvas, FormFieldWidget
from src.services.paper_format_service import PaperProfile


@dataclass
class DesignerPage:
    """Страница в DesignerTab.

    Attributes:
        index: Индекс страницы (0-based).
        profile: Профиль бумаги для страницы.
        canvas: FormCanvas для отрисовки полей.
        frame: Frame-контейнер в scrollable области.
        fields: Список виджетов полей на странице.
        page_break_id: ID линии разрыва страницы на canvas.
    """

    index: int
    profile: PaperProfile
    canvas: FormCanvas
    frame: tk.Frame
    fields: list[FormFieldWidget] = field(default_factory=list)
    page_break_id: Optional[int] = None


__all__ = ["DesignerPage"]
