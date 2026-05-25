"""Адаптеры для маппинга Model -> View протоколов.

Разрывают прямую зависимость View от Model, реализуя
DocumentViewProtocol и другие Protocol интерфейсы
поверх реальных объектов модели.

Архитектура:
    Model (Document) -> Adapter (DocumentViewAdapter) -> View (MainWindow)

Version: 1.0
Date: May 2026
"""

from src.gui.adapters.document_adapter import DocumentViewAdapter

__all__: list[str] = [
    "DocumentViewAdapter",
]
