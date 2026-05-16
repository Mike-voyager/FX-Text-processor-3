"""conftest для обхода legacy циркулярного импорта в src.gui.components.__init__.py.

src.gui.components.__init__ содержит циркулярный импорт (form_field ↔ renderers).
Чтобы тесты модуля sync могли импортировать подмодули напрямую,
подменяем родительский пакет на namespace package с корректным __path__
(без выполнения __init__.py).
"""

from __future__ import annotations

import sys
import types
from pathlib import Path


def _ensure_namespace() -> None:
    _repo_root = Path(__file__).resolve().parents[5]
    _components_dir = str(_repo_root / "src" / "gui" / "components")

    # src.gui.components
    if "src.gui.components" not in sys.modules:
        import src.gui.components  # noqa: F401

    mod = sys.modules["src.gui.components"]
    if not hasattr(mod, "__path__"):
        mod.__path__ = [_components_dir]

    # src.gui.components.sync
    sync_dir = str(_repo_root / "src" / "gui" / "components" / "sync")
    if "src.gui.components.sync" not in sys.modules:
        sync_pkg = types.ModuleType("src.gui.components.sync")
        sync_pkg.__path__ = [sync_dir]
        sys.modules["src.gui.components.sync"] = sync_pkg

    # src.gui.components.base
    base_dir = str(_repo_root / "src" / "gui" / "components" / "base")
    if "src.gui.components.base" not in sys.modules:
        base_pkg = types.ModuleType("src.gui.components.base")
        base_pkg.__path__ = [base_dir]
        sys.modules["src.gui.components.base"] = base_pkg


_ensure_namespace()
