"""Общие фикстуры для тестов фабрик GUI.

Version: 1.0
Date: May 2026
"""

from __future__ import annotations

import sys
import tkinter as tk
from typing import Generator

import pytest

sys.path.insert(0, "/home/Mike/Dev/FX-Text-processor/FX-Text-processor-3")

# Skip all tests if no display available
try:
    _root_test = tk.Tk()
    _root_test.withdraw()
    HAS_DISPLAY = True
    _root_test.destroy()
except (RuntimeError, AttributeError, ImportError, OSError):
    HAS_DISPLAY = False


pytestmark = [
    pytest.mark.skipif(not HAS_DISPLAY, reason="No display available"),
    pytest.mark.gui,
]


@pytest.fixture
def tk_root() -> Generator[tk.Tk, None, None]:
    """Фикстура для root окна tkinter."""
    root = tk.Tk()
    root.withdraw()
    yield root
    root.destroy()
