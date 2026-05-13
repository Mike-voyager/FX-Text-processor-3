"""Корневой модуль FX Text Processor 3.

Предоставляет глобальные утилиты и настройки проекта.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


def get_logger(name: str) -> logging.Logger:
    """Получить логгер для модуля.

    Args:
        name: Имя модуля (__name__)

    Returns:
        Настроенный логгер
    """
    return logging.getLogger(name)


def setup_logging(
    level: int = logging.INFO,
    format_string: Optional[str] = None,
    log_file: Optional[Path] = None,
) -> None:
    """Настроить глобальное логирование.

    Args:
        level: Уровень логирования
        format_string: Формат строки лога
        log_file: Путь к файлу лога (опционально)
    """
    if format_string is None:
        format_string = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=level,
        format=format_string,
        handlers=handlers,
        force=True,
    )

    # Уменьшаем шум от библиотек
    logging.getLogger("PIL").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


__version__ = "3.0.0"
__author__ = "FX Text Processor Team"
