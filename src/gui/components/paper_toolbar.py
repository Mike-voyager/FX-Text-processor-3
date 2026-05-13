"""Тулбар для настройки параметров бумаги и печати.

Предоставляет быстрый доступ к основным настройкам:
- Размер бумаги (A4, A5, Letter)
- CPI (символов на дюйм)
- Межстрочный интервал
- Источник бумаги

Security:
    - Все user input валидируются перед применением
    - Нет прямого доступа к файловой системе
    - Callbacks через Controller только с sanitize-данными

Example:
    >>> toolbar = PaperToolbar(widget_id="paper_toolbar", controller=ctrl)
    >>> toolbar.mount(parent_frame)
    >>> toolbar.set_paper_size("A4")

Version: 1.0
"""

from __future__ import annotations

import logging
import re
import tkinter as tk
from dataclasses import dataclass
from typing import Callable, Dict, Final, List, Optional, Tuple

from src.gui.components.base.widget import BaseWidget
from src.gui.core.protocols import ControllerProtocol
from src.gui.layout.layout_constants import PADDING_NORMAL, TOOLBAR_HEIGHT
from src.services.paper_format_service import Orientation, PaperSize

logger = logging.getLogger(__name__)

# =============================================================================
# CONSTANTS
# =============================================================================

# Допустимые значения CPI для FX-890
VALID_CPI_VALUES: Final[Tuple[int, ...]] = (10, 12, 15, 17, 20)

# Отображаемые названия размеров бумаги
PAPER_SIZE_DISPLAY: Final[Dict[PaperSize, str]] = {
    PaperSize.A4: "A4 (210×297 мм)",
    PaperSize.A5: "A5 (148×210 мм)",
    PaperSize.LETTER: 'Letter (8.5×11")',
    PaperSize.LEGAL: 'Legal (8.5×14")',
    PaperSize.A3: "A3 (297×420 мм)",
    PaperSize.TRACTOR_FULL: "Tractor Full (210×305 мм)",
    PaperSize.TRACTOR_HALF: "Tractor Half (210×152.5 мм)",
    PaperSize.TRACTOR_TRIPLET: "Tractor Triplet (210×101.6 мм)",
    PaperSize.ENVELOPE_DL: "Envelope DL (110×220 мм)",
    PaperSize.ENVELOPE_C5: "Envelope C5 (162×229 мм)",
}

# Отображаемые названия CPI
CPI_DISPLAY: Final[Dict[int, str]] = {
    10: "10 CPI (Pica)",
    12: "12 CPI (Elite)",
    15: "15 CPI (Condensed)",
    17: "17 CPI (Compressed)",
    20: "20 CPI (Ultra)",
}

# Отображаемые названия межстрочного интервала
LINE_SPACING_DISPLAY: Final[Dict[str, str]] = {
    "1/6": '1/6" (6 LPI)',
    "1/8": '1/8" (8 LPI)',
    "custom": "Произвольный (n/180)",
}

# Отображаемые названия источников бумаги
PAPER_SOURCE_DISPLAY: Final[Dict[str, str]] = {
    "tractor": "Тракторная подача",
    "manual": "Ручная подача",
    "auto": "Автовыбор",
}

# Regex для санитизации ввода
SANITIZE_PATTERN: Final[re.Pattern[str]] = re.compile(r"[<>&\"']")

# =============================================================================
# PaperConfig dataclass
# =============================================================================


@dataclass(frozen=True)
class PaperConfig:
    """Конфигурация настроек бумаги.

    Attrs:
        paper_size: Размер бумаги
        cpi: Символов на дюйм (10, 12, 15, 17, 20)
        line_spacing: Межстрочный интервал
        paper_source: Источник бумаги
        width_mm: Ширина бумаги в мм (для custom)
        height_mm: Высота бумаги в мм (для custom)
        top_margin_mm: Верхний отступ в мм
        bottom_margin_mm: Нижний отступ в мм
        left_margin_mm: Левый отступ в мм
        right_margin_mm: Правый отступ в мм
        orientation: Ориентация страницы
        skip_perforation: Пропускать линии перфорации
        perforation_enabled: Включена перфорация
        perforation_margin_mm: Отступ перфорации от верха (мм)
        paper_form_type: Тип бумажной формы
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

    def __post_init__(self) -> None:
        """Валидация значений после создания."""
        if self.cpi not in VALID_CPI_VALUES:
            raise ValueError(f"Недопустимое значение CPI: {self.cpi}")
        if self.line_spacing not in ("1/6", "1/8", "custom"):
            raise ValueError(f"Недопустимый межстрочный интервал: {self.line_spacing}")
        if self.paper_source not in ("tractor", "manual", "auto"):
            raise ValueError(f"Недопустимый источник бумаги: {self.paper_source}")
        if self.paper_form_type not in (
            "custom",
            "tractor_full",
            "tractor_half",
            "tractor_triplet",
            "envelope_dl",
            "envelope_c5",
        ):
            raise ValueError(f"Недопустимый тип формы: {self.paper_form_type}")

        # Валидация размеров
        for name, value in [
            ("width_mm", self.width_mm),
            ("height_mm", self.height_mm),
        ]:
            if not isinstance(value, (int, float)) or value <= 0 or value > 10000:
                raise ValueError(f"Недопустимое значение {name}: {value}")

        # Валидация отступов
        for name, value in [
            ("top_margin_mm", self.top_margin_mm),
            ("bottom_margin_mm", self.bottom_margin_mm),
            ("left_margin_mm", self.left_margin_mm),
            ("right_margin_mm", self.right_margin_mm),
        ]:
            if not isinstance(value, (int, float)) or value < 0 or value > 500:
                raise ValueError(f"Недопустимое значение {name}: {value}")

        if (
            not isinstance(self.perforation_margin_mm, (int, float))
            or self.perforation_margin_mm < 0
            or self.perforation_margin_mm > 500
        ):
            raise ValueError(
                f"Недопустимое значение perforation_margin_mm: {self.perforation_margin_mm}"
            )


# =============================================================================
# PaperToolbar
# =============================================================================


class PaperToolbar(BaseWidget):
    """Тулбар для быстрой настройки параметров бумаги.

    Attributes:
        widget_id: Уникальный идентификатор виджета.
        controller: Ссылка на контроллер для callbacks.
        on_config_change: Callback при изменении конфигурации.

    Example:
        >>> toolbar = PaperToolbar(
        ...     widget_id="paper_toolbar",
        ...     controller=ctrl,
        ...     on_config_change=lambda cfg: print(f"Changed: {cfg}")
        ... )
        >>> toolbar.mount(parent_frame)
        >>> toolbar.set_config(PaperConfig(paper_size=PaperSize.A4, cpi=12))
    """

    def __init__(
        self,
        widget_id: str,
        controller: Optional[ControllerProtocol] = None,
        on_config_change: Optional[Callable[[PaperConfig], None]] = None,
        on_setup_clicked: Optional[Callable[[], None]] = None,
        initial_config: Optional[PaperConfig] = None,
    ) -> None:
        """Инициализация тулбара.

        Args:
            widget_id: Уникальный идентификатор виджета.
            controller: Опциональная ссылка на контроллер.
            on_config_change: Callback при изменении конфигурации.
            on_setup_clicked: Callback при нажатии кнопки настройки бумаги.
            initial_config: Начальная конфигурация.
        """
        super().__init__(widget_id=widget_id, controller=controller)
        self._on_config_change = on_config_change
        self._on_setup_clicked = on_setup_clicked
        self._config = initial_config or PaperConfig()

        # Tkinter widgets
        self._paper_var: Optional[tk.StringVar] = None
        self._cpi_var: Optional[tk.StringVar] = None
        self._spacing_var: Optional[tk.StringVar] = None
        self._source_var: Optional[tk.StringVar] = None

        # Dropdown widgets
        self._paper_dropdown: Optional[tk.OptionMenu] = None
        self._cpi_dropdown: Optional[tk.OptionMenu] = None
        self._spacing_dropdown: Optional[tk.OptionMenu] = None
        self._source_dropdown: Optional[tk.OptionMenu] = None

    def _create_tk_widget(self, parent: tk.Widget) -> tk.Widget:
        """Создаёт тулбар с dropdown виджетами.

        Args:
            parent: Родительский Tkinter виджет.

        Returns:
            Созданный фрейм тулбара.
        """
        # Создаём фрейм тулбара
        toolbar = tk.Frame(
            parent,
            height=TOOLBAR_HEIGHT,
            relief=tk.RAISED,
            borderwidth=1,
        )
        toolbar.pack_propagate(False)

        # Создаём переменные для dropdown
        self._paper_var = tk.StringVar(value=PAPER_SIZE_DISPLAY.get(self._config.paper_size, "A4"))
        self._cpi_var = tk.StringVar(value=CPI_DISPLAY.get(self._config.cpi, "10 CPI"))
        spacing_default = LINE_SPACING_DISPLAY.get(self._config.line_spacing, '1/6"')
        self._spacing_var = tk.StringVar(value=spacing_default)
        source_default = PAPER_SOURCE_DISPLAY.get(self._config.paper_source, "Автовыбор")
        self._source_var = tk.StringVar(value=source_default)

        # Paper size dropdown
        self._create_dropdown(
            toolbar,
            "Размер:",
            self._paper_var,
            list(PAPER_SIZE_DISPLAY.values()),
            self._on_paper_size_change,
        )

        # CPI dropdown
        self._create_dropdown(
            toolbar,
            "CPI:",
            self._cpi_var,
            [CPI_DISPLAY[cpi] for cpi in VALID_CPI_VALUES],
            self._on_cpi_change,
        )

        # Line spacing dropdown
        self._create_dropdown(
            toolbar,
            "Интервал:",
            self._spacing_var,
            list(LINE_SPACING_DISPLAY.values()),
            self._on_line_spacing_change,
        )

        # Paper source dropdown
        self._create_dropdown(
            toolbar,
            "Источник:",
            self._source_var,
            list(PAPER_SOURCE_DISPLAY.values()),
            self._on_paper_source_change,
        )

        # Separator
        tk.Frame(toolbar, width=1, bg="gray").pack(side=tk.LEFT, fill=tk.Y, padx=PADDING_NORMAL)

        # Paper Setup button
        setup_btn = tk.Button(
            toolbar,
            text="⚙️ Paper Setup...",
            command=self._on_setup_button_clicked,
        )
        setup_btn.pack(side=tk.LEFT, padx=PADDING_NORMAL)

        return toolbar

    def _create_dropdown(
        self,
        parent: tk.Widget,
        label: str,
        var: tk.StringVar,
        options: List[str],
        command: Callable[[str], None],
    ) -> tk.OptionMenu:
        """Создаёт labeled dropdown.

        Args:
            parent: Родительский виджет.
            label: Текст метки.
            var: Переменная для хранения значения.
            options: Список опций.
            command: Callback при изменении.

        Returns:
            Созданный OptionMenu виджет.
        """
        # Label
        lbl = tk.Label(parent, text=label)
        lbl.pack(side=tk.LEFT, padx=(PADDING_NORMAL, 2))

        # Dropdown
        dropdown = tk.OptionMenu(
            parent,
            var,
            *options,
        )
        # Bind command to variable change
        var.trace_add("write", lambda *args: command(var.get()))
        dropdown.pack(side=tk.LEFT, padx=(0, PADDING_NORMAL))

        return dropdown

    def _sanitize_input(self, value: str) -> str:
        """Санитизирует пользовательский ввод.

        Args:
            value: Входная строка.

        Returns:
            Очищенная строка без опасных символов.
        """
        # Удаляем потенциально опасные символы
        sanitized = SANITIZE_PATTERN.sub("", value)
        # Ограничиваем длину
        return sanitized[:100]

    def _on_paper_size_change(self, value: str) -> None:
        """Обрабатывает изменение размера бумаги.

        Args:
            value: Выбранное значение.
        """
        sanitized = self._sanitize_input(value)

        # Находим PaperSize по отображаемому значению
        new_size = PaperSize.A4  # default
        for size, display in PAPER_SIZE_DISPLAY.items():
            if display == sanitized:
                new_size = size
                break

        if new_size != self._config.paper_size:
            self._config = PaperConfig(
                paper_size=new_size,
                cpi=self._config.cpi,
                line_spacing=self._config.line_spacing,
                paper_source=self._config.paper_source,
            )
            self._notify_config_change()
            logger.debug("Изменён размер бумаги: %s", new_size.name)

    def _on_cpi_change(self, value: str) -> None:
        """Обрабатывает изменение CPI.

        Args:
            value: Выбранное значение.
        """
        sanitized = self._sanitize_input(value)

        # Извлекаем числовое значение CPI из строки
        new_cpi = self._config.cpi  # default
        for cpi, display in CPI_DISPLAY.items():
            if display == sanitized:
                new_cpi = cpi
                break

        if new_cpi != self._config.cpi:
            self._config = PaperConfig(
                paper_size=self._config.paper_size,
                cpi=new_cpi,
                line_spacing=self._config.line_spacing,
                paper_source=self._config.paper_source,
            )
            self._notify_config_change()
            logger.debug("Изменён CPI: %d", new_cpi)

    def _on_line_spacing_change(self, value: str) -> None:
        """Обрабатывает изменение межстрочного интервала.

        Args:
            value: Выбранное значение.
        """
        sanitized = self._sanitize_input(value)

        # Находим ключ по отображаемому значению
        new_spacing = self._config.line_spacing  # default
        for key, display in LINE_SPACING_DISPLAY.items():
            if display == sanitized:
                new_spacing = key
                break

        if new_spacing != self._config.line_spacing:
            self._config = PaperConfig(
                paper_size=self._config.paper_size,
                cpi=self._config.cpi,
                line_spacing=new_spacing,
                paper_source=self._config.paper_source,
            )
            self._notify_config_change()
            logger.debug("Изменён межстрочный интервал: %s", new_spacing)

    def _on_paper_source_change(self, value: str) -> None:
        """Обрабатывает изменение источника бумаги.

        Args:
            value: Выбранное значение.
        """
        sanitized = self._sanitize_input(value)

        # Находим ключ по отображаемому значению
        new_source = self._config.paper_source  # default
        for key, display in PAPER_SOURCE_DISPLAY.items():
            if display == sanitized:
                new_source = key
                break

        if new_source != self._config.paper_source:
            self._config = PaperConfig(
                paper_size=self._config.paper_size,
                cpi=self._config.cpi,
                line_spacing=self._config.line_spacing,
                paper_source=new_source,
            )
            self._notify_config_change()
            logger.debug("Изменён источник бумаги: %s", new_source)

    def _on_setup_button_clicked(self) -> None:
        """Обрабатывает нажатие кнопки '⚙️ Paper Setup...'."""
        logger.debug("Открытие диалога настройки бумаги")

        # Если передан явный callback — вызываем его
        if self._on_setup_clicked is not None:
            try:
                self._on_setup_clicked()
            except (AttributeError, TypeError, ValueError, KeyError, IndexError) as exc:
                logger.error("Ошибка в callback on_setup_clicked: %s", exc)
            return

        # Fallback: отправляем событие через контроллер
        if self._controller is not None:
            self._controller.dispatch(
                "open_paper_setup_dialog",
                config=self._config,
            )

    def _notify_config_change(self) -> None:
        """Уведомляет об изменении конфигурации."""
        if self._on_config_change is not None:
            try:
                self._on_config_change(self._config)
            except (AttributeError, TypeError, ValueError, KeyError, IndexError) as exc:
                logger.error("Ошибка в callback on_config_change: %s", exc)

        # Также отправляем через контроллер
        if self._controller is not None:
            self._controller.dispatch(
                "paper_config_changed",
                config=self._config,
            )

    def get_config(self) -> PaperConfig:
        """Возвращает текущую конфигурацию.

        Returns:
            Текущая конфигурация бумаги.
        """
        return self._config

    def set_config(self, config: PaperConfig) -> None:
        """Устанавливает конфигурацию и обновляет UI.

        Args:
            config: Новая конфигурация.
        """
        self._config = config

        if self._is_mounted:
            # Обновляем значения переменных
            if self._paper_var is not None:
                self._paper_var.set(PAPER_SIZE_DISPLAY.get(config.paper_size, "A4"))
            if self._cpi_var is not None:
                self._cpi_var.set(CPI_DISPLAY.get(config.cpi, "10 CPI"))
            if self._spacing_var is not None:
                self._spacing_var.set(LINE_SPACING_DISPLAY.get(config.line_spacing, '1/6"'))
            if self._source_var is not None:
                self._source_var.set(PAPER_SOURCE_DISPLAY.get(config.paper_source, "Автовыбор"))

    def set_paper_size(self, paper_size: PaperSize) -> None:
        """Устанавливает размер бумаги.

        Args:
            paper_size: Новый размер бумаги.
        """
        self.set_config(
            PaperConfig(
                paper_size=paper_size,
                cpi=self._config.cpi,
                line_spacing=self._config.line_spacing,
                paper_source=self._config.paper_source,
            )
        )

    def set_cpi(self, cpi: int) -> None:
        """Устанавливает CPI.

        Args:
            cpi: Новое значение CPI (10, 12, 15, 17, 20).

        Raises:
            ValueError: Если CPI недопустим.
        """
        if cpi not in VALID_CPI_VALUES:
            raise ValueError(f"Недопустимое значение CPI: {cpi}")

        self.set_config(
            PaperConfig(
                paper_size=self._config.paper_size,
                cpi=cpi,
                line_spacing=self._config.line_spacing,
                paper_source=self._config.paper_source,
            )
        )

    def _cleanup(self) -> None:
        """Очищает ресурсы перед демонтированием."""
        self._paper_var = None
        self._cpi_var = None
        self._spacing_var = None
        self._source_var = None
        self._paper_dropdown = None
        self._cpi_dropdown = None
        self._spacing_dropdown = None
        self._source_dropdown = None
        self._on_config_change = None
        self._on_setup_clicked = None


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    "PaperToolbar",
    "PaperConfig",
    "VALID_CPI_VALUES",
    "PAPER_SIZE_DISPLAY",
    "CPI_DISPLAY",
    "LINE_SPACING_DISPLAY",
    "PAPER_SOURCE_DISPLAY",
]
