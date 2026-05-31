# -*- coding: utf-8 -*-
"""UI тумблер для переключения режимов Normal/Special.

Модуль предоставляет визуальный переключатель режимов работы приложения
с анимацией, MFA защитой и интеграцией с ThemeManager.

Features:
    - Плавная анимация переключения
    - Colorовая индикация режимов (зелёный/оранжевый)
    - MFA challenge для входа в Special Mode
    - Защита от случайного переключения
    - Drag-and-drop поддержка

Example:
    >>> from src.gui.security.mode_toggle import ModeToggle, Mode
    >>> from src.gui.security.mode_manager import ModeManager
    >>> toggle = ModeToggle(
    ...     parent=frame,
    ...     mode_manager=ModeManager(),
    ...     on_mode_changed=lambda m: print(f"Mode: {m}"),
    ... )
    >>> toggle.pack(pady=10)

Version: 1.0
Date: April 2026
"""

from __future__ import annotations

import logging
import tkinter as tk
from dataclasses import dataclass
from enum import Enum
from tkinter import messagebox
from typing import TYPE_CHECKING, Any, Callable, Optional

if TYPE_CHECKING:
    from src.gui.security.mfa_gate import MFAGate, MFAResult

logger: logging.Logger = logging.getLogger(__name__)


class Mode(str, Enum):
    """Режимы работы приложения.

    Attributes:
        NORMAL: Стандартная работа с документами.
        SPECIAL: Расширенные возможности (админ, отладка, аудит).
    """

    NORMAL = "normal"
    """🟢 Стандартная работа с документами."""

    SPECIAL = "special"
    """🟠 Расширенные возможности (админ, отладка, аудит)."""


@dataclass(frozen=True)
class ModeCapabilities:
    """Возможности режима работы.

    Attributes:
        title: Название режима для отображения.
        color: Color индикации режима (hex).
        features: Список доступных функций.
    """

    title: str
    color: str
    features: tuple[str, ...]


# Описание возможностей для каждого режима
MODE_CAPABILITIES: dict[Mode, ModeCapabilities] = {
    Mode.NORMAL: ModeCapabilities(
        title="Normal mode",
        color="#00AA00",  # Зелёный
        features=(
            "Create and edit documents",
            "Print on Epson FX-890",
            "Export to PDF",
        ),
    ),
    Mode.SPECIAL: ModeCapabilities(
        title="Special mode",
        color="#FFA500",  # Оранжевый
        features=(
            "Template management",
            "Audit log",
            "Отладка печати",
            "Доступ к настройкам безопасности",
        ),
    ),
}


class ModeToggle(tk.Frame):
    """UI тумблер переключения режимов Normal/Special.

    Визуальный переключатель с анимацией, цветовой индикацией
    и защитой от случайного переключения.

    Attributes:
        _mode_manager: Управляющий режимами.
        _mfa_gate: Опциональный MFAGate для MFA верификации.
        _on_mode_changed: Callback при изменении режима.
        _current_mode: Текущий режим.
        _is_animating: Флаг анимации.
        _confirm_pending: Флаг ожидания подтверждения.

    Example:
        >>> toggle = ModeToggle(parent, mode_manager=manager)
        >>> toggle.set_mode(Mode.SPECIAL)
        >>> current = toggle.get_mode()
    """

    # Константы для визуального оформления
    TOGGLE_WIDTH: int = 120
    TOGGLE_HEIGHT: int = 36
    KNOB_SIZE: int = 28
    TRACK_PADDING: int = 4
    ANIMATION_STEPS: int = 8
    ANIMATION_DELAY_MS: int = 16  # ~60 FPS

    def __init__(
        self,
        parent: tk.Widget,
        mode_manager: Any,
        mfa_gate: Optional["MFAGate"] = None,
        on_mode_changed: Optional[Callable[[Mode], None]] = None,
        initial_mode: Mode = Mode.NORMAL,
    ) -> None:
        """Инициализация тумблера режимов.

        Args:
            parent: Родительский виджет.
            mode_manager: ModeManager для управления режимами.
            mfa_gate: Опциональный MFAGate для MFA верификации.
            on_mode_changed: Callback при изменении режима.
            initial_mode: Начальный режим (по умолчанию NORMAL).
        """
        super().__init__(parent)

        self._mode_manager = mode_manager
        self._mfa_gate = mfa_gate
        self._on_mode_changed = on_mode_changed
        self._current_mode: Mode = initial_mode
        self._is_animating: bool = False
        self._confirm_pending: bool = False
        self._dragging: bool = False
        self._drag_start_x: int = 0

        # Colorа (будут обновлены из темы)
        self._normal_color: str = MODE_CAPABILITIES[Mode.NORMAL].color
        self._special_color: str = MODE_CAPABILITIES[Mode.SPECIAL].color
        self._track_color: str = "#333333"
        self._knob_color: str = "#FFFFFF"

        # UI элементы (инициализируются в _create_widgets)
        self._toggle_frame: Optional[tk.Frame] = None
        self._normal_label: Optional[tk.Label] = None
        self._special_label: Optional[tk.Label] = None
        self._canvas: Optional[tk.Canvas] = None
        self._track_id: Optional[int] = None
        self._knob_id: Optional[int] = None
        self._mode_title_label: Optional[tk.Label] = None
        self._features_frame: Optional[tk.LabelFrame] = None
        self._features_text: Optional[tk.Label] = None
        self._info_label: Optional[tk.Label] = None

        self._create_widgets()
        self._setup_bindings()
        self._apply_theme()

        # Установка начального состояния
        self._update_visual_state(animate=False)

    def _create_widgets(self) -> None:
        """Создаёт UI компоненты тумблера."""
        # Конфигурация grid
        self.configure(padx=10, pady=10)
        self.columnconfigure(0, weight=1)

        # Frame для тумблера и меток
        self._toggle_frame = tk.Frame(self)
        self._toggle_frame.grid(row=0, column=0, pady=(0, 10))

        # Левая метка (Normal)
        self._normal_label = tk.Label(
            self._toggle_frame,
            text="Normal",
            font=("Segoe UI", 10),
            cursor="hand2",
        )
        self._normal_label.pack(side=tk.LEFT, padx=(0, 10))

        # Canvas для визуального тумблера
        self._canvas = tk.Canvas(
            self._toggle_frame,
            width=self.TOGGLE_WIDTH,
            height=self.TOGGLE_HEIGHT,
            highlightthickness=0,
            cursor="hand2",
        )
        self._canvas.pack(side=tk.LEFT)

        # Создаём элементы на Canvas
        self._create_toggle_elements()

        # Правая метка (Special)
        self._special_label = tk.Label(
            self._toggle_frame,
            text="Special",
            font=("Segoe UI", 10),
            cursor="hand2",
        )
        self._special_label.pack(side=tk.LEFT, padx=(10, 0))

        # Метка текущего режима
        self._mode_title_label = tk.Label(
            self,
            text="",
            font=("Segoe UI", 11, "bold"),
        )
        self._mode_title_label.grid(row=1, column=0, pady=(0, 5))

        # Frame для списка возможностей
        self._features_frame = tk.LabelFrame(
            self,
            text="Available",
            font=("Segoe UI", 9),
        )
        self._features_frame.grid(row=2, column=0, sticky="ew", pady=(0, 5))
        self._features_frame.columnconfigure(0, weight=1)

        self._features_text = tk.Label(
            self._features_frame,
            text="",
            font=("Segoe UI", 9),
            justify=tk.LEFT,
            wraplength=300,
        )
        self._features_text.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        # Информационная метка
        self._info_label = tk.Label(
            self,
            text="Double-click to switch mode",
            font=("Segoe UI", 8),
            foreground="#666666",
        )
        self._info_label.grid(row=3, column=0)

    def _create_rounded_track(
        self,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        radius: int,
        **kwargs: Any,
    ) -> int:
        """Создаёт закруглённый прямоугольник на Canvas.

        Args:
            x1, y1: Координаты левого верхнего угла.
            x2, y2: Координаты правого нижнего угла.
            radius: Радиус скругления.
            **kwargs: Дополнительные параметры для create_polygon.

        Returns:
            ID созданного элемента.
        """
        if self._canvas is None:
            raise RuntimeError("Canvas not initialized")
        points = [
            x1 + radius,
            y1,
            x2 - radius,
            y1,
            x2,
            y1,
            x2,
            y1 + radius,
            x2,
            y2 - radius,
            x2,
            y2,
            x2 - radius,
            y2,
            x1 + radius,
            y2,
            x1,
            y2,
            x1,
            y2 - radius,
            x1,
            y1 + radius,
            x1,
            y1,
        ]
        return self._canvas.create_polygon(points, smooth=True, **kwargs)

    def _create_toggle_elements(self) -> None:
        """Создаёт визуальные элементы тумблера на Canvas."""
        if self._canvas is None:
            return

        # Трек (фоновая полоска)
        track_radius = self.TOGGLE_HEIGHT // 2
        self._track_id = self._create_rounded_track(
            self.TRACK_PADDING,
            self.TRACK_PADDING,
            self.TOGGLE_WIDTH - self.TRACK_PADDING,
            self.TOGGLE_HEIGHT - self.TRACK_PADDING,
            radius=track_radius,
            fill=self._track_color,
            outline="",
        )

        # Ползунок (круг)
        knob_radius = self.KNOB_SIZE // 2
        knob_y = self.TOGGLE_HEIGHT // 2
        knob_x = self._get_knob_position_x(Mode.NORMAL)

        self._knob_id = self._canvas.create_oval(
            knob_x - knob_radius,
            knob_y - knob_radius,
            knob_x + knob_radius,
            knob_y + knob_radius,
            fill=self._knob_color,
            outline="",
        )

    def _setup_bindings(self) -> None:
        """Настраивает обработчики событий."""
        if self._canvas is None:
            return

        # Клик по Canvas
        self._canvas.bind("<Button-1>", self._on_canvas_click)
        self._canvas.bind("<Double-Button-1>", self._on_canvas_double_click)
        self._canvas.bind("<B1-Motion>", self._on_canvas_drag)
        self._canvas.bind("<ButtonRelease-1>", self._on_canvas_release)

        # Клик по меткам
        if self._normal_label is not None:
            self._normal_label.bind("<Button-1>", lambda e: self._request_mode_change(Mode.NORMAL))
            self._normal_label.bind(
                "<Double-Button-1>", lambda e: self._request_mode_change(Mode.NORMAL)
            )
        if self._special_label is not None:
            self._special_label.bind(
                "<Button-1>", lambda e: self._request_mode_change(Mode.SPECIAL)
            )
            self._special_label.bind(
                "<Double-Button-1>", lambda e: self._request_mode_change(Mode.SPECIAL)
            )

        # Hover эффекты
        self._canvas.bind("<Enter>", self._on_canvas_enter)
        self._canvas.bind("<Leave>", self._on_canvas_leave)

    def _apply_theme(self) -> None:
        """Применяет текущую тему к виджету."""
        try:
            from src.gui.themes import get_theme_manager

            theme_manager = get_theme_manager()
            theme = theme_manager.get_current_theme()

            # Обновляем цвета из темы
            self._normal_color = theme.success_color
            self._special_color = theme.warning_color
            self._track_color = theme.border_color
            self._knob_color = theme.fg_color

            # Обновляем фон виджетов
            self.configure(bg=theme.bg_color)
            if self._toggle_frame is not None:
                self._toggle_frame.configure(bg=theme.bg_color)
            if self._normal_label is not None:
                self._normal_label.configure(
                    bg=theme.bg_color,
                    fg=theme.fg_color,
                )
            if self._special_label is not None:
                self._special_label.configure(
                    bg=theme.bg_color,
                    fg=theme.fg_color,
                )
            if self._mode_title_label is not None:
                self._mode_title_label.configure(
                    bg=theme.bg_color,
                    fg=theme.fg_color,
                )
            if self._features_frame is not None:
                self._features_frame.configure(
                    bg=theme.bg_color,
                    fg=theme.fg_color,
                )
            if self._features_text is not None:
                self._features_text.configure(
                    bg=theme.bg_color,
                    fg=theme.fg_color,
                )
            if self._info_label is not None:
                self._info_label.configure(
                    bg=theme.bg_color,
                    fg=theme.border_color,
                )
            if self._canvas is not None:
                self._canvas.configure(bg=theme.bg_color)

            # Обновляем Canvas элементы
            self._update_track_color()

        except (tk.TclError, AttributeError, ValueError, RuntimeError) as exc:
            logger.warning("Failed to apply theme to ModeToggle: %s", exc)

    def _get_knob_position_x(self, mode: Mode) -> int:
        """Возвращает X координату ползунка для режима.

        Args:
            mode: Режим для вычисления позиции.

        Returns:
            X координата центра ползунка.
        """
        knob_radius = self.KNOB_SIZE // 2
        padding = self.TRACK_PADDING + knob_radius + 2

        if mode == Mode.NORMAL:
            return padding + knob_radius
        else:
            return self.TOGGLE_WIDTH - padding - knob_radius

    def _update_track_color(self) -> None:
        """Обновляет цвет трека в зависимости от режима."""
        if self._canvas is None or self._track_id is None:
            return

        if self._current_mode == Mode.NORMAL:
            color = self._normal_color
        else:
            color = self._special_color

        self._canvas.itemconfigure(self._track_id, fill=color)

    def _update_visual_state(self, animate: bool = True) -> None:
        """Обновляет визуальное состояние тумблера.

        Args:
            animate: Если True - использовать анимацию.
        """
        # Обновляем цвет трека
        self._update_track_color()

        # Обновляем позицию ползунка
        if animate and not self._is_animating:
            self._animate_toggle(self._current_mode)
        else:
            self._set_knob_position(self._get_knob_position_x(self._current_mode))

        # Обновляем текст меток
        self._update_mode_info(self._current_mode)

        # Обновляем цвета меток
        self._update_label_colors()

    def _set_knob_position(self, x: int) -> None:
        """Устанавливает позицию ползунка.

        Args:
            x: X координата центра ползунка.
        """
        if self._canvas is None or self._knob_id is None:
            return

        knob_radius = self.KNOB_SIZE // 2
        knob_y = self.TOGGLE_HEIGHT // 2

        self._canvas.coords(
            self._knob_id,
            x - knob_radius,
            knob_y - knob_radius,
            x + knob_radius,
            knob_y + knob_radius,
        )

    def _update_label_colors(self) -> None:
        """Обновляет цвета меток режимов."""
        if self._current_mode == Mode.NORMAL:
            if self._normal_label is not None:
                self._normal_label.configure(foreground=self._normal_color)
            if self._special_label is not None:
                self._special_label.configure(foreground="#666666")
        else:
            if self._normal_label is not None:
                self._normal_label.configure(foreground="#666666")
            if self._special_label is not None:
                self._special_label.configure(foreground=self._special_color)

    def _on_canvas_click(self, event: tk.Event) -> None:
        """Обработчик клика по Canvas.

        Args:
            event: Событие клика.
        """
        self._dragging = True
        self._drag_start_x = event.x

    def _on_canvas_double_click(self, event: tk.Event) -> None:
        """Обработчик двойного клика по Canvas.

        Args:
            event: Событие двойного клика.
        """
        self._dragging = False
        self._on_toggle()

    def _on_canvas_drag(self, event: tk.Event) -> None:
        """Обработчик перетаскивания ползунка.

        Args:
            event: Событие движения мыши.
        """
        if not self._dragging or self._is_animating:
            return

        # Ограничиваем движение в пределах трека
        knob_radius = self.KNOB_SIZE // 2
        padding = self.TRACK_PADDING + knob_radius + 2
        min_x = padding + knob_radius
        max_x = self.TOGGLE_WIDTH - padding - knob_radius

        x = max(min_x, min(event.x, max_x))
        self._set_knob_position(x)

    def _on_canvas_release(self, event: tk.Event) -> None:
        """Обработчик отпускания кнопки мыши.

        Args:
            event: Событие отпускания кнопки.
        """
        if not self._dragging:
            return

        self._dragging = False

        # Определяем к какому режиму ближе
        center_x = self.TOGGLE_WIDTH // 2

        # Получаем текущую позицию ползунка
        if self._canvas is not None and self._knob_id is not None:
            coords = self._canvas.coords(self._knob_id)
            current_x = (coords[0] + coords[2]) // 2

            # Переключаем режим если перетащили достаточно далеко
            if self._current_mode == Mode.NORMAL and current_x > center_x:
                self._request_mode_change(Mode.SPECIAL)
            elif self._current_mode == Mode.SPECIAL and current_x < center_x:
                self._request_mode_change(Mode.NORMAL)
            else:
                # Возвращаем в исходное положение
                self._animate_toggle(self._current_mode)

    def _on_canvas_enter(self, event: tk.Event) -> None:
        """Обработчик наведения курсора на Canvas.

        Args:
            event: Событие наведения.
        """
        if self._canvas is not None:
            self._canvas.configure(cursor="hand2")

    def _on_canvas_leave(self, event: tk.Event) -> None:
        """Обработчик ухода курсора с Canvas.

        Args:
            event: Событие ухода курсора.
        """
        self._dragging = False

    def _on_toggle(self) -> None:
        """Обработчик переключения тумблера."""
        if self._is_animating:
            return

        new_mode = Mode.SPECIAL if self._current_mode == Mode.NORMAL else Mode.NORMAL
        self._request_mode_change(new_mode)

    def _request_mode_change(self, mode: Mode) -> None:
        """Запрашивает изменение режима с проверками.

        Args:
            mode: Целевой режим.
        """
        if mode == self._current_mode or self._is_animating:
            return

        # Для Special Mode требуется MFA
        if mode == Mode.SPECIAL:
            if not self._request_mfa_for_special():
                return

        # Подтверждение для выхода из Special
        if self._current_mode == Mode.SPECIAL:
            if not self._confirm_exit_special():
                return

        self.set_mode(mode)

    def _confirm_exit_special(self) -> bool:
        """Запрашивает подтверждение выхода из Special Mode.

        Returns:
            True если пользователь подтвердил выход.
        """
        result = messagebox.askyesno(
            "Подтверждение",
            "Выход из специального режима.\n\n"
            "Несохранённые изменения в специальных функциях могут быть потеряны.\n"
            "Продолжить?",
            icon="warning",
        )
        return bool(result)

    def _animate_toggle(self, target_mode: Mode) -> None:
        """Анимирует переключение тумблера.

        Args:
            target_mode: Целевой режим.
        """
        if self._is_animating:
            return

        self._is_animating = True
        target_x = self._get_knob_position_x(target_mode)

        # Текущая позиция
        if self._canvas is None or self._knob_id is None:
            self._is_animating = False
            return

        coords = self._canvas.coords(self._knob_id)
        current_x = (coords[0] + coords[2]) // 2

        # Вычисляем шаг анимации
        distance = target_x - current_x
        step = distance / self.ANIMATION_STEPS

        def animate_step(step_num: int) -> None:
            if step_num >= self.ANIMATION_STEPS:
                self._set_knob_position(target_x)
                self._is_animating = False
                return

            new_x = current_x + step * (step_num + 1)
            self._set_knob_position(int(new_x))
            self.after(self.ANIMATION_DELAY_MS, lambda: animate_step(step_num + 1))

        animate_step(0)

    def _update_mode_info(self, mode: Mode) -> None:
        """Обновляет информацию о текущем режиме.

        Args:
            mode: Текущий режим.
        """
        caps = MODE_CAPABILITIES[mode]

        # Обновляем заголовок
        if self._mode_title_label is not None:
            self._mode_title_label.configure(
                text=f"Current mode: {caps.title}",
                foreground=caps.color,
            )

        # Обновляем список возможностей
        if self._features_text is not None:
            features_text = "\n".join(f"• {feature}" for feature in caps.features)
            self._features_text.configure(text=features_text)

    def _request_mfa_for_special(self) -> bool:
        """Запрашивает MFA для входа в Special Mode.

        Returns:
            True если MFA пройден успешно.
        """
        # Проверяем через ModeManager
        if hasattr(self._mode_manager, "can_enter_special"):
            can_enter, reason = self._mode_manager.can_enter_special()
            if not can_enter:
                messagebox.showerror(
                    "Access denied",
                    f"Cannot enter special mode: {reason}",
                )
                return False

        # Если есть MFAGate - используем его
        if self._mfa_gate is not None:
            try:
                result: "MFAResult" = self._mfa_gate.challenge(
                    parent=self,
                    user_id="operator",
                    required_methods=["totp", "backup_code"],
                    operation="enter_special_mode",
                )
                if not result.verified:
                    messagebox.showerror(
                        "MFA не пройдена",
                        "Не удалось пройти многофакторную аутентификацию.",
                    )
                    return False
                return True
            except (ValueError, TypeError, AttributeError, RuntimeError) as exc:
                logger.error("MFA challenge failed: %s", exc)
                messagebox.showerror(
                    "Ошибка MFA",
                    f"Ошибка при проверке MFA: {exc}",
                )
                return False

        # Если нет MFA gate - просто подтверждение
        result_confirm = messagebox.askyesno(
            "Подтверждение входа",
            "Вход в специальный режим требует повышенных привилегий.\n\n"
            "Убедитесь, что вы имеете право использовать расширенные функции.\n"
            "Продолжить?",
            icon="warning",
        )
        return bool(result_confirm)

    def set_mode(self, mode: Mode) -> None:
        """Устанавливает режим работы.

        Args:
            mode: Новый режим.

        Raises:
            ValueError: Если режим невалиден.
        """
        if not isinstance(mode, Mode):
            raise ValueError(f"Invalid mode: {mode}")

        if mode == self._current_mode:
            return

        old_mode = self._current_mode
        self._current_mode = mode

        # Уведомляем ModeManager
        if hasattr(self._mode_manager, "force_mode"):
            if mode == Mode.SPECIAL:
                # MFA уже пройдена через _request_mfa_for_special(),
                # поэтому переключаем режим напрямую без повторной проверки.
                try:
                    self._mode_manager.force_mode("special")
                except (AttributeError, ValueError, RuntimeError) as exc:
                    logger.warning("Failed to force special mode: %s", exc)
            elif hasattr(self._mode_manager, "exit_special"):
                try:
                    self._mode_manager.exit_special(confirm=False)
                except (AttributeError, ValueError, RuntimeError) as exc:
                    logger.warning("Failed to exit special mode: %s", exc)

        # Callback
        if self._on_mode_changed is not None:
            try:
                self._on_mode_changed(mode)
            except (ValueError, TypeError, AttributeError, RuntimeError) as exc:
                logger.error("Mode change callback failed: %s", exc)

        # Обновляем UI
        self._update_visual_state(animate=True)

        logger.info("Mode changed: %s -> %s", old_mode.value, mode.value)

    def get_mode(self) -> Mode:
        """Возвращает текущий режим.

        Returns:
            Текущий режим работы.
        """
        return self._current_mode

    def _show_mode_info(self, mode: Mode) -> None:
        """Показывает информацию о режиме (tooltip-like).

        Args:
            mode: Режим для отображения информации.
        """
        self._update_mode_info(mode)

    def refresh_theme(self) -> None:
        """Обновляет тему виджета."""
        self._apply_theme()
        self._update_visual_state(animate=False)


__all__ = [
    "Mode",
    "ModeToggle",
    "ModeCapabilities",
    "MODE_CAPABILITIES",
]
