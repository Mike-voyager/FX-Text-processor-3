"""Генератор тестовой страницы ESC/P для Epson FX-890.

Создаёт тестовую страницу для проверки:
- Сброс принтера (ESC @)
- Таблицы символов текущей кодовой страницы
- Тест CPI (10/12/15 cpi)
- Тест выравнивания (левое/центральное/правое)
- Тест стилей (Bold/Italic/Underline)
- Тест графики 120 dpi
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from src.model.enums import CharactersPerInch, CodePage, PrintQuality

logger: Final = logging.getLogger(__name__)

# ESC/P команды
ESC = b"\x1b"
SO = b"\x0e"  # Shift Out — Double-width on
SI = b"\x0f"  # Shift In — Condensed on
DC2 = b"\x12"  # Device Control 2 — Condensed off
DC4 = b"\x14"  # Device Control 4 — Double-width off

# Базовые ESC/P команды
ESC_AT = ESC + b"@"  # Сброс принтера
ESC_E = ESC + b"E"  # Bold on
ESC_F = ESC + b"F"  # Bold off
ESC_4 = ESC + b"4"  # Italic on
ESC_5 = ESC + b"5"  # Italic off
ESC_MINUS_1 = ESC + b"-\x01"  # Underline on
ESC_MINUS_0 = ESC + b"-\x00"  # Underline off
ESC_G = ESC + b"G"  # Double-strike on
ESC_H = ESC + b"H"  # Double-strike off

# CPI команды
ESC_P = ESC + b"P"  # 10 CPI
ESC_M = ESC + b"M"  # 12 CPI
ESC_g = ESC + b"g"  # 15 CPI (semi-condensed)

# Качество
ESC_x_0 = ESC + b"x\x00"  # Draft mode
ESC_x_1 = ESC + b"x\x01"  # NLQ mode
ESC_y_1 = ESC + b"y\x01"  # HSD mode
ESC_y_2 = ESC + b"y\x02"  # UHSD mode

# Шрифты NLQ
ESC_k_0 = ESC + b"k\x00"  # Roman
ESC_k_1 = ESC + b"k\x01"  # Sans Serif

# Кодовые страницы
ESC_t = ESC + b"t"  # ESC t n — выбор кодовой страницы

# Позиционирование
ESC_DOLLAR = ESC + b"$"  # ESC $ n1 n2 — абсолютная позиция

# Перевод строки
LF = b"\n"
CR = b"\r"
CRLF = b"\r\n"

# Графика
ESC_ASTERISK = ESC + b"*"  # ESC * m n1 n2 — графика


class TestPageGenerator:
    """Генератор тестовой страницы ESC/P.

    Создаёт тестовую страницу для проверки принтера с заданными настройками.

    Attributes:
        _codepage: Кодовая страница для теста
        _cpi: CPI для теста
        _quality: Качество печати для теста

    Example:
        >>> generator = TestPageGenerator(
        ...     CodePage.PC866, CharactersPerInch.CPI_12, PrintQuality.DRAFT
        ... )
        >>> test_data = generator.generate()
        >>> len(test_data) > 0
        True
    """

    # Маппинг кодовых страниц в ESC t n
    CODEPAGE_MAP: Final[dict[str, int]] = {
        "pc437": 1,
        "pc850": 2,
        "pc860": 3,
        "pc863": 4,
        "pc865": 5,
        "pc852": 18,
        "pc866": 17,
        "pc858": 16,
        "pc861": 13,
        "pc857": 9,
        "pc869": 15,
        "pc855": 12,
    }

    def __init__(
        self,
        codepage: "CodePage",
        cpi: "CharactersPerInch",
        quality: "PrintQuality",
    ) -> None:
        """Инициализирует генератор тестовой страницы.

        Args:
            codepage: Кодовая страница для теста
            cpi: CPI для теста
            quality: Качество печати для теста
        """
        self._codepage = codepage
        self._cpi = cpi
        self._quality = quality
        self._logger = logging.getLogger(__name__)

    def generate(self) -> bytes:
        """Генерирует тестовую страницу ESC/P.

        Returns:
            Байты ESC/P команд для тестовой страницы
        """
        result = bytearray()

        # 1. Сброс принтера
        result.extend(ESC_AT)

        # 2. Установка кодовой страницы
        result.extend(self._set_codepage())

        # 3. Установка качества
        result.extend(self._set_quality())

        # 4. Заголовок тестовой страницы
        result.extend(self._render_header())

        # 5. Тест CPI
        result.extend(self._render_cpi_test())

        # 6. Тест выравнивания
        result.extend(self._render_alignment_test())

        # 7. Тест стилей
        result.extend(self._render_style_test())

        # 8. Таблица символов
        result.extend(self._render_char_table())

        # 9. Тест графики (120 dpi)
        result.extend(self._render_graphics_test())

        # 10. Сброс в конце
        result.extend(ESC_AT)

        self._logger.info("Сгенерирована тестовая страница: %d байт", len(result))
        return bytes(result)

    def _set_codepage(self) -> bytes:
        """Устанавливает кодовую страницу.

        Returns:
            ESC/P команда для установки кодовой страницы
        """
        cp_value = self.CODEPAGE_MAP.get(self._codepage.value, 1)
        return ESC_t + bytes([cp_value])

    def _set_quality(self) -> bytes:
        """Устанавливает качество печати.

        Returns:
            ESC/P команды для установки качества
        """
        quality_value = self._quality.value.lower()

        if quality_value == "draft":
            return ESC_x_0
        elif quality_value == "hsd":
            return ESC_x_0 + ESC_y_1
        elif quality_value == "usd":
            return ESC_x_0 + ESC_y_2
        elif quality_value == "nlq":
            return ESC_x_1 + ESC_k_0  # Roman по умолчанию

        return ESC_x_0

    def _render_header(self) -> bytes:
        """Рендерит заголовок тестовой страницы.

        Returns:
            ESC/P команды для заголовка
        """
        result = bytearray()

        # Установка 12 CPI для заголовка
        result.extend(ESC_M)

        # Заголовок
        result.extend(b"=== ESC/P TEST PAGE ===")
        result.extend(CRLF)

        # Информация о настройках
        cpi_str = str(self._cpi.numeric_value or "Prop")
        result.extend(f"CPI: {cpi_str}".encode("ascii", errors="replace"))
        result.extend(CRLF)

        result.extend(f"Quality: {self._quality.value.upper()}".encode("ascii", errors="replace"))
        result.extend(CRLF)

        result.extend(f"CodePage: {self._codepage.value}".encode("ascii", errors="replace"))
        result.extend(CRLF)

        result.extend(b"=" * 40)
        result.extend(CRLF)
        result.extend(CRLF)

        return bytes(result)

    def _render_cpi_test(self) -> bytes:
        """Рендерит тест CPI.

        Returns:
            ESC/P команды для теста CPI
        """
        result = bytearray()

        result.extend(b"--- CPI TEST ---")
        result.extend(CRLF)

        # 10 CPI
        result.extend(ESC_P)
        result.extend(b"10 CPI: 12345678901234567890")
        result.extend(CRLF)

        # 12 CPI
        result.extend(ESC_M)
        result.extend(b"12 CPI: 123456789012345678901234567890")
        result.extend(CRLF)

        # 15 CPI
        result.extend(ESC_g)
        result.extend(b"15 CPI: 1234567890123456789012345678901234567890")
        result.extend(CRLF)

        # Вернуть 10 CPI
        result.extend(ESC_P)

        result.extend(CRLF)
        return bytes(result)

    def _render_alignment_test(self) -> bytes:
        """Рендерит тест выравнивания.

        Returns:
            ESC/P команды для теста выравнивания
        """
        result = bytearray()

        result.extend(b"--- ALIGNMENT TEST ---")
        result.extend(CRLF)

        # Левое выравнивание (по умолчанию)
        result.extend(b"LEFT: This text is left aligned")
        result.extend(CRLF)

        # Центральное выравнивание (через ESC $)
        # Позиция для центра: ~240 units (4 дюйма * 60)
        result.extend(ESC_DOLLAR + bytes([240 % 256, 240 // 256]))
        result.extend(b"CENTER: Centered text")
        result.extend(CRLF)

        # Правое выравнивание (через ESC $)
        # Позиция для правого края: ~420 units (7 дюймов * 60)
        result.extend(ESC_DOLLAR + bytes([420 % 256, 420 // 256]))
        result.extend(b"RIGHT: Right aligned")
        result.extend(CRLF)

        result.extend(CRLF)
        return bytes(result)

    def _render_style_test(self) -> bytes:
        """Рендерит тест стилей.

        Returns:
            ESC/P команды для теста стилей
        """
        result = bytearray()

        result.extend(b"--- STYLE TEST ---")
        result.extend(CRLF)

        # Normal
        result.extend(b"Normal text")
        result.extend(CRLF)

        # Bold
        result.extend(ESC_E)
        result.extend(b"Bold text")
        result.extend(ESC_F)
        result.extend(CRLF)

        # Italic
        result.extend(ESC_4)
        result.extend(b"Italic text")
        result.extend(ESC_5)
        result.extend(CRLF)

        # Underline
        result.extend(ESC_MINUS_1)
        result.extend(b"Underlined text")
        result.extend(ESC_MINUS_0)
        result.extend(CRLF)

        # Double-strike
        result.extend(ESC_G)
        result.extend(b"Double-strike text")
        result.extend(ESC_H)
        result.extend(CRLF)

        # Bold + Italic
        result.extend(ESC_E + ESC_4)
        result.extend(b"Bold + Italic")
        result.extend(ESC_5 + ESC_F)
        result.extend(CRLF)

        result.extend(CRLF)
        return bytes(result)

    def _render_char_table(self) -> bytes:
        """Рендерит таблицу символов.

        Returns:
            ESC/P команды для таблицы символов
        """
        result = bytearray()

        result.extend(b"--- CHARACTER TABLE ---")
        result.extend(CRLF)

        # Печатаем символы 0x20-0xFF (пропуская управляющие)
        for row_start in range(0x20, 0x100, 16):
            # Адрес строки
            result.extend(f"{row_start:02X}: ".encode("ascii"))

            # Символы строки
            for i in range(16):
                char_code = row_start + i
                if char_code < 0x100:
                    try:
                        # Печатаем символ как есть (в выбранной кодовой странице)
                        result.extend(bytes([char_code]))
                    except TypeError:
                        result.extend(b".")

            result.extend(CRLF)

        result.extend(CRLF)
        return bytes(result)

    def _render_graphics_test(self) -> bytes:
        """Рендерит тест графики 120 dpi.

        Returns:
            ESC/P команды для теста графики
        """
        result = bytearray()

        result.extend(b"--- GRAPHICS TEST (120 dpi) ---")
        result.extend(CRLF)

        # ESC * m n1 n2 data
        # m=1: Single density (60 dpi vertical, 60 dpi horizontal)
        # m=2: Double density (120 dpi vertical, 60 dpi horizontal)
        # m=3: Quad density (240 dpi vertical, 60 dpi horizontal)

        # Горизонтальная полоса 120 dpi
        # m=2, n1=100, n2=0 (100 колонок)
        n1 = 100 % 256
        n2 = 100 // 256

        # Чередуемся: 0xFF (все точки) и 0xAA (каждая вторая)
        result.extend(ESC_ASTERISK + bytes([2, n1, n2]))
        for i in range(100):
            if i % 2 == 0:
                result.extend(bytes([0xFF]))  # Все точки
            else:
                result.extend(bytes([0xAA]))  # Шахматный паттерн

        result.extend(CRLF)
        result.extend(CRLF)

        # Финальная подпись
        result.extend(b"=== END OF TEST PAGE ===")
        result.extend(CRLF)

        return bytes(result)


__all__ = ["TestPageGenerator"]
