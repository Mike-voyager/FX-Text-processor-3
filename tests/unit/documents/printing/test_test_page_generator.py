"""Тесты для генератора тестовой страницы ESC/P."""

from __future__ import annotations

import pytest

from src.documents.printing.test_page_generator import (
    ESC,
    TestPageGenerator,
)
from src.model.enums import CharactersPerInch, CodePage, PrintQuality


class TestTestPageGenerator:
    """Тесты генератора тестовой страницы."""

    def test_init_defaults(self) -> None:
        """Тест инициализации с настройками по умолчанию."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        assert generator._codepage == CodePage.PC866
        assert generator._cpi == CharactersPerInch.CPI_10
        assert generator._quality == PrintQuality.DRAFT

    def test_generate_returns_bytes(self) -> None:
        """Тест что generate возвращает байты."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_generate_starts_with_reset(self) -> None:
        """Тест что страница начинается с ESC @ (сброс принтера)."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        # ESC @ = 0x1B 0x40
        assert result[:2] == ESC + b"@"

    def test_generate_ends_with_reset(self) -> None:
        """Тест что страница заканчивается сбросом принтера."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        # ESC @ = 0x1B 0x40
        assert result[-2:] == ESC + b"@"

    def test_generate_contains_header(self) -> None:
        """Тест что страница содержит заголовок."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        assert b"ESC/P TEST PAGE" in result
        assert b"CPI:" in result
        assert b"Quality:" in result
        assert b"CodePage:" in result

    def test_generate_contains_cpi_test(self) -> None:
        """Тест что страница содержит тест CPI."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        assert b"CPI TEST" in result
        assert b"10 CPI:" in result
        assert b"12 CPI:" in result
        assert b"15 CPI:" in result

    def test_generate_contains_alignment_test(self) -> None:
        """Тест что страница содержит тест выравнивания."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        assert b"ALIGNMENT TEST" in result
        assert b"LEFT:" in result
        assert b"CENTER:" in result
        assert b"RIGHT:" in result

    def test_generate_contains_style_test(self) -> None:
        """Тест что страница содержит тест стилей."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        assert b"STYLE TEST" in result
        assert b"Normal text" in result
        assert b"Bold text" in result
        assert b"Italic text" in result
        assert b"Underlined text" in result

    def test_generate_contains_char_table(self) -> None:
        """Тест что страница содержит таблицу символов."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        assert b"CHARACTER TABLE" in result

    def test_generate_contains_graphics_test(self) -> None:
        """Тест что страница содержит тест графики."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        assert b"GRAPHICS TEST" in result

    def test_set_codepage_pc866(self) -> None:
        """Тест установки кодовой страницы PC866 (кириллица)."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator._set_codepage()

        # ESC t 17 (PC866)
        assert result == ESC + b"t" + bytes([17])

    def test_set_codepage_pc437(self) -> None:
        """Тест установки кодовой страницы PC437 (США)."""
        generator = TestPageGenerator(
            codepage=CodePage.PC437,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator._set_codepage()

        # ESC t 1 (PC437)
        assert result == ESC + b"t" + bytes([1])

    def test_set_quality_draft(self) -> None:
        """Тест установки качества Draft."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator._set_quality()

        # ESC x 0 (Draft)
        assert result == ESC + b"x\x00"

    def test_set_quality_hsd(self) -> None:
        """Тест установки качества HSD."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.HSD,
        )

        result = generator._set_quality()

        # ESC x 0 + ESC y 1 (HSD)
        assert result == ESC + b"x\x00" + ESC + b"y\x01"

    def test_set_quality_nql(self) -> None:
        """Тест установки качества NLQ."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.NLQ,
        )

        result = generator._set_quality()

        # ESC x 1 + ESC k 0 (NLQ + Roman)
        assert result == ESC + b"x\x01" + ESC + b"k\x00"

    def test_different_cpi_values(self) -> None:
        """Тест с разными значениями CPI."""
        cpi_values = [
            CharactersPerInch.CPI_10,
            CharactersPerInch.CPI_12,
            CharactersPerInch.CPI_15,
            CharactersPerInch.CPI_17,
            CharactersPerInch.CPI_20,
            CharactersPerInch.PROPORTIONAL,
        ]

        for cpi in cpi_values:
            generator = TestPageGenerator(
                codepage=CodePage.PC866,
                cpi=cpi,
                quality=PrintQuality.DRAFT,
            )

            result = generator.generate()

            # CPI выводится в заголовке
            if cpi.numeric_value:
                expected = f"CPI: {cpi.numeric_value}".encode()
            else:
                expected = b"CPI: Prop"
            assert expected in result, f"Не найден CPI для {cpi}"

    def test_different_codepage_values(self) -> None:
        """Тест с разными кодовыми страницами."""
        codepages = [CodePage.PC437, CodePage.PC850, CodePage.PC866, CodePage.PC852]

        for codepage in codepages:
            generator = TestPageGenerator(
                codepage=codepage,
                cpi=CharactersPerInch.CPI_10,
                quality=PrintQuality.DRAFT,
            )

            result = generator.generate()

            # Страница должна начинаться с ESC @
            assert result[:2] == ESC + b"@"
            # Должен быть заголовок
            assert b"ESC/P TEST PAGE" in result

    def test_byte_size_estimate(self) -> None:
        """Тест примерного размера тестовой страницы."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        # Типичная тестовая страница ~1-5 KB (зависит от содержимого)
        assert 500 < len(result) < 10000, f"Размер {len(result)} вне ожидаемого диапазона"


class TestCodepageMapping:
    """Тесты маппинга кодовых страниц."""

    def test_known_codepages_mapped(self) -> None:
        """Тест что известные кодовые страницы имеют маппинг."""
        known_codepages = [
            "pc437",
            "pc850",
            "pc866",
            "pc852",
            "pc860",
            "pc863",
            "pc865",
        ]

        for cp in known_codepages:
            assert cp in TestPageGenerator.CODEPAGE_MAP, f"Отсутствует маппинг для {cp}"

    def test_unknown_codepage_defaults_to_1(self) -> None:
        """Тест что неизвестная кодовая страница по умолчанию PC437."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        # Неизвестная кодовая страница
        result = generator.CODEPAGE_MAP.get("unknown_codepage", 1)
        assert result == 1


class TestESCPCommands:
    """Тесты корректности ESC/P команд."""

    def test_bold_commands_paired(self) -> None:
        """Тест что команды Bold включаются и выключаются парно."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        # ESC E (Bold on) и ESC F (Bold off)
        assert ESC + b"E" in result
        assert ESC + b"F" in result

        # Подсчёт пар
        bold_on_count = result.count(ESC + b"E")
        bold_off_count = result.count(ESC + b"F")
        assert bold_on_count == bold_off_count, "Несбалансированные команды Bold"

    def test_italic_commands_paired(self) -> None:
        """Тест что команды Italic включаются и выключаются парно."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        # ESC 4 (Italic on) и ESC 5 (Italic off)
        assert ESC + b"4" in result
        assert ESC + b"5" in result

        italic_on_count = result.count(ESC + b"4")
        italic_off_count = result.count(ESC + b"5")
        assert italic_on_count == italic_off_count, "Несбалансированные команды Italic"

    def test_underline_commands_paired(self) -> None:
        """Тест что команды Underline включаются и выключаются парно."""
        generator = TestPageGenerator(
            codepage=CodePage.PC866,
            cpi=CharactersPerInch.CPI_10,
            quality=PrintQuality.DRAFT,
        )

        result = generator.generate()

        # ESC - 1 (Underline on) и ESC - 0 (Underline off)
        assert ESC + b"-\x01" in result
        assert ESC + b"-\x00" in result

        underline_on_count = result.count(ESC + b"-\x01")
        underline_off_count = result.count(ESC + b"-\x00")
        assert underline_on_count == underline_off_count, "Несбалансированные команды Underline"


__all__ = ["TestTestPageGenerator", "TestCodepageMapping", "TestESCPCommands"]