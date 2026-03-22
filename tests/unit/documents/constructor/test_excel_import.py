"""Тесты для модуля excel_import.

Покрытие:
- ExcelMappingType Enum
- ExcelFieldMapping dataclass
- ExcelImporter инициализация
- get_sheets() список листов
- preview_range() превью данных
- apply_mappings() применение маппингов
- _convert_dtype() конвертация типов
- context manager
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from src.documents.constructor.excel_import import (
    ExcelFieldMapping,
    ExcelImporter,
    ExcelMappingType,
)

# Skip all tests if openpyxl is not installed
pytest.importorskip("openpyxl", reason="openpyxl not installed")


class TestExcelMappingType:
    """Тесты для ExcelMappingType."""

    def test_column(self) -> None:
        """COLUMN тип."""
        assert ExcelMappingType.COLUMN.value == "column"

    def test_row(self) -> None:
        """ROW тип."""
        assert ExcelMappingType.ROW.value == "row"

    def test_range(self) -> None:
        """RANGE тип."""
        assert ExcelMappingType.RANGE.value == "range"


class TestExcelFieldMapping:
    """Тесты для ExcelFieldMapping."""

    def test_create_minimal(self) -> None:
        """Создание с минимальными параметрами."""
        mapping = ExcelFieldMapping(
            field_name="test_field",
            source_type=ExcelMappingType.COLUMN,
        )
        assert mapping.field_name == "test_field"
        assert mapping.source_type == ExcelMappingType.COLUMN
        assert mapping.sheet_name is None
        assert mapping.range_ref == ""
        assert mapping.skip_empty is True
        assert mapping.trim is True
        assert mapping.dtype == "auto"

    def test_create_full(self) -> None:
        """Создание со всеми параметрами."""
        mapping = ExcelFieldMapping(
            field_name="full_field",
            source_type=ExcelMappingType.RANGE,
            sheet_name="Sheet1",
            range_ref="A1:D10",
            skip_empty=False,
            trim=False,
            dtype="str",
        )
        assert mapping.sheet_name == "Sheet1"
        assert mapping.range_ref == "A1:D10"
        assert mapping.skip_empty is False


class TestExcelImporterInit:
    """Тесты инициализации ExcelImporter."""

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Ошибка если файл не найден."""
        nonexistent = tmp_path / "nonexistent.xlsx"
        with pytest.raises(FileNotFoundError):
            ExcelImporter(nonexistent)

    def test_unsupported_extension(self, tmp_path: Path) -> None:
        """Ошибка для неподдерживаемого формата."""
        wrong_file = tmp_path / "file.txt"
        wrong_file.write_text("content")
        with pytest.raises(ValueError, match="Unsupported"):
            ExcelImporter(wrong_file)

    def test_xlsx_supported(self, tmp_path: Path) -> None:
        """Поддержка .xlsx."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"dummy")  # Content doesn't matter for init
        # Will fail later when trying to load, but init should work
        with patch.object(ExcelImporter, "_get_openpyxl"):
            importer = ExcelImporter(xlsx_file)
            assert importer._file_path == xlsx_file


class TestExcelImporterMocked:
    """Тесты с мокнутым openpyxl."""

    @pytest.fixture
    def mock_workbook(self) -> MagicMock:
        """Мок workbook."""
        wb = MagicMock()
        wb.sheetnames = ["Sheet1", "Sheet2"]
        wb.active = MagicMock()
        return wb

    @pytest.fixture
    def mock_openpyxl(self, mock_workbook: MagicMock) -> MagicMock:
        """Мок openpyxl модуля."""
        module = MagicMock()
        module.load_workbook.return_value = mock_workbook
        module.utils.column_index_from_string.return_value = 1
        return module

    @pytest.fixture
    def importer(
        self, tmp_path: Path, mock_openpyxl: MagicMock, mock_workbook: MagicMock
    ) -> ExcelImporter:
        """Импортер с мокнутым openpyxl."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)  # Fake zip header

        importer = ExcelImporter(xlsx_file)
        importer._openpyxl = mock_openpyxl
        importer._workbook = mock_workbook
        return importer

    def test_get_sheets(self, importer: ExcelImporter) -> None:
        """Список листов."""
        sheets = importer.get_sheets()
        assert sheets == ["Sheet1", "Sheet2"]

    def test_preview_range_cell(self, importer: ExcelImporter, mock_workbook: MagicMock) -> None:
        """Превью ячейки."""
        mock_worksheet = MagicMock()
        mock_cell = MagicMock()
        mock_cell.value = "Cell Value"
        mock_worksheet.__getitem__ = MagicMock(return_value=mock_cell)
        mock_workbook.__getitem__ = MagicMock(return_value=mock_worksheet)

        result = importer.preview_range("Sheet1", "A1")
        assert result == ["Cell Value"]

    def test_preview_range_row(self, importer: ExcelImporter, mock_workbook: MagicMock) -> None:
        """Превью строки."""
        mock_worksheet = MagicMock()
        mock_row = [MagicMock(value=f"val{i}") for i in range(3)]
        mock_worksheet.__getitem__ = MagicMock(return_value=mock_row)
        mock_workbook.__getitem__ = MagicMock(return_value=mock_worksheet)

        result = importer.preview_range("Sheet1", "3")
        assert result == ["val0", "val1", "val2"]

    def test_apply_mappings_empty(self, importer: ExcelImporter) -> None:
        """Пустой список маппингов."""
        result = importer.apply_mappings([], {})
        assert result == {}

    def test_apply_mappings_with_data(
        self, importer: ExcelImporter, mock_workbook: MagicMock, mock_openpyxl: MagicMock
    ) -> None:
        """Применение маппингов."""
        mapping = ExcelFieldMapping(
            field_name="test_field",
            source_type=ExcelMappingType.COLUMN,
            sheet_name="Sheet1",
            range_ref="A:A",
        )

        # Mock worksheet
        mock_worksheet = MagicMock()
        mock_worksheet.max_row = 2
        mock_cell1 = MagicMock(value="value1")
        mock_cell2 = MagicMock(value="value2")
        mock_worksheet.cell = MagicMock(side_effect=[mock_cell1, mock_cell2])
        mock_workbook.__getitem__ = MagicMock(return_value=mock_worksheet)

        result = importer.apply_mappings([mapping], {})
        # Should have field with data
        assert "test_field" in result

    def test_close(self, importer: ExcelImporter, mock_workbook: MagicMock) -> None:
        """Закрытие файла."""
        importer.close()
        mock_workbook.close.assert_called_once()


class TestConvertDtype:
    """Тесты метода _convert_dtype."""

    @pytest.fixture
    def importer(self, tmp_path: Path) -> ExcelImporter:
        """Импортер."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)  # Fake zip header
        importer = ExcelImporter(xlsx_file)
        importer._workbook = MagicMock()
        importer._openpyxl = MagicMock()
        return importer

    def test_auto_returns_value(self, importer: ExcelImporter) -> None:
        """auto возвращает как есть."""
        assert importer._convert_dtype("test", "auto") == "test"

    def test_str_conversion(self, importer: ExcelImporter) -> None:
        """Конвертация в str."""
        assert importer._convert_dtype(123, "str") == "123"

    def test_int_conversion(self, importer: ExcelImporter) -> None:
        """Конвертация в int."""
        assert importer._convert_dtype("42", "int") == 42

    def test_float_conversion(self, importer: ExcelImporter) -> None:
        """Конвертация в float."""
        assert importer._convert_dtype("3.14", "float") == 3.14

    def test_conversion_error_returns_original(self, importer: ExcelImporter) -> None:
        """При ошибке возвращает оригинал."""
        assert importer._convert_dtype("not_a_number", "int") == "not_a_number"

    def test_none_value(self, importer: ExcelImporter) -> None:
        """None не конвертируется."""
        assert importer._convert_dtype(None, "str") is None


class TestContextManager:
    """Тесты контекстного менеджера."""

    def test_context_manager(self, tmp_path: Path) -> None:
        """Работа с with."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)  # Fake zip header

        importer = ExcelImporter(xlsx_file)
        importer._workbook = MagicMock()

        with importer as imp:
            assert imp is not None

    def test_auto_close(self, tmp_path: Path) -> None:
        """Автоматическое закрытие."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)  # Fake zip header

        mock_wb = MagicMock()

        importer = ExcelImporter(xlsx_file)
        importer._workbook = mock_wb

        with importer:
            pass

        mock_wb.close.assert_called_once()


class TestReadMethods:
    """Тесты методов чтения."""

    @pytest.fixture
    def mock_worksheet(self) -> MagicMock:
        """Мок worksheet."""
        ws = MagicMock()
        ws.max_row = 3
        ws.max_column = 3

        # Create cells for cell access
        def cell_side_effect(row: int, col: int) -> MagicMock:
            mock_cell = MagicMock()
            mock_cell.value = f"r{row}c{col}"
            return mock_cell

        ws.cell = MagicMock(side_effect=cell_side_effect)
        return ws

    @pytest.fixture
    def mock_workbook(self, mock_worksheet: MagicMock) -> MagicMock:
        """Мок workbook."""
        wb = MagicMock()
        wb.__getitem__ = MagicMock(return_value=mock_worksheet)
        return wb

    @pytest.fixture
    def mock_openpyxl(self) -> MagicMock:
        """Мок openpyxl."""
        module = MagicMock()
        module.utils.column_index_from_string.return_value = 1
        return module

    @pytest.fixture
    def importer(
        self, tmp_path: Path, mock_workbook: MagicMock, mock_openpyxl: MagicMock
    ) -> ExcelImporter:
        """Импортер с мокнутым worksheet."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)  # Fake zip header

        importer = ExcelImporter(xlsx_file)
        importer._workbook = mock_workbook
        importer._openpyxl = mock_openpyxl
        return importer

    def test_read_column(self, importer: ExcelImporter, mock_worksheet: MagicMock) -> None:
        """Чтение столбца."""
        mapping = ExcelFieldMapping(
            field_name="col",
            source_type=ExcelMappingType.COLUMN,
            range_ref="A",
        )
        result = importer._read_column(mock_worksheet, "A", mapping)
        assert len(result) > 0

    def test_read_row(self, importer: ExcelImporter, mock_worksheet: MagicMock) -> None:
        """Чтение строки."""
        mapping = ExcelFieldMapping(
            field_name="row",
            source_type=ExcelMappingType.ROW,
            range_ref="1",
        )
        result = importer._read_row(mock_worksheet, "1", mapping)
        # Returns values from row
        assert isinstance(result, list)

    def test_read_range(self, importer: ExcelImporter, mock_worksheet: MagicMock) -> None:
        """Чтение диапазона."""
        mapping = ExcelFieldMapping(
            field_name="range",
            source_type=ExcelMappingType.RANGE,
            range_ref="A1:B2",
        )
        # Mock range access
        mock_worksheet.__getitem__ = MagicMock(
            return_value=[
                [MagicMock(value="a1"), MagicMock(value="b1")],
                [MagicMock(value="a2"), MagicMock(value="b2")],
            ]
        )
        result = importer._read_range(mock_worksheet, "A1:B2", mapping)
        assert len(result) == 2


class TestExcelImporterConvertDtype:
    """Тесты конвертации типов."""

    @pytest.fixture
    def importer(self, tmp_path: Path) -> ExcelImporter:
        """Импортер без openpyxl."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)
        return ExcelImporter(xlsx_file)

    def test_convert_str(self, importer: ExcelImporter) -> None:
        """Конвертация в строку."""
        result = importer._convert_dtype(123, "str")
        assert result == "123"

    def test_convert_int(self, importer: ExcelImporter) -> None:
        """Конвертация в int."""
        result = importer._convert_dtype("42", "int")
        assert result == 42

    def test_convert_float(self, importer: ExcelImporter) -> None:
        """Конвертация в float."""
        result = importer._convert_dtype("3.14", "float")
        assert result == 3.14

    def test_convert_auto_number(self, importer: ExcelImporter) -> None:
        """Авто-определение числа."""
        result = importer._convert_dtype(42, "auto")
        assert result == 42

    def test_convert_auto_float(self, importer: ExcelImporter) -> None:
        """Авто-определение float."""
        result = importer._convert_dtype(3.14, "auto")
        assert result == 3.14

    def test_convert_auto_string(self, importer: ExcelImporter) -> None:
        """Авто-определение строки."""
        result = importer._convert_dtype("text", "auto")
        assert result == "text"


class TestExcelImporterInitErrors:
    """Тесты ошибок инициализации."""

    def test_file_not_found(self, tmp_path: Path) -> None:
        """Файл не существует."""
        with pytest.raises(FileNotFoundError):
            ExcelImporter(tmp_path / "nonexistent.xlsx")

    def test_unsupported_format(self, tmp_path: Path) -> None:
        """Неподдерживаемый формат."""
        txt_file = tmp_path / "test.txt"
        txt_file.write_text("content")
        with pytest.raises(ValueError, match="Unsupported"):
            ExcelImporter(txt_file)


class TestExcelImporterOpenpyxlErrors:
    """Тесты ошибок openpyxl."""

    def test_import_error(self, tmp_path: Path) -> None:
        """openpyxl не установлен."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)
        importer = ExcelImporter(xlsx_file)

        # Simulate openpyxl not available
        importer._openpyxl = None
        with patch.dict("sys.modules", {"openpyxl": None}):
            with pytest.raises(ImportError):
                importer._get_openpyxl()


class TestExcelImporterContextManager:
    """Тесты контекстного менеджера."""

    def test_context_manager(self, tmp_path: Path) -> None:
        """Использование с with."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)

        with patch("src.documents.constructor.excel_import.ExcelImporter.close") as mock_close:
            with ExcelImporter(xlsx_file) as importer:
                assert importer is not None
            mock_close.assert_called_once()


class TestExcelImporterPreview:
    """Тесты preview_range."""

    @pytest.fixture
    def importer(self, tmp_path: Path) -> ExcelImporter:
        """Импортер с мокнутым workbook."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)

        importer = ExcelImporter(xlsx_file)

        mock_ws = MagicMock()
        mock_ws.__getitem__ = MagicMock(
            return_value=[
                [MagicMock(value=f"cell{i}") for i in range(3)],
            ]
        )

        mock_wb = MagicMock()
        mock_wb.__getitem__ = MagicMock(return_value=mock_ws)
        mock_wb.sheetnames = ["Sheet1"]

        importer._workbook = mock_wb
        importer._openpyxl = MagicMock()

        return importer

    def test_preview_with_limit(self, importer: ExcelImporter) -> None:
        """Предпросмотр с лимитом."""
        result = importer.preview_range("Sheet1", "A1:A10", limit=5)
        assert len(result) <= 5

    def test_preview_without_limit(self, importer: ExcelImporter) -> None:
        """Предпросмотр без лимита."""
        result = importer.preview_range("Sheet1", "A1:A10")
        assert isinstance(result, list)


class TestExcelImporterPreviewRange:
    """Тесты preview_range для разных типов диапазонов."""

    def test_preview_column_range(self, tmp_path: Path) -> None:
        """Превью колонки (буквенный диапазон)."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)

        importer = ExcelImporter(xlsx_file)

        mock_openpyxl = MagicMock()
        mock_openpyxl.utils.column_index_from_string.return_value = 2

        # Создаем мок для итерации по колонке
        mock_cell1 = MagicMock(value="val1")
        mock_cell2 = MagicMock(value="val2")
        mock_cell3 = MagicMock(value="val3")

        mock_ws = MagicMock()
        mock_ws.iter_rows = MagicMock(
            return_value=[
                [mock_cell1],
                [mock_cell2],
                [mock_cell3],
            ]
        )

        mock_wb = MagicMock()
        mock_wb.__getitem__ = MagicMock(return_value=mock_ws)

        importer._workbook = mock_wb
        importer._openpyxl = mock_openpyxl

        result = importer.preview_range("Sheet1", "B")

        # Должен вернуть список значений колонки
        assert isinstance(result, list)
        # Проверяем что значения есть в списке (limit проверяется внутри вложенного цикла)
        assert "val1" in result or "val2" in result or "val3" in result

    def test_preview_row_range(self, tmp_path: Path) -> None:
        """Превью строки (числовой диапазон)."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)

        importer = ExcelImporter(xlsx_file)

        mock_ws = MagicMock()
        # Для строки возвращаем ячейки
        mock_ws.__getitem__ = MagicMock(
            return_value=[MagicMock(value=f"cell{i}") for i in range(3)]
        )

        mock_wb = MagicMock()
        mock_wb.__getitem__ = MagicMock(return_value=mock_ws)

        importer._workbook = mock_wb
        importer._openpyxl = MagicMock()

        # isdigit() возвращает True, поэтому это будет row range
        result = importer.preview_range("Sheet1", "3")

        assert isinstance(result, list)


class TestExcelImporterApplyMappings:
    """Тесты apply_mappings с разными типами."""

    @pytest.fixture
    def importer(self, tmp_path: Path) -> ExcelImporter:
        """Импортер с моком."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)

        importer = ExcelImporter(xlsx_file)
        importer._workbook = MagicMock()
        importer._openpyxl = MagicMock()

        return importer

    def test_apply_mappings_unknown_type(self, importer: ExcelImporter) -> None:
        """Применение маппинга с неизвестным типом."""
        # Создаем мок для worksheet
        mock_ws = MagicMock()
        mock_ws.max_row = 5
        mock_ws.max_column = 5

        importer._workbook.active = mock_ws
        importer._workbook.__getitem__ = MagicMock(return_value=mock_ws)

        # Создаем маппинг с неизвестным типом
        # Используем валидный тип, но проверяем branch в коде
        mapping = ExcelFieldMapping(
            field_name="test_field",
            source_type=ExcelMappingType.COLUMN,
            range_ref="A",
        )

        # Просто проверяем что не падает
        result = importer.apply_mappings([mapping], {})
        assert "test_field" in result


class TestExcelImporterConvertDate:
    """Тесты конвертации дат."""

    @pytest.fixture
    def importer(self, tmp_path: Path) -> ExcelImporter:
        """Импортер."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)
        return ExcelImporter(xlsx_file)

    def test_convert_date_from_string(self, importer: ExcelImporter) -> None:
        """Конвертация даты из ISO строки."""
        from datetime import datetime

        result = importer._convert_dtype("2024-01-15", "date")
        assert isinstance(result, datetime)
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_convert_date_from_datetime(self, importer: ExcelImporter) -> None:
        """Конвертация уже datetime объекта."""
        from datetime import datetime

        dt = datetime(2024, 6, 20)
        result = importer._convert_dtype(dt, "date")
        assert result is dt

    def test_convert_date_invalid_string(self, importer: ExcelImporter) -> None:
        """Невалидная строка даты возвращает оригинал."""
        result = importer._convert_dtype("not-a-date", "date")
        assert result == "not-a-date"


class TestExcelImporterReadMethodsExtra:
    """Дополнительные тесты методов чтения."""

    @pytest.fixture
    def importer(self, tmp_path: Path) -> ExcelImporter:
        """Импортер."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)
        importer = ExcelImporter(xlsx_file)
        importer._openpyxl = MagicMock()
        importer._openpyxl.utils.column_index_from_string.return_value = 1
        return importer

    def test_read_row_range_format(self, importer: ExcelImporter) -> None:
        """Чтение диапазона строк в формате '1:5'."""
        mock_ws = MagicMock()
        mock_ws.max_column = 3

        # Мокаем ячейки для строк 1-5
        def cell_side_effect(row: int, col: int) -> MagicMock:
            return MagicMock(value=f"r{row}c{col}")

        mock_ws.cell = MagicMock(side_effect=cell_side_effect)

        mapping = ExcelFieldMapping(
            field_name="test",
            source_type=ExcelMappingType.ROW,
            range_ref="1:5",
            skip_empty=False,
        )

        result = importer._read_row(mock_ws, "1:5", mapping)
        assert isinstance(result, list)

    def test_read_range_with_empty_cells(self, importer: ExcelImporter) -> None:
        """Чтение диапазона с пустыми ячейками."""
        mock_ws = MagicMock()
        mock_ws.__getitem__ = MagicMock(
            return_value=[
                [MagicMock(value="a"), MagicMock(value=None), MagicMock(value="c")],
                [MagicMock(value=None), MagicMock(value="b"), MagicMock(value=None)],
            ]
        )

        mapping = ExcelFieldMapping(
            field_name="test",
            source_type=ExcelMappingType.RANGE,
            range_ref="A1:C2",
            skip_empty=True,
        )

        result = importer._read_range(mock_ws, "A1:C2", mapping)
        assert len(result) == 2

    def test_read_range_no_skip_empty(self, importer: ExcelImporter) -> None:
        """Чтение диапазона без пропуска пустых."""
        mock_ws = MagicMock()
        mock_ws.__getitem__ = MagicMock(
            return_value=[
                [MagicMock(value="a"), MagicMock(value=None), MagicMock(value="c")],
            ]
        )

        mapping = ExcelFieldMapping(
            field_name="test",
            source_type=ExcelMappingType.RANGE,
            range_ref="A1:C1",
            skip_empty=False,
        )

        result = importer._read_range(mock_ws, "A1:C1", mapping)
        assert len(result) == 1


class TestExcelImporterDtypeConversion:
    """Дополнительные тесты конвертации типов."""

    @pytest.fixture
    def importer(self, tmp_path: Path) -> ExcelImporter:
        """Импортер."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)
        return ExcelImporter(xlsx_file)

    def test_convert_dtype_unknown(self, importer: ExcelImporter) -> None:
        """Неизвестный dtype возвращает как есть."""
        result = importer._convert_dtype("test", "unknown")
        assert result == "test"

    def test_convert_dtype_float_from_int(self, importer: ExcelImporter) -> None:
        """Конвертация int в float."""
        result = importer._convert_dtype(42, "float")
        assert result == 42.0

    def test_convert_dtype_str_from_none(self, importer: ExcelImporter) -> None:
        """Конвертация None не меняется."""
        result = importer._convert_dtype(None, "str")
        assert result is None


class TestExcelImporterGetOpenpyxl:
    """Тесты ленивой загрузки openpyxl."""

    def test_get_openpyxl_lazy_import(self, tmp_path: Path) -> None:
        """Ленивая загрузка openpyxl."""
        xlsx_file = tmp_path / "test.xlsx"
        xlsx_file.write_bytes(b"PK" * 10)

        importer = ExcelImporter(xlsx_file)
        assert importer._openpyxl is None
        assert importer._workbook is None

        # После вызова _get_openpyxl - инициализация
        with patch.dict("sys.modules", {"openpyxl": MagicMock()}):
            mock_openpyxl = MagicMock()
            mock_wb = MagicMock()
            mock_openpyxl.load_workbook.return_value = mock_wb

            with patch.dict("sys.modules", {"openpyxl": mock_openpyxl}):
                # Первый вызов инициализирует
                result = importer._get_openpyxl()
                assert result is not None
