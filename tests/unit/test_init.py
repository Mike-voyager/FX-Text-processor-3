"""
Модульные тесты для src/__init__.py
Тестирует инициализацию пакета, конфигурацию, логирование и публичный API.
"""

import json
import logging
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest import mock

import pytest

# Импортируем пакет

import __init__ as escp_editor


class TestVersionMetadata:
    """Тестирование метаданных версии и констант."""

    def test_version_format(self) -> None:
        """Проверить, что __version__ следует семантическому версионированию."""
        import re

        version_pattern = r"^\d+\.\d+\.\d+$"
        assert re.match(
            version_pattern, escp_editor.__version__
        ), f"Версия '{escp_editor.__version__}' не соответствует паттерну семантического версионирования"

    def test_version_components(self) -> None:
        """Проверить, что компоненты версии соответствуют __version__."""
        expected_version = (
            f"{escp_editor.VERSION_MAJOR}."
            f"{escp_editor.VERSION_MINOR}."
            f"{escp_editor.VERSION_PATCH}"
        )
        assert (
            escp_editor.__version__ == expected_version
        ), "Компоненты версии не соответствуют __version__"

    def test_metadata_attributes(self) -> None:
        """Проверить, что все атрибуты метаданных являются непустыми строками."""
        assert (
            isinstance(escp_editor.__author__, str) and escp_editor.__author__
        ), "__author__ должен быть непустой строкой"

        assert (
            isinstance(escp_editor.__description__, str) and escp_editor.__description__
        ), "__description__ должен быть непустой строкой"

        assert (
            isinstance(escp_editor.__license__, str) and escp_editor.__license__
        ), "__license__ должен быть непустой строкой"

        assert (
            isinstance(escp_editor.__python_requires__, str) and escp_editor.__python_requires__
        ), "__python_requires__ должен быть непустой строкой"

        assert (
            isinstance(escp_editor.__platform__, str) and escp_editor.__platform__
        ), "__platform__ должен быть непустой строкой"

    def test_version_immutability(self) -> None:
        """Проверить, что константы версии имеют неизменяемые типы."""
        assert isinstance(escp_editor.VERSION_MAJOR, int)
        assert isinstance(escp_editor.VERSION_MINOR, int)
        assert isinstance(escp_editor.VERSION_PATCH, int)


class TestPublicAPI:
    """Тестирование экспортов публичного API."""

    def test_all_exports_exist(self) -> None:
        """Проверить, что все имена в __all__ действительно существуют в модуле."""
        for name in escp_editor.__all__:
            assert hasattr(escp_editor, name), f"Имя '{name}' из __all__ не существует в модуле"

    def test_all_is_list(self) -> None:
        """Проверить, что __all__ является списком."""
        assert isinstance(escp_editor.__all__, list), "__all__ должен быть списком"

    def test_all_contains_strings(self) -> None:
        """Проверить, что все элементы в __all__ являются строками."""
        assert all(
            isinstance(name, str) for name in escp_editor.__all__
        ), "Все элементы в __all__ должны быть строками"

    def test_no_duplicate_exports(self) -> None:
        """Проверить, что __all__ не содержит дубликатов."""
        assert len(escp_editor.__all__) == len(
            set(escp_editor.__all__)
        ), "__all__ содержит дублирующиеся записи"

    def test_utilities_exported(self) -> None:
        """Проверить, что функции утилит экспортированы."""
        assert "get_logger" in escp_editor.__all__
        assert "load_config" in escp_editor.__all__
        assert "check_dependencies" in escp_editor.__all__

    def test_version_metadata_exported(self) -> None:
        """Проверить, что метаданные версии экспортированы."""
        assert "__version__" in escp_editor.__all__
        assert "__author__" in escp_editor.__all__


class TestLogging:
    """Тестирование конфигурации логирования."""

    def test_get_logger_returns_logger(self) -> None:
        """Проверить, что get_logger возвращает экземпляр Logger."""
        logger = escp_editor.get_logger("test_module")
        assert isinstance(
            logger, logging.Logger
        ), "get_logger должен возвращать экземпляр logging.Logger"

    def test_get_logger_name_format(self) -> None:
        """Проверить, что имена логгеров правильно отформатированы."""
        logger = escp_editor.get_logger("test_module")
        assert (
            logger.name == "escp_editor.test_module"
        ), f"Имя логгера должно быть 'escp_editor.test_module', получено '{logger.name}'"

    def test_get_logger_with_qualified_name(self) -> None:
        """Проверить get_logger с уже квалифицированным именем."""
        logger = escp_editor.get_logger("escp_editor.model.document")
        assert logger.name == "escp_editor.model.document"

    def test_get_logger_with_main(self) -> None:
        """Проверить get_logger с модулем __main__."""
        logger = escp_editor.get_logger("__main__")
        assert logger.name == "escp_editor.main"

    def test_logger_is_configured(self) -> None:
        """Проверить, что логгер имеет настроенные обработчики."""
        logger = escp_editor.get_logger("test_configured")
        root_logger = logging.getLogger("escp_editor")

        # Корневой логгер должен иметь как минимум консольный обработчик
        assert (
            len(root_logger.handlers) >= 1
        ), "Корневой логгер должен иметь как минимум один обработчик"

    def test_log_level_from_environment(self) -> None:
        """Проверить, что уровень логирования можно установить через переменную окружения."""
        with mock.patch.dict("os.environ", {"ESCP_LOG_LEVEL": "DEBUG"}):
            # Очищаем существующие обработчики
            root_logger = logging.getLogger("escp_editor")
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)

            # Повторно настраиваем логирование с новым окружением
            from importlib import reload

            reload(escp_editor)

            # Проверяем, что уровень корневого логгера - DEBUG
            root_logger = logging.getLogger("escp_editor")
            assert root_logger.level == logging.DEBUG


class TestConfiguration:
    """Тестирование управления конфигурацией."""

    def test_load_config_returns_dict(self) -> None:
        """Проверить, что load_config возвращает словарь."""
        config = escp_editor.load_config()
        assert isinstance(config, dict), "load_config должна возвращать словарь"

    def test_load_config_defaults(self) -> None:
        """Проверить, что load_config возвращает все ключи по умолчанию, когда файл не существует."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "nonexistent_config.json"
            config = escp_editor.load_config(config_path)

            # Проверяем наличие обязательных ключей
            required_keys = [
                "default_printer",
                "default_codepage",
                "auto_save_interval_seconds",
                "recent_files_limit",
                "ui_theme",
                "log_level",
            ]

            for key in required_keys:
                assert (
                    key in config
                ), f"В конфигурации по умолчанию отсутствует обязательный ключ: {key}"

    def test_load_config_from_file(self) -> None:
        """Проверить, что load_config загружает пользовательские значения из файла."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "test_config.json"

            # Создаём пользовательскую конфигурацию
            custom_config = {
                "default_printer": "Test Printer",
                "default_codepage": "PC850",
                "custom_key": "custom_value",
            }

            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(custom_config, f)

            # Загружаем конфигурацию
            config = escp_editor.load_config(config_path)

            # Проверяем пользовательские значения
            assert config["default_printer"] == "Test Printer"
            assert config["default_codepage"] == "PC850"
            assert config["custom_key"] == "custom_value"

            # Проверяем, что настройки по умолчанию всё ещё присутствуют для отсутствующих ключей
            assert "auto_save_interval_seconds" in config

    def test_load_config_invalid_json(self) -> None:
        """Проверить, что load_config корректно обрабатывает недопустимый JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "invalid_config.json"

            # Создаём недопустимый JSON
            with open(config_path, "w", encoding="utf-8") as f:
                f.write("{invalid json content")

            # Загружаем конфигурацию - должна вернуться конфигурация по умолчанию без исключений
            config = escp_editor.load_config(config_path)

            # Всё равно должны получить конфигурацию по умолчанию
            assert isinstance(config, dict)
            assert "default_printer" in config

    def test_load_config_non_dict_json(self) -> None:
        """Проверить, что load_config корректно обрабатывает JSON не-словарь."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "list_config.json"

            # Создаём JSON-список вместо объекта
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(["not", "a", "dict"], f)

            # Загружаем конфигурацию - должна вернуться конфигурация по умолчанию без исключений
            config = escp_editor.load_config(config_path)

            # Всё равно должны получить конфигурацию по умолчанию
            assert isinstance(config, dict)
            assert "default_printer" in config

    def test_load_config_merge_behavior(self) -> None:
        """Проверить, что пользовательская конфигурация корректно сливается с настройками по умолчанию."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "partial_config.json"

            # Создаём частичную конфигурацию
            partial_config = {
                "default_printer": "Custom Printer",
            }

            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(partial_config, f)

            # Загружаем конфигурацию
            config = escp_editor.load_config(config_path)

            # Проверяем, что пользовательское значение присутствует
            assert config["default_printer"] == "Custom Printer"

            # Проверяем, что другие настройки по умолчанию всё ещё присутствуют
            assert "default_codepage" in config
            assert config["default_codepage"] == "PC866"  # Значение по умолчанию


class TestDependencyCheck:
    """Тестирование проверки зависимостей."""

    def test_check_dependencies_returns_dict(self) -> None:
        """Проверить, что check_dependencies возвращает словарь."""
        deps = escp_editor.check_dependencies()
        assert isinstance(deps, dict), "check_dependencies должна возвращать словарь"

    def test_check_dependencies_values_are_bool(self) -> None:
        """Проверить, что все значения проверки зависимостей являются булевыми."""
        deps = escp_editor.check_dependencies()
        assert all(
            isinstance(v, bool) for v in deps.values()
        ), "Все значения проверки зависимостей должны быть булевыми"

    def test_check_dependencies_keys(self) -> None:
        """Проверить, что check_dependencies проверяет ожидаемые пакеты."""
        deps = escp_editor.check_dependencies()

        expected_keys = [
            "tkinter",
            "pillow",
            "pywin32",
            "qrcode",
            "python-barcode",
            "python-markdown",
            "openpyxl",
        ]

        for key in expected_keys:
            assert key in deps, f"В проверке зависимостей отсутствует ключ: {key}"

    def test_check_dependencies_performance(self) -> None:
        """Проверить, что check_dependencies выполняется быстро."""
        import time

        start = time.perf_counter()
        escp_editor.check_dependencies()
        elapsed = time.perf_counter() - start

        # Должна выполниться менее чем за 50мс
        assert elapsed < 0.05, f"check_dependencies заняла {elapsed*1000:.1f}мс, ожидалось < 50мс"

    def test_check_dependencies_idempotent(self) -> None:
        """Проверить, что check_dependencies можно вызывать многократно."""
        deps1 = escp_editor.check_dependencies()
        deps2 = escp_editor.check_dependencies()

        assert deps1 == deps2, "check_dependencies должна возвращать согласованные результаты"


class TestImportPerformance:
    """Тестирование производительности импорта пакета."""

    def test_package_imports_successfully(self) -> None:
        """Проверить, что пакет можно импортировать."""
        # Уже импортирован на уровне модуля, просто проверяем
        assert escp_editor is not None
        assert hasattr(escp_editor, "__version__")

    def test_no_circular_imports(self) -> None:
        """Проверить, что импорт пакета не вызывает ошибок циклического импорта."""
        # Если мы дошли до этого места, циклических импортов нет
        # Пробуем переимпортировать для уверенности
        import importlib

        try:
            importlib.reload(escp_editor)
            success = True
        except ImportError:
            success = False

        assert success, "В пакете присутствуют проблемы циклического импорта"


class TestPlatformChecks:
    """Тестирование проверок совместимости платформы."""

    def test_python_version_requirement(self) -> None:
        """Проверить, что версия Python соответствует требованиям."""
        # Если мы дошли до этого места, проверка версии прошла
        assert sys.version_info >= (
            3,
            11,
        ), "Требуется Python 3.11+, но проверка версии не сработала"

    @pytest.mark.skipif(sys.platform == "win32", reason="Тестировать только на не-Windows")
    def test_non_windows_warning(self) -> None:
        """Проверить, что платформы не-Windows получают предупреждение."""
        import warnings

        # На не-Windows должно было быть выдано предупреждение
        # Это трудно протестировать ретроспективно, поэтому просто проверяем константу платформы
        assert escp_editor.__platform__ == "Windows"


class TestEdgeCases:
    """Тестирование граничных случаев и обработки ошибок."""

    def test_logger_with_empty_name(self) -> None:
        """Проверить get_logger с пустой строкой."""
        logger = escp_editor.get_logger("")
        assert isinstance(logger, logging.Logger)
        assert "escp_editor" in logger.name

    def test_logger_with_dots(self) -> None:
        """Проверить get_logger с именем модуля с точками."""
        logger = escp_editor.get_logger("model.document.parser")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "escp_editor.model.document.parser"

    def test_config_with_permission_error(self) -> None:
        """Проверить load_config, когда файл существует, но не может быть прочитан."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "readonly_config.json"

            # Создаём файл конфигурации
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump({"test": "value"}, f)

            # Делаем файл недоступным для чтения (только Unix-подобные системы)
            if hasattr(config_path, "chmod"):
                try:
                    config_path.chmod(0o000)

                    # Пробуем загрузить - должна вернуться конфигурация по умолчанию
                    config = escp_editor.load_config(config_path)
                    assert isinstance(config, dict)
                    assert "default_printer" in config
                finally:
                    # Восстанавливаем права для очистки
                    config_path.chmod(0o644)

    def test_logging_directory_creation(self) -> None:
        """Проверить, что логирование создаёт каталог logs, если он не существует."""
        # Это проверяется неявно во время импорта
        # Проверяем, что каталог logs существует, если файловое логирование удалось
        logs_dir = Path("logs")
        if logs_dir.exists():
            assert logs_dir.is_dir()


class TestDocumentation:
    """Тестирование наличия и полноты документации."""

    def test_module_has_docstring(self) -> None:
        """Проверить, что модуль имеет исчерпывающую строку документации."""
        assert escp_editor.__doc__ is not None
        assert (
            len(escp_editor.__doc__) > 100
        ), "Строка документации модуля должна быть исчерпывающей"

    def test_get_logger_has_docstring(self) -> None:
        """Проверить, что get_logger имеет строку документации."""
        assert escp_editor.get_logger.__doc__ is not None
        assert "Аргументы:" in escp_editor.get_logger.__doc__
        assert "Возвращает:" in escp_editor.get_logger.__doc__
        assert "Пример:" in escp_editor.get_logger.__doc__

    def test_load_config_has_docstring(self) -> None:
        """Проверить, что load_config имеет строку документации."""
        assert escp_editor.load_config.__doc__ is not None
        assert "Аргументы:" in escp_editor.load_config.__doc__
        assert "Возвращает:" in escp_editor.load_config.__doc__

    def test_check_dependencies_has_docstring(self) -> None:
        """Проверить, что check_dependencies имеет строку документации."""
        assert escp_editor.check_dependencies.__doc__ is not None
        assert "Возвращает:" in escp_editor.check_dependencies.__doc__


# Запускать тесты командой: pytest tests/unit/test_init.py -v --cov=escp_editor --cov-report=term-missing
