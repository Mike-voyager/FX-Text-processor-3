"""Unit-тесты для WidgetRegistry.

Проверяет:
- Singleton паттерн
- Thread-safety (concurrent доступ)
- Регистрацию виджетов с валидацией Protocol
- Создание экземпляров
- Query API (search, list_by_category и т.д.)
- Статистику
- Error handling

Coverage target: ≥95%
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Generator
from unittest.mock import MagicMock

import pytest
from src.gui.core.exceptions import (
    ProtocolValidationError,
    WidgetCreationError,
    WidgetNotFoundError,
    WidgetRegistryError,
)
from src.gui.core.protocols import WidgetProtocol
from src.gui.core.registry import (
    WidgetCategory,
    WidgetComplexity,
    WidgetMetadata,
    WidgetRegistry,
    WidgetRegistryEntry,
    WidgetRegistryStatistics,
)

# ==============================================================================
# MOCK WIDGETS (реализуют WidgetProtocol для тестов)
# ==============================================================================


class MockButton:
    """Mock кнопки для тестов."""

    metadata = WidgetMetadata(
        category=WidgetCategory.INPUT,
        complexity=WidgetComplexity.PRIMITIVE,
        version="1.0.0",
        author="FX Team",
        description="Базовая кнопка",
        supported_events={"click", "focus"},
        requires_mfa=False,
    )

    def __init__(self, widget_id: str) -> None:
        self.widget_id = widget_id
        self._mounted = False

    def mount(self, parent: Any) -> Any:
        self._mounted = True
        return MagicMock()

    def unmount(self) -> None:
        self._mounted = False

    def handle_event(self, event: Any) -> bool:
        return True

    def is_mounted(self) -> bool:
        return self._mounted


class MockSecureButton:
    """Mock защищённой кнопки требующей MFA."""

    metadata = WidgetMetadata(
        category=WidgetCategory.INPUT,
        complexity=WidgetComplexity.PRIMITIVE,
        version="1.0.0",
        author="Security Team",
        description="Кнопка требующая MFA",
        supported_events={"click"},
        requires_mfa=True,
    )

    def __init__(self, widget_id: str) -> None:
        self.widget_id = widget_id
        self._mounted = False

    def mount(self, parent: Any) -> Any:
        self._mounted = True
        return MagicMock()

    def unmount(self) -> None:
        self._mounted = False

    def handle_event(self, event: Any) -> bool:
        return True

    def is_mounted(self) -> bool:
        return self._mounted


class MockContainer:
    """Mock контейнера (COMPOUND сложность)."""

    metadata = WidgetMetadata(
        category=WidgetCategory.CONTAINER,
        complexity=WidgetComplexity.COMPOUND,
        version="2.0.0",
        author="FX Team",
        description="Контейнер для виджетов",
        supported_events={"add", "remove"},
        requires_mfa=False,
    )

    def __init__(self, widget_id: str) -> None:
        self.widget_id = widget_id
        self._mounted = False
        self._children: list[Any] = []

    def mount(self, parent: Any) -> Any:
        self._mounted = True
        return MagicMock()

    def unmount(self) -> None:
        self._mounted = False
        self._children.clear()

    def handle_event(self, event: Any) -> bool:
        return False

    def is_mounted(self) -> bool:
        return self._mounted


class MockDocumentView:
    """Mock сложного виджета документа (COMPOSITE)."""

    metadata = WidgetMetadata(
        category=WidgetCategory.DISPLAY,
        complexity=WidgetComplexity.COMPOSITE,
        version="3.0.0",
        author="FX Team",
        description="Просмотр документа",
        supported_events={"render", "scroll", "zoom"},
        requires_mfa=False,
        extra={"supports_escp": True},
    )

    def __init__(self, widget_id: str) -> None:
        self.widget_id = widget_id
        self._mounted = False

    def mount(self, parent: Any) -> Any:
        self._mounted = True
        return MagicMock()

    def unmount(self) -> None:
        self._mounted = False

    def handle_event(self, event: Any) -> bool:
        return True

    def is_mounted(self) -> bool:
        return self._mounted


class MockInvalidWidget:
    """Mock НЕ реализующий WidgetProtocol (для негативных тестов)."""

    metadata = WidgetMetadata(
        category=WidgetCategory.INPUT,
        complexity=WidgetComplexity.PRIMITIVE,
        version="1.0.0",
        author="Test",
        description="Невалидный виджет",
    )

    def __init__(self, widget_id: str) -> None:
        # Нет widget_id атрибута, mount(), unmount() и т.д.
        pass


# ==============================================================================
# FIXTURES
# ==============================================================================


@pytest.fixture(autouse=True)
def reset_registry() -> Generator[None, None, None]:
    """Автоматически сбрасывать singleton перед каждым тестом."""
    WidgetRegistry.reset_instance()
    yield
    WidgetRegistry.reset_instance()


@pytest.fixture
def registry() -> WidgetRegistry:
    """Fixture для получения свежего registry instance."""
    return WidgetRegistry.get_instance()


@pytest.fixture
def populated_registry(registry: WidgetRegistry) -> WidgetRegistry:
    """Fixture для registry с несколькими зарегистрированными виджетами."""
    registry.register(
        "button_primary",
        MockButton,
        MockButton.metadata,
    )
    registry.register(
        "secure_button",
        MockSecureButton,
        MockSecureButton.metadata,
    )
    registry.register(
        "container_frame",
        MockContainer,
        MockContainer.metadata,
    )
    registry.register(
        "document_view",
        MockDocumentView,
        MockDocumentView.metadata,
    )
    return registry


# ==============================================================================
# TEST: Singleton Pattern
# ==============================================================================


class TestSingletonPattern:
    """Тесты Singleton паттерна."""

    def test_get_instance_returns_same_instance(self) -> None:
        """get_instance() возвращает один и тот же экземпляр."""
        registry1 = WidgetRegistry.get_instance()
        registry2 = WidgetRegistry.get_instance()

        assert registry1 is registry2

    def test_direct_instantiation_raises_error(self) -> None:
        """Прямое создание экземпляра выбрасывает RuntimeError."""
        # Первый get_instance() для создания singleton
        _ = WidgetRegistry.get_instance()

        # Попытка создать напрямую
        with pytest.raises(RuntimeError, match="WidgetRegistry is a singleton"):
            WidgetRegistry()

    def test_reset_instance_clears_singleton(self) -> None:
        """reset_instance() сбрасывает singleton."""
        registry1 = WidgetRegistry.get_instance()
        WidgetRegistry.reset_instance()
        registry2 = WidgetRegistry.get_instance()

        assert registry1 is not registry2

    def test_reset_instance_clears_registry(self, registry: WidgetRegistry) -> None:
        """reset_instance() очищает реестр."""
        registry.register(
            "test_widget",
            MockButton,
            MockButton.metadata,
        )

        assert registry.is_registered("test_widget")

        WidgetRegistry.reset_instance()
        new_registry = WidgetRegistry.get_instance()

        assert not new_registry.is_registered("test_widget")


# ==============================================================================
# TEST: Thread Safety
# ==============================================================================


class TestThreadSafety:
    """Тесты потокобезопасности."""

    def test_concurrent_get_instance(self) -> None:
        """Параллельные вызовы get_instance() возвращают один экземпляр."""
        instances = []

        def get_and_store() -> None:
            instance = WidgetRegistry.get_instance()
            instances.append(id(instance))

        # 100 параллельных потоков
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(get_and_store) for _ in range(100)]
            for future in as_completed(futures):
                future.result()

        # Все должны получить один и тот же экземпляр
        assert len(set(instances)) == 1

    def test_concurrent_registration(self, registry: WidgetRegistry) -> None:
        """Параллельная регистрация разных виджетов thread-safe."""
        errors = []

        def register_widget(name: str, index: int) -> None:
            try:
                # Каждый поток регистрирует свой уникальный виджет
                metadata = WidgetMetadata(
                    category=WidgetCategory.INPUT,
                    complexity=WidgetComplexity.PRIMITIVE,
                    version="1.0.0",
                    author="Test",
                    description=f"Test widget {index}",
                )
                registry.register(f"test_widget_{index}", MockButton, metadata)
            except Exception as e:
                errors.append(e)

        # 50 параллельных регистраций
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(register_widget, f"widget_{i}", i) for i in range(50)]
            for future in as_completed(futures):
                future.result()

        # Не должно быть ошибок
        assert len(errors) == 0
        # Все виджеты зарегистрированы
        assert len(registry.list_widgets()) == 50

    def test_concurrent_create(self, populated_registry: WidgetRegistry) -> None:
        """Параллельное создание экземпляров thread-safe."""
        instances = []
        errors = []

        def create_and_store() -> None:
            try:
                instance = populated_registry.create("button_primary", widget_id="btn")
                instances.append(instance)
            except Exception as e:
                errors.append(e)

        # 100 параллельных создаёт
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(create_and_store) for _ in range(100)]
            for future in as_completed(futures):
                future.result()

        # Не должно быть ошибок
        assert len(errors) == 0
        # Создано 100 экземпляров (каждый новый)
        assert len(instances) == 100
        # Все являются MockButton
        assert all(isinstance(inst, MockButton) for inst in instances)


# ==============================================================================
# TEST: Enums
# ==============================================================================


class TestWidgetCategory:
    """Тесты WidgetCategory enum."""

    def test_enum_values(self) -> None:
        """WidgetCategory имеет ожидаемые значения."""
        assert WidgetCategory.CONTAINER.value == "container"
        assert WidgetCategory.INPUT.value == "input"
        assert WidgetCategory.DISPLAY.value == "display"
        assert WidgetCategory.DIALOG.value == "dialog"
        assert WidgetCategory.MENU.value == "menu"
        assert WidgetCategory.TOOLBAR.value == "toolbar"
        assert WidgetCategory.CUSTOM.value == "custom"

    def test_label_method(self) -> None:
        """label() возвращает локализованные русские названия."""
        assert WidgetCategory.CONTAINER.label() == "Контейнер"
        assert WidgetCategory.INPUT.label() == "Ввод"
        assert WidgetCategory.DISPLAY.label() == "Отображение"
        assert WidgetCategory.DIALOG.label() == "Диалог"
        assert WidgetCategory.MENU.label() == "Меню"
        assert WidgetCategory.TOOLBAR.label() == "Панель инструментов"
        assert WidgetCategory.CUSTOM.label() == "Пользовательский"

    def test_from_str_valid(self) -> None:
        """from_str() парсит валидные значения (case-insensitive)."""
        assert WidgetCategory.from_str("container") == WidgetCategory.CONTAINER
        assert WidgetCategory.from_str("CONTAINER") == WidgetCategory.CONTAINER
        assert WidgetCategory.from_str("Input") == WidgetCategory.INPUT
        assert WidgetCategory.from_str("DISPLAY") == WidgetCategory.DISPLAY

    def test_from_str_invalid(self) -> None:
        """from_str() выбрасывает ValueError для невалидных значений."""
        with pytest.raises(ValueError, match="Unknown widget category"):
            WidgetCategory.from_str("invalid")


class TestWidgetComplexity:
    """Тесты WidgetComplexity enum."""

    def test_enum_values(self) -> None:
        """WidgetComplexity имеет ожидаемые значения."""
        assert WidgetComplexity.PRIMITIVE.value == "primitive"
        assert WidgetComplexity.COMPOUND.value == "compound"
        assert WidgetComplexity.COMPOSITE.value == "composite"

    def test_label_method(self) -> None:
        """label() возвращает локализованные русские названия."""
        assert WidgetComplexity.PRIMITIVE.label() == "Примитивный"
        assert WidgetComplexity.COMPOUND.label() == "Составной"
        assert WidgetComplexity.COMPOSITE.label() == "Композитный"

    def test_from_str_valid(self) -> None:
        """from_str() парсит валидные значения (case-insensitive)."""
        assert WidgetComplexity.from_str("primitive") == WidgetComplexity.PRIMITIVE
        assert WidgetComplexity.from_str("PRIMITIVE") == WidgetComplexity.PRIMITIVE
        assert WidgetComplexity.from_str("Compound") == WidgetComplexity.COMPOUND

    def test_from_str_invalid(self) -> None:
        """from_str() выбрасывает ValueError для невалидных значений."""
        with pytest.raises(ValueError, match="Unknown complexity level"):
            WidgetComplexity.from_str("invalid")


# ==============================================================================
# TEST: WidgetMetadata
# ==============================================================================


class TestWidgetMetadata:
    """Тесты WidgetMetadata."""

    def test_is_frozen(self) -> None:
        """WidgetMetadata является frozen dataclass."""
        metadata = WidgetMetadata(
            category=WidgetCategory.INPUT,
            complexity=WidgetComplexity.PRIMITIVE,
            version="1.0.0",
            author="Test",
            description="Test widget",
        )

        with pytest.raises(AttributeError):
            metadata.version = "2.0.0"  # type: ignore

    def test_validation_empty_version(self) -> None:
        """Валидация: version не может быть пустым."""
        with pytest.raises(ValueError, match="version cannot be empty"):
            WidgetMetadata(
                category=WidgetCategory.INPUT,
                complexity=WidgetComplexity.PRIMITIVE,
                version="",
                author="Test",
                description="Test",
            )

    def test_validation_empty_author(self) -> None:
        """Валидация: author не может быть пустым."""
        with pytest.raises(ValueError, match="author cannot be empty"):
            WidgetMetadata(
                category=WidgetCategory.INPUT,
                complexity=WidgetComplexity.PRIMITIVE,
                version="1.0.0",
                author="",
                description="Test",
            )

    def test_validation_empty_description(self) -> None:
        """Валидация: description не может быть пустым."""
        with pytest.raises(ValueError, match="description cannot be empty"):
            WidgetMetadata(
                category=WidgetCategory.INPUT,
                complexity=WidgetComplexity.PRIMITIVE,
                version="1.0.0",
                author="Test",
                description="",
            )

    def test_validation_supported_events_type(self) -> None:
        """Валидация: supported_events должен быть Set[str]."""
        with pytest.raises(TypeError, match="supported_events must be Set"):
            WidgetMetadata(
                category=WidgetCategory.INPUT,
                complexity=WidgetComplexity.PRIMITIVE,
                version="1.0.0",
                author="Test",
                description="Test",
                supported_events=["click"],  # type: ignore
            )

    def test_validation_empty_event_name(self) -> None:
        """Валидация: имена событий не могут быть пустыми."""
        with pytest.raises(ValueError, match="Event name cannot be empty"):
            WidgetMetadata(
                category=WidgetCategory.INPUT,
                complexity=WidgetComplexity.PRIMITIVE,
                version="1.0.0",
                author="Test",
                description="Test",
                supported_events={"click", ""},
            )

    def test_to_dict(self) -> None:
        """to_dict() сериализует метаданные."""
        metadata = WidgetMetadata(
            category=WidgetCategory.INPUT,
            complexity=WidgetComplexity.PRIMITIVE,
            version="1.0.0",
            author="Test",
            description="Test widget",
            supported_events={"click", "focus"},
            requires_mfa=True,
            extra={"key": "value"},
        )

        data = metadata.to_dict()

        assert isinstance(data, dict)
        assert data["category"] == "input"
        assert data["complexity"] == "primitive"
        assert data["version"] == "1.0.0"
        assert data["author"] == "Test"
        assert data["description"] == "Test widget"
        assert set(data["supported_events"]) == {"click", "focus"}
        assert data["requires_mfa"] is True
        assert data["extra"] == {"key": "value"}

    def test_from_dict(self) -> None:
        """from_dict() десериализует метаданные."""
        data = {
            "category": "input",
            "complexity": "primitive",
            "version": "1.0.0",
            "author": "Test",
            "description": "Test widget",
            "supported_events": ["click", "focus"],
            "requires_mfa": True,
            "extra": {"key": "value"},
        }

        metadata = WidgetMetadata.from_dict(data)

        assert metadata.category == WidgetCategory.INPUT
        assert metadata.complexity == WidgetComplexity.PRIMITIVE
        assert metadata.version == "1.0.0"
        assert metadata.author == "Test"
        assert metadata.description == "Test widget"
        assert metadata.supported_events == {"click", "focus"}
        assert metadata.requires_mfa is True
        assert metadata.extra == {"key": "value"}

    def test_from_dict_does_not_modify_original(self) -> None:
        """from_dict() не модифицирует оригинальный словарь."""
        data = {
            "category": "input",
            "complexity": "primitive",
            "version": "1.0.0",
            "author": "Test",
            "description": "Test widget",
            "supported_events": [],
        }
        original_category = data["category"]

        _ = WidgetMetadata.from_dict(data)

        assert data["category"] == original_category


# ==============================================================================
# TEST: Widget Registration
# ==============================================================================


class TestWidgetRegistration:
    """Тесты регистрации виджетов."""

    def test_register_valid_widget(self, registry: WidgetRegistry) -> None:
        """Регистрация валидного виджета."""
        registry.register(
            "button_primary",
            MockButton,
            MockButton.metadata,
        )

        assert registry.is_registered("button_primary")

    def test_register_duplicate_raises_error(self, registry: WidgetRegistry) -> None:
        """Повторная регистрация того же имени выбрасывает WidgetRegistryError."""
        registry.register(
            "test_widget",
            MockButton,
            MockButton.metadata,
        )

        with pytest.raises(WidgetRegistryError, match="already registered"):
            registry.register(
                "test_widget",
                MockContainer,
                MockContainer.metadata,
            )

    def test_register_empty_name_raises_error(self, registry: WidgetRegistry) -> None:
        """Пустое имя выбрасывает WidgetRegistryError."""
        with pytest.raises(WidgetRegistryError, match="cannot be empty"):
            registry.register(
                "",
                MockButton,
                MockButton.metadata,
            )

    def test_register_whitespace_name_raises_error(self, registry: WidgetRegistry) -> None:
        """Имя из whitespace выбрасывает WidgetRegistryError."""
        with pytest.raises(WidgetRegistryError, match="cannot be empty"):
            registry.register(
                "   ",
                MockButton,
                MockButton.metadata,
            )

    def test_register_non_callable_factory_raises_error(self, registry: WidgetRegistry) -> None:
        """Не-callable factory выбрасывает TypeError."""
        with pytest.raises(TypeError, match="factory must be callable"):
            registry.register(
                "test",
                "not_callable",  # type: ignore
                MockButton.metadata,
            )

    def test_register_invalid_metadata_raises_error(self, registry: WidgetRegistry) -> None:
        """Некорректные metadata выбрасывают TypeError."""
        with pytest.raises(TypeError, match="metadata must be WidgetMetadata"):
            registry.register(
                "test",
                MockButton,
                {"invalid": "metadata"},  # type: ignore
            )

    def test_register_without_validation(self, registry: WidgetRegistry) -> None:
        """Регистрация с validate=False пропускает проверку Protocol."""
        # MockInvalidWidget НЕ реализует WidgetProtocol
        # Но с validate=False это должно пройти
        registry.register(
            "invalid_widget",
            MockInvalidWidget,
            WidgetMetadata(
                category=WidgetCategory.INPUT,
                complexity=WidgetComplexity.PRIMITIVE,
                version="1.0.0",
                author="Test",
                description="Invalid widget",
            ),
            validate=False,
        )

        assert registry.is_registered("invalid_widget")


# ==============================================================================
# TEST: Protocol Validation
# ==============================================================================


class TestProtocolValidation:
    """Тесты валидации Protocol."""

    def test_validate_widget_protocol(self, registry: WidgetRegistry) -> None:
        """MockButton проходит валидацию WidgetProtocol."""
        # Не должно быть исключений
        registry.register(
            "valid_button",
            MockButton,
            MockButton.metadata,
            validate=True,
        )

        instance = registry.create("valid_button", widget_id="btn")
        assert isinstance(instance, WidgetProtocol)

    def test_validate_protocol_failure(self, registry: WidgetRegistry) -> None:
        """Класс без WidgetProtocol методов НЕ проходит валидацию."""
        with pytest.raises(ProtocolValidationError, match="does not implement"):
            registry.register(
                "invalid",
                MockInvalidWidget,
                WidgetMetadata(
                    category=WidgetCategory.INPUT,
                    complexity=WidgetComplexity.PRIMITIVE,
                    version="1.0.0",
                    author="Test",
                    description="Invalid",
                ),
                validate=True,
            )


# ==============================================================================
# TEST: Instance Creation
# ==============================================================================


class TestInstanceCreation:
    """Тесты создания экземпляров."""

    def test_create_existing_widget(self, populated_registry: WidgetRegistry) -> None:
        """Создание экземпляра зарегистрированного виджета."""
        button = populated_registry.create("button_primary", widget_id="btn_01")

        assert isinstance(button, MockButton)
        assert button.widget_id == "btn_01"

    def test_create_returns_new_instances(self, populated_registry: WidgetRegistry) -> None:
        """create() возвращает новые экземпляры (не singleton)."""
        button1 = populated_registry.create("button_primary", widget_id="btn_1")
        button2 = populated_registry.create("button_primary", widget_id="btn_2")

        assert button1 is not button2
        assert button1.widget_id == "btn_1"
        assert button2.widget_id == "btn_2"

    def test_create_nonexistent_widget_raises_error(self, registry: WidgetRegistry) -> None:
        """Создание несуществующего виджета выбрасывает WidgetNotFoundError."""
        with pytest.raises(WidgetNotFoundError, match="not found in registry"):
            registry.create("nonexistent_widget")

    def test_create_with_factory_error(self, registry: WidgetRegistry) -> None:
        """Ошибка в factory приводит к WidgetCreationError."""

        def failing_factory(widget_id: str) -> Any:
            raise ValueError("Factory failed!")

        metadata = WidgetMetadata(
            category=WidgetCategory.INPUT,
            complexity=WidgetComplexity.PRIMITIVE,
            version="1.0.0",
            author="Test",
            description="Failing widget",
        )

        registry.register("failing_widget", failing_factory, metadata, validate=False)

        with pytest.raises(WidgetCreationError, match="Failed to create"):
            registry.create("failing_widget", widget_id="test")


# ==============================================================================
# TEST: Metadata Access
# ==============================================================================


class TestMetadataAccess:
    """Тесты доступа к метаданным."""

    def test_get_metadata_existing_widget(self, populated_registry: WidgetRegistry) -> None:
        """Получение метаданных зарегистрированного виджета."""
        metadata = populated_registry.get_metadata("button_primary")

        assert metadata.category == WidgetCategory.INPUT
        assert metadata.complexity == WidgetComplexity.PRIMITIVE
        assert metadata.version == "1.0.0"

    def test_get_metadata_nonexistent_raises_error(self, registry: WidgetRegistry) -> None:
        """Получение метаданных несуществующего виджета выбрасывает WidgetNotFoundError."""
        with pytest.raises(WidgetNotFoundError, match="not found in registry"):
            registry.get_metadata("nonexistent")


# ==============================================================================
# TEST: Query API
# ==============================================================================


class TestQueryAPI:
    """Тесты Query API."""

    def test_list_widgets(self, populated_registry: WidgetRegistry) -> None:
        """list_widgets() возвращает все метаданные (sorted)."""
        metas = populated_registry.list_widgets()

        assert len(metas) == 4
        # Сортировка по category, затем complexity
        categories = [m.category for m in metas]
        assert categories == sorted(categories)

    def test_list_by_category_container(self, populated_registry: WidgetRegistry) -> None:
        """list_by_category() для контейнеров."""
        containers = populated_registry.list_by_category(WidgetCategory.CONTAINER)

        assert len(containers) == 1
        assert "container_frame" in containers

    def test_list_by_category_input(self, populated_registry: WidgetRegistry) -> None:
        """list_by_category() для input виджетов."""
        inputs = populated_registry.list_by_category(WidgetCategory.INPUT)

        assert len(inputs) == 2
        assert "button_primary" in inputs
        assert "secure_button" in inputs

    def test_list_by_category_empty(self, populated_registry: WidgetRegistry) -> None:
        """list_by_category() возвращает [] для пустой категории."""
        customs = populated_registry.list_by_category(WidgetCategory.CUSTOM)

        assert customs == []

    def test_list_by_complexity_primitive(self, populated_registry: WidgetRegistry) -> None:
        """list_by_complexity() для PRIMITIVE."""
        primitives = populated_registry.list_by_complexity(WidgetComplexity.PRIMITIVE)

        assert len(primitives) == 2
        assert "button_primary" in primitives
        assert "secure_button" in primitives

    def test_list_by_complexity_compound(self, populated_registry: WidgetRegistry) -> None:
        """list_by_complexity() для COMPOUND."""
        compounds = populated_registry.list_by_complexity(WidgetComplexity.COMPOUND)

        assert len(compounds) == 1
        assert "container_frame" in compounds

    def test_list_by_complexity_composite(self, populated_registry: WidgetRegistry) -> None:
        """list_by_complexity() для COMPOSITE."""
        composites = populated_registry.list_by_complexity(WidgetComplexity.COMPOSITE)

        assert len(composites) == 1
        assert "document_view" in composites

    def test_list_requires_mfa(self, populated_registry: WidgetRegistry) -> None:
        """list_requires_mfa() возвращает виджеты с MFA."""
        mfa_widgets = populated_registry.list_requires_mfa()

        assert len(mfa_widgets) == 1
        assert "secure_button" in mfa_widgets

    def test_search_single_filter(self, populated_registry: WidgetRegistry) -> None:
        """search() с одним фильтром."""
        results = populated_registry.search(category=WidgetCategory.INPUT)

        assert len(results) == 2
        assert "button_primary" in results
        assert "secure_button" in results

    def test_search_multiple_filters(self, populated_registry: WidgetRegistry) -> None:
        """search() с множественными фильтрами (AND логика)."""
        results = populated_registry.search(
            category=WidgetCategory.INPUT,
            complexity=WidgetComplexity.PRIMITIVE,
        )

        assert len(results) == 2
        assert "button_primary" in results
        assert "secure_button" in results

    def test_search_no_results(self, populated_registry: WidgetRegistry) -> None:
        """search() без результатов возвращает пустой список."""
        results = populated_registry.search(
            category=WidgetCategory.CUSTOM  # Нет таких в populated
        )

        assert len(results) == 0

    def test_search_requires_mfa_filter(self, populated_registry: WidgetRegistry) -> None:
        """search() с фильтром requires_mfa."""
        mfa = populated_registry.search(requires_mfa=True)

        assert len(mfa) == 1
        assert "secure_button" in mfa

        no_mfa = populated_registry.search(requires_mfa=False)

        assert len(no_mfa) == 3
        assert "button_primary" in no_mfa


# ==============================================================================
# TEST: Statistics
# ==============================================================================


class TestStatistics:
    """Тесты статистики."""

    def test_get_statistics_empty_registry(self, registry: WidgetRegistry) -> None:
        """Статистика пустого реестра."""
        stats = registry.get_statistics()

        assert stats.total == 0
        assert len(stats.by_category) == 0
        assert len(stats.by_complexity) == 0
        assert stats.requires_mfa_count == 0

    def test_get_statistics_populated(self, populated_registry: WidgetRegistry) -> None:
        """Статистика заполненного реестра."""
        stats = populated_registry.get_statistics()

        assert stats.total == 4
        assert stats.by_category[WidgetCategory.INPUT] == 2
        assert stats.by_category[WidgetCategory.CONTAINER] == 1
        assert stats.by_category[WidgetCategory.DISPLAY] == 1
        assert stats.by_complexity[WidgetComplexity.PRIMITIVE] == 2
        assert stats.by_complexity[WidgetComplexity.COMPOUND] == 1
        assert stats.by_complexity[WidgetComplexity.COMPOSITE] == 1
        assert stats.requires_mfa_count == 1

    def test_statistics_to_dict(self, populated_registry: WidgetRegistry) -> None:
        """Сериализация статистики в словарь."""
        stats = populated_registry.get_statistics()
        data = stats.to_dict()

        assert isinstance(data, dict)
        assert data["total"] == 4
        assert "input" in data["by_category"]
        assert "primitive" in data["by_complexity"]
        assert data["requires_mfa_count"] == 1


# ==============================================================================
# TEST: Unregister
# ==============================================================================


class TestUnregister:
    """Тесты удаления виджетов."""

    def test_unregister_existing_widget(self, populated_registry: WidgetRegistry) -> None:
        """Удаление зарегистрированного виджета."""
        assert populated_registry.is_registered("button_primary")

        populated_registry.unregister("button_primary")

        assert not populated_registry.is_registered("button_primary")

    def test_unregister_nonexistent_raises_error(self, registry: WidgetRegistry) -> None:
        """Удаление несуществующего виджета выбрасывает WidgetNotFoundError."""
        with pytest.raises(WidgetNotFoundError, match="not found in registry"):
            registry.unregister("nonexistent")


# ==============================================================================
# TEST: Dataclasses
# ==============================================================================


class TestDataclasses:
    """Тесты dataclass'ов."""

    def test_widget_registry_entry_immutable(self) -> None:
        """WidgetRegistryEntry immutable (frozen)."""
        entry = WidgetRegistryEntry(
            widget_type="test",
            factory=MockButton,
            metadata=MockButton.metadata,
        )

        with pytest.raises(AttributeError):
            entry.widget_type = "changed"  # type: ignore

    def test_widget_registry_statistics_immutable(self) -> None:
        """WidgetRegistryStatistics immutable (frozen)."""
        stats = WidgetRegistryStatistics(
            total=10,
            by_category={WidgetCategory.INPUT: 5},
            by_complexity={WidgetComplexity.PRIMITIVE: 5},
            requires_mfa_count=0,
        )

        with pytest.raises(AttributeError):
            stats.total = 20  # type: ignore


# ==============================================================================
# TEST: Edge Cases
# ==============================================================================


class TestEdgeCases:
    """Тесты граничных случаев."""

    def test_is_registered_empty_registry(self, registry: WidgetRegistry) -> None:
        """is_registered() в пустом реестре."""
        assert not registry.is_registered("any_widget")

    def test_list_widgets_empty_registry(self, registry: WidgetRegistry) -> None:
        """list_widgets() в пустом реестре."""
        assert registry.list_widgets() == []

    def test_search_empty_registry_returns_empty(self, registry: WidgetRegistry) -> None:
        """search() в пустом реестре возвращает []."""
        results = registry.search(category=WidgetCategory.INPUT)
        assert results == []

    def test_register_widget_with_spaces_in_name(self, registry: WidgetRegistry) -> None:
        """Регистрация виджета с пробелами в имени (trim)."""
        # Пробелы должны быть убраны при регистрации
        registry.register(
            "  test_widget  ",
            MockButton,
            MockButton.metadata,
        )

        # Имя должно быть обрезано
        assert registry.is_registered("test_widget")


# ==============================================================================
# TEST: Module Exports
# ==============================================================================


class TestModuleExports:
    """Тесты exports модуля."""

    def test_all_exports_defined(self) -> None:
        """Все exports определены в __all__."""
        from src.gui.core import registry

        assert hasattr(registry, "__all__")
        assert "WidgetCategory" in registry.__all__
        assert "WidgetComplexity" in registry.__all__
        assert "WidgetMetadata" in registry.__all__
        assert "WidgetRegistryEntry" in registry.__all__
        assert "WidgetRegistryStatistics" in registry.__all__
        assert "WidgetRegistry" in registry.__all__

    def test_module_version_metadata(self) -> None:
        """Модуль имеет метаданные версии."""
        from src.gui.core import registry

        assert hasattr(registry, "__version__")
        assert hasattr(registry, "__author__")
        assert hasattr(registry, "__date__")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=src.gui.core.registry"])
