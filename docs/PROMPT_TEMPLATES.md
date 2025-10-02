# AI Prompt Templates для ESC/P Text Editor

Этот документ содержит готовые шаблоны промптов для AI-assisted разработки.

## 📋 Оглавление

1. [Генерация модуля](#template-1-генерация-модуля)
2. [Code Review](#template-2-code-review)
3. [Исправление бага](#template-3-исправление-бага)
4. [Реализация фичи](#template-4-реализация-фичи)
5. [Рефакторинг](#template-5-рефакторинг)
6. [Генерация тестов](#template-6-генерация-тестов)

---

## Template 1: Генерация модуля

КОНТЕКСТ
Проект: https://github.com/Mike-voyager/FX-Text-processor-3
Архитектура: docs/ARCHITECTURE.md
Пример стиля кода: src/init.py
Пример тестов: tests/unit/test_init.py

ЗАДАЧА
Сгенерировать модуль: src/model/[MODULE_NAME].py

ТРЕБОВАНИЯ
Функциональные
[Описать что должен делать модуль]

[Перечислить классы/функции]

[Указать интерфейсы взаимодействия]

Нефункциональные
Python 3.11+ с type hints

Google-style docstrings на русском

Mypy strict compliance

Нет внешних зависимостей в model layer

Unit tests с 100% coverage

АРХИТЕКТУРНЫЕ ОГРАНИЧЕНИЯ
Следовать MVC паттерну

Model не зависит от View/Controller

Использовать dataclasses где возможно

Immutable объекты где возможно

ПРИМЕРЫ ИСПОЛЬЗОВАНИЯ
python
# Пример как будет использоваться модуль
from src.model.[MODULE_NAME] import ClassName

obj = ClassName(param1="value", param2=42)
result = obj.method()
assert result == expected_value
DELIVERABLES
src/model/[MODULE_NAME].py - полная реализация

tests/unit/model/test_[MODULE_NAME].py - unit тесты

Краткие implementation notes (200-300 слов)

VALIDATION
 Код проходит mypy --strict

 Тесты проходят pytest

 Coverage >= 100%

 Black/isort formatted

text

**Использование:**
1. Скопировать шаблон
2. Заменить `[MODULE_NAME]` на имя модуля
3. Заполнить функциональные требования
4. Вставить в Claude/ChatGPT

---

## Template 2: Code Review

КОНТЕКСТ
Проект: https://github.com/Mike-voyager/FX-Text-processor-3
Pull Request: [URL]

ЗАДАЧА
Провести code review изменений в этом PR

ПРОВЕРИТЬ
Качество кода
 Type safety (mypy strict passes)

 Test coverage (>90%)

 Documentation (Google-style docstrings)

 Code style (black, isort, flake8)

 No code smells

Архитектура
 Соответствие MVC pattern

 Нет циклических зависимостей

 Правильное использование слоёв

 DRY принцип соблюдён

Функциональность
 Логика корректна

 Edge cases обработаны

 Error handling присутствует

 Производительность адекватна

Безопасность
 Input validation

 No hardcoded secrets

 Safe file operations

ФОРМАТ ОТВЕТА
Предоставить структурированное ревью:

Summary:
[Общая оценка изменений]

Issues Found:

🔴 CRITICAL: [описание]

🟠 MAJOR: [описание]

🟡 MINOR: [описание]

Suggestions:

[предложение по улучшению]

Approval Status:
✅ APPROVE / ⚠️ APPROVE WITH COMMENTS / ❌ REQUEST CHANGES

text

---

## Template 3: Исправление бага

КОНТЕКСТ
Проект: https://github.com/Mike-voyager/FX-Text-processor-3
Issue: [ISSUE_URL]

ОПИСАНИЕ БАГА
text
[Вставить traceback или описание бага]
STEPS TO REPRODUCE
[Шаг 1]

[Шаг 2]

[Шаг 3]

EXPECTED BEHAVIOR
[Что должно происходить]

ACTUAL BEHAVIOR
[Что происходит на самом деле]

ЗАДАЧА
Исправить баг, сохранив:

Существующий функционал

Test coverage

Type safety

Code style

DELIVERABLES
Bug fix implementation

Regression test

Объяснение root cause

Prevention recommendations

VALIDATION
 Баг исправлен

 Все тесты проходят

 Добавлен regression test

 Mypy strict passes

text

---

## Template 4: Реализация фичи

КОНТЕКСТ
Проект: https://github.com/Mike-voyager/FX-Text-processor-3
Architecture: docs/ARCHITECTURE.md
Feature Request: [ISSUE_URL]

ОПИСАНИЕ ФИЧИ
[Детальное описание новой функциональности]

ACCEPTANCE CRITERIA
 Критерий 1

 Критерий 2

 Критерий 3

 Unit tests реализованы

 Documentation обновлена

USER STORIES
As a [тип пользователя]
I want [действие]
So that [цель]

ТЕХНИЧЕСКИЙ ПОДХОД
[Опционально: предложить стратегию реализации]

DELIVERABLES
Implementation code

Unit tests

Integration tests (если нужны)

Documentation updates

Example usage

VALIDATION
 Все acceptance criteria выполнены

 Тесты проходят

 Type checking passes

 Performance приемлема

text

---

## Template 5: Рефакторинг

КОНТЕКСТ
Проект: https://github.com/Mike-voyager/FX-Text-processor-3
Target Module: [module_path]

ПРОБЛЕМА
[Описать что не так с текущим кодом]

ЦЕЛЬ РЕФАКТОРИНГА
[Что хотим улучшить]

CONSTRAINTS
 Не ломать существующий API

 Сохранить test coverage

 Улучшить или сохранить производительность

 Улучшить читаемость

ПРЕДЛАГАЕМЫЙ ПОДХОД
[Опционально: как рефакторить]

DELIVERABLES
Refactored code

Updated tests

Migration guide (если API изменился)

Performance comparison (если релевантно)

VALIDATION
 Все тесты проходят

 Coverage не упал

 Type checking passes

 Code более читаемый

text

---

## Template 6: Генерация тестов

КОНТЕКСТ
Проект: https://github.com/Mike-voyager/FX-Text-processor-3
Target Module: src/[module_path].py

ЗАДАЧА
Сгенерировать comprehensive unit tests для модуля

ТРЕБОВАНИЯ К ТЕСТАМ
Coverage
 Все public функции/методы

 Все классы

 Все edge cases

 Error handling

 Target: 100% coverage

Структура тестов
python
class TestClassName:
    """Тесты для ClassName."""

    def test_basic_functionality(self) -> None:
        """Тест базовой функциональности."""
        # Arrange
        obj = ClassName(param=value)

        # Act
        result = obj.method()

        # Assert
        assert result == expected
Edge Cases
 Пустые входные данные

 Граничные значения

 Invalid inputs

 None values

 Большие объёмы данных

DELIVERABLES
Complete test file tests/unit/[module_path]/test_[module_name].py

Test coverage report

Список протестированных edge cases

VALIDATION
 Все тесты проходят

 Coverage >= 100%

 Pytest runs without warnings

text

---

## 🎯 Использование шаблонов

### Для Claude/ChatGPT:

1. **Скопировать нужный шаблон**
2. **Заменить placeholders** ([MODULE_NAME], [ISSUE_URL] и т.д.)
3. **Заполнить секции** (Описание, Требования и т.д.)
4. **Вставить в AI** и получить результат
5. **Проверить результат** (mypy, pytest)
6. **Применить изменения**

### Для Continue.dev/Cursor:

1. **Открыть файл** для работы
2. **Скопировать компактную версию** шаблона
3. **Нажать Ctrl+L** (Continue) или **Ctrl+K** (Cursor)
4. **Вставить промпт**
5. **Применить changes**

---

## 💡 Примеры успешного использования

### Пример 1: Генерация enums.py

КОНТЕКСТ
Проект: https://github.com/Mike-voyager/FX-Text-processor-3
Architecture: docs/ARCHITECTURE.md

ЗАДАЧА
Сгенерировать модуль: src/model/enums.py

ТРЕБОВАНИЯ
Реализовать enum классы:

Alignment (LEFT, RIGHT, CENTER, JUSTIFY)

FontFamily (DRAFT, ROMAN, SANS, COURIER)

PrintQuality (HIGH, DRAFT)

PaperType (A4, LETTER, LEGAL, ENVELOPE)

Каждый enum должен иметь:

Метод label() для человекочитаемого названия

Метод from_str(s: str) для парсинга из строки

Google-style docstrings на русском

[... остальное из Template 1]

text

**Результат:** Полный модуль за 2 минуты, 100% coverage, mypy strict pass.

---

## 🔗 Связанные документы

- [ARCHITECTURE.md](ARCHITECTURE.md) - Архитектура проекта
- [DEVELOPMENT.md](DEVELOPMENT.md) - Руководство разработчика
- [API_REFERENCE.md](API_REFERENCE.md) - API документация

---

**Последнее обновление:** October 2025
**Версия:** 1.0
docs/DEVELOPMENT.md
text
# Руководство разработчика

## 🚀 Быстрый старт

### 1. Установка окружения

Установить Python 3.11+
winget install Python.Python.3.11

Установить Git
winget install Git.Git

Клонировать репозиторий
git clone https://github.com/Mike-voyager/FX-Text-processor-3.git
cd FX-Text-processor-3

Создать виртуальное окружение
python -m venv .venv
.venv\Scripts\activate

Установить зависимости
pip install -e ".[dev]"

text

### 2. Настройка IDE (VS Code)

**Рекомендуемые расширения:**
- Python (Microsoft)
- Pylance
- Python Test Explorer
- autoDocstring
- GitHub Copilot (опционально)
- Continue (опционально для AI)

**Настройки (`.vscode/settings.json`):**
{
"python.defaultInterpreterPath": ".venv\Scripts\python.exe",
"python.analysis.typeCheckingMode": "strict",
"python.formatting.provider": "black",
"python.linting.enabled": true,
"python.linting.mypyEnabled": true,
"python.linting.flake8Enabled": true,
"python.testing.pytestEnabled": true,
"python.testing.unittestEnabled": false,
"editor.formatOnSave": true,
"editor.rulers": ,
"[python]": {
"editor.codeActionsOnSave": {
"source.organizeImports": true
}
}
}

text

---

## 📝 Workflow разработки

### Создание новой фичи

#### 1. Создать ветку
git checkout -b feature/module-name

text

#### 2. Написать тесты (TDD подход)

tests/unit/model/test_new_module.py
import pytest
from src.model.new_module import NewClass

class TestNewClass:
"""Тесты для NewClass."""

text
def test_basic_functionality(self) -> None:
    """Тест базовой функциональности."""
    # Arrange
    obj = NewClass(param="value")

    # Act
    result = obj.method()

    # Assert
    assert result == "expected"
text

#### 3. Реализовать модуль

src/model/new_module.py
"""
Модуль для [описание].

Этот модуль предоставляет [функциональность].
"""

from typing import Optional

class NewClass:
"""Класс для [назначение]."""

text
def __init__(self, param: str) -> None:
    """
    Инициализация NewClass.

    Args:
        param: Описание параметра

    Example:
        >>> obj = NewClass("test")
        >>> obj.param
        'test'
    """
    self.param = param

def method(self) -> str:
    """
    Метод для [действие].

    Returns:
        Результат операции

    Raises:
        ValueError: Если param пустой
    """
    if not self.param:
        raise ValueError("param не может быть пустым")
    return f"processed: {self.param}"
text

#### 4. Запустить тесты

Один модуль
pytest tests/unit/model/test_new_module.py -v

С coverage
pytest tests/unit/model/test_new_module.py --cov=src.model.new_module

Должно быть 100% coverage
text

#### 5. Type checking

mypy --strict src/model/new_module.py

text

#### 6. Форматирование

black src/model/new_module.py tests/unit/model/test_new_module.py
isort src/model/new_module.py tests/unit/model/test_new_module.py
flake8 src/model/new_module.py tests/unit/model/test_new_module.py

text

#### 7. Коммит

git add src/model/new_module.py tests/unit/model/test_new_module.py
git commit -m "feat(model): Add NewClass for [функциональность]"

text

**Формат commit messages:**
- `feat:` новая функциональность
- `fix:` исправление бага
- `docs:` документация
- `test:` тесты
- `refactor:` рефакторинг
- `style:` форматирование
- `chore:` рутинные задачи

#### 8. Push и PR

git push origin feature/module-name

Создать PR
gh pr create --title "Add NewClass" --body "Implements #ISSUE_NUMBER"

text

---

## 🧪 Тестирование

### Типы тестов

#### Unit Tests (`tests/unit/`)
- Тестируют **один модуль** изолированно
- Используют моки для зависимостей
- Быстрые (< 1ms на тест)
- Цель: **100% coverage**

def test_document_add_section(mocker) -> None:
"""Тест добавления секции в документ."""
# Arrange
doc = Document()
section = mocker.Mock(spec=Section)

text
# Act
doc.add_section(section)

# Assert
assert len(doc.sections) == 1
assert doc.sections is section
text

#### Integration Tests (`tests/integration/`)
- Тестируют **взаимодействие модулей**
- Используют реальные зависимости
- Медленнее (< 100ms на тест)
- Цель: критические пути

def test_document_to_escp_workflow() -> None:
"""Тест полного процесса Document → ESC/P."""
# Arrange
doc = Document()
section = Section()
paragraph = Paragraph(alignment=Alignment.LEFT)
paragraph.add_run(Run(text="Hello", bold=True))
section.add_paragraph(paragraph)
doc.add_section(section)

text
builder = EscpCommandBuilder()

# Act
commands = builder.build_from_document(doc)

# Assert
assert b'\x1b\x45' in commands  # Bold ON
assert b'Hello' in commands
assert b'\x1b\x46' in commands  # Bold OFF
text

### Запуск тестов

Все тесты
pytest

Только unit
pytest tests/unit/ -v

С coverage
pytest --cov=src --cov-report=html

Открыть HTML отчёт
start htmlcov/index.html

Watch mode (автоперезапуск)
pytest-watch

Только failed тесты
pytest --lf

Параллельно (быстрее)
pytest -n auto

text

### Fixtures

tests/conftest.py
import pytest
from src.model.document import Document

@pytest.fixture
def empty_document() -> Document:
"""Пустой документ."""
return Document()

@pytest.fixture
def sample_document() -> Document:
"""Документ с примером контента."""
doc = Document()
section = Section()
paragraph = Paragraph()
paragraph.add_run(Run(text="Sample"))
section.add_paragraph(paragraph)
doc.add_section(section)
return doc

text

**Использование:**
def test_with_fixture(empty_document: Document) -> None:
"""Тест с использованием fixture."""
assert len(empty_document.sections) == 0

text

---

## 🔍 Проверка качества

### Автоматизированные проверки

Запустить все проверки
python -m pytest --cov=src --mypy --flake8 --black --isort

Или по отдельности:
Type checking
mypy --strict src/

Linting
flake8 src/ tests/

Formatting check
black --check src/ tests/
isort --check src/ tests/

Apply formatting
black src/ tests/
isort src/ tests/

text

### Pre-commit hooks (опционально)

Установить pre-commit
pip install pre-commit

Создать .pre-commit-config.yaml
cat > .pre-commit-config.yaml << EOF
repos:

repo: https://github.com/psf/black
rev: 24.1.1
hooks:

id: black
language_version: python3.11

repo: https://github.com/PyCQA/isort
rev: 5.13.2
hooks:

id: isort

repo: https://github.com/PyCQA/flake8
rev: 7.0.0
hooks:

id: flake8

repo: https://github.com/pre-commit/mirrors-mypy
rev: v1.8.0
hooks:

id: mypy
additional_dependencies: [types-all]
EOF

Установить hooks
pre-commit install

Теперь при каждом commit будут автоматически проверки
text

---

## 🤖 AI-Assisted Development

### Использование Claude/ChatGPT

1. **Открыть https://claude.ai или https://chat.openai.com**

2. **Использовать prompt template:**
Проект: https://github.com/Mike-voyager/FX-Text-processor-3
Прочитай docs/PROMPT_TEMPLATES.md
Используй Template 1 для генерации src/model/enums.py

text

3. **Скопировать сгенерированный код**

4. **Проверить:**
pytest tests/unit/model/test_enums.py -v
mypy --strict src/model/enums.py
black --check src/model/enums.py

text

### Использование Continue.dev (VS Code)

1. **Установить расширение Continue**
2. **Открыть файл для работы**
3. **Нажать Ctrl+L**
4. **Написать:** "Generate unit tests for this module"
5. **Применить changes**

### Использование Cursor IDE

1. **Открыть проект в Cursor**
2. **Выделить код**
3. **Нажать Ctrl+K**
4. **Написать:** "Refactor this to use dataclass"
5. **Применить diff**

### Использование GitHub Copilot

1. **Установить в VS Code**
2. **Начать писать функцию**
3. **Copilot предложит completion**
4. **Tab для принятия**

---

## 📚 Code Style Guidelines

### Python Style

- **PEP 8** compliance
- **Line length:** 100 characters
- **Type hints:** везде
- **Docstrings:** Google style, на русском
- **Naming:**
  - Classes: `PascalCase`
  - Functions/methods: `snake_case`
  - Constants: `UPPER_CASE`
  - Private: `_leading_underscore`

### Example

from typing import Optional, List
from dataclasses import dataclass

@dataclass
class DocumentSection:
"""
Секция документа с параграфами.

text
Attributes:
    title: Заголовок секции
    paragraphs: Список параграфов

Example:
    >>> section = DocumentSection(title="Введение")
    >>> section.add_paragraph(Paragraph(text="Hello"))
    >>> len(section.paragraphs)
    1
"""

title: str
paragraphs: List['Paragraph'] = field(default_factory=list)

def add_paragraph(self, paragraph: 'Paragraph') -> None:
    """
    Добавить параграф в секцию.

    Args:
        paragraph: Параграф для добавления

    Raises:
        TypeError: Если paragraph не является Paragraph
    """
    if not isinstance(paragraph, Paragraph):
        raise TypeError(f"Expected Paragraph, got {type(paragraph)}")
    self.paragraphs.append(paragraph)
text

---

## 🐛 Отладка

### Logging

from src import get_logger

logger = get_logger(name)

def process_data(data: str) -> str:
logger.debug(f"Processing data: {data[:50]}")
try:
result = complex_operation(data)
logger.info(f"Successfully processed {len(result)} items")
return result
except Exception as e:
logger.error(f"Failed to process data: {e}", exc_info=True)
raise

text

### Debugger (VS Code)

**`.vscode/launch.json`:**
{
"version": "0.2.0",
"configurations": [
{
"name": "Python: Current File",
"type": "python",
"request": "launch",
"program": "${file}",
"console": "integratedTerminal",
"justMyCode": false
},
{
"name": "Python: Pytest",
"type": "python",
"request": "launch",
"module": "pytest",
"args": ["-v", "${file}"],
"console": "integratedTerminal",
"justMyCode": false
}
]
}

text

**Использование:**
1. Поставить breakpoint (F9)
2. F5 для запуска
3. Step over (F10), Step into (F11)

---

## 📖 Дополнительные ресурсы

- [ARCHITECTURE.md](ARCHITECTURE.md) - Архитектура проекта
- [PROMPT_TEMPLATES.md](PROMPT_TEMPLATES.md) - AI промпты
- [API_REFERENCE.md](API_REFERENCE.md) - API документация
- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

---

**Последнее обновление:** October 2025
**Версия:** 1.0
