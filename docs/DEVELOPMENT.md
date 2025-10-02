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
from dataclasses import dataclass, field

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
