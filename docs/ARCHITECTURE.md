# ESC/P Text Editor - Architecture

## Overview

ESC/P Text Editor follows strict MVC (Model-View-Controller) architecture with clear separation of concerns.

## Layer Responsibilities

### Model Layer (`src/model/`)
- **Purpose**: Data structures and business entities
- **Key Classes**:
  - `Document`: Root document container
  - `Section`: Page settings and content grouping
  - `Paragraph`: Text block with alignment
  - `Run`: Formatted text fragment
  - `Table`: Table structure with cells
- **No Dependencies**: Model layer is independent from View and Controller

### View Layer (`src/view/`)
- **Purpose**: UI components and rendering
- **Technology**: Tkinter
- **Key Components**:
  - `MainWindow`: Application window
  - `PagedCanvas`: WYSIWYG rendering
  - `FormatToolbar`: Formatting controls
  - Dialogs: Settings, table insertion, etc.

### Controller Layer (`src/controller/`)
- **Purpose**: Business logic and event handling
- **Patterns**:
  - Command pattern (Undo/Redo)
  - Observer pattern (Document changes)
- **Key Classes**:
  - `DocumentController`: Document manipulation
  - `CommandManager`: Undo/Redo stack

### ESC/P Layer (`src/escp/`)
- **Purpose**: ESC/P command generation
- **Key Classes**:
  - `EscpCommandBuilder`: Command generator
  - Specialized builders for fonts, positioning, etc.

## Data Flow

User Input → View → Controller → Model → ESC/P Builder → Printer
↑ ↓
└──────── Observer ────┘

text

## Module Dependencies

view → controller → model
↓
escp → printer

text

## File Format

Documents are stored as JSON with this structure:

{
"version": "0.1.0",
"metadata": {...},
"sections": [
{
"page_settings": {...},
"paragraphs": [...]
}
]
}

text

See `docs/FILE_FORMAT.md` for complete specification.
2. docs/PROMPT_TEMPLATES.md
text
# AI Prompt Templates for ESC/P Text Editor

This document contains ready-to-use prompt templates for AI-assisted development.

## Template 1: Module Generation

CONTEXT
Project: https://github.com/Mike-voyager/FX-Text-processor-3
Architecture: docs/ARCHITECTURE.md
Example: src/init.py

TASK
Generate module: src/model/[MODULE_NAME].py

REQUIREMENTS
Follow MVC architecture

Python 3.11+ with type hints

Google-style docstrings (Russian)

Mypy strict compliance

Unit tests with 100% coverage

No external dependencies in model layer

DELIVERABLES
src/model/[MODULE_NAME].py - implementation

tests/unit/model/test_[MODULE_NAME].py - tests

Brief implementation notes

text

## Template 2: Code Review

CONTEXT
Project: https://github.com/Mike-voyager/FX-Text-processor-3
PR: [PR_URL]

TASK
Review code changes in this Pull Request

CHECK FOR
Type safety (mypy strict)

Test coverage (>90%)

Documentation (Google-style docstrings)

Code style (black, isort)

Architecture compliance (MVC)

No circular dependencies

Error handling

Performance considerations

FORMAT
Provide structured review with:

Summary

Issues found (severity: critical/major/minor)

Suggestions for improvement

Approval status

text

## Template 3: Bug Fix

CONTEXT
Project: https://github.com/Mike-voyager/FX-Text-processor-3
Issue: [ISSUE_URL]

BUG DESCRIPTION
[Paste error traceback or description]

TASK
Fix the bug while maintaining:

Existing functionality

Test coverage

Type safety

Code style

DELIVERABLES
Bug fix implementation

Regression test

Explanation of root cause

text

## Template 4: Feature Implementation

CONTEXT
Project: https://github.com/Mike-voyager/FX-Text-processor-3
Architecture: docs/ARCHITECTURE.md
Feature request: [ISSUE_URL]

FEATURE DESCRIPTION
[Describe feature]

ACCEPTANCE CRITERIA
 Criterion 1

 Criterion 2

 Unit tests

 Documentation

TECHNICAL APPROACH
[Optional: suggest implementation strategy]

DELIVERABLES
Implementation code

Tests

Documentation updates

Example usage

text

## Using Templates

1. Copy template
2. Replace [PLACEHOLDERS] with actual values
3. Paste to Claude/ChatGPT
4. Review and apply generated code
3. docs/DEVELOPMENT.md
text
# Development Guide

## Setup Development Environment

### 1. Install Prerequisites
Python 3.11+
winget install Python.Python.3.11

Git
winget install Git.Git

VS Code (recommended)
winget install Microsoft.VisualStudioCode

text

### 2. Clone and Setup
git clone https://github.com/Mike-voyager/FX-Text-processor-3.git
cd FX-Text-processor-3
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"

text

### 3. Configure IDE

**VS Code Extensions:**
- Python (Microsoft)
- Pylance
- Python Test Explorer
- GitHub Copilot (optional)
- Continue (optional)

**Settings (`.vscode/settings.json`):**
{
"python.analysis.typeCheckingMode": "strict",
"python.formatting.provider": "black",
"python.linting.enabled": true,
"python.linting.mypyEnabled": true,
"python.testing.pytestEnabled": true,
"editor.formatOnSave": true
}

text

## Development Workflow

### 1. Create Feature Branch
git checkout -b feature/module-name

text

### 2. Implement Module

Follow this order:
1. Write tests first (TDD)
2. Implement module
3. Run tests: `pytest tests/unit/model/test_module.py -v`
4. Type check: `mypy --strict src/model/module.py`
5. Format: `black src/model/module.py`

### 3. Commit Changes
git add .
git commit -m "feat: Add module-name with XYZ functionality"

text

Commit message format:
- `feat:` - new feature
- `fix:` - bug fix
- `docs:` - documentation
- `test:` - tests
- `refactor:` - code refactoring
- `style:` - formatting

### 4. Push and Create PR
git push origin feature/module-name
gh pr create --title "Add module-name" --body "Implements #ISSUE_NUMBER"

text

## Testing Guidelines

### Unit Tests
- Located in `tests/unit/`
- Test single module in isolation
- Use mocks for dependencies
- Aim for 100% coverage

### Integration Tests
- Located in `tests/integration/`
- Test multiple modules together
- Test with real dependencies
- Aim for critical paths

### Running Tests
All tests
pytest

Specific module
pytest tests/unit/model/test_document.py -v

With coverage
pytest --cov=src --cov-report=html

Watch mode
pytest-watch

text

## Code Quality Checks

Type checking
mypy --strict src/

Linting
flake8 src/ tests/

Formatting
black --check src/ tests/
isort --check src/ tests/

Fix formatting
black src/ tests/
isort src/ tests/

text

## AI-Assisted Development

### Using Continue.dev
1. Install Continue extension in VS Code
2. Open file to work on
3. Press `Ctrl+L` to open chat
4. Ask: "Generate unit tests for this module"

### Using Claude/ChatGPT
1. Open browser: https://claude.ai or https://chat.openai.com
2. Paste prompt from `docs/PROMPT_TEMPLATES.md`
3. Replace placeholders
4. Copy generated code to project

### Using GitHub Copilot
1. Install Copilot in VS Code
2. Start typing function signature
3. Accept suggestions with `Tab`
4. Use `Ctrl+Enter` for alternatives
