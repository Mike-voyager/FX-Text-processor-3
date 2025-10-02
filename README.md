# ESC/P Text Editor

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Type checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](http://mypy-lang.org/)

Professional WYSIWYG text editor for **Epson FX-890** dot matrix printer with full ESC/P command support.

## 🎯 Project Goals

- Create a modern text editor for legacy matrix printers
- Full ESC/P protocol implementation
- WYSIWYG rendering at 240×144 DPI
- Batch document processing with form builder
- Russian (PC866) and multi-language support

## ✨ Features

### Core Functionality
- ✅ **Full ESC/P command support** for FX-890
- ✅ **WYSIWYG Canvas rendering** with accurate preview
- ✅ **Rich text formatting**: Bold, Italic, Underline, Double-width/height
- ✅ **PC866 Cyrillic encoding** with dynamic charset switching
- ✅ **Image processing**: Dithering (Floyd-Steinberg, Burkes), grayscale conversion
- ✅ **Barcode/QR generation**: Native ESC/P rendering
- ✅ **Form builder**: Template system with variable substitution
- ✅ **Table editor**: Excel import/export, cell merging, auto-alignment
- ✅ **Direct printing**: WritePrinter API (bypass Windows driver)

### Advanced Features
- ⏳ Markdown compatibility (import/export)
- ⏳ RTF parser/exporter
- ⏳ Multi-language GUI
- ⏳ Network printer support
- ⏳ Envelope printing with graphical preview

## 📁 Project Structure

FX-Text-processor-3/
├── src/ # Source code (MVC architecture)
│ ├── init.py # Package initialization (✅ DONE)
│ ├── model/ # Data models
│ │ ├── document.py # ⏳ TODO
│ │ ├── section.py # ⏳ TODO
│ │ ├── paragraph.py # ⏳ TODO
│ │ ├── run.py # ⏳ TODO
│ │ ├── table.py # ⏳ TODO
│ │ └── enums.py # ⏳ IN PROGRESS
│ ├── view/ # UI components (Tkinter)
│ ├── controller/ # Business logic
│ ├── escp/ # ESC/P command builders
│ ├── charset/ # Codepage management
│ ├── image/ # Image processing
│ ├── barcode/ # Barcode/QR generation
│ ├── printer/ # Direct printer access
│ ├── io/ # File I/O (JSON, RTF, Markdown)
│ ├── form/ # Form builder
│ ├── table/ # Table editor
│ └── utils/ # Utilities
├── tests/ # Test suite
│ ├── unit/ # Unit tests (✅ 39 tests, 86% coverage)
│ └── integration/ # Integration tests
├── docs/ # Documentation
│ ├── ARCHITECTURE.md # System architecture
│ ├── API_REFERENCE.md # API documentation
│ ├── PROMPT_TEMPLATES.md # AI prompt templates
│ └── DEVELOPMENT.md # Development guide
├── resources/ # External resources
├── .github/ # GitHub configuration
│ ├── workflows/ # CI/CD pipelines
│ └── ISSUE_TEMPLATE/ # Issue templates
├── pyproject.toml # Project configuration
├── pytest.ini # Pytest configuration
└── README.md # This file

text

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Windows 11 (for pywin32 printer access)
- Git

### Installation

Clone repository
git clone https://github.com/Mike-voyager/FX-Text-processor-3.git
cd FX-Text-processor-3

Create virtual environment
python -m venv .venv
.venv\Scripts\activate

Install dependencies
pip install -e ".[dev]"

text

### Running Tests

Run all tests
pytest tests/ -v

Run with coverage
pytest tests/ --cov=src --cov-report=html

Type checking
mypy --strict src/

Code formatting
black src/ tests/
isort src/ tests/

text

## 📊 Development Status

| Module | Status | Coverage | Notes |
|--------|--------|----------|-------|
| Core (`__init__.py`) | ✅ Done | 86% | Logging, config, dependencies |
| Model Layer | ⏳ 10% | - | `enums.py` in progress |
| ESC/P Commands | ❌ 0% | - | Planned |
| GUI (View) | ❌ 0% | - | Planned |
| Printer Access | ❌ 0% | - | Planned |
| Form Builder | ❌ 0% | - | Planned |
| Image Processing | ❌ 0% | - | Planned |

## 🤖 AI-Assisted Development

This project is optimized for AI-assisted development. See [PROMPT_TEMPLATES.md](docs/PROMPT_TEMPLATES.md) for ready-to-use prompts.

### Quick AI Workflow

1. **Analyze project structure:**
Project: https://github.com/Mike-voyager/FX-Text-processor-3
Analyze architecture and suggest next module to implement.

text

2. **Generate module:**
Project: https://github.com/Mike-voyager/FX-Text-processor-3
Reference: docs/PROMPT_TEMPLATES.md
Generate src/model/enums.py according to project structure.

text

3. **Review code:**
Review this PR: https://github.com/Mike-voyager/FX-Text-processor-3/pull/1
Check for: type safety, test coverage, documentation.

text

### AI Context Files
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - System design
- [API_REFERENCE.md](docs/API_REFERENCE.md) - API documentation
- [PROMPT_TEMPLATES.md](docs/PROMPT_TEMPLATES.md) - Prompt templates

## 🛠️ Technology Stack

**Core:**
- Python 3.11+
- Tkinter (GUI)
- MVC architecture

**Dependencies:**
- Pillow 10.0+ (image processing)
- pywin32 306+ (printer access)
- qrcode 7.4+ (QR generation)
- python-barcode 0.15+ (barcode generation)
- Markdown 3.5+ (Markdown support)
- openpyxl 3.1+ (Excel I/O)

**Development:**
- pytest 8.0+ (testing)
- mypy 1.8+ (type checking)
- black 24.0+ (formatting)
- flake8 7.0+ (linting)
- isort 5.13+ (import sorting)

## 📝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Epson ESC/P Reference Manual
- Python Markdown community
- Matrix printer enthusiasts

## 📞 Contact

- GitHub Issues: [Report bug or request feature](https://github.com/Mike-voyager/FX-Text-processor-3/issues)
- Discussions: [Ask questions](https://github.com/Mike-voyager/FX-Text-processor-3/discussions)

---

**Status:** 🚧 Active Development | **Version:** 0.1.0 | **Last Updated:** October 2025
