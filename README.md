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

## 🔒 Enterprise Security

FX-Text-processor-3 implements **Zero Trust Architecture** with military-grade cryptography:

### Security Highlights

- **🔐 Multi-Factor Authentication**: FIDO2/WebAuthn hardware keys (YubiKey, Windows Hello)
- **🛡️ AES-256-GCM Encryption**: Authenticated encryption with 128-bit MAC
- **✍️ Ed25519 Digital Signatures**: 270× faster than RSA-4096, tamper-proof protected blanks
- **🔑 Argon2id Password Hashing**: Memory-hard, 6,666× slower for attackers
- **📝 Immutable Audit Log**: Cryptographic integrity with HMAC chain verification
- **🌐 OpenPGP Multi-Recipient**: Encrypt for multiple users simultaneously

### Protected Blanks System

Financial organizations require special blank tracking:

from src.security.blanks import BlankManager

Issue numbered blank series
blanks = blank_mgr.issue_blank_series(
series='A', count=100, blank_type='invoice'
)

Print with digital signature
blank_mgr.print_blank(
blank_id='A-042',
document=invoice_doc,
user_id='operator-001'
)

Verify authenticity (scan QR code)
if verify_blank(qr_data, printed_content):
print("✓ Authentic blank")

### Compliance

- **GDPR**: Right to access, erasure, data minimization
- **Audit Retention**: 3-7 years configurable
- **SIEM Integration**: RFC 5424 Syslog, JSON Lines export
- **Zero-Knowledge**: No dependency on proprietary crypto

**→ Full documentation**: [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md)

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
├── escp/
│   ├── __init__.py
│   ├── commands/
│   │   ├── __init__.py  (✅ DONE)
│   │   ├── text_formatting.py (✅ DONE)
│   │   ├── fonts.py (✅ DONE)
│   │   ├── sizing.py (✅ DONE)
│   │   ├── positioning.py (✅ DONE)
│   │   ├── line_spacing.py (✅ DONE)
│   │   ├── print_quality.py (✅ DONE)
│   │   ├── graphics.py (✅ DONE)
│   │   ├── barcode.py (✅ DONE)
│   │   ├── page_control.py (✅ DONE)
│   │   ├── hardware.py (✅ DONE)
│   │   ├── charset.py (✅ DONE)
│   │   ├── special_effects.py (✅ DONE)
│   │   └── shading.py (✅ DONE)
│   ├── advanced_graphics/
│   │   ├── __init__.py
│   │   ├── dithering.py
│   │   ├── double_strike.py
│   │   ├── udc.py
│   │   ├── scanline.py
│   │   ├──esc_strikethrough.py
│   │   └── rendering.py
│   └── builders/
│       ├── __init__.py
│       ├── base.py
│       ├── table_builder.py
│       ├── paragraph_builder.py
│       ├── run_builder.py
│       └── document_builder.py
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
├── security/
│ ├── init.py # Public API exports
│ ├── crypto/
│ │ ├── init.py
│ │ ├── symmetric.py # AES-256-GCM encryption
│ │ ├── asymmetric.py # GPG/OpenPGP integration
│ │ ├── kdf.py # Argon2id key derivation
│ │ ├── signatures.py # Ed25519 digital signatures
│ │ └── hashing.py # SHA3-256, BLAKE2b
│ ├── auth/
│ │ ├── init.py
│ │ ├── password.py # Argon2id password hashing
│ │ ├── webauthn.py # FIDO2/WebAuthn manager
│ │ ├── session.py # JWT session management
│ │ └── permissions.py # RBAC permissions
│ ├── audit/
│ │ ├── init.py
│ │ ├── logger.py # Immutable audit log
│ │ ├── exporters.py # Syslog, JSON Lines export
│ │ └── integrity.py # HMAC chain verification
│ ├── blanks/
│ │ ├── init.py
│ │ ├── manager.py # Protected blank management
│ │ ├── watermark.py # Watermark generation
│ │ └── verification.py # Authenticity verification
│ └── compliance/
│ ├── init.py
│ ├── gdpr.py # GDPR compliance helpers
│ ├── retention.py # Data retention policies
│ └── anonymization.py # PII anonymization
├── resources/ # External resources
├── .github/ # GitHub configuration
│ ├── workflows/ # CI/CD pipelines
│ └── ISSUE_TEMPLATE/ # Issue templates
├── pyproject.toml # Project configuration
├── pytest.ini # Pytest configuration
└── README.md # This file

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
Module              |  Status      |  Coverage  |  Notes
--------------------+--------------+------------+------------------------------------------------------------------------------------------------------------------
Core (__init__.py)  |  ✅ Done      |  100%      |  Logging, config, dependencies
Model Layer         |  ✅ 71%       |  ~92%      |  5/7 modules complete
├─table.py          |  ✅ Done      |  96%       |  Grid structure, cells, borders (77 tests)
├─section.py        |  ✅ Done      |  100%      |  Document sections, page breaks (75 tests)
├─paragraph.py      |  ✅ Done      |  100%      |  Text blocks, alignment, spacing (87 tests)
├─run.py            |  ✅ Done      |  97%       |  Inline formatting, encoding (71 tests)
├─enums.py          |  ⚠️ Partial  |  68%       |  ESC/P constants - needs improvement
└─document.py       |  🚧 Blocked  |  43%       |  Root container - awaiting refactor
ESC/P Commands      |  ✅ Done      |  >95%      |  All core FX-890 ESC/P features, full test/manual coverage (unit/integration in progress), architecture finalized
GUI (View)          |  ❌ 0%        |  -         |  Main window, text editor
Printer Access      |  ❌ 0%        |  -         |  Windows printer API
Form Builder        |  ❌ 0%        |  -         |  Table/form templates
Image Processing    |  ❌ 0%        |  -         |  Graphics for matrix printers
Progress Summary:

✅ 404 tests passing (100% pass rate)

📊 Model Layer: 71% complete (5/7 modules production-ready)

🚀 ESC/P Commands: All commands and low-level FX-890 features implemented and structured; code reviewed and documented; ready for further integration with builders and advanced_graphics

🎯 Next Priority: Improve enums.py (68% → 90%+), then refactor document.py

🏗️ Overall Project: ~38% complete (now 6/15 major modules have core logic and/or full test coverage)

Recent Additions:

✨ commands/ — Full ESC/P command set (FX-890): text, fonts, graphics, barcode, hardware, charset, shading, effects

✨ New structure for advanced_graphics/ — ready for high-level bitmap/dithering features

✨ Readme and architecture docs updated for multi-layer structure

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
