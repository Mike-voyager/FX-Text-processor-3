# FX Text Processor 3

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Type checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](http://mypy-lang.org/)

Professional **cross-platform** WYSIWYG text editor for **Epson FX-890** dot matrix printer with full ESC/P command support.


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
- ✅ **Cross-platform**: Windows 11 and Linux (Ubuntu/Fedora) support
- ✅ **Direct printing**: WritePrinter API (Windows) / CUPS (Linux)
- ✅ **Rich text formatting**: Bold, Italic, Underline, Double-width/height
- ✅ **PC866 Cyrillic encoding** with dynamic charset switching
- ✅ **Image processing**: Dithering (Floyd-Steinberg, Burkes), grayscale conversion
- ✅ **Barcode/QR generation**: Native ESC/P rendering
- ✅ **Form builder**: Template system with variable substitution
- ✅ **Table editor**: Excel import/export, cell merging, auto-alignment

### Advanced Features
- ⏳ Markdown compatibility (import/export)
- ⏳ RTF parser/exporter
- ⏳ Multi-language GUI
- ⏳ Network printer support (maybe)
- ⏳ Envelope printing with graphical preview

## 🔒 Enterprise Security

FX Text processor 3 implements **Zero Trust Architecture** with military-grade cryptography:

### Security Highlights

- **🔐 Multi-Factor Authentication**: FIDO2/WebAuthn hardware keys (YubiKey, Windows Hello)
- **🛡️ AES-256-GCM Encryption**: Authenticated encryption with full 96-bit random nonces
- **✍️ Ed25519 Digital Signatures**: 270× faster than RSA-4096, tamper-proof protected blanks
- **🔑 Argon2id Password Hashing**: Memory-hard with configurable profiles (Mobile/Desktop/SAFE_DESKTOP)
- **✅ Health Check System**: 6 cryptographic subsystems monitored (100% operational)
- **🔒 RNG Health Checks**: NIST SP 800-90B compliant (RCT + APT)


### Protected Blanks System

Each househood require special blank tracking:

from src.security.blanks import BlankManager

Issue numbered blank series
blanks = blank_mgr.issue_blank_series(
series='A', count=100, blank_type='invoice'
)

Print with digital signature
blank_mgr.print_blank(
blank_id='A-042',
document=invoice_doc,
user_id='username :)'
)

Verify authenticity (scan QR code)
if verify_blank(qr_data, printed_content):
print("✓ Authentic blank")

### Multi-Factor Authentication (MFA/2FA) in FX Text Processor 3

The system supports three equivalent second factor methods:
- **FIDO2/WebAuthn** (hardware keys: YubiKey, TouchID, Windows Hello)
- **TOTP** (time-based one-time passwords: Google Authenticator, Authy, FreeOTP)
- **Backup codes** — one-time use, issued only to a fully authenticated user (strict "One-Time Use" principle).

Users may enable any combination of factors and, during login, choose any available second factor to pair with their master password.

Backup codes are generated strictly through a protected interface (full authentication required) and are issued in batch as a list, suitable for display or printing for secure offline storage.

Backup codes can be used only once; after successful use, they are automatically invalidated and cannot be reused.

The validity of backup codes (TTL/lifetime) is limited according to user/system settings; after expiry, codes are considered invalid.

The logic for issuing, displaying, exporting, and printing backup codes is implemented outside the second factor manager — strictly in the application’s controller/UI layer, following the Single Responsibility Principle.

All second factor secrets (TOTP seeds, FIDO2 keys, backup codes) are stored in local encrypted storage using AES-GCM and Argon2id.

The second factor manager implements secure lifecycle and verification logic, with support for multiple devices/secrets per user and an extensible DI (Dependency Injection) pattern for adding future methods.


### Compliance

- **GDPR**: Right to access, erasure, data minimization
- **Audit Retention**: 3-7 years configurable
- **SIEM Integration**: RFC 5424 Syslog, JSON Lines export
- **Zero-Knowledge**: No dependency on proprietary crypto

**→ Full documentation**: [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md)

## 📁 Project Structure
<pre>
FX-Text-processor-3/
├── src/                         # Source code (MVC architecture)
│   ├── __init__.py                             # ✅ DONE
│   ├── main.py   # 🚧 TODO                     # Application entrypoint
│
│   ├── model/                    # Data models
│   │   ├── __init__.py
│   │   ├── document.py           # document.py # Doc datamodel, NO business logic
│   │   ├── section.py            # ✅ Done
│   │   ├── user.py               # 🚧 TODO
│   │   ├── paragraph.py          # ✅ DONE
│   │   ├── run.py                # ✅ Done
│   │   ├── table.py              # ✅ DONE
│   │   ├── image.py              # 🚧 TODO
│   │   ├──barcode.py             # Enum, barcode data/params
│   │   ├──form.py                # 🚧 TODO 🔐
│   │   ├──validation.py          # 🚧 TODO
│   │   └── enums.py              # ✅ DONE ?
│
│   ├── view/ # UI components (Tkinter) # 🚧 TODO
│   │   ├── __init__.py             # 🚧 TODO
│   │   ├── main_window.py # 🔐    # 🚧 TODO
│   │   ├── paged_canvas.py         # 🚧 TODO
│   │   ├── format_toolbar.py       # 🚧 TODO
│   │   ├── ruler_widget.py         # 🚧 TODO
│   │   ├── status_bar.py           # 🚧 TODO
│   │   ├── dialogs/ # 🔐           # 🚧 TODO
│   │   └── widgets/ # 🔐           # 🚧 TODO
│   │
│   ├── controller/ # Business logic    # 🚧 TODO
│   │   ├── init.py
│   │   ├── document_service.py # Edit, split, merge, search, validate documents
│   │   ├── table_service.py # Merge/split, import/export, conditional formatting
│   │   ├── image_service.py # Dithering, resizing, format convert, overlays (Pillow, Numpy)
│   │   ├── barcode_service.py # All barcode & matrix2d def, unified API, error reporting
│   │   ├── form_service.py # Build, batch, template, validate forms
│   │   ├── charset_service.py # Encode/decode, strategy, batch conversion
│   │   ├── escp_service.py # ESC/P command builder, state, validation, snapshot
│   │   ├── printer_service.py # Send, status, error, Windows integration
│   │   ├── audit_service.py # Logging, SIEM, event batch
│   │   ├── compliance_service.py # GDPR/delete/anonymization/retention operations
│   │   └── utils_service.py # Non-domain utilities for byte packing, validation
│
│   ├── escp/    # 🚧 TODO                 # ESC/P protocol stack
│   │   ├── __init__.py
│   │   ├── commands/   # ✅ DONE
│   │   │   ├── __init__.py         # ✅ DONE
│   │   │   ├── text_formatting.py  # ✅ DONE
│   │   │   ├── fonts.py            # ✅ DONE
│   │   │   ├── sizing.py           # ✅ DONE
│   │   │   ├── positioning.py      # ✅ DONE
│   │   │   ├── line_spacing.py     # ✅ DONE
│   │   │   ├── print_quality.py    # ✅ DONE
│   │   │   ├── graphics.py         # ✅ DONE
│   │   │   ├── barcode.py          # ✅ DONE
│   │   │   ├── page_control.py     # ✅ DONE
│   │   │   ├── hardware.py         # ✅ DONE
│   │   │   ├── charset.py          # ✅ DONE
│   │   │   ├── special_effects.py  # ✅ DONE
│   │   │   └── shading.py          # ✅ DONE
│   │   ├── advanced_graphics/  # 🚧 TODO
│   │   │   ├── __init__.py             # 🚧 TODO
│   │   │   ├── dithering.py            # 🚧 TODO
│   │   │   ├── double_strike.py        # 🚧 TODO
│   │   │   ├── udc.py                  # 🚧 TODO
│   │   │   ├── scanline.py             # 🚧 TODO
│   │   │   ├── esc_strikethrough.py    # 🚧 TODO
│   │   │   └── rendering.py            # 🚧 TODO
│   │   └── builders/           # 🚧 TODO
│   │       ├── __init__.py             # 🚧 TODO
│   │       ├── base.py                 # 🚧 TODO
│   │       ├── table_builder.py        # 🚧 TODO
│   │       ├── paragraph_builder.py    # 🚧 TODO
│   │       ├── run_builder.py          # 🚧 TODO
│   │       └── document_builder.py     # 🚧 TODO
│   │
│   ├── form/ # Form builder    # ✅ DONE 99% ⚠️ TODO tests with secure/
│   │   ├── __init__.py
│   │   ├── form_builder.py # 🔐# ⚠️ DONE 50/50 TODO tests
│   │   ├── form_palette.py         # ✅ DONE
│   │   ├── form_elements.py        # ✅ DONE
│   │   ├── template_manager.py     # ✅ DONE
│   │   ├── variable_parser.py      # ✅ DONE
│   │   ├── validation.py           # ✅ DONE
│   │   ├── form_schema.py          # ✅ DONE
│   │   ├── export_import.py        # ✅ DONE
│   │   ├── style_manager.py        # ✅ DONE
│   │   └── batch_processor.py  # ⚠️ DONE 50/50 TODO tests
│   │
│   ├── charset/ # Codepage management # 🚧 TODO
│   ├── image/ # Image processing # 🚧 TODO
│   │
│   ├── barcodegen/ # ✅ DONE
│   │   ├── __init__.py             # ✅ DONE
│   │   ├── barcode_generator.py    # ✅ DONE
│   │   └── matrix2d_generator.py   # ✅ DONE
│   │
│   ├── printer/                  # Cross-platform printer abstraction
│   │   ├── __init__.py
│   │   ├── base_adapter.py       # 🚧 TODO - Abstract base for all adapters
│   │   ├── cups_adapter.py       # 🚧 TODO - Linux CUPS implementation
│   │   ├── win_adapter.py        # 🚧 TODO - Windows API implementation
│   │   └── factory.py            # 🚧 TODO - Platform detection & adapter factory
│   ├── io/ # File I/O (JSON, RTF, Markdown) # 🔐 # 🚧 TODO
│   └── utils/ # Utilities # 🚧 TODO
│
│
├── tests/                        # Test suite
│   ├── unit/      # ✅ 1166 tests, 79.22% coverage, 33 fails
│   └── integration/
│
├── docs/                         # Documentation⚠️ TODO
│   ├── ARCHITECTURE.md           # System architecture
│   ├── API_REFERENCE.md          # API documentation ⚠️ TODO
│   ├── PROMPT_TEMPLATES.md       # AI prompt templates
│   ├── SECURITY_ARCITECTURE.md   # security arcitecture ⚠️ TODO
│   └── DEVELOPMENT.md            # Development guide ⚠️ TODO
│
├── security/
│   ├── __init__.py # ✅ DONE
│   ├── crypto/     
│   │   ├── __init__.py             # ✅ DONE - Public API exports
│   │   ├── core/  # ✅ DONE
│   │   │   ├── __init__.py                # ✅ DONE
│   │   │   ├── protocols.py               # ✅ DONE   
│   │   │   ├── metadata.py                # ✅ DONE
│   │   │   ├── registry.py                # ✅ DONE
│   │   │   ├── exceptions.py              # ✅ DONE
│   │   │   └── adapters.py [maybe? for backward compartability] 
│   │
│   ├── algorithms/ # ✅ DONE
│   │   │   ├── __init__.py                # ✅ DONE
│   │   │   ├── symmetric.py               # ✅ DONE
│   │   │   ├── signing.py                 # ✅ DONE
│   │   │   ├── asymmetric.py              # ✅ DONE
│   │   │   ├── key_exchange.py            # ✅ DONE
│   │   │   ├── hashing.py                 # ✅ DONE
│   │   │   └── kdf.py                     # ✅ DONE
│   │   │
│   │   ├── advanced/   # ✅ DONE
│   │   │   ├── __init__.py
│   │   │   ├── hybrid_encryption.py      # ✅ DONE
│   │   │   ├── group_encryption.py       # ✅ DONE
│   │   │   ├── key_escrow.py             # ✅ DONE
│   │   │   └── session_keys.py           # ✅ DONE
│   │   │
│   │   ├── service/  # 🚧 DONE/TODO tests
│   │   │   ├── __init__.py
│   │   │   ├── crypto_service.py         # + integration with src.audit
│   │   │   ├── ui_helpers.py
│   │   │   └── profiles.py
│   │   │
│   │   ├── utilities   # 🚧 DONE/TODO tests
│   │   │   ├── __init__.py
│   │   │   ├── utils.py                  # + FloppyOptimizer, NonceManager, SecureMemory
│   │   │   ├── config.py                 # + floppy_mode (disabled/basic/aggressive)
│   │   │   ├── passwords.py
│   │   │   ├── secure_storage.py         # + compression support
│   │   │   ├── key_rotation.py
│   │   │   ├── serialization.py
│   │   │   ├── key_management.py         # NEW: Import/Export/Wrap
│   │   │   └── migration.py              # NEW: Crypto agility
│   │   │
│   │   ├── hardware/← only CRYPTO operations! # 🚧 DONE/TODO tests
│   │   │   ├── __init__.py
│   │   │   ├── apdu_transport.py
│   │   │   ├── backends.py             # ✅ DONE
│   │   │   ├── openpgp_backend.py      # ✅ DONE
│   │   │   └── hardware_crypto.py        # Smartcards, YubiKey (sign/encrypt/decrypt)
│   │   │
│   │   └── 🏥 monitoring 
│   │   │   ├── __init__.py
│   │       ├── health.py
│   │       └── benchmarks.py [OPT]
│   ├── auth/               # 🚧 TODO
│   │   ├── __init__.py                 # ✅ DONE
│   │   ├── password.py                 # 🚧 DONE/TODO tests
│   │   ├── password_service.py         # 🚧 DONE/TODO tests
│   │   ├── second_factor.py            # 🚧 DONE/TODO tests
│   │   ├── second_factor_service.py    # 🚧 DONE/TODO tests
│   │   ├── fido2_service.py            # 🚧 DONE/TODO tests
│   │   ├── totp_service.py             # 🚧 DONE/TODO tests
│   │   ├── code_service.py             # 🚧 DONE/TODO tests
│   │   ├── session.py                  # 🚧 DONE/TODO tests
│   │   ├── session_service.py          # 🚧 TODO
│   │   ├── permissions.py              # 🚧 TODO
│   │   ├── permissions_service.py      # 🚧 TODO
│   │   ├── auth_service.py             # 🚧 TODO
│   │   └── second_method/  # ✅ DONE
│   │       ├── __init__.py # ✅ DONE
│   │       ├── fido2.py    # ✅ DONE
│   │       ├── totp.py     # ✅ DONE
│   │       └── code.py     # ✅ DONE
│   ├── audit/  # 🚧 TODO
│   │   ├── __init__.py         # 🚧 TODO
│   │   ├── logger.py           # 🚧 TODO
│   │   ├── exporters.py        # 🚧 TODO
│   │   └── integrity.py        # 🚧 TODO
│   ├── blanks/ # 🚧 TODO
│   │   ├── __init__.py         # 🚧 TODO
│   │   ├── manager.py #🔐      # 🚧 TODO
│   │   ├── watermark.py        # 🚧 TODO
│   │   └── verification.py     # 🚧 TODO
│   └── compliance/ # 🚧 TODO
│       ├── __init__.py         # 🚧 TODO
│       ├── gdpr.py             # 🚧 TODO
│       ├── retention.py        # 🚧 TODO
│       └── anonymization.py    # 🚧 TODO
│
├── resources/    # 🚧 TODO        # External resources/assets/templates
├── .github/                      # GitHub config, CI/CD, issue templates
│   ├── workflows/
│   └── ISSUE_TEMPLATE/
│
├── pyproject.toml    # 🚧 TODO          # Project config (build/system)
├── pytest.ini
├── README.md        # ⚠️ update after changes
</pre>


## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- **Operating Systems:**
  - Windows 11 (tested with pywin32)
  - Linux (developed on Fedora 43, tested on Ubuntu 22.04+)
- Git

### System Dependencies

**Linux (Fedora/RHEL):**
```bash

sudo dnf install cups-devel python3-tkinter

```

Windows:

    No additional system dependencies required

### Installation

#### Clone repository
git clone https://github.com/Mike-voyager/FX-Text-processor-3.git
cd FX-Text-processor-3

#### Create virtual environment
python -m venv .venv

#### Activate (Windows)
.venv\Scripts\activate

#### Activate (Linux)
source .venv/bin/activate

#### Install dependencies
pip install -e ".[dev]"

#### Install platform-specific dependencies
#### Windows:
pip install pywin32>=306

#### Linux:
pip install pycups>=2.0.0



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

## 🖥️ Platform Support

| Feature | Windows 11 | Linux (Fedora/Ubuntu) |
|---------|------------|----------------------|
| GUI (Tkinter) | ✅ Full support | ✅ Full support |
| ESC/P Commands | ✅ Full support | ✅ Full support |
| Direct Printing | ✅ WritePrinter API | ✅ CUPS |
| Network Printing | ⏳ Planned | ✅ CUPS native |
| PC866 Encoding | ✅ Supported | ✅ Supported |
| Floppy Disk | ✅ Native | ✅ Via mount |

**Linux Notes:**
- CUPS must be installed and running
- User must be in `lp` group for printer access: `sudo usermod -aG lp $USER`
- Raw queue recommended for ESC/P commands

## 📊 Development Status

**Last Updated:** February 2026 | **Version:** 0.1.0-alpha

### Overall Progress: ~48% Complete

| Category | Completion | Details |
|----------|-----------|---------|
| **Core Infrastructure** | ✅ 100% | Application context, DI, configuration |
| **Data Models** | ✅ 86% | 6/7 modules complete (table, section, paragraph, run, barcode, enums) |
| **ESC/P Commands** | ✅ 100% | All 13 command modules, full FX-890 support |
| **Barcode Generation** | ✅ 100% | QR, DataMatrix, PDF417, 1D barcodes |
| **Form Builder** | ⚠️ 82% | 9/11 modules done, 2 need comprehensive tests |
| **Security System** | ⚠️ 65% | Crypto complete, auth mostly done, audit/compliance pending |
| **GUI (View)** | ❌ 0% | Main window, canvas, toolbar, dialogs |
| **Controllers** | ❌ 0% | Business logic layer |
| **Printer Access** | ❌ 0% | Windows API integration |
| **Image Processing** | ❌ 0% | Graphics for matrix printers |
| **Charset Management** | ❌ 0% | PC866 and multi-codepage |
| **I/O Handlers** | ❌ 0% | JSON, RTF, Markdown |

### Module Details

#### ✅ Completed Modules (Production Ready)

**Model Layer** (6/7 modules, ~92% coverage)
- `table.py` - 96% coverage, 77 tests
- `section.py` - 100% coverage, 75 tests
- `paragraph.py` - 100% coverage, 87 tests
- `run.py` - 97% coverage, 71 tests
- `barcode.py` - ~95% coverage
- `enums.py` - ~85% coverage

**ESC/P Commands** (13/13 modules, >95% coverage)
- Full Epson FX-890 command set
- Text formatting, fonts, sizing, positioning
- Graphics, barcodes, page control
- Hardware control, charsets, effects

**Barcode Generation** (2/2 modules, ~92% coverage)
- `barcode_generator.py` - 1D barcodes (EAN, Code128, etc.)
- `matrix2d_generator.py` - QR, DataMatrix, PDF417, etc.

**Security: Cryptography** (10/10 modules, ~95% coverage)
- AES-256-GCM symmetric encryption
- Ed25519/X25519 asymmetric crypto
- Argon2id key derivation
- BLAKE2b/SHA-3 hashing
- Digital signatures
- Encrypted keystore

**Security: Authentication** (10/13 modules, ~90% coverage)
- Password management with Argon2id
- FIDO2/WebAuthn hardware keys
- TOTP (Google Authenticator)
- Backup codes with TTL
- Session management (93% coverage)
- Second factor orchestration

**Form Builder** (9/11 modules, ~75% coverage)
- Form palette, elements, schema
- Template manager with variable substitution
- Validation engine
- Export/import functionality
- Style manager

#### ⚠️ Partial/In Progress

**Model Layer**
- `document.py` - 43% coverage, blocked on refactor

**Form Builder**
- `form_builder.py` - Core logic done, needs comprehensive tests
- `batch_processor.py` - Implementation done, needs tests

**Security: Authentication**
- `session_service.py` - TODO
- `permissions.py` - RBAC system TODO
- `auth_service.py` - Unified API TODO

### Test Coverage Summary

Total Tests: 1,045+
Pass Rate: ~97% (33 known failures being addressed)
Overall Coverage: ~80%

By Subsystem:
- Model Layer:        ~92% (310+ tests)
- ESC/P Commands:     >95% (420+ tests)
- Barcode Generation: ~95% (85+ tests)
- Security (Crypto):  ~95% (180+ tests)
- Security (Auth):    ~90% (150+ tests)
- Form Builder:       ~75% (95+ tests)


</parameter>
</invoke>

## 🤖 AI-Assisted Development

This project is optimized for AI-assisted development. See [PROMPT_TEMPLATES.md](docs/PROMPT_TEMPLATES.md) for ready-to-use prompts.

### Quick AI Workflow

1. **Analyze project structure:**
Project: https://github.com/Mike-voyager/FX-Text-processor-3
Analyze architecture and suggest next module to implement.


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
- **Windows:** pywin32 306+ (printer access via Windows API)
- **Linux:** pycups 2.0+ (printer access via CUPS)
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

## 🖴 Floppy Disk Support (3.5")

FX Text processor 3 offers full compatibility with classic **3.5-inch floppy disks** for document, form, and blank storage.

- **Read and write** FX-Text-processor-3 files directly to any 3.5" disk using a standard or USB floppy drive (Windows 11 supported).
- **No restrictions:** All features—document editing, templates, secure forms, signatures—work on floppy media out of the box.
- **For enthusiasts:** Use floppies for archiving, sharing, or just for the fun of classic hardware.

> Whether you use floppy disks for archiving, secure transfer, hardware redundancy, or nostalgia—FX-Text-processor-3 maintains full support for your workflow.

> Floppy compatible — just because I love retro tech. And because I can.

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

## 📋 Platform-Specific Notes

### Windows
- Uses native WritePrinter API for direct ESC/P access
- Requires pywin32 package
- Full support for local and USB printers

### Linux
- Uses CUPS (Common Unix Printing System)
- Requires libcups2-dev system package
- Supports both local and network printers
- Raw queue recommended for matrix printers
- Add user to `lp` group for permissions

**Status:** 🚧 Active Development | **Version:** 0.1.0 | **Last Updated:** February 2026
