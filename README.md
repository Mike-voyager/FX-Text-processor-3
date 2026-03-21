# FX Text Processor 3

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Type checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](http://mypy-lang.org/)

Professional **cross-platform** WYSIWYG text editor for **Epson FX-890** dot matrix printer with full ESC/P command support and enterprise-grade **Zero Trust** security.

## Project Goals

- Modern text editor for legacy dot matrix printers
- Full ESC/P protocol implementation for Epson FX-890
- WYSIWYG rendering at 240×144 DPI
- Hierarchical document type system with form builder and batch processing
- Enterprise security: Zero Trust architecture, Air-Gap First, post-quantum cryptography
- Russian (PC866) and multi-language support

## Features

### Core

- **Full ESC/P command support** — all 13 command modules for Epson FX-890
- **WYSIWYG canvas rendering** — accurate print preview
- **Cross-platform** — Windows 10+, Linux (Fedora/Ubuntu)
- **Direct printing** — WritePrinter API (Windows), CUPS (Linux)
- **Rich text** — bold, italic, underline, double-width/height, super/subscript, outline, shadow
- **PC866 Cyrillic** — dynamic charset switching (CP437, CP866, CP1251, etc.)
- **Image processing** — dithering (Floyd-Steinberg, Burkes), grayscale, raster graphics (8-pin, 24-pin)
- **Barcode/QR** — native ESC/P rendering (EAN, Code128, QR, DataMatrix, PDF417)
- **Free-form text editing** — Word-like documents with headers, footers, tables, images
- **Structured forms** — field-based documents with validation and cryptographic signing
- **Document types** — hierarchical type system with inheritance, field schemas, alphanumeric indexing
- **Form builder** — template system with variable substitution, field constructor
- **Excel import** — range-to-field mapping from .xlsx into document forms

### Document Indexing

Every document receives a unique hierarchical composite index:

```
DVN-44-K53-IX
 │   │   │   └── SEQUENCE: IX 
 │   │   └────── SERIES: K53 
 │   └────────── SUBTYPE: 44 
 └────────────── ROOT_CODE: DVN 
```

Arbitrary nesting depth. Last segment is always Roman numerals.

### File Formats

All file extensions use the `.fxs` (FX Super) prefix:

| Extension | Name | Purpose |
|-----------|------|---------|
| `.fxsd` | FX Super Document | Unencrypted document (JSON) |
| `.fxsd.enc` | FX Super Document Encrypted | AES-256-GCM encrypted document |
| `.fxstpl` | FX Super Template | Form/document template |
| `.fxsblank` | FX Super Blank | Protected blank (always encrypted) |
| `.fxskeystore.enc` | FX Super Keystore | Key storage (Argon2id + AES-256-GCM) |
| `.fxssig` | FX Super Signature | Detached digital signature |
| `.fxsconfig` | FX Super Config | App configuration (signed by master key) |
| `.fxsbackup` | FX Super Backup | Encrypted backup archive |
| `.fxsbundle.enc` | FX Super Bundle | Export bundle (document + keys + meta) |
| `.fxsreg` | FX Super Registry | Device registry (signed) |
| `.fxsf` / `.fxsfs` | FX Super Form | Open / encrypted form |
| `.fxsschema` | FX Super Schema | JSON Schema validation (Draft 2020-12) |
| `.escp` / `.escps` | ESC/P Raw / Script | Printer byte stream / automation script |

## Enterprise Security

Zero Trust Architecture with military-grade cryptography. Air-Gap First design — full operation without network connectivity.

### Security Presets

| Preset | Signing | Encryption | KDF |
|--------|---------|------------|-----|
| **Standard** | Ed25519 | AES-256-GCM | Argon2id (64 MB) |
| **Paranoid** | Ed25519 + ML-DSA-65 | AES-256-GCM + ChaCha20 | Argon2id (256 MB) |
| **PQC** | ML-DSA-65 | AES-256-GCM | Argon2id (64 MB) |
| **Legacy** | RSA-PSS-4096 | AES-256-GCM | PBKDF2-SHA256 |

Every parameter in every preset can be overridden individually in Settings.

### Key Capabilities

- **Multi-Factor Authentication** — Password + FIDO2 (YubiKey, CTAP2 direct) / TOTP / Backup Codes
- **46 cryptographic algorithms** — Ed25519, ML-DSA-65, AES-256-GCM, ChaCha20-Poly1305, ML-KEM-768, X25519, Argon2id, BLAKE2b, SHA-3, and more
- **Post-Quantum Cryptography** — ML-KEM-768, ML-DSA-65, SPHINCS+, Falcon via `liboqs-python`
- **Hybrid encryption** — Classical + PQC for transition period
- **Protected Blanks** — numbered series with cryptographic signing and QR-based offline verification
- **Immutable Audit Log** — append-only hash chain with HMAC integrity
- **Crypto Agility** — version headers in every encrypted file, seamless algorithm migration
- **Hardware security** — PIV smart cards (J3R200/JCOP4), OpenPGP, YubiKey 5
- **NIST SP 800-90B** compliant RNG health checks (RCT + APT)

### Protected Blanks

```python
from src.security.blanks import BlankManager

# Issue numbered blank series
blanks = blank_mgr.issue_blank_series(
    series='A', count=100, blank_type='invoice'
)

# Print with digital signature
blank_mgr.print_blank(
    blank_id='A-042',
    document=invoice_doc,
    user_id='operator'
)

# Verify authenticity (scan QR code)
if verify_blank(qr_data, printed_content):
    print("✓ Authentic blank")
```

### Compliance

- **GDPR** — right to access, erasure, data minimization
- **Audit retention** — 3-7 years configurable
- **SIEM integration** — RFC 5424 Syslog, JSON Lines export
- **Zero-Knowledge** — no dependency on proprietary crypto

**Full documentation:** [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md)

## Project Structure

```
src/
├── model/                   # Data layer — dataclasses, enums
│   ├── document.py          # Document, DocumentMetadata, PageSettings, PrinterSettings
│   ├── section.py           # Section
│   ├── paragraph.py         # Paragraph, EmbeddedObject
│   ├── run.py               # Run, TextFormatting
│   ├── table.py             # Table, Cell, Row
│   └── enums.py             # FontFamily, CPI, CodePage, Alignment, etc.
│
├── escp/                    # ESC/P protocol layer
│   └── commands/            # Pure byte constants — NO model imports
│       ├── text_formatting.py, fonts.py, sizing.py, positioning.py
│       ├── page_control.py, line_spacing.py, print_quality.py
│       ├── hardware.py, charset.py, barcode.py
│       ├── graphics.py, shading.py, special_effects.py
│       └── (13 modules total, ✅ 100% complete)
│
├── documents/               # Document processing & rendering
│   ├── types/               # 📋 Document types (DOC=text, INV/DVN=forms), TypeRegistry
│   ├── constructor/         # 📋 Form/document construction (ExcelImporter, FieldBuilder)
│   ├── format/              # 📋 Serialization (.fxsd, .fxsd.enc, migration)
│   └── printing/            # 📋 ESC/P render pipeline (document → paragraph → run → bytes)
│
├── security/                # Security subsystem
│   ├── crypto/              # ✅ Cryptographic primitives (v2.3, 46 algorithms)
│   │   ├── core/            #    Protocols, metadata, AlgorithmRegistry, exceptions
│   │   ├── algorithms/      #    symmetric, signing, asymmetric, key_exchange, hashing, kdf
│   │   ├── advanced/        #    Hybrid encryption, group encryption, key escrow, session keys
│   │   ├── service/         #    CryptoService, profiles (Standard/Paranoid/PQC/Legacy)
│   │   ├── utilities/       #    FloppyOptimizer, NonceManager, SecureStorage, key rotation
│   │   └── hardware/        #    PIV, OpenPGP card, YubiKey backends
│   │
│   ├── auth/                # ✅ Authentication (98%)
│   │   ├── password.py, password_service.py     # Argon2id
│   │   ├── session.py, session_service.py       # Access/refresh tokens, IP binding
│   │   ├── fido2_service.py                     # CTAP2 direct
│   │   ├── totp_service.py                      # RFC 6238
│   │   ├── code_service.py                      # Backup codes (one-time use)
│   │   ├── auth_service.py                      # MFA flow orchestration
│   │   ├── permissions.py, permissions_service.py # Scope-based access control
│   │   └── second_method/                       # Factor implementations
│   │
│   ├── audit/               # ✅ Immutable audit log (hash chain + HMAC)
│   ├── blanks/              # ✅ Protected Blanks (lifecycle, signing, QR verification)
│   └── compliance/          # ✅ GDPR, retention, anonymization
│
├── printer/                 # 📋 Print transport layer
│   ├── cups_adapter.py      #    CUPS (Linux)
│   ├── win_adapter.py       #    WritePrinter API (Windows)
│   └── file_adapter.py      #    File output (debug/testing)
│
├── app_context.py           # DI container — composition root (singleton)
│
├── barcodegen/              # ✅ Barcode generation (EAN, Code128, QR, DataMatrix, PDF417)
│   ├── barcode_generator.py # 1D barcodes
│   └── matrix2d_generator.py # 2D codes
│
└── form/                    # ✅ Form builder (legacy, → documents/constructor/)
    ├── form_builder.py, form_palette.py, form_elements.py
    ├── template_manager.py, variable_parser.py
    ├── validation.py, form_schema.py, export_import.py
    ├── style_manager.py, batch_processor.py
    └── (will be refactored into documents/types/ + documents/constructor/)
```

## Quick Start

### Prerequisites

- Python 3.11+ (3.13 compatible)
- Git
- **Windows 10+** / **Linux** (Fedora 43, Ubuntu 22.04+) 

### System Dependencies

**Linux (Fedora/RHEL):**
```bash
sudo dnf install cups-devel python3-tkinter
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt install libcups2-dev python3-tk
```

**Windows:** No additional system dependencies required.

### Installation

```bash
# Clone repository
git clone https://github.com/Mike-voyager/FX-Text-processor-3.git
cd FX-Text-processor-3

# Create virtual environment
python -m venv .venv

# Activate (Linux/macOS)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Platform-specific:
# Windows:
pip install pywin32>=306
# Linux:
pip install pycups>=2.0.0
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html

# Security-only tests
pytest tests/ -m security -v

# Type checking
mypy --strict src/

# Code formatting
black src/ tests/
isort src/ tests/
```

## Platform Support

| Feature | Windows 10+ | Linux (Fedora/Ubuntu) |
|---------|------------|----------------------|
| GUI (Tkinter) | ✅ | ✅ | 
| ESC/P Commands | ✅ | ✅ | 
| Direct Printing | ✅ WritePrinter API | ✅ CUPS | 
| PC866 Encoding | ✅ | ✅ | 
| Floppy Disk | ✅ Native | ✅ Via mount |
| FIDO2 (YubiKey) | ✅ | ✅ |

**Linux notes:**
- CUPS must be installed and running
- User must be in `lp` group: `sudo usermod -aG lp $USER`
- Raw queue recommended for ESC/P commands

## Development Status

**Last Updated:** March 2026 | **Version:** 0.2.0-alpha | **~48% Complete**

| Subsystem | Status | Coverage | Tests |
|-----------|--------|----------|-------|
| Core Infrastructure | ✅ 100% | ~100% | — |
| Data Models | ✅ 86% | ~92% | 310+ |
| ESC/P Commands | ✅ 100% | >95% | 420+ |
| Barcode Generation | ✅ 100% | ~95% | 85+ |
| Security (Crypto) | ✅ 100% | ~95% | 180+ |
| Security (Auth) | ✅ 98% | 98.67% | 616+ | MFA flow complete (Password + FIDO2/TOTP/Backup Codes) |
| Security (Audit/Blanks/Compliance) | ✅ 100% | >90% | — |
| Document Types & Indexing | 📋 TODO | — | — |
| Document Constructor | 📋 TODO | ~75% | 95+ |
| Document Rendering (ESC/P) | 📋 TODO | — | — |
| Printer Adapters | 📋 TODO | — | — |
| GUI (View) | ❌ 0% | — | — |
| Controllers/Services | ❌ 0% | — | — |

**Total: ~2,766 active tests, ~80% overall coverage**

### Development Priorities (Q2 2026)

1. `documents/types/` + `documents/constructor/` — refactor from form/
2. `documents/printing/` — ESC/P render pipeline
3. `printer/` — transport adapters
4. GUI (View) + Controllers — Tkinter interface
5. Integration testing — GUI ↔ Service layer

## Floppy Disk Optimization

Full compatibility with **3.5-inch floppy disks** (1.44 MB) for document exchange in air-gap environments. Optimization is optional and enabled per user preference.

```python
MAX_FLOPPY_BYTES = 1_340_000    # ~1.28 MB (with FAT12 headroom)
```

| Operation | Floppy-Friendly | Size | Full-Size | Size |
|-----------|----------------|------|-----------|------|
| Signature | Ed25519 | 64 B | ML-DSA-65 | 3,309 B |
| Encryption | AES-256-GCM | +28 B | Hybrid (ML-KEM + AES) | ~1.5 KB |
| Hashing | BLAKE2b | 32 B | SHA3-512 | 64 B |

`FloppyOptimizer` automatically substitutes algorithms for floppy-friendly counterparts. Each algorithm in `AlgorithmMetadata` has a `floppy_friendly: bool` flag.

> Floppy compatible — just because I love retro tech. And because I can.

## Technology Stack

**Core:**
- Python 3.11+ (3.13 compatible)
- Tkinter (GUI)
- MVC + Service Layer architecture

**Cryptography:**
- `cryptography` (PyCA) — AES, Ed25519, ECDSA, RSA, X25519, HKDF
- `liboqs-python` (≥0.15) — ML-KEM-768, ML-DSA-65, SPHINCS+, Falcon
- `argon2-cffi` — Argon2id password hashing

**Hardware Security:**
- `python-fido2` — CTAP2 direct attestation
- `pyscard` (≥2.0) — PIV, OpenPGP card access
- `yubikey-manager` (≥5.0) — YubiKey management

**Dependencies:**
- Pillow 10.0+ (image processing)
- openpyxl 3.1+ (Excel import)
- qrcode 7.4+ (QR generation)
- python-barcode 0.15+ (1D barcode generation)
- pywin32 306+ (Windows printer API)
- pycups 2.0+ (Linux CUPS)

**Development:**
- pytest 8.0+ / pytest-cov / hypothesis
- mypy 1.8+ (`--strict`)
- Black 24.0+ / isort 5.13+
- Bandit (security linting) / Safety (vulnerability checks)

## Documentation

| Document | Description |
|----------|-------------|
| [ARCHITECTURE_NEW.md](docs/ARCHITECTURE_NEW.md) | System architecture v3.0 — modules, data flow, file formats |
| [API_REFERENCE.md](docs/API_REFERENCE.md) | API reference for all public modules |
| [PROJECT_CONTEXT.md](docs/PROJECT_CONTEXT.md) | Project context for AI-assisted development |
| [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) | Security architecture v2.1 — crypto, auth, Protected Blanks |
| [SECURITY_SETUP.md](docs/SECURITY_SETUP.md) | Security setup guide — initial configuration, key ceremony |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

MIT License — see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Epson ESC/P Reference Manual
- PyCA `cryptography` library
- Open Quantum Safe (`liboqs`) project
- Matrix printer enthusiasts

## Contact

- GitHub Issues: [Report bug or request feature](https://github.com/Mike-voyager/FX-Text-processor-3/issues)
- Discussions: [Ask questions](https://github.com/Mike-voyager/FX-Text-processor-3/discussions)

---

**Status:** Active Development | **Version:** 0.2.0-alpha | **Last Updated:** March 2026
