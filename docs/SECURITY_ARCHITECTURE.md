# Security Architecture

**Document Version:** 2.1  
**Date:** March 2026  
**Status:** Living document — tracks implementation progress  
**Project:** FX Text Processor 3  

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Principles](#architecture-principles)
3. [Project Structure](#project-structure)
4. [Cryptographic Stack](#cryptographic-stack)
5. [Authentication System](#authentication-system)
6. [Hardware Security](#hardware-security)
7. [Protected Blanks — Security Layer](#protected-blanks--security-layer)
8. [FormHistory Security](#formhistory-security)
9. [Template Signing](#template-signing)
10. [Approval Workflow Security](#approval-workflow-security)
11. [Audit Logging](#audit-logging)
12. [Application Integrity](#application-integrity)
13. [Session Lock](#session-lock)
14. [Secure Erasure](#secure-erasure)
15. [Monitoring & Health Checks](#monitoring--health-checks)
16. [Backup & Key Recovery](#backup--key-recovery)
17. [Future: LAN Verification](#future-lan-verification)
18. [Future: Stealth Module](#future-stealth-module)
19. [Threat Model](#threat-model)
20. [Module Status](#module-status)
21. [References](#references)

---

## Overview

FX Text Processor 3 implements a **Zero Trust, air-gap first** security
architecture. The system is designed for a single operator on a physically
isolated machine with no network connectivity required for any core operation.

**Core philosophy:**
- All security decisions are explicit — no silent defaults
- Presets encode best practices; fine-tuning is always available
- Hardware keys are first-class citizens, not add-ons
- Every sensitive operation is MFA-gated
- If the machine is destroyed, recovery is possible. If recovery material
  is lost, it is lost forever — the system makes this explicit

**Threat model summary:** Physical attacker with disk access, compromised
dependencies, malicious operator attempting to bypass audit trail.
Network attacker: not applicable (air-gap). See [Threat Model](#threat-model).

---

## Architecture Principles

### 1. Zero Trust
Every operation is authenticated and authorized regardless of context.
No action is trusted by virtue of "already being logged in."

### 2. Air-Gap First
All cryptographic operations, key generation, signing, and verification
work fully offline. Network code exists only as an isolated, opt-in layer
(`src/network/`) that is disabled unless explicitly enabled in config.

### 3. Preset + Fine-Tune
Security decisions are encoded in four presets:

| Preset | Use Case | Signing | Encryption | KDF |
|--------|----------|---------|------------|-----|
| **Standard** | Daily use | Ed25519 | AES-256-GCM | Argon2id (64MB) |
| **Paranoid** | Long-term archive | Ed25519 + ML-DSA-65 | AES-256-GCM + ChaCha20 | Argon2id (256MB) |
| **PQC** | Post-quantum first | ML-DSA-65 | AES-256-GCM | Argon2id (64MB) |
| **Legacy** | Compatibility only | RSA-PSS-4096 | AES-256-GCM | PBKDF2-SHA256 |

Every parameter in every preset can be overridden individually in Settings.
The UI always shows the active preset label and highlights any deviation.

### 4. Crypto Agility
All encrypted documents carry a version header with algorithm identifiers
and parameters. Future algorithm changes do not break existing documents —
the format version determines the decryption path.

### 5. Defense in Depth
Multiple independent layers protect each asset. Compromise of one layer
does not expose protected assets.

### 6. Explicit MFA Gate
The following operations always require master password + active second
factor (FIDO2 / TOTP / backup code):
- Application unlock after lock screen
- Hardware device provisioning (writing keys to device)
- Preset security downgrade
- Master key export / backup ceremony
- Trusted device revocation

---

## Project Structure

```
src/
├── security/
│   ├── crypto/              # ✅ Cryptographic primitives (v2.3, 30 files)
│   ├── auth/                # 🚧 Authentication (partial — see Module Status)
│   ├── audit/               # ✅ Immutable audit log
│   ├── blanks/              # ✅ Blank lifecycle & security layer
│   ├── compliance/          # ✅ GDPR, retention, anonymization
│   ├── hardware/            # 🚧 Device registry & backends
│   ├── integrity/           # ✅ Complete — App hash check, config signature
│   ├── lock/                # ✅ Complete — SessionLockManager, AutoLockService
│   ├── erasure.py           # ✅ Complete — secure wipe (memory, files, clipboard)
│   └── monitoring/          # ✅ Complete — HealthChecker, 6 checks
│
├── documents/               # 🚧 Template engine, blank constructor, renderer
│   ├── templates/           # Type hierarchy, field schema, inheritance
│   ├── format/              # Document versioning & migration
│   └── printing/            # ESC/P render pipeline
│
├── backup/                  # 📋 TODO — key ceremony, Shamir SSS, paper key
├── network/                 # 📋 TODO — LAN verifier (opt-in, flag-enabled)
└── stealth/                 # 📋 TODO — steganography (future)
```

### `security/crypto/` internal structure (v2.3)

```
security/crypto/
├── core/                    # Protocols, metadata, registry, exceptions
│   ├── __init__.py
│   ├── protocols.py         # 8 typed Protocol interfaces
│   ├── metadata.py          # AlgorithmMetadata, SecurityLevel, FloppyFriendly
│   ├── registry.py          # AlgorithmRegistry (thread-safe singleton)
│   └── exceptions.py        # CryptoError hierarchy
│
├── algorithms/              # 46 implemented algorithms
│   ├── symmetric.py         # AES-256-GCM, ChaCha20-Poly1305, AES-GCM-SIV...
│   ├── signing.py           # Ed25519, ML-DSA, SLH-DSA, Falcon, ECDSA, RSA-PSS
│   ├── asymmetric.py        # RSA-OAEP (2048/3072/4096)
│   ├── key_exchange.py      # X25519, X448, ECDH, ML-KEM (Kyber)
│   ├── hashing.py           # SHA3-256, BLAKE2b, BLAKE3, SHA-256/512
│   └── kdf.py               # Argon2id, PBKDF2, HKDF, Scrypt
│
├── advanced/                # Composite schemes
│   ├── hybrid_encryption.py # KEX + symmetric, PQC support
│   ├── group_encryption.py  # Multi-recipient
│   ├── key_escrow.py        # Dual-key escrow
│   └── session_keys.py      # PFS / ratcheting
│
├── service/                 # Unified API
│   ├── crypto_service.py    # CryptoService — main entry point
│   ├── ui_helpers.py        # Badges, algorithm info for UI
│   └── profiles.py          # CryptoProfile enum → preset configs
│
├── utilities/               # Supporting infrastructure
│   ├── utils.py             # NonceManager, SecureMemory, key generation
│   ├── config.py            # CryptoConfig per preset
│   ├── passwords.py         # PasswordHasher (Argon2id)
│   ├── secure_storage.py    # Encrypted keystore (.fxskeystore.enc)
│   ├── key_rotation.py      # Key rotation & migration
│   ├── key_formats.py       # PEM, DER, PKCS#8, JWK import/export
│   ├── nonce_manager.py     # Nonce uniqueness guarantees
│   └── floppy_optimizer.py  # 1.44 MB optimization helpers
│
├── hardware/                # Hardware crypto operations
│   └── hardware_crypto.py   # HardwareCryptoManager (PIV, OpenPGP, OTP)
│
├── monitoring/              # Health checks at startup
│   ├── __init__.py          # Public API
│   ├── exceptions.py        # HealthCheckError hierarchy
│   ├── models.py            # HealthCheckStatus, HealthCheckResult, HealthCheckReport
│   ├── health_checker.py    # HealthChecker registry
│   └── checks/              # Individual checks
│       ├── entropy_check.py   # /dev/random entropy
│       ├── keystore_check.py  # Keystore health
│       ├── device_check.py     # Hardware devices
│       ├── algorithm_check.py  # Crypto algorithms
│       ├── audit_chain_check.py # Audit log integrity
│       └── config_check.py     # Config signature
```

---

## Cryptographic Stack

### Algorithm Registry

All 46 algorithms are registered in `AlgorithmRegistry` with rich metadata:
security level, compliance tags, performance class, floppy-friendly rating,
availability check (optional library dependencies).

```python
from src.security.crypto.core.registry import AlgorithmRegistry

registry = AlgorithmRegistry.get_instance()

# Recommended usage — via registry
signer = registry.create("ML-DSA-65")
private_key, public_key = signer.generate_keypair()
signature = signer.sign(private_key, message)

# Or via CryptoService (preferred in application code)
from src.security.crypto.service.crypto_service import CryptoService
cs = CryptoService(profile="paranoid")
signature = cs.sign_document(document, private_key)
```

### Signing Algorithms

| Algorithm | Standard | Security Level | Sig Size | Status |
|-----------|----------|---------------|----------|--------|
| **Ed25519** | RFC 8032 | 128-bit | 64 B | ✅ Recommended |
| **Ed448** | RFC 8032 | 224-bit | 114 B | ✅ High security |
| **ML-DSA-44** | FIPS 204 | NIST L2 | 2,420 B | ✅ PQC standard |
| **ML-DSA-65** | FIPS 204 | NIST L3 | 3,309 B | ✅ PQC recommended |
| **ML-DSA-87** | FIPS 204 | NIST L5 | 4,627 B | ✅ PQC paranoid |
| **SLH-DSA-SHA2-128s** | FIPS 205 | NIST L1 | 7,856 B | ✅ Hash-based PQC |
| **SLH-DSA-SHA2-192s** | FIPS 205 | NIST L3 | 16,224 B | ✅ Hash-based PQC |
| **SLH-DSA-SHA2-256s** | FIPS 205 | NIST L5 | 29,792 B | ✅ Hash-based PQC |
| **Falcon-512** | NIST L1 | NIST L1 | ~666 B | ✅ Compact PQC |
| **Falcon-1024** | NIST L5 | NIST L5 | ~1,280 B | ✅ Compact PQC |
| **ECDSA-P256/384/521** | FIPS 186 | 128-256-bit | 64-132 B | ✅ Standard |
| **RSA-PSS-2048/3072/4096** | PKCS#1 | 112-140-bit | 256-512 B | ✅ Standard |
| **Dilithium2/3/5** | — | — | — | ⚠️ DEPRECATED → use ML-DSA |
| **SPHINCS+-\*** | — | — | — | ⚠️ DEPRECATED → use SLH-DSA |

> **Migration note:** liboqs 0.15+ removes Dilithium and SPHINCS+ names.
> Use ML-DSA and SLH-DSA exclusively. Legacy classes remain in registry
> with `ImplementationStatus.DEPRECATED` but will fail at runtime with
> liboqs ≥ 0.15.

**Hybrid signing (Paranoid preset):**

```python
# Ed25519 (classical) + ML-DSA-65 (post-quantum)
# Both signatures must be valid for verification to pass

from src.security.crypto.algorithms.signing import Ed25519Signer, MLDSA65Signer

def hybrid_sign(message: bytes) -> tuple[bytes, bytes]:
    classical_sig = Ed25519Signer().sign(classical_private, message)
    pqc_sig       = MLDSA65Signer().sign(pqc_private, message)
    return classical_sig, pqc_sig
```

### Symmetric Encryption

| Algorithm | Type | Key | Status |
|-----------|------|-----|--------|
| **AES-256-GCM** | AEAD | 256-bit | ✅ Default |
| **ChaCha20-Poly1305** | AEAD | 256-bit | ✅ Alternative |
| **XChaCha20-Poly1305** | AEAD | 256-bit | ✅ Extended nonce |
| **AES-256-GCM-SIV** | AEAD | 256-bit | ✅ Nonce-misuse resistant |
| **AES-256-OCB** | AEAD | 256-bit | ✅ Standard |
| **AES-256-SIV** | Deterministic | 512-bit | ✅ Deterministic |
| **AES-256-CTR** | Stream | 256-bit | ⚠️ Non-AEAD, use with HMAC |
| **3DES-EDE3** | Block | 168-bit | ⚠️ Legacy only |
| **DES** | Block | 56-bit | ⛔ Broken, compat only |

### Key Derivation

| Algorithm | Memory | Time | Status |
|-----------|--------|------|--------|
| **Argon2id** | 64 MB (Standard) / 256 MB (Paranoid) | 3–5 iter | ✅ Default |
| **Scrypt** | configurable | configurable | ✅ Alternative |
| **PBKDF2-SHA256** | minimal | 600k iter | ⚠️ Legacy preset |
| **HKDF-SHA256** | — | — | ✅ Key expansion only |

### Key Exchange

| Algorithm | Type | Status |
|-----------|------|--------|
| **X25519** | ECDH | ✅ Default |
| **X448** | ECDH | ✅ High security |
| **ML-KEM-512/768/1024** | PQC KEM | ✅ Post-quantum |
| **ECDH-P256/384/521** | ECDH | ✅ Standard |

### Hashing

SHA3-256 for document integrity, BLAKE2b for performance-critical paths,
BLAKE3 for streaming, SHA-256/512 for compatibility.

---

## Authentication System

### MFA Architecture

```
┌─────────────────────────────────┐
│         Application Start       │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│   Integrity Check (at startup)  │
│   - App binary hash             │
│   - Config signature            │
│   - Keystore accessibility      │
└──────────────┬──────────────────┘
               │ ✓ pass
               ▼
┌─────────────────────────────────┐
│    Factor 1: Master Password    │
│    Argon2id — 64/256 MB         │
└──────────────┬──────────────────┘
               │ ✓ valid
               ▼
┌─────────────────────────────────┐
│    Factor 2 (one of):           │
│    - FIDO2/CTAP2 (primary)      │
│    - TOTP (backup)              │
│    - Backup code (last resort)  │
└──────────────┬──────────────────┘
               │ ✓ valid
               ▼
┌─────────────────────────────────┐
│    Session created              │
│    Keys loaded into SecureMemory│
└─────────────────────────────────┘
```

### FIDO2 / CTAP2

The application uses **FIDO2 CTAP2 directly** via `python-fido2`
(`CtapHidDevice`). This is a **native desktop** application — WebAuthn
(browser API with origin binding) is not used.

```python
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2

# Enumerate connected FIDO2 devices
devices = list(CtapHidDevice.list_devices())

# Authenticate
ctap = Ctap2(devices[0])
assertion = ctap.get_assertion(rp_id, client_data_hash, allow_list)
```

**Supported authenticators:**

- YubiKey 5 Series (USB-A, USB-C, NFC, Lightning)
- J3R200 with FIDO2 applet (if provisioned)
- Any CTAP2-compliant device

### TOTP

Software TOTP — compatible with KeePassXC, Aegis, andOTP, and any
RFC 6238 authenticator. Seeds are stored encrypted in the keystore,
never in plaintext.

```python
from src.security.auth.totp_service import TOTPService

totp = TOTPService()
is_valid = totp.verify(user_id="operator", code="123456")
```

> **Why software TOTP, not hardware OATH?**
> The operator uses the same YubiKey for FIDO2 (primary). Software TOTP
> via KeePassXC provides independence from device availability. Hardware
> OATH on YubiKey (ykman oath) is a future optional enhancement.

### Backup Codes

Single-use codes generated at account setup. Stored as Argon2id hashes.
Each code is consumed on use and cannot be reused. The operator is
expected to store them physically (printed, in a safe).

### MFA-Gated Critical Operations

The following require **master password + second factor**, regardless of
active session:

- `provision_device()` — writing keys to hardware token
- `revoke_device()` — removing a trusted device
- `export_master_key()` — backup ceremony
- `downgrade_security_preset()` — e.g., Paranoid → Standard
- `import_key_to_device()` — key copy mode (with warning)

### Module Status

| File | Status | Coverage | Tests |
|------|--------|----------|-------|
| `password.py` | ✅ Complete | 97.65% | 329+ |
| `password_service.py` | ✅ Complete | 100.00% | 231+ |
| `second_factor.py` | ✅ Complete | 98.39% | 283+ |
| `second_factor_service.py` | ✅ Complete | 100.00% | 79+ |
| `fido2_service.py` | ✅ Complete | 94.59% | 64+ |
| `totp_service.py` | ✅ Complete | 96.90% | 263+ |
| `code_service.py` | ✅ Complete | 100.00% | 101+ |
| `session.py` | ✅ Complete | 98.08% | 329+ |
| `session_service.py` | ✅ Complete | 100.00% | 66+ |
| `permissions.py` | ✅ Complete | 100.00% | 165+ |
| `permissions_service.py` | ✅ Complete | 100.00% | 53+ |
| `auth_service.py` | ✅ Complete | 100.00% | 94+ |
| `second_method/` | ✅ Complete | 99.25-100% | 336+ |

> ✅ **Status Update (March 2026):** All auth modules are now fully implemented with comprehensive test coverage (98.67% overall). The complete MFA flow (Password + FIDO2/TOTP/Backup Codes) is production-ready and awaiting GUI integration.

---

## Hardware Security

### Supported Devices

| Device | PIV | OpenPGP | FIDO2/CTAP2 | OATH TOTP | OTP |
|--------|-----|---------|-------------|-----------|-----|
| **YubiKey 5 NFC** | ✅ | ✅ | ✅ | ✅ (future) | ✅ |
| **J3R200 (JCOP4 P71)** | ✅ (PivApplet) | ✅ (SmartPGP) | ❌ | ✅ (OATH applet) | ❌ |

**J3R200 capabilities (NXP JCOP4 P71):**

- JavaCard 3.0.5, GlobalPlatform 2.3, CC EAL 6+
- 200 KB Flash, dual interface (contact + NFC)
- Hardware: AES-256, RSA-3072, ECDSA P-256/384/521
- Physical Unclonable Function (PUF) — clone-resistant

### Device Registry

Up to **5–7 trusted devices** per operator. The registry is a signed
document stored in the keystore:

```python
@dataclass
class TrustedDevice:
    device_id: str              # UUID
    label: str                  # "YubiKey Primary", "J3R200 Backup"
    device_type: DeviceType     # YUBIKEY / SMARTCARD
    protocol: DeviceProtocol    # PIV / OPENPGP
    public_keys: dict[str, bytes]  # slot_name → public key bytes
    priority: int               # 1 = highest, used for auto-selection
    added_at: datetime
    last_used: datetime
    status: DeviceStatus        # ACTIVE / REVOKED / COMPROMISED
```

The registry file is signed with the master key. Any modification without
re-signing is detected at load time.

### Key Models

**⚠️ Two modes are supported. Read carefully before choosing.**

#### Mode A: Multi-Key Trust (Recommended)

Each device generates its own keypair on-board. The public key is
registered in the device registry. Any device in the registry can
authenticate or sign independently.

```
YubiKey  → generates Key_A on-board → exports public_A → registry
J3R200   → generates Key_B on-board → exports public_B → registry
Backup   → generates Key_C on-board → exports public_C → registry

Verification: signature by Key_A OR Key_B OR Key_C → valid
```

- ✅ Private key never leaves the device
- ✅ Compromise of one device does not compromise others
- ✅ YubiKey's `generate_key_onboard()` guarantee is preserved
- ⚠️ Documents signed by different devices use different keys

#### Mode B: Key Copy (Use With Explicit Awareness)

One keypair is generated externally, then imported to multiple devices.
Any device holds the same private key.

```
Generate Key_X offline → import to YubiKey → import to J3R200 → import to Backup

Verification: signature by Key_X → valid (regardless of which device signed)
```

- ✅ All devices are interchangeable — same key everywhere
- ✅ Simpler verification (one public key for all devices)
- ⛔ **Private key exists outside hardware during import**
- ⛔ **Compromise of any device = compromise of Key_X**
- ⛔ Not compatible with YubiKey's "never exportable" security guarantee

> **UI behavior:** Mode B is available but shows a mandatory warning dialog
> before `import_key_to_device()`. The dialog requires explicit confirmation
> and is logged in the audit trail.

### Protocol Backends

#### PIV Backend (YubiKey + J3R200 with PivApplet)

Slots:

| Slot | Hex | Purpose |
|------|-----|---------|
| Authentication | 9A | Login / FIDO equivalent |
| Digital Signature | 9C | Document signing |
| Key Management | 9D | Encryption / ECDH |
| Card Auth | 9E | Card-only auth (no PIN required) |

```python
from src.security.crypto.hardware.hardware_crypto import HardwareCryptoManager

mgr = HardwareCryptoManager()

# Sign with PIV slot 9C
signature = mgr.sign_with_device(
    card_id="yubikey-001",
    slot=0x9C,
    message=document_bytes,
    pin="123456"
)

# ECDH key agreement (slot 9D) — private key never leaves device
shared_secret = mgr.ecdh_with_device(
    card_id="yubikey-001",
    slot=0x9D,
    peer_public_key=recipient_public_key,
    pin="123456"
)
```

#### OpenPGP Backend (YubiKey native + J3R200 with SmartPGP)

Three slots: Sign, Encrypt (ECDH), Authenticate.
Algorithms: Ed25519, X25519, ECDSA, RSA up to 4096.

```python
# OpenPGP signing — Ed25519 on Sign slot
signature = mgr.openpgp_sign(
    card_id="j3r200-001",
    data=document_bytes,
    pin="123456"
)

# Get all three public keys
keys = mgr.openpgp_get_public_keys(card_id="j3r200-001")
# keys = {"sign": b"...", "encrypt": b"...", "authenticate": b"..."}
```

> **Unified protocol:** Both YubiKey and J3R200 (with SmartPGP) implement
> OpenPGP card spec 3.4. The same `OpenPGPBackend` class handles both.
> APDU transport via `pyscard`. No additional Python dependencies required.

#### Hardware Ed25519 Bridge

```python
from src.security.hardware.hardware_crypto import HardwareEd25519Signer

# Drop-in compatible with signing.py SigningProtocol
signer = HardwareEd25519Signer(manager=mgr, card_id="yubikey-001")
signature = signer.sign(private_key=None, message=document_bytes)
# Private key stays on device — private_key param is ignored

is_valid = signer.verify(public_key=pub_key, message=document_bytes,
                          signature=signature)
# Verification is always software-side (only public key needed)
```

### Device Routing

When multiple devices are available, the routing priority is:

1. **Explicit selection** — user selects device in UI for this operation
2. **Preset default** — active security preset specifies preferred protocol
3. **User-configured priority** — ordered list in device registry
4. **First available** — fallback

The routing table is configurable in Settings → Hardware → Device Priority.

### Management Key (PIV Administrative Operations)

PIV operations like key generation and import require the management key
(default: `010203040506070801020304050607080102030405060708`).

> **Security requirement:** Change the default management key on every
> new YubiKey before use. The application will warn if the default key
> is detected. Management key operations are MFA-gated.

### Provisioning: Writing Keys to a Device

This is a **critical operation** — gated by MFA (master password +
second factor).

```
┌──────────────────────────────────┐
│  User initiates provisioning      │
└──────────────┬───────────────────┘
               │
               ▼
┌──────────────────────────────────┐
│  MFA challenge                   │
│  Password + FIDO2/TOTP/code      │
└──────────────┬───────────────────┘
               │ ✓
               ▼
┌──────────────────────────────────┐
│  Choose mode:                    │
│  A) Generate on-board (default)  │
│  B) Import existing key ⚠️       │
└──────────────┬───────────────────┘
               │
               ▼ (mode A)
┌──────────────────────────────────┐
│  Device generates keypair        │
│  App receives public key only    │
│  Public key added to registry    │
│  Registry re-signed              │
│  Event logged to audit trail     │
└──────────────────────────────────┘
```

---

## Protected Blanks — Security Layer

> **Scope:** This module (`security/blanks/`) handles only the security
> aspects of blanks: lifecycle state machine, cryptographic signing,
> and verification. Document structure, field definitions, type hierarchy,
> and rendering live in `src/documents/`.

### Lifecycle

```
ISSUED ──────────────────────────────────► SPOILED
  │                                         (physical damage)
  ▼
READY ──────────────────────────────────► VOIDED
  │                                         (max attempts exceeded)
  ▼
PRINTED
  │
  ▼
ARCHIVED  (retention: 7 years default, configurable)
```

### Cryptographic Identity

Each blank has a unique cryptographic identity:

```python
@dataclass
class ProtectedBlank:
    blank_id: str                    # UUID v4
    series: str                      # Alphanumeric code, e.g. "INV-A"
    number: int                      # Sequential within series
    blank_type: str                  # Registered type from documents/templates
    security_preset: str             # "standard" / "paranoid" / "pqc"

    # Signing identity (depends on active mode)
    signing_mode: SigningMode        # SOFTWARE / HARDWARE_PIV / HARDWARE_OPENPGP
    signing_device_id: str | None   # device_id from TrustedDevice registry
    signature_algorithm: str        # "Ed25519" / "ML-DSA-65" / ...
    public_key: bytes               # Verifying key (stored with blank)
    certificate_id: str | None      # X.509 cert reference, if CA mode enabled

    issued_to: str
    status: BlankStatus
    serial_counter: int              # From keystore counter (monotonic)
```

### Signing

```python
from src.security.blanks.manager import BlankManager

mgr = BlankManager(audit_log=audit, crypto_service=cs, hw_manager=hw_mgr)

# Sign document on blank (software)
signature = mgr.sign_blank(
    blank_id="uuid-...",
    document_content=document_bytes,
    pin=None  # software signing uses keystore key
)

# Sign document on blank (hardware)
signature = mgr.sign_blank(
    blank_id="uuid-...",
    document_content=document_bytes,
    device_id="yubikey-001",
    pin="123456"
)
```

### Serial Counter

Blank serial numbers use a **monotonic counter in the keystore**. The
counter is increment-only; no decrement or reset is possible without
MFA + explicit confirmation.

```python
# Current: software counter in secure_storage
counter = keystore.increment_counter("blank_series_INV-A")

# Future: sync to J3R200 hardware counter applet
# Hardware counter provides physical tamper-resistance
# (planned — see hardware_crypto_roadmap.md)
```

### Verification

**Two modes — both always available:**

**Offline (primary):** QR code on printed document contains all data
needed for standalone verification. No network required.

```json
{
  "blank_id": "550e8400-e29b-41d4-a716-446655440000",
  "series": "INV-A",
  "number": 42,
  "content_hash_sha3": "a3f2c5d8...",
  "signature": "7f3e9a1b...",
  "public_key": "2c8d4f6a...",
  "algorithm": "Ed25519",
  "preset": "standard",
  "printed_at": "2026-03-11T18:00:00Z",
  "format_version": "1.0"
}
```

```python
from src.security.blanks.verification import verify_blank

result = verify_blank(
    qr_data=parsed_qr,
    printed_content=document_bytes
)

if result.authentic:
    print(f"✓ Valid blank {result.series}-{result.number:04d}")
else:
    print(f"⚠️ Verification failed: {result.reason}")
```

**LAN (future, opt-in):** Verification request to a local network server
(Raspberry Pi or local workstation). Enabled only if `network.enabled=true`
in config. See [Future: LAN Verification](#future-lan-verification).

### CA Mode (Optional)

When enabled in Settings → Blanks → Certificate Authority:

```
Root CA cert (stored in: keystore / J3R200 / external file)
  └── Signs operator certificate
        └── Operator cert signs blank documents
              └── Verification checks full chain
```

CA mode is **optional and disabled by default**. When disabled, each blank
carries its own standalone public key — verification requires no chain.
CA mode allows: verifying document authenticity without the original device,
building trust chains for multi-operator scenarios (future).

### Form Validation Before Signing

Перед криптографической подписью документа выполняется обязательная валидация формы:

```python
from src.security.blanks.validation import FormValidator, ValidationPolicy

validator = FormValidator(
    policy=ValidationPolicy.STRICT,  # STRICT | LENIENT | CUSTOM
    require_all_mandatory=True,     # Все обязательные поля должны быть заполнены
    validate_cross_fields=True,     # Проверка кросс-полевых правил
    check_schema_version=True       # Проверка версии схемы
)

result = validator.validate(document, schema)

if not result.is_valid:
    # Подпись блокируется при ошибках валидации
    audit.log_event(
        AuditEventType.BLANK_SIGNING_BLOCKED,
        details={
            "blank_id": blank_id,
            "validation_errors": result.field_errors,
            "cross_field_errors": result.cross_field_errors
        }
    )
    raise FormValidationError(f"Signing blocked: {result.errors}")
```

**Уровни политики валидации:**

| Политика | Описание | Применение |
|----------|----------|------------|
| `STRICT` | Все правила обязательны, включая кросс-полевые | Production, финальные документы |
| `LENIENT` | Только базовые проверки (типы, обязательность) | Черновики, предварительный просмотр |
| `CUSTOM` | Пользовательский набор правил | Специальные сценарии |

**Проверки валидации:**

1. **Обязательные поля** — все поля с `required=True` должны быть заполнены
2. **Типы данных** — соответствие declared type (число, дата, email и т.д.)
3. **Форматы** — regex-паттерны, маски ввода
4. **Диапазоны** — min/max для чисел и дат
5. **Кросс-полевая валидация** — зависимости между полями (например, "дата окончания > даты начала")
6. **Условная обязательность** — `required_if` правила
7. **Ссылочная целостность** — внешние ссылки (Excel-импорт) актуальны

**Безопасность:**

- Валидация выполняется **до** доступа к приватному ключу подписи
- Ошибки валидации логируются в audit trail с полным контекстом
- Попытка подписать невалидную форму считается security event
- MFA не требуется для валидации (только для самой подписи)

---

## FormHistory Security

> **Module:** `src/documents/constructor/form_history.py`

FormHistory stores sensitive form field values (client names, amounts, addresses) that may constitute PII. Security considerations apply to storage, retention, and access.

### Encryption at Rest

```python
@dataclass
class FormHistoryStorage:
    """Шифрованное хранилище истории."""

    def __init__(self, key: bytes):
        self.key = key
        self.cipher = AES256GCM(key)

    def save(self, entries: list[HistoryEntry]) -> None:
        # Сериализация
        data = json.dumps([e.to_dict() for e in entries]).encode()
        # Сжатие
        compressed = gzip.compress(data)
        # Шифрование
        nonce = os.urandom(12)
        ciphertext = self.cipher.encrypt(compressed, nonce)
        # HMAC для целостности
        hmac = HMAC(self.key).compute(ciphertext)
        # Запись
        with open(HISTORY_FILE, "wb") as f:
            f.write(nonce + ciphertext + hmac)
```

**Security features:**
- AES-256-GCM encryption with dedicated key (derived from master key)
- Gzip compression before encryption (reduces plaintext pattern leakage)
- HMAC-SHA256 for integrity verification (detects tampering)
- 12-byte random nonce for each save operation

### Retention Policy (GDPR Compliance)

```python
class FormHistory:
    def enforce_retention_policy(self) -> None:
        """Применяет политику хранения."""
        # Удаляем записи старше 90 дней
        self.clear_old_entries(days=90)
        # Ограничиваем общее количество
        self.enforce_max_entries()
        # Анонимизируем старые записи (удаляем document_index)
        cutoff = datetime.now() - timedelta(days=30)
        for field_entries in self._cache.values():
            for entry in field_entries:
                if entry.timestamp < cutoff:
                    entry.document_index = None  # Remove PII
```

**Retention rules:**
- Default retention: 90 days (configurable)
- Max entries: 10,000 per field (configurable)
- Automatic anonymization after 30 days (document_index → None)
- Explicit user action "Clear History" — immediate wipe with secure overwrite

### Data Minimization

```python
def sanitize_value(value: str, field_type: FieldType) -> str:
    """Очищает значение перед сохранением в историю."""
    # Не сохраняем пароли
    if field_type == FieldType.PASSWORD:
        return "[REDACTED]"
    # Маскируем номера карт
    if field_type == FieldType.CREDIT_CARD:
        return "****-****-****-" + value[-4:]
    # Маскируем SSN
    if field_type == FieldType.SSN:
        return "***-**-" + value[-4:]
    return value
```

### Audit Events

| Event | Type | Trigger |
|-------|------|---------|
| `form_history.entry_added` | INFO | New value added to history |
| `form_history.retention_enforced` | INFO | Automatic cleanup executed |
| `form_history.cleared` | WARNING | User requested full clear |
| `form_history.integrity_failed` | ERROR | HMAC verification failed |

---

## Template Signing

> **Module:** `src/documents/constructor/template_library.py`

Templates (`.fxstpl`) are signed to prevent tampering and ensure authenticity. This is critical because templates define document structure and field validation rules.

### Signing Architecture

```
Template Content (JSON)
    ↓
Gzip compression
    ↓
AES-256-GCM encryption (optional, for sensitive templates)
    ↓
Ed25519 signature (master key)
    ↓
.fxstpl file format
```

### File Format

```python
@dataclass(frozen=True)
class TemplateFile:
    """Файл шаблона .fxstpl."""

    # Header (16 bytes)
    magic: bytes = b"FXSTPL"      # 6 bytes
    version: int = 1              # 2 bytes (uint16)
    reserved: bytes = b"\x00" * 8  # 8 bytes

    # Metadata (encrypted if sensitive)
    metadata: TemplateMetadata

    # Content (encrypted)
    schema: TypeSchema
    layout: TemplateLayout
    fields: list[FieldDefinition]

    # Signature (64 bytes for Ed25519)
    signature: bytes
```

### Verification on Import

```python
def import_with_verification(self, source_path: Path) -> TemplateInfo:
    """Импорт с полной верификацией."""

    # 1. Проверка подписи
    if not self._verify_signature(source_path):
        raise SecurityError("Template signature invalid")

    # 2. Проверка целостности
    if not self._verify_integrity(source_path):
        raise SecurityError("Template corrupted")

    # 3. Проверка на вредоносные поля
    template = self._load_template(source_path)
    if self._contains_suspicious_fields(template):
        raise SecurityError("Template contains suspicious fields")

    # 4. Проверка цепочки доверия
    if not self._verify_trust_chain(template):
        raise SecurityError("Template not in trust chain")

    # Импорт
    return self._import_template(template)
```

### Trust Chain

```python
def _verify_trust_chain(self, template: Template) -> bool:
    """Проверяет цепочку доверия для шаблона извне."""

    # Проверяем, что подпись сделана известным ключом
    public_key = template.signature_public_key

    # Проверяем против whitelist
    if public_key not in self.trusted_keys:
        return False

    # Проверяем timestamp (не старше 1 года)
    if template.created_at < datetime.now() - timedelta(days=365):
        return False

    return True
```

**Security considerations:**
- Unsigned templates are rejected by default (configurable for development)
- Template modifications invalidate signature
- Import from physical media (floppy/USB) requires same verification as network transfer
- Template version upgrades preserve signature chain

### Audit Events

| Event | Type | Trigger |
|-------|------|---------|
| `template.imported` | INFO | Template successfully imported |
| `template.exported` | INFO | Template exported to media |
| `template.signature_invalid` | ERROR | Import rejected — bad signature |
| `template.trust_chain_failed` | ERROR | Import rejected — unknown signer |

---

## Approval Workflow Security

> **Module:** `src/documents/constructor/approval_workflow.py`

Single-operator workflow with role switching. Security focuses on preventing accidental skip of critical steps and maintaining audit trail.

### State Machine

```
┌─────────┐     ┌─────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────┐
│  DRAFT  │────▶│ FILLED  │────▶│  VALIDATED  │────▶│  APPROVED   │────▶│ SIGNED  │
└────┬────┘     └────┬────┘     └──────┬──────┘     └──────┬──────┘     └────┬────┘
     │               │              │                │               │
     ▼               ▼              ▼                ▼               ▼
  OPERATOR         EDITOR       SUPERVISOR       SIGNATORY      SIGNATORY
```

### MFA Requirements

| Transition | From → To | MFA Required | Purpose |
|------------|-----------|--------------|---------|
| DRAFT → FILLED | → EDITOR | No | Initial save |
| FILLED → VALIDATED | → SUPERVISOR | Yes | Supervisor review |
| VALIDATED → APPROVED | SUPERVISOR → SIGNATORY | Yes | Approval for signing |
| APPROVED → SIGNED | SIGNATORY → SIGNATORY | Yes | Cryptographic signature |
| Any → REJECTED | Any → | Yes | Return for correction |

### Role Switching

```python
def switch_role(self, role: WorkflowRole) -> None:
    """Переключает текущую роль оператора."""

    if role in [WorkflowRole.SUPERVISOR, WorkflowRole.SIGNATORY]:
        # Требуем MFA для высокопривилегированных ролей
        if not self.auth.verify_mfa():
            raise MFAVerificationError("MFA required for this role")

    self.current_role = role
    self.audit.log_event(
        AuditEventType.WORKFLOW_ROLE_SWITCHED,
        details={"role": role.value}
    )
```

### Field Annotations (Comments)

```python
@dataclass(frozen=True)
class FieldAnnotation:
    """Комментарий к полю в контексте workflow."""
    annotation_id: str
    field_id: str
    comment: str
    author_role: WorkflowRole  # Role at time of comment
    created_at: datetime
    resolved: bool = False
    resolved_at: datetime | None = None
    resolved_by: WorkflowRole | None = None
```

**Security:**
- Comments are never printed (audit trail only)
- Each comment records the author's role
- Resolution requires the same or higher privilege role
- Immutable after creation (new annotation supersedes)

### Preventing Skip

```python
def can_transition(self, document: Document, target: FormStatus) -> bool:
    """Проверяет, можно ли выполнить переход."""

    # Нельзя пропускать состояния
    current = document.status
    allowed_next = self._get_allowed_transitions(current)

    if target not in allowed_next:
        return False

    # Проверяем MFA если требуется
    if self._is_mfa_required(current, target):
        if not self.session.mfa_verified:
            return False

    return True
```

### Audit Trail for Workflow

Каждый переход логируется с подписью:

```json
{
  "event_type": "workflow.transition",
  "timestamp": "2026-03-21T10:30:00Z",
  "document_id": "doc-uuid",
  "from_state": "FILLED",
  "to_state": "VALIDATED",
  "role": "SUPERVISOR",
  "mfa_verified": true,
  "signature": "base64..."
}
```

### Audit Events

| Event | Type | Trigger |
|-------|------|---------|
| `workflow.role_switched` | INFO | Operator switched role |
| `workflow.transition` | INFO | Document state changed |
| `workflow.comment_added` | INFO | Field annotation created |
| `workflow.comment_resolved` | INFO | Annotation marked resolved |
| `workflow.rejected` | WARNING | Document returned for correction |
| `workflow.skip_attempted` | ERROR | Attempt to skip state (blocked) |

---

## Audit Logging

### Design

Tamper-proof, append-only event log with cryptographic hash chain.
Stored locally. No network export by default.

```
Event N-1:
  event_hash: SHA3-256(event_data)
  previous_hash: Event(N-2).event_hash
  hmac_signature: HMAC-SHA256(event_data, audit_secret)

Event N:
  event_hash: SHA3-256(event_data)
  previous_hash: Event(N-1).event_hash   ← chain link
  hmac_signature: HMAC-SHA256(event_data, audit_secret)
```

Any modification to any event breaks the hash chain → detected immediately.

### Event Types

```python
class AuditEventType(Enum):
    # Application
    APP_STARTED = "app.started"
    APP_LOCKED = "app.locked"
    APP_UNLOCKED = "app.unlocked"
    INTEGRITY_CHECK_PASSED = "integrity.passed"
    INTEGRITY_CHECK_FAILED = "integrity.failed"

    # Authentication
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILED = "auth.failed"
    AUTH_MFA_CHALLENGED = "auth.mfa_challenged"
    SECOND_FACTOR_ADDED = "auth.2fa_added"
    BACKUP_CODE_USED = "auth.backup_code_used"

    # Hardware devices
    DEVICE_PROVISIONED = "device.provisioned"
    DEVICE_REVOKED = "device.revoked"
    DEVICE_KEY_IMPORTED = "device.key_imported"   # ⚠️ logged with warning
    DEVICE_OPERATION = "device.operation"

    # Blanks
    BLANK_ISSUED = "blank.issued"
    BLANK_SIGNED = "blank.signed"
    BLANK_VERIFIED = "blank.verified"
    BLANK_VERIFY_FAILED = "blank.verify_failed"
    BLANK_VOIDED = "blank.voided"
    BLANK_SPOILED = "blank.spoiled"

    # FormHistory
    FORM_HISTORY_ENTRY_ADDED = "form_history.entry_added"
    FORM_HISTORY_RETENTION_ENFORCED = "form_history.retention_enforced"
    FORM_HISTORY_CLEARED = "form_history.cleared"
    FORM_HISTORY_INTEGRITY_FAILED = "form_history.integrity_failed"

    # Template Library
    TEMPLATE_IMPORTED = "template.imported"
    TEMPLATE_EXPORTED = "template.exported"
    TEMPLATE_SIGNATURE_INVALID = "template.signature_invalid"
    TEMPLATE_TRUST_CHAIN_FAILED = "template.trust_chain_failed"

    # Approval Workflow
    WORKFLOW_ROLE_SWITCHED = "workflow.role_switched"
    WORKFLOW_TRANSITION = "workflow.transition"
    WORKFLOW_COMMENT_ADDED = "workflow.comment_added"
    WORKFLOW_COMMENT_RESOLVED = "workflow.comment_resolved"
    WORKFLOW_REJECTED = "workflow.rejected"
    WORKFLOW_SKIP_ATTEMPTED = "workflow.skip_attempted"

    # Key management
    KEY_GENERATED = "key.generated"
    KEY_EXPORTED = "key.exported"          # MFA-gated, always logged
    KEY_BACKUP_CREATED = "key.backup"
    PRESET_DOWNGRADED = "security.preset_downgraded"  # MFA-gated

    # Security events
    ACCESS_DENIED = "access.denied"
    CONFIG_MODIFIED = "config.modified"
    CONFIG_SIGNATURE_INVALID = "config.sig_invalid"
    AUDIT_CHAIN_BROKEN = "audit.chain_broken"  # Critical
```

### Usage

```python
from src.security.audit.logger import ImmutableAuditLog

audit = ImmutableAuditLog(
    hmac_secret=keystore.get_audit_secret(),
    log_path="./data/audit.jsonl"
)

# Verify integrity
if not audit.verify_chain_integrity():
    # This event logs itself before alerting
    alert_operator("⚠️ Audit log integrity violation detected")
```

---

## Application Integrity

### App Binary Hash

At startup, the application computes a SHA3-256 hash of its own executable
and compares against a stored reference hash. If mismatch → startup aborted
with a clear error.

```python
from src.security.integrity.app_integrity import AppIntegrityChecker

checker = AppIntegrityChecker(
    reference_hash_path="./data/app.hash",
    algorithm="SHA3-256"
)

result = checker.verify()
if not result.valid:
    audit.log_event(AuditEventType.INTEGRITY_CHECK_FAILED,
                    details={"reason": result.reason})
    raise ApplicationIntegrityError(result.reason)
```

### Config Signature

The main config file (`config.fxsconfig`) is signed with the master key.
Any modification outside the application (e.g., downgrading a security
preset in a text editor) is detected at load time.

```python
from src.security.integrity.config_integrity import ConfigIntegrityChecker

# On save: sign config
checker.sign_config(config_data, master_private_key)

# On load: verify signature
if not checker.verify_config(config_data):
    raise ConfigTamperedError("Config signature invalid — possible tampering")
```

> **Threat:** An attacker with disk access could modify `config.fxsconfig`
> to downgrade encryption before the next session. Config signing prevents
> silent downgrade.

---

## Session Lock

> **Status: 📋 TODO**

### Planned Behavior

**Instant lock** — hardware button / keyboard shortcut:

- Clears all in-memory keys via `SecureMemory.wipe()`
- Blanks sensitive UI fields
- Shows lock screen
- Requires full MFA to resume

**Auto-lock** — configurable inactivity timeout:

- Default: 30 minutes
- Range: 1 minute – never (operator's choice)
- Same behavior as instant lock on trigger

**Implementation target:** `src/security/lock/session_lock.py`

---

## Secure Erasure

> **Status: 📋 TODO** — `src/security/erasure.py`

### Planned Scope

| Target | Behavior |
|--------|----------|
| `SecureMemory` objects | Zeroed on `wipe()` or context exit — ✅ already in `crypto/utils.py` |
| Temp files | Overwrite + delete after use (render temp, export temp) |
| Clipboard | Optional — cleared after configurable timeout (default: off, user-enabled) |
| PyQt widget memory | Pending research — Qt internals make this non-trivial |

> **Clipboard policy:** The operator is considered security-conscious.
> Clipboard clearing is opt-in, configurable in Settings → Privacy →
> Clear clipboard after N seconds.

---

## Monitoring & Health Checks

> **Status: ✅ Complete** — `src/security/monitoring/`

Runs at application startup and on-demand via Settings → System → Health Check.

### Implemented Checks

| Check | Description | Critical |
|-------|-------------|----------|
| `EntropyCheck` | Sufficient entropy in `/dev/random` for key generation | Yes |
| `KeystoreCheck` | Keystore file accessible, not corrupted | Yes |
| `DeviceCheck` | Which hardware devices are currently connected | No |
| `AlgorithmCheck` | All algorithms in active preset are available (liboqs, pyscard) | Yes |
| `AuditChainCheck` | Audit log hash chain is intact | Yes |
| `ConfigCheck` | Config file has not been modified externally | No |

### Architecture

```python
from src.security.monitoring import HealthChecker, HealthCheckStatus

# Create health checker
checker = HealthChecker(version="1.0.0")

# Register checks
checker.register_function("entropy", entropy_check, critical=True)
checker.register_function("keystore", keystore_check, critical=True)

# Run all checks
report = checker.run_all()

# Check results
if report.is_healthy:
    print("All checks passed")
else:
    for check in report.critical_checks:
        print(f"Failed: {check.check_name} - {check.message}")
```

Results displayed in a startup health panel (dismissible). Critical failures
(keystore corrupted, config tampered) abort startup.

---

## Compliance (GDPR)

> **Status: ✅ Complete** — `src/security/compliance/`

Implements GDPR compliance features for data protection.

### Components

| Component | Purpose |
|-----------|---------|
| `RetentionPolicyManager` | Manages data retention policies |
| `PIIAnonymizer` | Anonymizes personal identifiable information |
| `DataExportService` | Exports data for data subject requests (Art. 20) |
| `RightToErasureHandler` | Handles deletion requests (Art. 17) |

### Data Categories

```python
from src.security.compliance import DataCategory, RetentionPolicyManager

# Categories with retention periods
DataCategory.PUBLIC        # 10 years
DataCategory.INTERNAL     # 1 year
DataCategory.PII          # 1 year (anonymize)
DataCategory.SENSITIVE    # 90 days (delete)
DataCategory.FINANCIAL   # 7 years (archive, legal requirement)
DataCategory.CREDENTIALS  # 1 year (delete)
```

### Retention Policy

```python
manager = RetentionPolicyManager()

# Find expired records
expired = manager.find_expired_records(records)

# Apply retention policy
result = manager.apply_retention(records, dry_run=True)
```

### PII Anonymization

```python
from src.security.compliance import PIIAnonymizer

anonymizer = PIIAnonymizer()

# Anonymize data
data = {"email": "user@example.com", "name": "John Doe"}
anonymized = anonymizer.anonymize(data)
# {"email": "a1b2c3d4e5f6g7h8", "name": "Anonymous User"}
```

### Data Export (Right to Access)

```python
from src.security.compliance import DataExportService

service = DataExportService(data_provider=get_user_data)

# Export in JSON format
result = service.export_data(user_id, format="json", anonymize_pii=True)
```

### Right to Erasure

```python
from src.security.compliance import RightToErasureHandler

handler = RightToErasureHandler(
    data_locator=find_user_data,
    data_deleter=delete_user_data,
)

# Process erasure request
result = handler.process_request(user_id, reason="Data subject request")
```

---

## Backup & Key Recovery

> **Status: 📋 TODO** — `src/backup/`

### Philosophy

In an air-gap system with no account recovery server, **the operator is
the only recovery path**. If all backup material is lost, access to
encrypted data is permanently lost. The application makes this explicit
in a first-run wizard.

### Planned Backup Methods

**1. Encrypted keystore export**
Full keystore exported to external media (USB drive), encrypted with a
separate backup passphrase.

**2. Paper key (QR + Human-Readable Groups)**
Master key (or its Shamir share) encoded in **two redundant formats**
that contain identical payload data:

- **QR code** — for quick scanning with recovery app
- **Base58-encoded groups** — for manual entry if QR damaged

Both formats encode the same data: `Base58(key + CRC-32)`.
Either one is sufficient to recover the master key.

Encoding specification:

| Parameter | Value |
|-----------|-------|
| Input | 32-byte (256-bit) master key |
| Checksum | CRC-32 (4 bytes, via `zlib.crc32()`) |
| Payload | 36 bytes (key + CRC-32) |
| Encoding | Base58 (Bitcoin alphabet, excludes 0OIl) |
| Fixed length | 52 characters (left-padded with '1' via `rjust`) |
| Groups | 13 groups × 4 characters |

> Left-padding with '1' is safe: in Base58, leading '1' encodes a leading
> 0x00 byte, which does not change the numeric value of the payload.

Format example:

```
╔═══════════════════════════════════════════════════════╗
║  FX TEXT PROCESSOR 3 — MASTER KEY RECOVERY            ║
║  Date: 2026-03-11  |  Username: Mike Voyager          ║
╚═══════════════════════════════════════════════════════╝

┌─────────────────────────────────┐
│                                 │
│      █████████  QR CODE         │
│      █ █   █ █  SCAN WITH       │
│      █████████   RECOVERY APP   │
│      █       █                  │
│      █████████                  │
│                                 │
└─────────────────────────────────┘

MANUAL ENTRY (if QR code damaged):

  Group  1– 7:  J7K2  M9P3  W4X8  R1T5  N6H9  V2D4  L8C3
  Group  8–13:  S7B1  Q5G6  A3F8  K1X7  P9M2  T4W6

  Format:      13 groups × 4 chars = 52 characters
  Alphabet:    Base58 (no 0/O/I/l ambiguity)
  Integrity:   CRC-32 (embedded in payload before encoding)
  Key strength: 256-bit (brute-force: ~10^57 years at 1T/sec)
```

**Why both formats:**
- QR code: fast, error-resistant (Reed-Solomon ECC built-in)
- Human-readable groups: QR damage fallback, no tech required
- Both encode identical data — true interchangeable redundancy
- CRC-32 checksum detects transcription errors
- Base58 avoids ambiguous characters (0/O, I/l/1)

**Key strength:**

```
Master key: 256 bits = 2^256 ≈ 1.16 × 10^77 combinations
At 1 trillion attempts/sec: ~10^57 years to exhaust
Equivalent to AES-256 security level

Note: The 52-character Base58 representation is an encoding format.
It does not increase entropy beyond the key's 256 bits.
```

**API:**

```python
from src.backup.paper_key import PaperKeyGenerator, PaperKeyConfig

gen = PaperKeyGenerator()

config = PaperKeyConfig(
    include_qr=True,
    include_groups=True,
    username="Mike Voyager"
)

gen.generate_pdf(
    master_key=master_key,
    output_path="./fx-paper-key.pdf",
    config=config
)
```

**3. Shamir's Secret Sharing**
Master key split into N shares, any K of N required to reconstruct.
Example: 3-of-5 — store shares in 5 different locations, any 3 suffice.

```python
from src.backup.shamir import ShamirSecretSharing

# Split
shares = ShamirSecretSharing.split(secret=master_key, n=5, k=3)

# Reconstruct (any 3 of 5)
recovered = ShamirSecretSharing.combine(shares=[share1, share3, share5])
```

**4. Device registry backup**
Signed device registry exported separately — allows re-establishing
trusted devices after a machine wipe.

### Recovery Ceremony

Restoring from backup is a **critical MFA-gated operation**. The ceremony
wizard guides the operator through:

1. Reconstruct master key (Shamir / paper key / encrypted export)
2. Verify key authenticity (HMAC check)
3. Re-provision hardware devices (or import device registry)
4. Verify audit log continuity

---

## Future: LAN Verification

> **Status: 📋 TODO** — `src/network/`
> **Activation:** Config flag `network.lan_verifier.enabled = true`

The LAN verifier is a **completely isolated network layer**. It has no
shared code with any other security module except the verification logic
from `security/blanks/verification.py`.

**Architecture:**

```
[Operator machine]  ──LAN──  [Verifier server: Raspberry Pi / local PC]
    signs blanks               verifies QR codes from printed documents
    hosts no server            runs: src/network/verifier_server.py
```

The main application **does not start any network listener** unless the
LAN server mode is explicitly enabled. Air-gap integrity is preserved
by default.

---

## Future: Stealth Module

> **Status: 📋 TODO** — `src/stealth/`

> **Conceptual note:** Steganography addresses a different threat model
> than cryptography. Encryption protects data content. Steganography
> hides the fact that data exists. These are complementary but independent
> layers. `src/stealth/` is separate from `src/security/` for this reason.

**Planned capabilities:**

- `image.py` — LSB embedding in PNG/JPEG
- `audio.py` — LSB embedding in WAV
- `video.py` — embedding in MP4
- `volume.py` — hidden partition support (VeraCrypt-compatible)

---

## Threat Model

### Protected Assets

| Tier | Asset | Protection |
|------|-------|------------|
| **Critical** | Hardware device private keys | Never leave device (Mode A) |
| **Critical** | Keystore master key | Argon2id + MFA unlock |
| **Critical** | Audit log HMAC secret | In keystore, never in config |
| **Critical** | Blank signing keys | In keystore or on hardware device |
| **High** | Session state | SecureMemory, auto-lock |
| **High** | Config file | Signed, tamper-detected |
| **High** | Document content | AES-256-GCM at rest |
| **Medium** | Blank registry | Signed, in keystore |
| **Medium** | Temp print files | Secure delete after use (planned) |

### Attack Scenarios

#### 1. Disk Theft / Forensic Analysis

**Attack:** Attacker images the disk and extracts keystore.

**Mitigations:**

- ✅ Keystore encrypted with Argon2id-derived key (64–256 MB memory cost)
- ✅ Hardware device required for high-security operations
- ✅ No plaintext keys ever written to disk (SecureMemory pattern)
- ✅ Temp files secure-deleted (planned)
- ✅ Swap file should be encrypted at OS level (documented in setup guide)

#### 2. Config Tampering (Preset Downgrade)

**Attack:** Attacker with brief physical access modifies config to
downgrade encryption preset before the operator's next session.

**Mitigations:**

- ✅ Config file is signed with master key
- ✅ Signature verified at startup — tampered config aborts launch
- ✅ Event logged to audit trail

#### 3. Application Binary Replacement

**Attack:** Malicious binary replacing the legitimate application
(supply chain / physical access).

**Mitigations:**

- ✅ App binary hash checked at startup
- ✅ Mismatch aborts startup and logs event
- ⚠️ Does not protect if the hash reference file is also replaced —
reference hash should be stored on external media or hardware device

#### 4. Counterfeit Blank

**Attack:** Forging a protected blank outside the system.

**Mitigations:**

- ✅ Ed25519/ML-DSA signature unforgeable without private key
- ✅ Private key in hardware device (Mode A) or keystore (software mode)
- ✅ QR code contains public key — verification is self-contained
- ✅ Blank registry allows detecting duplicate serial numbers

#### 5. Malicious Key Import (Mode B)

**Attack:** Operator unknowingly imports a backdoored key.

**Mitigations:**

- ✅ Mode B import requires explicit MFA confirmation
- ✅ Warning dialog is mandatory, not dismissible silently
- ✅ Event logged to audit trail with `device.key_imported` type
- ✅ Key fingerprint displayed before confirmation

#### 6. Hardware Device Cloning

**Attack:** Cloning a YubiKey or J3R200 to extract private key.

**Mitigations:**

- ✅ YubiKey: hardware-enforced non-exportable keys (Mode A)
- ✅ J3R200: CC EAL 6+ certification, Physical Unclonable Function (PUF)
- ✅ Mode A keys are generated on-board and cannot be extracted

#### 7. APDU Interception

**Attack:** Intercepting APDU communication between app and smartcard.

**Mitigations:**

- ✅ Secure Channel Protocol (SCP03) for sensitive operations on J3R200
- ✅ PIN verification required before cryptographic operations
- ⚠️ USB traffic interception remains a residual risk on compromised OS

#### 8. Entropy Starvation

**Attack:** Low-entropy RNG produces predictable keys on air-gapped machine.

**Mitigations:**

- ✅ Entropy check before key generation (planned in monitoring)
- ✅ Hardware device RNG supplements OS entropy during provisioning
- ✅ Argon2id memory hardness compensates for weak password entropy

---

## Module Status

| Module | Status | Notes |
|--------|--------|-------|
| `security/crypto/` | ✅ Complete | v2.3, 46 algorithms, 90%+ test coverage |
| `security/crypto/hardware/` | ✅ Complete | PIV, OpenPGP backends, smart card support |
| `security/auth/` | ✅ Complete | 98.67% coverage, 616+ tests, Password + FIDO2/TOTP/Backup Codes MFA |
| `security/audit/` | ✅ Complete | Hash-chain + HMAC-SHA256, 62 event types, thread-safe |
| `security/blanks/` | ✅ Complete | 6 lifecycle states, 3 signing modes, offline QR verification |
| `security/compliance/` | ✅ Complete | GDPR compliance, data retention, PII anonymization, right to erasure |
| `security/integrity/` | ✅ Complete | App hash check, config signature verification |
| `security/lock/` | ✅ Complete | SessionLockManager, AutoLockService, platform-specific idle |
| `security/erasure.py` | ✅ Complete | SecureMemory, wipe_file, wipe_directory, clear_clipboard |
| `security/monitoring/` | ✅ Complete | HealthChecker, 6 health checks, audit integration |
| `documents/` | 🚧 In progress |  |
| `backup/` | 📋 TODO |  |
| `network/` | 📋 TODO | LAN verifier, opt-in only |
| `stealth/` | 📋 TODO | Future scope |

---

## References

### Related Documents

- [form_designer.md](form_designer.md) — Form Template Designer security (template signing, ESC/P preview)
- [form_history.md](form_history.md) — Form History Security (encryption, retention policy, GDPR)
- [template_library.md](template_library.md) — Template Library Security (signing, trust chain, import verification)
- [approval_workflow.md](approval_workflow.md) — Approval Workflow Security (MFA-gated transitions, audit trail)

---
- **NIST FIPS 204** — ML-DSA (Module-Lattice Digital Signature Algorithm)
- **NIST FIPS 205** — SLH-DSA (Stateless Hash-based Digital Signature Algorithm)
- **NIST FIPS 203** — ML-KEM (Module-Lattice Key Encapsulation Mechanism)
- **NIST FIPS 140-3** — Security Requirements for Cryptographic Modules
- **RFC 8032** — EdDSA (Ed25519, Ed448)
- **RFC 8031** — X25519, X448 Key Agreement
- **RFC 4880** — OpenPGP Message Format
- **ISO 7816-4** — APDU command structure
- **FIDO2 CTAP2** — Client to Authenticator Protocol

### Libraries

- [cryptography](https://cryptography.io/) — PyCA, primary crypto library
- [liboqs-python](https://github.com/open-quantum-safe/liboqs-python) — PQC algorithms, **requires ≥ 0.15.0**
- [python-fido2](https://github.com/Yubico/python-fido2) — FIDO2/CTAP2
- [pyscard](https://pyscard.sourceforge.io/) — APDU transport, **requires ≥ 2.0.0**
- [yubikey-manager](https://github.com/Yubico/yubikey-manager) — YubiKey management, **requires ≥ 5.0.0**
- [argon2-cffi](https://argon2-cffi.readthedocs.io/) — Argon2id bindings
- [pycryptodome](https://pycryptodome.readthedocs.io/) — Secondary crypto (independence)
