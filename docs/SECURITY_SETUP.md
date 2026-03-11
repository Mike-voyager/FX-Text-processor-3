# Security Setup Guide

**Document Version:** 2.1  
**Date:** March 2026  
**Project:** FX Text Processor 3  

> This guide covers initial setup for a **single-operator, air-gap,
> offline-first** deployment. No network connectivity is required for
> any step unless explicitly noted.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [OS Hardening](#os-hardening)
3. [Install Dependencies](#install-dependencies)
4. [First-Run Wizard](#first-run-wizard)
5. [Crypto Configuration](#crypto-configuration)
6. [Hardware Device Setup](#hardware-device-setup)
7. [Authentication Setup](#authentication-setup)
8. [Blank Series Setup](#blank-series-setup)
9. [Backup & Recovery Ceremony](#backup--recovery-ceremony)
10. [Verification](#verification)
11. [Security Hardening](#security-hardening)
12. [Troubleshooting](#troubleshooting)
13. [Production Checklist](#production-checklist)

---

## Prerequisites

### System Requirements

- **OS:** Linux (recommended) / Windows 10+ / macOS 12+
- **Python:** 3.11+
- **RAM:** 8 GB minimum (Argon2id Paranoid preset requires 256 MB per operation)
- **Storage:** SSD recommended (Argon2id is memory-access-intensive)
- **CPU:** AES-NI support recommended (Intel Core 8th gen+ / AMD Ryzen 3000+)

### Hardware (optional but strongly recommended)

- YubiKey 5 Series (USB-A / USB-C / NFC)
- J3R200 smartcard + compatible reader (contact or NFC)
- Additional backup devices (up to 5–7 total)

### Verify Hardware

```bash
# List connected FIDO2 devices
python -c "
from fido2.hid import CtapHidDevice
devices = list(CtapHidDevice.list_devices())
print(f'FIDO2 devices found: {len(devices)}')
for d in devices: print(f'  {d}')
"

# List smartcard readers
python -c "
from smartcard.System import readers
for r in readers(): print(r)
"

# YubiKey info
ykman info
```

---

## OS Hardening

These steps should be done **before** installing the application.

### Linux

```bash
# Enable encrypted swap (prevents key material leaking to swap)
sudo swapoff -a
sudo cryptsetup luksFormat /dev/sdXN   # replace with your swap partition
sudo cryptsetup open /dev/sdXN cryptswap
sudo mkswap /dev/mapper/cryptswap
sudo swapon /dev/mapper/cryptswap

# Add to /etc/crypttab for persistence:
# cryptswap /dev/sdXN /dev/urandom swap,cipher=aes-xts-plain64,size=256

# Lock down /tmp to RAM (prevents temp file leakage to disk)
sudo systemctl enable tmp.mount

# Enable audit daemon
sudo systemctl enable auditd
sudo systemctl start auditd

# udev rule for YubiKey (allows non-root access)
echo 'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0664", GROUP="plugdev", ATTRS{idVendor}=="1050"' \
  | sudo tee /etc/udev/rules.d/70-yubikey.rules
sudo udevadm control --reload-rules && sudo udevadm trigger

# Add user to smartcard group
sudo usermod -aG plugdev,scard $USER
```

### Windows

```powershell
# Enable BitLocker on system drive (prevents disk forensics)
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256

# Disable hibernate (hiberfil.sys can contain key material)
powercfg /hibernate off

# Enable Windows Credential Guard (protects memory from certain attacks)
# Control Panel → Device Security → Core Isolation → Memory Integrity → ON
```

---

## Install Dependencies

```bash
# Core installation
pip install -e ".[security]"

# Verify critical libraries
python -c "
import oqs
print(f'liboqs-python: {oqs.__version__}')
# Must be >= 0.15.0 for ML-DSA/SLH-DSA support
assert tuple(int(x) for x in oqs.__version__.split('.')[:2]) >= (0, 15), \
    'liboqs >= 0.15.0 required — Dilithium/SPHINCS+ removed in 0.15'
"

python -c "from cryptography import __version__; print(f'cryptography: {__version__}')"
python -c "from fido2 import __version__; print(f'python-fido2: {__version__}')"
python -c "from smartcard.System import readers; print(f'pyscard: OK, readers: {len(readers())}')"
python -c "import ykman; print('yubikey-manager: OK')"
python -c "from argon2 import __version__; print(f'argon2-cffi: {__version__}')"

# Run algorithm availability check
python -m src.security.crypto.monitoring.algorithm_check
```

---

## First-Run Wizard

On first launch, the application runs a setup wizard. The wizard cannot
be skipped. It configures:

1. Master password (Argon2id hashed, never stored plaintext)
2. Security preset selection
3. Second factor setup (FIDO2 mandatory, TOTP optional)
4. Backup code generation
5. Keystore initialization
6. App binary hash registration
7. Backup ceremony (see [Backup & Recovery](#backup--recovery-ceremony))

```bash
# Launch application (wizard starts automatically on first run)
python -m src.main

# Or run setup explicitly
python -m src.security.setup
```

---

## Crypto Configuration

### Selecting a Security Preset

Presets are set in Settings → Security → Preset. The active preset is
shown in the status bar at all times.

| Preset | Recommended for | Argon2id Memory | Signing |
|--------|-----------------|-----------------|---------|
| **Standard** | Daily use | 64 MB | Ed25519 |
| **Paranoid** | Long-term, archive | 256 MB | Ed25519 + ML-DSA-65 |
| **PQC** | Post-quantum priority | 64 MB | ML-DSA-65 |
| **Legacy** | Compatibility only | PBKDF2 | RSA-PSS-4096 |

> **Downgrading a preset** (e.g., Paranoid → Standard) requires MFA
> confirmation and is logged to the audit trail.

### Fine-Tuning (Advanced)

In Settings → Security → Advanced, each parameter can be overridden:

```toml
# config.fxsconfig (managed by application — do not edit manually)
[crypto]
preset = "paranoid"

# Overrides (only set values that differ from preset)
[crypto.overrides]
signing_algorithm   = "ML-DSA-87"        # override: use Level 5 instead of Level 3
kdf_memory_cost     = 131072             # override: 128 MB instead of 256 MB
symmetric_algorithm = "AES-256-GCM"     # no override — same as preset default

[crypto.hybrid_signing]
enabled   = true
classical = "Ed25519"
pqc       = "ML-DSA-65"
```

> The config file is signed automatically on every save. Do not edit it
> with a text editor — use the application UI.

### Verify Active Configuration

```python
from src.security.crypto.service.profiles import CryptoProfile
from src.security.crypto.service.crypto_service import CryptoService

cs = CryptoService.from_config()
print(cs.active_profile)
print(cs.describe_config())
```

---

## Hardware Device Setup

### Step 1: Connect Device

```bash
# YubiKey — verify detection
ykman info

# Smartcard — verify detection
python -c "
from smartcard.System import readers
for r in readers():
    print(f'Reader: {r}')
"
```

### Step 2: Change Default PIV Management Key (YubiKey)

> ⚠️ **Required before any use.** The default management key is public knowledge.

```bash
# Change management key (store the new key in your password manager)
ykman piv access change-management-key --generate --protect

# Change PIV PIN (default: 123456)
ykman piv access change-pin

# Change PIV PUK (default: 12345678)
ykman piv access change-puk
```

### Step 3: J3R200 — Load SmartPGP Applet (if using OpenPGP)

```bash
# Requires GlobalPlatformPro (Java CLI tool) — not a Python dependency
# Download: https://github.com/martinpaljak/GlobalPlatformPro

# Load SmartPGP applet onto J3R200
java -jar gp.jar --install SmartPGPApplet.cap

# Load PivApplet (if using PIV on J3R200)
java -jar gp.jar --install PivApplet.cap

# Verify applets loaded
java -jar gp.jar --list
```

### Step 4: Provision Device in Application

In Settings → Hardware → Devices → Add Device:

1. Insert device → application detects it automatically
2. Select protocol: **PIV** or **OpenPGP**
3. **MFA challenge:** master password + second factor
4. Select key mode:
    - **Generate on-board** ✅ (recommended — private key never leaves device)
    - **Import existing key** ⚠️ (shows mandatory warning, requires confirmation)
5. Application receives public key → adds to device registry
6. Registry re-signed → event logged

```python
# Programmatic provisioning (advanced / scripting use)
from src.security.hardware.hardware_crypto import HardwareCryptoManager

mgr = HardwareCryptoManager()

# Generate key on device (PIV slot 9C — Digital Signature)
public_key = mgr.generate_key_onboard(
    card_id="yubikey-001",
    slot=0x9C,
    algorithm="ECCP384",
    management_key=your_management_key,
    pin="your-pin"
)

print(f"Public key generated: {public_key.hex()[:32]}...")
```

### Step 5: Set Device Priority

In Settings → Hardware → Device Priority:

- Drag devices to set order (1 = highest priority)
- Configure per-operation routing (authentication / signing / encryption)

### Step 6: Verify Device Operation

```python
from src.security.hardware.hardware_crypto import HardwareCryptoManager

mgr = HardwareCryptoManager()
devices = mgr.list_devices()

for device in devices:
    print(f"\nDevice: {device.label} ({device.device_type})")
    print(f"  Status: {device.status}")
    print(f"  Protocols: {device.available_protocols}")
    print(f"  Public keys: {list(device.public_keys.keys())}")

    # Test sign + verify round-trip
    test_msg = b"hardware_test_" + device.device_id.encode()
    sig = mgr.sign_with_device(device.device_id, slot=0x9C,
                                message=test_msg, pin=input("PIN: "))
    ok = mgr.verify_with_device(device.device_id, test_msg, sig)
    print(f"  Sign/Verify test: {'✓ PASS' if ok else '✗ FAIL'}")
```

---

## Authentication Setup

### Register Master Password

```python
from src.security.auth.password_service import PasswordService

svc = PasswordService()
svc.set_master_password(
    password=input("Master password: "),
    # Parameters follow active security preset
    # Standard:  time_cost=3, memory_cost=65536  (64 MB)
    # Paranoid:  time_cost=5, memory_cost=262144 (256 MB)
)
```

### Register FIDO2 Device (Required)

```python
from src.security.auth.fido2_service import FIDO2Service

fido2 = FIDO2Service()

# Enumerate CTAP2 devices
devices = fido2.list_devices()
print(f"Found {len(devices)} FIDO2 device(s)")

# Register device (requires physical touch)
credential = fido2.register_device(
    device=devices[0],
    label="YubiKey Primary",
    pin=input("Device PIN (if set): ") or None
)
print(f"✓ Registered: {credential.credential_id.hex()[:16]}...")
```

### Setup TOTP (Optional, Recommended as Backup)

In Settings → Authentication → TOTP → Setup:

1. Application generates TOTP secret
2. Displays QR code → scan with KeePassXC / Aegis / andOTP
3. Verify with a live code before saving
4. Secret stored encrypted in keystore

```python
from src.security.auth.totp_service import TOTPService

totp = TOTPService()
secret, qr_uri = totp.generate_secret()
print(f"URI (scan with authenticator): {qr_uri}")

# Verify before saving
code = input("Enter code from authenticator: ")
if totp.verify_provisional(secret, code):
    totp.save_secret(secret)
    print("✓ TOTP configured")
else:
    print("✗ Code incorrect — setup aborted")
```

### Generate Backup Codes

In Settings → Authentication → Backup Codes → Generate:

- Generates 10 single-use codes
- Each code is shown **once** — print or write down immediately
- Store physically (paper, safe)

```python
from src.security.auth.code_service import CodeService

codes = CodeService().generate_backup_codes(count=10)
print("\nBACKUP CODES — STORE SECURELY — SHOWN ONCE\n")
for i, code in enumerate(codes, 1):
    print(f"  {i:02d}. {code}")
print("\nEach code can be used only once.")
```

### Verify Full Auth Flow

```bash
# Lock and re-authenticate to confirm everything works
python -m src.security.auth.verify_flow

# Expected output:
# ✓ Master password: valid
# ✓ FIDO2 device: detected, credential valid
# ✓ TOTP: valid (if configured)
# ✓ Backup codes: 10 available
# ✓ Full MFA flow: PASS
```

---

## Blank Series Setup

### Initialize a Blank Series

```python
from src.security.blanks.manager import BlankManager
from src.security.audit.logger import ImmutableAuditLog

audit = ImmutableAuditLog(
    hmac_secret=keystore.get_audit_secret(),
    log_path="./data/audit.jsonl"
)

mgr = BlankManager(audit_log=audit, crypto_service=cs, hw_manager=hw_mgr)

# Issue a series using active security preset
blanks = mgr.issue_blank_series(
    series="INV-A",
    count=100,
    blank_type="invoice",         # registered type from documents/templates
    issued_to="Mike Voyager",
    security_preset="standard",   # explicit — never inherit silently
    signing_mode="software",      # or "hardware_piv" / "hardware_openpgp"
    signing_device_id=None        # None = software keystore key
)

print(f"✓ Issued {len(blanks)} blanks")
print(f"  Series:    INV-A")
print(f"  Numbers:   1–100")
print(f"  Preset:    standard (Ed25519, AES-256-GCM)")
print(f"  Signing:   software keystore")
```

### Issue with Hardware Signing

```python
# Hardware signing — private key stays on device
blanks = mgr.issue_blank_series(
    series="ACT-A",
    count=50,
    blank_type="act",
    issued_to="Mike Voyager",
    security_preset="paranoid",
    signing_mode="hardware_openpgp",
    signing_device_id="yubikey-001",
    signing_pin=input("Device PIN: ")
)
```

### Verify a Printed Blank (Offline)

```python
from src.security.blanks.verification import verify_blank
import json

# Parse QR code data from printed document
qr_raw = scan_qr_code(printed_document)
qr_data = json.loads(qr_raw)

result = verify_blank(
    qr_data=qr_data,
    printed_content=document_bytes
)

if result.authentic:
    print(f"✓ Authentic: {result.series}-{result.number:04d}")
    print(f"  Algorithm:  {result.algorithm}")
    print(f"  Signed at:  {result.printed_at}")
else:
    print(f"⚠️  VERIFICATION FAILED")
    print(f"  Reason: {result.reason}")
    audit.log_event(AuditEventType.BLANK_VERIFY_FAILED,
                    details={"reason": result.reason, "qr": qr_data})
```

---

## Backup & Recovery Ceremony

> ⚠️ **Do not skip this step.** In an air-gap system, this is the only
> recovery path. If all backup material is lost, encrypted data is
> permanently inaccessible.

### Run Backup Wizard

```bash
python -m src.backup.ceremony
```

The wizard guides through all steps interactively. Manual steps below
for reference.

### Step 1: Export Encrypted Keystore

```python
from src.backup.keystore_export import KeystoreExporter

exporter = KeystoreExporter()

# Export to USB drive — encrypted with a separate backup passphrase
# (different from master password — store separately)
exporter.export(
    output_path="/media/usb-backup/fx-keystore-backup.enc",
    backup_passphrase=input("Backup passphrase (new, separate from master): ")
)
print("✓ Keystore exported")
```

### Step 2: Shamir's Secret Sharing (Recommended)

```python
from src.backup.shamir import ShamirSecretSharing

# Split master key into 5 shares, any 3 required to recover
master_key = keystore.export_master_key()   # MFA-gated
shares = ShamirSecretSharing.split(secret=master_key, n=5, k=3)

print("SHAMIR SHARES — DISTRIBUTE TO 5 SEPARATE LOCATIONS\n")
for i, share in enumerate(shares, 1):
    print(f"Share {i}/5:")
    print(f"  {share.to_base58()}")
    print()

print("Recovery requires ANY 3 of these 5 shares.")
print("Store in separate physical locations.")
```

### Step 3: Paper Key (QR + Human-Readable)

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
print("✓ Paper key PDF generated")
print("  - QR code: primary recovery method")
print("  - Manual groups: 13×4 Base58 chars, 256-bit key strength")
print("  - CRC-32 integrity check embedded")
print("\nPrint on archival paper, store in fireproof safe")
```

**Format on printed page:**

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

─────────────────────────────────────────────────────────
SECURITY INSTRUCTIONS:

✓ Print on acid-free archival paper
✓ Store in fireproof safe or safety deposit box
✓ DO NOT photograph or save digitally
✓ Test manual entry during setup ceremony before storing
✗ NEVER share — this is your only recovery path

KEY STRENGTH:
256-bit master key = 2^256 ≈ 1.16 × 10^77 combinations
Time to exhaust at 1 trillion tries/sec: ~10^57 years

If this key is lost and all other backups fail,
encrypted data is PERMANENTLY INACCESSIBLE.
─────────────────────────────────────────────────────────
```

**Recovery — QR code method:**

```bash
python -m src.backup.restore --qr-scan
# Prompts to scan QR with camera/scanner
# Decodes Base58, extracts 36-byte payload
# Verifies CRC-32, reconstructs 256-bit master key
```

**Recovery — Manual entry method:**

```bash
python -m src.backup.restore --manual-entry

# Prompts:
# Enter group 1 (4 chars): J7K2
# Enter group 2 (4 chars): M9P3
# ...
# Enter group 13 (4 chars): T4W6
# ✓ CRC-32 valid
# ✓ Master key reconstructed (256-bit)
```

### Step 4: Device Registry Backup

```python
from src.security.hardware.device_registry import DeviceRegistry

registry = DeviceRegistry()
registry.export_signed(
    output_path="/media/usb-backup/device-registry.fxsreg"
)
print("✓ Device registry exported")
```

### Recovery: Restore from Backup

```bash
# Launch recovery wizard
python -m src.backup.restore

# The wizard will:
# 1. Ask for recovery method (keystore export / Shamir shares / paper key)
# 2. Verify recovered key authenticity (HMAC)
# 3. Re-initialize keystore
# 4. Restore device registry
# 5. Re-provision hardware devices (requires physical devices)
# 6. Verify audit log continuity
```

---

## Verification

### Full System Verification

```bash
# Run all security checks
python -m src.security.monitoring.health_check

# Expected output:
# ✓ App binary hash:          valid
# ✓ Config signature:         valid
# ✓ Keystore health:          OK (HMAC valid, not corrupted)
# ✓ Audit chain integrity:    intact (N events verified)
# ✓ Algorithm availability:   all preset algorithms available
#   ✓ Ed25519:                 available
#   ✓ ML-DSA-65:               available (liboqs 0.X.X)
#   ✓ AES-256-GCM:             available
#   ✓ Argon2id:                available
# ✓ Entropy:                  sufficient (/dev/random: N bits available)
# ✓ Hardware devices:         2 device(s) connected
#   ✓ YubiKey Primary (PIV):   responsive
#   ✓ J3R200 Backup (OpenPGP): responsive
# ─────────────────────────────
# OVERALL: PASS
```

### Verify Crypto Module

```bash
pytest tests/unit/security/crypto/ \
  --cov=src.security.crypto \
  --cov-report=term-missing \
  -v

# Minimum expected:
# 141+ tests passing
# 88%+ coverage
# 0 failures
```

### Verify Audit Log Integrity

```python
from src.security.audit.logger import ImmutableAuditLog

audit = ImmutableAuditLog.open("./data/audit.jsonl",
                                hmac_secret=keystore.get_audit_secret())
result = audit.verify_chain_integrity()

print(f"Events verified:  {result.event_count}")
print(f"Chain intact:     {'✓' if result.chain_valid else '✗'}")
print(f"HMAC valid:       {'✓' if result.hmac_valid else '✗'}")
print(f"No gaps detected: {'✓' if not result.gaps else '✗'}")
```

---

## Security Hardening

### File Permissions

```bash
# Restrict access to sensitive files
chmod 600 ./data/audit.jsonl
chmod 600 ./data/keystore.fxskeystore.enc
chmod 700 ./data/

# Make audit log append-only (Linux — prevents deletion/modification)
sudo chattr +a ./data/audit.jsonl

# Verify
lsattr ./data/audit.jsonl
# Expected: -----a--------e---- ./data/audit.jsonl
```

### AppArmor Profile (Linux)

```bash
# Install application AppArmor profile
sudo cp security/apparmor/fx-text-processor /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/fx-text-processor
sudo aa-enforce /etc/apparmor.d/fx-text-processor

# Verify
sudo aa-status | grep fx-text-processor
```

### Disable Network (Air-Gap Enforcement)

```bash
# If the machine is dedicated to this application — disable network entirely
sudo nmcli networking off

# Or use firewall to block all outbound except LAN verifier (if needed)
sudo ufw default deny outgoing
sudo ufw default deny incoming
# LAN verifier (future, opt-in):
# sudo ufw allow out to 192.168.1.0/24 port 8443
sudo ufw enable
```

### Verify LAN Module is Disabled

```python
from src.security.crypto.service.crypto_service import CryptoService
import src.config as cfg

# Verify network is disabled (default)
assert cfg.network.enabled == False, \
    "Network must be disabled in air-gap mode"

print("✓ Network module: disabled (air-gap mode)")
```

---

## Troubleshooting

### liboqs: `MechanismNotSupportedError: Dilithium2`

```
oqs.oqs.MechanismNotSupportedError: Dilithium2
```

**Cause:** liboqs ≥ 0.15 removed Dilithium in favour of ML-DSA.

```python
# Wrong (legacy, removed in liboqs 0.15+)
from src.security.crypto.algorithms.signing import Dilithium2Signer
signer = Dilithium2Signer()  # ✗ Will fail

# Correct (NIST FIPS 204)
from src.security.crypto.algorithms.signing import MLDSA44Signer
signer = MLDSA44Signer()  # ✓
```

```bash
# Verify liboqs version
python -c "import oqs; print(oqs.__version__)"
# Must be >= 0.15.0
```

### FIDO2: `No FIDO2 device detected`

```bash
# Linux: check udev rules
ls /etc/udev/rules.d/ | grep yubikey
cat /etc/udev/rules.d/70-yubikey.rules

# Reload udev
sudo udevadm control --reload-rules && sudo udevadm trigger

# Check USB
lsusb | grep -i "yubico\|feitian\|token"

# Test CTAP2 detection directly
python -c "
from fido2.hid import CtapHidDevice
devices = list(CtapHidDevice.list_devices())
print(f'Devices: {len(devices)}')
for d in devices: print(f'  {d}')
"
```

### Smartcard: `No readers found`

```bash
# Check pcscd daemon (Linux)
sudo systemctl status pcscd
sudo systemctl start pcscd
sudo systemctl enable pcscd

# Check reader detection
python -c "
from smartcard.System import readers
r = readers()
print(f'Readers: {len(r)}')
for x in r: print(f'  {x}')
"

# Test ATR reading
python -c "
from smartcard.System import readers
from smartcard.util import toHexString
conn = readers()[0].createConnection()
conn.connect()
print(f'ATR: {toHexString(conn.getATR())}')
"
```

### YubiKey: PIV operations fail with `Authentication required`

```bash
# Reset management key if default was not changed
ykman piv access change-management-key

# If management key is unknown — factory reset PIV application
# ⚠️ THIS DELETES ALL PIV KEYS
ykman piv reset
```

### Argon2id: Login takes > 2 seconds

```python
# Check active preset parameters
from src.security.crypto.service.crypto_service import CryptoService
cs = CryptoService.from_config()
kdf_config = cs.get_kdf_config()
print(f"Memory cost: {kdf_config.memory_cost // 1024} MB")
print(f"Time cost:   {kdf_config.time_cost} iterations")

# For development: temporarily reduce (NEVER in real use)
# Settings → Security → Advanced → KDF → memory_cost: 16384 (16 MB)
```

### Config: `ConfigTamperedError: Config signature invalid`

```
src.security.integrity.config_integrity.ConfigTamperedError:
Config signature invalid — possible tampering
```

**Do not ignore this error.**

```bash
# Option 1: Restore config from backup
cp /media/usb-backup/config.fxsconfig ./data/config.fxsconfig

# Option 2: Rebuild config (loses custom settings — resets to preset defaults)
python -m src.security.setup --reset-config

# Either way — investigate what changed:
python -m src.security.integrity.config_audit ./data/config.fxsconfig
```

### Audit Log: `Chain integrity violation`

```
CRITICAL: Audit log chain broken at event #N
```

**This is a serious security event.**

```python
from src.security.audit.logger import ImmutableAuditLog

audit = ImmutableAuditLog.open("./data/audit.jsonl",
                                hmac_secret=keystore.get_audit_secret())
report = audit.diagnose_chain()

print(f"Break at event:   #{report.break_at_index}")
print(f"Expected hash:    {report.expected_hash}")
print(f"Found hash:       {report.found_hash}")
print(f"Timestamp:        {report.event_timestamp}")
```

Preserve the audit log file unchanged. If running in a forensic context,
make a copy before any further operations.

---

## Production Checklist

Complete before any real document signing:

### Crypto & Config

- [ ] liboqs ≥ 0.15.0 installed and verified
- [ ] Active security preset selected and understood
- [ ] Config file signed (auto — verify with health check)
- [ ] App binary hash registered

### Authentication

- [ ] Master password set (Argon2id, ≥ 20 character passphrase recommended)
- [ ] FIDO2 device registered (at least one)
- [ ] TOTP configured and verified with authenticator app
- [ ] Backup codes generated, printed, stored physically
- [ ] Full MFA flow tested (lock → unlock cycle)

### Hardware Devices

- [ ] Default PIV management key changed on every YubiKey
- [ ] PIV PIN and PUK changed from defaults
- [ ] All devices provisioned (on-board key generation preferred)
- [ ] Device priority order configured
- [ ] Sign + Verify round-trip tested on each device

### Blanks & Audit

- [ ] At least one blank series issued and test-verified
- [ ] Audit log initialized and chain verified
- [ ] Audit log file permissions set (600, append-only chattr +a)

### Backup

- [ ] Keystore backup exported to external media
- [ ] Shamir shares generated and distributed
- [ ] Paper key printed and stored in safe
- [ ] Device registry backed up
- [ ] Recovery procedure tested on a separate machine (if possible)

### OS & Hardening

- [ ] Swap encrypted (Linux) or BitLocker enabled (Windows)
- [ ] Hibernate disabled (Windows)
- [ ] udev rules configured for YubiKey (Linux)
- [ ] pcscd daemon running and auto-start enabled (Linux)
- [ ] Network disabled or firewall blocking all outbound (air-gap)
- [ ] AppArmor profile installed (Linux, recommended)
- [ ] /tmp on RAM (Linux, recommended)

---

## Support & Security Contact

This is a personal, private application. There is no public issue tracker
for security vulnerabilities. Security notes are maintained in:

```
docs/security/
├── SECURITY_ARCHITECTURE.md   ← this document's companion
├── SECURITY_SETUP.md          ← this document
├── hardware_crypto_roadmap.md ← hardware integration plan
├── CRYPTO_MASTER_PLAN_v2.3_FINAL.md
└── SIGNING_UPDATE.md          ← ML-DSA/SLH-DSA migration guide
```
