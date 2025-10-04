# Security Setup Guide

## Prerequisites

### System Requirements
- Python 3.11+
- GnuPG 2.4+ (`gpg --version`)
- Hardware security key (optional but recommended)
  - YubiKey 5 Series
  - Google Titan
  - Compatible FIDO2 device

### Install Dependencies

Install security dependencies
pip install -e ".[security]"

Verify installation
python -c "from cryptography import version; print(f'cryptography: {version}')"
python -c "from argon2 import version; print(f'argon2-cffi: {version}')"
python -c "import gnupg; print('python-gnupg: OK')"
python -c "from fido2 import version; print(f'fido2: {version}')"

## Initial Configuration

### 1. Generate Audit Secret

Generate 256-bit HMAC secret for audit log
python -c "import secrets; print(secrets.token_hex(32))" > .audit_secret

Set restrictive permissions
chmod 600 .audit_secret

Add to environment
export FX_AUDIT_HMAC_SECRET=$(cat .audit_secret)


### 2. Configure GPG

Create dedicated GPG home
mkdir -p ~/.fx-text-processor/gnupg
chmod 700 ~/.fx-text-processor/gnupg

export GNUPGHOME=~/.fx-text-processor/gnupg

Generate master keypair (Ed25519)
gpg --quick-generate-key "FX Text Processor Admin admin@company.com" ed25519 default 0

List keys
gpg --list-keys

### 3. Setup Admin User

Run interactive setup
python -m src.security.setup

Prompts:
- Admin username: admin
- Admin email: admin@company.com
- Password: [enter secure password]
- Register FIDO2 key? [y/N]: y
[Insert YubiKey and touch sensor]
- Generate GPG key? [Y/n]: y

### 4. Initialize Audit Log

from src.security.audit.logger import ImmutableAuditLog
from src.security.audit import AuditEventType
import os

Load HMAC secret
hmac_secret = os.environ['FX_AUDIT_HMAC_SECRET'].encode()

Initialize audit log
audit = ImmutableAuditLog(
hmac_secret=hmac_secret,
log_path='./data/audit.jsonl'
)

Log first event
audit.log_event(
event_type=AuditEventType.SYSTEM_INITIALIZED,
user_id='system',
session_id='setup',
details={
'version': '1.0.0',
'setup_at': datetime.utcnow().isoformat()
}
)

print("✓ Audit log initialized")


## User Management

### Create New User

from src.security.auth.password import hash_password
from src.security.auth.permissions import Role

Create operator account
user = UserAccount(
userid=str(uuid.uuid4()),
username='operator-001',
email='operator@company.com',
password_hash=hash_password('secure-password-here'),
role=Role.OPERATOR,
created_at=datetime.utcnow()
)

Register FIDO2 key (optional)
from src.security.auth.webauthn import WebAuthnManager

webauthn = WebAuthnManager()
registration = webauthn.register_security_key(
user=user,
device_name='YubiKey 5C NFC'
)

Follow browser prompts to complete registration

### Grant Permissions

from src.security.auth.permissions import Permission

Define operator permissions
user.permissions = [
Permission.VIEW_DOCUMENTS,
Permission.CREATE_DOCUMENTS,
Permission.PRINT_DOCUMENTS,
Permission.PRINT_BLANKS_STANDARD,
# Permission.PRINT_BLANKS_PROTECTED requires elevated role
]

Save user
user_db.save(user)


## Protected Blank Setup

### Issue Blank Series

from src.security.blanks.manager import BlankManager

blank_mgr = BlankManager(audit_log=audit)

Issue 100 numbered blanks in series A
blanks = blank_mgr.issue_blank_series(
series='A',
count=100,
blank_type='invoice',
issued_to='operator-001'
)

print(f"✓ Issued {len(blanks)} blanks")
print(f" Series: A")
print(f" Numbers: 1-100")
print(f" Type: invoice")

Export to secure storage
blank_mgr.export_to_encrypted_backup(
output_path='./backups/blanks-series-a.gpg',
recipient='admin@company.com'
)


### Load Blank for Printing

Operator loads blank into printer
blank = blank_mgr.get_blank('A', 42)

Verify status
if blank.status != BlankStatus.READY:
blank_mgr.set_blank_ready(blank.blank_id, user_id='operator-001')

print(f"✓ Blank A-042 ready for printing")


## Hardware Security Key Setup

### Register YubiKey

**On Windows**:
Verify YubiKey detected
python -m yubico.otp.examples.list_devices


**On Linux**:
Verify FIDO2 support
lsusb | grep Yubico

Add udev rule (once)
echo 'KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0664", GROUP="plugdev", ATTRS{idVendor}=="1050"' | sudo tee /etc/udev/rules.d/70-yubikey.rules
sudo udevadm control --reload-rules


**Register in application**:
from src.security.auth.webauthn import WebAuthnManager

webauthn = WebAuthnManager()

User registration
registration_data = webauthn.register_security_key(
user=current_user,
device_name='YubiKey 5 NFC'
)

Browser WebAuthn API handles the rest
User: insert YubiKey → touch sensor → registered

### Verify Login with YubiKey

Login flow
username = input("Username: ")
password = getpass.getpass("Password: ")

Step 1: Password verification
user = user_db.get_by_username(username)
if not verify_password(password, user.password_hash):
print("✗ Invalid credentials")
exit(1)

Step 2: WebAuthn challenge
auth_data = webauthn.authenticate_begin(user.webauthn_credentials)

User: insert YubiKey → touch sensor
Browser sends credential_response
if webauthn.verify_security_key(user, credential_response):
create_session(user)
print("✓ Login successful")
else:
print("✗ Hardware key verification failed")


## Backup & Recovery

### Encrypted Backup

Backup entire data directory with GPG encryption
tar czf - ./data | gpg --encrypt --recipient admin@company.com --output backup-$(date +%Y%m%d).tar.gz.gpg

Verify backup
gpg --list-packets backup-20251004.tar.gz.gpg


### Restore from Backup

Decrypt and extract
gpg --decrypt backup-20251004.tar.gz.gpg | tar xzf -

Verify audit log integrity
python -m src.security.audit.integrity verify ./data/audit.jsonl

Expected output:
✓ HMAC signatures valid: 1,234 events
✓ Hash chain intact
✓ No gaps detected

### Disaster Recovery

**Scenario**: Complete system loss

**Recovery Steps**:
1. Install fresh system
2. Install FX-Text-processor with security dependencies
3. Restore GPG keys from backup
4. Restore audit log from backup
5. Verify audit log integrity
6. Restore document database
7. Verify user credentials
8. Re-register FIDO2 devices (keys must be re-registered)

**Estimated Recovery Time**: 2-4 hours

## Security Hardening

### File Permissions

Restrict access to sensitive files
chmod 600 .audit_secret
chmod 700 ~/.fx-text-processor/gnupg
chmod 600 ./data/audit.jsonl
chmod 600 ./data/users.db

Create audit log directory with append-only
sudo chattr +a /var/log/fx-text-processor/audit.log


### Network Security

**Firewall Rules**:
Allow only necessary ports (if running REST API)
sudo ufw allow 8443/tcp # HTTPS only
sudo ufw deny 8080/tcp # No HTTP

Enable firewall
sudo ufw enable


### System Hardening (Linux)

Install AppArmor profile
sudo cp security/apparmor/fx-text-processor /etc/apparmor.d/
sudo apparmor_parser -r /etc/apparmor.d/fx-text-processor

Enable audit daemon
sudo systemctl enable auditd
sudo systemctl start auditd

Add audit rules for sensitive files
echo "-w /var/log/fx-text-processor/ -p wa -k fx_audit" | sudo tee -a /etc/audit/rules.d/fx.rules
sudo service auditd restart


## Monitoring & Alerts

### Setup Log Forwarding to SIEM

from src.security.audit.exporters import setup_syslog_forwarding

Forward audit events to central SIEM
setup_syslog_forwarding(
audit_log=audit,
syslog_server='siem.company.com',
syslog_port=514,
protocol='TCP+TLS'
)

### Configure Alerts

from src.security.monitoring import AlertRule

Alert on suspicious activity
AlertRule(
name='Multiple Failed Logins',
condition=lambda events: len([e for e in events if e.type == AuditEventType.USER_LOGIN_FAILED]) >= 3,
window_seconds=300,
action=lambda: send_email('security@company.com', 'Brute force attempt detected')
)

AlertRule(
name='Audit Log Tampering',
condition=lambda: not audit.verify_chain_integrity(),
window_seconds=60,
action=lambda: alert_security_team('CRITICAL: Audit log integrity violation')
)


## Troubleshooting

### GPG Issues

**Problem**: `gpg: decryption failed: No secret key`

**Solution**:
Verify correct GNUPGHOME
echo $GNUPGHOME

List available keys
gpg --list-secret-keys

Import key if missing
gpg --import backup-private-key.asc


### FIDO2 Issues

**Problem**: `FIDO2 device not detected`

**Solution** (Linux):
Check USB device
lsusb | grep Yubico

Verify udev rules
cat /etc/udev/rules.d/70-yubikey.rules

Test FIDO2 detection
python -c "from fido2.hid import CtapHidDevice; print(list(CtapHidDevice.list_devices()))"


**Problem**: `WebAuthn origin mismatch`

**Solution**:
Verify RP ID matches domain
webauthn = WebAuthnManager()
print(f"Configured RP ID: {webauthn.rp.id}")

Must match: window.location.hostname in browser

### Argon2 Performance Issues

**Problem**: Login takes > 1 second

**Solution**:
Reduce memory cost for development (NOT for production)
from src.security.auth.password import hash_password

Development settings
hash_password(
password='test',
time_cost=2, # Reduced from 3
memory_cost=16384 # Reduced from 65536 (16 MB)
)


## Production Checklist

Before deploying to production:

- [ ] Generate unique HMAC secret (not example value)
- [ ] Audit log stored on append-only filesystem
- [ ] GPG keys backed up securely (offline storage)
- [ ] All users have FIDO2 keys registered
- [ ] File permissions set correctly (600 for secrets)
- [ ] TLS certificates valid (if using REST API)
- [ ] SIEM integration configured and tested
- [ ] Backup/restore procedure tested
- [ ] Penetration testing completed
- [ ] Security audit log review process established
- [ ] Incident response plan documented

## Support

For security issues:
- **DO NOT** open public GitHub issues
- Contact: security@fx-text-processor.local
- PGP Key: [fingerprint]
