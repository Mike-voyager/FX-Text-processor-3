# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open public GitHub issues for security vulnerabilities.

### Contact

- **Email**: security@fx-text-processor.local
- **PGP Key**: [See below]

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: 30-90 days depending on severity

### Disclosure Policy

We follow **Coordinated Vulnerability Disclosure**:
1. Reporter notifies us privately
2. We confirm and develop fix
3. We release patched version
4. Public disclosure after 90 days or patch release (whichever is sooner)

### Severity Classification

| Severity | Examples | Response Time |
|----------|----------|---------------|
| **Critical** | RCE, Authentication bypass | 24-48 hours |
| **High** | XSS, SQL injection, Crypto weakness | 7 days |
| **Medium** | Information disclosure, CSRF | 30 days |
| **Low** | Minor configuration issues | 90 days |

## Security Features

See [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) for details:

- AES-256-GCM authenticated encryption
- Argon2id password hashing
- Ed25519 digital signatures
- FIDO2/WebAuthn multi-factor authentication
- Immutable audit logging with HMAC integrity
- OpenPGP multi-recipient encryption

## Security Audits

- **Last Audit**: [Date]
- **Audit Firm**: [Name]
- **Report**: [Link if public]

## Known Issues

None currently.

## Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

- [Researcher Name] - [Vulnerability] - [Date]

Thank you for helping keep escp-editor secure!
