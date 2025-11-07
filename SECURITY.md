# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open public GitHub issues for security vulnerabilities.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

### Disclosure Policy

We follow **Coordinated Vulnerability Disclosure**:
1. Reporter notifies us privately
2. We confirm and develop fix
3. We release patched version
4. Public disclosure after 90 days or patch release (whichever is sooner)

## Security Features

See [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) for details:

- AES-256-GCM authenticated encryption
- Argon2id password hashing
- Ed25519 digital signatures
- FIDO2/TOTP/backup code multi-factor authentication
- Immutable audit logging with HMAC integrity


## Security Audits

- **Last Audit**: [Date]
- **Audit Firm**: [Name]
- **Report**: [Link if public]

## Known Issues

None currently.

## Hall of Fame

We recognize security researchers who responsibly disclose vulnerabilities:

- [Researcher Name] - [Vulnerability] - [Date]

Thank you for helping keep FX Text Processor 3 secure!
