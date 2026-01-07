# Password Vault

A secure password management tool built with enterprise security practices. This project implements encrypted credential storage, breach detection via HaveIBeenPwned, and SIEM-compatible logging for security operations workflows.

## Why I Built This

I wanted to create something that goes beyond a typical "store passwords in a file" project. This implements real security controls you'd see in production systems:

- **Proper cryptography** - Not just "encrypt with AES" but actual key derivation with PBKDF2 (600K iterations per OWASP 2023 guidelines)
- **API security** - Rate limiting, JWT tokens, brute force protection, security headers
- **Security operations** - Structured logging that can feed into Splunk/ELK, automated incident detection
- **Defense in depth** - Multiple layers so one failure doesn't compromise everything

## Features

**Password Management**
- Cryptographically secure generation using Python's `secrets` module
- Strength analysis with pattern detection (keyboard walks, repeated chars, common passwords)
- Password history tracking to prevent reuse

**Encryption**
- Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256)
- PBKDF2-SHA256 key derivation with 600,000 iterations
- Per-vault salt generation

**Authentication**
- JWT session tokens (15-minute access, 24-hour refresh)
- HTTP Basic Auth fallback for simpler use cases
- Per-IP brute force tracking with lockout (5 attempts → 60s cooldown)
- Timing-safe password comparison to prevent side-channel attacks

**Breach Detection**
- HaveIBeenPwned API integration
- Uses k-Anonymity model - only sends first 5 chars of SHA-1 hash, never the full password
- Severity-based warnings with actionable recommendations

**Security Logging**
- JSON Lines format for SIEM ingestion (Splunk, ELK, QRadar compatible)
- Log rotation with compression (configurable size/count)
- Automatic incident ticket generation from suspicious patterns

## Quick Start

```bash
# Clone and install
git clone https://github.com/daniel-ki-cyber/secure-password-vault.git
cd secure-password-vault
pip install -r requirements.txt

# CLI usage
python passapp.py

# API (development)
uvicorn api.main:app --reload
# Swagger docs at http://localhost:8000/docs
```

For production, set these environment variables:
```bash
export JWT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export REQUIRE_HTTPS=true
```

## API Endpoints

**Public:**
- `GET /health` - Health check
- `POST /generate` - Generate password with options
- `POST /check` - Strength analysis + breach check
- `POST /breach-check` - HaveIBeenPwned lookup only

**Authentication:**
- `POST /auth/login` - Get JWT tokens (use Basic Auth)
- `POST /auth/refresh` - Refresh access token

**Protected (requires Bearer token or Basic Auth):**
- `GET /vault` - List all entries
- `GET /vault/{label}` - Get specific password
- `POST /vault` - Store new password
- `PUT /vault/{label}` - Update password
- `DELETE /vault/{label}` - Delete entry
- `GET /vault/{label}/history` - Password history

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET_KEY` | None | Required for JWT auth (64 hex chars) |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | 15 | Access token lifetime |
| `JWT_REFRESH_TOKEN_EXPIRE_MINUTES` | 1440 | Refresh token lifetime |
| `REQUIRE_HTTPS` | false | Reject non-HTTPS requests |
| `TRUSTED_PROXIES` | (empty) | IPs allowed to set X-Forwarded-For |
| `SIEM_LOG_MAX_BYTES` | 10485760 | Log rotation threshold |
| `SIEM_LOG_BACKUP_COUNT` | 5 | Rotated logs to keep |

## Project Structure

```
password-vault/
├── api/                    # REST API (FastAPI)
│   ├── main.py             # App config, middleware, security headers
│   ├── dependencies.py     # Auth logic, brute force protection
│   └── routes/             # Endpoint handlers
├── core/                   # Business logic
│   ├── crypto.py           # Fernet encryption, PBKDF2
│   ├── jwt_auth.py         # Token generation/validation
│   ├── siem.py             # Security logging, rotation
│   ├── secure_memory.py    # Memory clearing utilities
│   └── ...
├── cli/                    # Command-line interface
├── tests/                  # pytest suite
├── .github/workflows/      # Security scanning CI
└── Dockerfile              # Hardened container
```

## Security Implementation Details

**Why PBKDF2 with 600K iterations?**
OWASP 2023 recommends this as the minimum for SHA-256. It makes brute-forcing the master password computationally expensive while keeping login time reasonable (~0.5s).

**Why JWT instead of just Basic Auth?**
Basic Auth sends the master password with every request. JWT means you authenticate once, get a short-lived token, and the password isn't transmitted repeatedly. The token payload is also encrypted (not just signed) so even if intercepted, the master password isn't extractable.

**Why the SecureBytes class?**
Python strings are immutable and garbage-collected unpredictably. You can't reliably zero them from memory. `SecureBytes` wraps a `bytearray` that can be explicitly overwritten before disposal. It's not perfect (this is Python, not C), but it reduces the exposure window.

**Why log rotation?**
Without it, an attacker could trigger endless login failures to fill the disk. The rotation also compresses old logs to save space while keeping audit history.

## Testing

```bash
pytest                          # Run all tests
pytest --cov=. --cov-report=html  # With coverage
pytest tests/test_api.py -v     # Specific module
```

The GitHub Actions workflow runs pip-audit, Bandit, detect-secrets, and CodeQL on every push.

## Docker

```bash
docker build -t password-vault .
docker run -p 8000:8000 -e JWT_SECRET_KEY="your-key" password-vault
```

The container runs as non-root and binds to localhost by default.

## Known Limitations

1. **Single-user design** - One master password for the whole vault. Multi-tenant would need a different architecture.
2. **No JWT key rotation** - Changing the secret invalidates all tokens. Would need a key versioning system for zero-downtime rotation.
3. **Python memory** - Even with SecureBytes, Python's GC and string interning mean sensitive data might linger in memory longer than ideal.

## License

MIT

## Author

Daniel Ki - [LinkedIn](https://linkedin.com/in/daniel-ki-712749196) | [GitHub](https://github.com/daniel-ki-cyber)
