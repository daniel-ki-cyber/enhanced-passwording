# Password Vault

A secure, enterprise-ready password management tool built for security professionals and developers who need robust credential storage with full audit capabilities.

## Why This Tool?

Managing passwords securely isn't just about encryption—it's about visibility, compliance, and incident response. This tool bridges the gap between personal password managers and enterprise security requirements:

- **For Security Teams**: SIEM-compatible logging and automatic incident ticketing for brute force detection
- **For Developers**: REST API with OpenAPI docs for integration into existing workflows
- **For Personal Use**: CLI interface with breach detection to keep your credentials safe

## What It Does

| Capability | Description |
|------------|-------------|
| **Generate** | Create cryptographically secure passwords with customizable complexity |
| **Analyze** | Check password strength against 100+ common patterns and breached databases |
| **Store** | Encrypt credentials with AES-256 and PBKDF2 key derivation (600K iterations) |
| **Audit** | Log all access attempts in JSON format for SIEM ingestion |
| **Alert** | Auto-generate incident tickets for suspicious login patterns |

## Quick Start

### CLI

```bash
pip install -r requirements.txt
python passapp.py
```

On first run, you'll set up a master password. Then access the menu:

```
=== Password Tool Menu ===
1. Generate a password
2. Test a password
3. View saved passwords
4. Change master password
5. Exit
```

### REST API

```bash
uvicorn api.main:app --reload
```

API docs available at `http://localhost:8000/docs`

### Docker

```bash
docker build -t password-vault .
docker run -p 8000:8000 password-vault
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Password Vault                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────────────┐   │
│  │   CLI App   │     │  REST API   │     │   Breach Check      │   │
│  │ (passapp.py)│     │(FastAPI)    │     │ (HaveIBeenPwned)    │   │
│  └──────┬──────┘     └──────┬──────┘     └──────────┬──────────┘   │
│         │                   │                       │               │
│         └─────────┬─────────┴───────────────────────┘               │
│                   │                                                  │
│         ┌─────────▼─────────┐                                       │
│         │   Password        │                                       │
│         │   Checker         │◄─── Pattern Detection                 │
│         │                   │◄─── Common Password List (100+)       │
│         └─────────┬─────────┘                                       │
│                   │                                                  │
│         ┌─────────▼─────────┐     ┌─────────────────────┐          │
│         │                   │     │    SIEM Logger      │          │
│         │   Vault Core      │────►│  (JSON Events)      │          │
│         │                   │     └─────────┬───────────┘          │
│         └─────────┬─────────┘               │                       │
│                   │                         ▼                       │
│    ┌──────────────┼──────────────┐   ┌─────────────────┐           │
│    │              │              │   │ Ticket System   │           │
│    ▼              ▼              ▼   │ (Auto-generate) │           │
│ ┌──────┐    ┌──────────┐   ┌───────┐ └─────────────────┘           │
│ │Master│    │  Vault   │   │ Salt  │                                │
│ │ Hash │    │  (JSON)  │   │ File  │                                │
│ └──────┘    └──────────┘   └───────┘                                │
│                                                                      │
│  Encryption: AES-256 (Fernet) + PBKDF2-SHA256 (600K iterations)    │
└─────────────────────────────────────────────────────────────────────┘
```

## Security Standards

| Feature | Implementation | Standard |
|---------|---------------|----------|
| Password Hashing | PBKDF2-SHA256 | OWASP 2023 |
| Iterations | 600,000 | NIST SP 800-132 |
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256) | Industry Standard |
| Breach Detection | HaveIBeenPwned k-Anonymity | Privacy-Preserving |
| Lockout Policy | 5 attempts, 60s lockout | OWASP |

## API Endpoints

### Public (No Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health status |
| POST | `/generate` | Generate secure password |
| POST | `/check` | Check password strength + breach status |
| POST | `/breach-check` | HaveIBeenPwned lookup only |

### Protected (Basic Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault` | List all saved passwords |
| GET | `/vault/{label}` | Get specific password |
| POST | `/vault` | Save new password |
| PUT | `/vault/{label}` | Update password |
| DELETE | `/vault/{label}` | Delete password |
| GET | `/vault/{label}/history` | Get password history |

## SIEM Integration

Security events are logged to `logs/siem_events.jsonl` in JSON Lines format:

```json
{
  "timestamp": "2024-01-15T10:30:00.000000",
  "event_type": "login_attempt",
  "status": "FAILURE",
  "username": "master",
  "ip_address": "127.0.0.1",
  "source": "vault_app"
}
```

**Event Types**: `login_attempt`, `password_change`, `password_saved`, `password_updated`, `password_deleted`

## Incident Ticketing

Automatic ticket generation for:
- Brute force patterns (3+ failures followed by success)
- Account lockouts (5 failed attempts)

Tickets stored as JSON in `tickets/` directory.

## Project Structure

```
password-vault/
├── api/                 # FastAPI REST interface
│   ├── main.py
│   ├── models.py
│   └── routes/
├── cli/                 # Command-line interface
│   ├── generator.py
│   ├── tester.py
│   └── manager.py
├── core/                # Core business logic
│   ├── auth.py          # Authentication & lockout
│   ├── crypto.py        # Encryption utilities
│   ├── siem.py          # Security event logging
│   ├── tickets.py       # Incident management
│   └── vault_ops.py     # CRUD operations
├── tests/               # Test suite
├── passapp.py           # CLI entry point
├── password_checker.py  # Strength analysis
├── breach_check.py      # HaveIBeenPwned integration
├── Dockerfile
└── requirements.txt
```

## Testing

```bash
pytest                           # Run all tests
pytest --cov=. --cov-report=html # With coverage
pytest tests/test_api.py -v      # Specific test file
```

## License

MIT License

## Author

Daniel Ki - [LinkedIn](https://linkedin.com/in/daniel-ki-712749196)
