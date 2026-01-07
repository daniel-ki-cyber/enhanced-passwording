# Password Vault

A secure password management tool with enterprise-grade security features including encrypted storage, breach detection, and SIEM integration.

## Purpose

This project demonstrates practical security engineering by implementing a complete credential management system that goes beyond basic password storage. It addresses real-world security requirements:

- **Credential Security**: Passwords encrypted at rest using industry-standard algorithms with key derivation that meets current OWASP recommendations
- **Breach Awareness**: Integration with HaveIBeenPwned to identify compromised credentials before they become a problem
- **Security Operations**: Structured logging and automated incident detection for SOC workflows
- **Defense in Depth**: Multiple layers including master password authentication, account lockout, and audit trails

## Features

### Password Management
- Generate cryptographically secure passwords using Python's `secrets` module
- Customizable complexity (length, character sets)
- Strength analysis with feedback on weak patterns
- Detection of 100+ commonly used passwords
- Password history tracking to prevent reuse

### Encryption & Authentication
- **Vault Encryption**: Fernet symmetric encryption (AES-128-CBC with HMAC-SHA256)
- **Key Derivation**: PBKDF2-SHA256 with 600,000 iterations (per NIST SP 800-132)
- **Master Password**: Salted hash storage with brute-force protection
- **Lockout Policy**: 5 failed attempts triggers 60-second lockout

### Breach Detection
- HaveIBeenPwned API integration using k-Anonymity model
- Only SHA-1 hash prefix (5 characters) sent to API—full password never transmitted
- Breach count severity warnings with actionable recommendations

### Security Logging (SIEM)
- JSON Lines format (`logs/siem_events.jsonl`) for direct ingestion into Splunk, ELK, QRadar
- Event types: `login_attempt`, `password_change`, `password_saved`, `password_updated`, `password_deleted`
- Includes timestamp, status, username, source IP, and custom details

### Incident Ticketing
- Automatic ticket generation from log analysis
- Detects brute force patterns (3+ failures followed by success)
- Flags account lockouts for investigation
- Ticket lifecycle management (create, resolve, export reports)

## Quick Start

### Prerequisites
- Python 3.10+
- pip

### Installation
```bash
git clone https://github.com/daniel-ki-cyber/enhanced-passwording.git
cd enhanced-passwording
pip install -r requirements.txt
```

### CLI Usage
```bash
python passapp.py
```

First run prompts for master password setup. Menu options:
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
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

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
│  │ (passapp.py)│     │  (FastAPI)  │     │ (HaveIBeenPwned)    │   │
│  └──────┬──────┘     └──────┬──────┘     └──────────┬──────────┘   │
│         │                   │                       │               │
│         └─────────┬─────────┴───────────────────────┘               │
│                   │                                                  │
│         ┌─────────▼─────────┐                                       │
│         │   Password        │                                       │
│         │   Checker         │◄─── Pattern Detection                 │
│         │                   │◄─── Common Password List              │
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
│    ▼              ▼              ▼   └─────────────────┘           │
│ ┌──────┐    ┌──────────┐   ┌───────┐                                │
│ │Master│    │  Vault   │   │ Key   │                                │
│ │ Hash │    │ (JSON)   │   │ File  │                                │
│ └──────┘    └──────────┘   └───────┘                                │
│                                                                      │
│  Encryption: Fernet (AES-128-CBC + HMAC) + PBKDF2-SHA256            │
└─────────────────────────────────────────────────────────────────────┘
```

## API Reference

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health and vault status |
| POST | `/generate` | Generate password with options |
| POST | `/check` | Analyze strength + check breaches |
| POST | `/breach-check` | HaveIBeenPwned lookup only |

### Protected Endpoints (Basic Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vault` | List all entries |
| GET | `/vault/{label}` | Retrieve specific password |
| POST | `/vault` | Store new password |
| PUT | `/vault/{label}` | Update existing password |
| DELETE | `/vault/{label}` | Remove entry |
| GET | `/vault/{label}/history` | Previous passwords for entry |

## Security Implementation

| Component | Implementation | Reference |
|-----------|---------------|-----------|
| Password Hashing | PBKDF2-SHA256, 600K iterations | OWASP 2023, NIST SP 800-132 |
| Vault Encryption | Fernet (AES-128-CBC + HMAC-SHA256) | cryptography.io |
| Breach Detection | SHA-1 k-Anonymity model | HaveIBeenPwned API |
| Lockout | 5 attempts / 60s cooldown | OWASP Authentication |

## Project Structure

```
password-vault/
├── api/                    # REST API layer
│   ├── main.py             # FastAPI application
│   ├── models.py           # Pydantic request/response models
│   ├── dependencies.py     # Auth and shared dependencies
│   └── routes/             # Endpoint handlers
├── cli/                    # Command-line interface
│   ├── generator.py        # Password generation flow
│   ├── tester.py           # Password testing flow
│   └── manager.py          # Vault management flow
├── core/                   # Business logic
│   ├── auth.py             # Master password, lockout
│   ├── crypto.py           # Encryption/decryption
│   ├── vault_ops.py        # CRUD operations
│   ├── siem.py             # Security event logging
│   └── tickets.py          # Incident management
├── tests/                  # Test suite
├── passapp.py              # CLI entry point
├── password_checker.py     # Strength analysis
├── breach_check.py         # HaveIBeenPwned integration
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=. --cov-report=html

# Specific module
pytest tests/test_api.py -v
```

## License

MIT License

## Author

Daniel Ki - [LinkedIn](https://linkedin.com/in/daniel-ki-712749196)
