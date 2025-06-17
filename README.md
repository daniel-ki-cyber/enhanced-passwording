# Password Vault and Security Ticketing System

This project is a command-line password manager combined with a security event tracking and ticketing system. It was developed as a hands-on cybersecurity learning tool and portfolio piece.

---

## Features

- Encrypted password storage using AES (Fernet)
- Master password protected with PBKDF2 and salted hash
- Automatic lockout after multiple failed login attempts
- Structured logging of all login activity in JSONL format (SIEM-style)
- Detection of suspicious patterns such as brute-force attempts or lockouts
- Automatic ticket generation for suspicious activity
- Command-line interface for viewing and resolving security tickets
- Exportable audit report of resolved incidents

---

## Installation

1. Clone or download the project.
2. Install dependencies (cryptography):
```bash
pip install -r requirements.txt
```

---

## Usage

Run the application using:

```bash
python main.py
```

If it's your first time running the app, you'll be prompted to create a master password. 
Note: You cannot change the master password yet. This password also does not undergo the password recommendations suggested by the generator and checker programs.

---

## Simulating Suspicious Activity

To simulate a brute-force pattern:
- Enter the wrong master password three times
- Then enter the correct password

This will log multiple failed attempts followed by a success, triggering a ticket.

---

### Generating Tickets from Logs

After triggering suspicious behavior (like failed login attempts), you must manually generate tickets from the SIEM logs before they will appear in the ticket menu:

```python
from vault import generate_tickets_from_logs
generate_tickets_from_logs()
```

## Ticket Management

From a Python shell or script, you can run:

```python
from vault import ticket_menu
ticket_menu()
```

Options include:
- Viewing open tickets
- Resolving tickets with notes
- Exporting resolved ticket reports

Reports are written to `reports/resolved_tickets_report.txt`.

---

## Project Structure

```
vault.py               # Core vault logic and ticketing system
passapp.py             # CLI for password generation and management
main.py                # Launch point for the application
requirements.txt       # Python dependencies
logs/                  # Login activity logs (JSONL format)
tickets/               # JSON files for each open/resolved ticket
reports/               # Resolved ticket audit reports
```

---

## Purpose

This project is designed to demonstrate practical skills in:
- Secure storage
- Access control
- Event logging and incident detection
- Cybersecurity operations workflows

It serves as a simulated environment to showcase core principles used by SOC teams and entry-level security analysts.
