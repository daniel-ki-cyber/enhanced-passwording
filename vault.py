import json
import os
import hashlib
import time
import logging
import uuid
from cryptography.fernet import Fernet      # save password entry securely
from datetime import datetime

KEY_FILE = "vault.key" # filename where encryption key is stored
VAULT_FILE = "vault.json" # filename where passwords are stored
MASTER_FILE = "master.hash" # filename where hashed master password is storeed
SIEM_LOG_FILE = "logs/siem_events.jsonl" # path for SIEM-style JSONL log file

# ensure logs directory and necessary folders for ticketing/reporting exists
os.makedirs("logs", exist_ok=True)
siem_log_path = os.path.join("logs", "siem_events.jsonl")
if not os.path.exists(siem_log_path):
    with open(siem_log_path, "w") as f:
        f.write("")  # create empty log file

# configure logging and record login attempts
logging.basicConfig(
    filename='login.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# log login attempts with timestamp and IP (assuming local IP)
def log_attempt(success: bool, source_ip="127.0.0.1"):
    status = "SUCCESS" if success else "FAILURE"
    logging.info(f"Login attempt - {status} - IP: {source_ip}")

# log event in JSON format suitable for SIEM tools
def log_siem_event(event_type, status, username="master", source_ip="127.0.0.1"):
    event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "status": status,
        "username": username,
        "ip_address": source_ip,
        "source": "vault_app"
    }
    # path for SIEM-style JSONL log file
    with open(SIEM_LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

# generate or load master key  (symmetric encryption)
# uses cryptography library (Fernet AES encryption)
def load_key():
    if not os.path.exists(KEY_FILE): 
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

# Securely create and save a master password hash with a salt.
def set_master_password():
    import getpass # securely input passwords (prevent echo in terminal)
    print("\nSet up a new master password.")
    while True:
        pw1 = getpass.getpass("Enter new master password: ")
        pw2 = getpass.getpass("Confirm master password: ")
        if pw1 != pw2:
            print("Passwords do not match. Try again.")
        elif len(pw1) < 6:
            print("Password too short. Use at least 6 characters.")
        else:
            break

    salt = os.urandom(16)
    hash_bytes = hashlib.pbkdf2_hmac("sha256", pw1.encode(), salt, 100000)
    # filename where hashed master password is stored
    with open(MASTER_FILE, "wb") as f:
        f.write(salt + hash_bytes)
    print("Master password set successfully.")

# Prompt for master password and verify against stored hash.
# Returns True if password is correct, False otherwise.
def verify_master_password():
    import getpass # securely input passwords
    if not os.path.exists(MASTER_FILE):
        print("No master password set.")
        set_master_password()

    with open(MASTER_FILE, "rb") as f:
        data = f.read()
        salt = data[:16]
        stored_hash = data[16:]
    MAX_ATTEMPTS = 5
    for attempt in range(1, MAX_ATTEMPTS + 1):
        pw = getpass.getpass("Enter master password: ")
        hash_try = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 100000)
        if hash_try == stored_hash:
            log_siem_event("login_attempt", "SUCCESS")
            print("Access granted.")
            log_attempt(True)
            return True
        else:
            remaining = MAX_ATTEMPTS - attempt
            print(f"Incorrect password. {remaining} attempt(s) remaining.")
            log_siem_event("login_attempt", "FAILURE")
            log_attempt(False)
    
    log_siem_event("login_attempt", "LOCKOUT")
    print("Too many failed attempts. Locked out for 60 seconds...")
    log_attempt(False)
    time.sleep(60)
    return False



# encrypt and store new password entry under given label name
# initializes creation timestamp and empty history list
def save_password(name, password):
    fernet = load_key()
    encrypted_password = fernet.encrypt(password.encode()).decode()

    entry = {
        "password": encrypted_password,
        "created": datetime.now().isoformat(),
        "history": []  # no history yet for initial save
    }

    data = {}
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "r") as f:
            data = json.load(f)

    data[name] = entry

    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)


# decrypt and return all saved password entries as a dictionary
# each entry includes decrypted password and creation date
def load_all_passwords():
    fernet = load_key()
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "r") as f:
        raw_data = json.load(f)

    output = {}
    for name, entry in raw_data.items():
        decrypted = fernet.decrypt(entry["password"].encode()).decode()
        output[name] = {
            "password": decrypted,
            "created": entry.get("created", "Unknown")
        }

    return output

# update existing password and archive previous one into history
def update_password(name, new_password):
    fernet = load_key()
    encrypted_new = fernet.encrypt(new_password.encode()).decode()
    # filename where encrypted passwords are stored
    if not os.path.exists(VAULT_FILE):
        return False

    with open(VAULT_FILE, "r") as f:
        data = json.load(f)

    if name not in data:
        return False

    entry = data[name]

    # get old password and add it to history
    old_encrypted = entry.get("password")
    if "history" not in entry:
        entry["history"] = []
    if old_encrypted:
        entry["history"].append({
            "password": old_encrypted,
            "timestamp": entry.get("created", datetime.now().isoformat())
        })

    # update current password
    entry["password"] = encrypted_new
    entry["created"] = datetime.now().isoformat()

    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)

    return True
# remove password entry from vault by name
def delete_password(name):
    if not os.path.exists(VAULT_FILE):
        return False

    with open(VAULT_FILE, "r") as f:
        data = json.load(f)

    if name not in data:
        return False

    del data[name]

    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return True

# return list of previously used passwords for given name
# decrypt and return password history stored in the vault
def get_password_history(name):
    fernet = load_key()
    if not os.path.exists(VAULT_FILE):
        return []

    with open(VAULT_FILE, "r") as f:
        data = json.load(f)

    if name not in data:
        return []

    history = data[name].get("history", [])
    return [
        fernet.decrypt(h["password"].encode()).decode()
        for h in history
    ]

# review recent login activity and flag suspicious patterns.
def review_login_activity(count=10):
    if not os.path.exists("login.log"):
        print("No login log file found.")
        return

    print(f"\n=== Last {count} Login Attempts ===")

    with open("login.log", "r") as f:
        lines = f.readlines()[-count:]

    failures_in_row = 0
    last_was_failure = False

    for line in lines:
        print(line.strip())
        if "FAILURE" in line:
            failures_in_row += 1
            last_was_failure = True
        elif "SUCCESS" in line and last_was_failure:
            print("⚠️  Suspicious: Success after prior failures")
            failures_in_row = 0
            last_was_failure = False
        else:
            failures_in_row = 0
            last_was_failure = False

    if failures_in_row >= 3:
        print("⚠️  Suspicious: Multiple consecutive failures")


# ensure tickets directory exists
TICKET_DIR = "tickets"
os.makedirs(TICKET_DIR, exist_ok=True) # directory for incident tickets

# generate structured tickets based on suspicious patterns in SIEM logs.
def generate_tickets_from_logs():
    SIEM_LOG_FILE = os.path.join("logs", "siem_events.jsonl")
    if not os.path.exists(SIEM_LOG_FILE):
        print("No SIEM logs found.")
        return

    with open(SIEM_LOG_FILE, "r") as f:
        lines = f.readlines()

    failures = 0
    new_tickets = 0

    for i in range(len(lines)):
        try:
            event = json.loads(lines[i])
        except json.JSONDecodeError:
            continue

        status = event.get("status", "")
        timestamp = event.get("timestamp", datetime.now().isoformat())

        if status == "FAILURE":
            failures += 1
        elif status == "SUCCESS":
            if failures >= 3:
                new_tickets += 1
                ticket_id = f"INC-{str(uuid.uuid4())[:8]}"
                ticket = {
                    "id": ticket_id,
                    "timestamp": timestamp,
                    "issue": "Brute force login pattern detected",
                    "details": f"{failures} consecutive login failures followed by success",
                    "status": "OPEN"
                }
                with open(os.path.join(TICKET_DIR, f"{ticket_id}.json"), "w") as t:
                    json.dump(ticket, t, indent=2)
            failures = 0
        elif status == "LOCKOUT":
            new_tickets += 1
            ticket_id = f"INC-{str(uuid.uuid4())[:8]}"
            ticket = {
                "id": ticket_id,
                "timestamp": timestamp,
                "issue": "Account lockout detected",
                "details": "Too many failed master password attempts (lockout triggered)",
                "status": "OPEN"
            }
            with open(os.path.join(TICKET_DIR, f"{ticket_id}.json"), "w") as t:
                json.dump(ticket, t, indent=2)
            failures = 0
    # list all open tickets in tickets directory
    print(f"Generated {new_tickets} new ticket(s).")

# list all open tickets in the tickets directory
def list_open_tickets():
    print("\n--- Open Tickets ---")
    open_tickets = []

    for filename in os.listdir(TICKET_DIR):
        if filename.endswith(".json"):
            with open(os.path.join(TICKET_DIR, filename), "r") as f:
                ticket = json.load(f)
                if ticket.get("status") == "OPEN":
                    open_tickets.append(ticket)

    if not open_tickets:
        print("No open tickets found.")
        return []

    for i, t in enumerate(open_tickets, start=1):
        print(f"{i}. {t['id']} - {t['issue']} @ {t['timestamp']}")

    return [t['id'] for t in open_tickets]

# resolve a specific ticket by ID and add resolution details
def resolve_ticket(ticket_id): # mark specific ticket as resolved and record resolution note
    file_path = os.path.join(TICKET_DIR, f"{ticket_id}.json")
    if not os.path.exists(file_path):
        print(f"No ticket found with ID: {ticket_id}")
        return

    with open(file_path, "r") as f:
        ticket = json.load(f)

    if ticket.get("status") == "RESOLVED":
        print(f"Ticket {ticket_id} is already resolved.")
        return

    resolution_note = input("Enter a resolution note: ").strip()
    ticket["status"] = "RESOLVED"
    ticket["resolved_at"] = datetime.now().isoformat()
    ticket["resolution_note"] = resolution_note

    with open(file_path, "w") as f:
        json.dump(ticket, f, indent=2)

    print(f"✅ Ticket {ticket_id} marked as RESOLVED.")

# interactive CLI menu for managing tickets
def ticket_menu():
    while True:
        print("\n=== Ticket Management ===")
        print("1. View Open Tickets")
        print("2. Resolve a Ticket")
        print("3. Export Resolved Ticket Report")
        print("4. Exit Ticket Menu")

        choice = input("Choose an option (1-4): ").strip()
        if choice == '1':
            list_open_tickets()

        elif choice == '2':
            ticket_ids = list_open_tickets()
            if not ticket_ids:
                continue

            sel = input("Select a ticket to resolve by number (or 'b' to go back): ").strip().lower()
            if sel == 'b':
                continue

            if not sel.isdigit() or not (1 <= int(sel) <= len(ticket_ids)):
                print("Invalid selection.")
                continue

            selected_id = ticket_ids[int(sel) - 1]
            confirm = input(f"You have selected the ticket {selected_id}. Continue? (y/n): ").strip().lower()
            if confirm == 'y':
                resolve_ticket(selected_id)
            else:
                print("Cancelled ticket resolution.")

        elif choice == '3':
            export_resolved_tickets_report()

        elif choice == '4':
            break

        else:
            print("Invalid choice. Please enter 1 to 4.")

# export all resolved tickets to a text-based audit report.
def export_resolved_tickets_report():
    REPORT_DIR = "reports"
    os.makedirs(REPORT_DIR, exist_ok=True)
    report_path = os.path.join(REPORT_DIR, "resolved_tickets_report.txt")

    resolved_tickets = []

    for filename in os.listdir(TICKET_DIR):
        if filename.endswith(".json"):
            with open(os.path.join(TICKET_DIR, filename), "r") as f:
                ticket = json.load(f)
                if ticket.get("status") == "RESOLVED":
                    resolved_tickets.append(ticket)

    if not resolved_tickets:
        print("No resolved tickets to report.")
        return

    with open(report_path, "w") as report:
        report.write("=== Resolved Ticket Report ===\n\n")
        for t in resolved_tickets:
            report.write(f"ID: {t['id']}\n")
            report.write(f"Issue: {t['issue']}\n")
            report.write(f"Resolved At: {t.get('resolved_at', 'Unknown')}\n")
            report.write(f"Resolution Note: {t.get('resolution_note', 'N/A')}\n")
            report.write("\n---\n\n")

    print(f"Resolved ticket report written to: {report_path}")
