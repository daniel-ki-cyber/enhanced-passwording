"""Incident ticket management system.

Generates and manages security incident tickets based on SIEM events.
Supports ticket lifecycle from creation through resolution and reporting.
"""

import os
import uuid
from datetime import datetime
from typing import Optional

from core.config import TICKET_DIR, REPORT_DIR
from core.storage import (
    ensure_directories,
    load_json,
    save_json,
    list_json_files,
    file_exists,
)
from core.siem import get_siem_events


def generate_ticket_id() -> str:
    """Generate a unique incident ticket ID.

    Returns:
        Formatted ticket ID (e.g., 'INC-a1b2c3d4')
    """
    return f"INC-{str(uuid.uuid4())[:8]}"


def create_ticket(issue: str, details: str, timestamp: Optional[str] = None) -> str:
    """Create a new incident ticket.

    Args:
        issue: Brief description of the issue
        details: Detailed information about the incident
        timestamp: Optional timestamp (defaults to now)

    Returns:
        The new ticket ID
    """
    ensure_directories()

    ticket_id = generate_ticket_id()
    ticket = {
        "id": ticket_id,
        "timestamp": timestamp or datetime.now().isoformat(),
        "issue": issue,
        "details": details,
        "status": "OPEN"
    }

    filepath = os.path.join(TICKET_DIR, f"{ticket_id}.json")
    save_json(filepath, ticket)

    return ticket_id


def get_ticket(ticket_id: str) -> Optional[dict]:
    """Retrieve a ticket by ID.

    Args:
        ticket_id: Ticket identifier

    Returns:
        Ticket data dictionary, or None if not found
    """
    filepath = os.path.join(TICKET_DIR, f"{ticket_id}.json")
    return load_json(filepath)


def list_tickets(status_filter: Optional[str] = None) -> list[dict]:
    """List all tickets, optionally filtered by status.

    Args:
        status_filter: Optional status to filter by ('OPEN', 'RESOLVED')

    Returns:
        List of ticket dictionaries
    """
    ensure_directories()
    tickets = []

    for filepath in list_json_files(TICKET_DIR):
        ticket = load_json(filepath)
        if ticket:
            if status_filter is None or ticket.get("status") == status_filter:
                tickets.append(ticket)

    return tickets


def list_open_tickets() -> list[str]:
    """List all open tickets and print summary.

    Returns:
        List of open ticket IDs
    """
    print("\n--- Open Tickets ---")
    tickets = list_tickets(status_filter="OPEN")

    if not tickets:
        print("No open tickets found.")
        return []

    for i, t in enumerate(tickets, start=1):
        print(f"{i}. {t['id']} - {t['issue']} @ {t['timestamp']}")

    return [t['id'] for t in tickets]


def resolve_ticket(ticket_id: str, resolution_note: Optional[str] = None) -> bool:
    """Resolve a ticket with optional note.

    Args:
        ticket_id: Ticket to resolve
        resolution_note: Optional resolution details (prompts if None)

    Returns:
        True if resolved successfully
    """
    ticket = get_ticket(ticket_id)
    if ticket is None:
        print(f"No ticket found with ID: {ticket_id}")
        return False

    if ticket.get("status") == "RESOLVED":
        print(f"Ticket {ticket_id} is already resolved.")
        return False

    if resolution_note is None:
        resolution_note = input("Enter a resolution note: ").strip()

    ticket["status"] = "RESOLVED"
    ticket["resolved_at"] = datetime.now().isoformat()
    ticket["resolution_note"] = resolution_note

    filepath = os.path.join(TICKET_DIR, f"{ticket_id}.json")
    save_json(filepath, ticket)

    print(f"Ticket {ticket_id} marked as RESOLVED.")
    return True


def generate_tickets_from_logs() -> int:
    """Generate tickets from suspicious patterns in SIEM logs.

    Analyzes SIEM events for:
    - Brute force patterns (3+ failures followed by success)
    - Account lockouts

    Returns:
        Number of new tickets created
    """
    events = get_siem_events(limit=10000)

    if not events:
        print("No SIEM logs found.")
        return 0

    failures = 0
    new_tickets = 0

    for event in events:
        status = event.get("status", "")
        timestamp = event.get("timestamp", datetime.now().isoformat())

        if status == "FAILURE":
            failures += 1

        elif status == "SUCCESS":
            if failures >= 3:
                create_ticket(
                    issue="Brute force login pattern detected",
                    details=f"{failures} consecutive login failures followed by success",
                    timestamp=timestamp
                )
                new_tickets += 1
            failures = 0

        elif status == "LOCKOUT":
            create_ticket(
                issue="Account lockout detected",
                details="Too many failed master password attempts (lockout triggered)",
                timestamp=timestamp
            )
            new_tickets += 1
            failures = 0

    print(f"Generated {new_tickets} new ticket(s).")
    return new_tickets


def export_resolved_tickets_report() -> Optional[str]:
    """Export all resolved tickets to a text report.

    Returns:
        Report filepath on success, None if no resolved tickets
    """
    os.makedirs(REPORT_DIR, exist_ok=True)
    report_path = os.path.join(REPORT_DIR, "resolved_tickets_report.txt")

    resolved = list_tickets(status_filter="RESOLVED")

    if not resolved:
        print("No resolved tickets to report.")
        return None

    with open(report_path, "w") as report:
        report.write("=== Resolved Ticket Report ===\n\n")
        for t in resolved:
            report.write(f"ID: {t['id']}\n")
            report.write(f"Issue: {t['issue']}\n")
            report.write(f"Resolved At: {t.get('resolved_at', 'Unknown')}\n")
            report.write(f"Resolution Note: {t.get('resolution_note', 'N/A')}\n")
            report.write("\n---\n\n")

    print(f"Resolved ticket report written to: {report_path}")
    return report_path


def ticket_menu() -> None:
    """Interactive CLI menu for ticket management."""
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
            confirm = input(f"You have selected {selected_id}. Continue? (y/n): ").strip().lower()
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
