"""SIEM-compatible security event logging.

Provides structured JSON logging for security events, suitable for
integration with SIEM platforms like Splunk, ELK, or QRadar.
"""

import json
import logging
from datetime import datetime
from typing import Optional

from core.config import LOG_DIR, SIEM_LOG_FILE, LOGIN_LOG_FILE
from core.storage import ensure_directories, append_line, file_exists


# Module-level state
_logging_configured = False


def _configure_logging() -> None:
    """Configure standard logging on first use."""
    global _logging_configured
    if _logging_configured:
        return

    ensure_directories()
    logging.basicConfig(
        filename=LOGIN_LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(message)s'
    )
    _logging_configured = True


def log_login_attempt(success: bool, source_ip: str = "127.0.0.1") -> None:
    """Log login attempts with timestamp and IP.

    Args:
        success: Whether login was successful
        source_ip: Source IP address of the attempt
    """
    _configure_logging()
    status = "SUCCESS" if success else "FAILURE"
    logging.info(f"Login attempt - {status} - IP: {source_ip}")


def log_siem_event(
    event_type: str,
    status: str,
    username: str = "master",
    source_ip: str = "127.0.0.1",
    details: Optional[dict] = None
) -> None:
    """Log event in JSON format suitable for SIEM tools.

    Args:
        event_type: Type of security event (e.g., 'login_attempt', 'password_change')
        status: Event status (e.g., 'SUCCESS', 'FAILURE', 'LOCKOUT')
        username: User identifier
        source_ip: Source IP address
        details: Optional additional event details
    """
    ensure_directories()

    event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "status": status,
        "username": username,
        "ip_address": source_ip,
        "source": "vault_app"
    }

    if details:
        event["details"] = details

    append_line(SIEM_LOG_FILE, json.dumps(event))


def review_login_activity(count: int = 10) -> list[dict]:
    """Review recent login activity and flag suspicious patterns.

    Args:
        count: Number of recent entries to review

    Returns:
        List of parsed log entries with warning flags
    """
    if not file_exists(LOGIN_LOG_FILE):
        print("No login log file found.")
        return []

    print(f"\n=== Last {count} Login Attempts ===")

    with open(LOGIN_LOG_FILE, "r") as f:
        lines = f.readlines()[-count:]

    entries = []
    failures_in_row = 0
    last_was_failure = False

    for line in lines:
        line = line.strip()
        print(line)

        entry = {"raw": line, "warnings": []}

        if "FAILURE" in line:
            failures_in_row += 1
            last_was_failure = True
        elif "SUCCESS" in line and last_was_failure:
            entry["warnings"].append("Suspicious - Success after prior failures")
            print(f"Warning: {entry['warnings'][-1]}")
            failures_in_row = 0
            last_was_failure = False
        else:
            failures_in_row = 0
            last_was_failure = False

        entries.append(entry)

    if failures_in_row >= 3:
        print("Warning: Suspicious - Multiple consecutive failures")

    return entries


def get_siem_events(limit: int = 100) -> list[dict]:
    """Read and parse SIEM log events.

    Args:
        limit: Maximum number of events to return

    Returns:
        List of parsed event dictionaries
    """
    if not file_exists(SIEM_LOG_FILE):
        return []

    events = []
    with open(SIEM_LOG_FILE, "r") as f:
        for line in f:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return events[-limit:]


def count_events_by_status(event_type: Optional[str] = None) -> dict[str, int]:
    """Count SIEM events grouped by status.

    Args:
        event_type: Optional filter by event type

    Returns:
        Dictionary mapping status to count
    """
    events = get_siem_events(limit=10000)
    counts = {}

    for event in events:
        if event_type and event.get("event_type") != event_type:
            continue

        status = event.get("status", "UNKNOWN")
        counts[status] = counts.get(status, 0) + 1

    return counts
