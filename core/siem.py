"""SIEM-compatible security event logging.

Provides structured JSON logging for security events, suitable for
integration with SIEM platforms like Splunk, ELK, or QRadar.

Includes log rotation to prevent disk exhaustion and manage retention.
"""

import gzip
import json
import logging
import os
import shutil
from datetime import datetime
from logging.handlers import RotatingFileHandler
from threading import Lock
from typing import Optional

from core.config import LOG_DIR, SIEM_LOG_FILE, LOGIN_LOG_FILE
from core.storage import ensure_directories, append_line, file_exists


# Module-level state
_logging_configured = False
_rotation_lock = Lock()

# Log rotation configuration
# Can be overridden via environment variables
SIEM_LOG_MAX_BYTES = int(os.environ.get("SIEM_LOG_MAX_BYTES", 10 * 1024 * 1024))  # 10MB default
SIEM_LOG_BACKUP_COUNT = int(os.environ.get("SIEM_LOG_BACKUP_COUNT", 5))  # 5 backups
SIEM_LOG_COMPRESS = os.environ.get("SIEM_LOG_COMPRESS", "true").lower() == "true"


def _compress_log_file(filepath: str) -> None:
    """Compress a log file using gzip.

    Args:
        filepath: Path to the file to compress
    """
    try:
        with open(filepath, 'rb') as f_in:
            with gzip.open(f"{filepath}.gz", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        os.remove(filepath)
    except Exception:
        # Don't fail logging if compression fails
        pass


def _rotate_siem_log() -> None:
    """Rotate SIEM log file if it exceeds size limit.

    Implements rotation with compression:
    1. Checks if current log exceeds SIEM_LOG_MAX_BYTES
    2. Rotates existing backups (log.1 -> log.2, etc.)
    3. Moves current log to log.1
    4. Compresses old backups if SIEM_LOG_COMPRESS is enabled
    """
    with _rotation_lock:
        if not file_exists(SIEM_LOG_FILE):
            return

        try:
            file_size = os.path.getsize(SIEM_LOG_FILE)
        except OSError:
            return

        if file_size < SIEM_LOG_MAX_BYTES:
            return

        # Rotate existing backup files
        for i in range(SIEM_LOG_BACKUP_COUNT - 1, 0, -1):
            src = f"{SIEM_LOG_FILE}.{i}"
            src_gz = f"{src}.gz"
            dst = f"{SIEM_LOG_FILE}.{i + 1}"
            dst_gz = f"{dst}.gz"

            # Handle both compressed and uncompressed backups
            if os.path.exists(src_gz):
                if i + 1 <= SIEM_LOG_BACKUP_COUNT:
                    try:
                        shutil.move(src_gz, dst_gz)
                    except OSError:
                        pass
                else:
                    try:
                        os.remove(src_gz)
                    except OSError:
                        pass
            elif os.path.exists(src):
                if i + 1 <= SIEM_LOG_BACKUP_COUNT:
                    try:
                        shutil.move(src, dst)
                    except OSError:
                        pass
                else:
                    try:
                        os.remove(src)
                    except OSError:
                        pass

        # Delete oldest backup if over limit
        oldest = f"{SIEM_LOG_FILE}.{SIEM_LOG_BACKUP_COUNT + 1}"
        for ext in ['', '.gz']:
            if os.path.exists(oldest + ext):
                try:
                    os.remove(oldest + ext)
                except OSError:
                    pass

        # Move current log to .1
        backup_path = f"{SIEM_LOG_FILE}.1"
        try:
            shutil.move(SIEM_LOG_FILE, backup_path)

            # Compress the backup if enabled
            if SIEM_LOG_COMPRESS:
                _compress_log_file(backup_path)
        except OSError:
            pass


def _configure_logging() -> None:
    """Configure standard logging with rotation on first use."""
    global _logging_configured
    if _logging_configured:
        return

    ensure_directories()

    # Use RotatingFileHandler for login.log
    handler = RotatingFileHandler(
        LOGIN_LOG_FILE,
        maxBytes=SIEM_LOG_MAX_BYTES,
        backupCount=SIEM_LOG_BACKUP_COUNT,
    )
    handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

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

    # Check if rotation is needed before writing
    _rotate_siem_log()

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
