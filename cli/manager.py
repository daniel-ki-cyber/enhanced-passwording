"""Password management CLI flows.

Handles viewing, editing, and deleting saved passwords.
"""

from typing import Optional

from password_checker import check_password_strength
from vault import (
    load_all_passwords,
    update_password,
    delete_password,
    get_password_history,
)

from cli.prompts import confirm_action, double_confirm


def select_password() -> Optional[str]:
    """List saved passwords and let user select by label.

    Supports searching by keyword.

    Returns:
        Selected label, or None to cancel
    """
    passwords = load_all_passwords()
    if not passwords:
        print("No saved passwords found.")
        return None

    labels = list(passwords.keys())

    while True:
        print("\n--- Saved Passwords ---")
        for idx, label in enumerate(labels, start=1):
            entry = passwords[label]
            warning = " [!]" if entry.get("age_warning") else ""
            print(f"{idx}. {label}{warning}")

        action = input(
            "\nEnter a number to select, 's' to search, or 'b' to go back: "
        ).strip().lower()

        if action == 'b':
            return None

        elif action == 's':
            query = input("Enter label or keyword to search: ").strip().lower()
            matches = [label for label in labels if query in label.lower()]

            if not matches:
                print("No matching entries found.")
                continue

            print("\nMatching Results:")
            for i, match in enumerate(matches, start=1):
                print(f"{i}. {match}")

            sel = input(
                f"Select a result to manage (1 to {len(matches)}), or 'b' to go back: "
            ).strip().lower()

            if sel == 'b':
                continue
            if sel.isdigit() and 1 <= int(sel) <= len(matches):
                return matches[int(sel) - 1]
            else:
                print("Invalid selection.")

        elif action.isdigit() and 1 <= int(action) <= len(labels):
            return labels[int(action) - 1]

        else:
            print("Invalid input.")


def display_details(label: str, entry: dict) -> tuple[str, list[str]]:
    """Show full details and strength feedback of a password.

    Args:
        label: Password label
        entry: Password entry data

    Returns:
        Tuple of (strength, feedback)
    """
    pwd = entry["password"]
    created = entry.get("created", "Unknown")
    age_warning = entry.get("age_warning")
    strength, feedback = check_password_strength(pwd)

    print(f"\n--- Details for '{label}' ---")
    print(f"Password: {pwd}")
    print(f"Created: {created}")
    print(f"Strength: {strength}")

    if age_warning:
        print(f"Warning: {age_warning}")

    if feedback:
        print("Suggestions:")
        for tip in feedback:
            print(f"  - {tip}")

    return strength, feedback


def update_flow(label: str, old_entry: dict) -> bool:
    """Prompt user to replace password with reuse detection.

    Args:
        label: Password label
        old_entry: Current password entry

    Returns:
        True if updated, False otherwise
    """
    new_pwd = input("Enter new password to replace the existing one: ").strip()
    if not new_pwd:
        print("No password entered. Update canceled.")
        return False

    # Check for password reuse
    current_password = old_entry["password"]
    previous_passwords = get_password_history(label)
    all_previous = previous_passwords + [current_password]

    if new_pwd in all_previous:
        print("Warning: You are attempting to reuse a password that was used before.")
        if not confirm_action("Reuse anyway?"):
            print("Update canceled due to reused password.")
            return False

    # Analyze new password
    strength, feedback = check_password_strength(new_pwd)
    print(f"New Password Strength: {strength}")

    if feedback:
        print("Suggestions:")
        for tip in feedback:
            print(f"  - {tip}")

    if strength == "Weak" or any("common" in f.lower() for f in feedback):
        if not confirm_action("Warning: New password may still be weak. Proceed anyway?"):
            print("Update canceled due to weak password.")
            return False

    if not double_confirm("overwrite the existing password"):
        print("Update canceled.")
        return False

    if update_password(label, new_pwd):
        print(f"Password for '{label}' has been updated.")
        return True
    else:
        print("Failed to update entry.")
        return False


def delete_flow(label: str) -> bool:
    """Prompt user to delete password entry with confirmations.

    Args:
        label: Password label to delete

    Returns:
        True if deleted, False otherwise
    """
    if not confirm_action("Are you sure you want to delete this entry?"):
        print("Deletion canceled.")
        return False

    if not confirm_action("", require_word="DELETE"):
        print("Deletion canceled.")
        return False

    if delete_password(label):
        print(f"'{label}' has been deleted.")
        return True
    else:
        print("Failed to delete entry.")
        return False


def handle_action(label: str) -> None:
    """Route view/edit/delete commands for selected password.

    Args:
        label: Password label to manage
    """
    passwords = load_all_passwords()
    if label not in passwords:
        print("Selected label no longer exists.")
        return

    entry = passwords[label]

    while True:
        action = input(
            f"\nOptions for '{label}': (v)iew, (e)dit, (d)elete, (b)ack: "
        ).strip().lower()

        if action == 'b':
            print("Returning to password list.")
            return

        elif action == 'v':
            strength, feedback = display_details(label, entry)

            # Suggest update for weak/old passwords
            needs_update = (
                strength in ["Weak", "🔓 Weak"]
                or any("common" in f.lower() for f in feedback)
                or entry.get("age_warning")
            )

            if needs_update:
                prompt = input(
                    "This password may need updating. Would you like to update it? (y/n): "
                ).strip().lower()
                if prompt == 'y':
                    update_flow(label, entry)
                    return

        elif action == 'e':
            update_flow(label, entry)
            return

        elif action == 'd':
            if delete_flow(label):
                return

        else:
            print("Invalid option. Please enter 'v', 'e', 'd', or 'b'.")


def view_passwords_flow() -> None:
    """Show saved passwords menu and handle user selections."""
    while True:
        selected_label = select_password()
        if selected_label is None:
            break
        handle_action(selected_label)
