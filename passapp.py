# Personal Password Management Tool
# Purpose: Provide functionality for generating, saving, testing and managing passwords.
# Encrypts saved passwords using a symmetric key (Fernet/AES) to protect saved passwords


import string
import secrets
# import password strength checker function
from password_checker import check_password_strength
from vault import (
    save_password,                      # save password entry to encrypted vault (vault.json)
    load_all_passwords,                 # load and decrypt password entries
    update_password,                    # update a stored password and log history
    delete_password,                    # delete password entries from vault
    get_password_history                # retrieve previously used passwwords
)

# prompt user for valid password length and return length as an integer or none to cancel
def prompt_for_password_length():
    while True:
        val = input("Enter password length (8 to 16, or 'q' to cancel): ").strip().lower()
        if val in ['q', 'exit']:
            return None
        try:
            length = int(val)
            if 8 <= length <= 16:
                return length
            print("Please enter a number between 8 and 16.")
        except ValueError:
            print("Invalid input. Enter a number.")

# prompt user to choose character types to include in generated password
# returns a tuple for (uppercase, lowercase, digits, and special characters) as booleans, or none to cancel
def prompt_for_character_types():
    def ask(part):
        while True:
            ans = input(f"Include {part}? (y/n or q to cancel): ").strip().lower()
            if ans == 'q' or ans == 'exit':
                return None
            if ans in ['y', 'n']:
                return ans == 'y'
            print("Please enter 'y', 'n', or 'q' to cancel.")

    upper = ask("uppercase letters")
    if upper is None: return None
    lower = ask("lowercase letters")
    if lower is None: return None
    digits = ask("digits")
    if digits is None: return None
    special = ask("special characters")
    if special is None: return None

    if not any([upper, lower, digits, special]):
        print("At least one character type must be selected.\n")
        return prompt_for_character_types()

    return upper, lower, digits, special

# generates secure password using pool of selected character types from prompt_for_character_types()
# returns generated password as a string of specified length
def generate_password(length=12, use_upper=True, use_lower=True, use_digits=True, use_special=True):
    if length < 4:
        raise ValueError("Password length should be at least 4 characters.")

    character_pool = ''
    if use_upper:
        character_pool += string.ascii_uppercase
    if use_lower:
        character_pool += string.ascii_lowercase
    if use_digits:
        character_pool += string.digits
    if use_special:
        character_pool += string.punctuation

    if not character_pool:
        raise ValueError("At least one character type must be selected.")

    return ''.join(secrets.choice(character_pool) for _ in range(length))

# display generated or entered password
# analyze password strength and provide feedback
def preview_and_analyze_password(pwd):
    print(f"\nGenerated Password: {pwd}")
    # import password strength checker function
    strength, feedback = check_password_strength(pwd)
    print(f"Password Strength: {strength}")
    if feedback:
        print("Suggestions:")
        for tip in feedback:
            print(f"  - {tip}")
    return strength, feedback

# prompt user to save generated password
# encrypts and saves password with user-provided label if save is confirmed
def save_generated_password(pwd, strength, feedback):
    from vault import load_all_passwords  # ensure access to existing labels
    # ask user if they want to save password
    save = input("\nWould you like to save this password? (y/n): ").strip().lower()
    if save != 'y':
        print("Password not saved.")
        return

    if strength in ["Weak", "🔓 Weak"] or any("common" in f.lower() for f in feedback):
        # warn user if password is weak or common
        warn = input("⚠️ This password may be weak or common. Proceed with saving? (y/n): ").strip().lower()
        if warn != 'y':
            print("Save canceled due to weak password.")
            return
    # load currently saved password labels to avoid duplicates
    existing_labels = load_all_passwords()

    while True:
        # ask user for label name
        label = input("Enter a name or label for this password (example: 'Gmail'): ").strip()
        if not label:
            print("No label provided. Password not saved.")
            return
        # check if label is already in use
        if label in existing_labels:
            choice = input(f"A password with this label already exists. Do you want to update it instead? (y/n): ").strip().lower()
            if choice == 'y':
                # import functions for saving and updated encrypted passwords
                if update_password(label, pwd):
                    print(f"Password for '{label}' has been updated.")
                # handle invalid input
                else:
                    print("Failed to update password.")
                return
            else:
                print("Please choose a different label.")
        else:
            # import functions for saving and updating encrypted passwords
            save_password(label, pwd)
            print(f"Password saved as '{label}'.")
            return

# conduct full process of generating password
# includes asking options, displays strength, and saves if confirmed
def generate_password_flow():
    print("\n--- Password Generation ---")
    length = prompt_for_password_length()
    if length is None:
        print("Canceled password generation.")
        return

    char_types = prompt_for_character_types()
    if char_types is None:
        print("Canceled password generation.")
        return

    upper, lower, digits, special = char_types
    pwd = generate_password(length, upper, lower, digits, special)
    strength, feedback = preview_and_analyze_password(pwd)
    save_generated_password(pwd, strength, feedback)

# allows user to manually enter personal passwords, test their strength, and give the option to encrypt and store them
def test_password_flow():
    print("\n--- Test a Password ---")
    user_pwd = input("Enter the password you want to test: ").strip()
    strength, feedback = preview_and_analyze_password(user_pwd)
    save_generated_password(user_pwd, strength, feedback)

# list saved passwords and let user select the label name
# supports label searching by keyword 
def select_saved_password():
    passwords = load_all_passwords()
    if not passwords:
        print("No saved passwords found.")
        return None

    labels = list(passwords.keys())

    while True:
        print("\n--- Saved Passwords ---")
        for idx, label in enumerate(labels, start=1):
            print(f"{idx}. {label}")

        action = input("\nEnter a number to select, 's' to search, or 'b' to go back: ").strip().lower()

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

            sel = input(f"Select a result to manage (1 to {len(matches)}), or 'b' to go back: ").strip().lower()
            if sel == 'b':
                continue
            if sel.isdigit() and 1 <= int(sel) <= len(matches):
                return matches[int(sel) - 1]
            else:
                # handle invalid input
                print("Invalid selection.")

        elif action.isdigit() and 1 <= int(action) <= len(labels):
            return labels[int(action) - 1]

        else:
            print("Invalid input.")

# show full details and strength feedback of a selected password
def display_password_details(label, entry):
    pwd = entry["password"]
    created = entry.get("created", "Unknown")
    # import password strength checker
    strength, feedback = check_password_strength(pwd)

    print(f"\n--- Details for '{label}' ---")
    print(f"Password: {pwd}")
    print(f"Created: {created}")
    print(f"Strength: {strength}")
    if feedback:
        print("Suggestions:")
        for tip in feedback:
            print(f"  - {tip}")

# prompt user to replace password for an existing entry
# returns feedback if replacement password has been used before
# provides strength analysis and confirmation prompts
def update_password_flow(label, old_entry):
    new_pwd = input("Enter new password to replace the existing one: ").strip()

    current_password = old_entry["password"]
    previous_passwords = get_password_history(label)
    print(f"(Debug) Previously used passwords for '{label}': {len(previous_passwords)} total.")
    all_previous = previous_passwords + [current_password]

    if new_pwd in all_previous:
        print("⚠️ Warning: You are attempting to reuse a password that was used before or is currently active.")
        reuse_confirm = input("Reuse anyway? (y/n): ").strip().lower()
        if reuse_confirm != 'y':
            print("Update canceled due to reused password.")
            return

    #import password strength checker
    strength, feedback = check_password_strength(new_pwd)
    print(f"New Password Strength: {strength}")
    if feedback:
        print("Suggestions:")
        for tip in feedback:
            print(f"  - {tip}")

    if strength in ["Weak", "🔓 Weak"] or any("common" in f.lower() for f in feedback):
        # warn user if password is weak or common
        warn = input("Warning: New password may still be weak. Proceed anyway? (y/n): ").strip().lower()
        if warn != 'y':
            print("Update canceled due to weak password.")
            return

    confirm_1 = input("Are you sure you want to overwrite the existing password? (y/n): ").strip().lower()
    confirm_2 = input("Please confirm again. (y/n): ").strip().lower()

    if confirm_1 == 'y' and confirm_2 == 'y':
    # import functions for saving and updating encrypted passwords
        if update_password(label, new_pwd):
            print(f"Password for '{label}' has been updated.")
        else:
            # handle invalid input
            print("Failed to update entry.")
    else:
        print("Update canceled.")

# prompt user to delete password entry with multiple confirmations
def delete_password_flow(label):
    confirm_1 = input("Are you sure you want to delete this entry? (y/n): ").strip().lower()
    if confirm_1 != 'y':
        print("Deletion canceled.")
        return False

    confirm_2 = input("Type DELETE to confirm: ").strip()
    if confirm_2 != 'DELETE':
        print("Deletion canceled.")
        return False

    if delete_password(label):
        print(f"'{label}' has been deleted.")
        return True
    else:
        print("Failed to delete entry.")
        return False

# route view/edit/delete commands for selected password label
def handle_password_action(label):
    passwords = load_all_passwords()
    if label not in passwords:
        print("Selected label no longer exists.")
        return

    entry = passwords[label]

    while True:
        action = input(f"\nOptions for '{label}': (v)iew, (e)dit, (d)elete, (b)ack: ").strip().lower()

        if action == 'b':
            print("Returning to password list.")
            return

        elif action == 'v':
            display_password_details(label, entry)
            strength, feedback = check_password_strength(entry["password"])
            if strength in ["Weak", "🔓 Weak"] or any("common" in f.lower() for f in feedback):
                prompt = input("This password may be weak or common. Would you like to update it? (y/n): ").strip().lower()
                if prompt == 'y':
                    update_password_flow(label, entry)
                    return

        elif action == 'e':
            update_password_flow(label, entry)
            return

        elif action == 'd':
            deleted = delete_password_flow(label)
            if deleted:
                return
        else:
            print("Invalid option. Please enter 'v', 'e', 'd', or 'b'.")

# show saved passwords menu and prompt for handling of saved passwords from handle_password_action()
def view_saved_passwords():
    while True:
        selected_label = select_saved_password()
        if selected_label is None:
            break
        handle_password_action(selected_label)

# main app menu and selection options
def main_menu():
    while True:
        print("\n=== Password Tool Menu ===")
        print("1. Generate a password")
        print("2. Test a password")
        print("3. View saved passwords")
        print("4. Exit")

        choice = input("Choose an option (1-4): ").strip()
        if choice == '1':
            generate_password_flow() # generate password
        elif choice == '2':
            test_password_flow() # allow user to check personal password strength
        elif choice == '3':
            view_saved_passwords() # view saved passwords
        elif choice == '4':
            print("Exiting the program. Goodbye.")
            break   # exit program
        else:
            print("Invalid choice. Please enter a number from 1 to 4.")

# script entry after entering master password
if __name__ == "__main__":
    from vault import verify_master_password
    if verify_master_password():
        main_menu()
