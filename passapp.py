"""Personal Password Management Tool.

Main entry point for the password vault CLI application.
"""

from cli import generate_password_flow, test_password_flow, view_passwords_flow
from vault import change_master_password


def main_menu() -> None:
    """Main application menu."""
    while True:
        print("\n=== Password Tool Menu ===")
        print("1. Generate a password")
        print("2. Test a password")
        print("3. View saved passwords")
        print("4. Change master password")
        print("5. Exit")

        choice = input("Choose an option (1-5): ").strip()

        if choice == '1':
            generate_password_flow()
        elif choice == '2':
            test_password_flow()
        elif choice == '3':
            view_passwords_flow()
        elif choice == '4':
            change_master_password()
        elif choice == '5':
            print("Exiting the program. Goodbye.")
            break
        else:
            print("Invalid choice. Please enter a number from 1 to 5.")


if __name__ == "__main__":
    from vault import verify_master_password

    if verify_master_password():
        main_menu()
