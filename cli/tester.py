"""Password testing CLI flows.

Allows users to test password strength and optionally save.
"""

from cli.generator import preview_and_analyze, prompt_save_password


def test_password_flow() -> None:
    """Allow user to test a password's strength and optionally save it."""
    print("\n--- Test a Password ---")

    user_pwd = input("Enter the password you want to test: ").strip()
    if not user_pwd:
        print("No password entered.")
        return

    strength, feedback = preview_and_analyze(user_pwd)
    prompt_save_password(user_pwd, strength, feedback)
