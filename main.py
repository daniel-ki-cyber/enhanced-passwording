from vault import verify_master_password
from passapp import main_menu

if __name__ == "__main__":
    if verify_master_password():
        main_menu()
