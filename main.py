from database.database import initialize_database
from interface.app import SecureVaultApp


def main():
    initialize_database()

    app = SecureVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
