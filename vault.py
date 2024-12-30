# import required modules so they can be used in the program
from tkinter import simpledialog
from db import init_db

# creates class for vault methods
class VaultMethods:

    # initialises database and cursor
    def __init__(self):
        self.db, self.cursor = init_db()

    # displays a dialog box that allows user to enter information
    def popup_entry(self, heading):
        answer = simpledialog.askstring("Enter details", heading)
        return answer

    # add password function that allows user to enter and update information
    def add_password(self, vault_screen):
        # creates popup entry boxes for platform, username and password so user can enter details
        platform = self.popup_entry("Platform")
        userid = self.popup_entry("Username/Email")
        password = self.popup_entry("Password")

        # inserts the new information into the vault table and commits to save changes
        insert_cmd = """INSERT INTO vault(platform, userid, password) VALUES (?, ?, ?)"""
        self.cursor.execute(insert_cmd, (platform, userid, password))
        self.db.commit()
        vault_screen()

    # allows user to update their stored password in the database
    def update_password(self, id, vault_screen):
        # creates popup entry box for user to enter new password
        password = self.popup_entry("Enter New Password")
        # updates the password in the vault table and commits to save changes
        self.cursor.execute(
            "UPDATE vault SET password = ? WHERE id = ?", (password, id))
        self.db.commit()
        vault_screen()

    # allows the user to remove a password from the database
    def remove_password(self, id, vault_screen):
        # deletes the password from the vault table and commits to save changes
        self.cursor.execute("DELETE FROM vault WHERE id = ?", (id,))
        self.db.commit()
        vault_screen()
