# imports requires modules and classes so they can be used in the program
import hashlib
from tkinter.constants import BOTH, CENTER, END, LEFT, RIGHT, VERTICAL, Y
from gen import PassGen
from db import init_db
from tkinter import Canvas, Frame, ttk
import tkinter as tk
from functools import partial
from vault import VaultMethods
from ttkthemes import ThemedTk
import re

# main window class for the application, used so it can be called when ran
class PassMan:
    # initializes the database and creates themed Tkinter window
    def __init__(self):
        self.db, self.cursor = init_db()
        self.window = ThemedTk(theme="breeze")
        style = ttk.Style()
        style.configure("Red.TLabel", foreground="red")
        self.window.update()

    # creates new window for user to create a new master password
    def new_user(self):
        # sets window size, locks resizing, and sets window title to make it look better
        self.window.geometry("440x250")
        self.window.title("PassMan - New User")
        self.window.resizable(False, False)

        # creates a label indicating where the user should enter their new master password
        label1 = ttk.Label(self.window, text="Create a new master password:")
        label1.config(anchor=CENTER)
        label1.pack(pady=10)

        # creates entry box for master password and sets focus to it so user can type right away
        mspwd_entry = ttk.Entry(self.window, width=20, show="*")
        mspwd_entry.pack()
        mspwd_entry.focus()

        # creates a label indicating where the user should confirm their new master password
        label2 = ttk.Label(self.window, text="Confirm your password")
        label2.config(anchor=CENTER)
        label2.pack(pady=10)

        # creates entry box for master password confirmation so user can confirm their password
        mspwd_confirm = ttk.Entry(self.window, width=20, show="*")
        mspwd_confirm.pack()

        # creates label to indicate if the passwords match or not so the user knows if there is an error
        self.check = ttk.Label(self.window)
        self.check.config(text="Password needs at least one letter, number, and special character")
        self.check.pack(pady=5)

        # creates checkbox to allow user to see their password to make sure they typed it correctly
        showpwd_var = tk.BooleanVar()
        showpwd_cb = ttk.Checkbutton(self.window, text="Show Password", variable=showpwd_var,
                                    command=lambda: self.toggle_password_create(mspwd_entry, mspwd_confirm, showpwd_var))
        showpwd_cb.pack(pady=5)

        # creates button to create the master password and executes save_master_password function when clicked
        # also binds the enter key to the button to increase familiarity for the user
        createpwd = ttk.Button(self.window, text="Create Password",
                          command=partial(self.save_master_password, mspwd_entry, mspwd_confirm))
        createpwd.pack(pady=5)
        self.window.bind("<Return>", lambda event=None: createpwd.invoke)

    # creates new window for user to login using their existing password so they can access their data       
    def login_user(self):
        for widget in self.window.winfo_children():
            widget.destroy()

        # sets window size, locks the resize, and sets window title to make it look better
        self.window.geometry("440x180")
        self.window.title("PassMan - Login")
        self.window.resizable(False, False)

        # creates a label indicating where the user should enter their master password
        label1 = ttk.Label(self.window, text="Please enter your master password:")
        label1.config(anchor=CENTER)
        label1.pack(pady=10)

        # creates entry box for master password and sets focus to it so user can type right away
        self.pass_entry = ttk.Entry(self.window, width=20, show="*")
        self.pass_entry.pack(pady=4)
        self.pass_entry.focus()

        # creates label to indicate if the passwords match or not so the user knows if there is an error
        self.check = ttk.Label(self.window)
        self.check.pack()

        # creates checkbox to allow user to show password if they want to
        showpwd_var = tk.BooleanVar()
        showpwd_cb = ttk.Checkbutton(self.window, text="Show Password", variable=showpwd_var,
                                    command=lambda: self.toggle_password_login(self.pass_entry, showpwd_var))
        showpwd_cb.pack(pady=5)

        # creates button to login and executes check_master_password function when clicked
        # also binds the enter key to the button to increase familiarity for the user
        login_btn = ttk.Button(self.window, text="Log in", command=partial(
            self.check_master_password, self.pass_entry))
        login_btn.pack(pady=5)
        self.window.bind('<Return>', lambda event=None: login_btn.invoke())

    # allows user to toggle password visibility for the new user window
    def toggle_password_create(self, entry1, entry2, var):
        if var.get():
            entry1.config(show="")
            entry2.config(show="")

        else:
            entry1.config(show="*")
            entry2.config(show="*")

    # allows user to toggle password visibility for the login window
    def toggle_password_login(self, entry, var):
        if var.get():
            entry.config(show="")
        else:
            entry.config(show="*")

    # save master password function
    def save_master_password(self, mspwd_entry, mspwd_confirm):
        password1 = mspwd_entry.get()
        password2 = mspwd_confirm.get()
        # checks if the passwords match
        if password1 == password2:
            # sets minimum password length to 8 characters
            min_password_length = 8
            # checks if the password meets the minimum length requirement
            if len(password1) < min_password_length:
                self.check.config(style="Red.TLabel", text=f"Password must be at least {min_password_length} characters long")
            # checks if the password meets the password strength requirements to be considered secure
            elif not self.check_password_strength(password1):
                # checks if the password contains letters and numbers
                if re.search(r'[a-zA-Z]', password1) and re.search(r'\d', password1):
                    self.check.config(style="Red.TLabel", text="Password needs at least one special character")
                # checks if the password contains letters and special characters
                elif re.search(r'[a-zA-Z]', password1) and re.search(r'[!@#$%^&*()_\-+={[}\]|:;"\'<,>.?/]', password1):
                    self.check.config(style="Red.TLabel", text="Password needs at least one number")
                # checks if the password contains numbers and special characters
                elif re.search(r'\d', password1) and re.search(r'[!@#$%^&*()_\-+={[}\]|:;"\'<,>.?/]', password1):
                    self.check.config(style="Red.TLabel", text="Password needs at least one letter")
                # checks if the password contains only letters
                elif re.search(r'[a-zA-Z]', password1):
                    self.check.config(style="Red.TLabel", text="Password needs at least one number and one special character")
                # checks if the password contains only numbers
                elif re.search(r'\d', password1):
                    self.check.config(style="Red.TLabel", text="Password needs at least one letter and one special character")
                # checks if the password contains only special characters
                elif re.search(r'[!@#$%^&*()_\-+={[}\]|:;"\'<,>.?/]', password1):
                    self.check.config(style="Red.TLabel", text="Password needs at least one letter and one number")
            # if the passwords meet the requirements, the password is hashed and stored in the database
            else:
                hashed_password = self.encrypt_password(password1)
                insert_command = """INSERT INTO master(password)
                VALUES(?) """
                self.cursor.execute(insert_command, [hashed_password])
                self.db.commit()
                self.login_user()

        # if the passwords do not match, the user is notified so they can try again
        else:
            self.check.config(text="Passwords do not match")
            self.check.configure(style="Red.TLabel")

    # checks password strength
    def check_password_strength(self, password):
    # checks if password contains at least one letter, one number, and one special character
        if re.search(r'[a-zA-Z]', password) and re.search(r'\d', password) and re.search(r'[!@#$%^&*()_\-+={[}\]|:;"\'<,>.?/]', password):
            return True
        else:
            return False

    # checks if the master password is correct
    def check_master_password(self, eb):
        password = eb.get()
        if not password:
            # checks if the user entered a password and if not, changes text on label to indicate error
            self.check.config(style="Red.TLabel", text="Please enter a password")
        else:
            # hashes the password entered by the user and checks if it matches the hashed password in the database to maintain security
            hashed = self.encrypt_password(eb.get())
            self.cursor.execute(
                "SELECT * FROM master WHERE id = 1 AND password = ?", [hashed])
            if self.cursor.fetchall():
                self.vault()
            # otherwise it gives an error so the user knows they entered the wrong password
            else:
                self.pass_entry.delete(0, END)
                self.check.config(style="Red.TLabel", text="Incorrect password")

    # creates new window and destroys child widgets to clean up from previous window
    def vault(self):
        for widget in self.window.winfo_children():
            widget.destroy()

        # sets aliases for imported vault method function 
        vault_methods = VaultMethods()

        # sets window size, locks the resize, and sets window title to make it look better
        self.window.geometry("880x350")
        self.window.title("Passify - Vault")
        self.window.resizable(True, False)

        # creates frame and canvas to allow for scrolling of vault entries
        frame = Frame(self.window)
        frame.pack(fill=BOTH, expand=1)
        canvas = Canvas(frame)
        canvas.pack(side=LEFT, fill=BOTH, expand=1)

        # creates scrollbar and packs it to the right side of the window so it is usable
        scrollbar = ttk.Scrollbar(frame, orient=VERTICAL, command=canvas.yview)
        scrollbar.pack(side=RIGHT, fill=Y)

        # configures canvas and binds it to the scrollbar
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        
        # creates frame to hold vault entries
        frame_two = Frame(canvas)
        canvas.create_window((0, 0), window=frame_two, anchor="nw")

        # adds warning label to indicate that there may be dialog boxes behind the window
        warn_label = ttk.Label(frame_two)
        warn_label.config(style="Red.TLabel", text="Please check behind this window for dialogue boxes when adding an entry.")
        warn_label.grid(row=0, column=1, columnspan=6, pady=2)

        # creates button to open imported PassGen class to generate passwords
        gen_pwn_button = ttk.Button(frame_two, text="Generate Password", command=PassGen)
        gen_pwn_button.grid(row=1, column=2, pady=10)

        # creates button that calls add_password function from imported VaultMethods class
        add_pwd_button = ttk.Button(
            frame_two, text="Add Entry", command=partial(vault_methods.add_password, self.vault))
        add_pwd_button.grid(row=1, column=3, pady=10)

        # creates labels for each column and aligns them
        label = ttk.Label(frame_two, text="Platform")
        label.grid(row=2, column=0, padx=40, pady=10)
        label = ttk.Label(frame_two, text="Email/Username")
        label.grid(row=2, column=1, padx=40, pady=10)
        label = ttk.Label(frame_two, text="Password")
        label.grid(row=2, column=2, padx=40, pady=10)

        # executes select command to get all entries from the vault table
        self.cursor.execute("SELECT * FROM vault")

        # checks if there are any entries in the vault table
        if self.cursor.fetchall():
            i = 0
            # loops through each entry in the vault table and displays them
            while True:
                # executes select command to get all entries from the vault table
                self.cursor.execute("SELECT * FROM vault")
                array = self.cursor.fetchall()

                # creates labels for each column and places them into a grid to display them correctly
                # uses variable named array (list of tuples) to store data fetched from the database
                platform = ttk.Label(frame_two, text=(array[i][1]))
                platform.grid(column=0, row=i + 3)

                account = ttk.Label(frame_two, text=(array[i][2]))
                account.grid(column=1, row=i + 3)

                password = ttk.Label(frame_two, text=(array[i][3]))
                password.grid(column=2, row=i + 3)

                # creates buttons for functions, packs them into a grid, adds commands
                copy_button = ttk.Button(frame_two, text="Copy",
                                  command=partial(self.copy_text, array[i][3]))
                copy_button.grid(column=3, row=i + 3, pady=10, padx=10)
                update_button = ttk.Button(frame_two, text="Update",
                                    command=partial(vault_methods.update_password, array[i][0], self.vault))
                update_button.grid(column=4, row=i + 3, pady=10, padx=10)
                delete_button = ttk.Button(frame_two, text="Delete",
                                    command=partial(vault_methods.remove_password, array[i][0], self.vault))
                delete_button.grid(column=5, row=i + 3, pady=10, padx=10)

                i += 1

                # checks if the number of entries in the vault table is less than the current index, if so, breaks the loop
                # this is done to prevent an index error
                self.cursor.execute("SELECT * FROM vault")
                if len(self.cursor.fetchall()) <= i:
                    break

    # takes input and encrypts it using sha256 to enforce security and prevent data breaches
    def encrypt_password(self, password):
        password = password.encode("utf-8")
        encoded = hashlib.sha256(password).hexdigest()
        return encoded
    
    # clears clipboard, then copies text so the user can paste it
    def copy_text(self, text):
        self.window.clipboard_clear()
        self.window.clipboard_append(text)

# runs program, initializes database, and checks if there are any entries in the master table
# if they do, open login window, otherwise open new user window so they can create a password
if __name__ == '__main__':
    db, cursor = init_db()
    cursor.execute("SELECT * FROM master")
    passman = PassMan()
    if cursor.fetchall():
        passman.login_user()
    else:
        passman.new_user()
    passman.window.mainloop()
