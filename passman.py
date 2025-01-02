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

class PassMan:
    def __init__(self):
        self.db, self.cursor = init_db()
        self.window = ThemedTk(theme="breeze")
        style = ttk.Style()
        style.configure("Red.TLabel", foreground="red")
        self.window.update()

    def new_user(self):
        self.window.geometry("440x250")
        self.window.title("PassMan - New User")
        self.window.resizable(False, False)

        label1 = ttk.Label(self.window, text="Create a new master password:")
        label1.config(anchor=CENTER)
        label1.pack(pady=10)

        mspwd_entry = ttk.Entry(self.window, width=20, show="*")
        mspwd_entry.pack()
        mspwd_entry.focus()

        label2 = ttk.Label(self.window, text="Confirm your password")
        label2.config(anchor=CENTER)
        label2.pack(pady=10)

        mspwd_confirm = ttk.Entry(self.window, width=20, show="*")
        mspwd_confirm.pack()

        self.check = ttk.Label(self.window)
        self.check.config(text="Password needs at least one letter, number, and special character")
        self.check.pack(pady=5)

        showpwd_var = tk.BooleanVar()
        showpwd_cb = ttk.Checkbutton(self.window, text="Show Password", variable=showpwd_var,
                                    command=lambda: self.toggle_password_create(mspwd_entry, mspwd_confirm, showpwd_var))
        showpwd_cb.pack(pady=5)

        createpwd = ttk.Button(self.window, text="Create Password",
                          command=partial(self.save_master_password, mspwd_entry, mspwd_confirm))
        createpwd.pack(pady=5)
        self.window.bind("<Return>", lambda event=None: createpwd.invoke)

    def login_user(self):
        for widget in self.window.winfo_children():
            widget.destroy()

        self.window.geometry("440x180")
        self.window.title("PassMan - Login")
        self.window.resizable(False, False)

        label1 = ttk.Label(self.window, text="Please enter your master password:")
        label1.config(anchor=CENTER)
        label1.pack(pady=10)

        self.pass_entry = ttk.Entry(self.window, width=20, show="*")
        self.pass_entry.pack(pady=4)
        self.pass_entry.focus()

        self.check = ttk.Label(self.window)
        self.check.pack()

        showpwd_var = tk.BooleanVar()
        showpwd_cb = ttk.Checkbutton(self.window, text="Show Password", variable=showpwd_var,
                                    command=lambda: self.toggle_password_login(self.pass_entry, showpwd_var))
        showpwd_cb.pack(pady=5)

        login_btn = ttk.Button(self.window, text="Log in", command=partial(
            self.check_master_password, self.pass_entry))
        login_btn.pack(pady=5)
        self.window.bind('<Return>', lambda event=None: login_btn.invoke())

    def toggle_password_create(self, entry1, entry2, var):
        if var.get():
            entry1.config(show="")
            entry2.config(show="")

        else:
            entry1.config(show="*")
            entry2.config(show="*")

    def toggle_password_login(self, entry, var):
        if var.get():
            entry.config(show="")
        else:
            entry.config(show="*")

    def save_master_password(self, mspwd_entry, mspwd_confirm):
        password1 = mspwd_entry.get()
        password2 = mspwd_confirm.get()
        
        if password1 != password2:
            self.check.config(text="Passwords do not match", style="Red.TLabel")
            return

        if len(password1) < 8:
            self.check.config(style="Red.TLabel", text="Password must be at least 8 characters long")
            return

        if not self.check_password_strength(password1):
            has_letter = bool(re.search(r'[a-zA-Z]', password1))
            has_number = bool(re.search(r'\d', password1))
            has_special = bool(re.search(r'[!@#$%^&*()_\-+={[}\]|:;"\'<,>.?/]', password1))
            
            error_msg = "Password needs at least one "
            missing = []
            
            if not has_letter: missing.append("letter")
            if not has_number: missing.append("number")
            if not has_special: missing.append("special character")
            
            self.check.config(style="Red.TLabel", text=error_msg + " and ".join(missing))
            return

        hashed_password = self.encrypt_password(password1)
        self.cursor.execute("INSERT INTO master(password) VALUES(?)", [hashed_password])
        self.db.commit()
        self.login_user()

    def check_password_strength(self, password):
        if re.search(r'[a-zA-Z]', password) and re.search(r'\d', password) and re.search(r'[!@#$%^&*()_\-+={[}\]|:;"\'<,>.?/]', password):
            return True
        else:
            return False

    def check_master_password(self, eb):
        password = eb.get()
        if not password:
            self.check.config(style="Red.TLabel", text="Please enter a password")
        else:
            hashed = self.encrypt_password(eb.get())
            self.cursor.execute(
                "SELECT * FROM master WHERE id = 1 AND password = ?", [hashed])
            if self.cursor.fetchall():
                self.vault()
            else:
                self.pass_entry.delete(0, END)
                self.check.config(style="Red.TLabel", text="Incorrect password")

    def vault(self):
        for widget in self.window.winfo_children():
            widget.destroy()

        vault_methods = VaultMethods()

        self.window.geometry("880x350")
        self.window.title("Passify - Vault")
        self.window.resizable(True, False)

        frame = Frame(self.window)
        frame.pack(fill=BOTH, expand=1)
        canvas = Canvas(frame)
        canvas.pack(side=LEFT, fill=BOTH, expand=1)

        scrollbar = ttk.Scrollbar(frame, orient=VERTICAL, command=canvas.yview)
        scrollbar.pack(side=RIGHT, fill=Y)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(
            scrollregion=canvas.bbox("all")))
        
        frame_two = Frame(canvas)
        canvas.create_window((0, 0), window=frame_two, anchor="nw")

        warn_label = ttk.Label(frame_two)
        warn_label.config(style="Red.TLabel", text="Please check behind this window for dialogue boxes when adding an entry.")
        warn_label.grid(row=0, column=1, columnspan=6, pady=2)

        gen_pwn_button = ttk.Button(frame_two, text="Generate Password", command=PassGen)
        gen_pwn_button.grid(row=1, column=2, pady=10)

        add_pwd_button = ttk.Button(
            frame_two, text="Add Entry", command=partial(vault_methods.add_password, self.vault))
        add_pwd_button.grid(row=1, column=3, pady=10)

        label = ttk.Label(frame_two, text="Platform")
        label.grid(row=2, column=0, padx=40, pady=10)
        label = ttk.Label(frame_two, text="Email/Username")
        label.grid(row=2, column=1, padx=40, pady=10)
        label = ttk.Label(frame_two, text="Password")
        label.grid(row=2, column=2, padx=40, pady=10)

        self.cursor.execute("SELECT * FROM vault")

        if self.cursor.fetchall():
            i = 0
            while True:
                self.cursor.execute("SELECT * FROM vault")
                array = self.cursor.fetchall()

                platform = ttk.Label(frame_two, text=(array[i][1]))
                platform.grid(column=0, row=i + 3)

                account = ttk.Label(frame_two, text=(array[i][2]))
                account.grid(column=1, row=i + 3)

                password = ttk.Label(frame_two, text=(array[i][3]))
                password.grid(column=2, row=i + 3)

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

                self.cursor.execute("SELECT * FROM vault")
                if len(self.cursor.fetchall()) <= i:
                    break

    def encrypt_password(self, password):
        password = password.encode("utf-8")
        encoded = hashlib.sha256(password).hexdigest()
        return encoded
    
    def copy_text(self, text):
        self.window.clipboard_clear()
        self.window.clipboard_append(text)

if __name__ == '__main__':
    db, cursor = init_db()
    cursor.execute("SELECT * FROM master")
    passman = PassMan()
    if cursor.fetchall():
        passman.login_user()
    else:
        passman.new_user()
    passman.window.mainloop()
