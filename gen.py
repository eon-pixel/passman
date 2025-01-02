from tkinter import ttk
import tkinter as tk
from ttkthemes import ThemedTk
import string
from secrets import choice
from tkinter.constants import END

UPPERCASE = list(string.ascii_uppercase)
LOWERCASE = list(string.ascii_lowercase)
NUMBER = list(string.digits)
SYMBOLS = [
    '@', '#', '$', '%', '&', '_', '(', ')', '+', '-', '*', '/', '=', '?', '!', '[', ']', '{', '}', '<', '>'
    ]

global counter
counter = 1

class PassGen:
    def __init__ (self):
        global counter
        if counter < 2:
            counter = 2
            self.window = ThemedTk(theme='breeze')
            style = ttk.Style()
            style.configure("Red.TLabel", foreground="red")
            self.window.title("PassMan - Generator")
            self.window.geometry("450x260")
            self.window.resizable(False, False)

            self.label_frame = ttk.LabelFrame(self.window, text="Enter the number of characters:")
            self.label_frame.pack(pady=20)

            self.length_entry = ttk.Entry(self.label_frame, width=20)
            self.length_entry.insert(0, "8")
            self.length_entry.pack(padx=10, pady=10)

            self.check = ttk.Label(self.window)
            self.check.pack(pady=2)

            self.password_entry = ttk.Entry(self.window, width=50)
            self.password_entry.pack(pady=20)

            self.button_frame = ttk.Frame(self.window)
            self.button_frame.pack(pady=10)

            self.generate = ttk.Button(self.button_frame, text="Generate Password", command=self.generate_password)
            self.generate.grid(row=0, column=0, padx=10)

            copy = ttk.Button(self.button_frame, text="Copy Password", command=self.copy)
            copy.grid(row=0, column=1, padx=10)

            self.window.protocol("WM_DELETE_WINDOW", self.close_window)

    def generate_password(self):
        self.password_entry.delete(0, END)
        self.check.config(text="")
        try:
            password_length = int(self.length_entry.get())
            if password_length < 8 or password_length > 32:
                self.check.config(style="Red.TLabel", text="Password must be between 8 and 32 characters long")
            else:
                data = UPPERCASE+LOWERCASE+NUMBER+SYMBOLS
                password = ''.join(choice(data) for _ in range(password_length))
                self.password_entry.insert(0,password)

        except ValueError:
            self.check.config(style="Red.TLabel", text="Please enter number of characters")

    def copy(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.password_entry.get())

    def close_window(self):
        global counter
        counter = 1
        self.window.destroy()

if __name__ == '__main__':
    PassGen().window.mainloop()
