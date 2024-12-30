# imports required modules and classes so they can be used in the program
from tkinter import ttk
import tkinter as tk
from ttkthemes import ThemedTk
import string
from secrets import choice
from tkinter.constants import END


# creates lists for elements of password, so they can be used later
UPPERCASE = list(string.ascii_uppercase)
LOWERCASE = list(string.ascii_lowercase)
NUMBER = list(string.digits)
SYMBOLS = [
    '@', '#', '$', '%', '&', '_', '(', ')', '+', '-', '*', '/', '=', '?', '!', '[', ']', '{', '}', '<', '>'
    ]

# defines counter and sets it to 1
global counter
counter = 1

class PassGen:
    # creates themed Tkinter window for password generator
    def __init__ (self):
        # defines counter, if value smaller than 2 then window opens else
        global counter
        if counter < 2:
            counter = 2
            # sets window theme, title, size and locks resize
            self.window = ThemedTk(theme='breeze')
            style = ttk.Style()
            style.configure("Red.TLabel", foreground="red")
            self.window.title("PassMan - Generator")
            self.window.geometry("450x260")
            self.window.resizable(False, False)

            # creates label frame for password length so user knows where to enter the length
            self.label_frame = ttk.LabelFrame(self.window, text="Enter the number of characters:")
            self.label_frame.pack(pady=20)

            # creates entry box for password length and sets default value to 8 so user doesn't have to type it
            self.length_entry = ttk.Entry(self.label_frame, width=20)
            self.length_entry.insert(0, "8")
            self.length_entry.pack(padx=10, pady=10)

            # declare length not found so user knows if there is an error
            self.check = ttk.Label(self.window)
            self.check.pack(pady=2)

            # creates entry box for password result so user sees output
            self.password_entry = ttk.Entry(self.window, width=50)
            self.password_entry.pack(pady=20)

            # creates frame for buttons so they can be placed stacked
            self.button_frame = ttk.Frame(self.window)
            self.button_frame.pack(pady=10)

            # generate password button, executes generate password function so user can generate a password
            self.generate = ttk.Button(self.button_frame, text="Generate Password", command=self.generate_password)
            self.generate.grid(row=0, column=0, padx=10)

            # copy password button, executes copy function so user can copy password toclipboard
            copy = ttk.Button(self.button_frame, text="Copy Password", command=self.copy)
            copy.grid(row=0, column=1, padx=10)

            # uses close_window function to destroy window on exit
            self.window.protocol("WM_DELETE_WINDOW", self.close_window)

    # generates password function
    def generate_password(self):
        # clears password entry box and attempts to generate password according to the length entered
        self.password_entry.delete(0, END)
        self.check.config(text="")
        try:
            # if password length is not between 8 and 32, error message is displayed so user knows what went wrong
            password_length = int(self.length_entry.get())
            if password_length < 8 or password_length > 32:
                self.check.config(style="Red.TLabel", text="Password must be between 8 and 32 characters long")
            # otherwise password is generated according to length using lists of characters if input is correct
            else:
                data = UPPERCASE+LOWERCASE+NUMBER+SYMBOLS
                password = ''.join(choice(data) for _ in range(password_length))
                self.password_entry.insert(0,password)

        # if user enters a string instead of a integer, error message is displayed so user knows what happened
        except ValueError:
            self.check.config(style="Red.TLabel", text="Please enter number of characters")

    # clears clipboard, then copies password so the user can paste it
    def copy(self):
        self.window.clipboard_clear()
        self.window.clipboard_append(self.password_entry.get())

    # resets counter to 1 and destroys window so user can open it again
    def close_window(self):
        global counter
        counter = 1
        self.window.destroy()

# runs program
if __name__ == '__main__':
    PassGen().window.mainloop()
