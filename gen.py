from PyQt6.QtWidgets import (QMainWindow, QWidget, QPushButton, QLabel, 
                           QLineEdit, QVBoxLayout, QHBoxLayout, QFrame)
from PyQt6.QtCore import Qt
import string
from secrets import choice

UPPERCASE = list(string.ascii_uppercase)
LOWERCASE = list(string.ascii_lowercase)
NUMBER = list(string.digits)
SYMBOLS = ['@', '#', '$', '%', '&', '_', '(', ')', '+', '-', '*', '/', '=', '?', '!', '[', ']', '{', '}', '<', '>']

class PassGen(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PassMan - Generator")
        self.setFixedSize(450, 260)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Length entry
        length_frame = QFrame()
        length_frame.setFrameStyle(QFrame.Shape.Box)
        length_layout = QVBoxLayout(length_frame)
        length_layout.addWidget(QLabel("Enter the number of characters:"))
        
        self.length_entry = QLineEdit()
        self.length_entry.setText("8")
        length_layout.addWidget(self.length_entry)
        layout.addWidget(length_frame)

        # Check label
        self.check = QLabel()
        layout.addWidget(self.check)

        # Password entry
        self.password_entry = QLineEdit()
        self.password_entry.setMinimumWidth(300)
        layout.addWidget(self.password_entry)

        # Buttons
        button_layout = QHBoxLayout()
        generate_btn = QPushButton("Generate Password")
        generate_btn.clicked.connect(self.generate_password)
        copy_btn = QPushButton("Copy Password")
        copy_btn.clicked.connect(self.copy)
        
        button_layout.addWidget(generate_btn)
        button_layout.addWidget(copy_btn)
        layout.addLayout(button_layout)

    def generate_password(self):
        self.password_entry.clear()
        self.check.setText("")
        try:
            password_length = int(self.length_entry.text())
            if password_length < 8 or password_length > 32:
                self.check.setText("Password must be between 8 and 32 characters long")
                self.check.setStyleSheet("color: red")
            else:
                data = UPPERCASE+LOWERCASE+NUMBER+SYMBOLS
                password = ''.join(choice(data) for _ in range(password_length))
                self.password_entry.setText(password)

        except ValueError:
            self.check.setText("Please enter number of characters")
            self.check.setStyleSheet("color: red")

    def copy(self):
        text = self.password_entry.text()
        if text:
            clipboard = self.clipboard()
            clipboard.setText(text)

if __name__ == '__main__':
    app = QApplication([])
    window = PassGen()
    window.show()
    app.exec()
