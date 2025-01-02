from PyQt6.QtWidgets import (QMainWindow, QWidget, QPushButton, QLabel, 
                           QLineEdit, QVBoxLayout, QHBoxLayout, QScrollArea,
                           QGridLayout, QCheckBox, QApplication)
from PyQt6.QtCore import Qt
import hashlib
from gen import PassGen
from db import init_db
from vault import VaultMethods
import re

class PassMan(QMainWindow):
    def __init__(self):
        super().__init__()
        self.db, self.cursor = init_db()
        
        self.setWindowTitle("PassMan")
        self.setMinimumWidth(440)
        
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # Check if master password exists
        self.cursor.execute("SELECT * FROM master")
        if self.cursor.fetchall():
            self.login_user()
        else:
            self.new_user()

    def new_user(self):
        self.clear_layout()
        self.setFixedSize(440, 250)
        
        self.layout.addWidget(QLabel("Create a new master password:"))
        
        self.mspwd_entry = QLineEdit()
        self.mspwd_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.mspwd_entry)
        
        self.layout.addWidget(QLabel("Confirm your password"))
        
        self.mspwd_confirm = QLineEdit()
        self.mspwd_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.mspwd_confirm)
        
        self.check = QLabel("Password needs at least one letter, number, and special character")
        self.layout.addWidget(self.check)
        
        show_pwd = QCheckBox("Show Password")
        show_pwd.stateChanged.connect(self.toggle_password_create)
        self.layout.addWidget(show_pwd)
        
        create_btn = QPushButton("Create Password")
        create_btn.clicked.connect(self.save_master_password)
        self.layout.addWidget(create_btn)

    def login_user(self):
        self.clear_layout()
        self.setFixedSize(440, 180)
        
        self.layout.addWidget(QLabel("Please enter your master password:"))
        
        self.pass_entry = QLineEdit()
        self.pass_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.pass_entry)
        
        self.check = QLabel()
        self.layout.addWidget(self.check)
        
        show_pwd = QCheckBox("Show Password")
        show_pwd.stateChanged.connect(self.toggle_password_login)
        self.layout.addWidget(show_pwd)
        
        login_btn = QPushButton("Log in")
        login_btn.clicked.connect(self.check_master_password)
        self.layout.addWidget(login_btn)

    def toggle_password_create(self, state):
        if state == Qt.CheckState.Checked:
            self.mspwd_entry.setEchoMode(QLineEdit.EchoMode.Normal)
            self.mspwd_confirm.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.mspwd_entry.setEchoMode(QLineEdit.EchoMode.Password)
            self.mspwd_confirm.setEchoMode(QLineEdit.EchoMode.Password)

    def toggle_password_login(self, state):
        if state == Qt.CheckState.Checked:
            self.pass_entry.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.pass_entry.setEchoMode(QLineEdit.EchoMode.Password)

    def save_master_password(self):
        password1 = self.mspwd_entry.text()
        password2 = self.mspwd_confirm.text()
        
        if password1 != password2:
            self.check.setText("Passwords do not match")
            return

        if len(password1) < 8:
            self.check.setText("Password must be at least 8 characters long")
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
            
            self.check.setText(error_msg + " and ".join(missing))
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

    def check_master_password(self):
        password = self.pass_entry.text()
        if not password:
            self.check.setText("Please enter a password")
        else:
            hashed = self.encrypt_password(password)
            self.cursor.execute(
                "SELECT * FROM master WHERE id = 1 AND password = ?", [hashed])
            if self.cursor.fetchall():
                self.vault()
            else:
                self.pass_entry.clear()
                self.check.setText("Incorrect password")

    def vault(self):
        self.clear_layout()
        vault_methods = VaultMethods()

        self.setFixedSize(880, 350)
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        self.layout.addWidget(scroll_area)
        
        scroll_content = QWidget()
        scroll_area.setWidget(scroll_content)
        
        scroll_layout = QVBoxLayout(scroll_content)
        
        warn_label = QLabel("Please check behind this window for dialogue boxes when adding an entry.")
        scroll_layout.addWidget(warn_label)
        
        gen_pwn_button = QPushButton("Generate Password")
        gen_pwn_button.clicked.connect(PassGen)
        scroll_layout.addWidget(gen_pwn_button)
        
        add_pwd_button = QPushButton("Add Entry")
        add_pwd_button.clicked.connect(lambda: vault_methods.add_password(self.vault))
        scroll_layout.addWidget(add_pwd_button)
        
        grid_layout = QGridLayout()
        scroll_layout.addLayout(grid_layout)
        
        grid_layout.addWidget(QLabel("Platform"), 0, 0)
        grid_layout.addWidget(QLabel("Email/Username"), 0, 1)
        grid_layout.addWidget(QLabel("Password"), 0, 2)
        
        self.cursor.execute("SELECT * FROM vault")
        array = self.cursor.fetchall()
        
        for i, entry in enumerate(array):
            platform = QLabel(entry[1])
            grid_layout.addWidget(platform, i + 1, 0)
            
            account = QLabel(entry[2])
            grid_layout.addWidget(account, i + 1, 1)
            
            password = QLabel(entry[3])
            grid_layout.addWidget(password, i + 1, 2)
            
            copy_button = QPushButton("Copy")
            copy_button.clicked.connect(lambda _, text=entry[3]: self.copy_text(text))
            grid_layout.addWidget(copy_button, i + 1, 3)
            
            update_button = QPushButton("Update")
            update_button.clicked.connect(lambda _, id=entry[0]: vault_methods.update_password(id, self.vault))
            grid_layout.addWidget(update_button, i + 1, 4)
            
            delete_button = QPushButton("Delete")
            delete_button.clicked.connect(lambda _, id=entry[0]: vault_methods.remove_password(id, self.vault))
            grid_layout.addWidget(delete_button, i + 1, 5)

    def encrypt_password(self, password):
        password = password.encode("utf-8")
        encoded = hashlib.sha256(password).hexdigest()
        return encoded
    
    def copy_text(self, text):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)

    def clear_layout(self):
        while self.layout.count():
            child = self.layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

if __name__ == '__main__':
    app = QApplication([])
    window = PassMan()
    window.show()
    app.exec()
