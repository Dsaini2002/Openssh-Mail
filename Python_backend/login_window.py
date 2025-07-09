import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox
)
from PyQt5.QtCore import pyqtSignal
from .user_manager import UserManager

class LoginWindow(QWidget):
    login_successful = pyqtSignal(str)
    goto_register = pyqtSignal()   # ✅ नया सिग्नल

    def __init__(self):
        super().__init__()
        self.setWindowTitle("User Login")
        self.setGeometry(100, 100, 300, 200)

        # Initialize UserManager
        self.user_manager = UserManager()

        # Widgets
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.login_user)

        # ✅ नया Register बटन
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.goto_register.emit)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.login_button)
        layout.addWidget(self.register_button)   # ✅ Register बटन भी ऐड कर दिया

        self.setLayout(layout)

    def login_user(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter username and password")
            return

        success, user_data, message = self.user_manager.authenticate_user(username, password)

        if success:
            QMessageBox.information(
                self, "Login Successful",
                f"Welcome, {username}!\nLast login: {user_data.get('last_login')}"
            )
            self.login_successful.emit(username)
        else:
            QMessageBox.critical(self, "Login Failed", message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec_())
