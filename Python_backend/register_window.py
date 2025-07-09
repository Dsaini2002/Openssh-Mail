#!/usr/bin/env python3
# register_window.py

import oqs
import os
import sys
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox
)
from .user_manager import UserManager

class RegisterWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Register User")
        self.setGeometry(300, 300, 300, 200)

        self.user_manager = UserManager()

        # Widgets
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.register_user)

        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)
        layout.addWidget(self.register_button)

        self.setLayout(layout)

    def generate_user_certificates(self, username):
        """Generate and save KEM and Signature keypairs for the user."""
        os.makedirs("certs/private_keys", exist_ok=True)
        os.makedirs("certs/public_keys", exist_ok=True)

        # KEM Keypair (Kyber512)
        kem = oqs.KeyEncapsulation("Kyber512")
        kem_public = kem.generate_keypair()
        kem_private = kem.export_secret_key()

        kem_pub_path = f"certs/public_keys/{username}_kem_public.bin"
        kem_priv_path = f"certs/private_keys/{username}_kem_private.bin"

        with open(kem_priv_path, "wb") as f:
            f.write(kem_private)
        with open(kem_pub_path, "wb") as f:
            f.write(kem_public)

        # Signature Keypair (Dilithium2)
        sig = oqs.Signature("Dilithium2")
        sig_public = sig.generate_keypair()
        sig_private = sig.export_secret_key()

        sig_pub_path = f"certs/public_keys/{username}_sig_public.bin"
        sig_priv_path = f"certs/private_keys/{username}_sig_private.bin"

        with open(sig_priv_path, "wb") as f:
            f.write(sig_private)
        with open(sig_pub_path, "wb") as f:
            f.write(sig_public)

        # Update the user_cert_map.json
        self.update_user_cert_map(username, kem_pub_path, sig_pub_path)

    def update_user_cert_map(self, username, kem_pub_path, sig_pub_path):
        """Update certs/user_cert_map.json mapping."""
        cert_map_path = "certs/user_cert_map.json"

        # Load existing map
        if os.path.exists(cert_map_path):
            with open(cert_map_path, "r") as f:
                cert_map = json.load(f)
        else:
            cert_map = {}

        # Update entry
        cert_map[username] = {
            "kem_public": kem_pub_path,
            "sig_public": sig_pub_path
        }

        # Save updated map
        with open(cert_map_path, "w") as f:
            json.dump(cert_map, f, indent=4)

    def register_user(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Error", "Please fill all fields")
            return

        success, message = self.user_manager.register_user(username, password)
        if success:
            # Generate keys after successful registration
            self.generate_user_certificates(username)

            QMessageBox.information(
                self,
                "Success",
                f"{message}\nQuantum certificates generated and mapped successfully."
            )
            self.username_input.clear()
            self.password_input.clear()
        else:
            QMessageBox.critical(self, "Error", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = RegisterWindow()
    window.show()
    sys.exit(app.exec_())
