# python_backend/inbox_window.py
import os
import json
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QTextEdit,
    QMessageBox,
    QPushButton,
    QFileDialog,
)
from PyQt5.QtCore import Qt

# Import decrypt function
from email_crypto import decrypt_and_verify_email


class InboxWindow(QWidget):
    def __init__(self, kem_private_key_b64=None):
        super().__init__()
        self.kem_private_key_b64 = kem_private_key_b64
        self.setWindowTitle("Inbox - Quantum Email")
        self.setGeometry(200, 200, 700, 550)

        self.kem_private_key_path = None
        self.selected_email = None

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.label = QLabel("📥 Inbox - Encrypted Emails")
        self.label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.label)

        self.list_widget = QListWidget()
        self.list_widget.itemClicked.connect(self.handle_email_selection)
        layout.addWidget(self.list_widget)

        self.email_content = QTextEdit()
        self.email_content.setReadOnly(True)
        layout.addWidget(self.email_content)

        # Decrypt Button
        self.decrypt_button = QPushButton("🔓 Decrypt Selected Email")
        self.decrypt_button.setEnabled(False)
        self.decrypt_button.clicked.connect(self.decrypt_selected_email)
        layout.addWidget(self.decrypt_button)

        # Load emails
        self.load_emails()

    def load_emails(self):
        inbox_path = os.path.join("emails", "inbox.json")
        if not os.path.exists(inbox_path):
            QMessageBox.warning(self, "Inbox", "No inbox.json found.")
            return

        try:
            with open(inbox_path, "r") as f:
                self.emails = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load inbox: {e}")
            return

        self.list_widget.clear()

        for idx, email in enumerate(self.emails):
            sender = email.get("from", "Unknown Sender")
            subject = email.get("subject", "No Subject")
            item = QListWidgetItem(f"From: {sender} | Subject: {subject}")
            item.setData(Qt.UserRole, idx)
            self.list_widget.addItem(item)

    def handle_email_selection(self, item):
        """Enable decrypt button and show metadata."""
        idx = item.data(Qt.UserRole)
        self.selected_email = self.emails[idx]

        # Show metadata without decryption
        content = (
            f"From: {self.selected_email.get('from', '')}\n"
            f"To: {self.selected_email.get('to', '')}\n"
            f"Subject: {self.selected_email.get('subject', '')}\n\n"
            f"(Encrypted content hidden until decryption)"
        )
        self.email_content.setPlainText(content)
        self.decrypt_button.setEnabled(True)

    def decrypt_selected_email(self):
        """Decrypt using selected private key."""
        if not self.selected_email:
            QMessageBox.warning(self, "Decrypt", "No email selected.")
            return

        # Prompt user to pick .pem file
        if not self.kem_private_key_path:
            pem_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select your Private Key (.pem)",
                "",
                "PEM Files (*.pem)"
            )
            if not pem_path:
                QMessageBox.warning(self, "Private Key", "No .pem file selected.")
                return
            self.kem_private_key_path = pem_path

        # Load private key bytes
        try:
            with open(self.kem_private_key_path, "rb") as f:
                private_key_bytes = f.read()
        except Exception as e:
            QMessageBox.critical(self, "Private Key Error", f"Could not load .pem file:\n{e}")
            return

        # Call decrypt_and_verify_email
        try:
            decrypted = decrypt_and_verify_email(
                encrypted_data=self.selected_email,
                kem_private_key_b64=self.kem_private_key_b64
            )
        except Exception as e:
            QMessageBox.critical(self, "Decryption Error", f"Decryption failed:\n{e}")
            return

        if decrypted.get("error"):
            content = f"❌ Decryption failed:\n{decrypted.get('error_message', 'Unknown error')}"
        else:
            email_data = decrypted.get("email", {})
            content = (
                f"From: {email_data.get('from', '')}\n"
                f"To: {email_data.get('to', '')}\n"
                f"Subject: {email_data.get('subject', '')}\n\n"
                f"{email_data.get('body', '')}\n\n"
                f"Signature valid: {decrypted.get('signature_valid')}"
            )

        self.email_content.setPlainText(content)
