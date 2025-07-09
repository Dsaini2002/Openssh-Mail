# gui/inbox_view.py

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QListWidget, QListWidgetItem, QTextEdit, QPushButton, QSplitter
)
from PyQt5.QtCore import Qt


class InboxView(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Inbox - Quantum-Safe Email")
        layout = QVBoxLayout()

        self.list_widget = QListWidget()
        self.message_view = QTextEdit()
        self.message_view.setReadOnly(True)

        self.refresh_button = QPushButton("🔄 Refresh Inbox")
        self.refresh_button.clicked.connect(self.load_mock_emails)  # Replace with real loader later

        layout.addWidget(self.refresh_button)
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.list_widget)
        splitter.addWidget(self.message_view)

        layout.addWidget(splitter)
        self.setLayout(layout)

        self.list_widget.itemClicked.connect(self.display_message)

        self.emails = []
        self.load_mock_emails()

    def load_mock_emails(self):
        # 🧪 Mock data — replace with actual inbox later
        self.emails = [
            {
                "from": "alice@example.com",
                "subject": "Encrypted Plan A",
                "content": "📦 EncryptedPayload123==",
                "time": "10:45 AM"
            },
            {
                "from": "bob@example.com",
                "subject": "Public Key Exchange",
                "content": "📦 CipherTextXYZ==",
                "time": "9:12 AM"
            }
        ]
        self.list_widget.clear()
        for email in self.emails:
            item_text = f"{email['time']} - {email['from']} - {email['subject']}"
            item = QListWidgetItem(item_text)
            self.list_widget.addItem(item)

    def display_message(self, item):
        index = self.list_widget.row(item)
        email = self.emails[index]
        self.message_view.setPlainText(email["content"])
