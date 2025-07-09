# main_window.py
from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QPushButton,
    QLabel,
    QMessageBox,
)
from PyQt5.QtCore import Qt

# Import your Compose and Inbox windows
from python_backend.compose_window import ComposeWindow
from python_backend.inbox_window import InboxWindow


def load_pem_key(filepath):
    """Load a PEM file and return its Base64 string (without headers)"""
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()
        b64_lines = [line.strip() for line in lines if not line.startswith("-----")]
        return "".join(b64_lines)
    except Exception as e:
        print(f"❌ Error loading PEM key: {e}")
        return None


class QuantumEmailMainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Quantum Email Client")
        with open("kem_private_key.b64", "r") as f:
            self.kem_private_key_b64 = f.read().strip()
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()
        self.setLayout(layout)

        label = QLabel("📧 Quantum Email Client")
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        # Compose Mail Button
        compose_button = QPushButton("📨 Compose Mail")
        compose_button.clicked.connect(self.open_compose_window)
        layout.addWidget(compose_button)

        # Inbox Button
        inbox_button = QPushButton("📥 Open Inbox")
        inbox_button.clicked.connect(self.open_inbox_window)
        layout.addWidget(inbox_button)

        # Exit Button
        exit_button = QPushButton("❌ Exit")
        exit_button.clicked.connect(self.close)
        layout.addWidget(exit_button)

        # Initialize windows
        self.compose_window = None
        self.inbox_window = None

    def open_compose_window(self):
        # Create Compose Window without passing crypto_config (it manages itself)
        self.compose_window = ComposeWindow()
        self.compose_window.show()

    def open_inbox_window(self):
        # Crypto config
        crypto_config = {
            "kem": "Kyber512",
            "sig": "Dilithium2"
        }

        # Load KEM private key from PEM file
        kem_private_key_b64 = load_pem_key("keys/kem_private_key.pem")
        if not kem_private_key_b64:
            QMessageBox.critical(
                self,
                "Error",
                "Could not load kem_private_key.pem.\nMake sure the file exists and is readable."
            )
            return

        # Create Inbox Window with keys
        self.inbox_window = InboxWindow(kem_private_key_b64=self.kem_private_key_b64)
        self.inbox_window.show()
