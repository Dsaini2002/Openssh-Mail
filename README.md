# 💌 Quantum-Safe Email Client

This project is a **Post-Quantum Secure Email Client**, developed using:

- 💠 [liboqs](https://github.com/open-quantum-safe/liboqs)
- 🔐 [OQS-OpenSSH](https://github.com/open-quantum-safe/openssh)
- 🧪 PyQt5 GUI framework
- 📬 Custom local SMTP server
It supports encryption, digital signature, and secure communication using post-quantum cryptography standards like **Kyber** and **Dilithium**.
---
## 🚀 Features
- ✅ Register users with automatic generation of post-quantum keys (KEM + Signature)
- ✅ Compose and send encrypted + signed emails
- ✅ Decrypt and verify received emails
- ✅ Supports quantum-safe algorithms (Kyber, Dilithium, Falcon, etc.)
- ✅ Custom certificate system stored in `certs/`
- ✅ Inbox and sent mail stored in local JSON files

---

## 📁 Folder Structure

quantum-email/
├── main.py
├──Python_backend
│     ├── email_crypto.py
│     ├── compose_window.py
│     ├── register_window.py
│     ├── inbox_window.py
├── certs/
│ ├── private_keys/ # Sender’s private keys (excluded via .gitignore)
│ ├── public_keys/ # Public keys to share
│ └── user_cert_map.json # Maps users to their cert files
├── emails/
│ ├── inbox.json
│ └── sent.json
├── keys/ # Optional SSH server keys (ignored)
├── .gitignore
├── requirements.txt
└── README.md


---

## 🔧 Setup Instructions

### 1. 🐍 Create a virtual environment

python3 -m venv venv
source venv/bin/activate

2. 📦 Install dependencies

pip install -r requirements.txt

3. 🛠️ Build and install liboqs

git clone --recursive https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=../install
make -j
make install

4. 🔐 Build OQS-OpenSSH (optional, for full crypto system)

Follow instructions at https://github.com/open-quantum-safe/openssh
🧪 Running the App

Run main application:

python3 main.py

You can also launch specific modules during development:

python3 register_window.py
python3 compose_window.py

🗂️ Quantum Certificates
    Each user is assigned two key pairs:
        KEM public/private key (for encryption using Kyber)
        Signature public/private key (for signing using Dilithium or Falcon)
    These are stored in:
        certs/private_keys/
        certs/public_keys/
        Paths are mapped inside certs/user_cert_map.json
📬 Email Flow
    User composes a message and selects:
        KEM algorithm (e.g., Kyber512)
        Signature algorithm (e.g., Dilithium2)
    Message is:
        Encrypted using recipient’s KEM public key
        Signed using sender’s private signature key
    Sent using local SMTP server (localhost:1025)
    Saved to emails/sent.json and emails/inbox.json for testing

import oqs
print(oqs.get_enabled_kem_mechanisms())
print(oqs.get_enabled_sig_mechanisms())

📂 .gitignore

This project includes a .gitignore file to prevent leaking sensitive files:

# Python
__pycache__/
*.pyc
venv/
.env

# Emails and secrets
emails/inbox.json
emails/sent.json
certs/private_keys/
keys/

📦 requirements.txt

Your requirements.txt includes:

PyQt5
oqs-python

Install it with:

pip install -r requirements.txt

⚠️ Disclaimer

    This is a research/educational project and not intended for production use. Always validate cryptographic systems with experts before deployment in real-world scenarios.

👨‍💻 Author

Made with ❤️ by Dinesh Saini
GitHub: https://github.com/dineshsaini

