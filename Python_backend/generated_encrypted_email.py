#!/usr/bin/env python3

"""
generate_encrypted_email.py
This script generates an encrypted email and saves it to emails/inbox.json
in the EXACT format you specified.
"""

import os
import json
from datetime import datetime

# Import your EmailCrypto class
from email_crypto import EmailCrypto

# Initialize EmailCrypto
crypto = EmailCrypto()

# Prepare test email data
test_email = {
    "to": "dineshsaini@mail",
    "from": "dineshsaini@mail",
    "subject": "Test Email",
    "body": "Hello, this is a quantum-encrypted test email generated automatically!",
}

print("🔐 Encrypting email...")
result = crypto.encrypt_email(test_email)

# Check for errors
if result.get("error"):
    print(f"❌ Encryption failed: {result['message']}")
    exit(1)

# Prepare JSON entry in YOUR SPECIFIED FORMAT
email_entry = {
    "to": test_email["to"],
    "from": test_email["from"],
    "subject": test_email["subject"],
    "encrypted_content": result["encrypted_data"],
    "signature": result["signature"],
    "shared_secret": result["shared_secret"],
    "kem_private_key": result["kem_private_key"],
    "sig_public_key": result["sig_public_key"],
    "encryption_method": result["metadata"].get("encryption_method", "AES_CBC"),
    "fallback_key": "ZG9fc29tZV9rZXlfdGVzdA==",  # dummy fallback key (can be replaced)
    "metadata": {
        "kem": result["metadata"].get("kem_algo", "Kyber512"),
        "signature": result["metadata"].get("sig_algo", "Dilithium2"),
        "timestamp": datetime.now().isoformat(),
        "encrypted": True,
        "signed": True,
        "quantum_safe": True,
        "crypto_available": result["metadata"].get("crypto_available", True),
        "oqs_available": result["metadata"].get("oqs_available", True),
        "encryption_method": result["metadata"].get("encryption_method", "AES_CBC")
    }
}

# Ensure emails directory exists
os.makedirs("emails", exist_ok=True)

# Check if inbox.json exists
inbox_path = "emails/inbox.json"
if os.path.exists(inbox_path):
    # Load existing emails
    with open(inbox_path, "r") as f:
        inbox = json.load(f)
else:
    inbox = []

# Append new email
inbox.append(email_entry)

# Save back to inbox.json
with open(inbox_path, "w") as f:
    json.dump(inbox, f, indent=2)

print("✅ Encrypted email saved to emails/inbox.json")
print(f"📧 Subject: {test_email['subject']}")
print(f"🔑 KEM: {result['metadata']['kem_algo']}, SIG: {result['metadata']['sig_algo']}")
