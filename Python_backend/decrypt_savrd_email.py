import json
from email_crypto import decrypt_and_verify_email

file_path = "/home/dinesh/openssh/openssh/DD.json"

# Load encrypted email from file
with open(file_path, "r") as f:
    encrypted_data = json.load(f)

# Decrypt
result = decrypt_and_verify_email(encrypted_data)

# Show result
if result["success"]:
    email = result["email"]
    print("✅ Decryption Successful!")
    print(f"From: {email['from']}")
    print(f"To: {email['to']}")
    print(f"Subject: {email['subject']}")
    print(f"Body: {email['body']}")
    print(f"Signature Valid: {result['signature_valid']}")
else:
    print(f"❌ Decryption Failed: {result['message']}")
