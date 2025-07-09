import json

# Existing inbox
inbox_path = "/home/dinesh/openssh/openssh/emails/inbox.json"
try:
    with open(inbox_path, "r") as f:
        inbox = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    inbox = []

# Load new encrypted email
new_email_path = "emails/encrypted_email1.json"
with open(new_email_path, "r") as f:
    new_email = json.load(f)

# Append
inbox.append(new_email)

# Save back
with open(inbox_path, "w") as f:
    json.dump(inbox, f, indent=2)

print(f"✅ {new_email_path} added to {inbox_path}")
