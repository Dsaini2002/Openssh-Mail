import smtpd
import asyncore
import json
import base64
from datetime import datetime
import os

INBOX_FILE = "/home/dinesh/openssh/openssh/emails/inbox.json"

class QuantumSMTPServer(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data, **kwargs):
        print("📨 Received email from:", mailfrom)
        print("📨 Recipients:", rcpttos)
        
        try:
            # DEBUG: Check data type
            print(f"🔍 Data type: {type(data)}")
            
            # Ensure data is bytes - this is the key fix
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data  # Already bytes
            
            # Try to extract Subject from headers
            subject = "No Subject"
            try:
                # Safely decode bytes to string for header parsing
                data_str = data_bytes.decode('utf-8', errors='ignore')
                for line in data_str.splitlines():
                    if line.lower().startswith("subject:"):
                        subject = line.partition(":")[2].strip()
                        break
            except Exception as e:
                print(f"⚠️ Warning: Could not parse subject: {e}")
            
            # Base64 encode the raw bytes
            raw_encoded = base64.b64encode(data_bytes).decode('ascii')
            
            # Prepare email entry
            email_entry = {
                "from": mailfrom,
                "to": rcpttos,
                "subject": subject,
                "timestamp": datetime.utcnow().isoformat(),
                "raw_data": raw_encoded
            }
            
            # Load existing emails
            if os.path.exists(INBOX_FILE):
                with open(INBOX_FILE, "r") as f:
                    try:
                        inbox = json.load(f)
                    except json.JSONDecodeError:
                        inbox = []
            else:
                inbox = []
            
            inbox.append(email_entry)
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(INBOX_FILE), exist_ok=True)
            
            with open(INBOX_FILE, "w") as f:
                json.dump(inbox, f, indent=2)
            
            print("✅ Email saved to inbox.json")
            print(f"📧 Subject: {subject}")
            
        except Exception as e:
            print(f"❌ Error processing message: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    # Create emails directory if it doesn't exist
    os.makedirs("emails", exist_ok=True)
    
    server = QuantumSMTPServer(('localhost', 1025), None)
    print("🚀 Quantum SMTP Server running on localhost:1025")
    print("📧 Emails will be saved to:", INBOX_FILE)
    print("🔄 Press Ctrl+C to stop")
    
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped")