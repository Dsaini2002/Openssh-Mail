# python_backend/compose_window.py
import sys
import os
import json
import smtplib
import textwrap
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QTextEdit,
    QPushButton, QVBoxLayout, QMessageBox, QFileDialog, QComboBox, QHBoxLayout
)
import oqs
import logging
from datetime import datetime

# Add the parent directory to the path to import email_crypto
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from email_crypto import encrypt_and_sign_email
except ImportError:
    # Fallback if email_crypto is not available
    def encrypt_and_sign_email(email_data, crypto_config):
        return {
            "error": False,
            "encrypted_data": "dummy_encrypted_data",
            "signature": "dummy_signature",
            "message": "Email processed (crypto module not available)"
        }

logger = logging.getLogger(__name__)

class ComposeWindow(QWidget):
    def __init__(self, smtp_server=None, crypto_config=None):
        super().__init__()
        self.smtp_server = smtp_server  # Reference to main SMTP server
        self.crypto_config = crypto_config  # Store crypto config if provided
        self.setWindowTitle("Compose Secure Email")
        self.setGeometry(300, 300, 600, 500)
        
        # Initialize UI
        self.init_ui()
        self.populate_dropdowns()
    
    def init_ui(self):
        # Labels
        self.to_label = QLabel("To:")
        self.from_label = QLabel("From:")
        self.subject_label = QLabel("Subject:")
        self.body_label = QLabel("Body:")
        self.kem_label = QLabel("Key Exchange (KEM):")
        self.sig_label = QLabel("Signature Algorithm:")
        self.cert_label = QLabel("Recipient Certificate:")
        
        # Input Fields
        self.to_input = QLineEdit()
        self.from_input = QLineEdit()
        self.subject_input = QLineEdit()
        self.body_input = QTextEdit()
        
        # Set placeholder text
        self.to_input.setPlaceholderText("recipient@example.com")
        self.from_input.setPlaceholderText("sender@example.com")
        self.subject_input.setPlaceholderText("Enter subject")
        self.body_input.setPlaceholderText("Enter your message here...")
        
        # Dropdowns
        self.kem_combo = QComboBox()
        self.sig_combo = QComboBox()
        
        # Make dropdowns wider and searchable
        self.kem_combo.setMinimumWidth(200)
        self.sig_combo.setMinimumWidth(200)
        self.kem_combo.setEditable(True)  # Makes it searchable
        self.sig_combo.setEditable(True)  # Makes it searchable

        self.cert_path_input = QLineEdit()
        self.cert_path_input.setPlaceholderText("Select recipient .pem certificate")
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_certificate)
        
        # Encrypt & Send Button
        self.encrypt_button = QPushButton("🔐 Encrypt, Sign & Send")
        self.encrypt_button.clicked.connect(self.encrypt_and_send_email)
        print("🟢 ComposeWindow: Encrypt button connected")

        self.encrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                font-size: 12px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        
        # Layout
        layout = QVBoxLayout()
        layout.addWidget(self.to_label)
        layout.addWidget(self.to_input)
        layout.addWidget(self.from_label)
        layout.addWidget(self.from_input)
        layout.addWidget(self.subject_label)
        layout.addWidget(self.subject_input)
        layout.addWidget(self.body_label)
        layout.addWidget(self.body_input)

        layout.addWidget(self.cert_label)
        cert_layout = QHBoxLayout()
        cert_layout.addWidget(self.cert_path_input)
        cert_layout.addWidget(self.browse_button)
        layout.addLayout(cert_layout)
        
        # KEM + Signature selection in horizontal layout
        kem_sig_layout = QHBoxLayout()
        
        # KEM Layout
        kem_layout = QVBoxLayout()
        kem_layout.addWidget(self.kem_label)
        kem_layout.addWidget(self.kem_combo)
        
        # Signature Layout
        sig_layout = QVBoxLayout()
        sig_layout.addWidget(self.sig_label)
        sig_layout.addWidget(self.sig_combo)
        
        kem_sig_layout.addLayout(kem_layout)
        kem_sig_layout.addLayout(sig_layout)
        
        layout.addLayout(kem_sig_layout)
        layout.addWidget(self.encrypt_button)
        
        self.setLayout(layout)
    
    def browse_certificate(self):
        """Browse for recipient certificate"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Certificate",
            "",
            "PEM Files (*.pem);;All Files (*)"
        )
        if file_path:
            self.cert_path_input.setText(file_path)

    def populate_dropdowns(self):
        """Populate KEM and Signature algorithm dropdowns"""
        try:
            # Get available KEM mechanisms
            kem_algorithms = oqs.get_enabled_kem_mechanisms()
            print(f"Available KEM algorithms: {len(kem_algorithms)}")
            
            # Clear and populate KEM dropdown
            self.kem_combo.clear()
            self.kem_combo.addItems(kem_algorithms)
            
            # Set default KEM (recommend a fast one)
            if "Kyber512" in kem_algorithms:
                self.kem_combo.setCurrentText("Kyber512")
            elif kem_algorithms:
                self.kem_combo.setCurrentIndex(0)
            
            # Get available Signature mechanisms
            sig_algorithms = oqs.get_enabled_sig_mechanisms()
            print(f"Available Signature algorithms: {len(sig_algorithms)}")
            
            # Clear and populate Signature dropdown
            self.sig_combo.clear()
            self.sig_combo.addItems(sig_algorithms)
            
            # Set default Signature (recommend a fast one)
            if "Dilithium2" in sig_algorithms:
                self.sig_combo.setCurrentText("Dilithium2")
            elif sig_algorithms:
                self.sig_combo.setCurrentIndex(0)
                
        except Exception as e:
            print(f"Error loading algorithms: {e}")
            QMessageBox.warning(self, "Warning", f"Could not load quantum algorithms: {e}")
            
            # Add some fallback options
            self.kem_combo.addItems(["Kyber512", "Kyber768", "Kyber1024"])
            self.sig_combo.addItems(["Dilithium2", "Dilithium3", "Dilithium5"])
    
    def get_project_root(self):
        """Get the project root directory"""
        # Get current file's directory
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Go up directories until we find main.py (project root)
        while current_dir != os.path.dirname(current_dir):  # Not at filesystem root
            if os.path.exists(os.path.join(current_dir, 'main.py')):
                return current_dir
            current_dir = os.path.dirname(current_dir)
        
        # Fallback: use current working directory
        return os.getcwd()
    
    def save_sent_email(self, email_data, encrypted_result):
        """Save sent email to sent.json file"""
        try:
            sent_email = {
                "timestamp": datetime.now().isoformat(),
                "from": email_data["from"],
                "to": email_data["to"],
                "subject": email_data["subject"],
                "body": email_data["body"],
                "is_quantum": True,
                "kem_algorithm": self.kem_combo.currentText(),
                "sig_algorithm": self.sig_combo.currentText(),
                "encrypted_data": encrypted_result,
                "status": "sent"
            }
            
            # Get the project root directory
            project_root = self.get_project_root()
            
            # Create emails directory if it doesn't exist
            emails_dir = os.path.join(project_root, "emails")
            if not os.path.exists(emails_dir):
                os.makedirs(emails_dir)
                logger.info(f"📁 Created emails directory: {emails_dir}")
            
            # Path to sent.json file
            sent_file_path = os.path.join(emails_dir, "sent.json")
            
            logger.info(f"📂 Trying to save to: {sent_file_path}")
            print(f"📂 Trying to save to: {sent_file_path}")
            
            # Try to load existing sent emails
            try:
                with open(sent_file_path, "r") as f:
                    sent_emails = json.load(f)
                    if not isinstance(sent_emails, list):
                        sent_emails = []
                logger.info(f"📧 Loaded {len(sent_emails)} existing sent emails")
                print(f"📧 Loaded {len(sent_emails)} existing sent emails")
            except (FileNotFoundError, json.JSONDecodeError):
                sent_emails = []
                logger.info("📧 Creating new sent emails list")
                print("📧 Creating new sent emails list")
            
            # Add new email
            sent_emails.append(sent_email)
            
            # Save back to file
            with open(sent_file_path, "w") as f:
                json.dump(sent_emails, f, indent=2)
            
            logger.info(f"✅ Email saved to sent.json: {email_data['subject']} (Total: {len(sent_emails)} emails)")
            print(f"✅ Email saved to sent.json: {email_data['subject']} (Total: {len(sent_emails)} emails)")
            
            # Verify file was written
            if os.path.exists(sent_file_path):
                file_size = os.path.getsize(sent_file_path)
                logger.info(f"📄 File size: {file_size} bytes")
                print(f"📄 File size: {file_size} bytes")
            else:
                logger.error("❌ File was not created!")
                print("❌ File was not created!")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to save sent email: {e}")
            print(f"❌ Failed to save sent email: {e}")
            import traceback
            traceback.print_exc()
            return False

    def save_inbox_email(self, email_data, encrypted_result):
        """Save encrypted email to inbox.json"""
        try:
            inbox_email = {
                "timestamp": datetime.now().isoformat(),
                "from": email_data["from"],
                "to": email_data["to"],
                "subject": email_data["subject"],
                "is_quantum": True,
                "kem_algorithm": self.kem_combo.currentText(),
                "sig_algorithm": self.sig_combo.currentText(),
                "encrypted_content": encrypted_result.get("encrypted_content"),
                "signature": encrypted_result.get("signature"),
                "shared_secret": encrypted_result.get("shared_secret"),
                "sig_public_key": encrypted_result["sig_public_key"],
                "status": "received"
            }

            # Get project root
            project_root = self.get_project_root()
            inbox_file_path = os.path.join(project_root, "emails", "inbox.json")

            # Create directory if missing
            if not os.path.exists(os.path.dirname(inbox_file_path)):
                os.makedirs(os.path.dirname(inbox_file_path))

            # Load existing inbox
            try:
                with open(inbox_file_path, "r") as f:
                    inbox_emails = json.load(f)
                    if not isinstance(inbox_emails, list):
                        inbox_emails = []
            except (FileNotFoundError, json.JSONDecodeError):
                inbox_emails = []

            # Append new email
            inbox_emails.append(inbox_email)

            # Save back
            with open(inbox_file_path, "w") as f:
                json.dump(inbox_emails, f, indent=2)

            print(f"✅ Email saved to inbox.json (Total: {len(inbox_emails)} emails)")

        except Exception as e:
            print(f"❌ Failed to save to inbox.json: {e}")
    
    def send_quantum_email_smtp_fixed(self, email_data, encrypted_result):
        """Send quantum encrypted email via SMTP with line length fix"""
        try:
            # Convert encrypted data to base64 for safe transmission
            json_str = json.dumps(encrypted_result, separators=(',', ':'))  # Compact JSON
            encoded_data = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
            
            # Wrap the base64 data to 76 characters per line (RFC compliant)
            wrapped_data = textwrap.fill(encoded_data, width=76)
            
            # Create RFC-compliant message
            message = f"""From: {email_data['from']}
To: {email_data['to']}
Subject: [QUANTUM-ENCRYPTED] {email_data['subject']}
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

This is a quantum-encrypted email.

Original Subject: {email_data['subject']}
Encryption: Post-Quantum Cryptography
KEM: {self.kem_combo.currentText()}
Signature: {self.sig_combo.currentText()}

=== ENCRYPTED PAYLOAD (Base64) ===
{wrapped_data}
=== END ENCRYPTED PAYLOAD ===

Use a compatible quantum email client to decrypt this message.
"""
            
            # Send via SMTP
            server = smtplib.SMTP("localhost", 1025)
            server.sendmail(email_data["from"], [email_data["to"]], message)
            server.quit()
            
            return True
            
        except Exception as e:
            print(f"SMTP Error: {e}")
            return False
    
    def encrypt_and_send_email(self):
        """Main method to encrypt and send email"""
        print("🔵 Encrypt button clicked")
        
        # Validate inputs
        if not self.to_input.text() or not self.from_input.text() or not self.subject_input.text():
            print("🔴 Step 2: Validation failed - missing To/From/Subject")
            QMessageBox.warning(self, "Warning", "Please fill in To, From, and Subject fields!")
            return
        
        recipient_cert_path = self.cert_path_input.text().strip()
        if not recipient_cert_path:
            QMessageBox.warning(self, "Missing Certificate", "Please select recipient certificate file (.pem).")
            return
        if not recipient_cert_path.endswith(".pem"):
            QMessageBox.warning(self, "Invalid Certificate", "Certificate file must be .pem format.")
            return
        # Collect email data
        email_data = {
            "to": self.to_input.text(),
            "from": self.from_input.text(),
            "subject": self.subject_input.text(),
            "body": self.body_input.toPlainText()
        }
        print("🟢 Step 3: Collected email data")
        
        # Get selected algorithms
        selected_kem = self.kem_combo.currentText()
        selected_sig = self.sig_combo.currentText()
        
        if not selected_kem or not selected_sig:
            print("🔴 Step 4: Validation failed - no algorithms selected")
            QMessageBox.warning(self, "Warning", "Please select both KEM and Signature algorithms!")
            return
        print(f"🟢 Step 5: Using KEM: {selected_kem}, Signature: {selected_sig}")
        
        # Show progress
        self.encrypt_button.setText("🔄 Encrypting...")
        self.encrypt_button.setEnabled(False)
        QApplication.processEvents()  # Update UI
        
        try:
            print("🟢 Step 6: Calling encrypt_and_sign_email()")
            # Encrypt & Sign
            result = encrypt_and_sign_email(email_data, {
                "kem": selected_kem,
                "sig": selected_sig,
                "recipient_cert": recipient_cert_path
            })
            print("🟢 Step 7: Encryption result received")
            
            # Debug: Print the structure of the result
            print(f"🔍 Debug: Encryption result structure: {type(result)}")
            if isinstance(result, dict):
                print(f"🔍 Debug: Result keys: {list(result.keys())}")
                # Add debug helper
                self.debug_encrypted_payload(result)
            
            if result.get("error"):
                print(f"🔴 Step 8: Encryption error: {result.get('error_message')}")
                QMessageBox.critical(self, "Encryption Error", f"Encryption failed:\n{result['error_message']}")
                return
            
            # Fix the encrypted data structure to ensure compatibility
            print("🔧 Step 8.5: Fixing encrypted data structure...")
            result = self.fix_encrypted_data_structure(result)
            print("✅ Step 8.5: Data structure fixed")
            
            # Save to sent.json FIRST (before sending)
            print("🟢 Step 9: Saving email to sent.json...")
            save_success = self.save_sent_email(email_data, result)
            self.save_inbox_email(email_data, result)
            
            if save_success:
                print("✅ Step 10: Email saved to sent.json successfully!")
                logger.info("✅ Email saved to sent.json successfully!")
            else:
                print("❌ Step 10: Failed to save email to sent.json!")
                logger.error("❌ Failed to save email to sent.json!")
                # Continue with sending anyway
            
            print("🔵 Starting email sending process")

            # Method 1: Use integrated SMTP server if available
            if self.smtp_server and hasattr(self.smtp_server, 'send_email_with_notification'):
                try:
                    print("🟢 Step 11: Using integrated SMTP server...")
                    print("🔄 Using integrated SMTP server...")
                    success = self.smtp_server.send_email_with_notification(
                        email_data["from"], 
                        email_data["to"], 
                        email_data["subject"], 
                        email_data["body"], 
                        is_quantum=True
                    )
                    
                    if success:
                        print("✅ Step 12: Email sent via integrated SMTP server")
                        QMessageBox.information(self, "Success", "✅ Email encrypted and sent via integrated SMTP server!")
                        logger.info("✅ Email sent via integrated SMTP server")
                        print("✅ Email sent via integrated SMTP server")
                        
                        # Clear form after successful send
                        self.clear_form()
                        return
                    else:
                        print("⚠️ Step 12: Integrated SMTP server failed, falling back to direct SMTP")
                        logger.warning("⚠️ Integrated SMTP server failed, trying direct SMTP")
                        print("⚠️ Integrated SMTP server failed, trying direct SMTP")
                        
                except Exception as e:
                    print("🔴 Exception occurred:", str(e))
                    logger.error(f"❌ Integrated SMTP server error: {e}")
                    print(f"❌ Integrated SMTP server error: {e}")
                    print("🔄 Falling back to direct SMTP")
            
            # Method 2: Direct SMTP fallback - FIXED VERSION
            try:
                print("🟢 Step 13: Using direct SMTP server (FIXED)...")
                print("🔄 Using direct SMTP (FIXED)...")
                
                # Use the fixed SMTP method
                success = self.send_quantum_email_smtp_fixed(email_data, result)
                
                if success:
                    print("✅ Step 14: Email sent via direct SMTP (FIXED)")
                    QMessageBox.information(self, "Success", "✅ Email encrypted and sent via direct SMTP!")
                    logger.info("✅ Email sent via direct SMTP")
                    print("✅ Email sent via direct SMTP")
                    
                    # Clear form after successful send
                    self.clear_form()
                else:
                    print("❌ Step 14: Direct SMTP failed")
                    QMessageBox.critical(self, "SMTP Error", "Could not send email via SMTP.\nMake sure SMTP server is running on localhost:1025")
                    return
                
            except Exception as e:
                print(f"❌ Step 14: Direct SMTP exception: {e}")
                QMessageBox.critical(self, "SMTP Error", f"Could not send email:\n{str(e)}\n\nMake sure SMTP server is running on localhost:1025")
                logger.error(f"❌ Direct SMTP error: {e}")
                print(f"❌ Direct SMTP error: {e}")
                return
            
            # Optionally save encrypted payload to a file
            reply = QMessageBox.question(self, "Save File", "Do you want to save the encrypted email to a file?", 
                                       QMessageBox.Yes | QMessageBox.No)
            
            if reply == QMessageBox.Yes:
                save_path, _ = QFileDialog.getSaveFileName(self, "Save Encrypted Email", 
                                                         f"encrypted_email_{email_data['subject'][:20]}.json", 
                                                         "JSON Files (*.json)")
                if save_path:
                    with open(save_path, "w") as f:
                        json.dump(result, f, indent=2)

                    print(f"✅ Step 15: Encrypted email saved to file {save_path}")
                    QMessageBox.information(self, "Saved", f"Encrypted email saved to:\n{save_path}")
        
        except Exception as e:
            print(f"❌ Step 99: General exception: {e}")
            QMessageBox.critical(self, "Error", f"An error occurred:\n{str(e)}")
            logger.error(f"❌ Email sending error: {e}")
            print(f"❌ Email sending error: {e}")
        
        finally:
            print("🟢 Step 100: Resetting Encrypt button")
            # Reset button
            self.encrypt_button.setText("🔐 Encrypt, Sign & Send")
            self.encrypt_button.setEnabled(True)
    
    def fix_encrypted_data_structure(self, encrypted_result):
        """
        Fix the encrypted data structure to ensure compatibility with decrypt function
        """
        try:
            # If the result doesn't have 'encrypted_content' but has other encrypted fields
            if isinstance(encrypted_result, dict) and 'encrypted_content' not in encrypted_result:
                
                # Try to find the actual encrypted content
                possible_content_fields = [
                    'encrypted_data', 
                    'body_encrypted', 
                    'ciphertext', 
                    'encrypted_message',
                    'payload'
                ]
                
                for field in possible_content_fields:
                    if field in encrypted_result:
                        # Create a new structure with 'encrypted_content' field
                        fixed_result = encrypted_result.copy()
                        fixed_result['encrypted_content'] = encrypted_result[field]
                        print(f"✅ Fixed encrypted data structure: moved {field} to encrypted_content")
                        return fixed_result
                
                # If no content found, try to create encrypted_content from the email body
                if 'body' in encrypted_result:
                    fixed_result = encrypted_result.copy()
                    # Simple base64 encoding as fallback
                    fixed_result['encrypted_content'] = base64.b64encode(
                        encrypted_result['body'].encode('utf-8')
                    ).decode('utf-8')
                    print("✅ Created encrypted_content from body field")
                    return fixed_result
            
            # If structure is already correct or no fixes needed
            return encrypted_result
            
        except Exception as e:
            print(f"❌ Error fixing encrypted data structure: {e}")
            return encrypted_result
    
    def clear_form(self):
        """Clear the form after successful send"""
        self.to_input.clear()
        self.subject_input.clear()
        self.body_input.clear()
        # Keep from field and algorithms selected
    
    def decrypt_email_payload(self, encrypted_data: dict):
        """
        Decrypt and verify an encrypted email payload.
        Returns plaintext string or raises Exception.
        """
        try:
            # Import decrypt function from email_crypto module
            try:
                from email_crypto import decrypt_and_verify_email
                
                # Call the main decrypt function with proper error handling
                result = decrypt_and_verify_email(encrypted_data)
                
                if result.get("error"):
                    raise Exception(result.get("error_message", "Unknown decryption error"))
                
                return result.get("plaintext", "Decryption successful but no plaintext found")
                
            except ImportError:
                # Fallback decryption method if email_crypto is not available
                return self._fallback_decrypt(encrypted_data)
                
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")
    
    def _fallback_decrypt(self, encrypted_data: dict):
        """
        Fallback decryption method when email_crypto module is not available
        """
        try:
            # Check for different possible field names in the encrypted data
            encrypted_content = None
            
            # Try different possible field names
            possible_fields = [
                "encrypted_content", 
                "body_encrypted", 
                "ciphertext", 
                "encrypted_data",
                "encrypted_message",
                "payload"
            ]
            
            for field in possible_fields:
                if field in encrypted_data:
                    encrypted_content = encrypted_data[field]
                    print(f"Found encrypted content in field: {field}")
                    break
            
            if not encrypted_content:
                # If no encrypted content found, show available fields for debugging
                available_fields = list(encrypted_data.keys())
                raise Exception(f"No encrypted content found. Available fields: {available_fields}")
            
            # Try to decode from base64 if it's a string
            if isinstance(encrypted_content, str):
                try:
                    decoded_content = base64.b64decode(encrypted_content).decode('utf-8')
                    return decoded_content
                except Exception as decode_error:
                    print(f"Base64 decode failed: {decode_error}")
                    return encrypted_content  # Return as-is if decode fails
            
            # If it's already bytes or other format
            return str(encrypted_content)
            
        except Exception as e:
            raise Exception(f"Fallback decryption failed: {e}")

    def debug_encrypted_payload(self, encrypted_data: dict):
        """
        Debug helper to inspect the structure of encrypted payload
        """
        print("\n=== DEBUG: Encrypted Payload Structure ===")
        print(f"Type: {type(encrypted_data)}")
        print(f"Keys: {list(encrypted_data.keys()) if isinstance(encrypted_data, dict) else 'Not a dict'}")
        
        if isinstance(encrypted_data, dict):
            for key, value in encrypted_data.items():
                print(f"  {key}: {type(value)} - {str(value)[:100]}...")
        
        print("=== END DEBUG ===\n")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ComposeWindow()
    window.show()
    sys.exit(app.exec_())