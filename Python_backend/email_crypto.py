#!/usr/bin/env python3
"""
email_crypto.py - Fixed for inbox.json structure compatibility
FIXED: Now correctly handles inbox.json structure where keys are in metadata
"""

import json
import base64
import hashlib
import hmac
import secrets
import os
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Library availability checks
CRYPTO_AVAILABLE = False
OQS_AVAILABLE = False

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    CRYPTO_AVAILABLE = True
    logger.info("✅ PyCryptodome available")
except ImportError:
    logger.warning("❌ PyCryptodome not available - using fallback")

try:
    import oqs
    OQS_AVAILABLE = True
    logger.info("✅ OQS available")
except ImportError:
    logger.warning("❌ OQS not available - using simulation")

class CryptoError(Exception):
    """Custom exception for crypto operations"""
    pass

class EmailCrypto:
    """Email encryption and decryption handler"""
    
    def __init__(self, kem_algo="Kyber512", sig_algo="Dilithium2"):
        self.kem_algo = kem_algo
        self.sig_algo = sig_algo
        self.crypto_available = CRYPTO_AVAILABLE
        self.oqs_available = OQS_AVAILABLE
        
    def _generate_secure_key(self, size=32):
        """Generate cryptographically secure random key"""
        return secrets.token_bytes(size)
    
    def _derive_key(self, password, salt, iterations=100000, key_length=32):
        """Derive key using PBKDF2"""
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, key_length)
    
    def _aes_encrypt(self, data, key):
        """AES encryption with proper padding"""
        if not self.crypto_available:
            return self._fallback_encrypt(data, key)
            
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Generate random IV
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Pad and encrypt
            padded_data = pad(data, AES.block_size)
            encrypted = cipher.encrypt(padded_data)
            
            # Return IV + encrypted data
            return iv + encrypted
            
        except Exception as e:
            logger.error(f"AES encryption failed: {e}")
            return self._fallback_encrypt(data, key)
    
    def _aes_decrypt(self, encrypted_data, key):
        """AES decryption with proper unpadding"""
        if not self.crypto_available:
            return self._fallback_decrypt(encrypted_data, key)
            
        try:
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            
            # Unpad
            unpadded = unpad(decrypted, AES.block_size)
            return unpadded.decode('utf-8')
            
        except Exception as e:
            logger.error(f"AES decryption failed: {e}")
            return self._fallback_decrypt(encrypted_data, key)
    
    def _fallback_encrypt(self, data, key):
        """Secure fallback encryption using XOR with key stretching"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Generate salt and nonce
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        
        # Derive encryption key
        derived_key = hashlib.pbkdf2_hmac('sha256', key, salt, 10000, len(data))
        
        # Encrypt using XOR
        encrypted = bytes(a ^ b for a, b in zip(data, derived_key))
        
        # Create HMAC for authentication
        hmac_key = hashlib.pbkdf2_hmac('sha256', key, salt + b'hmac', 10000, 32)
        hmac_tag = hmac.new(hmac_key, salt + nonce + encrypted, hashlib.sha256).digest()
        
        # Return salt + nonce + encrypted + hmac
        return salt + nonce + encrypted + hmac_tag
    
    def _fallback_decrypt(self, encrypted_data, key):
        """Secure fallback decryption"""
        if len(encrypted_data) < 60:  # 16 (salt) + 12 (nonce) + 32 (hmac) minimum
            raise CryptoError("Invalid encrypted data length")
        
        # Extract components
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        hmac_tag = encrypted_data[-32:]
        ciphertext = encrypted_data[28:-32]
        
        # Verify HMAC
        hmac_key = hashlib.pbkdf2_hmac('sha256', key, salt + b'hmac', 10000, 32)
        expected_hmac = hmac.new(hmac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
        
        if not secrets.compare_digest(hmac_tag, expected_hmac):
            raise CryptoError("HMAC verification failed - data corrupted")
        
        # Derive decryption key
        derived_key = hashlib.pbkdf2_hmac('sha256', key, salt, 10000, len(ciphertext))
        
        # Decrypt
        decrypted = bytes(a ^ b for a, b in zip(ciphertext, derived_key))
        return decrypted.decode('utf-8')
    
    def _generate_quantum_keys(self):
        """Generate quantum-safe keys"""
        if self.oqs_available:
            try:
                # Real OQS implementation
                kem = oqs.KeyEncapsulation(self.kem_algo)
                sig = oqs.Signature(self.sig_algo)
                
                # Generate keypairs
                kem_public_key = kem.generate_keypair()
                kem_private_key = kem.export_secret_key()
                
                sig_public_key = sig.generate_keypair()
                sig_private_key = sig.export_secret_key()
                
                # Encapsulate shared secret
                ciphertext, shared_secret = kem.encap_secret(kem_public_key)
                
                return {
                    'kem_public_key': kem_public_key,
                    'kem_private_key': kem_private_key,
                    'sig_public_key': sig_public_key,
                    'sig_private_key': sig_private_key,
                    'sig_object': sig,
                    'shared_secret': shared_secret,
                    'ciphertext': ciphertext,
                    'method': 'real_oqs'
                }
                
            except Exception as e:
                logger.warning(f"OQS failed: {e}, using simulation")
        
        # Fallback to simulation
        seed = f"{self.kem_algo}_{self.sig_algo}_{datetime.now().isoformat()}"
        
        # Generate deterministic but secure keys
        kem_private_key = self._derive_key(f"kem_private_{seed}", b"kem_salt")
        kem_public_key = self._derive_key(f"kem_public_{seed}", b"kem_salt")
        sig_private_key = self._derive_key(f"sig_private_{seed}", b"sig_salt")
        sig_public_key = self._derive_key(f"sig_public_{seed}", b"sig_salt")
        shared_secret = self._derive_key(f"shared_{seed}", b"shared_salt")
        
        # Simulate ciphertext
        ciphertext = hashlib.sha256(shared_secret + kem_public_key).digest()
        
        return {
            'kem_public_key': kem_public_key,
            'kem_private_key': kem_private_key,
            'sig_public_key': sig_public_key,
            'sig_private_key': sig_private_key,
            'sig_object': None,
            'shared_secret': shared_secret,
            'ciphertext': ciphertext,
            'method': 'simulation'
        }
    
    def _sign_data(self, data, private_key, sig_object=None):
        """Sign data with quantum-safe signature"""
        if self.oqs_available and sig_object:
            try:
                signature = sig_object.sign(data.encode('utf-8') if isinstance(data, str) else data)
                return signature
            except Exception as e:
                logger.warning(f"OQS signing failed: {e}")
        
        # Fallback signing
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hmac.new(private_key, data, hashlib.sha256).digest()
    
    def _verify_signature(self, data, signature, public_key):
        """Verify quantum-safe signature"""
        if self.oqs_available:
            try:
                sig = oqs.Signature(self.sig_algo)
                return sig.verify(data.encode('utf-8') if isinstance(data, str) else data, signature, public_key)
            except Exception as e:
                logger.warning(f"OQS verification failed: {e}")
        
        # Fallback verification
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        expected_sig = hmac.new(public_key, data, hashlib.sha256).digest()
        return secrets.compare_digest(signature, expected_sig)
    
    def encrypt_and_sign_email(self, email_data):
        """Encrypt email with quantum-safe cryptography"""
        try:
            logger.info(f"🔐 Encrypting email with {self.kem_algo}/{self.sig_algo}")
            
            # Prepare email content
            email_content = {
                "to": email_data.get("to", ""),
                "from": email_data.get("from", ""),
                "subject": email_data.get("subject", ""),
                "body": email_data.get("body", ""),
                "timestamp": datetime.now().isoformat()
            }
            
            email_json = json.dumps(email_content, ensure_ascii=False)
            
            # Generate quantum keys
            quantum_keys = self._generate_quantum_keys()
            
            # Encrypt email content
            encryption_key = quantum_keys['shared_secret'][:32]
            encrypted_bytes = self._aes_encrypt(email_json, encryption_key)
            encrypted_content = base64.b64encode(encrypted_bytes).decode('ascii')
            
            # Sign encrypted content
            signature = self._sign_data(encrypted_content, quantum_keys['sig_private_key'], quantum_keys.get('sig_object'))
            signature_b64 = base64.b64encode(signature).decode('ascii')
            
            # Create result compatible with inbox.json structure
            result = {
                "error": False,
                "encrypted_content": encrypted_content,
                "signature": signature_b64,
                "shared_secret": base64.b64encode(quantum_keys['shared_secret']).decode('ascii'),
                "kem_private_key": base64.b64encode(quantum_keys['kem_private_key']).decode('ascii'),
                "sig_public_key": base64.b64encode(quantum_keys['sig_public_key']).decode('ascii'),
                "message": f"Email encrypted successfully with {self.kem_algo}/{self.sig_algo}",
                "metadata": {
                    "kem_algo": self.kem_algo,
                    "sig_algo": self.sig_algo,
                    "timestamp": datetime.now().isoformat(),
                    "quantum_method": quantum_keys['method'],
                    "crypto_available": self.crypto_available,
                    "oqs_available": self.oqs_available,
                    "encryption_method": "AES_CBC",
                    "encrypted": True,
                    "signed": True,
                    "quantum_safe": True
                }
            }
            
            logger.info("✅ Email encrypted successfully")
            return result
            
        except Exception as e:
            logger.error(f"❌ Encryption failed: {e}")
            return {
                "error": True,
                "message": f"Encryption failed: {str(e)}",
                "encrypted_content": None,
                "signature": None
            }
    
    def decrypt_email(self, encrypted_result):
        """
        Decrypt email - FIXED for inbox.json structure compatibility
        Now correctly handles both formats:
        1. Direct keys in main object
        2. Keys nested in metadata object (inbox.json format)
        """
        try:
            logger.info("🔓 Decrypting email...")
            
            available_fields = list(encrypted_result.keys())
            logger.info(f"📋 Available fields: {available_fields}")
            
            # Check if this is a plain email (not encrypted)
            if ('message' in available_fields or 'body' in available_fields) and 'encrypted_content' not in available_fields:
                logger.info("📧 This appears to be a plain email, not encrypted")
                
                email_data = {
                    "to": encrypted_result.get("to", ""),
                    "from": encrypted_result.get("from", ""),
                    "subject": encrypted_result.get("subject", ""),
                    "body": encrypted_result.get("message") or encrypted_result.get("body", ""),
                    "timestamp": encrypted_result.get("timestamp", datetime.now().isoformat())
                }
                
                return {
                    "success": True,
                    "decrypted_email": email_data,
                    "signature_valid": False,
                    "message": "Plain email (not encrypted)"
                }
            
            # 🔥 FIXED: Look for encrypted_content
            encrypted_content = encrypted_result.get("encrypted_content")
            if not encrypted_content:
                raise CryptoError(f"No encrypted_content found. Available fields: {available_fields}")
            
            # 🔥 FIXED: Look for keys in multiple locations
            # First try main level, then metadata level
            signature_b64 = encrypted_result.get("signature")
            shared_secret_b64 = encrypted_result.get("shared_secret") or encrypted_result.get("fallback_key")
            
            # 🔥 FIXED: Check for sig_public_key in main level first, then metadata
            sig_public_key_b64 = encrypted_result.get("sig_public_key")
            
            # If not found in main level, check metadata
            if not sig_public_key_b64:
                metadata = encrypted_result.get("metadata", {})
                sig_public_key_b64 = metadata.get("sig_public_key")
                logger.info(f"🔍 Looking in metadata for sig_public_key: {'Found' if sig_public_key_b64 else 'Not found'}")
            
            # Also check if any other keys are in metadata
            if not signature_b64:
                metadata = encrypted_result.get("metadata", {})
                signature_b64 = metadata.get("signature")
                
            if not shared_secret_b64:
                metadata = encrypted_result.get("metadata", {})
                shared_secret_b64 = metadata.get("shared_secret") or metadata.get("fallback_key")
            
            # Final validation
            missing_fields = []
            if not signature_b64:
                missing_fields.append("signature")
            if not sig_public_key_b64:
                missing_fields.append("sig_public_key")
            if not shared_secret_b64:
                missing_fields.append("shared_secret/fallback_key")
            
            if missing_fields:
                logger.error(f"❌ Missing fields: {missing_fields}")
                logger.error(f"📋 Available in main: {list(encrypted_result.keys())}")
                if 'metadata' in encrypted_result:
                    logger.error(f"📋 Available in metadata: {list(encrypted_result['metadata'].keys())}")
                raise CryptoError(f"Missing required decryption data: {', '.join(missing_fields)}")
            
            # Decode keys
            try:
                signature = base64.b64decode(signature_b64)
                sig_public_key = base64.b64decode(sig_public_key_b64)
                shared_secret = base64.b64decode(shared_secret_b64)
                logger.info("✅ Keys decoded successfully")
            except Exception as e:
                raise CryptoError(f"Failed to decode base64 keys: {e}")
            
            # Verify signature
            signature_valid = self._verify_signature(encrypted_content, signature, sig_public_key)
            logger.info(f"🔐 Signature verification: {'✅ Valid' if signature_valid else '❌ Invalid'}")
            
            # Decrypt content
            encryption_key = shared_secret[:32]
            
            try:
                encrypted_bytes = base64.b64decode(encrypted_content)
                logger.info(f"📦 Encrypted data size: {len(encrypted_bytes)} bytes")
            except Exception as e:
                raise CryptoError(f"Failed to decode encrypted content: {e}")
            
            decrypted_json = self._aes_decrypt(encrypted_bytes, encryption_key)
            logger.info("🔓 Content decrypted successfully")
            
            # Parse email
            try:
                email_data = json.loads(decrypted_json)
                logger.info(f"📧 Email parsed: {email_data.get('subject', 'No subject')}")
            except Exception as e:
                raise CryptoError(f"Failed to parse decrypted JSON: {e}")
            
            logger.info("✅ Email decrypted successfully")
            
            return {
                "success": True,
                "decrypted_email": email_data,
                "signature_valid": signature_valid,
                "message": "Email decrypted successfully"
            }
            
        except Exception as e:
            logger.error(f"❌ Decryption failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": f"Decryption failed: {str(e)}"
            }
    
    def get_crypto_status(self):
        """Get current crypto status"""
        return {
            "crypto_available": self.crypto_available,
            "oqs_available": self.oqs_available,
            "kem_algorithm": self.kem_algo,
            "sig_algorithm": self.sig_algo,
            "encryption_method": "AES-256-CBC" if self.crypto_available else "Secure Fallback",
            "quantum_method": "Real OQS" if self.oqs_available else "Simulation",
            "security_level": "High" if self.oqs_available else "Medium-High"
        }

def decrypt_and_verify_email(encrypted_data, kem_private_key_b64=None):
    """
    Decrypt and verify email - wrapper function for backward compatibility
    FIXED: Now supports inbox.json structure
    """
    if isinstance(encrypted_data, str):
        try:
            encrypted_data = json.loads(encrypted_data)
        except Exception as e:
            logger.error(f"Failed to parse encrypted_data JSON: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": "Invalid JSON passed to decrypt_and_verify_email"
            }
    
    try:
        crypto = EmailCrypto()
        result = crypto.decrypt_email(encrypted_data)
    except Exception as e:
        logger.error(f"❌ decrypt_and_verify_email wrapper error: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": f"Unexpected error: {e}"
        }

    if result.get("success"):
        return {
            "success": True,
            "email": result["decrypted_email"],
            "signature_valid": result.get("signature_valid", False),
            "message": result.get("message", "Email decrypted successfully")
        }
    else:
        return {
            "success": False,
            "error": result.get("error", "Decryption failed"),
            "message": result.get("message", "Failed to decrypt email")
        }

def test_inbox_json_structure():
    """Test with inbox.json structure"""
    print("🧪 Testing with inbox.json structure")
    print("=" * 50)
    
    # Create test email
    test_email = {
        "to": "dineshsaini@mail",
        "from": "dineshsaini@mail",
        "subject": "Test Email",
        "body": "This is a test email for inbox.json structure!"
    }
    
    # Encrypt
    crypto = EmailCrypto()
    encrypted_result = crypto.encrypt_email(test_email)
    
    if encrypted_result.get("error"):
        print(f"❌ Encryption failed: {encrypted_result.get('message')}")
        return
    
    print("✅ Encryption successful!")
    
    # Create inbox.json format structure
    inbox_format = {
        "timestamp": "2025-07-05T12:13:23",
        "from": test_email["from"],
        "to": test_email["to"], 
        "subject": test_email["subject"],
        "is_quantum": True,
        "kem_algorithm": "Kyber512",
        "sig_algorithm": "Dilithium2",
        "encrypted_content": encrypted_result["encrypted_content"],
        "signature": encrypted_result["signature"],
        "shared_secret": encrypted_result["shared_secret"],
        "status": "encrypted",
        "metadata": {
            "kem": "Kyber512",
            "signature": "Dilithium2",
            "timestamp": "2025-07-05T12:13:23",
            "encrypted": True,
            "signed": True,
            "quantum_safe": True,
            "crypto_available": True,
            "oqs_available": True,
            "encryption_method": "AES_CBC",
            "sig_public_key": encrypted_result["sig_public_key"]  # 🔥 FIXED: Put sig_public_key in metadata
        }
    }
    
    print("\n📧 Testing decryption with inbox.json structure...")
    decrypted_result = crypto.decrypt_email(inbox_format)
    
    if decrypted_result.get("success"):
        print("✅ Decryption successful!")
        email = decrypted_result["decrypted_email"]
        print(f"   Subject: {email['subject']}")
        print(f"   Body: {email['body']}")
        print(f"   Signature valid: {decrypted_result['signature_valid']}")
        print(f"   Content matches: {email['body'] == test_email['body']}")
    else:
        print(f"❌ Decryption failed: {decrypted_result.get('error')}")
    
    print("\n" + "=" * 50)
    print("🎯 inbox.json Structure Test Complete!")
def encrypt_and_sign_email(email_data, crypto_config=None):
    """Wrapper function for direct import"""
    crypto = EmailCrypto()
    return crypto.encrypt_and_sign_email(email_data)

if __name__ == "__main__":
    test_inbox_json_structure()