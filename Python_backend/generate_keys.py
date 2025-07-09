#!/usr/bin/env python3
"""
Key Generation Script for Quantum-Safe Email System
Generates KEM key pairs and signature key pairs
"""

import os
import sys

def generate_keys_with_cryptography():
    """Generate keys using the cryptography library (RSA for demonstration)"""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        print("Generating keys using cryptography library...")
        
        # Generate KEM private key (RSA for now - replace with post-quantum when available)
        kem_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate signature key pair
        sig_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        sig_public_key = sig_private_key.public_key()
        
        # Create keys directory
        os.makedirs("keys", exist_ok=True)
        
        # Save KEM private key
        kem_private_pem = kem_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open("keys/kem_private_key.pem", "wb") as f:
            f.write(kem_private_pem)
        
        # Save KEM public key (for senders to encrypt to you)
        kem_public_key = kem_private_key.public_key()
        kem_public_pem = kem_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open("keys/kem_public_key.pem", "wb") as f:
            f.write(kem_public_pem)
        
        # Save signature public key (for verifying signatures from senders)
        sig_public_pem = sig_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open("keys/sig_public_key.pem", "wb") as f:
            f.write(sig_public_pem)
        
        # Save signature private key (for signing your own messages)
        sig_private_pem = sig_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        with open("keys/sig_private_key.pem", "wb") as f:
            f.write(sig_private_pem)
        
        print("✅ Keys generated successfully!")
        print("Generated files:")
        print("  - keys/kem_private_key.pem (your private key for decryption)")
        print("  - keys/kem_public_key.pem (your public key - share with senders)")
        print("  - keys/sig_public_key.pem (public key for signature verification)")
        print("  - keys/sig_private_key.pem (your private key for signing)")
        
        return True
        
    except ImportError:
        print("❌ cryptography library not found")
        return False
    except Exception as e:
        print(f"❌ Error generating keys: {e}")
        return False

def generate_dummy_keys():
    """Generate dummy keys for testing purposes"""
    print("Generating dummy keys for testing...")
    
    os.makedirs("keys", exist_ok=True)
    
    # Create dummy PEM-formatted keys
    dummy_private_key = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC8Q7HgL8yK2R2x
7rW8X9Y5Z3V4M2N1P6Q8R7S9T0U3V6W7X8Y9Z1A2B3C4D5E6F7G8H9I0J1K2L3M4
N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6
T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8
Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0
F1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1A2B3C4D5E6F7G8H9I0J1K2
L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q4
R5S6T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6
X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8
D9E0F1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1A2B3C4D5E6F7G8H9I0
J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2
P3Q4R5S6T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4
V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4Z5A6
B7C8D9E0F1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1A2B3C4D5E6F7G8
H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0
N1O2P3Q4R5S6T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2
T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4
Z5A6B7C8D9E0F1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1A2B3C4D5E6
F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8
L9M0N1O2P3Q4R5S6T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0
R1S2T3U4V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0wIDAQABAoIBAQCXX1X2X3X4
X5X6X7X8X9Y0Y1Y2Y3Y4Y5Y6Y7Y8Y9Z0Z1Z2Z3Z4Z5Z6Z7Z8Z9A0A1A2A3A4A5A6
A7A8A9B0B1B2B3B4B5B6B7B8B9C0C1C2C3C4C5C6C7C8C9D0D1D2D3D4D5D6D7D8
D9E0E1E2E3E4E5E6E7E8E9F0F1F2F3F4F5F6F7F8F9G0G1G2G3G4G5G6G7G8G9H0
H1H2H3H4H5H6H7H8H9I0I1I2I3I4I5I6I7I8I9J0J1J2J3J4J5J6J7J8J9K0K1K2
K3K4K5K6K7K8K9L0L1L2L3L4L5L6L7L8L9M0M1M2M3M4M5M6M7M8M9N0N1N2N3N4
N5N6N7N8N9O0O1O2O3O4O5O6O7O8O9P0P1P2P3P4P5P6P7P8P9Q0Q1Q2Q3Q4Q5Q6
Q7Q8Q9R0R1R2R3R4R5R6R7R8R9S0S1S2S3S4S5S6S7S8S9T0T1T2T3T4T5T6T7T8
T9U0U1U2U3U4U5U6U7U8U9V0V1V2V3V4V5V6V7V8V9W0W1W2W3W4W5W6W7W8W9X0
X1X2X3X4X5X6X7X8X9Y0Y1Y2Y3Y4Y5Y6Y7Y8Y9Z0Z1Z2Z3Z4Z5Z6Z7Z8Z9A0A1A2
A3A4A5A6A7A8A9B0B1B2B3B4B5B6B7B8B9C0C1C2C3C4C5C6C7C8C9D0D1D2D3D4
D5D6D7D8D9E0E1E2E3E4E5E6E7E8E9F0F1F2F3F4F5F6F7F8F9G0G1G2G3G4G5G6
G7G8G9H0H1H2H3H4H5H6H7H8H9I0I1I2I3I4I5I6I7I8I9J0J1J2J3J4J5J6J7J8
J9K0K1K2K3K4K5K6K7K8K9L0L1L2L3L4L5L6L7L8L9M0M1M2M3M4M5M6M7M8M9N0
N1N2N3N4N5N6N7N8N9O0O1O2O3O4O5O6O7O8O9P0P1P2P3P4P5P6P7P8P9Q0Q1Q2
Q3Q4Q5Q6Q7Q8Q9R0R1R2R3R4R5R6R7R8R9S0S1S2S3S4S5S6S7S8S9T0T1T2T3T4
T5T6T7T8T9U0U1U2U3U4U5U6U7U8U9V0V1V2V3V4V5V6V7V8V9W0W1W2W3W4W5W6
W7W8W9X0X1X2X3X4X5X6X7X8X9Y0Y1Y2Y3Y4Y5Y6Y7Y8Y9Z0Z1Z2Z3Z4Z5Z6Z7Z8
Z9
-----END PRIVATE KEY-----"""

    dummy_public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvEOx4C/MitkdsJ61vF/W
OWd1eDNjdT+kPEe0vU9FN1elu1/GPWdQNgdwuA5Rxvxx7G8H9I0J1K2L3M4N5O6
P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6T7U8
V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8Z9A0
B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0F1G2
H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1A2B3C4D5E6F7G8H9I0J1K2L3M4
N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6
T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8
Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8D9E0
F1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1A2B3C4D5E6F7G8H9I0J1K2
L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q4
R5S6T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6
X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4P5Q6R7S8T9U0V1W2X3Y4Z5A6B7C8
D9E0F1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U6V7W8X9Y0Z1A2B3C4D5E6F7G8H9I0
J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7A8B9C0D1E2F3G4H5I6J7K8L9M0N1O2
P3Q4R5S6T7U8V9W0X1Y2Z3A4B5C6D7E8F9G0H1I2J3K4L5M6N7O8P9Q0R1S2T3U4
V5W6X7Y8Z9A0B1C2D3E4F5G6H7I8J9K0wIDAQAB
-----END PUBLIC KEY-----"""

    # Write the dummy keys
    with open("keys/kem_private_key.pem", "w") as f:
        f.write(dummy_private_key)
    
    with open("keys/sig_public_key.pem", "w") as f:
        f.write(dummy_public_key)
    
    with open("keys/kem_public_key.pem", "w") as f:
        f.write(dummy_public_key)
    
    with open("keys/sig_private_key.pem", "w") as f:
        f.write(dummy_private_key)
    
    print("✅ Dummy keys generated successfully!")
    print("⚠️  WARNING: These are dummy keys for testing only!")
    print("Generated files:")
    print("  - keys/kem_private_key.pem")
    print("  - keys/kem_public_key.pem") 
    print("  - keys/sig_public_key.pem")
    print("  - keys/sig_private_key.pem")

def main():
    print("🔐 Quantum-Safe Email Key Generator")
    print("=" * 40)
    
    # Try to generate real keys first, fall back to dummy keys
    if not generate_keys_with_cryptography():
        print("\n⚠️  Falling back to dummy keys for testing...")
        print("To use real keys, install: pip install cryptography")
        generate_dummy_keys()
    
    # Also create emails directory if it doesn't exist
    os.makedirs("emails", exist_ok=True)
    if not os.path.exists("emails/inbox.json"):
        with open("emails/inbox.json", "w") as f:
            f.write("[]")
        print("📧 Created empty emails/inbox.json")

if __name__ == "__main__":
    main()