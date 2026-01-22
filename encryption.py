# encryption.py - ENCRYPTION
import os
from cryptography.fernet import Fernet

class EncryptionManager:
    def __init__(self):
        self.key_file = "vault_key.key"
        self.load_or_create_key()
    
    def load_or_create_key(self):
        """Load or generate encryption key"""
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(self.key)
        
        self.cipher = Fernet(self.key)
    
    def encrypt(self, text):
        """Encrypt text"""
        return self.cipher.encrypt(text.encode()).decode()
    
    def decrypt(self, encrypted):
        """Decrypt text"""
        return self.cipher.decrypt(encrypted.encode()).decode()
