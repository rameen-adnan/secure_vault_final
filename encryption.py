# encryption.py - Per-User Encryption System
import os
import base64
import hashlib
import json
from cryptography.fernet import Fernet

class EncryptionManager:
    def __init__(self):
        # NO MORE vault_key.key - each user has their own key
        self.cipher = None
        self.current_user = None
        self.salts_file = "user_salts.json"
    
    def get_user_salt(self, username):
        """Get or create unique salt for each user"""
        salts = {}
        if os.path.exists(self.salts_file):
            try:
                with open(self.salts_file, 'r') as f:
                    salts = json.load(f)
            except:
                salts = {}
        
        if username not in salts:
            # Generate new random salt for this user
            salt_bytes = os.urandom(16)
            salt_str = base64.b64encode(salt_bytes).decode('utf-8')
            salts[username] = salt_str
            
            # Save salts
            with open(self.salts_file, 'w') as f:
                json.dump(salts, f, indent=2)
            
            return salt_str
        else:
            # Return existing salt
            return salts[username]
    
    def create_key_from_password(self, master_password, username):
        """Create encryption key from password + user's unique salt"""
        # Get user's salt
        salt_str = self.get_user_salt(username)
        salt_bytes = base64.b64decode(salt_str)
        
        # Combine password + salt
        combined = master_password.encode() + salt_bytes
        
        # Create key using SHA256
        key_material = hashlib.sha256(combined).digest()
        
        # Convert to Fernet key
        key = base64.urlsafe_b64encode(key_material)
        
        return key
    
    def setup_for_user(self, username, master_password):
        """Setup encryption for specific user"""
        self.current_user = username
        key = self.create_key_from_password(master_password, username)
        self.cipher = Fernet(key)
        return True
    
    def encrypt(self, text):
        """Encrypt text with user's unique key"""
        if self.cipher is None:
            raise ValueError("Encryption not set up. Call setup_for_user() first.")
        return self.cipher.encrypt(text.encode()).decode()
    
    def decrypt(self, encrypted):
        """Decrypt text with user's unique key"""
        if self.cipher is None:
            raise ValueError("Encryption not set up. Call setup_for_user() first.")
        return self.cipher.decrypt(encrypted.encode()).decode()
