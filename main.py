#!/usr/bin/env python3
"""
SECURE PASSWORD MANAGER - MAIN FILE (WITH REGISTRATION)

"""

import tkinter as tk
import json
import os
import bcrypt
import time
from login import create_login_screen, create_registration_screen
from dashboard import Dashboard
from encryption import EncryptionManager
from credential_management import CredentialManager
from audit_log import AuditLog
from tkinter import messagebox

class SecureVaultApp:
    def __init__(self):
        # ---------------- Main Window ----------------
        self.root = tk.Tk()
        self.root.title("Secure Vault - Password Manager")
        self.root.geometry("1300x800")
        self.root.configure(bg='#f8f9fa')

        # ---------------- Encryption ----------------
        self.encryption = EncryptionManager()

        # ---------------- Session Data ----------------
        self.current_user = None
        self.user_data = None
        self.failed_attempts = 0
        self.login_attempts = 0
        self.locked_until = None
        self.lock_timer_id = None
        self.lockout_label = None
        self.login_frame = None  # Track current login frame

        # ---------------- Auto-Lock Timer ----------------
        self.auto_lock_timer_id = None
        self.auto_lock_time = 1

        # ---------------- File Paths ----------------
        self.users_file = "users.json"
        self.vault_file = "vault.json"
        self.settings_file = "settings.json"

        # ---------------- Credential Manager ----------------
        self.credential_manager = CredentialManager(
            root=self.root,
            current_user=None,
            update_callback=self.update_vault_data,
            encryption=self.encryption,
            dashboard_callback=self.show_dashboard
        )

        # ---------------- Create Sample Data ----------------
        self.initialize_sample_data()

        # ---------------- Start Login ----------------
        self.show_login()

        # ---------------- Run App ----------------
        self.root.mainloop()

    # ---------------- Sample Users & Vault ----------------
    def initialize_sample_data(self):
        """Create 3 users with sample credentials"""
        if not os.path.exists(self.users_file):
            users = {
                "john.doe": {
                    "name": "John Doe",
                    "password": bcrypt.hashpw("Password123!".encode(), bcrypt.gensalt()).decode(),
                    "email": "john.doe@gmail.com",
                    "created": "2024-01-15",
                    "has_recovery": False
                },
                "alice.smith": {
                    "name": "Alice Smith",
                    "password": bcrypt.hashpw("SecurePass456@".encode(), bcrypt.gensalt()).decode(),
                    "email": "alice.smith@protonmail.com",
                    "created": "2024-02-20",
                    "has_recovery": False
                },
                "bob.johnson": {
                    "name": "Bob Johnson",
                    "password": bcrypt.hashpw("VaultPass789#".encode(), bcrypt.gensalt()).decode(),
                    "email": "bob.j@outlook.com",
                    "created": "2024-03-10",
                    "has_recovery": False
                }
            }
            with open(self.users_file, "w") as f:
                json.dump(users, f, indent=4)

        # Create vault.json if not exists with passwords for ALL users
        if not os.path.exists(self.vault_file):
            sample_vault = {
                "john.doe": [
                    {
                        "service": self.encryption.encrypt("Facebook"),
                        "username": self.encryption.encrypt("john@example.com"),
                        "password": self.encryption.encrypt("MyPassword123!"),
                        "category": "Social Media",
                        "strength": "Strong"
                    },
                    {
                        "service": self.encryption.encrypt("Gmail"),
                        "username": self.encryption.encrypt("john.doe@gmail.com"),
                        "password": self.encryption.encrypt("SecurePass123"),
                        "category": "Email",
                        "strength": "Weak"
                    },
                    {
                        "service": self.encryption.encrypt("Google"),
                        "username": self.encryption.encrypt("john.doe@gmail.com"),
                        "password": self.encryption.encrypt("WeakPass1"),
                        "category": "Email",
                        "strength": "Weak"
                    },
                    {
                        "service": self.encryption.encrypt("Netflix"),
                        "username": self.encryption.encrypt("john@gmail.com"),
                        "password": self.encryption.encrypt("StrongPass$123"),
                        "category": "Entertainment",
                        "strength": "Strong"
                    }
                ],
                "alice.smith": [
                    {
                        "service": self.encryption.encrypt("Google"),
                        "username": self.encryption.encrypt("alice.smith@gmail.com"),
                        "password": self.encryption.encrypt("SecurePass456@"),
                        "category": "Email",
                        "strength": "Strong"
                    },
                    {
                        "service": self.encryption.encrypt("GitHub"),
                        "username": self.encryption.encrypt("alice.smith"),
                        "password": self.encryption.encrypt("GitHubPass789"),
                        "category": "Development",
                        "strength": "Strong"
                    },
                    {
                        "service": self.encryption.encrypt("Twitter"),
                        "username": self.encryption.encrypt("alice_smith"),
                        "password": self.encryption.encrypt("TwitterPass!123"),
                        "category": "Social Media",
                        "strength": "Medium"
                    }
                ],
                "bob.johnson": [
                    {
                        "service": self.encryption.encrypt("Microsoft"),
                        "username": self.encryption.encrypt("bob.j@outlook.com"),
                        "password": self.encryption.encrypt("VaultPass789#"),
                        "category": "Email",
                        "strength": "Strong"
                    },
                    {
                        "service": self.encryption.encrypt("Amazon"),
                        "username": self.encryption.encrypt("bob.johnson"),
                        "password": self.encryption.encrypt("AmazonPass123"),
                        "category": "Shopping",
                        "strength": "Weak"
                    },
                    {
                        "service": self.encryption.encrypt("LinkedIn"),
                        "username": self.encryption.encrypt("bob.johnson@pro.com"),
                        "password": self.encryption.encrypt("LinkedIn#2024"),
                        "category": "Professional",
                        "strength": "Strong"
                    }
                ]
            }
            with open(self.vault_file, "w") as f:
                json.dump(sample_vault, f, indent=4)
            
            # Add empty vault for any other existing users
            self.add_vault_for_existing_users()

    def add_vault_for_existing_users(self):
        """Add vault entries for all existing users"""
        if not os.path.exists(self.users_file) or not os.path.exists(self.vault_file):
            return
        
        try:
            with open(self.users_file, "r") as f:
                users = json.load(f)
            
            with open(self.vault_file, "r") as f:
                vault = json.load(f)
            
            updated = False
            for username in users:
                if username not in vault:
                    vault[username] = []
                    updated = True
            
            if updated:
                with open(self.vault_file, "w") as f:
                    json.dump(vault, f, indent=4)
        except:
            pass

    # ---------------- Login Screen ----------------
    def show_login(self):
        """Show login screen"""
        # Clear any existing timer
        if self.auto_lock_timer_id:
            self.root.after_cancel(self.auto_lock_timer_id)
            self.auto_lock_timer_id = None
        
        # Clear any existing lock timer
        if self.lock_timer_id:
            self.root.after_cancel(self.lock_timer_id)
            self.lock_timer_id = None
        
        # Clear lockout label reference
        self.lockout_label = None
        
        # Destroy all widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create new login screen
        self.login_frame, update_attempts, username_entry, password_entry = create_login_screen(
            self.root, 
            self.handle_login,
            self.show_registration
        )
        
        self.update_attempts_func = update_attempts
        self.username_entry = username_entry
        self.password_entry = password_entry
        self.login_frame.pack(expand=True, fill='both')
        
        # Start checking lock status
        self.check_lock_status()

    def show_registration(self):
        """Show registration screen"""
        # Clear lock timer
        if self.lock_timer_id:
            self.root.after_cancel(self.lock_timer_id)
            self.lock_timer_id = None
        
        # Clear lockout label
        self.lockout_label = None
        
        # Destroy all widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Create registration screen
        registration_frame = create_registration_screen(
            self.root,
            self.handle_registration,
            self.show_login
        )
        registration_frame.pack(expand=True, fill='both')

    def handle_registration(self, name, email, username, password):
        """Handle new user registration"""
        # Load existing users
        users = {}
        if os.path.exists(self.users_file):
            with open(self.users_file, "r") as f:
                users = json.load(f)
        
        # Check if username already exists
        if username in users:
            messagebox.showerror("Error", "Username already exists! Please choose a different username.")
            return
        
        # Check if email already exists
        for existing_user in users.values():
            if existing_user.get('email') == email:
                messagebox.showerror("Error", "Email already registered! Please use a different email.")
                return
        
        # Create new user
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        users[username] = {
            "name": name,
            "password": hashed_password,
            "email": email,
            "created": time.strftime("%Y-%m-%d"),
            "has_recovery": False
        }
        
        # Save users
        with open(self.users_file, "w") as f:
            json.dump(users, f, indent=4)
        
        # Initialize empty vault for new user
        vault = {}
        if os.path.exists(self.vault_file):
            with open(self.vault_file, "r") as f:
                vault = json.load(f)
        
        vault[username] = []
        
        with open(self.vault_file, "w") as f:
            json.dump(vault, f, indent=4)
        
        # Initialize default settings for new user
        settings = {}
        if os.path.exists(self.settings_file):
            with open(self.settings_file, "r") as f:
                settings = json.load(f)
        
        settings[username] = {
            "auto_lock_time": 1,
            "lock_after_failed_attempts": True,
            "max_failed_attempts": 5,
            "lockout_duration": 5
        }
        
        with open(self.settings_file, "w") as f:
            json.dump(settings, f, indent=4)
        
        # Log registration event
        AuditLog.log_event(
            event_type="USER_REGISTERED",
            severity="INFO",
            description=f"New user account created: {name}",
            user=email
        )
        
        messagebox.showinfo("Success", 
                          f"Account created successfully!\n\n" +
                          f"Username: {username}\n" +
                          f"Email: {email}\n\n" +
                          "You can now login with your credentials.")
        
        self.show_login()

    def check_lock_status(self):
        """Check and display lock status with countdown"""
        try:
            # Check if we have a lockout time
            if self.locked_until:
                current_time = time.time()
                
                # Check if still locked
                if current_time < self.locked_until:
                    remaining = int(self.locked_until - current_time)
                    minutes = remaining // 60
                    seconds = remaining % 60
                    
                    # Update attempts display
                    if hasattr(self, 'update_attempts_func'):
                        self.update_attempts_func(5)
                    
                    # Find the current login frame
                    current_frame = None
                    for widget in self.root.winfo_children():
                        if isinstance(widget, tk.Frame):
                            current_frame = widget
                            break
                    
                    # Create or update lockout label
                    if current_frame:
                        # Check if lockout_label exists and is valid
                        if self.lockout_label is None or not hasattr(self.lockout_label, 'winfo_exists') or not self.lockout_label.winfo_exists():
                            # Create new label
                            self.lockout_label = tk.Label(
                                current_frame,
                                text=f"⏱ Account locked for: {minutes:02d}:{seconds:02d}",
                                font=('Segoe UI', 14, 'bold'),
                                fg='#D93025',
                                bg='#F4F6F8'
                            )
                            self.lockout_label.place(relx=0.5, rely=0.7, anchor='center')
                        else:
                            # Update existing label
                            self.lockout_label.config(text=f"⏱ Account locked for: {minutes:02d}:{seconds:02d}")
                        
                        # Schedule next update
                        self.lock_timer_id = self.root.after(1000, self.check_lock_status)
                        return True
                    else:
                        # No frame found, schedule check later
                        self.lock_timer_id = self.root.after(1000, self.check_lock_status)
                        return True
                else:
                    # Lock has expired
                    self.locked_until = None
                    self.login_attempts = 0
                    self.failed_attempts = 0
                    
                    # Update attempts display
                    if hasattr(self, 'update_attempts_func'):
                        self.update_attempts_func(0)
                    
                    # Remove lockout label if it exists
                    if self.lockout_label and hasattr(self.lockout_label, 'winfo_exists') and self.lockout_label.winfo_exists():
                        self.lockout_label.destroy()
                    
                    self.lockout_label = None
                    
                    # Clear timer
                    if self.lock_timer_id:
                        self.root.after_cancel(self.lock_timer_id)
                        self.lock_timer_id = None
            
            # Remove lockout label if no lock and it exists
            elif self.lockout_label and hasattr(self.lockout_label, 'winfo_exists') and self.lockout_label.winfo_exists():
                self.lockout_label.destroy()
                self.lockout_label = None
            
            return False
            
        except Exception as e:
            # If there's an error, schedule a retry
            print(f"Error in check_lock_status: {e}")
            self.lock_timer_id = self.root.after(1000, self.check_lock_status)
            return True

    def get_lockout_duration(self, username):
        """Get lockout duration from settings"""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r") as f:
                    settings = json.load(f)
                    if username in settings:
                        return settings[username].get("lockout_duration", 5) * 60
            except:
                pass
        return 300

    def handle_login(self, username, password):
        """Handle login attempt WITH AUDIT LOGGING"""
        # Check if account is locked
        if self.check_lock_status():
            messagebox.showerror("Account Locked", 
                               "Too many failed attempts! Please wait for the timer to expire.")
            return
        
        # Load users
        if not os.path.exists(self.users_file):
            messagebox.showerror("Error", "No users found!")
            return
        
        with open(self.users_file, "r") as f:
            users = json.load(f)

        if username in users:
            user_data = users[username]
            user_email = user_data["email"]
            
            if bcrypt.checkpw(password.encode(), user_data["password"].encode()):
                # Successful login
                self.current_user = username
                self.user_data = user_data
                self.failed_attempts = 0
                self.login_attempts = 0

                AuditLog.log_login_success(user_email, "Windows PC")
                self.load_auto_lock_setting()
                self.credential_manager.current_user = self.current_user
                self.show_dashboard()
                return
            else:
                # Failed login
                self.failed_attempts += 1
                self.login_attempts += 1
                AuditLog.log_login_failed(user_email, "Invalid Password", "Windows PC")
                
                # Check if should lock account
                if self.login_attempts >= 5:
                    lockout_duration = self.get_lockout_duration(username)
                    self.locked_until = time.time() + lockout_duration
                    
                    if hasattr(self, 'update_attempts_func'):
                        self.update_attempts_func(5)
                    
                    minutes = lockout_duration // 60
                    messagebox.showerror("Account Locked", 
                                       f"Too many failed attempts! Account locked for {minutes} minutes.")
                    
                    # Start lock timer
                    self.check_lock_status()
                    return
                
                # Log multiple failed attempts
                if self.login_attempts >= 3:
                    AuditLog.log_multiple_failed_attempts(
                        user_email, 
                        self.login_attempts, 
                        "203.45.67.89"
                    )
        else:
            # Invalid username
            self.failed_attempts += 1
            self.login_attempts += 1
            fake_email = username if '@' in username else f"{username}@unknown.com"
            AuditLog.log_login_failed(fake_email, "Invalid Username", "Windows PC")
            
            if self.login_attempts >= 5:
                lockout_duration = 300
                self.locked_until = time.time() + lockout_duration
                
                if hasattr(self, 'update_attempts_func'):
                    self.update_attempts_func(5)
                
                messagebox.showerror("Account Locked", 
                                   "Too many failed attempts! Account locked for 5 minutes.")
                self.check_lock_status()
                return

        # Update attempts display
        if hasattr(self, 'update_attempts_func'):
            self.update_attempts_func(self.failed_attempts)
        
        messagebox.showerror("Login Failed", "Invalid username or password!")

    def load_auto_lock_setting(self):
        """Load auto-lock time from settings"""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, "r") as f:
                    settings = json.load(f)
                    if self.current_user in settings:
                        self.auto_lock_time = settings[self.current_user].get("auto_lock_time", 1)
            except:
                self.auto_lock_time = 1
        else:
            self.auto_lock_time = 1

    def reset_auto_lock_timer(self):
        """Reset the auto-lock timer"""
        if self.auto_lock_timer_id:
            self.root.after_cancel(self.auto_lock_timer_id)
        
        timeout_ms = self.auto_lock_time * 60 * 1000
        self.auto_lock_timer_id = self.root.after(timeout_ms, self.auto_lock_triggered)

    def auto_lock_triggered(self):
        """Called when auto-lock timer expires"""
        if self.current_user:
            user_email = self.current_user
            if os.path.exists("users.json"):
                with open("users.json", "r") as f:
                    users = json.load(f)
                    if self.current_user in users:
                        user_email = users[self.current_user]['email']
            
            AuditLog.log_event(
                event_type="AUTO_LOCK",
                severity="INFO",
                description=f"Vault auto-locked after {self.auto_lock_time} minute(s) of inactivity",
                user=user_email
            )
            
            messagebox.showinfo("Auto-Lock", 
                              f"Vault locked due to {self.auto_lock_time} minute(s) of inactivity.")
            self.handle_logout()

    def bind_activity_events(self):
        """Bind events to detect user activity"""
        def on_activity(event=None):
            self.reset_auto_lock_timer()
        
        self.root.bind_all('<Motion>', on_activity)
        self.root.bind_all('<Button>', on_activity)
        self.root.bind_all('<Key>', on_activity)

    # ---------------- Dashboard ----------------
    def show_dashboard(self):
        """Show dashboard with FIXED decryption"""
        # Load vault data
        if not os.path.exists(self.vault_file):
            messagebox.showerror("Error", "Vault file not found!")
            self.show_login()
            return
        
        with open(self.vault_file, "r") as f:
            vault_data = json.load(f)

        # Decrypt credentials with error handling
        credentials = []
        if self.current_user in vault_data:
            for cred in vault_data[self.current_user]:
                try:
                    # Try to decrypt
                    decrypted = {
                        'service': self.encryption.decrypt(cred['service']),
                        'username': self.encryption.decrypt(cred['username']),
                        'password': self.encryption.decrypt(cred['password']),
                        'category': cred.get('category', 'General'),
                        'strength': cred.get('strength', 'Weak')
                    }
                    credentials.append(decrypted)
                except Exception as e:
                    # If decryption fails, use placeholder
                    print(f"Note: Could not decrypt some credentials for {self.current_user}")
                    # Add placeholder instead of crashing
                    credentials.append({
                        'service': '[Encryption Error]',
                        'username': '[Please re-add this credential]',
                        'password': '********',
                        'category': cred.get('category', 'General'),
                        'strength': 'Weak'
                    })

        # Get user email for audit logging
        users_file = "users.json"
        user_email = self.current_user
        if os.path.exists(users_file):
            with open(users_file, "r") as f:
                users = json.load(f)
                if self.current_user in users:
                    user_email = users[self.current_user]['email']

        # Check for weak passwords
        AuditLog.check_weak_passwords(credentials, user_email)

        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Create dashboard
        self.dashboard = Dashboard(
            self.root,
            self.current_user,
            self.user_data,
            credentials,
            self.handle_logout,
            self.update_vault_data,
            self.open_credentials_manager
        )

        # Set up activity monitoring
        self.bind_activity_events()
        self.reset_auto_lock_timer()

    def update_vault_data(self, updated_credentials):
        """Save updated credentials to vault"""
        encrypted_creds = []
        for cred in updated_credentials:
            # Skip placeholder entries
            if cred['service'] == '[Encryption Error]':
                continue
                
            encrypted_creds.append({
                'service': self.encryption.encrypt(cred['service']),
                'username': self.encryption.encrypt(cred['username']),
                'password': self.encryption.encrypt(cred['password']),
                'category': cred.get('category', 'General'),
                'strength': cred['strength']
            })

        # Load existing vault
        vault = {}
        if os.path.exists(self.vault_file):
            with open(self.vault_file, "r") as f:
                vault = json.load(f)

        # Update user's credentials
        vault[self.current_user] = encrypted_creds

        # Save vault
        with open(self.vault_file, "w") as f:
            json.dump(vault, f, indent=4)
        
        # Check for weak passwords
        users_file = "users.json"
        user_email = self.current_user
        if os.path.exists(users_file):
            with open(users_file, "r") as f:
                users = json.load(f)
                if self.current_user in users:
                    user_email = users[self.current_user]['email']
        
        AuditLog.check_weak_passwords(updated_credentials, user_email)

    def handle_logout(self):
        """Handle logout"""
        # Get user email for logging
        user_email = self.current_user
        if os.path.exists("users.json"):
            with open("users.json", "r") as f:
                users = json.load(f)
                if self.current_user in users:
                    user_email = users[self.current_user]['email']
        
        # Log logout event
        AuditLog.log_event(
            event_type="LOGOUT",
            severity="INFO",
            description="User logged out successfully",
            user=user_email
        )
        
        # Clear timers
        if self.lock_timer_id:
            self.root.after_cancel(self.lock_timer_id)
            self.lock_timer_id = None
        
        if self.auto_lock_timer_id:
            self.root.after_cancel(self.auto_lock_timer_id)
            self.auto_lock_timer_id = None
        
        # Unbind activity events
        self.root.unbind_all('<Motion>')
        self.root.unbind_all('<Button>')
        self.root.unbind_all('<Key>')
        
        # Reset session data
        self.current_user = None
        self.user_data = None
        self.failed_attempts = 0
        self.login_attempts = 0
        self.locked_until = None
        self.lockout_label = None
        
        # Show login screen
        self.show_login()

    # ---------------- Open Credential Manager ----------------
    def open_credentials_manager(self):
        """Open credential management screen - FIXED DECRYPTION"""
        self.credential_manager.current_user = self.current_user

        # Load user's credentials with error handling
        self.credential_manager.data["users"][self.current_user] = {"credentials": []}
        if os.path.exists(self.vault_file):
            with open(self.vault_file, "r") as f:
                vault_data = json.load(f)
                for cred in vault_data.get(self.current_user, []):
                    try:
                        # Try to decrypt
                        decrypted_cred = {
                            "service": self.encryption.decrypt(cred['service']),
                            "username": self.encryption.decrypt(cred['username']),
                            "password": self.encryption.decrypt(cred['password']),
                            "strength": cred.get('strength', 'Weak')
                        }
                        self.credential_manager.data["users"][self.current_user]["credentials"].append(decrypted_cred)
                    except:
                        # If decryption fails, skip this credential
                        print(f"Note: Skipping one credential for {self.current_user} (encryption mismatch)")

        self.credential_manager.show_credentials()


print(">>> MAIN.PY EXECUTED <<<")
print(">>> STARTING SECURE VAULT APPLICATION <<<")
print(">>> WITH USER REGISTRATION ENABLED <<<")

if __name__ == "__main__":
    app = SecureVaultApp()
