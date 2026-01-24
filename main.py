#!/usr/bin/env python3
"""
SECURE PASSWORD MANAGER - SINGLE PASSWORD SYSTEM
Run this file to start the application
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
        self.login_frame = None

        # ---------------- Auto-Lock Timer ----------------
        self.auto_lock_timer_id = None
        self.auto_lock_time = 1

        # ---------------- File Paths ----------------
        self.users_file = "users.json"
        self.vault_file = "vault.json"
        self.settings_file = "settings.json"

        # ---------------- Initialize Files ----------------
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
                    "created": "2024-01-15"
                },
                "alice.smith": {
                    "name": "Alice Smith",
                    "password": bcrypt.hashpw("SecurePass456@".encode(), bcrypt.gensalt()).decode(),
                    "email": "alice.smith@protonmail.com",
                    "created": "2024-02-20"
                },
                "bob.johnson": {
                    "name": "Bob Johnson",
                    "password": bcrypt.hashpw("VaultPass789#".encode(), bcrypt.gensalt()).decode(),
                    "email": "bob.j@outlook.com",
                    "created": "2024-03-10"
                }
            }
            with open(self.users_file, "w") as f:
                json.dump(users, f, indent=4)

        # Create vault.json if not exists
        if not os.path.exists(self.vault_file):
            # Load existing users to create vault entries for them
            users = {}
            if os.path.exists(self.users_file):
                with open(self.users_file, "r") as f:
                    users = json.load(f)
            
            # Create empty vault for all users
            vault = {}
            for username in users.keys():
                vault[username] = []
            
            with open(self.vault_file, "w") as f:
                json.dump(vault, f, indent=4)

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
            "created": time.strftime("%Y-%m-%d")
        }
        
        # Save users
        with open(self.users_file, "w") as f:
            json.dump(users, f, indent=4)
        
        # Setup encryption for new user (SAME password!)
        temp_encryption = EncryptionManager()
        temp_encryption.setup_for_user(username, password)
        
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
                          "Remember: Your login password also encrypts your vault!")
        
        self.show_login()

    def check_lock_status(self):
        """Check and display lock status with countdown"""
        try:
            if self.locked_until:
                current_time = time.time()
                
                if current_time < self.locked_until:
                    remaining = int(self.locked_until - current_time)
                    minutes = remaining // 60
                    seconds = remaining % 60
                    
                    if hasattr(self, 'update_attempts_func'):
                        self.update_attempts_func(5)
                    
                    current_frame = None
                    for widget in self.root.winfo_children():
                        if isinstance(widget, tk.Frame):
                            current_frame = widget
                            break
                    
                    if current_frame:
                        if self.lockout_label is None or not hasattr(self.lockout_label, 'winfo_exists') or not self.lockout_label.winfo_exists():
                            self.lockout_label = tk.Label(
                                current_frame,
                                text=f"⏱ Account locked for: {minutes:02d}:{seconds:02d}",
                                font=('Segoe UI', 14, 'bold'),
                                fg='#D93025',
                                bg='#F4F6F8'
                            )
                            self.lockout_label.place(relx=0.5, rely=0.7, anchor='center')
                        else:
                            self.lockout_label.config(text=f"⏱ Account locked for: {minutes:02d}:{seconds:02d}")
                        
                        self.lock_timer_id = self.root.after(1000, self.check_lock_status)
                        return True
                    else:
                        self.lock_timer_id = self.root.after(1000, self.check_lock_status)
                        return True
                else:
                    self.locked_until = None
                    self.login_attempts = 0
                    self.failed_attempts = 0
                    
                    if hasattr(self, 'update_attempts_func'):
                        self.update_attempts_func(0)
                    
                    if self.lockout_label and hasattr(self.lockout_label, 'winfo_exists') and self.lockout_label.winfo_exists():
                        self.lockout_label.destroy()
                    
                    self.lockout_label = None
                    
                    if self.lock_timer_id:
                        self.root.after_cancel(self.lock_timer_id)
                        self.lock_timer_id = None
            
            elif self.lockout_label and hasattr(self.lockout_label, 'winfo_exists') and self.lockout_label.winfo_exists():
                self.lockout_label.destroy()
                self.lockout_label = None
            
            return False
            
        except Exception as e:
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
        """Handle login attempt - ONE PASSWORD DOES EVERYTHING"""
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
                # ✅ SUCCESSFUL LOGIN - USE SAME PASSWORD FOR ENCRYPTION!
                try:
                    self.encryption.setup_for_user(username, password)
                    
                    # Set session data
                    self.current_user = username
                    self.user_data = user_data
                    self.failed_attempts = 0
                    self.login_attempts = 0

                    # Log successful login
                    AuditLog.log_login_success(user_email, "Windows PC")
                    self.load_auto_lock_setting()
                    self.show_dashboard()
                    return
                    
                except Exception as e:
                    messagebox.showerror("Encryption Error", 
                                       f"Cannot setup encryption: {str(e)}")
                    return
            else:
                # Failed login
                self.failed_attempts += 1
                self.login_attempts += 1
                AuditLog.log_login_failed(user_email, "Invalid Password", "Windows PC")
                
                if self.login_attempts >= 5:
                    lockout_duration = self.get_lockout_duration(username)
                    self.locked_until = time.time() + lockout_duration
                    
                    if hasattr(self, 'update_attempts_func'):
                        self.update_attempts_func(5)
                    
                    minutes = lockout_duration // 60
                    messagebox.showerror("Account Locked", 
                                       f"Too many failed attempts! Account locked for {minutes} minutes.")
                    
                    self.check_lock_status()
                    return
                
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
        """Show dashboard"""
        # Load vault data
        if not os.path.exists(self.vault_file):
            messagebox.showerror("Error", "Vault file not found!")
            self.show_login()
            return
        
        with open(self.vault_file, "r") as f:
            vault_data = json.load(f)

        # Decrypt credentials using user's password (same as login!)
        credentials = []
        if self.current_user in vault_data:
            for cred in vault_data[self.current_user]:
                try:
                    decrypted = {
                        'service': self.encryption.decrypt(cred['service']),
                        'username': self.encryption.decrypt(cred['username']),
                        'password': self.encryption.decrypt(cred['password']),
                        'category': cred.get('category', 'General'),
                        'strength': cred.get('strength', 'Weak')
                    }
                    credentials.append(decrypted)
                except Exception as e:
                    print(f"Error decrypting credential: {e}")
                    messagebox.showerror("Decryption Error", 
                                       "Cannot decrypt your vault!")
                    self.handle_logout()
                    return

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

        # Create credential manager
        self.credential_manager = CredentialManager(
            root=self.root,
            current_user=self.current_user,
            update_callback=self.update_vault_data,
            encryption=self.encryption,
            dashboard_callback=self.show_dashboard
        )

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
        """Open credential management screen"""
        self.credential_manager.show_credentials()


print(">>> MAIN.PY EXECUTED <<<")
print(">>> STARTING SECURE VAULT APPLICATION <<<")
print(">>> SINGLE PASSWORD SYSTEM <<<")

if __name__ == "__main__":
    app = SecureVaultApp()
