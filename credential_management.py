# credential_management.py - FIXED DATA PERSISTENCE
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import string
import os
import json
from audit_log import AuditLog

class CredentialManager:
    def __init__(self, root, current_user, update_callback, encryption, dashboard_callback):
        self.root = root
        self.current_user = current_user
        self.update_callback = update_callback
        self.encryption = encryption
        self.dashboard_callback = dashboard_callback

        # FIXED: Load existing credentials from vault
        self.data = {"users": {}}
        self.load_credentials()

    # NEW METHOD: Load credentials from vault
    def load_credentials(self):
        """Load existing credentials from vault.json"""
        vault_file = "vault.json"
        if os.path.exists(vault_file):
            with open(vault_file, "r") as f:
                vault_data = json.load(f)
            
            # Decrypt credentials for current user
            if self.current_user in vault_data:
                credentials = []
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
                
                self.data["users"][self.current_user] = {"credentials": credentials}

    # ---------------- Show Credentials ----------------
    def show_credentials(self):
        # Reload credentials to ensure we have latest data
        self.load_credentials()
        
        self.clear_window()

        # Back button
        tk.Button(
            self.root,
            text="← Back to Dashboard",
            font=("Arial", 12, "bold"),
            bg="#2563eb",
            fg="white",
            bd=0,
            padx=15,
            pady=8,
            cursor="hand2",
            command=self.go_back
        ).pack(anchor="nw", padx=20, pady=10)

        # HEADER WITH RECTANGULAR BOX
        header_container = tk.Frame(self.root, bg="#f0f2f5", padx=30, pady=20)
        header_container.pack(fill="x")
        
        # Create rectangular box around header content
        header_box = tk.Frame(header_container, bg="#ffffff", relief='solid', bd=2, highlightthickness=0)
        header_box.pack(fill="x")
        
        # Inner padding frame
        header = tk.Frame(header_box, bg="#ffffff", padx=25, pady=20)
        header.pack(fill="x")

        # Title and description
        title_frame = tk.Frame(header, bg="#ffffff")
        title_frame.pack(side="left", fill="x", expand=True)
        
        tk.Label(
            title_frame,
            text="Credential Management",
            font=("Arial", 24, "bold"),
            bg="#ffffff",
            fg="#1e293b",
            anchor="w"
        ).pack(anchor="w")

        tk.Label(
            title_frame,
            text="Add, update, or delete your stored credentials",
            font=("Arial", 12),
            bg="#ffffff",
            fg="#64748b",
            anchor="w"
        ).pack(anchor="w", pady=(5, 0))

        # Add Credential Button
        tk.Button(
            header,
            text="➕ Add Credential",
            bg="#2563eb",
            fg="white",
            font=("Arial", 11, "bold"),
            cursor="hand2",
            bd=0,
            padx=20,
            pady=8,
            command=self.add_credential_dialog
        ).pack(side="right", padx=10)

        # Container for credentials list
        container = tk.Frame(self.root, bg="#f0f2f5")
        container.pack(fill="both", expand=True, padx=10, pady=10)

        canvas = tk.Canvas(container, bg="#f0f2f5", highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        self.scrollable_frame = tk.Frame(canvas, bg="#f0f2f5")
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Load credentials for current user
        if self.current_user in self.data["users"]:
            credentials = self.data["users"][self.current_user]["credentials"]
            if credentials:
                for cred in credentials:
                    self.create_credential_card(cred)
            else:
                # Display message if no credentials
                tk.Label(
                    self.scrollable_frame,
                    text="No credentials found. Click 'Add Credential' to create your first entry.",
                    font=("Arial", 12),
                    bg="#f0f2f5",
                    fg="#64748b",
                    pady=50
                ).pack()
        else:
            # Display message if no credentials
            tk.Label(
                self.scrollable_frame,
                text="No credentials found. Click 'Add Credential' to create your first entry.",
                font=("Arial", 12),
                bg="#f0f2f5",
                fg="#64748b",
                pady=50
            ).pack()

    # ---------------- Credential Card (FULLY EXTENDED TO RIGHT) ----------------
    def create_credential_card(self, credential):
        # MAXIMUM WIDTH CARD - EXTENDED FULLY TO RIGHT
        card = tk.Frame(self.scrollable_frame, bg="white", padx=50, pady=22, relief='solid', bd=1)
        card.pack(fill='both', expand=True, pady=10, padx=3)

        # Icon
        tk.Label(card, text="🔑", font=("Arial", 28), bg="white", fg="#a855f7").pack(side="left", padx=30)

        # Service and Username Info
        info = tk.Frame(card, bg="white")
        info.pack(side="left", expand=True, fill="both", padx=20)

        tk.Label(info, text=credential["service"], font=("Arial", 15, "bold"),
                 bg="white", fg="#1e293b", anchor='w').pack(fill='x')
        tk.Label(info, text=credential["username"], font=("Arial", 12),
                 bg="white", fg="#64748b", anchor='w').pack(fill='x', pady=(3, 0))

        # Strength badge (Strong or Weak only)
        strength = credential.get("strength", "Weak")
        strength_color = "#10b981" if strength == "Strong" else "#ef4444"
        strength_icon = "✅" if strength == "Strong" else "⚠️"
        
        strength_frame = tk.Frame(card, bg=strength_color, padx=18, pady=7)
        strength_frame.pack(side="right", padx=25)
        
        tk.Label(strength_frame, text=f"{strength_icon} {strength}", 
                font=("Arial", 11, "bold"), fg="white", bg=strength_color).pack()

        # Action buttons
        tk.Button(card, text="👁 View", bd=0, font=("Arial", 11, "bold"),
                  bg="#dbeafe", fg="#2563eb", padx=14, pady=7,
                  command=lambda c=credential: self.view_credential(c)).pack(side="right", padx=8)

        tk.Button(card, text="✏️ Edit", bg="#fef3c7", fg="#d97706", bd=0,
                  font=("Arial", 11, "bold"), padx=14, pady=7,
                  command=lambda c=credential: self.edit_credential(c)).pack(side="right", padx=8)

        tk.Button(card, text="🗑️ Delete", bg="#fee2e2", fg="#dc2626", bd=0,
                  font=("Arial", 11, "bold"), padx=14, pady=7,
                  command=lambda c=credential: self.delete_credential(c)).pack(side="right", padx=8)

    # ---------------- Add ----------------
    def add_credential_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Credential")
        dialog.geometry("550x520")
        dialog.grab_set()
        dialog.configure(bg="#f8fafc")

        tk.Label(dialog, text="Add New Credential", font=("Arial", 18, "bold"),
                bg="#f8fafc", fg="#1e293b").pack(pady=20)

        entries = {}
        fields = ["Service", "Username", "Password"]
        
        for i, label in enumerate(fields):
            frame = tk.Frame(dialog, bg="#f8fafc")
            frame.pack(fill="x", padx=40, pady=10)
            
            tk.Label(frame, text=label, font=("Arial", 12, "bold"),
                    bg="#f8fafc", fg="#475569").pack(anchor="w", pady=(0, 8))
            
            e = tk.Entry(frame, font=("Arial", 12), width=40,
                        bg="white", fg="#1e293b", relief="solid", bd=1)
            if label == "Password":
                e.config(show="•")
            e.pack(fill="x")
            entries[label] = e

        # Password strength indicator
        strength_frame = tk.Frame(dialog, bg="#f8fafc", padx=40, pady=10)
        strength_frame.pack(fill="x")
        
        self.strength_label = tk.Label(strength_frame, text="Strength: Not evaluated", 
                                      font=("Arial", 11), bg="#f8fafc", fg="#6b7280")
        self.strength_label.pack(anchor="w")
        
        # Update strength on password change
        def update_strength(event=None):
            password = entries["Password"].get()
            if password:
                strength = self.calculate_password_strength(password)
                color = "#10b981" if strength == "Strong" else "#ef4444"
                self.strength_label.config(
                    text=f"Strength: {strength}",
                    fg=color,
                    font=("Arial", 11, "bold")
                )
            else:
                self.strength_label.config(
                    text="Strength: Not evaluated",
                    fg="#6b7280"
                )
        
        entries["Password"].bind("<KeyRelease>", update_strength)

        def save():
            service_name = entries["Service"].get()
            username = entries["Username"].get()
            pwd = entries["Password"].get()
            
            if not service_name or not username or not pwd:
                messagebox.showerror("Error", "All fields are required!")
                return
            
            cred = {
                "service": service_name,
                "username": username,
                "password": pwd,
                "strength": self.calculate_password_strength(pwd),
                "category": "General",
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            self.data["users"].setdefault(self.current_user, {"credentials": []})
            self.data["users"][self.current_user]["credentials"].append(cred)

            # Get user email for audit log
            users_file = "users.json"
            user_email = self.current_user
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    users = json.load(f)
                    if self.current_user in users:
                        user_email = users[self.current_user]['email']
            
            # LOG PASSWORD ADDED
            AuditLog.log_password_operation("added", service_name, "Created new password entry", user_email)

            # Update vault with encrypted data
            self.update_callback(self.data["users"][self.current_user]["credentials"])
            dialog.destroy()
            self.show_credentials()
            
            messagebox.showinfo("Success", f"Credential for {service_name} added successfully!")

        button_frame = tk.Frame(dialog, bg="#f8fafc")
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Cancel", bg="#e2e8f0", fg="#475569",
                 font=("Arial", 11), padx=25, pady=8,
                 command=dialog.destroy).pack(side="left", padx=10)
        
        tk.Button(button_frame, text="Save Credential", bg="#2563eb", fg="white",
                 font=("Arial", 11, "bold"), padx=25, pady=8,
                 command=save).pack(side="left", padx=10)

    # ---------------- View ----------------
    def view_credential(self, credential):
        # Get user email for audit log
        users_file = "users.json"
        user_email = self.current_user
        if os.path.exists(users_file):
            with open(users_file, "r") as f:
                users = json.load(f)
                if self.current_user in users:
                    user_email = users[self.current_user]['email']
        
        # LOG PASSWORD VIEWED
        AuditLog.log_password_operation("viewed", credential['service'], "Password revealed and copied", user_email)
        
        # Create custom dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("View Credential")
        dialog.geometry("600x450")
        dialog.grab_set()
        dialog.configure(bg="#f8fafc")
        
        tk.Label(dialog, text="🔐 Credential Details", font=("Arial", 20, "bold"),
                bg="#f8fafc", fg="#1e293b").pack(pady=25)
        
        details = tk.Frame(dialog, bg="white", padx=35, pady=25)
        details.pack(fill="both", expand=True, padx=35, pady=15)
        
        # Service
        service_frame = tk.Frame(details, bg="white")
        service_frame.pack(fill="x", pady=18)
        tk.Label(service_frame, text="Service:", font=("Arial", 13, "bold"),
                bg="white", fg="#475569", width=14, anchor="w").pack(side="left")
        tk.Label(service_frame, text=credential['service'], font=("Arial", 13),
                bg="white", fg="#1e293b").pack(side="left", padx=10)
        
        # Username
        user_frame = tk.Frame(details, bg="white")
        user_frame.pack(fill="x", pady=18)
        tk.Label(user_frame, text="Username:", font=("Arial", 13, "bold"),
                bg="white", fg="#475569", width=14, anchor="w").pack(side="left")
        tk.Label(user_frame, text=credential['username'], font=("Arial", 13),
                bg="white", fg="#1e293b").pack(side="left", padx=10)
        
        # Password
        pass_frame = tk.Frame(details, bg="white")
        pass_frame.pack(fill="x", pady=18)
        tk.Label(pass_frame, text="Password:", font=("Arial", 13, "bold"),
                bg="white", fg="#475569", width=14, anchor="w").pack(side="left")
        
        password_var = tk.StringVar(value="•" * 12)
        pass_label = tk.Label(pass_frame, textvariable=password_var, 
                             font=("Arial", 13, "bold"), bg="white", fg="#64748b")
        pass_label.pack(side="left", padx=10)
        
        def show_password():
            password_var.set(credential['password'])
            show_btn.config(text="👁 Hide", command=hide_password)
        
        def hide_password():
            password_var.set("•" * 12)
            show_btn.config(text="👁 Show", command=show_password)
        
        show_btn = tk.Button(pass_frame, text="👁 Show", font=("Arial", 11, "bold"),
                           bg="#dbeafe", fg="#2563eb", bd=0, padx=15, pady=5,
                           command=show_password)
        show_btn.pack(side="left", padx=15)
        
        # Strength
        strength_frame = tk.Frame(details, bg="white")
        strength_frame.pack(fill="x", pady=18)
        tk.Label(strength_frame, text="Strength:", font=("Arial", 13, "bold"),
                bg="white", fg="#475569", width=14, anchor="w").pack(side="left")
        
        strength = credential['strength']
        strength_color = "#10b981" if strength == "Strong" else "#ef4444"
        tk.Label(strength_frame, text=strength, font=("Arial", 13, "bold"),
                fg="white", bg=strength_color, padx=15, pady=4).pack(side="left", padx=10)
        
        # Close button
        tk.Button(dialog, text="Close", bg="#2563eb", fg="white",
                 font=("Arial", 13, "bold"), padx=50, pady=12,
                 command=dialog.destroy).pack(pady=25)

    # ---------------- Edit ----------------
    def edit_credential(self, credential):
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Credential")
        dialog.geometry("550x520")
        dialog.grab_set()
        dialog.configure(bg="#f8fafc")

        tk.Label(dialog, text="Edit Credential", font=("Arial", 18, "bold"),
                bg="#f8fafc", fg="#1e293b").pack(pady=20)

        fields = {}
        field_names = ["service", "username", "password"]
        
        for i, key in enumerate(field_names):
            frame = tk.Frame(dialog, bg="#f8fafc")
            frame.pack(fill="x", padx=40, pady=10)
            
            label = key.capitalize()
            tk.Label(frame, text=label, font=("Arial", 12, "bold"),
                    bg="#f8fafc", fg="#475569").pack(anchor="w", pady=(0, 8))
            
            e = tk.Entry(frame, font=("Arial", 12), width=40,
                        bg="white", fg="#1e293b", relief="solid", bd=1)
            e.insert(0, credential[key])
            if key == "password":
                e.config(show="•")
            e.pack(fill="x")
            fields[key] = e

        # Password strength indicator
        strength_frame = tk.Frame(dialog, bg="#f8fafc", padx=40, pady=10)
        strength_frame.pack(fill="x")
        
        self.edit_strength_label = tk.Label(strength_frame, 
                                           text=f"Current Strength: {credential['strength']}", 
                                           font=("Arial", 11), bg="#f8fafc", fg="#6b7280")
        self.edit_strength_label.pack(anchor="w")
        
        def update_strength(event=None):
            password = fields["password"].get()
            if password:
                strength = self.calculate_password_strength(password)
                color = "#10b981" if strength == "Strong" else "#ef4444"
                self.edit_strength_label.config(
                    text=f"Strength: {strength}",
                    fg=color,
                    font=("Arial", 11, "bold")
                )
        
        fields["password"].bind("<KeyRelease>", update_strength)

        def save():
            for k in fields:
                credential[k] = fields[k].get()
            credential["strength"] = self.calculate_password_strength(credential["password"])

            # Get user email for audit log
            users_file = "users.json"
            user_email = self.current_user
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    users = json.load(f)
                    if self.current_user in users:
                        user_email = users[self.current_user]['email']
            
            # LOG PASSWORD EDITED
            AuditLog.log_password_operation("edited", credential['service'], "Password updated and modified", user_email)

            # Update vault with encrypted data
            self.update_callback(self.data["users"][self.current_user]["credentials"])
            dialog.destroy()
            self.show_credentials()
            
            messagebox.showinfo("Success", f"Credential for {credential['service']} updated successfully!")

        button_frame = tk.Frame(dialog, bg="#f8fafc")
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="Cancel", bg="#e2e8f0", fg="#475569",
                 font=("Arial", 11), padx=25, pady=8,
                 command=dialog.destroy).pack(side="left", padx=10)
        
        tk.Button(button_frame, text="Save Changes", bg="#2563eb", fg="white",
                 font=("Arial", 11, "bold"), padx=25, pady=8,
                 command=save).pack(side="left", padx=10)

    # ---------------- Delete ----------------
    def delete_credential(self, credential):
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete the credential for {credential['service']}?\n\nThis action cannot be undone!"
        )
        
        if not confirm:
            return
        
        # Get user email for audit log
        users_file = "users.json"
        user_email = self.current_user
        if os.path.exists(users_file):
            with open(users_file, "r") as f:
                users = json.load(f)
                if self.current_user in users:
                    user_email = users[self.current_user]['email']
        
        # LOG PASSWORD DELETED
        AuditLog.log_password_operation("deleted", credential['service'], "Permanently removed from vault", user_email)
        
        self.data["users"][self.current_user]["credentials"].remove(credential)
        
        # Update vault with encrypted data
        self.update_callback(self.data["users"][self.current_user]["credentials"])
        self.show_credentials()
        
        messagebox.showinfo("Deleted", f"Credential for {credential['service']} has been deleted.")

    # ---------------- Utils ----------------
    def calculate_password_strength(self, password):
        """Calculate password strength: Strong or Weak only (no Medium)"""
        if len(password) < 8:
            return "Weak"
        
        score = 0
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
        if len(password) >= 12:
            score += 1
        
        # Strong if score >= 4, otherwise Weak
        return "Strong" if score >= 4 else "Weak"

    def strength_color(self, strength):
        colors = {
            "Strong": "#10b981",
            "Weak": "#ef4444"
        }
        return colors.get(strength, "#6b7280")

    def clear_window(self):
        for w in self.root.winfo_children():
            w.destroy()

    def go_back(self):
        if self.current_user in self.data["users"]:
            self.update_callback(self.data["users"][self.current_user]["credentials"])
        self.dashboard_callback()
