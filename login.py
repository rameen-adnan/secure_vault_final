# login.py - LOGIN SCREEN WITH REGISTRATION AND FORGOT PASSWORD (FIXED)
import tkinter as tk
from tkinter import messagebox
import bcrypt
import json
import os
import re
from datetime import datetime

def create_login_screen(parent, on_login_callback, on_register_callback):
    """
    Creates login screen with registration and forgot password options
    Returns: (frame, update_attempts_func, username_entry, password_entry)
    """
    
    # Clear window first
    for widget in parent.winfo_children():
        widget.destroy()
    
    # ================= COLORS =================
    BG_MAIN        = "#F4F6F8"
    BG_CARD        = "#FFFFFF"
    TEXT_PRIMARY   = "#1F2937"
    TEXT_SECONDARY = "#6B7280"
    INPUT_BORDER   = "#CBD5E1"
    BTN_PRIMARY    = "#1A73E8"
    BTN_ACTIVE     = "#1558B0"
    BTN_REGISTER   = "#10b981"
    BTN_REGISTER_HOVER = "#059669"
    ERROR_RED      = "#D93025"
    LOCK_BLUE      = "#4DABF7"
    
    # ================= MAIN FRAME =================
    frame = tk.Frame(parent, bg=BG_MAIN)
    frame.pack(fill='both', expand=True)
    
    # ================= CENTER CARD =================
    center = tk.Frame(frame, bg=BG_CARD, padx=40, pady=25)
    center.place(relx=0.5, rely=0.5, anchor='center')
    
    # ================= LOCK ICON =================
    lock_frame = tk.Frame(center, bg=BG_CARD)
    lock_frame.pack(pady=(0, 10))
    
    lock_icon = tk.Label(
        lock_frame,
        text="🔒",
        font=('Segoe UI', 42),
        fg=LOCK_BLUE,
        bg=BG_CARD
    )
    lock_icon.pack()
    
    # ================= TITLE =================
    tk.Label(
        center,
        text="Secure Vault",
        font=('Segoe UI', 28, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).pack(pady=(0, 5))
    
    tk.Label(
        center,
        text="Password Manager",
        font=('Segoe UI', 13),
        fg=TEXT_SECONDARY,
        bg=BG_CARD
    ).pack(pady=(0, 25))
    
    # ================= FORM =================
    form = tk.Frame(center, bg=BG_CARD)
    form.pack()
    
    # Username
    tk.Label(
        form,
        text="Username / Email",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=0, column=0, sticky='w', pady=(0, 5))
    
    username_entry = tk.Entry(
        form,
        font=('Segoe UI', 11),
        width=38,
        bg="white",
        fg=TEXT_PRIMARY,
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    username_entry.grid(row=1, column=0, pady=(0, 18))
    username_entry.insert(0, "Enter your username")
    
    # Password
    tk.Label(
        form,
        text="Master Password",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=2, column=0, sticky='w', pady=(0, 5))
    
    password_frame = tk.Frame(form, bg=BG_CARD)
    password_frame.grid(row=3, column=0, pady=(0, 10), sticky='ew')
    
    password_entry = tk.Entry(
        password_frame,
        font=('Segoe UI', 11),
        width=32,
        bg="white",
        fg=TEXT_PRIMARY,
        show="•",
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    password_entry.pack(side='left')
    password_entry.insert(0, "Enter master password")
    
    # Show / Hide button
    def toggle_password_visibility():
        if password_entry.cget('show') == "•":
            password_entry.config(show="")
            eye_button.config(text="👁")
        else:
            password_entry.config(show="•")
            eye_button.config(text="👁🗨")
    
    eye_button = tk.Button(
        password_frame,
        text="👁🗨",
        font=('Segoe UI', 11),
        bg="#E5E7EB",
        fg=TEXT_PRIMARY,
        relief='flat',
        width=3,
        command=toggle_password_visibility
    )
    eye_button.pack(side='right', padx=(6, 0))
    
    # Failed attempts
    attempts_var = tk.StringVar(value="Failed attempts: 0/5")
    attempts_label = tk.Label(
        form,
        textvariable=attempts_var,
        font=('Segoe UI', 10),
        fg=ERROR_RED,
        bg=BG_CARD
    )
    attempts_label.grid(row=4, column=0, sticky='w', pady=(0, 20))
    
    # ================= LOGIN BUTTON =================
    def login_click():
        username = username_entry.get()
        password = password_entry.get()
        
        if username == "Enter your username":
            username = ""
        if password == "Enter master password":
            password = ""
        
        on_login_callback(username, password)
    
    login_btn = tk.Button(
        form,
        text="Login",
        font=('Segoe UI', 12, 'bold'),
        bg=BTN_PRIMARY,
        fg="white",
        activebackground=BTN_ACTIVE,
        relief='flat',
        width=16,
        command=login_click
    )
    login_btn.grid(row=5, column=0, pady=10)
    
    # ================= REGISTER BUTTON =================
    register_btn = tk.Button(
        form,
        text="Create New Account",
        font=('Segoe UI', 11, 'bold'),
        bg=BTN_REGISTER,
        fg="white",
        activebackground=BTN_REGISTER_HOVER,
        relief='flat',
        width=16,
        command=on_register_callback
    )
    register_btn.grid(row=6, column=0, pady=(5, 10))
    
    # ================= FORGOT PASSWORD LINK =================
    def show_forgot_password():
        create_forgot_password_screen(parent, on_login_callback, on_register_callback)
    
    forgot_link = tk.Label(
        form,
        text="Forgot Password?",
        font=('Segoe UI', 10, 'underline'),
        fg=BTN_PRIMARY,
        bg=BG_CARD,
        cursor='hand2'
    )
    forgot_link.grid(row=7, column=0, pady=(5, 8))
    forgot_link.bind('<Button-1>', lambda e: show_forgot_password())
    
    # Lock warning
    tk.Label(
        form,
        text="Account locked after 5 failed attempts",
        font=('Segoe UI', 9),
        fg=ERROR_RED,
        bg=BG_CARD
    ).grid(row=8, column=0, pady=(8, 0))
    
    # ================= PLACEHOLDERS =================
    def clear_placeholder(entry, placeholder):
        if entry.get() == placeholder:
            entry.delete(0, tk.END)
            if placeholder == "Enter master password":
                entry.config(show="•")
    
    def add_placeholder(entry, placeholder):
        if entry.get() == "":
            entry.insert(0, placeholder)
            if placeholder == "Enter master password":
                entry.config(show="")
    
    username_entry.bind("<FocusIn>", lambda e: clear_placeholder(username_entry, "Enter your username"))
    username_entry.bind("<FocusOut>", lambda e: add_placeholder(username_entry, "Enter your username"))
    
    password_entry.bind("<FocusIn>", lambda e: clear_placeholder(password_entry, "Enter master password"))
    password_entry.bind("<FocusOut>", lambda e: add_placeholder(password_entry, "Enter master password"))
    
    # ================= UPDATE ATTEMPTS (FIXED) =================
    def update_attempts(count, max_attempts=5):
        # Check if widget still exists before updating
        try:
            if attempts_label.winfo_exists():
                attempts_var.set(f"Failed attempts: {count}/{max_attempts}")
                if count >= 3:
                    attempts_label.config(font=('Segoe UI', 10, 'bold'))
        except:
            pass  # Widget no longer exists, ignore
    
    # Enter key login
    username_entry.bind("<Return>", lambda e: login_click())
    password_entry.bind("<Return>", lambda e: login_click())
    
    return frame, update_attempts, username_entry, password_entry


def create_forgot_password_screen(parent, on_login_callback, on_register_callback):
    """Create forgot password screen - PROPERLY CLEARS AND RECREATES"""
    
    # ================= CLEAR WINDOW FIRST =================
    for widget in parent.winfo_children():
        widget.destroy()
    
    # ================= COLORS =================
    BG_MAIN        = "#F4F6F8"
    BG_CARD        = "#FFFFFF"
    TEXT_PRIMARY   = "#1F2937"
    TEXT_SECONDARY = "#6B7280"
    INPUT_BORDER   = "#CBD5E1"
    BTN_PRIMARY    = "#1A73E8"
    BTN_ACTIVE     = "#1558B0"
    BTN_BACK       = "#6B7280"
    ERROR_RED      = "#D93025"
    SUCCESS_GREEN  = "#10b981"
    
    # ================= MAIN FRAME =================
    frame = tk.Frame(parent, bg=BG_MAIN)
    frame.pack(fill='both', expand=True)
    
    # ================= CENTER CARD =================
    center = tk.Frame(frame, bg=BG_CARD, padx=40, pady=25)
    center.place(relx=0.5, rely=0.5, anchor='center')
    
    # ================= ICON =================
    icon_frame = tk.Frame(center, bg=BG_CARD)
    icon_frame.pack(pady=(0, 10))
    
    icon = tk.Label(
        icon_frame,
        text="🔑",
        font=('Segoe UI', 42),
        fg="#f59e0b",
        bg=BG_CARD
    )
    icon.pack()
    
    # ================= TITLE =================
    tk.Label(
        center,
        text="Reset Password",
        font=('Segoe UI', 28, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).pack(pady=(0, 5))
    
    tk.Label(
        center,
        text="Enter your username and new password",
        font=('Segoe UI', 13),
        fg=TEXT_SECONDARY,
        bg=BG_CARD
    ).pack(pady=(0, 25))
    
    # ================= FORM =================
    form = tk.Frame(center, bg=BG_CARD)
    form.pack()
    
    # Username
    tk.Label(
        form,
        text="Username",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=0, column=0, sticky='w', pady=(0, 5))
    
    username_entry = tk.Entry(
        form,
        font=('Segoe UI', 11),
        width=38,
        bg="white",
        fg=TEXT_PRIMARY,
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    username_entry.grid(row=1, column=0, pady=(0, 15))
    
    # New Password
    tk.Label(
        form,
        text="New Master Password",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=2, column=0, sticky='w', pady=(0, 5))
    
    password_frame = tk.Frame(form, bg=BG_CARD)
    password_frame.grid(row=3, column=0, pady=(0, 15), sticky='ew')
    
    password_entry = tk.Entry(
        password_frame,
        font=('Segoe UI', 11),
        width=32,
        bg="white",
        fg=TEXT_PRIMARY,
        show="•",
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    password_entry.pack(side='left')
    
    def toggle_password():
        if password_entry.cget('show') == "•":
            password_entry.config(show="")
            eye_btn.config(text="👁")
        else:
            password_entry.config(show="•")
            eye_btn.config(text="👁🗨")
    
    eye_btn = tk.Button(
        password_frame,
        text="👁🗨",
        font=('Segoe UI', 11),
        bg="#E5E7EB",
        fg=TEXT_PRIMARY,
        relief='flat',
        width=3,
        command=toggle_password
    )
    eye_btn.pack(side='right', padx=(6, 0))
    
    # Confirm Password
    tk.Label(
        form,
        text="Confirm New Password",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=4, column=0, sticky='w', pady=(0, 5))
    
    confirm_frame = tk.Frame(form, bg=BG_CARD)
    confirm_frame.grid(row=5, column=0, pady=(0, 15), sticky='ew')
    
    confirm_entry = tk.Entry(
        confirm_frame,
        font=('Segoe UI', 11),
        width=32,
        bg="white",
        fg=TEXT_PRIMARY,
        show="•",
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    confirm_entry.pack(side='left')
    
    def toggle_confirm():
        if confirm_entry.cget('show') == "•":
            confirm_entry.config(show="")
            eye_btn2.config(text="👁")
        else:
            confirm_entry.config(show="•")
            eye_btn2.config(text="👁🗨")
    
    eye_btn2 = tk.Button(
        confirm_frame,
        text="👁🗨",
        font=('Segoe UI', 11),
        bg="#E5E7EB",
        fg=TEXT_PRIMARY,
        relief='flat',
        width=3,
        command=toggle_confirm
    )
    eye_btn2.pack(side='right', padx=(6, 0))
    
    # Password strength indicator
    strength_var = tk.StringVar(value="")
    strength_label = tk.Label(
        form,
        textvariable=strength_var,
        font=('Segoe UI', 9),
        fg=TEXT_SECONDARY,
        bg=BG_CARD
    )
    strength_label.grid(row=6, column=0, sticky='w', pady=(0, 15))
    
    def check_password_strength(event=None):
        password = password_entry.get()
        if not password:
            strength_var.set("")
            return
        
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        
        if score >= 5:
            strength_var.set("✓ Strong password")
            strength_label.config(fg=SUCCESS_GREEN)
        elif score >= 3:
            strength_var.set("⚠ Medium password")
            strength_label.config(fg="#f59e0b")
        else:
            strength_var.set("✗ Weak password")
            strength_label.config(fg=ERROR_RED)
    
    password_entry.bind("<KeyRelease>", check_password_strength)
    
    # ================= RESET PASSWORD FUNCTION =================
    def reset_password():
        username = username_entry.get().strip()
        new_password = password_entry.get()
        confirm_password = confirm_entry.get()
        
        # Validation
        if not username:
            messagebox.showerror("Error", "Please enter your username!")
            return
        
        if not new_password or not confirm_password:
            messagebox.showerror("Error", "Please enter and confirm your new password!")
            return
        
        if len(new_password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters!")
            return
        
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        # Check if username exists
        users_file = "users.json"
        if not os.path.exists(users_file):
            messagebox.showerror("Error", "Username not found!")
            return
        
        with open(users_file, "r") as f:
            users = json.load(f)
        
        if username not in users:
            messagebox.showerror("Error", "Username not found!")
            return
        
        # Update password
        hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        users[username]["password"] = hashed_password
        
        # Save updated users
        with open(users_file, "w") as f:
            json.dump(users, f, indent=4)
        
        # Log password reset
        from audit_log import AuditLog
        user_email = users[username].get('email', username)
        AuditLog.log_event(
            event_type="PASSWORD_RESET",
            severity="WARNING",
            description="Master password was reset successfully",
            user=user_email
        )
        
        messagebox.showinfo("Success", 
                          f"Password reset successfully!\n\n" +
                          f"Username: {username}\n\n" +
                          "You can now login with your new password.")
        
        # Return to login screen properly
        create_login_screen(parent, on_login_callback, on_register_callback)
    
    # ================= BUTTONS =================
    button_frame = tk.Frame(form, bg=BG_CARD)
    button_frame.grid(row=7, column=0, pady=10)
    
    reset_btn = tk.Button(
        button_frame,
        text="Reset Password",
        font=('Segoe UI', 12, 'bold'),
        bg=BTN_PRIMARY,
        fg="white",
        activebackground=BTN_ACTIVE,
        relief='flat',
        width=18,
        command=reset_password
    )
    reset_btn.pack(pady=(0, 10))
    
    back_btn = tk.Button(
        button_frame,
        text="← Back to Login",
        font=('Segoe UI', 11),
        bg=BG_CARD,
        fg=BTN_BACK,
        activebackground=BG_CARD,
        relief='flat',
        width=18,
        command=lambda: create_login_screen(parent, on_login_callback, on_register_callback)
    )
    back_btn.pack()


def create_registration_screen(parent, on_register_submit, on_back_to_login):
    """Create registration screen"""
    
    # Clear window first
    for widget in parent.winfo_children():
        widget.destroy()
    
    # ================= COLORS =================
    BG_MAIN        = "#F4F6F8"
    BG_CARD        = "#FFFFFF"
    TEXT_PRIMARY   = "#1F2937"
    TEXT_SECONDARY = "#6B7280"
    INPUT_BORDER   = "#CBD5E1"
    BTN_PRIMARY    = "#10b981"
    BTN_ACTIVE     = "#059669"
    BTN_BACK       = "#6B7280"
    ERROR_RED      = "#D93025"
    SUCCESS_GREEN  = "#10b981"
    
    # ================= MAIN FRAME =================
    frame = tk.Frame(parent, bg=BG_MAIN)
    frame.pack(fill='both', expand=True)
    
    # ================= CENTER CARD =================
    center = tk.Frame(frame, bg=BG_CARD, padx=40, pady=25)
    center.place(relx=0.5, rely=0.5, anchor='center')
    
    # ================= ICON =================
    icon_frame = tk.Frame(center, bg=BG_CARD)
    icon_frame.pack(pady=(0, 10))
    
    icon = tk.Label(
        icon_frame,
        text="👤",
        font=('Segoe UI', 42),
        fg=SUCCESS_GREEN,
        bg=BG_CARD
    )
    icon.pack()
    
    # ================= TITLE =================
    tk.Label(
        center,
        text="Create Account",
        font=('Segoe UI', 28, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).pack(pady=(0, 5))
    
    tk.Label(
        center,
        text="Join Secure Vault Password Manager",
        font=('Segoe UI', 13),
        fg=TEXT_SECONDARY,
        bg=BG_CARD
    ).pack(pady=(0, 25))
    
    # ================= FORM =================
    form = tk.Frame(center, bg=BG_CARD)
    form.pack()
    
    # Full Name
    tk.Label(
        form,
        text="Full Name",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=0, column=0, sticky='w', pady=(0, 5))
    
    name_entry = tk.Entry(
        form,
        font=('Segoe UI', 11),
        width=38,
        bg="white",
        fg=TEXT_PRIMARY,
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    name_entry.grid(row=1, column=0, pady=(0, 15))
    
    # Email
    tk.Label(
        form,
        text="Email Address",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=2, column=0, sticky='w', pady=(0, 5))
    
    email_entry = tk.Entry(
        form,
        font=('Segoe UI', 11),
        width=38,
        bg="white",
        fg=TEXT_PRIMARY,
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    email_entry.grid(row=3, column=0, pady=(0, 15))
    
    # Username
    tk.Label(
        form,
        text="Username",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=4, column=0, sticky='w', pady=(0, 5))
    
    username_entry = tk.Entry(
        form,
        font=('Segoe UI', 11),
        width=38,
        bg="white",
        fg=TEXT_PRIMARY,
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    username_entry.grid(row=5, column=0, pady=(0, 15))
    
    # Password
    tk.Label(
        form,
        text="Master Password",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=6, column=0, sticky='w', pady=(0, 5))
    
    password_frame = tk.Frame(form, bg=BG_CARD)
    password_frame.grid(row=7, column=0, pady=(0, 15), sticky='ew')
    
    password_entry = tk.Entry(
        password_frame,
        font=('Segoe UI', 11),
        width=32,
        bg="white",
        fg=TEXT_PRIMARY,
        show="•",
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    password_entry.pack(side='left')
    
    def toggle_password():
        if password_entry.cget('show') == "•":
            password_entry.config(show="")
            eye_btn.config(text="👁")
        else:
            password_entry.config(show="•")
            eye_btn.config(text="👁🗨")
    
    eye_btn = tk.Button(
        password_frame,
        text="👁🗨",
        font=('Segoe UI', 11),
        bg="#E5E7EB",
        fg=TEXT_PRIMARY,
        relief='flat',
        width=3,
        command=toggle_password
    )
    eye_btn.pack(side='right', padx=(6, 0))
    
    # Confirm Password
    tk.Label(
        form,
        text="Confirm Password",
        font=('Segoe UI', 11, 'bold'),
        fg=TEXT_PRIMARY,
        bg=BG_CARD
    ).grid(row=8, column=0, sticky='w', pady=(0, 5))
    
    confirm_frame = tk.Frame(form, bg=BG_CARD)
    confirm_frame.grid(row=9, column=0, pady=(0, 15), sticky='ew')
    
    confirm_entry = tk.Entry(
        confirm_frame,
        font=('Segoe UI', 11),
        width=32,
        bg="white",
        fg=TEXT_PRIMARY,
        show="•",
        insertbackground=TEXT_PRIMARY,
        relief='solid',
        bd=1,
        highlightthickness=1,
        highlightbackground=INPUT_BORDER
    )
    confirm_entry.pack(side='left')
    
    def toggle_confirm():
        if confirm_entry.cget('show') == "•":
            confirm_entry.config(show="")
            eye_btn2.config(text="👁")
        else:
            confirm_entry.config(show="•")
            eye_btn2.config(text="👁🗨")
    
    eye_btn2 = tk.Button(
        confirm_frame,
        text="👁🗨",
        font=('Segoe UI', 11),
        bg="#E5E7EB",
        fg=TEXT_PRIMARY,
        relief='flat',
        width=3,
        command=toggle_confirm
    )
    eye_btn2.pack(side='right', padx=(6, 0))
    
    # Password strength indicator
    strength_var = tk.StringVar(value="")
    strength_label = tk.Label(
        form,
        textvariable=strength_var,
        font=('Segoe UI', 9),
        fg=TEXT_SECONDARY,
        bg=BG_CARD
    )
    strength_label.grid(row=10, column=0, sticky='w', pady=(0, 15))
    
    def check_password_strength(event=None):
        password = password_entry.get()
        if not password:
            strength_var.set("")
            return
        
        score = 0
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        
        if score >= 5:
            strength_var.set("✓ Strong password")
            strength_label.config(fg=SUCCESS_GREEN)
        elif score >= 3:
            strength_var.set("⚠ Medium password")
            strength_label.config(fg="#f59e0b")
        else:
            strength_var.set("✗ Weak password")
            strength_label.config(fg=ERROR_RED)
    
    password_entry.bind("<KeyRelease>", check_password_strength)
    
    # ================= BUTTONS =================
    def submit_registration():
        name = name_entry.get().strip()
        email = email_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get()
        confirm = confirm_entry.get()
        
        # Validation
        if not name or not email or not username or not password:
            messagebox.showerror("Error", "All fields are required!")
            return
        
        if len(name) < 2:
            messagebox.showerror("Error", "Name must be at least 2 characters!")
            return
        
        # Email validation
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            messagebox.showerror("Error", "Invalid email address!")
            return
        
        if len(username) < 3:
            messagebox.showerror("Error", "Username must be at least 3 characters!")
            return
        
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters!")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        
        # Check password strength
        score = 0
        if len(password) >= 12:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        
        if score < 3:
            messagebox.showwarning("Weak Password", 
                                 "Your password is weak! Consider adding:\n" +
                                 "• Uppercase letters\n• Numbers\n• Special characters\n• At least 12 characters")
        
        on_register_submit(name, email, username, password)
    
    button_frame = tk.Frame(form, bg=BG_CARD)
    button_frame.grid(row=11, column=0, pady=10)
    
    register_btn = tk.Button(
        button_frame,
        text="Create Account",
        font=('Segoe UI', 12, 'bold'),
        bg=BTN_PRIMARY,
        fg="white",
        activebackground=BTN_ACTIVE,
        relief='flat',
        width=18,
        command=submit_registration
    )
    register_btn.pack(pady=(0, 10))
    
    back_btn = tk.Button(
        button_frame,
        text="← Back to Login",
        font=('Segoe UI', 11),
        bg=BG_CARD,
        fg=BTN_BACK,
        activebackground=BG_CARD,
        relief='flat',
        width=18,
        command=on_back_to_login
    )
    back_btn.pack()
    
    return frame
