# security_utilities.py - FIXED FULL WIDTH LAYOUT & WORKING TIMERS
import tkinter as tk
from tkinter import ttk, messagebox
import string
import random
import json
import os
from datetime import datetime, timedelta

class SecurityUtilities:
    def __init__(self, root, dashboard_callback, current_user):
        self.root = root
        self.dashboard_callback = dashboard_callback
        self.current_user = current_user
        self.settings_file = "settings.json"
        
        # Initialize gen_options BEFORE calling show_security_screen
        self.gen_options = {
            'uppercase': None,
            'lowercase': None,
            'numbers': None,
            'symbols': None
        }
        
        self.load_settings()
        
        # Auto-lock timer
        self.auto_lock_timer = None
        self.last_activity_time = datetime.now()
        
    def load_settings(self):
        """Load user settings"""
        if os.path.exists(self.settings_file):
            with open(self.settings_file, "r") as f:
                self.settings = json.load(f)
        else:
            self.settings = {}
        
        if self.current_user not in self.settings:
            self.settings[self.current_user] = {
                "auto_lock_time": 1,
                "lock_after_failed_attempts": True,
                "max_failed_attempts": 5,
                "lockout_duration": 5
            }
            self.save_settings()
    
    def save_settings(self):
        """Save settings to file"""
        with open(self.settings_file, "w") as f:
            json.dump(self.settings, f, indent=4)
    
    def show_security_screen(self):
        """Display security utilities screen"""
        # Clear window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main container
        main_frame = tk.Frame(self.root, bg='#f8f9fa')
        main_frame.pack(fill='both', expand=True)
        
        # Header with back button
        header = tk.Frame(main_frame, bg='#ffffff', height=70)
        header.pack(fill='x', pady=(0, 2))
        header.pack_propagate(False)
        
        # Back button
        back_btn = tk.Button(
            header,
            text="← Back to Dashboard",
            font=('Arial', 12, 'bold'),
            bg='#2563eb',
            fg='white',
            relief='flat',
            padx=20,
            pady=8,
            cursor='hand2',
            command=self.dashboard_callback
        )
        back_btn.place(x=20, y=15)
        
        # Title
        title_label = tk.Label(
            header,
            text="Security Utilities",
            font=('Arial', 22, 'bold'),
            fg='#2c3e50',
            bg='#ffffff'
        )
        title_label.place(x=250, y=10)
        
        subtitle = tk.Label(
            header,
            text="Advanced security tools and password management",
            font=('Arial', 11),
            fg='#7f8c8d',
            bg='#ffffff'
        )
        subtitle.place(x=250, y=40)
        
        # Content area with scrollbar (FULL WIDTH)
        content_container = tk.Frame(main_frame, bg='#f8f9fa')
        content_container.pack(fill='both', expand=True, padx=40, pady=20)
        
        canvas = tk.Canvas(content_container, bg='#f8f9fa', highlightthickness=0)
        scrollbar = tk.Scrollbar(content_container, orient='vertical', command=canvas.yview)
        
        scrollable_frame = tk.Frame(canvas, bg='#f8f9fa')
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Update canvas width when resized
        def update_canvas_width(event):
            canvas.itemconfig(canvas_window, width=event.width)
        
        canvas.bind('<Configure>', update_canvas_width)
        
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # ========== PASSWORD STRENGTH METER (FULL WIDTH) ==========
        strength_panel = self.create_panel(scrollable_frame, bg='white')
        strength_panel.pack(fill='both', expand=True, pady=(0, 20))
        
        strength_content = tk.Frame(strength_panel, bg='white', padx=30, pady=25)
        strength_content.pack(fill='both', expand=True)
        
        # Header with icon
        strength_header = tk.Frame(strength_content, bg='white')
        strength_header.pack(fill='x', pady=(0, 20))
        
        icon_frame = tk.Frame(strength_header, bg='#e8f5e9', width=60, height=60)
        icon_frame.pack(side='left', padx=(0, 15))
        icon_frame.pack_propagate(False)
        
        icon_label = tk.Label(
            icon_frame,
            text="🛡",
            font=('Arial', 28),
            bg='#e8f5e9',
            fg='#4caf50'
        )
        icon_label.pack(expand=True)
        
        title_frame = tk.Frame(strength_header, bg='white')
        title_frame.pack(side='left', fill='x', expand=True)
        
        tk.Label(
            title_frame,
            text="Password Strength Meter",
            font=('Arial', 18, 'bold'),
            fg='#1e293b',
            bg='white',
            anchor='w'
        ).pack(fill='x')
        
        # Password input
        self.password_input = tk.Entry(
            strength_content,
            font=('Arial', 14),
            bg='#f8fafc',
            fg='#1e293b',
            relief='solid',
            bd=1,
            highlightthickness=1,
            highlightbackground='#cbd5e1',
            highlightcolor='#2563eb'
        )
        self.password_input.pack(fill='x', pady=(0, 20), ipady=10)
        self.password_input.insert(0, "khadija12367****&%^H&")
        self.password_input.bind('<KeyRelease>', self.update_strength_meter)
        
        # Strength label and bar
        strength_info = tk.Frame(strength_content, bg='white')
        strength_info.pack(fill='x', pady=(0, 10))
        
        tk.Label(
            strength_info,
            text="Strength:",
            font=('Arial', 12),
            fg='#64748b',
            bg='white'
        ).pack(side='left')
        
        self.strength_text = tk.Label(
            strength_info,
            text="Strong",
            font=('Arial', 14, 'bold'),
            fg='#22c55e',
            bg='white'
        )
        self.strength_text.pack(side='right')
        
        # Progress bar
        self.strength_bar = tk.Canvas(
            strength_content,
            height=30,
            bg='#e5e7eb',
            highlightthickness=0
        )
        self.strength_bar.pack(fill='x', pady=(0, 20))
        
        # Criteria checklist
        criteria_grid = tk.Frame(strength_content, bg='white')
        criteria_grid.pack(fill='x')
        
        self.criteria_labels = {}
        criteria = [
            ("uppercase", "Contains uppercase"),
            ("symbols", "Contains symbols"),
            ("numbers", "Contains numbers"),
            ("length", "Length greater than 12")
        ]
        
        for i, (key, text) in enumerate(criteria):
            row = i // 2
            col = i % 2
            
            criterion_frame = tk.Frame(criteria_grid, bg='#e8f5e9', height=50)
            criterion_frame.grid(row=row, column=col, sticky='ew', padx=(0, 10) if col == 0 else (0, 0), pady=(0, 10))
            criterion_frame.grid_propagate(False)
            
            criterion_content = tk.Frame(criterion_frame, bg='#e8f5e9')
            criterion_content.pack(expand=True, padx=15)
            
            check_label = tk.Label(
                criterion_content,
                text="✓",
                font=('Arial', 16, 'bold'),
                fg='#22c55e',
                bg='#e8f5e9'
            )
            check_label.pack(side='left', padx=(0, 10))
            
            text_label = tk.Label(
                criterion_content,
                text=text,
                font=('Arial', 11),
                fg='#15803d',
                bg='#e8f5e9'
            )
            text_label.pack(side='left')
            
            self.criteria_labels[key] = (criterion_frame, check_label, text_label)
        
        criteria_grid.grid_columnconfigure(0, weight=1)
        criteria_grid.grid_columnconfigure(1, weight=1)
        
        # Initial update
        self.update_strength_meter()
        
        # ========== AUTO-LOCK CONFIGURATION (FULL WIDTH) ==========
        autolock_panel = self.create_panel(scrollable_frame, bg='white')
        autolock_panel.pack(fill='both', expand=True, pady=(0, 20))
        
        autolock_content = tk.Frame(autolock_panel, bg='white', padx=30, pady=25)
        autolock_content.pack(fill='both', expand=True)
        
        # Header
        autolock_header = tk.Frame(autolock_content, bg='white')
        autolock_header.pack(fill='x', pady=(0, 20))
        
        icon_frame2 = tk.Frame(autolock_header, bg='#e3f2fd', width=60, height=60)
        icon_frame2.pack(side='left', padx=(0, 15))
        icon_frame2.pack_propagate(False)
        
        icon_label2 = tk.Label(
            icon_frame2,
            text="🕐",
            font=('Arial', 28),
            bg='#e3f2fd'
        )
        icon_label2.pack(expand=True)
        
        tk.Label(
            autolock_header,
            text="Auto-Lock Configuration",
            font=('Arial', 18, 'bold'),
            fg='#1e293b',
            bg='white'
        ).pack(side='left')
        
        # Auto-lock setting
        autolock_setting = tk.Frame(autolock_content, bg='#eff6ff', relief='flat', bd=1)
        autolock_setting.pack(fill='x', pady=(0, 15))
        
        setting_content = tk.Frame(autolock_setting, bg='#eff6ff', padx=20, pady=15)
        setting_content.pack(fill='x')
        
        icon_and_text = tk.Frame(setting_content, bg='#eff6ff')
        icon_and_text.pack(side='left', fill='x', expand=True)
        
        tk.Label(
            icon_and_text,
            text="🔒",
            font=('Arial', 20),
            bg='#eff6ff'
        ).pack(side='left', padx=(0, 15))
        
        text_frame = tk.Frame(icon_and_text, bg='#eff6ff')
        text_frame.pack(side='left', fill='x', expand=True)
        
        tk.Label(
            text_frame,
            text="Vault Auto-Lock Time",
            font=('Arial', 13, 'bold'),
            fg='#1e293b',
            bg='#eff6ff',
            anchor='w'
        ).pack(fill='x')
        
        tk.Label(
            text_frame,
            text="Lock after inactivity",
            font=('Arial', 10),
            fg='#64748b',
            bg='#eff6ff',
            anchor='w'
        ).pack(fill='x')
        
        # Dropdown - Load saved value
        time_options = ["1 minute", "5 minutes", "10 minutes", "15 minutes", "30 minutes"]
        saved_time = self.settings[self.current_user].get("auto_lock_time", 1)
        default_value = f"{saved_time} minute" if saved_time == 1 else f"{saved_time} minutes"
        
        self.autolock_var = tk.StringVar(value=default_value)
        
        time_dropdown = ttk.Combobox(
            setting_content,
            textvariable=self.autolock_var,
            values=time_options,
            state='readonly',
            font=('Arial', 11),
            width=15
        )
        time_dropdown.pack(side='right')
        time_dropdown.bind('<<ComboboxSelected>>', self.save_autolock_setting)
        
        # NEW: Lockout Duration Setting
        lockout_setting = tk.Frame(autolock_content, bg='#fff3cd', relief='flat', bd=1)
        lockout_setting.pack(fill='x')
        
        lockout_content = tk.Frame(lockout_setting, bg='#fff3cd', padx=20, pady=15)
        lockout_content.pack(fill='x')
        
        lockout_icon_text = tk.Frame(lockout_content, bg='#fff3cd')
        lockout_icon_text.pack(side='left', fill='x', expand=True)
        
        tk.Label(
            lockout_icon_text,
            text="⏱",
            font=('Arial', 20),
            bg='#fff3cd'
        ).pack(side='left', padx=(0, 15))
        
        lockout_text_frame = tk.Frame(lockout_icon_text, bg='#fff3cd')
        lockout_text_frame.pack(side='left', fill='x', expand=True)
        
        tk.Label(
            lockout_text_frame,
            text="Vault Login Attempt Lockout Time",
            font=('Arial', 13, 'bold'),
            fg='#1e293b',
            bg='#fff3cd',
            anchor='w'
        ).pack(fill='x')
        
        tk.Label(
            lockout_text_frame,
            text="Lock duration after 5 failed login attempts",
            font=('Arial', 10),
            fg='#64748b',
            bg='#fff3cd',
            anchor='w'
        ).pack(fill='x')
        
        # Lockout duration dropdown - Load saved value
        lockout_options = ["5 minutes", "10 minutes", "15 minutes", "30 minutes", "60 minutes"]
        saved_lockout = self.settings[self.current_user].get("lockout_duration", 5)
        default_lockout = f"{saved_lockout} minutes"
        
        self.lockout_var = tk.StringVar(value=default_lockout)
        
        lockout_dropdown = ttk.Combobox(
            lockout_content,
            textvariable=self.lockout_var,
            values=lockout_options,
            state='readonly',
            font=('Arial', 11),
            width=15
        )
        lockout_dropdown.pack(side='right')
        lockout_dropdown.bind('<<ComboboxSelected>>', self.save_lockout_setting)
        
        # ========== PASSWORD GENERATOR (FULL WIDTH) ==========
        generator_panel = self.create_panel(scrollable_frame, bg='white')
        generator_panel.pack(fill='both', expand=True)
        
        generator_content = tk.Frame(generator_panel, bg='white', padx=30, pady=25)
        generator_content.pack(fill='both', expand=True)
        
        # Header
        generator_header = tk.Frame(generator_content, bg='white')
        generator_header.pack(fill='x', pady=(0, 20))
        
        icon_frame3 = tk.Frame(generator_header, bg='#f3e8ff', width=60, height=60)
        icon_frame3.pack(side='left', padx=(0, 15))
        icon_frame3.pack_propagate(False)
        
        icon_label3 = tk.Label(
            icon_frame3,
            text="🔑",
            font=('Arial', 28),
            bg='#f3e8ff',
            fg='#9333ea'
        )
        icon_label3.pack(expand=True)
        
        tk.Label(
            generator_header,
            text="Password Generator",
            font=('Arial', 18, 'bold'),
            fg='#1e293b',
            bg='white'
        ).pack(side='left')
        
        # Initialize BooleanVars NOW (before using them)
        self.gen_options = {
            'uppercase': tk.BooleanVar(value=True),
            'lowercase': tk.BooleanVar(value=True),
            'numbers': tk.BooleanVar(value=True),
            'symbols': tk.BooleanVar(value=True)
        }
        
        # Generated password display
        password_display_frame = tk.Frame(generator_content, bg='#faf5ff', relief='solid', bd=1)
        password_display_frame.pack(fill='x', pady=(0, 20))
        
        self.generated_password = tk.StringVar(value=self.generate_password())
        
        password_entry = tk.Entry(
            password_display_frame,
            textvariable=self.generated_password,
            font=('Arial', 14, 'bold'),
            bg='#faf5ff',
            fg='#1e293b',
            relief='flat',
            state='readonly'
        )
        password_entry.pack(fill='x', padx=20, pady=15)
        
        # Buttons
        button_frame = tk.Frame(generator_content, bg='white')
        button_frame.pack(fill='x')
        
        copy_btn = tk.Button(
            button_frame,
            text="📋 Copy",
            font=('Arial', 12, 'bold'),
            bg='#9333ea',
            fg='white',
            relief='flat',
            padx=30,
            pady=10,
            cursor='hand2',
            command=self.copy_password
        )
        copy_btn.pack(side='left', padx=(0, 10))
        
        generate_btn = tk.Button(
            button_frame,
            text="🔄 Generate",
            font=('Arial', 12, 'bold'),
            bg='#2563eb',
            fg='white',
            relief='flat',
            padx=30,
            pady=10,
            cursor='hand2',
            command=self.regenerate_password
        )
        generate_btn.pack(side='left')
        
        # Options
        options_frame = tk.Frame(generator_content, bg='white')
        options_frame.pack(fill='x', pady=(20, 0))
        
        option_labels = [
            ('uppercase', 'Include Uppercase'),
            ('lowercase', 'Include Lowercase'),
            ('numbers', 'Include Numbers'),
            ('symbols', 'Include Symbols')
        ]
        
        for i, (key, text) in enumerate(option_labels):
            row = i // 2
            col = i % 2
            
            option_frame = tk.Frame(options_frame, bg='white')
            option_frame.grid(row=row, column=col, sticky='w', padx=(0, 20), pady=5)
            
            checkbox = tk.Checkbutton(
                option_frame,
                text=text,
                variable=self.gen_options[key],
                font=('Arial', 11),
                bg='white',
                fg='#1e293b',
                selectcolor='#e0e7ff',
                activebackground='white',
                activeforeground='#1e293b',
                command=self.regenerate_password
            )
            checkbox.pack(side='left')
        
        options_frame.grid_columnconfigure(0, weight=1)
        options_frame.grid_columnconfigure(1, weight=1)
    
    def create_panel(self, parent, bg='white'):
        """Create styled panel"""
        panel = tk.Frame(parent, bg=bg, relief='solid', bd=1, highlightthickness=0)
        
        shadow = tk.Frame(panel, bg='#e0e6ed', height=2)
        shadow.pack(fill='x', side='bottom')
        
        return panel
    
    def update_strength_meter(self, event=None):
        """Update password strength display"""
        password = self.password_input.get()
        
        criteria_met = {
            'uppercase': any(c.isupper() for c in password),
            'symbols': any(c in string.punctuation for c in password),
            'numbers': any(c.isdigit() for c in password),
            'length': len(password) >= 12
        }
        
        score = sum(criteria_met.values())
        
        for key, (frame, check, text) in self.criteria_labels.items():
            if criteria_met[key]:
                frame.config(bg='#e8f5e9')
                check.config(text='✓', fg='#22c55e', bg='#e8f5e9')
                text.config(fg='#15803d', bg='#e8f5e9')
            else:
                frame.config(bg='#fee2e2')
                check.config(text='✗', fg='#ef4444', bg='#fee2e2')
                text.config(fg='#991b1b', bg='#fee2e2')
        
        if score >= 4:
            strength = "Strong"
            color = '#22c55e'
            percentage = 1.0
        elif score == 3:
            strength = "Medium"
            color = '#eab308'
            percentage = 0.65
        else:
            strength = "Weak"
            color = '#ef4444'
            percentage = 0.35
        
        self.strength_text.config(text=strength, fg=color)
        
        self.strength_bar.delete('all')
        width = self.strength_bar.winfo_width() if self.strength_bar.winfo_width() > 1 else 700
        bar_width = int(width * percentage)
        
        self.strength_bar.create_rectangle(
            0, 0, bar_width, 30,
            fill=color,
            outline=color
        )
    
    def generate_password(self, length=20):
        """Generate strong password"""
        chars = ""
        if self.gen_options['uppercase'].get():
            chars += string.ascii_uppercase
        if self.gen_options['lowercase'].get():
            chars += string.ascii_lowercase
        if self.gen_options['numbers'].get():
            chars += string.digits
        if self.gen_options['symbols'].get():
            chars += string.punctuation
        
        if not chars:
            chars = string.ascii_letters + string.digits
        
        password = ''.join(random.choice(chars) for _ in range(length))
        return password
    
    def regenerate_password(self):
        """Generate new password"""
        new_password = self.generate_password()
        self.generated_password.set(new_password)
    
    def copy_password(self):
        """Copy password to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(self.generated_password.get())
        messagebox.showinfo("Success", "Password copied to clipboard!")
    
    def save_autolock_setting(self, event=None):
        """Save auto-lock time setting - NOW WORKING"""
        time_str = self.autolock_var.get()
        minutes = int(time_str.split()[0])
        
        self.settings[self.current_user]["auto_lock_time"] = minutes
        self.save_settings()
        
        messagebox.showinfo("Settings Saved", f"✓ Auto-lock set to {minutes} minute{'s' if minutes != 1 else ''}\n\nVault will lock after {minutes} minute{'s' if minutes != 1 else ''} of inactivity.")
    
    def save_lockout_setting(self, event=None):
        """Save lockout duration setting - NOW WORKING"""
        time_str = self.lockout_var.get()
        minutes = int(time_str.split()[0])
        
        self.settings[self.current_user]["lockout_duration"] = minutes
        self.save_settings()
        
        messagebox.showinfo("Settings Saved", f"✓ Lockout duration set to {minutes} minutes\n\nAfter 5 failed login attempts, the account will be locked for {minutes} minutes.")
