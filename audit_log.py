# audit_log.py - WITH ALL BOXES EXTENDED HORIZONTALLY TO MATCH ERROR ALERTS
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
import json
import os
import socket
import random
import subprocess

class AuditLog:
    LOG_FILE = "audit_logs.json"
    
    @staticmethod
    def get_real_ip():
        """Get actual IP address"""
        try:
            # Method for Linux/Kali
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
            if result.stdout:
                ip = result.stdout.strip().split()[0]
                return ip
        except:
            pass
        
        try:
            # Fallback method
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "192.168.1.100"
    
    @staticmethod
    def generate_external_ip():
        """Generate a fake external IP for failed attempts"""
        return f"203.45.67.{random.randint(85, 99)}"
    
    @staticmethod
    def log_event(event_type, severity, description, user, ip_address=None):
        """Log an audit event in real-time"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if not ip_address:
            if "FAILED" in event_type or "failed" in event_type.lower():
                ip_address = AuditLog.generate_external_ip()
            else:
                ip_address = AuditLog.get_real_ip()
        
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "severity": severity,
            "description": description,
            "user": user,
            "ip_address": ip_address
        }
        
        # Load existing logs
        logs = []
        if os.path.exists(AuditLog.LOG_FILE):
            try:
                with open(AuditLog.LOG_FILE, "r") as f:
                    logs = json.load(f)
            except:
                logs = []
        
        # Check for duplicate logs (prevent multiple weak password warnings)
        if event_type == "WEAK_PASSWORD_DETECTED":
            # Remove any existing weak password logs for same user
            logs = [log for log in logs if not (log.get('event_type') == "WEAK_PASSWORD_DETECTED" and 
                                               log.get('user') == user and
                                               "Weak Passwords Detected" in log.get('description', ''))]
        
        # Add new log
        logs.append(log_entry)
        
        # Keep only last 200 entries
        if len(logs) > 200:
            logs = logs[-200:]
        
        # Save to file
        with open(AuditLog.LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
        
        return log_entry
    
    @staticmethod
    def log_login_success(user_email, device_info="Windows PC"):
        """Log successful login"""
        return AuditLog.log_event(
            event_type="LOGIN_SUCCESS",
            severity="INFO",
            description=f"User: {user_email} | Device: {device_info}",
            user=user_email
        )
    
    @staticmethod
    def log_login_failed(user_email, reason, device_info="Windows PC"):
        """Log failed login attempt"""
        fake_ip = AuditLog.generate_external_ip()
        return AuditLog.log_event(
            event_type="LOGIN_FAILED",
            severity="WARNING" if "Invalid" in reason else "CRITICAL",
            description=f"User: {user_email} | Device: {device_info} | Reason: {reason}",
            user=user_email,
            ip_address=fake_ip
        )
    
    @staticmethod
    def log_password_operation(operation, service_name, details, user_email):
        """Log password operations"""
        severity_map = {
            "added": "INFO",
            "viewed": "WARNING",
            "edited": "INFO",
            "deleted": "CRITICAL"
        }
        
        action_text = {
            "added": "Created new password entry",
            "viewed": "Password revealed and copied",
            "edited": "Password updated and modified",
            "deleted": "Permanently removed from vault"
        }
        
        description = f"Service: {service_name} | Action: {action_text.get(operation, details)}"
        
        return AuditLog.log_event(
            event_type=f"PASSWORD_{operation.upper()}",
            severity=severity_map.get(operation, "INFO"),
            description=description,
            user=user_email
        )
    
    @staticmethod
    def check_weak_passwords(credentials, user_email):
        """Check for weak passwords and log them ONCE only"""
        weak_creds = [cred for cred in credentials if cred.get('strength') == 'Weak']
        weak_count = len(weak_creds)
        
        if weak_count > 0:
            # Check if we already logged weak passwords for this user recently
            existing_logs = AuditLog.get_logs_for_user(user_email, 10)
            recent_weak_logs = [log for log in existing_logs if 
                               log.get('event_type') == "WEAK_PASSWORD_DETECTED"]
            
            if not recent_weak_logs:  # Only log if no recent weak password logs
                weak_services = [cred['service'] for cred in weak_creds[:3]]
                service_list = ', '.join(weak_services)
                if len(weak_creds) > 3:
                    service_list += f" and {len(weak_creds) - 3} more"
                
                return AuditLog.log_event(
                    event_type="WEAK_PASSWORD_DETECTED",
                    severity="WARNING" if weak_count < 5 else "CRITICAL",
                    description=f"{weak_count} Weak Passwords Detected for services: {service_list}",
                    user=user_email
                )
        return None
    
    @staticmethod
    def log_multiple_failed_attempts(user_email, count, ip_address):
        """Log multiple failed login attempts"""
        return AuditLog.log_event(
            event_type="MULTIPLE_FAILED_ATTEMPTS",
            severity="CRITICAL",
            description=f"{count} failed attempts from IP {ip_address}",
            user=user_email,
            ip_address=ip_address
        )
    
    @staticmethod
    def get_logs_for_user(user_email, limit=100):
        """Get audit logs for a specific user"""
        if not os.path.exists(AuditLog.LOG_FILE):
            return []
        
        try:
            with open(AuditLog.LOG_FILE, "r") as f:
                all_logs = json.load(f)
        except:
            return []
        
        # Filter logs for user
        user_logs = [log for log in all_logs if log.get('user') == user_email]
        return user_logs[-limit:]
    
    @staticmethod
    def get_error_alerts(user_email, limit=20):
        """Get error and alert logs"""
        logs = AuditLog.get_logs_for_user(user_email, limit*2)
        error_logs = [log for log in logs if log.get('severity') in ['WARNING', 'CRITICAL']]
        return error_logs[-limit:]
    
    @staticmethod
    def get_login_activities(user_email, limit=20):
        """Get login activities"""
        logs = AuditLog.get_logs_for_user(user_email, limit*2)
        login_logs = [log for log in logs if 'LOGIN' in log.get('event_type', '')]
        return login_logs[-limit:]
    
    @staticmethod
    def get_password_operations(user_email, limit=20):
        """Get password operations"""
        logs = AuditLog.get_logs_for_user(user_email, limit*2)
        password_logs = [log for log in logs if 'PASSWORD' in log.get('event_type', '')]
        return password_logs[-limit:]
    
    def __init__(self, parent, return_to_dashboard, username):
        self.parent = parent
        self.return_to_dashboard = return_to_dashboard
        self.username = username
        self.user_email = self.get_user_email()
        self.notebook = None
    
    def get_user_email(self):
        """Get user's email address"""
        users_file = "users.json"
        if os.path.exists(users_file):
            try:
                with open(users_file, "r") as f:
                    users = json.load(f)
                    if self.username in users:
                        return users[self.username]['email']
            except:
                pass
        return self.username
    
    def show_audit_screen(self):
        """Display audit logs screen with tabs"""
        for widget in self.parent.winfo_children():
            widget.destroy()
        
        # Main container
        main_frame = tk.Frame(self.parent, bg='#f0f4f8')
        main_frame.pack(fill='both', expand=True)
        
        # Header
        header = tk.Frame(main_frame, bg='#ffffff', height=80)
        header.pack(fill='x', pady=(0, 2))
        
        # LARGER Back button
        tk.Button(
            header,
            text="← Back to Dashboard",
            font=('Arial', 12, 'bold'),
            bg='#2563eb',
            fg='white',
            relief='flat',
            padx=25,
            pady=10,
            cursor='hand2',
            command=self.return_to_dashboard
        ).pack(side='left', padx=20, pady=20)
        
        # Title
        tk.Label(
            header,
            text="Audit Log",
            font=('Arial', 24, 'bold'),
            fg='#1f2937',
            bg='#ffffff'
        ).pack(side='left', padx=20)
        
        tk.Label(
            header,
            text="Track all activities and changes in your password vault",
            font=('Arial', 11),
            fg='#6b7280',
            bg='#ffffff'
        ).pack(side='left', pady=5)
        
        # Create Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Style the notebook
        style = ttk.Style()
        style.configure('TNotebook.Tab', font=('Arial', 11, 'bold'), padding=[15, 5])
        
        # Create tabs
        self.create_all_activities_tab()
        self.create_error_alerts_tab()
        self.create_login_activities_tab()
        self.create_password_operations_tab()
    
    def create_all_activities_tab(self):
        """Create All Activities tab"""
        tab1 = tk.Frame(self.notebook, bg='#f9fafb')
        self.notebook.add(tab1, text='All Activities')
        
        container = tk.Frame(tab1, bg='#f9fafb')
        container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Create scrollable frame
        canvas = tk.Canvas(container, bg='#f9fafb', highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient='vertical', command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#f9fafb')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Make scrollable frame expand to full canvas width
        def configure_scroll_region(event):
            canvas.itemconfig(canvas_window, width=event.width)
        
        canvas.bind('<Configure>', configure_scroll_region)
        
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Get all logs
        logs = AuditLog.get_logs_for_user(self.user_email, 50)
        
        if not logs:
            tk.Label(scrollable_frame, text="No activities recorded yet.", 
                    font=('Arial', 12), bg='#f9fafb', fg='#6b7280').pack(pady=50)
            return
        
        # Display logs in reverse order (newest first)
        for i, log in enumerate(reversed(logs)):
            self.create_log_card(scrollable_frame, log, i)
    
    def create_error_alerts_tab(self):
        """Create Error Alerts tab"""
        tab2 = tk.Frame(self.notebook, bg='#f9fafb')
        self.notebook.add(tab2, text='Error Alerts')
        
        container = tk.Frame(tab2, bg='#f9fafb')
        container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        tk.Label(
            container,
            text="Error Alerts and Notifications",
            font=('Arial', 18, 'bold'),
            fg='#1f2937',
            bg='#f9fafb'
        ).pack(anchor='w', padx=15, pady=(0, 20))
        
        # Create scrollable frame
        canvas = tk.Canvas(container, bg='#f9fafb', highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient='vertical', command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#f9fafb')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Make scrollable frame expand to full canvas width
        def configure_scroll_region(event):
            canvas.itemconfig(canvas_window, width=event.width)
        
        canvas.bind('<Configure>', configure_scroll_region)
        
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Get error alerts
        error_logs = AuditLog.get_error_alerts(self.user_email, 20)
        
        if not error_logs:
            tk.Label(scrollable_frame, text="No error alerts.", 
                    font=('Arial', 12), bg='#f9fafb', fg='#6b7280').pack(pady=50)
            return
        
        # Display error alerts
        for i, log in enumerate(reversed(error_logs)):
            self.create_error_alert_card(scrollable_frame, log, i)
    
    def create_login_activities_tab(self):
        """Create Login Activities tab"""
        tab3 = tk.Frame(self.notebook, bg='#f9fafb')
        self.notebook.add(tab3, text='Login Activities')
        
        container = tk.Frame(tab3, bg='#f9fafb')
        container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        tk.Label(
            container,
            text="Login Activities (Who accessed what and when)",
            font=('Arial', 18, 'bold'),
            fg='#1f2937',
            bg='#f9fafb'
        ).pack(anchor='w', padx=15, pady=(0, 20))
        
        # Create scrollable frame
        canvas = tk.Canvas(container, bg='#f9fafb', highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient='vertical', command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#f9fafb')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Make scrollable frame expand to full canvas width
        def configure_scroll_region(event):
            canvas.itemconfig(canvas_window, width=event.width)
        
        canvas.bind('<Configure>', configure_scroll_region)
        
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Get login activities
        login_logs = AuditLog.get_login_activities(self.user_email, 20)
        
        if not login_logs:
            tk.Label(scrollable_frame, text="No login activities.", 
                    font=('Arial', 12), bg='#f9fafb', fg='#6b7280').pack(pady=50)
            return
        
        # Display login activities
        for i, log in enumerate(reversed(login_logs)):
            self.create_login_activity_card(scrollable_frame, log, i)
    
    def create_password_operations_tab(self):
        """Create Password Operations tab"""
        tab4 = tk.Frame(self.notebook, bg='#f9fafb')
        self.notebook.add(tab4, text='Password Operations')
        
        container = tk.Frame(tab4, bg='#f9fafb')
        container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Title
        tk.Label(
            container,
            text="Password Operations (What changed in your vault)",
            font=('Arial', 18, 'bold'),
            fg='#1f2937',
            bg='#f9fafb'
        ).pack(anchor='w', padx=15, pady=(0, 20))
        
        # Create scrollable frame
        canvas = tk.Canvas(container, bg='#f9fafb', highlightthickness=0)
        scrollbar = tk.Scrollbar(container, orient='vertical', command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg='#f9fafb')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Make scrollable frame expand to full canvas width
        def configure_scroll_region(event):
            canvas.itemconfig(canvas_window, width=event.width)
        
        canvas.bind('<Configure>', configure_scroll_region)
        
        canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Get password operations
        password_logs = AuditLog.get_password_operations(self.user_email, 20)
        
        if not password_logs:
            tk.Label(scrollable_frame, text="No password operations.", 
                    font=('Arial', 12), bg='#f9fafb', fg='#6b7280').pack(pady=50)
            return
        
        # Display password operations
        for i, log in enumerate(reversed(password_logs)):
            self.create_password_operation_card(scrollable_frame, log, i)
    
    def create_log_card(self, parent, log, index):
        """Create a log card for all activities - FULLY EXTENDED TO RIGHT (MATCHING ERROR ALERTS)"""
        card = tk.Frame(parent, bg='white', relief='solid', bd=1, padx=55, pady=32)
        card.pack(fill='both', expand=True, pady=12, padx=0)
        
        # Event type and timestamp
        event_frame = tk.Frame(card, bg='white')
        event_frame.pack(fill='x', pady=(0, 12))
        
        tk.Label(
            event_frame,
            text=log.get('event_type', 'Unknown').replace('_', ' ').title(),
            font=('Arial', 15, 'bold'),
            fg='#1f2937',
            bg='white'
        ).pack(side='left')
        
        tk.Label(
            event_frame,
            text=log.get('timestamp', ''),
            font=('Arial', 11),
            fg='#6b7280',
            bg='white'
        ).pack(side='right')
        
        # Description
        desc = log.get('description', '')
        if 'User:' in desc and 'Device:' in desc:
            # Format login activities nicely
            parts = desc.split(' | ')
            for part in parts:
                tk.Label(
                    card,
                    text=f"  {part}",
                    font=('Arial', 12),
                    fg='#4b5563',
                    bg='white',
                    justify='left',
                    anchor='w'
                ).pack(fill='x', pady=2)
        else:
            tk.Label(
                card,
                text=desc,
                font=('Arial', 12),
                fg='#4b5563',
                bg='white',
                wraplength=1100,
                justify='left',
                anchor='w'
            ).pack(fill='x', pady=2)
        
        # IP Address display
        ip_address = log.get('ip_address', 'N/A')
        tk.Label(
            card,
            text=f"IP Address: {ip_address}",
            font=('Arial', 11),
            fg='#3b82f6',
            bg='white',
            justify='left',
            anchor='w'
        ).pack(fill='x', pady=(12, 0))
        
        # Severity badge
        severity = log.get('severity', 'INFO')
        severity_color = {
            'INFO': '#10b981',
            'WARNING': '#f59e0b',
            'CRITICAL': '#ef4444'
        }.get(severity, '#6b7280')
        
        severity_frame = tk.Frame(card, bg=severity_color, padx=15, pady=5)
        severity_frame.pack(anchor='e', pady=(12, 0))
        
        tk.Label(
            severity_frame,
            text=severity,
            font=('Arial', 11, 'bold'),
            fg='white',
            bg=severity_color
        ).pack()
    
    def create_error_alert_card(self, parent, log, index):
        """Create error alert card - FULLY EXTENDED TO RIGHT"""
        card = tk.Frame(parent, bg='white', relief='solid', bd=1, padx=55, pady=32)
        card.pack(fill='both', expand=True, pady=12, padx=0)
        
        # Parse description for better display
        description = log.get('description', '')
        
        # Extract main title (before dash)
        if ' - ' in description:
            title, details = description.split(' - ', 1)
        else:
            title = description
            details = ""
        
        # Title
        tk.Label(
            card,
            text=title,
            font=('Arial', 15, 'bold'),
            fg='#1f2937',
            bg='white',
            anchor='w'
        ).pack(fill='x', pady=(0, 12))
        
        # Details
        if details:
            tk.Label(
                card,
                text=details,
                font=('Arial', 12),
                fg='#6b7280',
                bg='white',
                wraplength=1100,
                justify='left',
                anchor='w'
            ).pack(fill='x', pady=(0, 12))
        
        # IP Address
        ip_address = log.get('ip_address', 'N/A')
        tk.Label(
            card,
            text=f"IP Address: {ip_address}",
            font=('Arial', 11),
            fg='#3b82f6',
            bg='white',
            anchor='w'
        ).pack(fill='x', pady=(0, 12))
        
        # Timestamp and severity
        footer = tk.Frame(card, bg='white')
        footer.pack(fill='x')
        
        tk.Label(
            footer,
            text=log.get('timestamp', ''),
            font=('Arial', 11),
            fg='#6b7280',
            bg='white'
        ).pack(side='left')
        
        # Severity badge
        severity = log.get('severity', 'WARNING')
        severity_color = '#ef4444' if severity == 'CRITICAL' else '#f59e0b'
        
        severity_frame = tk.Frame(footer, bg=severity_color, padx=15, pady=5)
        severity_frame.pack(side='right')
        
        tk.Label(
            severity_frame,
            text=severity,
            font=('Arial', 11, 'bold'),
            fg='white',
            bg=severity_color
        ).pack()
    
    def create_login_activity_card(self, parent, log, index):
        """Create login activity card - FULLY EXTENDED TO RIGHT (MATCHING ERROR ALERTS)"""
        card = tk.Frame(parent, bg='white', relief='solid', bd=1, padx=55, pady=32)
        card.pack(fill='both', expand=True, pady=12, padx=0)
        
        # Bullet point and event type
        event_frame = tk.Frame(card, bg='white')
        event_frame.pack(fill='x', pady=(0, 12))
        
        tk.Label(
            event_frame,
            text="•",
            font=('Arial', 18),
            fg='#1f2937',
            bg='white'
        ).pack(side='left')
        
        event_type = log.get('event_type', '')
        if 'SUCCESS' in event_type:
            event_text = "Successful Login"
            color = '#10b981'
        else:
            event_text = "Failed Login Attempt"
            color = '#ef4444'
        
        tk.Label(
            event_frame,
            text=f" {event_text}",
            font=('Arial', 15, 'bold'),
            fg=color,
            bg='white'
        ).pack(side='left', padx=5)
        
        # Parse description
        desc = log.get('description', '')
        
        # Display in formatted way
        if ' | ' in desc:
            lines = desc.split(' | ')
            for line in lines:
                tk.Label(
                    card,
                    text=f"  {line}",
                    font=('Arial', 12),
                    fg='#4b5563',
                    bg='white',
                    justify='left',
                    anchor='w'
                ).pack(fill='x', padx=25, pady=2)
        else:
            tk.Label(
                card,
                text=f"  {desc}",
                font=('Arial', 12),
                fg='#4b5563',
                bg='white',
                justify='left',
                anchor='w'
            ).pack(fill='x', padx=25, pady=2)
        
        # IP Address
        ip_address = log.get('ip_address', 'N/A')
        tk.Label(
            card,
            text=f"IP Address: {ip_address}",
            font=('Arial', 11),
            fg='#3b82f6',
            bg='white',
            anchor='w'
        ).pack(fill='x', padx=25, pady=(12, 0))
    
    def create_password_operation_card(self, parent, log, index):
        """Create password operation card - FULLY EXTENDED TO RIGHT (MATCHING ERROR ALERTS)"""
        card = tk.Frame(parent, bg='white', relief='solid', bd=1, padx=55, pady=32)
        card.pack(fill='both', expand=True, pady=12, padx=0)
        
        # Bullet point and event type
        event_frame = tk.Frame(card, bg='white')
        event_frame.pack(fill='x', pady=(0, 12))
        
        tk.Label(
            event_frame,
            text="•",
            font=('Arial', 18),
            fg='#1f2937',
            bg='white'
        ).pack(side='left')
        
        event_type = log.get('event_type', '')
        if 'ADDED' in event_type:
            event_text = "Password Added"
            color = '#10b981'
        elif 'VIEWED' in event_type:
            event_text = "Password Viewed"
            color = '#f59e0b'
        elif 'DELETED' in event_type:
            event_text = "Password Deleted"
            color = '#ef4444'
        else:
            event_text = "Password Edited"
            color = '#3b82f6'
        
        tk.Label(
            event_frame,
            text=f" {event_text}",
            font=('Arial', 15, 'bold'),
            fg=color,
            bg='white'
        ).pack(side='left', padx=5)
        
        # Parse description
        desc = log.get('description', '')
        
        # Display in formatted way
        if ' | ' in desc:
            lines = desc.split(' | ')
            for line in lines:
                tk.Label(
                    card,
                    text=f"  {line}",
                    font=('Arial', 12),
                    fg='#4b5563',
                    bg='white',
                    justify='left',
                    anchor='w'
                ).pack(fill='x', padx=25, pady=2)
        else:
            tk.Label(
                card,
                text=f"  {desc}",
                font=('Arial', 12),
                fg='#4b5563',
                bg='white',
                justify='left',
                anchor='w'
            ).pack(fill='x', padx=25, pady=2)
        
        # IP Address
        ip_address = log.get('ip_address', 'N/A')
        tk.Label(
            card,
            text=f"IP Address: {ip_address}",
            font=('Arial', 11),
            fg='#3b82f6',
            bg='white',
            anchor='w'
        ).pack(fill='x', padx=25, pady=(12, 0))
