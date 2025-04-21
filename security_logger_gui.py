import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import sys
import os
import json
import psutil
import platform
import threading
import time
from datetime import datetime
from typing import Optional, List
from cryptography.fernet import Fernet
import dotenv
from ttkthemes import ThemedTk
import re

class ThemeManager:
    def __init__(self, root):
        self.root = root
        self.is_dark_mode = True  # Start with dark mode by default
        
        # Define color schemes
        self.light_theme = {
            'bg': '#ffffff',
            'fg': '#000000',
            'select_bg': '#0078d7',
            'select_fg': '#ffffff',
            'button_bg': '#f0f0f0',
            'entry_bg': '#ffffff',
            'frame_bg': '#f5f5f5',
            'accent': '#0078d7'
        }
        
        self.dark_theme = {
            'bg': '#1e1e1e',
            'fg': '#ffffff',
            'select_bg': '#0078d7',
            'select_fg': '#ffffff',
            'button_bg': '#333333',
            'entry_bg': '#2d2d2d',
            'frame_bg': '#252526',
            'accent': '#0078d7'
        }
    
    def toggle_theme(self):
        self.is_dark_mode = not self.is_dark_mode
        theme = self.dark_theme if self.is_dark_mode else self.light_theme
        
        style = ttk.Style()
        
        # Configure main theme colors
        style.configure('.',
            background=theme['bg'],
            foreground=theme['fg'],
            fieldbackground=theme['entry_bg'],
            selectbackground=theme['select_bg'],
            selectforeground=theme['select_fg'])
            
        # Configure specific elements
        style.configure('TFrame', background=theme['frame_bg'])
        style.configure('TLabel', background=theme['frame_bg'], foreground=theme['fg'])
        style.configure('TButton', background=theme['button_bg'], foreground=theme['fg'])
        style.configure('Accent.TButton', background=theme['accent'], foreground='white')
        style.configure('TEntry', fieldbackground=theme['entry_bg'], foreground=theme['fg'])
        style.configure('TCombobox', fieldbackground=theme['entry_bg'], foreground=theme['fg'])
        style.configure('TNotebook', background=theme['frame_bg'])
        style.configure('TNotebook.Tab', background=theme['button_bg'], foreground=theme['fg'])
        
        # Configure Treeview
        style.configure('Treeview',
            background=theme['entry_bg'],
            foreground=theme['fg'],
            fieldbackground=theme['entry_bg'])
        style.configure('Treeview.Heading', background=theme['button_bg'], foreground=theme['fg'])
        
        # Update scrolled text widgets
        for widget in self.root.winfo_children():
            if isinstance(widget, scrolledtext.ScrolledText):
                widget.configure(bg=theme['entry_bg'], fg=theme['fg'])

class SystemMonitor:
    def __init__(self, callback):
        self.running = False
        self.monitor_thread = None
        self.monitored_processes = set()
        self.callback = callback
        self.system_events = {
            'process_creation': True,
            'process_termination': True,
            'file_access': True,
            'network_activity': True,
            'system_call': True
        }
        
    def start_monitoring(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_system)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_monitoring(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join()
            
    def _monitor_system(self):
        while self.running:
            try:
                # Monitor process creation and termination
                current_processes = set(p.pid for p in psutil.process_iter(['pid']))
                new_processes = current_processes - self.monitored_processes
                terminated_processes = self.monitored_processes - current_processes
                
                for pid in new_processes:
                    if self.system_events['process_creation']:
                        try:
                            process = psutil.Process(pid)
                            self.callback({
                                'timestamp': datetime.now().isoformat(),
                                'event_type': 'Process Creation',
                                'severity': 'Medium',
                                'description': f'New process created: {process.name()} (PID: {pid})',
                                'source': 'System Monitor',
                                'user': process.username(),
                                'ip_address': None
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                            
                for pid in terminated_processes:
                    if self.system_events['process_termination']:
                        self.callback({
                            'timestamp': datetime.now().isoformat(),
                            'event_type': 'Process Termination',
                            'severity': 'Low',
                            'description': f'Process terminated (PID: {pid})',
                            'source': 'System Monitor',
                            'user': None,
                            'ip_address': None
                        })
                
                self.monitored_processes = current_processes
                
                # Monitor network activity
                if self.system_events['network_activity']:
                    connections = psutil.net_connections()
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            self.callback({
                                'timestamp': datetime.now().isoformat(),
                                'event_type': 'Network Connection',
                                'severity': 'Medium',
                                'description': f'Network connection established: {conn.laddr.ip}:{conn.laddr.port} -> {conn.raddr.ip}:{conn.raddr.port}',
                                'source': 'System Monitor',
                                'user': None,
                                'ip_address': conn.raddr.ip
                            })
                
                time.sleep(1)  # Adjust monitoring frequency
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(5)

class SecurityEvent:
    def __init__(self, timestamp, event_type, severity, description, source, user=None, ip_address=None):
        self.timestamp = timestamp
        self.event_type = event_type
        self.severity = severity
        self.description = description
        self.source = source
        self.user = user
        self.ip_address = ip_address

class SecurityLogger:
    def __init__(self):
        self.log_file = "security_logs.json"
        self.encryption_key = self._get_or_create_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.system_monitor = SystemMonitor(self.handle_system_event)
        
    def _get_or_create_key(self) -> bytes:
        """Get encryption key from .env or create a new one"""
        dotenv.load_dotenv()
        key = os.getenv("ENCRYPTION_KEY")
        
        if not key:
            key = Fernet.generate_key().decode()
            with open(".env", "w") as f:
                f.write(f"ENCRYPTION_KEY={key}")
        else:
            key = key.encode()
            
        return key

    def _encrypt_data(self, data: str) -> bytes:
        """Encrypt the log data"""
        return self.cipher_suite.encrypt(data.encode())

    def _decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt the log data"""
        return self.cipher_suite.decrypt(encrypted_data).decode()

    def log_event(self, event: SecurityEvent):
        """Log a security event"""
        event_dict = {
            "timestamp": event.timestamp.isoformat() if isinstance(event.timestamp, datetime) else event.timestamp,
            "event_type": event.event_type,
            "severity": event.severity,
            "description": event.description,
            "source": event.source,
            "user": event.user,
            "ip_address": event.ip_address
        }
        
        # Read existing logs
        logs = []
        if os.path.exists(self.log_file):
            with open(self.log_file, "rb") as f:
                encrypted_data = f.read()
                if encrypted_data:
                    decrypted_data = self._decrypt_data(encrypted_data)
                    logs = json.loads(decrypted_data)
        
        # Add new log
        logs.append(event_dict)
        
        # Write encrypted logs
        with open(self.log_file, "wb") as f:
            encrypted_data = self._encrypt_data(json.dumps(logs))
            f.write(encrypted_data)

    def get_logs(self):
        """Get all logs"""
        if not os.path.exists(self.log_file):
            return []
            
        with open(self.log_file, "rb") as f:
            encrypted_data = f.read()
            if not encrypted_data:
                return []
                
            decrypted_data = self._decrypt_data(encrypted_data)
            return json.loads(decrypted_data)
            
    def handle_system_event(self, event_data):
        event = SecurityEvent(
            timestamp=event_data['timestamp'],
            event_type=event_data['event_type'],
            severity=event_data['severity'],
            description=event_data['description'],
            source=event_data['source'],
            user=event_data.get('user'),
            ip_address=event_data.get('ip_address')
        )
        self.log_event(event)

    def search_logs(self, search_term: str, severity: str = None, event_type: str = None) -> list:
        """Search logs with filters"""
        logs = self.get_logs()
        filtered_logs = []
        
        for log in logs:
            # Apply search term
            if search_term.lower() in json.dumps(log).lower():
                # Apply filters
                if severity and log['severity'] != severity:
                    continue
                if event_type and log['event_type'] != event_type:
                    continue
                filtered_logs.append(log)
                
        return filtered_logs

class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Real-Time OS Security Event Logger")
        self.root.geometry("1200x800")
        
        # Sleek modern colors
        self.bg_dark = "#1a1a1a"      # Darker background
        self.bg_color = "#242424"      # Main background
        self.fg_color = "#e0e0e0"      # Softer white text
        self.input_bg = "#2d2d2d"      # Input background
        self.accent_color = "#4cc2ff"  # Vibrant blue
        self.hover_color = "#363636"   # Subtle hover
        self.border_color = "#363636"  # Subtle borders
        self.active_tab = "#4cc2ff"    # Active tab indicator
        
        # Configure root window
        self.root.configure(bg=self.bg_dark)
        
        # Configure ttk styles
        self.style = ttk.Style()
        self.style.theme_use('default')
        
        # Common styles
        self.style.configure(".", 
            background=self.bg_color,
            foreground=self.fg_color,
            troughcolor=self.bg_dark,
            selectbackground=self.accent_color,
            selectforeground=self.bg_dark,
            fieldbackground=self.input_bg,
            font=('Segoe UI', 10),
            borderwidth=0)
            
        # Frame styles
        self.style.configure("TFrame",
            background=self.bg_color)
            
        self.style.configure("Card.TFrame",
            background=self.bg_color,
            relief="flat")
            
        # LabelFrame styles
        self.style.configure("TLabelframe",
            background=self.bg_color,
            relief="flat")
            
        self.style.configure("TLabelframe.Label",
            background=self.bg_color,
            foreground=self.fg_color,
            font=('Segoe UI Semibold', 11),
            padding=(5, 5))
            
        # Button styles
        self.style.configure("TButton",
            background=self.input_bg,
            foreground=self.fg_color,
            padding=(20, 10),
            font=('Segoe UI', 10),
            relief="flat",
            borderwidth=0)
            
        self.style.map("TButton",
            background=[
                ("pressed", self.accent_color),
                ("active", self.hover_color)
            ],
            foreground=[
                ("pressed", self.bg_dark),
                ("active", self.fg_color)
            ])
            
        self.style.configure("Accent.TButton",
            background=self.accent_color,
            foreground=self.bg_dark)
            
        self.style.map("Accent.TButton",
            background=[
                ("pressed", self.accent_color),
                ("active", "#5ccfff")  # Slightly lighter on hover
            ],
            foreground=[("pressed", self.bg_dark)])
            
        # Entry styles
        self.style.configure("TEntry",
            fieldbackground=self.input_bg,
            foreground=self.fg_color,
            padding=(12, 8),
            font=('Segoe UI', 10))
            
        # Combobox styles
        self.style.configure("TCombobox",
            background=self.input_bg,
            fieldbackground=self.input_bg,
            foreground=self.fg_color,
            arrowcolor=self.fg_color,
            padding=(12, 8),
            font=('Segoe UI', 10))
            
        self.style.map("TCombobox",
            fieldbackground=[("readonly", self.input_bg)],
            selectbackground=[("readonly", self.input_bg)])
            
        # Notebook styles
        self.style.configure("TNotebook",
            background=self.bg_dark,
            borderwidth=0)
            
        self.style.configure("TNotebook.Tab",
            background=self.bg_color,
            foreground=self.fg_color,
            padding=(25, 10),
            font=('Segoe UI', 10),
            borderwidth=0)
            
        self.style.map("TNotebook.Tab",
            background=[
                ("selected", self.bg_color),
                ("active", self.hover_color)
            ],
            foreground=[
                ("selected", self.accent_color),
                ("active", self.fg_color)
            ],
            expand=[("selected", [0, 0, 0, 2])])  # Bottom border for selected tab
            
        # Treeview styles
        self.style.configure("Treeview",
            background=self.input_bg,
            foreground=self.fg_color,
            fieldbackground=self.input_bg,
            font=('Segoe UI', 10),
            borderwidth=0,
            rowheight=35)
            
        self.style.configure("Treeview.Heading",
            background=self.bg_color,
            foreground=self.fg_color,
            font=('Segoe UI Semibold', 10),
            relief="flat",
            padding=15)
            
        self.style.map("Treeview",
            background=[
                ("selected", self.accent_color),
                ("active", self.hover_color)
            ],
            foreground=[("selected", self.bg_dark)])
            
        self.style.map("Treeview.Heading",
            background=[("active", self.hover_color)])
        
        self.logger = SecurityLogger()
        
        # Create main container
        self.main_container = ttk.Frame(self.root, style="Card.TFrame")
        self.main_container.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Create notebook
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(expand=True, fill='both')
        
        # Create tabs
        self.log_tab = ttk.Frame(self.notebook, style="Card.TFrame", padding=25)
        self.view_tab = ttk.Frame(self.notebook, style="Card.TFrame", padding=25)
        self.monitor_tab = ttk.Frame(self.notebook, style="Card.TFrame", padding=25)
        self.stats_tab = ttk.Frame(self.notebook, style="Card.TFrame", padding=25)
        
        self.notebook.add(self.log_tab, text="Log Event")
        self.notebook.add(self.view_tab, text="View Logs")
        self.notebook.add(self.monitor_tab, text="System Monitor")
        self.notebook.add(self.stats_tab, text="Statistics")
        
        # Setup tabs
        self.setup_log_tab()
        self.setup_view_tab()
        self.setup_monitor_tab()
        self.setup_stats_tab()
        
        # Status bar
        status_frame = ttk.Frame(self.root, style="Card.TFrame")
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=(0, 20))
        
        self.status_bar = ttk.Label(
            status_frame,
            text="Ready",
            background=self.bg_color,
            foreground=self.fg_color,
            font=('Segoe UI', 9),
            padding=(20, 10))
        self.status_bar.pack(fill=tk.X)
        
        # Start monitoring
        self.logger.system_monitor.start_monitoring()
        
        # Bind events
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.setup_auto_refresh()

    def setup_log_tab(self):
        # Create form frame
        form_frame = ttk.LabelFrame(
            self.log_tab,
            text="Event Details",
            padding=25)
        form_frame.pack(fill='x')
        
        # Grid layout
        pad = 15  # Consistent padding
        
        # Event Type
        ttk.Label(
            form_frame,
            text="Event Type:",
            background=self.bg_color,
            foreground=self.fg_color,
            font=('Segoe UI', 10)
        ).grid(row=0, column=0, sticky='e', padx=pad, pady=pad)
        
        self.event_type = ttk.Entry(form_frame, width=40)
        self.event_type.grid(row=0, column=1, sticky='w', padx=pad, pady=pad)
        
        # Severity
        ttk.Label(
            form_frame,
            text="Severity:",
            background=self.bg_color,
            foreground=self.fg_color,
            font=('Segoe UI', 10)
        ).grid(row=1, column=0, sticky='e', padx=pad, pady=pad)
        
        self.severity = ttk.Combobox(
            form_frame,
            values=["Low", "Medium", "High", "Critical"],
            width=37,
            state="readonly")
        self.severity.grid(row=1, column=1, sticky='w', padx=pad, pady=pad)
        self.severity.set("Medium")
        
        # Description
        ttk.Label(
            form_frame,
            text="Description:",
            background=self.bg_color,
            foreground=self.fg_color,
            font=('Segoe UI', 10)
        ).grid(row=2, column=0, sticky='ne', padx=pad, pady=pad)
        
        self.description = tk.Text(
            form_frame,
            height=5,
            width=50,
            bg=self.input_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            relief="flat",
            font=('Segoe UI', 10),
            wrap=tk.WORD,
            padx=12,
            pady=8)
        self.description.grid(row=2, column=1, sticky='w', padx=pad, pady=pad)
        
        # Buttons frame
        button_frame = ttk.Frame(form_frame, style="Card.TFrame")
        button_frame.grid(row=3, column=0, columnspan=2, pady=(25, 0))
        
        # Log Button
        log_button = ttk.Button(
            button_frame,
            text="Log Event",
            command=self.log_event,
            style="Accent.TButton")
        log_button.pack(side=tk.LEFT, padx=5)
        
        # Clear Button
        clear_button = ttk.Button(
            button_frame,
            text="Clear Form",
            command=self.clear_form)
        clear_button.pack(side=tk.LEFT, padx=5)

    def setup_view_tab(self):
        # Search and filter frame
        search_frame = ttk.Frame(self.view_tab)
        search_frame.pack(fill='x', padx=5, pady=5)
        
        # Search entry
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        
        # Severity filter
        ttk.Label(search_frame, text="Severity:").pack(side=tk.LEFT, padx=5)
        self.severity_filter = ttk.Combobox(search_frame, values=["All", "Low", "Medium", "High", "Critical"], width=10)
        self.severity_filter.set("All")
        self.severity_filter.pack(side=tk.LEFT, padx=5)
        
        # Search button
        search_button = ttk.Button(search_frame, text="Search", command=self.search_logs)
        search_button.pack(side=tk.LEFT, padx=5)
        
        # Create treeview with scrollbars
        tree_frame = ttk.Frame(self.view_tab)
        tree_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create treeview
        self.tree = ttk.Treeview(tree_frame, columns=("Timestamp", "Event Type", "Severity", "Description", "Source", "User", "IP Address"))
        
        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Column headings
        self.tree.heading("#0", text="ID")
        self.tree.heading("Timestamp", text="Timestamp")
        self.tree.heading("Event Type", text="Event Type")
        self.tree.heading("Severity", text="Severity")
        self.tree.heading("Description", text="Description")
        self.tree.heading("Source", text="Source")
        self.tree.heading("User", text="User")
        self.tree.heading("IP Address", text="IP Address")
        
        # Column widths
        self.tree.column("#0", width=50)
        self.tree.column("Timestamp", width=150)
        self.tree.column("Event Type", width=100)
        self.tree.column("Severity", width=70)
        self.tree.column("Description", width=300)
        self.tree.column("Source", width=100)
        self.tree.column("User", width=100)
        self.tree.column("IP Address", width=100)
        
        # Pack treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        # Configure grid weights
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Buttons frame
        button_frame = ttk.Frame(self.view_tab)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        # Refresh button
        refresh_button = ttk.Button(button_frame, text="Refresh", command=self.refresh_logs)
        refresh_button.pack(side=tk.LEFT, padx=5)
        
        # Export button
        export_button = ttk.Button(button_frame, text="Export Logs", command=self.export_logs)
        export_button.pack(side=tk.LEFT, padx=5)

    def setup_monitor_tab(self):
        # System Information
        info_frame = ttk.LabelFrame(self.monitor_tab, text="System Information", padding=10)
        info_frame.pack(fill='x', padx=5, pady=5)
        
        # OS Info with icon
        os_info = ttk.Label(info_frame, text=f"Operating System: {platform.system()} {platform.release()}")
        os_info.pack(anchor='w', padx=5, pady=2)
        
        # CPU Info with usage
        cpu_frame = ttk.Frame(info_frame)
        cpu_frame.pack(fill='x', padx=5, pady=2)
        
        cpu_info = ttk.Label(cpu_frame, text=f"CPU: {platform.processor()}")
        cpu_info.pack(side=tk.LEFT)
        
        self.cpu_usage = ttk.Label(cpu_frame, text="Usage: 0%")
        self.cpu_usage.pack(side=tk.RIGHT)
        
        # Memory Info with bar
        memory = psutil.virtual_memory()
        memory_frame = ttk.Frame(info_frame)
        memory_frame.pack(fill='x', padx=5, pady=2)
        
        memory_info = ttk.Label(memory_frame, text=f"Memory: {memory.total / (1024**3):.2f} GB Total")
        memory_info.pack(side=tk.LEFT)
        
        self.memory_usage = ttk.Label(memory_frame, text=f"Used: {memory.percent}%")
        self.memory_usage.pack(side=tk.RIGHT)
        
        # Monitoring Options
        monitor_frame = ttk.LabelFrame(self.monitor_tab, text="Monitoring Options", padding=10)
        monitor_frame.pack(fill='x', padx=5, pady=5)
        
        # Variables
        self.process_creation_var = tk.BooleanVar(value=True)
        self.process_termination_var = tk.BooleanVar(value=True)
        self.network_activity_var = tk.BooleanVar(value=True)
        
        # Checkbuttons with icons
        ttk.Checkbutton(monitor_frame, text="Monitor Process Creation", variable=self.process_creation_var).pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(monitor_frame, text="Monitor Process Termination", variable=self.process_termination_var).pack(anchor='w', padx=5, pady=2)
        ttk.Checkbutton(monitor_frame, text="Monitor Network Activity", variable=self.network_activity_var).pack(anchor='w', padx=5, pady=2)
        
        # Active Processes
        processes_frame = ttk.LabelFrame(self.monitor_tab, text="Active Processes", padding=10)
        processes_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Process treeview
        self.process_tree = ttk.Treeview(processes_frame, columns=("PID", "Name", "CPU", "Memory", "Status"))
        self.process_tree.heading("#0", text="")
        self.process_tree.heading("PID", text="PID")
        self.process_tree.heading("Name", text="Process Name")
        self.process_tree.heading("CPU", text="CPU %")
        self.process_tree.heading("Memory", text="Memory %")
        self.process_tree.heading("Status", text="Status")
        
        # Process scrollbar
        process_vsb = ttk.Scrollbar(processes_frame, orient="vertical", command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=process_vsb.set)
        
        # Pack process tree and scrollbar
        self.process_tree.pack(side=tk.LEFT, fill='both', expand=True)
        process_vsb.pack(side=tk.RIGHT, fill='y')
        
        # Buttons
        button_frame = ttk.Frame(self.monitor_tab)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(button_frame, text="Apply Settings", command=self.apply_monitoring_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh Processes", command=self.refresh_processes).pack(side=tk.LEFT, padx=5)

    def setup_stats_tab(self):
        # Statistics frame
        stats_frame = ttk.LabelFrame(self.stats_tab, text="Security Event Statistics", padding=10)
        stats_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create statistics labels
        self.total_events_label = ttk.Label(stats_frame, text="Total Events: 0")
        self.total_events_label.pack(anchor='w', padx=5, pady=2)
        
        self.severity_stats_label = ttk.Label(stats_frame, text="Events by Severity:")
        self.severity_stats_label.pack(anchor='w', padx=5, pady=2)
        
        self.type_stats_label = ttk.Label(stats_frame, text="Events by Type:")
        self.type_stats_label.pack(anchor='w', padx=5, pady=2)
        
        # Refresh button
        ttk.Button(self.stats_tab, text="Refresh Statistics", command=self.update_statistics).pack(pady=10)

    def setup_auto_refresh(self):
        """Setup automatic refresh of dynamic content"""
        def update():
            if self.notebook.select() == self.notebook.tabs()[1]:  # View Logs tab
                self.refresh_logs()
            elif self.notebook.select() == self.notebook.tabs()[2]:  # Monitor tab
                self.update_system_info()
            self.root.after(5000, update)  # Update every 5 seconds
        
        self.root.after(5000, update)

    def update_system_info(self):
        """Update system information in monitor tab"""
        # Update CPU usage
        cpu_percent = psutil.cpu_percent()
        self.cpu_usage.config(text=f"Usage: {cpu_percent}%")
        
        # Update memory usage
        memory = psutil.virtual_memory()
        self.memory_usage.config(text=f"Used: {memory.percent}%")
        
        # Update process list
        self.refresh_processes()

    def refresh_processes(self):
        """Refresh the process list"""
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Add current processes
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            try:
                info = proc.info
                self.process_tree.insert("", "end", values=(
                    info['pid'],
                    info['name'],
                    f"{info['cpu_percent']:.1f}",
                    f"{info['memory_percent']:.1f}",
                    info['status']
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def update_statistics(self):
        """Update statistics in stats tab"""
        logs = self.logger.get_logs()
        
        # Update total events
        self.total_events_label.config(text=f"Total Events: {len(logs)}")
        
        # Count events by severity
        severity_counts = {}
        for log in logs:
            severity = log['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        severity_stats = "Events by Severity:\n" + "\n".join(f"  {k}: {v}" for k, v in severity_counts.items())
        self.severity_stats_label.config(text=severity_stats)
        
        # Count events by type
        type_counts = {}
        for log in logs:
            event_type = log['event_type']
            type_counts[event_type] = type_counts.get(event_type, 0) + 1
        
        type_stats = "Events by Type:\n" + "\n".join(f"  {k}: {v}" for k, v in type_counts.items())
        self.type_stats_label.config(text=type_stats)

    def search_logs(self):
        """Search logs with filters"""
        search_term = self.search_entry.get()
        severity = self.severity_filter.get()
        severity = None if severity == "All" else severity
        
        logs = self.logger.search_logs(search_term, severity)
        self.update_log_tree(logs)

    def update_log_tree(self, logs):
        """Update the log tree with the given logs"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Add new items
        for i, log in enumerate(logs):
            item = self.tree.insert("", "end", text=str(i+1), values=(
                log["timestamp"],
                log["event_type"],
                log["severity"],
                log["description"],
                log["source"],
                log.get("user", "N/A"),
                log.get("ip_address", "N/A")
            ))
            
            # Apply severity-based styling
            if log["severity"] == "Critical":
                self.tree.tag_configure(item, background="red", foreground="white")
            elif log["severity"] == "High":
                self.tree.tag_configure(item, background="orange")
            elif log["severity"] == "Medium":
                self.tree.tag_configure(item, background="yellow")
            elif log["severity"] == "Low":
                self.tree.tag_configure(item, background="lightgreen")

    def export_logs(self):
        """Export logs to a file"""
        logs = self.logger.get_logs()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_logs_{timestamp}.json"
        
        try:
            with open(filename, "w") as f:
                json.dump(logs, f, indent=2)
            messagebox.showinfo("Success", f"Logs exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export logs: {e}")

    def apply_monitoring_settings(self):
        """Apply monitoring settings"""
        self.logger.system_monitor.system_events['process_creation'] = self.process_creation_var.get()
        self.logger.system_monitor.system_events['process_termination'] = self.process_termination_var.get()
        self.logger.system_monitor.system_events['network_activity'] = self.network_activity_var.get()
        messagebox.showinfo("Success", "Monitoring settings updated!")

    def clear_form(self):
        """Clear all form fields"""
        self.event_type.delete(0, tk.END)
        self.description.delete("1.0", tk.END)
        self.source.delete(0, tk.END)
        self.user.delete(0, tk.END)
        self.ip_address.delete(0, tk.END)
        self.severity.set("Medium")

    def log_event(self):
        # Validate required fields
        if not self.event_type.get() or not self.description.get("1.0", tk.END).strip() or not self.source.get():
            messagebox.showerror("Error", "Please fill in all required fields!")
            return
            
        # Create event
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type=self.event_type.get(),
            severity=self.severity.get(),
            description=self.description.get("1.0", tk.END).strip(),
            source=self.source.get(),
            user=self.user.get() or None,
            ip_address=self.ip_address.get() or None
        )
        
        # Log event
        self.logger.log_event(event)
        
        # Clear fields
        self.event_type.delete(0, tk.END)
        self.description.delete("1.0", tk.END)
        self.source.delete(0, tk.END)
        self.user.delete(0, tk.END)
        self.ip_address.delete(0, tk.END)
        
        messagebox.showinfo("Success", "Event logged successfully!")

    def refresh_logs(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Add new items
        logs = self.logger.get_logs()
        for i, log in enumerate(logs):
            self.tree.insert("", "end", text=str(i+1), values=(
                log["timestamp"],
                log["event_type"],
                log["severity"],
                log["description"],
                log["source"],
                log.get("user", "N/A"),
                log.get("ip_address", "N/A")
            ))

    def on_tab_change(self, event):
        if self.notebook.select() == self.notebook.tabs()[1]:  # View Logs tab
            self.refresh_logs()

    def on_closing(self):
        self.logger.system_monitor.stop_monitoring()
        self.root.destroy()

    def run(self):
        self.root.mainloop()

def main():
    app = MainWindow()
    app.run()

if __name__ == "__main__":
    main() 