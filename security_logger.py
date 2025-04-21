import os
import json
from datetime import datetime
from typing import Optional
from pathlib import Path
from cryptography.fernet import Fernet
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from pydantic import BaseModel
import dotenv

# Initialize rich console
console = Console()

class SecurityEvent(BaseModel):
    timestamp: datetime
    event_type: str
    severity: str
    description: str
    source: str
    user: Optional[str] = None
    ip_address: Optional[str] = None

class SecurityLogger:
    def __init__(self):
        self.log_file = "security_logs.json"
        self.encryption_key = self._get_or_create_key()
        self.cipher_suite = Fernet(self.encryption_key)
        
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
        event_dict = event.model_dump()
        event_dict["timestamp"] = event_dict["timestamp"].isoformat()
        
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
            
        console.print(f"[green]Event logged successfully![/green]")

    def view_logs(self):
        """Display all security logs in a table"""
        if not os.path.exists(self.log_file):
            console.print("[red]No logs found![/red]")
            return
            
        with open(self.log_file, "rb") as f:
            encrypted_data = f.read()
            if not encrypted_data:
                console.print("[red]No logs found![/red]")
                return
                
            decrypted_data = self._decrypt_data(encrypted_data)
            logs = json.loads(decrypted_data)
            
        table = Table(title="Security Logs")
        table.add_column("Timestamp", style="cyan")
        table.add_column("Event Type", style="magenta")
        table.add_column("Severity", style="red")
        table.add_column("Description", style="green")
        table.add_column("Source", style="blue")
        table.add_column("User", style="yellow")
        table.add_column("IP Address", style="yellow")
        
        for log in logs:
            table.add_row(
                log["timestamp"],
                log["event_type"],
                log["severity"],
                log["description"],
                log["source"],
                log.get("user", "N/A"),
                log.get("ip_address", "N/A")
            )
            
        console.print(table)

def main():
    logger = SecurityLogger()
    
    while True:
        console.print("\n[bold]Security Logging System[/bold]")
        console.print("1. Log new event")
        console.print("2. View all logs")
        console.print("3. Exit")
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3"])
        
        if choice == "1":
            event_type = Prompt.ask("Event type")
            severity = Prompt.ask("Severity", choices=["Low", "Medium", "High", "Critical"])
            description = Prompt.ask("Description")
            source = Prompt.ask("Source")
            user = Prompt.ask("User (optional)", default="")
            ip_address = Prompt.ask("IP Address (optional)", default="")
            
            event = SecurityEvent(
                timestamp=datetime.now(),
                event_type=event_type,
                severity=severity,
                description=description,
                source=source,
                user=user if user else None,
                ip_address=ip_address if ip_address else None
            )
            
            logger.log_event(event)
            
        elif choice == "2":
            logger.view_logs()
            
        elif choice == "3":
            console.print("[yellow]Exiting...[/yellow]")
            break

if __name__ == "__main__":
    main() 