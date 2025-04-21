# Security Logging System

A Python-based security event logging system that provides secure storage and viewing of security events.

## Features

- Secure encryption of log data using Fernet (symmetric encryption)
- Beautiful console interface using Rich
- Structured event logging with timestamps
- Optional user and IP address tracking
- Severity levels for events
- Easy-to-use command-line interface

## Installation

1. Clone this repository
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python security_logger.py
```

The application provides the following options:
1. Log new event - Record a new security event
2. View all logs - Display all logged events in a table format
3. Exit - Close the application

## Security Features

- All logs are encrypted using Fernet encryption
- Encryption key is stored in a .env file
- Automatic key generation if not present
- Secure storage of sensitive information

## Event Fields

- Timestamp (automatically generated)
- Event Type (user-defined)
- Severity (Low, Medium, High, Critical)
- Description
- Source
- User (optional)
- IP Address (optional)

## Example Usage

1. Start the application
2. Choose option 1 to log a new event
3. Enter the event details:
   - Event Type: "Login Attempt"
   - Severity: "High"
   - Description: "Multiple failed login attempts"
   - Source: "Web Application"
   - User: "admin"
   - IP Address: "192.168.1.1"
4. View the logs using option 2

## Note

Keep your .env file secure as it contains the encryption key. Without this key, you cannot decrypt and view the logs. 