from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from datetime import datetime
import json
import os
from cryptography.fernet import Fernet
import psutil
import platform
from functools import wraps, lru_cache
import dotenv
import socket
import time
from collections import deque
from threading import Lock

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management and flash messages

# Cache configuration
CACHE_DURATION = 2  # seconds
last_system_info_update = 0
last_system_info = None
system_info_lock = Lock()

# Add template filter for severity class
@app.template_filter('severity_class')
def severity_class(severity):
    if severity == 'Critical':
        return 'bg-red-900 text-red-200'
    elif severity == 'High':
        return 'bg-orange-900 text-orange-200'
    elif severity == 'Medium':
        return 'bg-yellow-900 text-yellow-200'
    else:
        return 'bg-green-900 text-green-200'

# Network speed monitoring with optimized data collection
class NetworkMonitor:
    def __init__(self, history_size=60):
        self.history_size = history_size
        self.upload_history = deque(maxlen=history_size)
        self.download_history = deque(maxlen=history_size)
        self.last_bytes = None
        self.last_time = None
        self.lock = Lock()
        self.cache = {'speeds': None, 'last_update': 0}
        self.cache_duration = 0.5  # 500ms cache duration
        
    def update(self):
        with self.lock:
            current_time = time.time()
            current_bytes = psutil.net_io_counters()
            
            if self.last_bytes is not None and self.last_time is not None:
                time_delta = current_time - self.last_time
                
                # Calculate speeds in bytes per second
                upload_speed = (current_bytes.bytes_sent - self.last_bytes.bytes_sent) / time_delta
                download_speed = (current_bytes.bytes_recv - self.last_bytes.bytes_recv) / time_delta
                
                self.upload_history.append(upload_speed)
                self.download_history.append(download_speed)
            
            self.last_bytes = current_bytes
            self.last_time = current_time
        
    def get_speeds(self):
        current_time = time.time()
        
        # Return cached data if within cache duration
        if self.cache['speeds'] and (current_time - self.cache['last_update']) < self.cache_duration:
            return self.cache['speeds']
            
        with self.lock:
            if not self.upload_history or not self.download_history:
                result = {
                    'upload': 0,
                    'download': 0,
                    'max_upload': 1,
                    'max_download': 1
                }
            else:
                result = {
                    'upload': self.upload_history[-1],
                    'download': self.download_history[-1],
                    'max_upload': max(self.upload_history),
                    'max_download': max(self.download_history)
                }
            
            # Update cache
            self.cache['speeds'] = result
            self.cache['last_update'] = current_time
            
            return result

# Initialize network monitor
network_monitor = NetworkMonitor()

class SecurityLogger:
    def __init__(self):
        self.log_file = "security_logs.json"
        self.encryption_key = self._get_or_create_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.cache = {'logs': None, 'last_update': 0}
        self.cache_duration = 5  # 5 seconds cache duration
        self.lock = Lock()
        
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

    def _read_logs(self):
        """Read and cache logs"""
        current_time = time.time()
        
        # Return cached logs if within cache duration
        if self.cache['logs'] and (current_time - self.cache['last_update']) < self.cache_duration:
            return self.cache['logs']
            
        with self.lock:
            if not os.path.exists(self.log_file):
                logs = []
            else:
                with open(self.log_file, "rb") as f:
                    encrypted_data = f.read()
                    if encrypted_data:
                        decrypted_data = self._decrypt_data(encrypted_data)
                        logs = json.loads(decrypted_data)
                    else:
                        logs = []
            
            # Update cache
            self.cache['logs'] = logs
            self.cache['last_update'] = current_time
            
            return logs

    def log_event(self, event_data: dict):
        """Log a security event"""
        event_data["timestamp"] = datetime.now().isoformat()
        
        with self.lock:
            logs = self._read_logs()
            logs.append(event_data)
            
            # Write encrypted logs
            with open(self.log_file, "wb") as f:
                encrypted_data = self._encrypt_data(json.dumps(logs))
                f.write(encrypted_data)
            
            # Update cache
            self.cache['logs'] = logs
            self.cache['last_update'] = time.time()

    def get_logs(self, search_term=None, severity=None, date_from=None, date_to=None, page=1, page_size=10):
        """Get logs with filtering and pagination"""
        logs = self._read_logs()
        
        # Apply filters
        filtered_logs = []
        search_term_lower = search_term.lower() if search_term else None
        
        for log in logs:
            if search_term_lower and search_term_lower not in json.dumps(log).lower():
                continue
            if severity and log['severity'] != severity:
                continue
            if date_from and log['timestamp'] < date_from:
                continue
            if date_to and log['timestamp'] > date_to:
                continue
            filtered_logs.append(log)
        
        # Calculate pagination
        total = len(filtered_logs)
        start_idx = (page - 1) * page_size
        end_idx = start_idx + page_size
        
        return filtered_logs[start_idx:end_idx], total

    @lru_cache(maxsize=1)
    def get_statistics(self):
        """Get statistics about logged events with caching"""
        logs = self._read_logs()
        
        stats = {
            'total_events': len(logs),
            'severity_counts': {},
            'event_type_counts': {},
            'recent_events': logs[-5:] if logs else []
        }
        
        for log in logs:
            # Count by severity
            severity = log['severity']
            stats['severity_counts'][severity] = stats['severity_counts'].get(severity, 0) + 1
            
            # Count by event type
            event_type = log['event_type']
            stats['event_type_counts'][event_type] = stats['event_type_counts'].get(event_type, 0) + 1
        
        return stats

# Initialize security logger
logger = SecurityLogger()

def get_system_info():
    """Get detailed system information with caching"""
    global last_system_info, last_system_info_update
    
    current_time = time.time()
    
    # Return cached data if within cache duration
    if last_system_info and (current_time - last_system_info_update) < CACHE_DURATION:
        return last_system_info
    
    with system_info_lock:
        try:
            # Get Windows version more accurately
            if platform.system() == 'Windows':
                win_version = platform.win32_ver()[0]
                os_name = f"Windows {win_version}"
            else:
                os_name = f"{platform.system()} {platform.release()}"

            # Get CPU info with error handling
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_freq = psutil.cpu_freq() or psutil.cpu_freq(percpu=True)[0]
            cpu_count = psutil.cpu_count(logical=True)
            cpu_cores = psutil.cpu_percent(interval=0.1, percpu=True)
            
            # Get memory info
            memory = psutil.virtual_memory()
            
            # Get disk info for system drive
            disk = psutil.disk_usage('/')
            
            # Get boot time
            boot_time = psutil.boot_time()
            
            system_info = {
                'os': os_name,
                'hostname': socket.gethostname(),
                'cpu': {
                    'total': cpu_percent,
                    'cores': cpu_cores,
                    'frequency': {
                        'current': round(cpu_freq.current if hasattr(cpu_freq, 'current') else 0, 2),
                        'min': round(cpu_freq.min if hasattr(cpu_freq, 'min') else 0, 2),
                        'max': round(cpu_freq.max if hasattr(cpu_freq, 'max') else 0, 2)
                    },
                    'count': {
                        'physical': psutil.cpu_count(logical=False) or 1,
                        'logical': cpu_count
                    }
                },
                'memory': {
                    'total': memory.total,
                    'used': memory.used,
                    'free': memory.available,
                    'percent': memory.percent,
                    'used_percent': memory.percent
                },
                'disk': {
                    'total': disk.total,
                    'used': disk.used,
                    'free': disk.free,
                    'percent': disk.percent
                },
                'boot_time': boot_time,
                'uptime': current_time - boot_time,
                'cpu_usage': cpu_percent,
                'processes': cpu_count
            }
            
            # Update cache
            last_system_info = system_info
            last_system_info_update = current_time
            
            return system_info
        except Exception as e:
            print(f"Error getting system info: {str(e)}")
            return last_system_info if last_system_info else None

@lru_cache(maxsize=100)
def get_process_info():
    """Get process information with caching"""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
        try:
            pinfo = proc.info
            processes.append({
                'pid': pinfo['pid'],
                'name': pinfo['name'],
                'cpu_percent': pinfo['cpu_percent'] or 0.0,
                'memory_bytes': pinfo['memory_info'].rss if pinfo['memory_info'] else 0,
                'status': pinfo['status']
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def get_network_info():
    """Get network information"""
    network_monitor.update()
    speeds = network_monitor.get_speeds()
    
    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            try:
                connections.append({
                    'protocol': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                    'status': conn.status
                })
            except (AttributeError, IndexError):
                continue
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    
    return {
        'speeds': speeds,
        'connections': connections[:10]  # Limit to 10 connections for performance
    }

# Routes
@app.route('/')
def index():
    """Home page with system overview"""
    try:
        system_info = get_system_info()
        stats = logger.get_statistics()
        return render_template('index.html', system_info=system_info, stats=stats)
    except Exception as e:
        flash(f"Error loading system information: {str(e)}", 'error')
        return render_template('index.html', system_info=None, stats=None)

@app.route('/log', methods=['GET', 'POST'])
def log_event():
    """Log security events"""
    if request.method == 'POST':
        try:
            event_data = {
                'event_type': request.form['event_type'],
                'severity': request.form['severity'],
                'description': request.form['description'],
                'source': request.form['source'],
                'user': request.form['user']
            }
            logger.log_event(event_data)
            flash('Event logged successfully!', 'success')
            return redirect(url_for('view_logs'))
        except Exception as e:
            flash(f'Error logging event: {str(e)}', 'error')
    
    return render_template('log_event.html')

@app.route('/view')
def view_logs():
    """View security logs with filtering"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    severity = request.args.get('severity', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    logs, total = logger.get_logs(
        search_term=search,
        severity=severity,
        date_from=date_from,
        date_to=date_to,
        page=page
    )
    
    return render_template(
        'view_logs.html',
        logs=logs,
        total=total,
        page=page,
        search=search,
        severity=severity,
        date_from=date_from,
        date_to=date_to
    )

@app.route('/monitor')
def system_monitor():
    """System monitoring page"""
    return render_template('monitor.html')

# API endpoints
@app.route('/api/system-info')
def api_system_info():
    """Get system information"""
    return jsonify(get_system_info())

@app.route('/api/processes')
def api_processes():
    """Get process information"""
    return jsonify(get_process_info())

@app.route('/api/network')
def api_network():
    """Get network information"""
    return jsonify(get_network_info())

@app.route('/api/logs')
def api_logs():
    """Get security logs"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    severity = request.args.get('severity', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    logs, total = logger.get_logs(
        search_term=search,
        severity=severity,
        date_from=date_from,
        date_to=date_to,
        page=page
    )
    
    return jsonify({
        'logs': logs,
        'total': total,
        'page': page
    })

@app.route('/api/statistics')
def api_statistics():
    """Get security event statistics"""
    return jsonify(logger.get_statistics())

if __name__ == '__main__':
    app.run(debug=True, threaded=True) 