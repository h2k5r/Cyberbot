import os
import sys
import json
import yaml
import time
import threading
import subprocess
import platform
from datetime import datetime
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('suricata_alerts.log')
    ]
)

logger = logging.getLogger(__name__)

class SuricataConfigManager:
    """Manages Suricata configuration files and rules"""
    
    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir) if base_dir else Path(os.getcwd())
        self.suricata_dir = self.base_dir / 'suricata'
        self.config_dir = self.suricata_dir / 'configs'
        self.rules_dir = self.suricata_dir / 'rules'
        self.logs_dir = self.suricata_dir / 'logs'
        
        # Ensure directories exist
        self.create_directory_structure()
        
    def create_directory_structure(self):
        """Create the necessary directory structure"""
        directories = [
            self.suricata_dir,
            self.config_dir,
            self.rules_dir,
            self.logs_dir
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")
    
    def load_external_config(self, config_file_path=None):
        """Load external Suricata configuration"""
        if config_file_path is None:
            config_file_path = self.base_dir / 'config' / 'suricata_config.yaml'
        
        try:
            with open(config_file_path, 'r') as f:
                config = yaml.safe_load(f)
            return config
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_file_path}")
            return self.get_default_config()
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return self.get_default_config()
    
    def get_default_config(self):
        """Return default configuration"""
        return {
            'vars': {
                'address-groups': {
                    'HOME_NET': '[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]',
                    'EXTERNAL_NET': '!$HOME_NET',
                    'HTTP_SERVERS': '$HOME_NET',
                    'SMTP_SERVERS': '$HOME_NET',
                    'SQL_SERVERS': '$HOME_NET',
                    'DNS_SERVERS': '$HOME_NET',
                    'TELNET_SERVERS': '$HOME_NET',
                    'AIM_SERVERS': '$EXTERNAL_NET',
                    'DC_SERVERS': '$HOME_NET',
                    'DNP3_SERVER': '$HOME_NET',
                    'DNP3_CLIENT': '$HOME_NET',
                    'MODBUS_CLIENT': '$HOME_NET',
                    'MODBUS_SERVER': '$HOME_NET',
                    'ENIP_CLIENT': '$HOME_NET',
                    'ENIP_SERVER': '$HOME_NET'
                },
                'port-groups': {
                    'HTTP_PORTS': '80',
                    'SHELLCODE_PORTS': '!80',
                    'ORACLE_PORTS': '1521',
                    'SSH_PORTS': '22',
                    'DNP3_PORTS': '20000',
                    'MODBUS_PORTS': '502',
                    'FILE_DATA_PORTS': '[$HTTP_PORTS,110,143]',
                    'FTP_PORTS': '21'
                }
            },
            'default-log-dir': str(self.logs_dir),
            'stats': {
                'enabled': True,
                'interval': 8
            },
            'outputs': [
                {
                    'eve-log': {
                        'enabled': True,
                        'filetype': 'regular',
                        'filename': 'eve.json',
                        'types': [
                            {'alert': {'payload': True, 'packet': True, 'metadata': True}},
                            {'http': {'extended': True}},
                            {'dns': {'query': True, 'answer': True}},
                            {'tls': {'extended': True}},
                            'files',
                            'smtp',
                            'ssh',
                            'flow'
                        ]
                    }
                },
                {
                    'fast': {
                        'enabled': True,
                        'filename': 'fast.log',
                        'append': True
                    }
                }
            ],
            'logging': {
                'default-log-level': 'notice',
                'outputs': [
                    {'console': {'enabled': True}},
                    {
                        'file': {
                            'enabled': True,
                            'level': 'info',
                            'filename': str(self.logs_dir / 'suricata.log')
                        }
                    }
                ]
            },
            'af-packet': [
                {
                    'interface': 'eth0',
                    'cluster-id': 99,
                    'cluster-type': 'cluster_flow',
                    'defrag': True
                }
            ],
            'detect-engine': [
                {'profile': 'medium'},
                {
                    'custom-values': {
                        'toclient-groups': 3,
                        'toserver-groups': 25
                    }
                }
            ],
            'default-rule-path': str(self.rules_dir),
            'rule-files': self.get_rule_files(),
            'classification-file': str(self.config_dir / 'classification.config'),
            'reference-config-file': str(self.config_dir / 'reference.config'),
            'threshold-file': str(self.config_dir / 'threshold.config')
        }
    
    def get_rule_files(self):
        """Get list of available rule files"""
        rule_files = []
        if self.rules_dir.exists():
            for rule_file in self.rules_dir.glob('*.rules'):
                rule_files.append(rule_file.name)
        
        # If no external rules exist, create default ones
        if not rule_files:
            self.create_default_rules()
            rule_files = ['custom-security.rules']
        
        return rule_files
    
    def create_default_rules(self):
        """Create default rule files"""
        rules_content = {
            'custom-security.rules': '''
# Custom Security Rules
alert tcp any any -> $HOME_NET any (msg:"CUSTOM: Suspicious TCP Traffic"; flow:to_server; content:"malware"; sid:1000001; rev:1;)
alert http any any -> $HOME_NET any (msg:"CUSTOM: Suspicious HTTP Request"; http_method; content:"GET"; http_uri; content:"/admin"; sid:1000002; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"CUSTOM: SSH Brute Force Attempt"; flags:S; threshold:type threshold, track by_src, seconds 60, count 10; sid:1000003; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"CUSTOM: HTTP SQL Injection Attempt"; flow:to_server; content:"SELECT"; content:"FROM"; distance:0; sid:1000004; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"CUSTOM: Port Scan Detected"; flags:S; threshold:type threshold, track by_src, seconds 10, count 10; sid:1000005; rev:1;)
''',
            'web-attacks.rules': '''
# Web Attack Detection Rules
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB: XSS Attack Attempt"; flow:to_server; content:"<script"; nocase; sid:2000001; rev:1;)
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB: Command Injection Attempt"; flow:to_server; content:"|3B|"; content:"system"; distance:0; sid:2000002; rev:1;)
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB: Directory Traversal Attempt"; flow:to_server; content:"../"; sid:2000003; rev:1;)
alert http any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"WEB: PHP Code Injection"; flow:to_server; content:"<?php"; nocase; sid:2000004; rev:1;)
''',
            'malware-detection.rules': '''
# Malware Detection Rules
alert tcp any any -> $HOME_NET any (msg:"MALWARE: Known C&C Communication"; flow:to_server; content:"botnet"; sid:3000001; rev:1;)
alert http any any -> $EXTERNAL_NET any (msg:"MALWARE: Suspicious User Agent"; flow:to_server, to_client; http_user_agent; content:"malware"; sid:3000002; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"MALWARE: Ransomware Communication Pattern"; flow:to_server; content:"encrypt"; content:"payment"; sid:3000003; rev:1;)
''',
            'network-scan.rules': '''
# Network Scanning Detection Rules
alert tcp any any -> $HOME_NET any (msg:"SCAN: NMAP TCP Connect Scan"; flags:S; threshold:type threshold, track by_src, seconds 30, count 15; sid:4000001; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"SCAN: NMAP SYN Scan"; flags:S; threshold:type threshold, track by_src, seconds 10, count 20; sid:4000002; rev:1;)
alert udp any any -> $HOME_NET any (msg:"SCAN: UDP Port Scan"; threshold:type threshold, track by_src, seconds 30, count 10; sid:4000003; rev:1;)
'''
        }
        
        for filename, content in rules_content.items():
            rule_file = self.rules_dir / filename
            with open(rule_file, 'w') as f:
                f.write(content.strip())
            logger.info(f"Created rule file: {rule_file}")
    
    def create_config_files(self):
        """Create additional configuration files"""
        # Classification config
        classification_content = '''
config classification: not-suspicious,Not Suspicious Traffic,3
config classification: unknown,Unknown Traffic,3
config classification: bad-unknown,Potentially Bad Traffic,2
config classification: attempted-recon,Attempted Information Leak,2
config classification: successful-recon-limited,Information Leak,2
config classification: successful-recon-largescale,Large Scale Information Leak,2
config classification: attempted-dos,Attempted Denial of Service,2
config classification: successful-dos,Denial of Service,2
config classification: attempted-user,Attempted User Privilege Gain,1
config classification: unsuccessful-user,Unsuccessful User Privilege Gain,1
config classification: successful-user,Successful User Privilege Gain,1
config classification: attempted-admin,Attempted Administrator Privilege Gain,1
config classification: successful-admin,Successful Administrator Privilege Gain,1
config classification: rpc-portmap-decode,Decode of RPC Query,2
config classification: shellcode-detect,Executable code was detected,1
config classification: string-detect,A suspicious string was detected,3
config classification: suspicious-filename-detect,A suspicious filename was detected,2
config classification: suspicious-login,An attempted login using a suspicious username was detected,2
config classification: system-call-detect,A system call was detected,2
config classification: tcp-connection,A TCP connection was detected,4
config classification: trojan-activity,A Network Trojan was detected,1
config classification: unusual-client-port-connection,A client was using an unusual port,2
config classification: network-scan,Detection of a Network Scan,3
config classification: denial-of-service,Detection of a Denial of Service Attack,2
config classification: non-standard-protocol,Detection of a non-standard protocol or event,2
config classification: protocol-command-decode,Generic Protocol Command Decode,3
config classification: web-application-activity,access to a potentially vulnerable web application,2
config classification: web-application-attack,Web Application Attack,1
config classification: misc-activity,Misc activity,3
config classification: misc-attack,Misc Attack,2
config classification: icmp-event,Generic ICMP event,3
config classification: inappropriate-content,Inappropriate Content was Detected,1
config classification: policy-violation,Potential Corporate Privacy Violation,1
config classification: default-login-attempt,Attempt to login by a default username and password,2
'''
        
        # Reference config
        reference_content = '''
config reference: bugtraq   http://www.securityfocus.com/bid/
config reference: bid       http://www.securityfocus.com/bid/
config reference: cve       http://cve.mitre.org/cgi-bin/cvename.cgi?name=
config reference: arachNIDS http://www.whitehats.com/info/IDS
config reference: McAfee    http://vil.nai.com/vil/content/v_
config reference: nessus    http://cgi.nessus.org/plugins/dump.php3?id=
config reference: url       http://
config reference: et        http://doc.emergingthreats.net/
config reference: etpro     http://doc.emergingthreatspro.com/
'''
        
        # Threshold config
        threshold_content = '''
# Threshold configuration
# Format: threshold gen_id <gid>, sig_id <sid>, type <threshold|limit|both>, track <by_src|by_dst>, count <c>, seconds <s>

# Suppress noisy rules
suppress gen_id 1, sig_id 2100498
suppress gen_id 1, sig_id 2103461

# Rate limit DNS queries
threshold gen_id 1, sig_id 2100366, type limit, track by_src, count 1, seconds 60

# Rate limit HTTP requests
threshold gen_id 1, sig_id 2100368, type threshold, track by_src, count 10, seconds 60
'''
        
        config_files = {
            'classification.config': classification_content,
            'reference.config': reference_content,
            'threshold.config': threshold_content
        }
        
        for filename, content in config_files.items():
            config_file = self.config_dir / filename
            with open(config_file, 'w') as f:
                f.write(content.strip())
            logger.info(f"Created config file: {config_file}")
    
    def generate_suricata_yaml(self, interface='eth0'):
        """Generate the main Suricata YAML configuration"""
        config = self.load_external_config()
        
        # Update interface if specified
        if interface != 'eth0':
            config['af-packet'][0]['interface'] = interface
        
        # Ensure all paths are absolute
        config['default-log-dir'] = str(self.logs_dir.absolute())
        config['default-rule-path'] = str(self.rules_dir.absolute())
        config['classification-file'] = str(self.config_dir.absolute() / 'classification.config')
        config['reference-config-file'] = str(self.config_dir.absolute() / 'reference.config')
        config['threshold-file'] = str(self.config_dir.absolute() / 'threshold.config')
        
        # Write the configuration file
        config_file = self.suricata_dir / 'suricata.yaml'
        with open(config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        logger.info(f"Generated Suricata config: {config_file}")
        return str(config_file.absolute())

class SuricataLogHandler(FileSystemEventHandler):
    """Handler for monitoring Suricata log files"""
    
    def __init__(self, callback_function, log_file_path):
        self.callback_function = callback_function
        self.log_file_path = Path(log_file_path)
        self.last_position = 0
        
    def on_modified(self, event):
        if Path(event.src_path) == self.log_file_path:
            self.process_new_logs()
    
    def process_new_logs(self):
        """Process new log entries"""
        try:
            with open(self.log_file_path, 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
                for line in new_lines:
                    line = line.strip()
                    if line:
                        try:
                            log_entry = json.loads(line)
                            if log_entry.get('event_type') == 'alert':
                                self.callback_function(log_entry)
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            logger.error(f"Error processing Suricata logs: {e}")

class SuricataManager:
    """Enhanced Suricata manager with external configuration support"""
    
    def __init__(self, base_dir=None, interface='eth0'):
        self.base_dir = Path(base_dir) if base_dir else Path(os.getcwd())
        self.interface = interface
        self.config_manager = SuricataConfigManager(self.base_dir)
        self.suricata_process = None
        self.monitor_process = None
        self.observer = None
        self.callback_function = None
        
        # Initialize configuration
        self.setup_configuration()
        
    def setup_configuration(self):
        """Set up all configuration files"""
        self.config_manager.create_config_files()
        self.config_file = self.config_manager.generate_suricata_yaml(self.interface)
        self.eve_json_path = self.config_manager.logs_dir / 'eve.json'
        
    def start_suricata(self, callback_function):
        """Start Suricata with file watcher monitoring"""
        try:
            self.callback_function = callback_function
            
            # Start Suricata process
            suricata_cmd = [
                'suricata',
                '-c', str(self.config_file),
                '-i', self.interface,
                '--init-errors-fatal'
            ]
            
            if platform.system() == 'Windows':
                cmd_str = ' '.join(suricata_cmd)
                self.suricata_process = subprocess.Popen(
                    ['cmd', '/c', 'start', 'Suricata IDS', 'cmd', '/k', cmd_str],
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
                logger.info(f"Started Suricata with PID: {self.suricata_process.pid}")
                
                # Start file watcher monitor instead of separate window
                self.start_log_monitoring_with_watcher()
                return True
                
            else:
                # Linux implementation
                if os.environ.get('DISPLAY'):
                    self.suricata_process = subprocess.Popen(
                        ['gnome-terminal', '--', 'bash', '-c', 
                         f"{' '.join(suricata_cmd)}; echo 'Press Enter to close...'; read"]
                    )
                else:
                    self.suricata_process = subprocess.Popen(suricata_cmd)
                return True
                
        except Exception as e:
            logger.error(f"Failed to start Suricata: {e}")
            return False
    
    def create_monitor_script(self, monitor_script):
        """Create the enhanced monitor script with clean output"""
        monitor_content = '''import json
import time
import sys
import os
from pathlib import Path
from datetime import datetime

# Windows console color support
if os.name == 'nt':
    os.system('color')

class Colors:
    """ANSI color codes for cross-platform colored output"""
    RED = '\\033[31m'
    GREEN = '\\033[32m'
    YELLOW = '\\033[33m'
    BLUE = '\\033[34m'
    MAGENTA = '\\033[35m'
    CYAN = '\\033[36m'
    WHITE = '\\033[37m'
    BRIGHT_RED = '\\033[91m'
    BRIGHT_GREEN = '\\033[92m'
    BRIGHT_YELLOW = '\\033[93m'
    BRIGHT_BLUE = '\\033[94m'
    BRIGHT_MAGENTA = '\\033[95m'
    BRIGHT_CYAN = '\\033[96m'
    BRIGHT_WHITE = '\\033[97m'
    RESET = '\\033[0m'

def print_colored(text, color=Colors.WHITE):
    """Print colored text with fallback for non-ANSI terminals"""
    try:
        print(f"{color}{text}{Colors.RESET}")
    except:
        print(text)

def print_banner():
    """Print startup banner"""
    banner = f"""{Colors.CYAN}
========================================================
               SURICATA IDS LOG MONITOR
========================================================
{Colors.RESET}"""
    print(banner)

def get_severity_color(severity):
    """Get color based on severity level"""
    severity_colors = {
        1: Colors.BRIGHT_RED,     # Critical
        2: Colors.RED,            # High
        3: Colors.YELLOW,         # Medium
        4: Colors.GREEN,          # Low
    }
    return severity_colors.get(severity, Colors.WHITE)

def format_alert(alert_data, alert_count):
    """Format alert data for display"""
    alert = alert_data.get('alert', {})
    severity = alert.get('severity', 3)
    
    severity_color = get_severity_color(severity)
    severity_text = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}.get(severity, "UNKNOWN")
    
    timestamp = datetime.now().strftime('%H:%M:%S')
    
    # Header
    print_colored(f"\\nALERT #{alert_count} - {timestamp}", Colors.BRIGHT_WHITE)
    print_colored("-" * 60, severity_color)
    
    # Alert details
    print_colored(f"Signature:  {alert.get('signature', 'Unknown')}", Colors.WHITE)
    print_colored(f"Category:   {alert.get('category', 'Unknown')}", Colors.WHITE)
    print_colored(f"Severity:   {severity_text} ({severity})", severity_color)
    print_colored(f"Source:     {alert_data.get('src_ip', 'Unknown')}:{alert_data.get('src_port', 'Unknown')}", Colors.CYAN)
    print_colored(f"Target:     {alert_data.get('dest_ip', 'Unknown')}:{alert_data.get('dest_port', 'Unknown')}", Colors.CYAN)
    print_colored(f"Protocol:   {alert_data.get('proto', 'Unknown')}", Colors.WHITE)
    print_colored(f"SID:        {alert.get('signature_id', 'Unknown')}", Colors.WHITE)
    
    # Additional info if available
    if alert_data.get('flow_id'):
        print_colored(f"Flow ID:    {alert_data.get('flow_id')}", Colors.BLUE)
    
    if alert.get('rev'):
        print_colored(f"Revision:   {alert.get('rev')}", Colors.WHITE)
    
    # Payload preview (first 100 chars)
    if alert_data.get('payload_printable'):
        payload = alert_data.get('payload_printable')[:100]
        if len(alert_data.get('payload_printable', '')) > 100:
            payload += "..."
        print_colored(f"Payload:    {payload}", Colors.MAGENTA)
    
    print_colored("-" * 60, severity_color)

def monitor_log_file(log_file_path):
    """Monitor the log file for new alerts with enhanced display"""
    log_file_path = Path(log_file_path)
    last_position = 0
    alert_count = 0
    
    print_banner()
    print_colored(f"Log File:   {log_file_path}", Colors.WHITE)
    print_colored(f"Started:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Colors.WHITE)
    print_colored("Stop:       Press Ctrl+C to stop monitoring", Colors.YELLOW)
    print_colored("=" * 60, Colors.CYAN)
    print_colored("Waiting for alerts...", Colors.GREEN)
    
    while True:
        try:
            if not log_file_path.exists():
                print_colored("Waiting for log file to be created...", Colors.YELLOW)
                time.sleep(2)
                continue
                
            with open(log_file_path, 'r', encoding='utf-8') as f:
                f.seek(last_position)
                new_lines = f.readlines()
                last_position = f.tell()
                
                for line in new_lines:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            if entry.get('event_type') == 'alert':
                                alert_count += 1
                                format_alert(entry, alert_count)
                                
                                # Beep for high severity alerts (Windows)
                                alert_severity = entry.get('alert', {}).get('severity', 4)
                                if alert_severity <= 2 and os.name == 'nt':
                                    try:
                                        import winsound
                                        winsound.Beep(1000, 300)  # 1000Hz for 300ms
                                    except ImportError:
                                        pass
                                        
                        except json.JSONDecodeError as e:
                            continue
                            
        except Exception as e:
            print_colored(f"Error reading log file: {e}", Colors.RED)
        
        time.sleep(1)

def main():
    """Main function with argument handling and error management"""
    if len(sys.argv) != 2:
        print_colored("Usage: python monitor.py <path_to_eve.json>", Colors.RED)
        print_colored("Example: python monitor.py C:\\\\path\\\\to\\\\eve.json", Colors.WHITE)
        input("Press Enter to exit...")
        sys.exit(1)
    
    log_file = sys.argv[1]
    
    try:
        # Set console title on Windows
        if os.name == 'nt':
            os.system(f'title Suricata Log Monitor - {Path(log_file).name}')
        
        monitor_log_file(log_file)
        
    except KeyboardInterrupt:
        print_colored("\\n\\nStopping Suricata Log Monitor...", Colors.YELLOW)
        print_colored("Monitor stopped successfully!", Colors.GREEN)
        input("Press Enter to close window...")
        sys.exit(0)
    except Exception as e:
        print_colored(f"\\nFatal error: {e}", Colors.RED)
        print_colored("Check the log file path and permissions.", Colors.YELLOW)
        input("Press Enter to close window...")
        sys.exit(1)

if __name__ == '__main__':
    main()
'''
        
        with open(monitor_script, 'w', encoding='utf-8') as f:
            f.write(monitor_content)
    
    def start_log_monitoring(self):
        """Start monitoring the eve.json file in a separate window"""
        try:
            # Ensure log file exists and directory structure
            eve_log_path = Path(self.config_manager.suricata_dir) / 'logs' / 'eve.json'
            eve_log_path.parent.mkdir(parents=True, exist_ok=True)
            eve_log_path.touch(exist_ok=True)
            
            # Create monitor script with absolute path
            monitor_script = Path(self.config_manager.suricata_dir) / 'log_monitor.py'
            self.create_monitor_script(monitor_script)
            
            # Start the monitor in a new window using absolute paths
            if platform.system() == 'Windows':
                python_exe = sys.executable  # Get current Python interpreter path
                monitor_cmd = f'"{python_exe}" "{monitor_script}" "{eve_log_path}"'
                
                self.monitor_process = subprocess.Popen(
                    ['cmd', '/c', 'start', '"Suricata Log Monitor"', 'cmd', '/k', monitor_cmd],
                    creationflags=subprocess.CREATE_NEW_CONSOLE | subprocess.CREATE_NEW_PROCESS_GROUP,
                    cwd=str(self.config_manager.suricata_dir),
                    env=os.environ.copy()
                )
                logger.info(f"Started log monitor in new window with PID: {self.monitor_process.pid}")
                return True
            else:
                # Linux implementation
                if os.environ.get('DISPLAY'):
                    self.monitor_process = subprocess.Popen(
                        ['gnome-terminal', '--title', 'Suricata Log Monitor', '--', 
                         'python3', str(monitor_script), str(eve_log_path)]
                    )
                else:
                    self.monitor_process = subprocess.Popen(
                        ['python3', str(monitor_script), str(eve_log_path)]
                    )
                return True
                
        except Exception as e:
            logger.error(f"Failed to start log monitoring: {e}")
            return False

    def start_log_monitoring_with_watcher(self):
        """Start monitoring eve.json using FileSystemEventHandler"""
        try:
            # Ensure log file exists
            eve_log_path = Path(self.config_manager.suricata_dir) / 'logs' / 'eve.json'
            eve_log_path.parent.mkdir(parents=True, exist_ok=True)
            eve_log_path.touch(exist_ok=True)

            # Create and start the observer
            event_handler = SuricataLogHandler(self.process_alert, eve_log_path)
            self.observer = Observer()
            self.observer.schedule(event_handler, str(eve_log_path.parent), recursive=False)
            self.observer.start()
            
            logger.info(f"Started log monitoring for: {eve_log_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to start log monitoring: {e}")
            return False

    def stop_log_monitoring(self):
        """Stop the log monitor"""
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join()
                logger.info("Log monitoring stopped")
            except Exception as e:
                logger.error(f"Error stopping log monitor: {e}")
    
    def process_alert(self, alert_data):
        """Process and forward alerts"""
        try:
            processed_alert = {
                'timestamp': alert_data.get('timestamp'),
                'event_type': alert_data.get('event_type'),
                'severity': self.map_severity(alert_data.get('alert', {}).get('severity', 3)),
                'signature': alert_data.get('alert', {}).get('signature', 'Unknown'),
                'category': alert_data.get('alert', {}).get('category', 'Unknown'),
                'source_ip': alert_data.get('src_ip'),
                'dest_ip': alert_data.get('dest_ip'),
                'source_port': alert_data.get('src_port'),
                'dest_port': alert_data.get('dest_port'),
                'protocol': alert_data.get('proto'),
                'payload': alert_data.get('payload'),
                'rule_file': self.get_rule_source(alert_data.get('alert', {}).get('signature_id')),
                'raw_data': alert_data
            }
            
            if self.callback_function:
                self.callback_function(processed_alert)
                
        except Exception as e:
            logger.error(f"Error processing alert: {e}")
    
    def get_rule_source(self, signature_id):
        """Determine which rule file triggered the alert"""
        if not signature_id:
            return 'unknown'
        
        try:
            sid = int(signature_id)
            if 1000000 <= sid < 2000000:
                return 'custom-security.rules'
            elif 2000000 <= sid < 3000000:
                return 'web-attacks.rules'
            elif 3000000 <= sid < 4000000:
                return 'malware-detection.rules'
            elif 4000000 <= sid < 5000000:
                return 'network-scan.rules'
            else:
                return 'external.rules'
        except (ValueError, TypeError):
            return 'unknown'
    
    def map_severity(self, suricata_severity):
        """Map Suricata severity to application severity"""
        severity_map = {1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low'}
        return severity_map.get(suricata_severity, 'Medium')
    
    def reload_rules(self):
        """Reload Suricata rules without restarting"""
        if self.suricata_process and self.suricata_process.poll() is None:
            try:
                # Send USR2 signal to reload rules (Unix/Linux)
                if platform.system() != 'Windows':
                    os.kill(self.suricata_process.pid, signal.SIGUSR2)
                    logger.info("Reloaded Suricata rules")
                else:
                    logger.warning("Rule reloading not supported on Windows without restart")
            except Exception as e:
                logger.error(f"Failed to reload rules: {e}")
    
    def stop_suricata(self):
        """Stop Suricata and cleanup"""
        try:
            # Stop the monitor process
            if hasattr(self, 'monitor_process') and self.monitor_process:
                try:
                    if platform.system() == 'Windows':
                        # Better process termination for Windows
                        subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.monitor_process.pid)], 
                                     timeout=10, capture_output=True)
                    else:
                        self.monitor_process.terminate()
                        self.monitor_process.wait(timeout=5)
                    logger.info("Monitor process stopped")
                except (subprocess.TimeoutExpired, ProcessLookupError) as e:
                    logger.warning(f"Failed to stop monitor process gracefully: {e}")
        
            # Stop Suricata process
            if self.suricata_process:
                try:
                    if platform.system() == 'Windows':
                        # For Windows, try to terminate gracefully first
                        subprocess.run(['taskkill', '/PID', str(self.suricata_process.pid)], 
                                     timeout=10, capture_output=True)
                    else:
                        self.suricata_process.terminate()
                        self.suricata_process.wait(timeout=10)
                    logger.info("Suricata stopped successfully")
                except (subprocess.TimeoutExpired, ProcessLookupError) as e:
                    logger.warning(f"Failed to stop Suricata gracefully: {e}")
                    
        except Exception as e:
            logger.error(f"Error stopping Suricata: {e}")
    
    def get_status(self):
        """Get comprehensive status"""
        suricata_running = False
        monitor_running = False
        
        if self.suricata_process:
            suricata_running = self.suricata_process.poll() is None
            
        if hasattr(self, 'monitor_process') and self.monitor_process:
            monitor_running = self.monitor_process.poll() is None
        
        return {
            'suricata_running': suricata_running,
            'monitor_running': monitor_running,
            'suricata_pid': self.suricata_process.pid if self.suricata_process else None,
            'monitor_pid': getattr(self.monitor_process, 'pid', None) if hasattr(self, 'monitor_process') else None,
            'config_file': str(self.config_file),
            'rules_directory': str(self.config_manager.rules_dir),
            'logs_directory': str(self.config_manager.logs_dir),
            'rule_files': self.config_manager.get_rule_files(),
            'log_file': str(self.eve_json_path)
        }
