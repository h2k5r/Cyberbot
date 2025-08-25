import subprocess
import json
import re
import socket
import platform
from typing import Optional, List, Dict
import logging

logger = logging.getLogger(__name__)

class WindowsNetworkDetector:
    """Utility class to detect active network interfaces on Windows"""
    
    @staticmethod
    def get_active_interface_powershell() -> Optional[str]:
        """Get active network interface using PowerShell Get-NetAdapter"""
        try:
            # PowerShell command to get active network adapters
            cmd = [
                'powershell.exe',
                '-Command',
                'Get-NetAdapter | Where-Object {$_.Status -eq "Up" -and $_.Virtual -eq $false} | Select-Object -First 1 | ConvertTo-Json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout.strip():
                adapter_info = json.loads(result.stdout)
                interface_name = adapter_info.get('Name')
                logger.info(f"Detected active interface via PowerShell: {interface_name}")
                return interface_name
            
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            logger.warning(f"PowerShell method failed: {e}")
        
        return None
    
    @staticmethod
    def get_active_interface_wmic() -> Optional[str]:
        """Get active network interface using WMIC"""
        try:
            # Get network adapters with active connections
            cmd = [
                'wmic',
                'path',
                'win32_networkadapter',
                'where',
                'netenabled=true',
                'get',
                'netconnectionid,name,macaddress',
                '/format:csv'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                for line in lines:
                    if line.strip() and ',' in line:
                        parts = line.strip().split(',')
                        if len(parts) >= 4:  # Node,MACAddress,Name,NetConnectionID
                            net_connection_id = parts[3].strip()
                            if net_connection_id and net_connection_id != 'NULL':
                                logger.info(f"Detected active interface via WMIC: {net_connection_id}")
                                return net_connection_id
                        
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.warning(f"WMIC method failed: {e}")
        
        return None
    
    @staticmethod
    def get_active_interface_route() -> Optional[str]:
        """Get active interface by checking default route"""
        try:
            # Get routing table
            cmd = ['route', 'print', '0.0.0.0']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Look for the default route (0.0.0.0)
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and 'On-link' not in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            interface_idx = parts[-1]
                            # Now get interface name from index
                            return WindowsNetworkDetector.get_interface_name_from_index(interface_idx)
                            
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.warning(f"Route method failed: {e}")
        
        return None
    
    @staticmethod
    def get_interface_name_from_index(interface_idx: str) -> Optional[str]:
        """Get interface name from interface index"""
        try:
            cmd = [
                'powershell.exe',
                '-Command',
                f'Get-NetAdapter -InterfaceIndex {interface_idx} | Select-Object -ExpandProperty Name'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                interface_name = result.stdout.strip()
                logger.info(f"Interface index {interface_idx} maps to: {interface_name}")
                return interface_name
                
        except Exception as e:
            logger.warning(f"Failed to get interface name from index {interface_idx}: {e}")
        
        return None
    
    @staticmethod
    def get_active_interface_ipconfig() -> Optional[str]:
        """Get active interface using ipconfig and find the one with default gateway"""
        try:
            cmd = ['ipconfig', '/all']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                sections = result.stdout.split('adapter ')
                
                for section in sections[1:]:  # Skip first empty section
                    lines = section.split('\n')
                    if not lines:
                        continue
                        
                    # Extract adapter name
                    adapter_line = lines[0]
                    adapter_name = adapter_line.split(':')[0].strip()
                    
                    # Check if this adapter has IP and gateway (active)
                    has_ip = False
                    has_gateway = False
                    
                    for line in lines:
                        if 'IPv4 Address' in line and '(' in line:
                            has_ip = True
                        elif 'Default Gateway' in line and ':' in line:
                            gateway_part = line.split(':', 1)[1].strip()
                            if gateway_part and gateway_part != '':
                                has_gateway = True
                    
                    if has_ip and has_gateway:
                        logger.info(f"Detected active interface via ipconfig: {adapter_name}")
                        return adapter_name
                        
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.warning(f"ipconfig method failed: {e}")
        
        return None
    
    @staticmethod
    def get_interface_by_connection_test() -> Optional[str]:
        """Get active interface by testing actual connectivity"""
        try:
            # Create a socket and connect to a remote server to see which interface is used
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            
            # Now find which interface has this IP
            cmd = [
                'powershell.exe',
                '-Command',
                f'Get-NetIPAddress -IPAddress {local_ip} | Get-NetAdapter | Select-Object -ExpandProperty Name'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                interface_name = result.stdout.strip()
                logger.info(f"Detected active interface via connection test: {interface_name}")
                return interface_name
                
        except Exception as e:
            logger.warning(f"Connection test method failed: {e}")
        
        return None

def detect_primary_network_interface() -> str:
    """
    Detect the primary network interface on Windows using multiple methods
    Returns the interface name or falls back to default
    """
    if platform.system() != 'Windows':
        logger.warning("This detector is designed for Windows only")
        return 'eth0'  # Default fallback for non-Windows
    
    detector = WindowsNetworkDetector()
    
    # Try multiple methods in order of reliability
    methods = [
        ('PowerShell Get-NetAdapter', detector.get_active_interface_powershell),
        ('Connection Test', detector.get_interface_by_connection_test),
        ('Route Table', detector.get_active_interface_route),
        ('ipconfig', detector.get_active_interface_ipconfig),
        ('WMIC', detector.get_active_interface_wmic),
    ]
    
    for method_name, method_func in methods:
        try:
            logger.info(f"Trying {method_name} method...")
            interface = method_func()
            if interface:
                logger.info(f"Successfully detected interface '{interface}' using {method_name}")
                return interface
        except Exception as e:
            logger.warning(f"{method_name} method failed: {e}")
            continue
    
    # Ultimate fallback
    logger.warning("All detection methods failed, using default interface name")
    return 'Ethernet'  # Common default on Windows

def get_all_network_interfaces() -> List[Dict[str, str]]:
    """Get list of all network interfaces with their status"""
    interfaces = []
    
    if platform.system() != 'Windows':
        return interfaces
    
    try:
        cmd = [
            'powershell.exe',
            '-Command',
            'Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed | ConvertTo-Json'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            
            # Handle both single interface and multiple interfaces
            if isinstance(data, dict):
                data = [data]
            
            for adapter in data:
                interfaces.append({
                    'name': adapter.get('Name', 'Unknown'),
                    'description': adapter.get('InterfaceDescription', 'Unknown'),
                    'status': adapter.get('Status', 'Unknown'),
                    'speed': adapter.get('LinkSpeed', 'Unknown')
                })
                
    except Exception as e:
        logger.error(f"Failed to get all network interfaces: {e}")
    
    return interfaces

# Test function
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("Detecting primary network interface...")
    primary_interface = detect_primary_network_interface()
    print(f"Primary interface: {primary_interface}")
    
    print("\nAll available interfaces:")
    all_interfaces = get_all_network_interfaces()
    for interface in all_interfaces:
        print(f"  - {interface['name']}: {interface['status']} ({interface['description']})")
