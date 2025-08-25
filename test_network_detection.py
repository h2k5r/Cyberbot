"""
Test script for network interface detection
"""

import logging
from network_utils import detect_primary_network_interface, get_all_network_interfaces

def test_detection():
    logging.basicConfig(level=logging.INFO)
    
    print("Testing Network Interface Detection on Windows")
    print("=" * 50)
    
    # Test primary detection
    primary = detect_primary_network_interface()
    print(f"Primary Interface: {primary}")
    print()
    
    # Test all interfaces
    interfaces = get_all_network_interfaces()
    print("All Interfaces:")
    for i, interface in enumerate(interfaces, 1):
        print(f"{i}. Name: {interface['name']}")
        print(f"   Description: {interface['description']}")
        print(f"   Status: {interface['status']}")
        print(f"   Speed: {interface['speed']}")
        print()

if __name__ == '__main__':
    test_detection()
