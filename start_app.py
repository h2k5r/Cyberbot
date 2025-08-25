#!/usr/bin/env python3
"""
Startup script for the Flask Security Application with Suricata Integration
"""

import logging
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from network_utils import detect_primary_network_interface, get_all_network_interfaces
from app import app, socketio, auto_start_suricata

def setup_logging():
    """Setup logging configuration"""
    # Ensure UTF-8 capable console on Windows to avoid UnicodeEncodeError for ✓/✗
    try:
        if os.name == 'nt':
            os.system('chcp 65001 > NUL')
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def display_network_info():
    """Display network interface information at startup"""
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("NETWORK INTERFACE DETECTION")
    logger.info("=" * 60)
    
    # Detect primary interface
    primary = detect_primary_network_interface()
    logger.info(f"Primary Interface: {primary}")
    
    # Show all interfaces
    interfaces = get_all_network_interfaces()
    logger.info("Available Interfaces:")
    for interface in interfaces:
        status_icon = "OK" if interface['status'] == 'Up' else "X"
        logger.info(f"  {status_icon} {interface['name']}: {interface['status']} - {interface['description']}")
    
    logger.info("=" * 60)
    return primary

def test_database_connection():
    """Test database connectivity on startup"""
    logger = logging.getLogger(__name__)
    
    try:
        from app import db
        with app.app_context():
            db.session.execute('SELECT 1')
            logger.info("Database connection successful")
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
        sys.exit(1)

def main():
    """Main startup function"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("Starting Flask Security Application with Suricata Integration")
    
    # Test database connection
    test_database_connection()
    
    # Display network information
    primary_interface = display_network_info()
    
    # Ensure Suricata starts when launching via this script
    try:
        auto_start_suricata()
    except Exception:
        pass
    
    # Start the application using SocketIO to support websockets
    logger.info(f"Starting Flask-SocketIO app with Suricata on interface: {primary_interface}")
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=app.config.get('DEBUG', False)
    )

if __name__ == '__main__':
    main()
