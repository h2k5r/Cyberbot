#!/usr/bin/env python3
"""
Startup script for the Flask Security Application with Suricata Integration
"""

import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from network_utils import detect_primary_network_interface, get_all_network_interfaces
from app import app

def setup_logging():
    """Setup logging configuration"""
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
        status_icon = "✓" if interface['status'] == 'Up' else "✗"
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
    
    # Start the Flask application
    logger.info(f"Starting Flask app with Suricata on interface: {primary_interface}")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=app.config.get('DEBUG', False)
    )

if __name__ == '__main__':
    main()
