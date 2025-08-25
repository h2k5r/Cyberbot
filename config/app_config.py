import os
from pathlib import Path

import os
from pathlib import Path
from network_utils import detect_primary_network_interface, get_all_network_interfaces

class Config:
    """Application configuration with automatic interface detection"""
    
    # Base directory
    BASE_DIR = Path(__file__).parent.parent
    
    # Automatically detect primary network interface
    @staticmethod
    def get_network_interface():
        """Get the primary network interface"""
        # Check if manually specified in environment
        manual_interface = os.getenv('SURICATA_INTERFACE')
        if manual_interface:
            return manual_interface
        
        # Auto-detect
        return detect_primary_network_interface()
    
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://user:password@localhost/security_db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Suricata configuration with auto-detection
    SURICATA_CONFIG = {
        'AUTO_START': os.getenv('SURICATA_AUTO_START', 'true').lower() == 'true',
        'INTERFACE': get_network_interface(),  # Auto-detected
        'BASE_DIR': BASE_DIR,
        'EXTERNAL_CONFIG': BASE_DIR / 'config' / 'suricata_config.yaml',
        'RULES_UPDATE_INTERVAL': int(os.getenv('SURICATA_RULES_UPDATE_INTERVAL', '3600')),
        'LOG_RETENTION_DAYS': int(os.getenv('SURICATA_LOG_RETENTION_DAYS', '30'))
    }
    
class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

# Configuration mapping
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
