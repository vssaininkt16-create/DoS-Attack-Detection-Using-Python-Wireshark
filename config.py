"""
Configuration file for DoS Detection System
Centralized settings for thresholds and parameters
"""

# Attack Detection Thresholds
DETECTION_THRESHOLDS = {
    # SYN Flood: packets per second from single source
    'syn_flood_threshold': 50,
    
    # UDP Flood: packets per second to single destination
    'udp_flood_threshold': 100,
    
    # ICMP Flood: packets per second from single source
    'icmp_flood_threshold': 50,
    
    # Bandwidth Spike: bytes in time window
    'bandwidth_spike_threshold': 10_000_000,  # 10 MB
    
    # Time window for analysis (seconds)
    'time_window': 5,
}

# Alert Configuration
ALERT_CONFIG = {
    'enable_email_alerts': False,
    'enable_webhook_alerts': False,
    'enable_slack_alerts': False,
    'log_to_file': True,
    'log_to_console': True,
}

# Logging Configuration
LOGGING_CONFIG = {
    'log_directory': 'logs',
    'log_level': 'INFO',
    'max_log_size': 10_000_000,  # 10 MB
    'backup_count': 5,
}

# Network Configuration
NETWORK_CONFIG = {
    'default_interface': None,  # None = auto-detect
    'promiscuous_mode': True,
    'buffer_size': 65535,
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    'max_packets_in_memory': 10000,
    'cleanup_interval': 10,  # seconds
    'stats_update_interval': 30,  # seconds
}

# PCAP Analysis Configuration
PCAP_CONFIG = {
    'pcap_directory': 'pcap_files',
    'export_format': 'json',  # json or csv
}

# GeoIP Configuration (optional)
GEOIP_CONFIG = {
    'enabled': False,
    'database_path': None,
}

# Machine Learning Configuration (future)
ML_CONFIG = {
    'enabled': False,
    'model_path': None,
    'retrain_interval': 86400,  # 24 hours
}
