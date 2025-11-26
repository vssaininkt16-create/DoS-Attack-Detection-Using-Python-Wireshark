"""
DoS Attack Detection System
Network Forensics and Attack Detection using Python and Scapy
"""

__version__ = "1.0.0"
__author__ = "Network Security Team"
__description__ = "Real-time DoS attack detection and analysis system"

from .dos_detector import DoSDetector
from .alert_manager import AlertManager, AlertSeverity
from .packet_sniffer import PacketSniffer
from .pcap_analyzer import PCAPAnalyzer

__all__ = [
    'DoSDetector',
    'AlertManager',
    'AlertSeverity',
    'PacketSniffer',
    'PCAPAnalyzer'
]
