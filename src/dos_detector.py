"""
DoS Attack Detection Engine
Analyzes packets for DoS attack patterns and anomalies
"""

import logging
from collections import defaultdict, deque
from datetime import datetime, timedelta
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/dos_detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class DoSDetector:
    """Detects various DoS attack patterns"""
    
    # Thresholds for detection
    SYN_FLOOD_THRESHOLD = 50  # SYN packets per second from one IP
    UDP_FLOOD_THRESHOLD = 100  # UDP packets per second to one target
    ICMP_FLOOD_THRESHOLD = 50  # ICMP packets per second from one IP
    BANDWIDTH_SPIKE_THRESHOLD = 10_000_000  # 10 MB in 5 seconds
    TIME_WINDOW = 5  # seconds
    
    def __init__(self):
        """Initialize DoS detector"""
        self.src_ip_packets = defaultdict(deque)  # {src_ip: deque of (timestamp, packet_info)}
        self.dst_ip_packets = defaultdict(deque)
        self.alerts = []
        self.attack_detected = False
        self.last_cleanup = time.time()
        
    def add_packet(self, packet_info):
        """
        Add packet to analysis
        
        Args:
            packet_info (dict): Packet information from sniffer
        """
        if packet_info is None:
            return
        
        timestamp = time.time()
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        protocol = packet_info['protocol']
        flags = packet_info.get('flags')
        size = packet_info['size']
        
        # Store packet info
        self.src_ip_packets[src_ip].append({
            'timestamp': timestamp,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'flags': flags,
            'size': size
        })
        
        self.dst_ip_packets[dst_ip].append({
            'timestamp': timestamp,
            'src_ip': src_ip,
            'protocol': protocol,
            'size': size
        })
        
        # Cleanup old entries periodically
        if time.time() - self.last_cleanup > 10:
            self._cleanup_old_packets()
            self.last_cleanup = time.time()
        
        # Run detection algorithms
        self._detect_syn_flood(src_ip)
        self._detect_udp_flood(dst_ip)
        self._detect_icmp_flood(src_ip)
        self._detect_bandwidth_spike(dst_ip)
    
    def _cleanup_old_packets(self):
        """Remove packets older than TIME_WINDOW"""
        current_time = time.time()
        cutoff_time = current_time - self.TIME_WINDOW
        
        for ip in list(self.src_ip_packets.keys()):
            while self.src_ip_packets[ip] and self.src_ip_packets[ip][0]['timestamp'] < cutoff_time:
                self.src_ip_packets[ip].popleft()
            if not self.src_ip_packets[ip]:
                del self.src_ip_packets[ip]
        
        for ip in list(self.dst_ip_packets.keys()):
            while self.dst_ip_packets[ip] and self.dst_ip_packets[ip][0]['timestamp'] < cutoff_time:
                self.dst_ip_packets[ip].popleft()
            if not self.dst_ip_packets[ip]:
                del self.dst_ip_packets[ip]
    
    def _detect_syn_flood(self, src_ip):
        """
        Detect SYN Flood Attack
        Characteristics: High rate of SYN packets from single source
        """
        packets = self.src_ip_packets[src_ip]
        if not packets:
            return
        
        current_time = time.time()
        cutoff_time = current_time - self.TIME_WINDOW
        
        # Count SYN packets in time window
        syn_count = sum(1 for p in packets 
                       if p['timestamp'] > cutoff_time and 
                       p['protocol'] == 'TCP' and 
                       p['flags'] and 
                       (p['flags'] & 0x02))  # SYN flag
        
        syn_rate = syn_count / self.TIME_WINDOW
        
        if syn_rate > self.SYN_FLOOD_THRESHOLD:
            alert = {
                'timestamp': datetime.now(),
                'type': 'SYN_FLOOD',
                'severity': 'HIGH',
                'source_ip': src_ip,
                'detection_value': syn_rate,
                'threshold': self.SYN_FLOOD_THRESHOLD,
                'description': f'SYN Flood detected from {src_ip}: {syn_rate:.2f} packets/sec'
            }
            self.alerts.append(alert)
            self.attack_detected = True
            logger.warning(f"🚨 {alert['description']}")
    
    def _detect_udp_flood(self, dst_ip):
        """
        Detect UDP Flood Attack
        Characteristics: High rate of UDP packets to single destination
        """
        packets = self.dst_ip_packets[dst_ip]
        if not packets:
            return
        
        current_time = time.time()
        cutoff_time = current_time - self.TIME_WINDOW
        
        # Count UDP packets in time window
        udp_count = sum(1 for p in packets 
                       if p['timestamp'] > cutoff_time and 
                       p['protocol'] == 'UDP')
        
        udp_rate = udp_count / self.TIME_WINDOW
        
        if udp_rate > self.UDP_FLOOD_THRESHOLD:
            alert = {
                'timestamp': datetime.now(),
                'type': 'UDP_FLOOD',
                'severity': 'HIGH',
                'target_ip': dst_ip,
                'detection_value': udp_rate,
                'threshold': self.UDP_FLOOD_THRESHOLD,
                'description': f'UDP Flood detected to {dst_ip}: {udp_rate:.2f} packets/sec'
            }
            self.alerts.append(alert)
            self.attack_detected = True
            logger.warning(f"🚨 {alert['description']}")
    
    def _detect_icmp_flood(self, src_ip):
        """
        Detect ICMP Flood Attack
        Characteristics: High rate of ICMP packets (ping flood)
        """
        packets = self.src_ip_packets[src_ip]
        if not packets:
            return
        
        current_time = time.time()
        cutoff_time = current_time - self.TIME_WINDOW
        
        # Count ICMP packets in time window
        icmp_count = sum(1 for p in packets 
                        if p['timestamp'] > cutoff_time and 
                        p['protocol'] == 'ICMP')
        
        icmp_rate = icmp_count / self.TIME_WINDOW
        
        if icmp_rate > self.ICMP_FLOOD_THRESHOLD:
            alert = {
                'timestamp': datetime.now(),
                'type': 'ICMP_FLOOD',
                'severity': 'MEDIUM',
                'source_ip': src_ip,
                'detection_value': icmp_rate,
                'threshold': self.ICMP_FLOOD_THRESHOLD,
                'description': f'ICMP Flood detected from {src_ip}: {icmp_rate:.2f} packets/sec'
            }
            self.alerts.append(alert)
            self.attack_detected = True
            logger.warning(f"🚨 {alert['description']}")
    
    def _detect_bandwidth_spike(self, dst_ip):
        """
        Detect Bandwidth Spike Anomaly
        Characteristics: Abnormal increase in total traffic volume
        """
        packets = self.dst_ip_packets[dst_ip]
        if not packets:
            return
        
        current_time = time.time()
        cutoff_time = current_time - self.TIME_WINDOW
        
        # Calculate total bandwidth in time window
        total_bytes = sum(p['size'] for p in packets 
                         if p['timestamp'] > cutoff_time)
        
        if total_bytes > self.BANDWIDTH_SPIKE_THRESHOLD:
            alert = {
                'timestamp': datetime.now(),
                'type': 'BANDWIDTH_SPIKE',
                'severity': 'MEDIUM',
                'target_ip': dst_ip,
                'detection_value': total_bytes / (1024 * 1024),  # Convert to MB
                'threshold': self.BANDWIDTH_SPIKE_THRESHOLD / (1024 * 1024),
                'description': f'Bandwidth spike to {dst_ip}: {total_bytes / (1024*1024):.2f} MB in {self.TIME_WINDOW}s'
            }
            self.alerts.append(alert)
            self.attack_detected = True
            logger.warning(f"🚨 {alert['description']}")
    
    def get_recent_alerts(self, count=10):
        """Get recent alerts"""
        return self.alerts[-count:]
    
    def get_statistics(self):
        """Get detection statistics"""
        return {
            'total_alerts': len(self.alerts),
            'attack_detected': self.attack_detected,
            'tracked_source_ips': len(self.src_ip_packets),
            'tracked_dest_ips': len(self.dst_ip_packets),
            'alert_types': self._count_alert_types()
        }
    
    def _count_alert_types(self):
        """Count alerts by type"""
        types = defaultdict(int)
        for alert in self.alerts:
            types[alert['type']] += 1
        return dict(types)
    
    def clear_alerts(self):
        """Clear alert history"""
        self.alerts = []
        self.attack_detected = False


if __name__ == "__main__":
    detector = DoSDetector()
    
    # Example packet
    sample_packet = {
        'src_ip': '192.168.1.100',
        'dst_ip': '10.0.0.1',
        'protocol': 'TCP',
        'flags': 0x02,  # SYN flag
        'size': 64
    }
    
    print("DoS Detector initialized successfully")
