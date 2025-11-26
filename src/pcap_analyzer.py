"""
PCAP File Analyzer
Analyzes Wireshark pcap files for DoS attack validation and forensics
"""

import logging
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import os

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/pcap_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PCAPAnalyzer:
    """Analyzes pcap files for forensic investigation"""
    
    def __init__(self, pcap_dir='pcap_files'):
        """
        Initialize PCAP analyzer
        
        Args:
            pcap_dir (str): Directory containing pcap files
        """
        self.pcap_dir = Path(pcap_dir)
        self.pcap_dir.mkdir(exist_ok=True)
        self.results = {}
        
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available. Some features will be limited.")
    
    def analyze_pcap(self, filename):
        """
        Analyze a pcap file for DoS attack patterns
        
        Args:
            filename (str): Name of pcap file to analyze
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is required for PCAP analysis")
            return None
        
        pcap_path = self.pcap_dir / filename
        
        if not pcap_path.exists():
            logger.error(f"PCAP file not found: {pcap_path}")
            return None
        
        try:
            logger.info(f"Analyzing PCAP file: {filename}")
            packets = rdpcap(str(pcap_path))
            
            # Extract statistics
            stats = self._extract_statistics(packets)
            stats['filename'] = filename
            stats['timestamp'] = datetime.now().isoformat()
            
            self.results[filename] = stats
            
            # Detect attack patterns
            attack_patterns = self._detect_attack_patterns(packets, stats)
            stats['attack_patterns'] = attack_patterns
            
            logger.info(f"Analysis complete. Found {len(packets)} packets")
            
            return stats
        
        except Exception as e:
            logger.error(f"Error analyzing PCAP file: {str(e)}")
            return None
    
    def _extract_statistics(self, packets):
        """Extract basic statistics from packets"""
        stats = {
            'total_packets': len(packets),
            'src_ips': defaultdict(int),
            'dst_ips': defaultdict(int),
            'protocols': defaultdict(int),
            'tcp_flags': defaultdict(int),
            'total_bytes': 0,
            'packet_sizes': []
        }
        
        for packet in packets:
            if IP in packet:
                ip_layer = packet[IP]
                
                # Track IPs
                stats['src_ips'][ip_layer.src] += 1
                stats['dst_ips'][ip_layer.dst] += 1
                
                # Track protocols
                if TCP in packet:
                    stats['protocols']['TCP'] += 1
                    tcp_flags = packet[TCP].flags
                    if tcp_flags & 0x02:  # SYN
                        stats['tcp_flags']['SYN'] = stats['tcp_flags'].get('SYN', 0) + 1
                    if tcp_flags & 0x10:  # ACK
                        stats['tcp_flags']['ACK'] = stats['tcp_flags'].get('ACK', 0) + 1
                    if tcp_flags & 0x01:  # FIN
                        stats['tcp_flags']['FIN'] = stats['tcp_flags'].get('FIN', 0) + 1
                
                elif UDP in packet:
                    stats['protocols']['UDP'] += 1
                
                elif ICMP in packet:
                    stats['protocols']['ICMP'] += 1
                
                # Track sizes
                packet_size = len(packet)
                stats['packet_sizes'].append(packet_size)
                stats['total_bytes'] += packet_size
        
        # Calculate aggregates
        stats['src_ips'] = dict(stats['src_ips'])
        stats['dst_ips'] = dict(stats['dst_ips'])
        stats['protocols'] = dict(stats['protocols'])
        stats['tcp_flags'] = dict(stats['tcp_flags'])
        
        if stats['packet_sizes']:
            stats['avg_packet_size'] = sum(stats['packet_sizes']) / len(stats['packet_sizes'])
            stats['max_packet_size'] = max(stats['packet_sizes'])
            stats['min_packet_size'] = min(stats['packet_sizes'])
            stats['packet_sizes'] = None  # Don't store all sizes
        
        return stats
    
    def _detect_attack_patterns(self, packets, stats):
        """Detect DoS attack patterns in PCAP"""
        patterns = {
            'syn_flood_detected': False,
            'udp_flood_detected': False,
            'icmp_flood_detected': False,
            'suspicious_ips': []
        }
        
        # SYN Flood detection
        syn_count = stats['tcp_flags'].get('SYN', 0)
        if syn_count > len(packets) * 0.5:  # More than 50% SYN packets
            patterns['syn_flood_detected'] = True
            logger.warning("Potential SYN Flood detected in PCAP")
        
        # UDP Flood detection
        udp_count = stats['protocols'].get('UDP', 0)
        if udp_count > len(packets) * 0.5:
            patterns['udp_flood_detected'] = True
            logger.warning("Potential UDP Flood detected in PCAP")
        
        # ICMP Flood detection
        icmp_count = stats['protocols'].get('ICMP', 0)
        if icmp_count > len(packets) * 0.3:
            patterns['icmp_flood_detected'] = True
            logger.warning("Potential ICMP Flood detected in PCAP")
        
        # Identify suspicious IPs (high packet count)
        total_packets = len(packets)
        threshold = total_packets * 0.2  # IPs sending more than 20% of packets
        
        for ip, count in stats['src_ips'].items():
            if count > threshold:
                patterns['suspicious_ips'].append({
                    'ip': ip,
                    'packet_count': count,
                    'percentage': (count / total_packets) * 100
                })
        
        return patterns
    
    def get_analysis_report(self, filename):
        """Get detailed analysis report for a file"""
        if filename not in self.results:
            return None
        
        return self.results[filename]
    
    def export_analysis(self, filename, format='json'):
        """
        Export analysis results
        
        Args:
            filename (str): PCAP filename to export analysis for
            format (str): 'json' or 'txt'
        """
        if filename not in self.results:
            logger.error(f"No analysis found for {filename}")
            return None
        
        results = self.results[filename]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        try:
            if format == 'json':
                export_file = self.pcap_dir / f"analysis_{timestamp}.json"
                with open(export_file, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
            
            elif format == 'txt':
                export_file = self.pcap_dir / f"analysis_{timestamp}.txt"
                with open(export_file, 'w') as f:
                    f.write("DoS Attack Analysis Report\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(f"File: {results['filename']}\n")
                    f.write(f"Timestamp: {results['timestamp']}\n\n")
                    
                    f.write("STATISTICS:\n")
                    f.write(f"Total Packets: {results['total_packets']}\n")
                    f.write(f"Total Bytes: {results['total_bytes']:,}\n")
                    f.write(f"Avg Packet Size: {results.get('avg_packet_size', 0):.2f}\n\n")
                    
                    f.write("PROTOCOLS:\n")
                    for protocol, count in results['protocols'].items():
                        f.write(f"  {protocol}: {count}\n")
                    
                    f.write("\nATTACK PATTERNS:\n")
                    patterns = results.get('attack_patterns', {})
                    f.write(f"  SYN Flood: {patterns.get('syn_flood_detected', False)}\n")
                    f.write(f"  UDP Flood: {patterns.get('udp_flood_detected', False)}\n")
                    f.write(f"  ICMP Flood: {patterns.get('icmp_flood_detected', False)}\n")
            
            logger.info(f"Analysis exported to {export_file}")
            return str(export_file)
        
        except Exception as e:
            logger.error(f"Failed to export analysis: {str(e)}")
            return None
    
    def list_pcap_files(self):
        """List all pcap files in directory"""
        try:
            return [f.name for f in self.pcap_dir.glob('*.pcap*')]
        except Exception as e:
            logger.error(f"Error listing PCAP files: {str(e)}")
            return []


if __name__ == "__main__":
    analyzer = PCAPAnalyzer()
    print(f"PCAP directory: {analyzer.pcap_dir}")
    print(f"Scapy available: {SCAPY_AVAILABLE}")
