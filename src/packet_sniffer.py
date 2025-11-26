"""
Packet Sniffer Module
Real-time packet capture and processing for DoS detection
"""

import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers.inet import IP
from datetime import datetime
from collections import defaultdict, deque
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/packet_sniffer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PacketSniffer:
    """Captures and processes network packets for analysis"""
    
    def __init__(self, interface=None, packet_count=0):
        """
        Initialize packet sniffer
        
        Args:
            interface (str): Network interface to sniff on (None = default)
            packet_count (int): Number of packets to capture (0 = unlimited)
        """
        self.interface = interface
        self.packet_count = packet_count
        self.packets_captured = 0
        self.start_time = None
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        self.packets_captured += 1
        
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            packet_size = len(packet)
            
            # Extract protocol info
            protocol_name = "OTHER"
            flags = None
            
            if TCP in packet:
                protocol_name = "TCP"
                flags = packet[TCP].flags
            elif UDP in packet:
                protocol_name = "UDP"
            elif ICMP in packet:
                protocol_name = "ICMP"
            
            return {
                'timestamp': datetime.now(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': protocol_name,
                'flags': flags,
                'size': packet_size,
                'raw_packet': packet
            }
        
        return None
    
    def start_sniffing(self, callback=None):
        """
        Start packet capture
        
        Args:
            callback (function): Custom callback for each packet
        """
        self.start_time = time.time()
        logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
        logger.info(f"Will capture {self.packet_count if self.packet_count > 0 else 'unlimited'} packets")
        
        try:
            sniff(
                iface=self.interface,
                prn=callback or self.packet_callback,
                count=self.packet_count if self.packet_count > 0 else 0,
                store=False
            )
        except PermissionError:
            logger.error("Permission denied! Please run with sudo for packet capture")
        except Exception as e:
            logger.error(f"Error during packet capture: {str(e)}")
        finally:
            elapsed = time.time() - self.start_time
            logger.info(f"Capture stopped. Captured {self.packets_captured} packets in {elapsed:.2f}s")
    
    def get_stats(self):
        """Return capture statistics"""
        elapsed = time.time() - self.start_time if self.start_time else 0
        return {
            'packets_captured': self.packets_captured,
            'elapsed_time': elapsed,
            'packets_per_second': self.packets_captured / elapsed if elapsed > 0 else 0
        }


if __name__ == "__main__":
    # Example usage
    sniffer = PacketSniffer(packet_count=100)
    sniffer.start_sniffing()
    print(sniffer.get_stats())
