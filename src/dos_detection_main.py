"""
Main DoS Detection Application
Orchestrates packet capture, detection, and alerting
"""

import logging
import time
import sys
from pathlib import Path
from argparse import ArgumentParser
import threading
import json

from packet_sniffer import PacketSniffer
from dos_detector import DoSDetector
from alert_manager import AlertManager, AlertSeverity
from pcap_analyzer import PCAPAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/dos_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class DoSDetectionSystem:
    """Main DoS detection system orchestrator"""
    
    def __init__(self, interface=None):
        """
        Initialize DoS detection system
        
        Args:
            interface (str): Network interface to monitor
        """
        self.interface = interface
        self.sniffer = PacketSniffer(interface=interface)
        self.detector = DoSDetector()
        self.alert_manager = AlertManager()
        self.pcap_analyzer = PCAPAnalyzer()
        self.running = False
        self.stats = {
            'packets_processed': 0,
            'alerts_generated': 0,
            'start_time': None
        }
    
    def packet_handler(self, packet):
        """Handle each captured packet"""
        try:
            # Extract packet info
            from scapy.all import IP
            
            if IP in packet:
                packet_info = {
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': self._get_protocol_name(packet),
                    'flags': self._get_flags(packet),
                    'size': len(packet),
                    'raw_packet': packet
                }
                
                # Process through detector
                self.detector.add_packet(packet_info)
                self.stats['packets_processed'] += 1
                
                # Check for new alerts
                new_alerts = self.detector.get_recent_alerts(1)
                if new_alerts and len(new_alerts) > self.stats['alerts_generated']:
                    alert = new_alerts[-1]
                    self.stats['alerts_generated'] += 1
                    self._handle_alert(alert)
                
                # Print progress
                if self.stats['packets_processed'] % 100 == 0:
                    self._print_status()
        
        except Exception as e:
            logger.error(f"Error in packet handler: {str(e)}")
    
    def _get_protocol_name(self, packet):
        """Extract protocol name from packet"""
        from scapy.all import TCP, UDP, ICMP
        
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        else:
            return 'OTHER'
    
    def _get_flags(self, packet):
        """Extract TCP flags if available"""
        from scapy.all import TCP
        
        if TCP in packet:
            return packet[TCP].flags
        return None
    
    def _handle_alert(self, alert):
        """Handle new alert"""
        try:
            severity_map = {
                'LOW': AlertSeverity.LOW,
                'MEDIUM': AlertSeverity.MEDIUM,
                'HIGH': AlertSeverity.HIGH,
                'CRITICAL': AlertSeverity.CRITICAL
            }
            
            severity = severity_map.get(alert['severity'], AlertSeverity.MEDIUM)
            
            self.alert_manager.create_alert(
                alert_type=alert['type'],
                severity=severity,
                details=alert
            )
        except Exception as e:
            logger.error(f"Error handling alert: {str(e)}")
    
    def start(self, packet_count=0):
        """
        Start the DoS detection system
        
        Args:
            packet_count (int): Number of packets to capture (0 = unlimited)
        """
        self.running = True
        self.stats['start_time'] = time.time()
        
        logger.info("=" * 60)
        logger.info("DoS ATTACK DETECTION SYSTEM STARTED")
        logger.info("=" * 60)
        logger.info(f"Monitoring interface: {self.interface or 'default'}")
        logger.info(f"Packet capture limit: {packet_count if packet_count > 0 else 'unlimited'}")
        logger.info("Press Ctrl+C to stop")
        logger.info("=" * 60)
        
        try:
            self.sniffer.packet_count = packet_count
            self.sniffer.start_sniffing(callback=self.packet_handler)
        
        except KeyboardInterrupt:
            logger.info("\nReceived interrupt signal. Shutting down...")
        except Exception as e:
            logger.error(f"Error during detection: {str(e)}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the detection system"""
        self.running = False
        logger.info("\n" + "=" * 60)
        logger.info("DoS DETECTION SYSTEM STOPPED")
        logger.info("=" * 60)
        self._print_final_report()
        logger.info("=" * 60)
    
    def _print_status(self):
        """Print current status"""
        detector_stats = self.detector.get_statistics()
        elapsed = time.time() - self.stats['start_time']
        
        logger.info(f"\n--- Status Update ({elapsed:.1f}s) ---")
        logger.info(f"Packets processed: {self.stats['packets_processed']}")
        logger.info(f"Alerts generated: {self.stats['alerts_generated']}")
        logger.info(f"Attack detected: {detector_stats['attack_detected']}")
        logger.info(f"Tracked source IPs: {detector_stats['tracked_source_ips']}")
        logger.info(f"Tracked dest IPs: {detector_stats['tracked_dest_ips']}")
        
        alert_types = detector_stats['alert_types']
        if alert_types:
            logger.info(f"Alert types: {alert_types}")
    
    def _print_final_report(self):
        """Print final detection report"""
        elapsed = time.time() - self.stats['start_time']
        detector_stats = self.detector.get_statistics()
        alert_summary = self.alert_manager.get_alert_summary()
        
        logger.info(f"\nElapsed time: {elapsed:.2f} seconds")
        logger.info(f"Total packets processed: {self.stats['packets_processed']}")
        logger.info(f"Packets per second: {self.stats['packets_processed'] / elapsed:.2f}")
        logger.info(f"\nTotal alerts: {alert_summary['total_alerts']}")
        
        if alert_summary['by_type']:
            logger.info("Alerts by type:")
            for alert_type, count in alert_summary['by_type'].items():
                logger.info(f"  {alert_type}: {count}")
        
        if alert_summary['by_severity']:
            logger.info("Alerts by severity:")
            for severity, count in alert_summary['by_severity'].items():
                logger.info(f"  {severity}: {count}")
        
        if alert_summary['critical_alerts'] > 0:
            logger.critical(f"\n⚠️  {alert_summary['critical_alerts']} CRITICAL alerts detected!")
        
        # Export alerts
        export_file = self.alert_manager.export_alerts(format='json')
        if export_file:
            logger.info(f"\nAlerts exported to: {export_file}")
    
    def analyze_pcap(self, filename):
        """
        Analyze a pcap file for forensics
        
        Args:
            filename (str): Name of pcap file to analyze
        """
        logger.info(f"\nStarting PCAP analysis: {filename}")
        results = self.pcap_analyzer.analyze_pcap(filename)
        
        if results:
            logger.info(f"Analysis complete!")
            logger.info(json.dumps(results, indent=2, default=str))
            
            # Export analysis
            export_file = self.pcap_analyzer.export_analysis(filename, format='json')
            logger.info(f"Analysis exported to: {export_file}")
        else:
            logger.error(f"Failed to analyze PCAP file: {filename}")


def main():
    """Main entry point"""
    parser = ArgumentParser(description='DoS Attack Detection System')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('--analyze', help='Analyze a pcap file instead of live capture')
    parser.add_argument('--list-pcaps', action='store_true',
                       help='List available pcap files')
    
    args = parser.parse_args()
    
    # Check for root/admin privileges
    if not args.analyze and not args.list_pcaps:
        try:
            import os
            if os.geteuid() != 0:
                logger.error("This script requires root privileges for packet capture!")
                logger.error("Please run with: sudo python3 dos_detection_main.py")
                sys.exit(1)
        except AttributeError:
            # Windows doesn't have geteuid()
            pass
    
    # Create system
    system = DoSDetectionSystem(interface=args.interface)
    
    # Handle different modes
    if args.list_pcaps:
        pcap_files = system.pcap_analyzer.list_pcap_files()
        if pcap_files:
            logger.info("Available PCAP files:")
            for f in pcap_files:
                logger.info(f"  - {f}")
        else:
            logger.info("No PCAP files found")
    
    elif args.analyze:
        system.analyze_pcap(args.analyze)
    
    else:
        # Start live capture
        try:
            system.start(packet_count=args.count)
        except KeyboardInterrupt:
            logger.info("\nInterrupted by user")


if __name__ == "__main__":
    main()
