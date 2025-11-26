"""
Utility functions for DoS detection
Helper functions for IP analysis, pattern matching, and reporting
"""

import re
from ipaddress import ip_address, IPv4Address
from datetime import datetime


class IPAnalyzer:
    """Analyze and classify IP addresses"""
    
    # Common private IP ranges
    PRIVATE_RANGES = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),  # Loopback
    ]
    
    @staticmethod
    def is_private_ip(ip_str):
        """Check if IP is in private range"""
        try:
            ip = ip_address(ip_str)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_ip(ip_str):
        """Validate IP address format"""
        try:
            ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def get_ip_type(ip_str):
        """Classify IP type"""
        try:
            ip = ip_address(ip_str)
            if ip.is_private:
                return 'PRIVATE'
            elif ip.is_loopback:
                return 'LOOPBACK'
            elif ip.is_multicast:
                return 'MULTICAST'
            elif ip.is_reserved:
                return 'RESERVED'
            else:
                return 'PUBLIC'
        except ValueError:
            return 'INVALID'


class PatternMatcher:
    """Match network patterns"""
    
    @staticmethod
    def is_syn_flood_pattern(packet_list):
        """
        Check if packets match SYN Flood pattern
        Pattern: Many SYN packets, few SYN-ACK responses
        """
        if not packet_list:
            return False
        
        syn_count = sum(1 for p in packet_list 
                       if p.get('protocol') == 'TCP' and (p.get('flags', 0) & 0x02))
        ack_count = sum(1 for p in packet_list 
                       if p.get('protocol') == 'TCP' and (p.get('flags', 0) & 0x10))
        
        if len(packet_list) == 0:
            return False
        
        syn_ratio = syn_count / len(packet_list)
        return syn_ratio > 0.8 and ack_count < syn_count * 0.1
    
    @staticmethod
    def is_distributed_attack(src_ip_list):
        """Check if attack appears to be distributed (multiple sources)"""
        unique_ips = set(src_ip_list)
        return len(unique_ips) > 5
    
    @staticmethod
    def has_spoofed_packets(packets):
        """Detect potential IP spoofing"""
        # Simple heuristic: packets with same source but different MAC would indicate spoofing
        # This would require MAC address data
        return False


class ReportGenerator:
    """Generate detection reports"""
    
    @staticmethod
    def generate_summary(detector_stats, alert_summary, elapsed_time):
        """Generate summary report"""
        report = {
            'report_generated': datetime.now().isoformat(),
            'execution_time_seconds': elapsed_time,
            'overview': {
                'total_alerts': alert_summary['total_alerts'],
                'critical_alerts': alert_summary.get('critical_alerts', 0),
                'tracked_ips': {
                    'sources': detector_stats.get('tracked_source_ips', 0),
                    'destinations': detector_stats.get('tracked_dest_ips', 0)
                }
            },
            'alerts_by_type': alert_summary.get('by_type', {}),
            'alerts_by_severity': alert_summary.get('by_severity', {}),
            'attack_status': 'DETECTED' if alert_summary['total_alerts'] > 0 else 'CLEAN'
        }
        
        return report
    
    @staticmethod
    def format_report_text(report):
        """Format report as human-readable text"""
        lines = [
            "=" * 70,
            "DoS ATTACK DETECTION REPORT",
            "=" * 70,
            f"\nReport Generated: {report['report_generated']}",
            f"Execution Time: {report['execution_time_seconds']:.2f} seconds",
            f"Status: {report['attack_status']}",
            f"\nOverview:",
            f"  Total Alerts: {report['overview']['total_alerts']}",
            f"  Critical Alerts: {report['overview']['critical_alerts']}",
            f"  Source IPs Tracked: {report['overview']['tracked_ips']['sources']}",
            f"  Destination IPs Tracked: {report['overview']['tracked_ips']['destinations']}",
        ]
        
        if report['alerts_by_type']:
            lines.append("\nAlerts by Type:")
            for alert_type, count in report['alerts_by_type'].items():
                lines.append(f"  {alert_type}: {count}")
        
        if report['alerts_by_severity']:
            lines.append("\nAlerts by Severity:")
            for severity, count in report['alerts_by_severity'].items():
                lines.append(f"  {severity}: {count}")
        
        lines.append("\n" + "=" * 70)
        
        return "\n".join(lines)


class TrafficAnalyzer:
    """Analyze traffic characteristics"""
    
    @staticmethod
    def calculate_packet_rate(packet_timestamps, time_window=1):
        """Calculate packets per second in time window"""
        if not packet_timestamps:
            return 0
        
        return len(packet_timestamps) / time_window
    
    @staticmethod
    def calculate_bandwidth(packet_sizes, time_window=1):
        """Calculate bandwidth in bytes per second"""
        if not packet_sizes:
            return 0
        
        total_bytes = sum(packet_sizes)
        return total_bytes / time_window
    
    @staticmethod
    def detect_anomaly(current_value, baseline, threshold=2.0):
        """
        Detect anomaly using standard deviation threshold
        
        Args:
            current_value: Current metric value
            baseline: Dict with 'mean' and 'std_dev'
            threshold: Number of standard deviations to trigger alert
        """
        if baseline['std_dev'] == 0:
            return False
        
        z_score = abs((current_value - baseline['mean']) / baseline['std_dev'])
        return z_score > threshold


class GeoIP:
    """GeoIP lookup utilities (placeholder for external service)"""
    
    @staticmethod
    def get_country(ip_str):
        """Get country for IP (requires GeoIP database)"""
        # This would integrate with MaxMind GeoIP or similar
        return None
    
    @staticmethod
    def is_vpn_ip(ip_str):
        """Check if IP is from VPN provider"""
        # This would check against known VPN provider ranges
        return False


if __name__ == "__main__":
    # Test utilities
    print("Testing IP Analyzer...")
    assert IPAnalyzer.is_private_ip('192.168.1.1')
    assert not IPAnalyzer.is_private_ip('8.8.8.8')
    assert IPAnalyzer.is_valid_ip('192.168.1.1')
    print("✓ IP Analyzer working")
    
    print("\nTesting Pattern Matcher...")
    packets = [
        {'protocol': 'TCP', 'flags': 0x02},  # SYN
        {'protocol': 'TCP', 'flags': 0x02},  # SYN
        {'protocol': 'TCP', 'flags': 0x02},  # SYN
    ]
    assert PatternMatcher.is_syn_flood_pattern(packets)
    print("✓ Pattern Matcher working")
    
    print("\nTesting Report Generator...")
    detector_stats = {'tracked_source_ips': 5, 'tracked_dest_ips': 2}
    alert_summary = {'total_alerts': 10, 'critical_alerts': 2, 'by_type': {}, 'by_severity': {}}
    report = ReportGenerator.generate_summary(detector_stats, alert_summary, 30.5)
    assert report['attack_status'] == 'DETECTED'
    print("✓ Report Generator working")
    
    print("\nAll utilities tests passed!")
