#!/usr/bin/env python3
"""
Quick Start Guide - DoS Attack Detection System
Demonstrates basic usage of the detection system
"""

import sys
import time
sys.path.insert(0, 'src')

from dos_detector import DoSDetector
from alert_manager import AlertManager, AlertSeverity


def simulate_syn_flood():
    """Simulate a SYN Flood attack for testing"""
    print("\n" + "="*60)
    print("SIMULATING SYN FLOOD ATTACK")
    print("="*60)
    
    detector = DoSDetector()
    alert_manager = AlertManager()
    
    attacker_ip = "192.168.1.100"
    target_ip = "10.0.0.1"
    
    print(f"\nAttacker IP: {attacker_ip}")
    print(f"Target IP: {target_ip}")
    print("\nGenerating 100 SYN packets over 5 seconds...")
    
    # Simulate SYN flood spread over time window
    for i in range(100):
        packet = {
            'src_ip': attacker_ip,
            'dst_ip': target_ip,
            'protocol': 'TCP',
            'flags': 0x02,  # SYN flag
            'size': 64
        }
        detector.add_packet(packet)
        time.sleep(0.05)  # 50ms between packets = 20 packets/sec > threshold of 50/sec in window
        
        if (i + 1) % 25 == 0:
            print(f"  Generated {i + 1} packets...")
    
    # Check for alerts
    print("\nChecking for alerts...")
    alerts = detector.get_recent_alerts(10)
    
    if alerts:
        print(f"\n✓ Successfully detected attack!")
        print(f"Total alerts: {len(alerts)}\n")
        
        for alert in alerts:
            print(f"  Alert Type: {alert['type']}")
            print(f"  Severity: {alert['severity']}")
            print(f"  Source IP: {alert.get('source_ip', 'N/A')}")
            print(f"  Detection Value: {alert.get('detection_value', 'N/A'):.2f}")
            print(f"  Description: {alert['description']}")
            print()
    else:
        print("✗ No alerts detected (timing issue)")
    
    # Get statistics
    stats = detector.get_statistics()
    print("\nDetection Statistics:")
    print(f"  Total Alerts: {stats['total_alerts']}")
    print(f"  Attack Detected: {stats['attack_detected']}")
    print(f"  Tracked Source IPs: {stats['tracked_source_ips']}")
    print(f"  Tracked Dest IPs: {stats['tracked_dest_ips']}")
    print(f"  Alert Types: {stats['alert_types']}")


def simulate_udp_flood():
    """Simulate a UDP Flood attack"""
    print("\n" + "="*60)
    print("SIMULATING UDP FLOOD ATTACK")
    print("="*60)
    
    detector = DoSDetector()
    target_ip = "10.0.0.1"
    
    print(f"\nTarget IP: {target_ip}")
    print("Generating 150 UDP packets over 5 seconds...")
    
    # Simulate UDP flood from multiple sources, spread over time
    for i in range(150):
        packet = {
            'src_ip': f"192.168.1.{(i % 20) + 100}",  # Multiple source IPs
            'dst_ip': target_ip,
            'protocol': 'UDP',
            'flags': None,
            'size': 512
        }
        detector.add_packet(packet)
        time.sleep(0.033)  # ~30 packets per second
        
        if (i + 1) % 50 == 0:
            print(f"  Generated {i + 1} packets...")
    
    alerts = detector.get_recent_alerts(10)
    
    if alerts:
        print(f"\n✓ Successfully detected attack!")
        print(f"Total alerts: {len(alerts)}")
        
        for alert in alerts:
            if alert['type'] == 'UDP_FLOOD':
                print(f"\n  UDP Flood Alert:")
                print(f"    Target: {alert.get('target_ip')}")
                print(f"    Detection Rate: {alert.get('detection_value', 0):.2f} packets/sec")
    
    stats = detector.get_statistics()
    print(f"\nAlert Types Found: {stats['alert_types']}")


def simulate_icmp_flood():
    """Simulate an ICMP Flood (ping flood) attack"""
    print("\n" + "="*60)
    print("SIMULATING ICMP FLOOD (PING FLOOD) ATTACK")
    print("="*60)
    
    detector = DoSDetector()
    attacker_ip = "203.0.113.50"  # Example external IP
    target_ip = "10.0.0.50"
    
    print(f"\nAttacker IP: {attacker_ip}")
    print(f"Target IP: {target_ip}")
    print("Generating 75 ICMP packets over 5 seconds...")
    
    # Simulate ICMP flood spread over time window
    for i in range(75):
        packet = {
            'src_ip': attacker_ip,
            'dst_ip': target_ip,
            'protocol': 'ICMP',
            'flags': None,
            'size': 64
        }
        detector.add_packet(packet)
        time.sleep(0.067)  # ~15 packets per second
        
        if (i + 1) % 25 == 0:
            print(f"  Generated {i + 1} packets...")
    
    alerts = detector.get_recent_alerts(10)
    
    if alerts:
        print(f"\n✓ Attack detection results:")
        for alert in alerts:
            if alert['type'] == 'ICMP_FLOOD':
                print(f"  ICMP Flood detected from {alert.get('source_ip')}")
                print(f"  Severity: {alert['severity']}")
    
    stats = detector.get_statistics()
    print(f"\nFinal Detection Statistics: {stats['alert_types']}")


def simulate_normal_traffic():
    """Simulate normal network traffic (should not trigger alerts)"""
    print("\n" + "="*60)
    print("SIMULATING NORMAL NETWORK TRAFFIC")
    print("="*60)
    
    detector = DoSDetector()
    
    print("\nGenerating normal traffic patterns...")
    
    normal_patterns = [
        {'src_ip': '192.168.1.10', 'dst_ip': '8.8.8.8', 'protocol': 'TCP', 'flags': 0x10, 'size': 1024},
        {'src_ip': '192.168.1.20', 'dst_ip': '8.8.8.8', 'protocol': 'TCP', 'flags': 0x10, 'size': 1024},
        {'src_ip': '192.168.1.30', 'dst_ip': '8.8.8.8', 'protocol': 'UDP', 'flags': None, 'size': 512},
        {'src_ip': '192.168.1.40', 'dst_ip': '1.1.1.1', 'protocol': 'TCP', 'flags': 0x18, 'size': 2048},
        {'src_ip': '192.168.1.50', 'dst_ip': '1.1.1.1', 'protocol': 'UDP', 'flags': None, 'size': 256},
    ]
    
    for i in range(20):
        packet = normal_patterns[i % len(normal_patterns)]
        detector.add_packet(packet)
    
    stats = detector.get_statistics()
    
    print(f"\nPackets processed: 20")
    print(f"Alerts triggered: {stats['total_alerts']}")
    
    if stats['total_alerts'] == 0:
        print("✓ Correctly identified normal traffic (no false positives)")
    else:
        print("⚠ Unexpected alerts on normal traffic")
        for alert in detector.alerts:
            print(f"  - {alert['type']}: {alert['description']}")


def main():
    """Run all simulations"""
    print("\n" + "█"*60)
    print("█ DoS ATTACK DETECTION - QUICK START SIMULATIONS")
    print("█"*60)
    
    try:
        # Run simulations
        simulate_syn_flood()
        print("\n" + "-"*60)
        
        simulate_udp_flood()
        print("\n" + "-"*60)
        
        simulate_icmp_flood()
        print("\n" + "-"*60)
        
        simulate_normal_traffic()
        
        print("\n" + "█"*60)
        print("█ SIMULATIONS COMPLETED")
        print("█"*60)
        print("\nNext steps:")
        print("1. Review the detection results above")
        print("2. Check logs in the 'logs/' directory")
        print("3. For live capture, run: sudo python3 src/dos_detection_main.py")
        print("4. To analyze PCAP files: python3 src/dos_detection_main.py --analyze <file.pcap>")
        print("\n")
    
    except Exception as e:
        print(f"\n✗ Error during simulation: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
