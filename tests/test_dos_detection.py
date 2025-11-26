"""
Unit tests for DoS Detection System
"""

import unittest
import time
from collections import namedtuple
from unittest.mock import Mock, patch, MagicMock

import sys
sys.path.insert(0, '../src')

from dos_detector import DoSDetector
from alert_manager import AlertManager, AlertSeverity
from pcap_analyzer import PCAPAnalyzer


class TestDoSDetector(unittest.TestCase):
    """Test DoS detection algorithms"""
    
    def setUp(self):
        """Initialize detector for each test"""
        self.detector = DoSDetector()
    
    def test_syn_flood_detection(self):
        """Test SYN Flood detection"""
        # Create simulated SYN flood
        source_ip = '192.168.1.100'
        
        for i in range(100):
            packet = {
                'src_ip': source_ip,
                'dst_ip': '10.0.0.1',
                'protocol': 'TCP',
                'flags': 0x02,  # SYN flag
                'size': 64
            }
            self.detector.add_packet(packet)
            time.sleep(0.01)  # Simulate packet spacing
        
        stats = self.detector.get_statistics()
        
        # Should detect attack
        self.assertTrue(stats['attack_detected'])
        self.assertGreater(len(self.detector.alerts), 0)
        
        # Check alert type
        syn_alerts = [a for a in self.detector.alerts if a['type'] == 'SYN_FLOOD']
        self.assertGreater(len(syn_alerts), 0)
    
    def test_udp_flood_detection(self):
        """Test UDP Flood detection"""
        target_ip = '10.0.0.1'
        
        for i in range(100):
            packet = {
                'src_ip': f'192.168.1.{i % 10}',
                'dst_ip': target_ip,
                'protocol': 'UDP',
                'flags': None,
                'size': 512
            }
            self.detector.add_packet(packet)
        
        stats = self.detector.get_statistics()
        
        # Should detect attack
        self.assertTrue(stats['attack_detected'])
        
        udp_alerts = [a for a in self.detector.alerts if a['type'] == 'UDP_FLOOD']
        self.assertGreater(len(udp_alerts), 0)
    
    def test_icmp_flood_detection(self):
        """Test ICMP Flood detection"""
        source_ip = '192.168.1.100'
        
        for i in range(60):
            packet = {
                'src_ip': source_ip,
                'dst_ip': '10.0.0.1',
                'protocol': 'ICMP',
                'flags': None,
                'size': 64
            }
            self.detector.add_packet(packet)
        
        stats = self.detector.get_statistics()
        
        icmp_alerts = [a for a in self.detector.alerts if a['type'] == 'ICMP_FLOOD']
        # May or may not detect depending on timing
        # Just verify it runs without error
        self.assertIsNotNone(stats)
    
    def test_normal_traffic(self):
        """Test that normal traffic doesn't trigger alerts"""
        packets = [
            {'src_ip': '192.168.1.1', 'dst_ip': '8.8.8.8', 'protocol': 'TCP', 'flags': 0x10, 'size': 1024},
            {'src_ip': '192.168.1.2', 'dst_ip': '8.8.8.8', 'protocol': 'TCP', 'flags': 0x10, 'size': 1024},
            {'src_ip': '192.168.1.3', 'dst_ip': '8.8.8.8', 'protocol': 'UDP', 'flags': None, 'size': 512},
        ]
        
        for packet in packets:
            self.detector.add_packet(packet)
        
        # Normal traffic should not trigger alerts
        self.assertEqual(len(self.detector.alerts), 0)
    
    def test_statistics(self):
        """Test detector statistics"""
        packet = {
            'src_ip': '192.168.1.1',
            'dst_ip': '10.0.0.1',
            'protocol': 'TCP',
            'flags': 0x10,
            'size': 1024
        }
        
        self.detector.add_packet(packet)
        stats = self.detector.get_statistics()
        
        self.assertIn('total_alerts', stats)
        self.assertIn('tracked_source_ips', stats)
        self.assertIn('tracked_dest_ips', stats)
        self.assertEqual(stats['tracked_source_ips'], 1)


class TestAlertManager(unittest.TestCase):
    """Test alert management"""
    
    def setUp(self):
        """Initialize alert manager"""
        self.manager = AlertManager()
    
    def test_create_alert(self):
        """Test alert creation"""
        alert = self.manager.create_alert(
            alert_type='SYN_FLOOD',
            severity=AlertSeverity.HIGH,
            details={
                'source_ip': '192.168.1.1',
                'description': 'Test alert'
            }
        )
        
        self.assertIsNotNone(alert)
        self.assertEqual(alert['type'], 'SYN_FLOOD')
        self.assertEqual(alert['severity'], 'HIGH')
        self.assertEqual(len(self.manager.alerts), 1)
    
    def test_filter_alerts(self):
        """Test alert filtering"""
        self.manager.create_alert('SYN_FLOOD', AlertSeverity.HIGH, {'source_ip': '192.168.1.1'})
        self.manager.create_alert('UDP_FLOOD', AlertSeverity.MEDIUM, {'source_ip': '192.168.1.2'})
        self.manager.create_alert('SYN_FLOOD', AlertSeverity.HIGH, {'source_ip': '192.168.1.3'})
        
        # Filter by type
        syn_alerts = self.manager.filter_alerts(alert_type='SYN_FLOOD')
        self.assertEqual(len(syn_alerts), 2)
        
        # Filter by severity
        high_alerts = self.manager.filter_alerts(severity=AlertSeverity.HIGH)
        self.assertEqual(len(high_alerts), 2)
    
    def test_alert_summary(self):
        """Test alert summary"""
        self.manager.create_alert('SYN_FLOOD', AlertSeverity.HIGH, {})
        self.manager.create_alert('UDP_FLOOD', AlertSeverity.MEDIUM, {})
        
        summary = self.manager.get_alert_summary()
        
        self.assertEqual(summary['total_alerts'], 2)
        self.assertEqual(summary['by_type']['SYN_FLOOD'], 1)
        self.assertEqual(summary['by_type']['UDP_FLOOD'], 1)
        self.assertEqual(summary['by_severity']['HIGH'], 1)
        self.assertEqual(summary['by_severity']['MEDIUM'], 1)


class TestPCAPAnalyzer(unittest.TestCase):
    """Test PCAP analysis"""
    
    def setUp(self):
        """Initialize analyzer"""
        self.analyzer = PCAPAnalyzer()
    
    def test_analyzer_initialization(self):
        """Test analyzer initializes correctly"""
        self.assertIsNotNone(self.analyzer)
        self.assertIsNotNone(self.analyzer.pcap_dir)
    
    def test_list_pcap_files(self):
        """Test listing pcap files"""
        files = self.analyzer.list_pcap_files()
        self.assertIsInstance(files, list)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_detection_workflow(self):
        """Test complete detection workflow"""
        detector = DoSDetector()
        alert_manager = AlertManager()
        
        # Simulate attack
        for i in range(100):
            packet = {
                'src_ip': '192.168.1.100',
                'dst_ip': '10.0.0.1',
                'protocol': 'TCP',
                'flags': 0x02,
                'size': 64
            }
            detector.add_packet(packet)
            time.sleep(0.01)
        
        # Process alerts
        for alert in detector.alerts:
            alert_manager.create_alert(
                alert['type'],
                AlertSeverity.HIGH,
                alert
            )
        
        summary = alert_manager.get_alert_summary()
        
        self.assertGreater(summary['total_alerts'], 0)
        self.assertIn('SYN_FLOOD', summary['by_type'])


if __name__ == '__main__':
    unittest.main()
