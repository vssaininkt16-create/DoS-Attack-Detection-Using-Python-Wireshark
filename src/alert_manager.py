"""
Alert Management and Notification System
Handles alert generation, filtering, and reporting
"""

import logging
import json
from datetime import datetime
from enum import Enum
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/alerts.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AlertManager:
    """Manages alerts, filtering, and notifications"""
    
    def __init__(self, log_dir='logs'):
        """Initialize alert manager"""
        self.alerts = []
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.alert_log_file = self.log_dir / 'dos_alerts.json'
        
    def create_alert(self, alert_type, severity, details):
        """
        Create a new alert
        
        Args:
            alert_type (str): Type of alert (SYN_FLOOD, UDP_FLOOD, etc.)
            severity (AlertSeverity): Severity level
            details (dict): Alert details
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity.name,
            'details': details,
            'id': self._generate_alert_id()
        }
        
        self.alerts.append(alert)
        self._log_alert(alert)
        self._trigger_notification(alert)
        
        return alert
    
    def _generate_alert_id(self):
        """Generate unique alert ID"""
        return f"ALERT-{len(self.alerts):06d}"
    
    def _log_alert(self, alert):
        """Log alert to file"""
        try:
            with open(self.alert_log_file, 'a') as f:
                f.write(json.dumps(alert) + '\n')
            logger.info(f"Alert logged: {alert['id']} - {alert['type']}")
        except Exception as e:
            logger.error(f"Failed to log alert: {str(e)}")
    
    def _trigger_notification(self, alert):
        """
        Trigger notification for alert
        Can be extended to send emails, webhooks, Slack messages, etc.
        """
        severity = AlertSeverity[alert['severity']]
        
        if severity == AlertSeverity.CRITICAL:
            logger.critical(f"CRITICAL ALERT: {alert['details'].get('description', '')}")
            # Could send email or SMS here
        elif severity == AlertSeverity.HIGH:
            logger.warning(f"HIGH SEVERITY: {alert['details'].get('description', '')}")
            # Could send webhook notification
    
    def filter_alerts(self, alert_type=None, severity=None, source_ip=None):
        """Filter alerts by criteria"""
        filtered = self.alerts
        
        if alert_type:
            filtered = [a for a in filtered if a['type'] == alert_type]
        
        if severity:
            filtered = [a for a in filtered if a['severity'] == severity.name]
        
        if source_ip:
            filtered = [a for a in filtered if a['details'].get('source_ip') == source_ip]
        
        return filtered
    
    def get_alert_summary(self):
        """Get summary of alerts"""
        summary = {
            'total_alerts': len(self.alerts),
            'by_type': {},
            'by_severity': {},
            'critical_alerts': 0
        }
        
        for alert in self.alerts:
            # Count by type
            alert_type = alert['type']
            summary['by_type'][alert_type] = summary['by_type'].get(alert_type, 0) + 1
            
            # Count by severity
            severity = alert['severity']
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count critical
            if severity == 'CRITICAL':
                summary['critical_alerts'] += 1
        
        return summary
    
    def export_alerts(self, format='json', filename=None):
        """
        Export alerts in specified format
        
        Args:
            format (str): 'json' or 'csv'
            filename (str): Export filename
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"alerts_export_{timestamp}.{format}"
        
        export_path = self.log_dir / filename
        
        try:
            if format == 'json':
                with open(export_path, 'w') as f:
                    json.dump(self.alerts, f, indent=2, default=str)
            
            elif format == 'csv':
                import csv
                with open(export_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=['timestamp', 'type', 'severity', 'details'])
                    writer.writeheader()
                    for alert in self.alerts:
                        row = alert.copy()
                        row['details'] = json.dumps(row['details'])
                        writer.writerow(row)
            
            logger.info(f"Alerts exported to {export_path}")
            return str(export_path)
        
        except Exception as e:
            logger.error(f"Failed to export alerts: {str(e)}")
            return None
    
    def clear_old_alerts(self, days=7):
        """Clear alerts older than specified days"""
        from datetime import timedelta
        cutoff_date = datetime.now() - timedelta(days=days)
        
        initial_count = len(self.alerts)
        self.alerts = [
            a for a in self.alerts 
            if datetime.fromisoformat(a['timestamp']) > cutoff_date
        ]
        
        removed_count = initial_count - len(self.alerts)
        logger.info(f"Cleared {removed_count} alerts older than {days} days")


if __name__ == "__main__":
    manager = AlertManager()
    
    # Example alert
    alert = manager.create_alert(
        alert_type='SYN_FLOOD',
        severity=AlertSeverity.HIGH,
        details={
            'source_ip': '192.168.1.100',
            'target_ip': '10.0.0.1',
            'packet_rate': 150,
            'description': 'SYN Flood attack detected'
        }
    )
    
    print(f"Alert created: {alert['id']}")
    print(f"Summary: {manager.get_alert_summary()}")
