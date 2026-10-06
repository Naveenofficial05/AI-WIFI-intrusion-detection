"""
Alert Generator Module
Generates alerts for the administrator when suspicious activity is detected
"""

import json
from datetime import datetime
from colorama import Fore, Style, init


# Initialize colorama
init(autoreset=True)


class AlertGenerator:
    def __init__(self, log_file_path=None):
        self.log_file_path = log_file_path
        self.alert_history = []

    def generate_alert(self, detection):
        """Generate alert for a single detection"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'detection_type': detection['detection_type'].value,
            'security_level': detection['security_level'].value,
            'severity': detection['severity'],
            'reason': detection['reason'],
            'action': detection['action']
        }

        if 'ip_address' in detection:
            alert['ip_address'] = detection['ip_address']
        if 'traffic_rate' in detection:
            alert['traffic_rate'] = detection['traffic_rate']

        self.alert_history.append(alert)
        return alert

    def format_alert(self, alert):
        """Format alert for console display with colors"""
        severity_colors = {
            'LOW': Fore.GREEN,
            'MEDIUM': Fore.YELLOW,
            'HIGH': Fore.RED,
            'CRITICAL': Fore.RED + Style.BRIGHT
        }

        color = severity_colors.get(alert['severity'], Fore.WHITE)

        output = []
        output.append("=" * 60)
        output.append(f"{color}SECURITY ALERT{Style.RESET_ALL}")
        output.append("=" * 60)
        output.append(f"Time: {alert['timestamp']}")
        output.append(f"Type: {alert['detection_type']}")
        output.append(f"Security Level: {alert['security_level']}")
        output.append(f"{color}Severity: {alert['severity']}{Style.RESET_ALL}")

        if 'ip_address' in alert:
            output.append(f"Device: {alert['ip_address']}")

        if 'traffic_rate' in alert:
            output.append(f"Traffic Rate: {alert['traffic_rate']:.2f} bytes/sec")

        output.append(f"Reason: {alert['reason']}")
        output.append(f"{color}Action: {alert['action']}{Style.RESET_ALL}")
        output.append("=" * 60)

        return "\n".join(output)

    def format_summary(self, analysis_result):
        """Format summary of analysis results"""
        overall_level = analysis_result['overall_security_level']
        total_detections = analysis_result['total_detections']

        level_colors = {
            'NORMAL': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'SUSPICIOUS': Fore.RED,
            'HIGH RISK': Fore.RED + Style.BRIGHT
        }

        color = level_colors.get(overall_level, Fore.WHITE)

        output = []
        output.append("")
        output.append("=" * 60)
        output.append(f"{color}NETWORK MONITORING STATUS{Style.RESET_ALL}")
        output.append("=" * 60)
        output.append(f"Overall Status: {color}{overall_level}{Style.RESET_ALL}")
        output.append(f"Total Detections: {total_detections}")

        if total_detections > 0:
            output.append("")
            output.append(f"{color}ALERTS GENERATED{Style.RESET_ALL}")
            output.append("-" * 60)
            for i, detection in enumerate(analysis_result['detections'], 1):
                output.append(f"{i}. {detection['detection_type'].value}")
                output.append(f"   Severity: {detection['severity']}")
                output.append(f"   {detection['reason']}")
        else:
            output.append("")
            output.append(f"{Fore.GREEN}No suspicious activity detected.{Style.RESET_ALL}")
            output.append("Network traffic is normal.")

        output.append("=" * 60)
        output.append("")

        return "\n".join(output)

    def log_alert(self, alert):
        """Log alert to file"""
        if self.log_file_path:
            try:
                with open(self.log_file_path, 'a') as f:
                    f.write(json.dumps(alert, indent=2) + "\n")
            except Exception as e:
                print(f"Error logging alert: {e}")

    def display_alert(self, alert):
        """Display alert to console"""
        formatted_alert = self.format_alert(alert)
        print(formatted_alert)
        self.log_alert(alert)

    def display_summary(self, analysis_result):
        """Display summary to console"""
        formatted_summary = self.format_summary(analysis_result)
        print(formatted_summary)

    def get_alert_statistics(self):
        """Get statistics about generated alerts"""
        if not self.alert_history:
            return {
                'total_alerts': 0,
                'by_type': {},
                'by_severity': {}
            }

        by_type = {}
        by_severity = {}

        for alert in self.alert_history:
            det_type = alert['detection_type']
            severity = alert['severity']

            by_type[det_type] = by_type.get(det_type, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1

        return {
            'total_alerts': len(self.alert_history),
            'by_type': by_type,
            'by_severity': by_severity
        }
