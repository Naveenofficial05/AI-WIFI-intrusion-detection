"""AI rule/expert-system analyzer. No machine learning is used."""

import ipaddress
import json
from datetime import datetime
from enum import Enum


class SecurityLevel(Enum):
    NORMAL = "NORMAL"
    WARNING = "WARNING"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH RISK"


class DetectionType(Enum):
    UNKNOWN_DEVICE = "Unknown / Unauthorized Device"
    SUSPICIOUS_CONNECTION = "Suspicious Connection Attempts"
    PORT_SCANNING = "Port Scanning"
    ABNORMAL_TRAFFIC = "Abnormal Traffic"
    DOS_FLOODING = "Possible DoS / Flooding Activity"
    FAILED_CONNECTIONS = "Repeated Failed Connection Attempts"


class AIAnalyzer:
    def __init__(self, authorized_devices_path, settings_path):
        self.authorized_devices = self.load_authorized_devices(authorized_devices_path)
        self.settings = self.load_settings(settings_path)
        self.detection_history = []

    @staticmethod
    def load_authorized_devices(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f).get("authorized_devices", [])
        except Exception as e:
            print(f"Error loading authorized devices: {e}")
            return []

    @staticmethod
    def load_settings(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading settings: {e}")
            return {}

    def is_authorized_device(self, ip_address):
        for device in self.authorized_devices:
            if device.get("ip_address") == ip_address:
                return True, device.get("device_name", "Unknown")
        return False, None

    def _is_local_candidate(self, ip_address, local_network=None):
        try:
            ip = ipaddress.ip_address(ip_address)
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or not ip.is_private:
                return False
            return local_network is None or (ip.version == local_network.version and ip in local_network)
        except (ValueError, TypeError):
            return False

    def analyze_unknown_device(self, ip_address, local_network=None):
        """AI Rule: local/private device not present in authorized list -> suspicious."""
        if not self._is_local_candidate(ip_address, local_network):
            return None
        is_authorized, _ = self.is_authorized_device(ip_address)
        if not is_authorized:
            return {
                "detection_type": DetectionType.UNKNOWN_DEVICE,
                "security_level": SecurityLevel.SUSPICIOUS,
                "ip_address": ip_address,
                "reason": f"Local device {ip_address} is not in the authorized devices list",
                "severity": "HIGH",
                "action": "Alert Admin",
            }
        return None

    def analyze_suspicious_connections(self, ip_address, connection_count):
        threshold = self.settings.get("connection_attempt_threshold", 20)
        if connection_count > threshold:
            return {
                "detection_type": DetectionType.SUSPICIOUS_CONNECTION,
                "security_level": SecurityLevel.WARNING,
                "ip_address": ip_address,
                "reason": f"{connection_count} connection attempts detected within time window (threshold: {threshold})",
                "severity": "MEDIUM",
                "action": "Alert Admin",
            }
        return None

    def analyze_port_scanning(self, ip_address, port_count):
        threshold = self.settings.get("port_scan_threshold", 10)
        if port_count > threshold:
            return {
                "detection_type": DetectionType.PORT_SCANNING,
                "security_level": SecurityLevel.HIGH_RISK,
                "ip_address": ip_address,
                "reason": f"{port_count} unique destination ports accessed within time window (threshold: {threshold})",
                "severity": "HIGH",
                "action": "Alert Admin",
            }
        return None

    def analyze_abnormal_traffic(self, traffic_rate):
        threshold = self.settings.get("traffic_threshold", 1_000_000)
        if traffic_rate > threshold:
            return {
                "detection_type": DetectionType.ABNORMAL_TRAFFIC,
                "security_level": SecurityLevel.WARNING,
                "traffic_rate": traffic_rate,
                "reason": f"Traffic rate {traffic_rate:.2f} bytes/sec exceeds normal threshold {threshold}",
                "severity": "MEDIUM",
                "action": "Alert Admin",
            }
        return None

    def analyze_dos_flooding(self, traffic_rate):
        threshold = self.settings.get("dos_threshold", 10_000_000)
        if traffic_rate > threshold:
            return {
                "detection_type": DetectionType.DOS_FLOODING,
                "security_level": SecurityLevel.HIGH_RISK,
                "traffic_rate": traffic_rate,
                "reason": f"Extremely high traffic rate {traffic_rate:.2f} bytes/sec detected (DoS threshold: {threshold})",
                "severity": "CRITICAL",
                "action": "Alert Admin Immediately",
            }
        return None

    def analyze_failed_connections(self, ip_address, failed_count):
        threshold = self.settings.get("failed_connection_threshold", 5)
        if failed_count > threshold:
            return {
                "detection_type": DetectionType.FAILED_CONNECTIONS,
                "security_level": SecurityLevel.SUSPICIOUS,
                "ip_address": ip_address,
                "reason": f"{failed_count} failed connection attempts detected (threshold: {threshold})",
                "severity": "HIGH",
                "action": "Alert Admin",
            }
        return None

    def analyze_traffic(self, network_info, port_scan_data, connection_data, failed_data, local_network=None):
        detections = []
        for conn in network_info.get("active_connections", []):
            ip = conn.get("remote_address")
            detection = self.analyze_unknown_device(ip, local_network) if ip else None
            if detection and detection not in detections:
                detections.append(detection)

        traffic_rate = network_info.get("traffic_rate", 0)
        for detection in (self.analyze_abnormal_traffic(traffic_rate), self.analyze_dos_flooding(traffic_rate)):
            if detection:
                detections.append(detection)

        for ip, count in port_scan_data.items():
            detection = self.analyze_port_scanning(ip, count)
            if detection:
                detections.append(detection)
        for ip, count in connection_data.items():
            detection = self.analyze_suspicious_connections(ip, count)
            if detection:
                detections.append(detection)
        for ip, count in failed_data.items():
            detection = self.analyze_failed_connections(ip, count)
            if detection:
                detections.append(detection)

        order = {level: i for i, level in enumerate(SecurityLevel)}
        overall = max((d["security_level"] for d in detections), key=lambda x: order[x], default=SecurityLevel.NORMAL)
        result = {
            "timestamp": datetime.now().isoformat(),
            "overall_security_level": overall.value,
            "detections": detections,
            "total_detections": len(detections),
        }
        self.detection_history.append(result)
        self.detection_history = self.detection_history[-100:]
        return result
