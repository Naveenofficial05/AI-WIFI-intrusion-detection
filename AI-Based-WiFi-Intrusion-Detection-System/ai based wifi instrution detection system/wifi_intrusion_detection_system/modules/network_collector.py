"""Network collection for the AI-based Wi-Fi intrusion detection demo.

The collector intentionally uses host-level information available through psutil.
It does not perform packet injection, password attacks, or any offensive action.
"""

import ipaddress
import socket
import psutil
import re
import subprocess
import platform
from datetime import datetime
from collections import defaultdict


class NetworkCollector:
    def __init__(self, interface_name="Wi-Fi"):
        self.interface_name = interface_name
        self.connection_history = defaultdict(list)
        self.port_access_history = defaultdict(list)
        self.failed_connections = defaultdict(list)
        self.start_time = datetime.now()
        self._last_stats = None
        self._last_stats_time = None

    def get_network_interfaces(self):
        return list(psutil.net_if_addrs().keys())

    def get_interface_ip(self):
        try:
            interfaces = psutil.net_if_addrs()

            if self.interface_name in interfaces:
                for addr in interfaces[self.interface_name]:
                    if addr.family == socket.AF_INET:
                        return addr.address

        except Exception as e:
            print(f"Error getting interface IP: {e}")

        return None

    def get_interface_network(self):
        """Return the local IPv4 network for the selected interface."""
        try:
            interfaces = psutil.net_if_addrs()

            for addr in interfaces.get(self.interface_name, []):
                if (
                    addr.family == socket.AF_INET
                    and addr.address
                    and addr.netmask
                ):
                    return ipaddress.ip_network(
                        f"{addr.address}/{addr.netmask}",
                        strict=False
                    )

        except Exception:
            pass

        return None

    def is_local_private_ip(self, ip_address):
        """True only for a private address belonging to the local host LAN.

        Public Internet endpoints are not treated as Wi-Fi clients.
        """
        if not ip_address:
            return False

        try:
            ip = ipaddress.ip_address(ip_address)

            if (
                ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or not ip.is_private
            ):
                return False

            network = self.get_interface_network()

            return (
                network is not None
                and ip.version == network.version
                and ip in network
                and ip != network.broadcast_address
            )

        except ValueError:
            return False

    def collect_active_connections(self):
        connections = []

        try:
            for conn in psutil.net_connections(kind="inet"):

                if conn.status not in {
                    "ESTABLISHED",
                    "SYN_SENT",
                    "SYN_RECV"
                }:
                    continue

                remote_ip = conn.raddr.ip if conn.raddr else None

                connections.append({
                    "local_address": conn.laddr.ip if conn.laddr else None,
                    "local_port": conn.laddr.port if conn.laddr else None,
                    "remote_address": remote_ip,
                    "remote_port": conn.raddr.port if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid,
                    "is_local_device": self.is_local_private_ip(remote_ip),
                    "timestamp": datetime.now().isoformat(),
                })

        except Exception as e:
            print(f"Error collecting connections: {e}")

        return connections

    def track_port_access(self, ip_address, port):
        if not self.is_local_private_ip(ip_address) or not port:
            return

        self.port_access_history[ip_address].append({
            "port": port,
            "timestamp": datetime.now()
        })

    def track_connection_attempt(self, ip_address):
        if not self.is_local_private_ip(ip_address):
            return

        self.connection_history[ip_address].append(datetime.now())

    def track_failed_connection(self, ip_address):
        if not self.is_local_private_ip(ip_address):
            return

        self.failed_connections[ip_address].append(datetime.now())

    def get_port_scan_count(self, ip_address, time_window_seconds):
        current_time = datetime.now()
        ports = set()

        for entry in self.port_access_history[ip_address]:
            if (
                current_time - entry["timestamp"]
            ).total_seconds() <= time_window_seconds:
                ports.add(entry["port"])

        return len(ports)

    def get_connection_attempt_count(
        self,
        ip_address,
        time_window_seconds
    ):
        current_time = datetime.now()

        return sum(
            1
            for timestamp in self.connection_history[ip_address]
            if (
                current_time - timestamp
            ).total_seconds() <= time_window_seconds
        )

    def get_failed_connection_count(
        self,
        ip_address,
        time_window_seconds
    ):
        current_time = datetime.now()

        return sum(
            1
            for timestamp in self.failed_connections[ip_address]
            if (
                current_time - timestamp
            ).total_seconds() <= time_window_seconds
        )

    def get_network_stats(self):
        try:
            stats = psutil.net_io_counters(pernic=True)
            return stats.get(self.interface_name)

        except Exception as e:
            print(f"Error getting network stats: {e}")

        return None

    def get_traffic_rate(self):
        """Calculate bytes/sec from the selected interface between samples."""

        stats = self.get_network_stats()
        now = datetime.now()

        if not stats:
            return 0.0

        if self._last_stats is None or self._last_stats_time is None:
            self._last_stats = stats
            self._last_stats_time = now
            return 0.0

        elapsed = (
            now - self._last_stats_time
        ).total_seconds()

        if elapsed <= 0:
            return 0.0

        total_now = (
            stats.bytes_sent +
            stats.bytes_recv
        )

        total_prev = (
            self._last_stats.bytes_sent +
            self._last_stats.bytes_recv
        )

        rate = max(
            0.0,
            (total_now - total_prev) / elapsed
        )

        self._last_stats = stats
        self._last_stats_time = now

        return rate

    def collect_network_info(self):
        stats = self.get_network_stats()

        return {
            "timestamp": datetime.now().isoformat(),
            "interface": self.interface_name,
            "ip_address": self.get_interface_ip(),
            "active_connections": self.collect_active_connections(),

            "network_stats": {
                "bytes_sent": stats.bytes_sent if stats else 0,
                "bytes_recv": stats.bytes_recv if stats else 0,
                "packets_sent": stats.packets_sent if stats else 0,
                "packets_recv": stats.packets_recv if stats else 0,
            },

            "traffic_rate": self.get_traffic_rate(),
        }

    def _get_arp_neighbors(self):
        """Read the operating system's local ARP/neighbour table.

        This is passive local discovery only. It does not scan or probe hosts.
        On Windows, ``arp -a`` provides IP/MAC pairs already known by the host.
        """

        neighbors = {}

        if platform.system().lower() != "windows":
            return neighbors

        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=getattr(
                    subprocess,
                    "CREATE_NO_WINDOW",
                    0
                ),
            )

            if result.returncode != 0:
                return neighbors

            pattern = re.compile(
                r"(\d{1,3}(?:\.\d{1,3}){3})\s+"
                r"([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+"
                r"([A-Za-z]+)"
            )

            local_network = self.get_interface_network()
            local_ip = self.get_interface_ip()

            for line in result.stdout.splitlines():

                match = pattern.search(line)

                if not match:
                    continue

                ip_text, mac_text, entry_type = match.groups()

                try:
                    ip = ipaddress.ip_address(ip_text)

                except ValueError:
                    continue

                mac = mac_text.replace("-", ":").upper()

                # Ignore invalid/non-device network entries.
                if (
                    local_network is None
                    or ip.version != local_network.version
                    or ip not in local_network
                    or ip_text == local_ip
                    or ip.is_loopback
                    or ip.is_multicast
                    or ip.is_link_local
                    or ip == local_network.broadcast_address
                    or mac == "FF:FF:FF:FF:FF:FF"
                ):
                    continue

                neighbors[ip_text] = {
                    "ip_address": ip_text,
                    "mac_address": mac,
                    "entry_type": entry_type.upper(),
                }

        except (
            OSError,
            subprocess.SubprocessError,
            ValueError
        ) as e:
            print(
                f"Warning: could not read Windows ARP table: {e}"
            )

        return neighbors

    def get_connected_devices(self):
        """Return local/private LAN endpoints discovered from ARP + active connections.

        ARP gives LAN IP/MAC information already known to Windows.
        Active connections are used as a fallback/source of additional local IPs.
        Public Internet endpoints are deliberately excluded.
        """

        devices = set(
            self._get_arp_neighbors().keys()
        )

        for conn in self.collect_active_connections():

            remote_ip = conn.get("remote_address")

            if self.is_local_private_ip(remote_ip):
                devices.add(remote_ip)

        return sorted(
            devices,
            key=lambda value: tuple(
                int(part)
                for part in value.split(".")
            )
        )

    def get_device_details(self, ip_address):
        """Return local-device details including hostname when available."""

        details = self._get_arp_neighbors().get(
            ip_address,
            {
                "ip_address": ip_address,
                "mac_address": "N/A",
                "entry_type": "UNKNOWN",
            }
        )

        # Try to resolve the device hostname from its local IP.
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]

            if hostname and hostname != ip_address:
                details["device_name"] = hostname
            else:
                details["device_name"] = "Unknown Device"

        except (
            socket.herror,
            socket.gaierror,
            OSError
        ):
            details["device_name"] = "Unknown Device"

        return details

    def cleanup_old_data(self, time_window_seconds):
        current_time = datetime.now()

        for history in (
            self.port_access_history,
            self.connection_history,
            self.failed_connections
        ):

            for ip in list(history.keys()):

                if history is self.port_access_history:

                    history[ip] = [
                        x
                        for x in history[ip]
                        if (
                            current_time - x["timestamp"]
                        ).total_seconds()
                        <= time_window_seconds
                    ]

                else:

                    history[ip] = [
                        x
                        for x in history[ip]
                        if (
                            current_time - x
                        ).total_seconds()
                        <= time_window_seconds
                    ]