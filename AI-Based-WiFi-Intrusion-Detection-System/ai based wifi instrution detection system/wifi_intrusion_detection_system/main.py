"""AI-Based Wi-Fi Intrusion Detection System with local Chrome dashboard."""

import json
import os
import sys
import time
import threading
import webbrowser
import subprocess

from datetime import datetime

from flask import Flask, jsonify, render_template
from colorama import Fore, Style, init

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.network_collector import NetworkCollector
from modules.ai_analyzer import AIAnalyzer
from modules.alert_generator import AlertGenerator

init(autoreset=True)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

system = None


class WiFiIntrusionDetectionSystem:

    def __init__(self):

        self.config_dir = os.path.join(BASE_DIR, "config")
        self.logs_dir = os.path.join(BASE_DIR, "logs")

        self.authorized_devices_path = os.path.join(
            self.config_dir,
            "authorized_devices.json"
        )

        self.settings_path = os.path.join(
            self.config_dir,
            "settings.json"
        )

        self.log_file_path = os.path.join(
            self.logs_dir,
            f"alerts_{datetime.now().strftime('%Y%m%d')}.log"
        )

        self.settings = self.load_settings()

        self.network_collector = None
        self.ai_analyzer = None
        self.alert_generator = None

        self.running = False

        self.lock = threading.Lock()

        self.latest = {}

    # ---------------------------------------------------------
    # LOAD SETTINGS
    # ---------------------------------------------------------

    def load_settings(self):

        try:

            with open(
                self.settings_path,
                "r",
                encoding="utf-8"
            ) as f:

                return json.load(f)

        except Exception as e:

            print(f"Error loading settings: {e}")

            return {}

    # ---------------------------------------------------------
    # INITIALIZE SYSTEM
    # ---------------------------------------------------------

    def initialize(self):

        os.makedirs(
            self.logs_dir,
            exist_ok=True
        )

        interfaces = NetworkCollector().get_network_interfaces()

        requested = self.settings.get(
            "network_interface",
            "Wi-Fi"
        )

        interface = (
            requested
            if requested in interfaces
            else self._best_interface(interfaces)
        )

        if interface != requested:

            print(
                f"Configured interface '{requested}' not found. "
                f"Using '{interface}'."
            )

        self.network_collector = NetworkCollector(interface)

        self.ai_analyzer = AIAnalyzer(
            self.authorized_devices_path,
            self.settings_path
        )

        self.alert_generator = AlertGenerator(
            self.log_file_path
        )

        self.latest = {

            "running": False,

            "interface": interface,

            "interface_ip":
                self.network_collector.get_interface_ip(),

            "active_connections": 0,

            "traffic_rate": 0,

            "connected_devices": [],

            "authorized_devices":
                len(self.ai_analyzer.authorized_devices),

            "unknown_devices": 0,

            "ai": {

                "overall_security_level":
                    "NORMAL",

                "total_detections": 0,

                "detections": []

            },

            "alerts": []

        }

    # ---------------------------------------------------------
    # SELECT BEST NETWORK INTERFACE
    # ---------------------------------------------------------

    @staticmethod
    def _best_interface(interfaces):

        for name in interfaces:

            if name.lower() in {
                "wi-fi",
                "wifi",
                "wlan0",
                "wlan"
            }:

                return name

        return interfaces[0] if interfaces else "Wi-Fi"

    # ---------------------------------------------------------
    # ONE MONITORING CYCLE
    # ---------------------------------------------------------

    def one_cycle(self):

        nc = self.network_collector

        interval = self.settings.get(
            "monitoring_interval",
            5
        )

        window = self.settings.get(
            "time_window_seconds",
            60
        )

        # -----------------------------------------------------
        # COLLECT NETWORK INFORMATION
        # -----------------------------------------------------

        network_info = nc.collect_network_info()

        connections = network_info["active_connections"]

        # -----------------------------------------------------
        # TRACK LOCAL CONNECTIONS
        # -----------------------------------------------------

        for conn in connections:

            ip = conn.get("remote_address")

            port = conn.get("remote_port")

            if ip and nc.is_local_private_ip(ip):

                nc.track_connection_attempt(ip)

                if port:

                    nc.track_port_access(
                        ip,
                        port
                    )

        # -----------------------------------------------------
        # GET CONNECTED DEVICES
        # -----------------------------------------------------

        devices = nc.get_connected_devices()

        port_data = {}
        conn_data = {}
        failed_data = {}

        # -----------------------------------------------------
        # COLLECT DETECTION DATA
        # -----------------------------------------------------

        for ip in devices:

            pc = nc.get_port_scan_count(
                ip,
                window
            )

            cc = nc.get_connection_attempt_count(
                ip,
                window
            )

            fc = nc.get_failed_connection_count(
                ip,
                window
            )

            if pc:

                port_data[ip] = pc

            if cc:

                conn_data[ip] = cc

            if fc:

                failed_data[ip] = fc

        # -----------------------------------------------------
        # LOCAL NETWORK
        # -----------------------------------------------------

        local_network = nc.get_interface_network()

        # -----------------------------------------------------
        # AI ANALYSIS
        # -----------------------------------------------------

        analysis = self.ai_analyzer.analyze_traffic(

            network_info,

            port_data,

            conn_data,

            failed_data,

            local_network

        )

        # -----------------------------------------------------
        # GENERATE ALERTS
        # -----------------------------------------------------

        new_alerts = []

        for detection in analysis["detections"]:

            alert = self.alert_generator.generate_alert(
                detection
            )

            self.alert_generator.log_alert(
                alert
            )

            new_alerts.append(alert)

        # -----------------------------------------------------
        # AUTHORIZED DEVICES
        # -----------------------------------------------------

        authorized_by_ip = {

            d.get("ip_address"): d

            for d in self.ai_analyzer.authorized_devices

        }

        # -----------------------------------------------------
        # DEVICE DISPLAY DATA
        # -----------------------------------------------------

        device_rows = []

        for ip in devices:

            # Authorized device information
            d = authorized_by_ip.get(
                ip,
                {}
            )

            # Information discovered from local network
            discovered = nc.get_device_details(
                ip
            )

            # -------------------------------------------------
            # DEVICE NAME FIX
            # -------------------------------------------------

            device_name = (

                d.get("device_name")

                or discovered.get("device_name")

                or "Unknown Device"

            )

            # -------------------------------------------------
            # MAC ADDRESS
            # -------------------------------------------------

            mac_address = (

                d.get("mac_address")

                or discovered.get("mac_address")

                or "N/A"

            )

            # -------------------------------------------------
            # DEVICE ROW
            # -------------------------------------------------

            device_rows.append({

                "ip_address": ip,

                "authorized": bool(d),

                "device_name": device_name,

                "mac_address": mac_address

            })

        # -----------------------------------------------------
        # UPDATE DASHBOARD DATA
        # -----------------------------------------------------

        with self.lock:

            history = (
                self.latest.get("alerts", [])
                + new_alerts
            )

            self.latest.update({

                "running": True,

                "interface":
                    nc.interface_name,

                "interface_ip":
                    network_info.get("ip_address"),

                "active_connections":
                    len(connections),

                "traffic_rate":
                    network_info.get(
                        "traffic_rate",
                        0
                    ),

                "connected_devices":
                    device_rows,

                "authorized_devices":
                    len(
                        self.ai_analyzer.authorized_devices
                    ),

                "unknown_devices":
                    sum(
                        1
                        for d in device_rows
                        if not d["authorized"]
                    ),

                "ai": {

                    "overall_security_level":
                        analysis[
                            "overall_security_level"
                        ],

                    "total_detections":
                        analysis[
                            "total_detections"
                        ],

                    "detections":
                        analysis[
                            "detections"
                        ]

                },

                "alerts":
                    history[-50:],

                "monitoring_interval":
                    interval,

                "time_window_seconds":
                    window,

                "thresholds": {

                    "traffic_threshold":
                        self.settings.get(
                            "traffic_threshold",
                            1_000_000
                        ),

                    "dos_threshold":
                        self.settings.get(
                            "dos_threshold",
                            10_000_000
                        )

                }

            })

        # -----------------------------------------------------
        # CLEAN OLD DATA
        # -----------------------------------------------------

        nc.cleanup_old_data(
            window
        )

        return analysis

    # ---------------------------------------------------------
    # MONITORING LOOP
    # ---------------------------------------------------------

    def monitoring_loop(self):

        print(
            f"{Fore.GREEN}"
            "Starting network monitoring..."
            f"{Style.RESET_ALL}"
        )

        while self.running:

            try:

                analysis = self.one_cycle()

                print(

                    f"[{datetime.now():%Y-%m-%d %H:%M:%S}] "

                    f"Connections: "
                    f"{self.latest['active_connections']} | "

                    f"Traffic: "
                    f"{self.latest['traffic_rate']:.0f} B/s | "

                    f"Devices: "
                    f"{len(self.latest['connected_devices'])} | "

                    f"AI: "
                    f"{analysis['overall_security_level']} | "

                    f"Detections: "
                    f"{analysis['total_detections']}"

                )

                time.sleep(
                    self.settings.get(
                        "monitoring_interval",
                        5
                    )
                )

            except Exception as e:

                print(
                    f"{Fore.RED}"
                    f"Monitoring error: {e}"
                    f"{Style.RESET_ALL}"
                )

                time.sleep(2)

        with self.lock:

            self.latest["running"] = False

    # ---------------------------------------------------------
    # START SYSTEM
    # ---------------------------------------------------------

    def start(self):

        self.initialize()

        self.running = True

        threading.Thread(

            target=self.monitoring_loop,

            daemon=True,

            name="network-monitor"

        ).start()

    # ---------------------------------------------------------
    # STOP SYSTEM
    # ---------------------------------------------------------

    def stop(self):

        self.running = False


# =============================================================
# OPEN CHROME
# =============================================================

def open_chrome(url):

    candidates = []

    if sys.platform.startswith("win"):

        candidates += [

            os.path.expandvars(
                r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"
            ),

            os.path.expandvars(
                r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
            ),

            os.path.expandvars(
                r"%LocalAppData%\Google\Chrome\Application\chrome.exe"
            )

        ]

    elif sys.platform == "darwin":

        candidates.append(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )

    else:

        candidates += [

            "/usr/bin/google-chrome",

            "/usr/bin/google-chrome-stable",

            "/usr/bin/chromium"

        ]

    for exe in candidates:

        if os.path.exists(exe):

            subprocess.Popen(

                [exe, url],

                stdout=subprocess.DEVNULL,

                stderr=subprocess.DEVNULL

            )

            return

    # Fallback browser
    webbrowser.open(url)


# =============================================================
# DASHBOARD ROUTES
# =============================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


@app.route("/api/status")
def status():

    if system is None:

        return jsonify({
            "running": False
        })

    with system.lock:

        data = dict(
            system.latest
        )

    return jsonify(data)


# =============================================================
# RUN APPLICATION
# =============================================================

def run():

    global system

    system = WiFiIntrusionDetectionSystem()

    system.start()

    url = "http://127.0.0.1:5000"

    print(
        f"{Fore.CYAN}"
        f"Dashboard: {url}"
        f"{Style.RESET_ALL}"
    )

    # Open Chrome automatically
    threading.Timer(
        1.5,
        lambda: open_chrome(url)
    ).start()

    try:

        app.run(

            host="127.0.0.1",

            port=5000,

            debug=False,

            use_reloader=False,

            threaded=True

        )

    finally:

        system.stop()


# =============================================================
# MAIN
# =============================================================

if __name__ == "__main__":

    run()