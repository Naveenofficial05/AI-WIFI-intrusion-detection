# AI-Based Wi-Fi Intrusion Detection System

A local, defensive network-monitoring project using an **AI rule/expert system**. It does not use machine learning, deep learning, training datasets, password cracking, exploitation, or attack generation.

## What it does
1. Collects host network connection/interface data.
2. Analyzes the data using configurable AI rules.
3. Detects: unauthorized local devices, suspicious connection attempts, port scanning patterns, abnormal traffic, possible DoS/flooding, and repeated failed connections when actual failure data is available.
4. Generates administrator alerts.
5. Shows the latest results in a live local Chrome dashboard.

## Run on Windows
Open PowerShell in this folder:

```powershell
python -m pip install -r requirements.txt
python main.py
```

`python main.py` starts the monitoring thread, starts Flask, and attempts to open Google Chrome at **http://127.0.0.1:5000**. If Chrome is not found, the default browser is opened.

## Important
- Run the command from the folder containing `main.py`.
- Windows Firewall/security software may ask for permission for Python to use the local port.
- The collector uses host-level information available through `psutil`; it is not a full Wi-Fi radio/802.11 packet sniffer.
- Public Internet IPs and loopback addresses are not treated as Wi-Fi client devices for unauthorized-device detection.
- MAC addresses are never invented. If the host API cannot provide a MAC address, the dashboard shows `N/A`.
- Traffic and DoS thresholds are configurable in `config/settings.json`; they are demonstration defaults, not universal attack thresholds.
- The failed-connection feature does not generate fake/random failures.

## Stop
Press `Ctrl+C` in the terminal.
