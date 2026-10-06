# Quick Start Guide

## Step-by-Step Instructions for Windows

### 1. Open Command Prompt as Administrator
- Press Windows key
- Type "cmd"
- Right-click "Command Prompt"
- Select "Run as administrator"

### 2. Navigate to Project Directory
```bash
cd "D:\ai based wifi instrution detection system\wifi_intrusion_detection_system"
```

### 3. Create Virtual Environment
```bash
python -m venv venv
```

### 4. Activate Virtual Environment
```bash
venv\Scripts\activate
```

### 5. Install Required Libraries
```bash
pip install -r requirements.txt
```

### 6. Find Your Network Interface Name
```bash
netsh interface show interface
```
Note the name (e.g., "Wi-Fi", "Ethernet")

### 7. Update Configuration (if needed)
Edit `config/settings.json` and change `network_interface` to your interface name

### 8. Find Your IP Address
```bash
ipconfig
```
Note your IPv4 address (e.g., 192.168.1.10)

### 9. Add Your Device to Authorized List
Edit `config/authorized_devices.json` and add your device:
```json
{
  "mac_address": "YOUR_MAC_ADDRESS",
  "ip_address": "YOUR_IP_ADDRESS",
  "device_name": "Your Device Name"
}
```

### 10. Run the Application
```bash
python main.py
```

### 11. Stop Monitoring
Press `Ctrl+C` to stop

---

## Common Commands

### To deactivate virtual environment:
```bash
deactivate
```

### To run again (after first setup):
```bash
cd "D:\ai based wifi instrution detection system\wifi_intrusion_detection_system"
venv\Scripts\activate
python main.py
```

---

## Troubleshooting

### If you see "No module named 'psutil'":
```bash
pip install -r requirements.txt
```

### If you see permission errors:
- Make sure you're running Command Prompt as Administrator

### If no network interfaces are found:
- Check that you're connected to a network
- Verify the interface name in settings.json matches your actual interface
