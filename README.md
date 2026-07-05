# 🛡️ CyberGuard | Real-Time Web-Based Packet Sniffer & IDS

A lightweight, high-performance network traffic analyzer and mini-Intrusion Detection System (IDS). This security tool pairs a multi-threaded Python backend with a real-time responsive HTML5 dashboard to capture, analyze, and visualize live network card streams using WebSockets.

---

## 🚀 Key Architectural Features
- **Real-Time Data Streaming:** Leverages `Flask-SocketIO` to push captured packets instantly to the user interface without requiring a webpage refresh.
- **Asynchronous Processing:** Operates the raw packet sniffer on a background thread daemon to avoid blocking interface responsiveness.
- **Automated Memory Safety:** Automatically truncates frontend records past 100 entries to prevent localized browser memory exhaustion.

---

## 🛠️ Advanced Production Additions (IDS & Threat Intel)

Beyond basic logging, this repository features advanced enterprise modules designed to mimic production Security Operations Center (SOC) environments:

### 1. Intrusion Detection System (IDS) Engine
Monitors the live traffic thread for signature patterns and volumetric thresholds to trigger real-time, color-coded visual alerts on the dashboard UI:
* **Port Scan Analytics:** Warns operators via red alerts if an isolated Source IP scans across more than 10 separate target ports inside a rolling 5-second matrix.
* **Exfiltration / Volumetric Detection:** Automatically flags payload bursts scaling over 1,500 bytes to isolate potential Data Exfiltration attempts.
* **Plaintext Leak Warnings:** Inspects unencrypted protocols (HTTP/FTP/Telnet) for explicit patterns matching `password=`, `token=`, or `admin=` keys.

### 2. GeoIP Threat Intelligence Enrichment
Enriches raw IP strings with spatial telemetry. Integrates local IP databases to parse public source routing, automatically injecting country origin flags and organizational metadata beside every external node in the streaming datagrid.

### 3. Forensic PCAP Export Utility
Enables deep-dive offline incident response. Uses Scapy’s native `wrpcap()` system to commit the current live stream into structured `.pcap` files, exposed via a one-click frontend action bar to allow instantaneous handoffs into Wireshark or Network Miner.

### 4. Surgical Traffic Filtering Console
Gives analysts granular control over noisy networks. Includes a dynamic filter toolbar to instantly isolate records by Protocol (TCP/UDP/ICMP), capture specific target IP subnets, or pinpoint high-severity alerts.

---

## 📁 Project Directory Structure
```text
cyberguard-sniffer/
│
├── app.py                # Main backend (Flask Server, SocketIO, Scapy Engine)
├── requirements.txt      # Project library dependencies
├── README.md             # Project documentation & setup guide
└── templates/
    └── index.html        # Frontend dashboard (Tailwind CSS, Socket.IO client)
```

---

## ⚙️ Installation & Prerequisites

This application requires Python 3.8+ and elevated system administrative privileges to interface directly with network hardware interfaces.

### 1. Clone the Repository
```bash
git clone https://github.com
cd cyberguard-sniffer
```

### 2. Install Project Dependencies
```bash
pip install -r requirements.txt
```
*(Content of `requirements.txt`: `flask`, `flask-socketio`, `scapy`)*

---

## 🧪 Execution & Verification Tests

Because intercepting raw network card sockets is restricted, **you must execute the application entry script with administrator or root privileges**.

### Step 1: Run the Server Engine
* **On Windows (Open Command Prompt / PowerShell as Administrator):**
  ```bash
  python app.py
  ```
* **On Linux / macOS:**
  ```bash
  sudo python app.py
  ```

### Step 2: Access the Security Console
Open your preferred web browser and navigate to:
`http://127.0.0`

### Step 3: Trigger Mock Telemetry Tests
If your local host environment is quiet, execute the following commands in an isolated terminal to generate immediate, verifiable metrics on your frontend:

1. **Test ICMP & Counters:** Run a perpetual ping trace to force ICMP packet logs:
   - *Windows:* `ping 8.8.8.8 -t`
   - *Linux/macOS:* `ping 8.8.8.8`
2. **Test TCP Engine:** Query a public webpage via your browser or terminal (`curl https://google.com`) to instantly drive up the TCP dashboard charts.

---

## 🛡️ Educational Use & Disclaimer
This software is developed strictly for educational purposes, defensive portfolio prototyping, and internal research. It must never be used against public network infrastructures without prior explicit, written authorization from the system stakeholders.
