# 🛡️ CyberGuard | Real-Time Web-Based Packet Sniffer & IDS

A lightweight, high-performance network traffic analyzer and mini-Intrusion Detection System (IDS). This security tool pairs a multi-threaded Python backend with a real-time responsive HTML5 dashboard to capture, analyze, and visualize live network card streams using WebSockets.

---

## 🚀 Key Architectural Features
- **Real-Time Data Streaming:** Leverages `Flask-SocketIO` to push captured packets instantly to the user interface without requiring a webpage refresh.
- **Asynchronous Processing:** Operates the raw packet sniffer on a background thread daemon to avoid blocking interface responsiveness.
- **Automated Memory Safety:** Automatically truncates frontend records past 100 entries to prevent localized browser memory exhaustion.

---

## 🛠️ Implemented Security & Analysis Modules

This repository features fully implemented network diagnostic and threat monitoring modules designed to simulate Security Operations Center (SOC) environments:

### 1. Intrusion Detection System (IDS) Engine
Monitors the background Scapy packet stream for signature patterns and volumetric anomalies, piping real-time warnings to the dashboard:
* **Port Scan Analytics:** Uses a sliding tracking cache (`time` & `collections.defaultdict`) inside `app.py`. If any isolated source IP connects to more than 10 unique destination ports within a rolling 5-second matrix, a critical alert is triggered.
* **Exfiltration / Volumetric Detection:** Flags any packet whose payload size scales over 1,500 bytes to highlight data exfiltration anomalies.
* **Plaintext Leak Warnings:** Audits unencrypted frame payloads (HTTP, FTP, Telnet) inside the Scapy `Raw` layer for sensitive query markers matching `password=`, `token=`, `admin=`, `passwd=`, or `secret=`.

### 2. GeoIP Threat Intelligence Enrichment
Analyzes source and destination IPs on every capture. Private ranges are mapped to local origin indicators, while external public IPs are enriched using a lightweight caching prefix resolver that dynamically pushes country metadata, flag emojis (e.g., 🇺🇸, 🇬🇧, 🇦🇺), and ISP/organization names to the UI.

### 3. Forensic PCAP Export Utility
Retains an active buffer of the last 100 captured frames in-memory. Clicking the **Export PCAP** console button invokes an asynchronous query to the `/api/export` Flask endpoint, which writes the network stream to a structured PCAP file using Scapy's native `wrpcap()` and sends it down to the client.

### 4. Deep Packet Inspector & Hex Console
Enables surgical session investigations. Selecting a packet row instantly populates:
* **Layer Decoder:** Expandable header structures mapping Ethernet, IP, and transport layers.
* **Raw Hex Dump:** A side-by-side hexadecimal and ASCII memory dump format of raw payloads.

### 5. Surgical Traffic Filtering Console
Provides real-time, fluid UI controls to:
* Isolate traffic dynamically by Protocol (All, TCP, UDP, ICMP).
* Search instantly for specific source or destination IP addresses.
* Toggle the **Alerts Only** switch to hide safe traffic and focus exclusively on triggered IDS threat events.

---

## 📁 Project Directory Structure
```text
PSniffer/
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

> [!NOTE]
> **Windows Users:** You must install [Npcap](https://npcap.com/) (ensure "Install Npcap in WinPcap API-compatible mode" is checked) or WinPcap to enable packet capture capabilities.

### 1. Clone the Repository
```bash
git clone https://github.com/kurmaraopalli/PSniffer.git
cd PSniffer
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
`http://127.0.0.1:5000`

### Step 3: Trigger Mock Telemetry Tests
If your local host environment is quiet, execute the following commands in an isolated terminal to generate immediate, verifiable metrics on your frontend:

1. **Test ICMP & Counters:** Run a perpetual ping trace to force ICMP packet logs:
   - *Windows:* `ping 8.8.8.8 -t`
   - *Linux/macOS:* `ping 8.8.8.8`
2. **Test TCP Engine:** Query a public webpage via your browser or terminal (`curl https://google.com`) to instantly drive up the TCP dashboard charts.

---

## 🛡️ Educational Use & Disclaimer
This software is developed strictly for educational purposes, defensive portfolio prototyping, and internal research. It must never be used against public network infrastructures without prior explicit, written authorization from the system stakeholders.
