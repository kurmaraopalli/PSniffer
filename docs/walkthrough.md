# Walkthrough & Verification Guide - PSniffer (CyberGuard)

This guide documents the changes made to develop the real-time Packet Sniffer & Intrusion Detection System, and provides guidelines to test and verify every module.

## 🛠️ Codebase Additions
1. [requirements.txt](../requirements.txt): Declares runtime python packages (`flask`, `flask-socketio`, `scapy`).
2. [app.py](../app.py): Core backend server handling background thread raw packet sniffing (`scapy.sniff`), mock GeoIP enrichment, dynamic IDS signature scanning, in-memory logs rotation, and WebSocket event distribution.
3. [index.html](../index.html): HTML5 single-page application built on top of premium light-mode Vanilla CSS styling. Connects to Flask-SocketIO to display real-time captures, filter items inline, show structured alerts, parse detailed packet fields, and render live hex dumps.

---

## ⚙️ Testing & Verification Steps

### Step 1: Run the Flask Webapp Server
First, make sure your python environment has the packages installed. Open a terminal or console with **Administrator / elevated root privileges** and execute:
```bash
pip install -r requirements.txt
python app.py
```
*(Windows users must also have **Npcap** or **WinPcap** installed for the packet capture engine to bind to interface sockets).*

### Step 2: Open Dashboard Interface
Access the security console dashboard from your web browser at:
`http://127.0.0.1:5000`

Click on the green **Start Sniffing** button on the top right.

---

### Step 3: Trigger Security & Packet Rules (Verifications)

If your local environment is silent, trigger these specific actions in a separate terminal to verify dashboard capabilities:

#### 1. Verify Packet Capture & Streaming (ICMP Test)
Send ICMP packets (ping queries) to force immediate logs on the streaming datagrid:
* **Windows:** `ping 8.8.8.8 -t`
* **Linux/macOS:** `ping 8.8.8.8`

*Result:* The dashboard will log the incoming packets, assign them the yellow **ICMP** protocol badge, resolve source/destination flags (e.g. 🇺🇸 for Google's DNS `8.8.8.8`), and display ping request metadata inside the datagrid.

#### 2. Trigger IDS Plaintext Leak Warning (Plaintext HTTP Request)
Transmit basic unencrypted GET commands containing sensitive keyword arguments. In your separate terminal, run:
```bash
curl "http://example.com/?password=mySecretAdminPassword&token=abc123token"
```

*Result:* The IDS thread intercepts the unencrypted packet payload, flags the presence of keys `password=` and `token=`, and broadcasts a yellow/orange threat card onto the **IDS Live Threat Feed** with a message about plaintext credential exposure.

#### 3. Trigger IDS Volumetric Anomaly Alert (Data Exfiltration Test)
Construct a request carrying an payload larger than 1,500 bytes. Run the following curl query:
```bash
curl -X POST -d "$(head -c 2000 < /dev/zero | tr '\0' 'A')" "http://example.com"
```
*(On Windows cmd, you can simply run any query or upload action that sends data matching size constraints).*

*Result:* The IDS parser flags payload size $>1500$ bytes and outputs a high-priority red alert card to the threat feed warning of possible data exfiltration.

#### 4. Trigger Port Scan Analytics Warning
Simulate port-scanning activity to trigger the volumetric alert tracker. Run the following powershell or bash sequence to quickly scan multiple ports:
* **Windows (PowerShell):**
  ```powershell
  1..15 | % { Test-NetConnection -ComputerName 127.0.0.1 -Port $_ -WarningAction SilentlyContinue }
  ```
* **Linux/macOS (nc):**
  ```bash
  for port in {1..15}; do nc -z -w 1 127.0.0.1 $port; done
  ```

*Result:* An alert card pops up on the feed indicating a host scanned $>10$ unique ports inside a rolling 5-second matrix.

---

### Step 4: Verify PCAP Offline Export
1. Let the sniffer run for a few seconds so that it registers logs in the server buffer.
2. Click the **Export PCAP** button in the dashboard toolbar.
3. Verify that a `.pcap` file download begins.
4. Try opening the saved pcap inside **Wireshark** or other network analyzers to verify the integrity of the captured headers.
