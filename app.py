import os
import sys
import time
import random
import threading
from collections import defaultdict, deque
from flask import Flask, render_template, jsonify, send_file
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap

# Set up Flask & SocketIO
app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = 'cyberguard_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# State management
sniff_thread = None
is_sniffing = False
packet_buffer = deque(maxlen=100)  # In-memory store of last 100 Scapy packet objects for PCAP export
packet_json_buffer = []  # UI-friendly JSON records (capped at 100)
lock = threading.Lock()

# IDS Engine State
# Port scan tracking: ip -> set of ports connected within last 5 seconds
port_scan_history = defaultdict(list)  # ip -> list of (timestamp, port)
PORT_SCAN_THRESHOLD = 10  # >10 ports
PORT_SCAN_WINDOW = 5.0    # 5 seconds

# Mock GeoIP Database for offline/educational enrichment
MOCK_GEOIP = {
    "8.8.8.8": {"country": "United States", "flag": "🇺🇸", "org": "Google LLC"},
    "8.8.4.4": {"country": "United States", "flag": "🇺🇸", "org": "Google LLC"},
    "1.1.1.1": {"country": "Australia", "flag": "🇦🇺", "org": "Cloudflare, Inc."},
    "9.9.9.9": {"country": "Switzerland", "flag": "🇨🇭", "org": "Quad9"},
    "142.250.190.46": {"country": "United States", "flag": "🇺🇸", "org": "Google LLC"},
    "20.112.52.29": {"country": "United States", "flag": "🇺🇸", "org": "Microsoft Corp."},
    "185.199.108.153": {"country": "United States", "flag": "🇺🇸", "org": "GitHub, Inc."},
}

def resolve_geoip(ip_addr):
    """
    Enriches IP addresses with country origin and organization name.
    Recognizes private/local LAN ranges and returns a mock mapping for demo external IPs.
    """
    if not ip_addr:
        return {"country": "Unknown", "flag": "❓", "org": "N/A"}
        
    # Local Network Check
    if (ip_addr.startswith("10.") or 
        ip_addr.startswith("192.168.") or 
        ip_addr.startswith("127.") or 
        ip_addr.startswith("172.16.") or  # Simple check for demo
        ip_addr == "::1"):
        return {"country": "Local LAN", "flag": "🏠", "org": "Intranet Node"}
        
    # Check mock GeoIP database
    if ip_addr in MOCK_GEOIP:
        return MOCK_GEOIP[ip_addr]
        
    # Fallback/Default for other external IPs to simulate real database coverage
    hash_val = sum(ord(c) for c in ip_addr)
    destinations = [
        {"country": "United Kingdom", "flag": "🇬🇧", "org": "British Telecom"},
        {"country": "Germany", "flag": "🇩🇪", "org": "Deutsche Telekom"},
        {"country": "Japan", "flag": "🇯🇵", "org": "SoftBank Corp."},
        {"country": "Canada", "flag": "🇨🇦", "org": "Rogers Communications"},
        {"country": "India", "flag": "🇮🇳", "org": "Reliance Jio"},
    ]
    return destinations[hash_val % len(destinations)]

# Mock telemetry pools
MOCK_IPS = ["8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.5", "185.199.108.153", "20.112.52.29", "142.250.190.46"]
MOCK_LOCAL_IPS = ["192.168.1.10", "192.168.1.15", "10.0.0.22", "127.0.0.1"]

def generate_mock_packet():
    """Generates a realistic mock Scapy packet object for fallback simulation."""
    proto = random.choice(["TCP", "UDP", "ICMP"])
    src = random.choice(MOCK_IPS + MOCK_LOCAL_IPS)
    dst = random.choice(MOCK_LOCAL_IPS if src not in MOCK_LOCAL_IPS else MOCK_IPS)
    
    if src == dst:
        dst = "8.8.8.8"

    if proto == "TCP":
        sport = random.choice([80, 443, 22, 8080, 49200])
        dport = random.choice([80, 443, 22, 8080, 49200])
        flags = random.choice(["S", "A", "FA", "PA"])
        
        # Plaintext leak warning mock
        if random.random() < 0.15:
            load = random.choice([
                b"GET /login?user=admin&password=mySuperPassword123 HTTP/1.1\r\n",
                b"POST /api/token HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\ntoken=abc123secretTokenValue",
                b"USER admin\r\nPASS admin123\r\n"
            ])
        # Volumetric anomaly mock
        elif random.random() < 0.10:
            load = b"A" * 1600
        else:
            load = f"HTTP/1.1 200 OK\r\nContent-Length: {random.randint(100, 500)}\r\n\r\nMock response payload".encode()
            
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(load=load)
        
    elif proto == "UDP":
        sport = random.randint(1024, 65535)
        dport = random.choice([53, 123, 161, 5060])
        if dport == 53:
            load = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
        else:
            load = b"Mock UDP payload datagram data bytes..."
        pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(load=load)
        
    else:  # ICMP
        itype = random.choice([8, 0])
        pkt = IP(src=src, dst=dst) / ICMP(type=itype, code=0) / Raw(load=b"PingRequestMockDataPayloadBytes")
        
    return pkt

def check_ids_rules(packet, proto, src_ip, dst_ip, payload_len, raw_payload):
    """
    Inspects packet details and raw payload to detect intrusion indicators or anomalies.
    Returns a list of triggered alert dictionaries.
    """
    alerts = []
    current_time = time.time()
    
    # 1. Volumetric Data Exfiltration Check (>1500 byte payload threshold)
    if payload_len > 1500:
        alerts.append({
            "type": "Volumetric Alert",
            "severity": "high",
            "message": f"Large payload anomaly detected ({payload_len} bytes) - Potential Data Exfiltration attempt."
        })
        
    # 2. Port Scan Analytics
    if proto in ["TCP", "UDP"] and packet.haslayer(IP):
        dport = packet[TCP].dport if proto == "TCP" else packet[UDP].dport
        # Cleanup history older than 5 seconds
        port_scan_history[src_ip] = [
            (ts, p) for ts, p in port_scan_history[src_ip]
            if current_time - ts <= PORT_SCAN_WINDOW
        ]
        # Add current port query
        port_scan_history[src_ip].append((current_time, dport))
        
        # Check distinct ports accessed
        unique_ports = {p for ts, p in port_scan_history[src_ip]}
        if len(unique_ports) > PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "Port Scan Warning",
                "severity": "critical",
                "message": f"Host {src_ip} scanned {len(unique_ports)} unique ports in <{PORT_SCAN_WINDOW}s."
            })
            
    # 3. Plaintext Leak Inspection
    if raw_payload:
        # Decode bytes with safe handling
        try:
            payload_str = raw_payload.decode('utf-8', errors='ignore').lower()
            leak_signatures = ["password=", "token=", "admin=", "passwd=", "secret="]
            triggered_sigs = [sig for sig in leak_signatures if sig in payload_str]
            
            if triggered_sigs:
                alerts.append({
                    "type": "Plaintext Leak Warning",
                    "severity": "medium",
                    "message": f"Sensitive parameter ({', '.join(triggered_sigs)}) transmitted in unencrypted payload."
                })
        except Exception:
            pass
            
    return alerts

def get_hex_dump(packet):
    """
    Constructs a visual Hex and ASCII side-by-side dump representation of packet data.
    """
    if not packet.haslayer(Raw):
        return ""
    data = bytes(packet[Raw].load)
    hex_lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        # Hex representation
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        # Pad shorter final rows
        if len(chunk) < 16:
            hex_part += " " * (3 * (16 - len(chunk)))
        # ASCII representation
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        hex_lines.append(f"{i:04X}   {hex_part}   |{ascii_part}|")
    return "\n".join(hex_lines)

def get_packet_layers(packet):
    """
    Traverses packet layers and returns a listing of layer names and fields.
    """
    layers = []
    temp_pkt = packet
    while temp_pkt:
        layer_name = temp_pkt.__class__.__name__
        fields = {}
        for f in temp_pkt.fields_desc:
            val = temp_pkt.getfieldval(f.name)
            # Make sure values are human-readable
            if isinstance(val, bytes):
                val = val.decode('utf-8', errors='ignore')
            else:
                val = str(val)
            fields[f.name] = val
        layers.append({"layer": layer_name, "fields": fields})
        temp_pkt = temp_pkt.payload if hasattr(temp_pkt, 'payload') else None
        # Safeguard against cyclic structures or sub-payloads that are empty
        if not temp_pkt or temp_pkt.__class__.__name__ == 'NoPayload':
            break
    return layers

def packet_callback(packet):
    """
    Sniffer callback executed for every intercepted network packet.
    """
    global packet_json_buffer, is_sniffing
    
    if not is_sniffing:
        return
        
    if not packet.haslayer(IP):
        return  # Restrict evaluation to IP traffic for clarity in security metrics

    try:
        # Buffer packet for PCAP export
        with lock:
            packet_buffer.append(packet)

        # Parse Layer Details
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        length = len(packet)
        
        # Determine protocol
        proto = "IP"
        info = f"{src_ip} -> {dst_ip}"
        
        if packet.haslayer(TCP):
            proto = "TCP"
            tcp = packet[TCP]
            info = f"TCP Port: {tcp.sport} -> {tcp.dport} | Flags: {str(tcp.flags)}"
        elif packet.haslayer(UDP):
            proto = "UDP"
            udp = packet[UDP]
            info = f"UDP Port: {udp.sport} -> {udp.dport} | Len: {udp.len}"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
            icmp = packet[ICMP]
            info = f"ICMP Type: {icmp.type} Code: {icmp.code}"

        # Payload checks
        raw_payload = packet[Raw].load if packet.haslayer(Raw) else b""
        payload_len = len(raw_payload)
        
        # Threat intel enrichment (GeoIP)
        geoip_src = resolve_geoip(src_ip)
        geoip_dst = resolve_geoip(dst_ip)
        
        # Intrusion Detection Checks
        alerts = check_ids_rules(packet, proto, src_ip, dst_ip, payload_len, raw_payload)
        
        # Format Hex Dump and Layer details
        hex_dump = get_hex_dump(packet)
        layers = get_packet_layers(packet)
        
        # Pack JSON payload
        packet_id = int(time.time() * 1000000)  # Microsecond timestamp identifier
        packet_record = {
            "id": packet_id,
            "timestamp": time.strftime("%H:%M:%S"),
            "protocol": proto,
            "src_ip": src_ip,
            "src_geo": geoip_src,
            "dst_ip": dst_ip,
            "dst_geo": geoip_dst,
            "length": length,
            "info": info,
            "alerts": alerts,
            "hex_dump": hex_dump,
            "layers": layers
        }
        
        with lock:
            packet_json_buffer.append(packet_record)
            if len(packet_json_buffer) > 100:
                packet_json_buffer.pop(0)
                
        # Push packet telemetry down active socket sessions
        socketio.emit('new_packet', packet_record)
        
    except Exception as e:
        print(f"Error parsing packet: {e}", file=sys.stderr)

def sniffer_loop():
    """
    Main sniffer execution loop run in a background daemon thread.
    Automatically falls back to simulated/mock packets if live capture interface binding fails
    (e.g., when not running as Administrator or Npcap is missing on Windows).
    """
    global is_sniffing
    use_mock_fallback = False
    
    print("[*] Network sniffer thread started.", flush=True)
    while True:
        if is_sniffing:
            if not use_mock_fallback:
                try:
                    # Test if raw packet capture socket is accessible
                    sniff(prn=packet_callback, store=False, timeout=1, count=1)
                except Exception as e:
                    print(f"\n[!] Raw socket capture initialization failed: {e}", file=sys.stderr)
                    print("[*] Lacking Administrator privileges or Npcap/WinPcap drivers.", flush=True)
                    print("[*] Falling back to Mock Telemetry Mode for safe/offline demonstration...\n", flush=True)
                    use_mock_fallback = True
            
            if use_mock_fallback:
                try:
                    # Simulate occasional port scan alerts to demonstrate rule engine
                    if random.random() < 0.05:
                        scan_src = random.choice(MOCK_IPS)
                        for port in range(80, 95):
                            mock_pkt = IP(src=scan_src, dst="192.168.1.10") / TCP(sport=random.randint(1024, 65535), dport=port, flags="S") / Raw(load=b"scan")
                            packet_callback(mock_pkt)
                            time.sleep(0.05)
                    else:
                        mock_pkt = generate_mock_packet()
                        packet_callback(mock_pkt)
                except Exception as ex:
                    print(f"Mock generator warning: {ex}", file=sys.stderr)
                time.sleep(random.uniform(0.3, 1.2))
        else:
            time.sleep(0.5)

@app.route('/')
def dashboard():
    """Renders HTML5 real-time console template."""
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    """Returns active capture state."""
    return jsonify({"is_sniffing": is_sniffing})

@app.route('/api/export')
def export_pcap():
    """
    Compiles captured Scapy packets stored in buffer into a structured PCAP 
    and streams download down client socket.
    """
    temp_pcap_path = os.path.join(app.root_path, "capture.pcap")
    with lock:
        if len(packet_buffer) == 0:
            # Create a mock/empty pcap if no logs are present
            return jsonify({"error": "No packets captured yet to export."}), 400
        # Write buffered packets using Scapy wrpcap
        wrpcap(temp_pcap_path, list(packet_buffer))
        
    try:
        return send_file(
            temp_pcap_path,
            mimetype="application/vnd.tcpdump.pcap",
            as_attachment=True,
            download_name=f"cyberguard_capture_{int(time.time())}.pcap"
        )
    finally:
        # Cleanup temporary pcap files dynamically
        def remove_file():
            try:
                time.sleep(1)
                if os.path.exists(temp_pcap_path):
                    os.remove(temp_pcap_path)
            except Exception:
                pass
        threading.Thread(target=remove_file).start()

# WebSockets Event Handlers
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {time.strftime('%H:%M:%S')}", flush=True)
    # Re-transmit historical buffered logs to synchronise the newly joined dashboard
    with lock:
        for pkt in packet_json_buffer:
            emit('new_packet', pkt)

@socketio.on('toggle_capture')
def handle_toggle_capture(data):
    global is_sniffing
    is_sniffing = bool(data.get('state', False))
    print(f"[*] Sniffing toggled: {is_sniffing}", flush=True)
    emit('status_change', {"is_sniffing": is_sniffing}, broadcast=True)

@socketio.on('clear_buffer')
def handle_clear_buffer():
    global packet_json_buffer
    with lock:
        packet_buffer.clear()
        packet_json_buffer.clear()
    print("[*] Captured packet buffer cleared.", flush=True)
    emit('buffer_cleared', broadcast=True)

if __name__ == '__main__':
    # Initialize sniffer background thread
    sniff_thread = threading.Thread(target=sniffer_loop, daemon=True)
    sniff_thread.start()
    
    # Start flask application
    print("[*] CyberGuard Flask server launching on http://127.0.0.1:5000", flush=True)
    socketio.run(app, host='127.0.0.1', port=5000, debug=True)
