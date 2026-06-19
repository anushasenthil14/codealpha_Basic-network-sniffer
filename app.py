import os
import tempfile
import threading
import queue
import datetime
import json
from flask import Flask, render_template, jsonify, request, Response, send_file
from scapy.all import IP, IPv6, TCP, UDP, ARP, ICMP, DNS, Raw, Ether, sniff, get_working_ifaces, wrpcap, rdpcap
from scapy.packet import Packet
from scapy.utils import hexdump

app = Flask(__name__)
# Ensure templates are found
app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app.static_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

def get_packet_info(packet):
    """Generates a brief summary of the packet contents based on protocol layers."""
    try:
        if packet.haslayer(ARP):
            arp = packet[ARP]
            if arp.op == 1:
                return f"Who has {arp.pdst}? Tell {arp.psrc}"
            elif arp.op == 2:
                return f"{arp.psrc} is at {arp.hwsrc}"
            return f"ARP Op={arp.op}"
            
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            types = {0: "Echo Reply", 8: "Echo Request", 3: "Destination Unreachable", 11: "Time Exceeded"}
            type_str = types.get(icmp.type, f"Type {icmp.type}")
            return f"ICMP {type_str} (code={icmp.code})"
            
        elif packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0:
                if dns.qd:
                    qname = dns.qd.qname.decode('utf-8', errors='ignore') if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname)
                    return f"DNS Query: {qname.strip('.')}"
                return "DNS Query"
            else:
                if dns.an:
                    rdata = dns.an.rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode('utf-8', errors='ignore')
                    return f"DNS Response: {str(rdata).strip('.')}"
                return "DNS Response"
                
        elif packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            if tcp.flags & 0x20: flags.append("URG")
            flags_str = "+".join(flags)
            
            # Check for HTTP
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                    if payload_str.startswith(("GET ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "HEAD ", "PATCH ", "HTTP/1.", "HTTP/2")):
                        first_line = payload_str.split("\r\n")[0]
                        return f"HTTP {first_line}"
                except Exception:
                    pass
                    
            return f"{tcp.sport} → {tcp.dport} [{flags_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"
            
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            return f"{udp.sport} → {udp.dport} Len={udp.len}"
            
        elif packet.haslayer(IP):
            ip = packet[IP]
            return f"IP Proto={ip.proto} TTL={ip.ttl}"
            
        elif packet.haslayer(Ether):
            return f"Ethernet Frame ({packet[Ether].src} → {packet[Ether].dst})"
            
        return "Network Packet"
    except Exception as e:
        return f"Error parsing: {str(e)}"

def parse_packet_summary(packet, pkt_id):
    """Extracts high-level summary metadata from a Scapy packet."""
    timestamp = datetime.datetime.fromtimestamp(float(packet.time)).strftime('%H:%M:%S.%f')[:-3]
    length = len(packet)
    
    source = "Unknown"
    destination = "Unknown"
    protocol = "Other"
    
    if packet.haslayer(IP):
        source = packet[IP].src
        destination = packet[IP].dst
        protocol = "IPv4"
    elif packet.haslayer(IPv6):
        source = packet[IPv6].src
        destination = packet[IPv6].dst
        protocol = "IPv6"
    elif packet.haslayer(ARP):
        source = packet[ARP].psrc
        destination = packet[ARP].pdst
        protocol = "ARP"
    elif packet.haslayer(Ether):
        source = packet[Ether].src
        destination = packet[Ether].dst
        protocol = "Ethernet"
        
    # Higher layer overrides
    if packet.haslayer(TCP):
        protocol = "TCP"
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                if payload_str.startswith(("GET ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "HEAD ", "PATCH ", "HTTP/1.", "HTTP/2")):
                    protocol = "HTTP"
            except Exception:
                pass
    elif packet.haslayer(UDP):
        protocol = "UDP"
        if packet.haslayer(DNS):
            protocol = "DNS"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        
    info = get_packet_info(packet)
    
    return {
        "id": pkt_id,
        "time": timestamp,
        "source": source,
        "destination": destination,
        "protocol": protocol,
        "length": length,
        "info": info
    }

class SnifferEngine:
    def __init__(self):
        self.sniffing = False
        self.thread = None
        self.interface = None
        self.bpf_filter = None
        self.packet_id_counter = 0
        self.packets_history = []      # List of parsed packet dicts
        self.raw_packets_history = []  # List of raw Scapy packets
        self.clients = []              # List of Queue objects for SSE clients
        self.lock = threading.Lock()

    def start(self, interface, bpf_filter=""):
        with self.lock:
            if self.sniffing:
                return False
            self.interface = interface
            self.bpf_filter = bpf_filter
            self.sniffing = True
            self.thread = threading.Thread(target=self._run_sniff, daemon=True)
            self.thread.start()
            return True

    def stop(self):
        with self.lock:
            if not self.sniffing:
                return False
            self.sniffing = False
            return True

    def clear(self):
        with self.lock:
            self.packets_history.clear()
            self.raw_packets_history.clear()
            self.packet_id_counter = 0

    def _run_sniff(self):
        iface = self.interface if self.interface else None
        filt = self.bpf_filter if self.bpf_filter else None
        
        try:
            # We sniff packets in a loop
            sniff(
                iface=iface,
                filter=filt,
                prn=self._packet_callback,
                stop_filter=lambda p: not self.sniffing,
                store=0
            )
        except Exception as e:
            print(f"Error in sniffing thread: {e}")
            with self.lock:
                self.sniffing = False

    def _packet_callback(self, packet):
        with self.lock:
            if not self.sniffing:
                return
            self.packet_id_counter += 1
            pkt_id = self.packet_id_counter
            
            # Keep history capped at 3000 packets to prevent excessive memory utilization
            if len(self.packets_history) >= 3000:
                self.packets_history.pop(0)
                self.raw_packets_history.pop(0)
                
            parsed = parse_packet_summary(packet, pkt_id)
            self.packets_history.append(parsed)
            self.raw_packets_history.append(packet)
            
            # Broadcast to SSE clients
            for client_queue in self.clients:
                client_queue.put(parsed)

    def import_pcap_packets(self, packets):
        with self.lock:
            self.clear()
            for packet in packets:
                self.packet_id_counter += 1
                pkt_id = self.packet_id_counter
                parsed = parse_packet_summary(packet, pkt_id)
                self.packets_history.append(parsed)
                self.raw_packets_history.append(packet)
            return list(self.packets_history)

# Global sniffer instance
sniffer = SnifferEngine()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    try:
        ifaces = get_working_ifaces()
        res = []
        for i in ifaces:
            res.append({
                "name": i.name,
                "description": i.description or i.name,
                "ip": i.ip or "N/A"
            })
        # Add loopback specifically if not in list
        if not any("loopback" in r["name"].lower() or "loopback" in r["description"].lower() for r in res):
            res.append({
                "name": "Loopback Pseudo-Interface 1",
                "description": "Software Loopback Interface 1",
                "ip": "127.0.0.1"
            })
        return jsonify({"success": True, "interfaces": res})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/api/start', methods=['POST'])
def start_sniffing():
    data = request.json or {}
    interface = data.get("interface")
    bpf_filter = data.get("filter", "")
    
    if not interface:
        return jsonify({"success": False, "error": "Interface name is required"}), 400
        
    success = sniffer.start(interface, bpf_filter)
    if success:
        return jsonify({"success": True, "status": "Sniffing started"})
    else:
        return jsonify({"success": False, "error": "Sniffer is already running"}), 400

@app.route('/api/stop', methods=['POST'])
def stop_sniffing():
    success = sniffer.stop()
    if success:
        return jsonify({"success": True, "status": "Sniffing stopped"})
    else:
        return jsonify({"success": False, "error": "Sniffer is not running"}), 400

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        "success": True,
        "sniffing": sniffer.sniffing,
        "interface": sniffer.interface,
        "filter": sniffer.bpf_filter,
        "count": len(sniffer.packets_history)
    })

@app.route('/api/clear', methods=['POST'])
def clear_packets():
    sniffer.clear()
    return jsonify({"success": True, "status": "History cleared"})

@app.route('/api/packet/<int:packet_id>', methods=['GET'])
def get_packet_detail(packet_id):
    with sniffer.lock:
        # Check if the requested ID exists in our history
        target_index = None
        for idx, pkt in enumerate(sniffer.packets_history):
            if pkt["id"] == packet_id:
                target_index = idx
                break
                
        if target_index is None or target_index >= len(sniffer.raw_packets_history):
            return jsonify({"success": False, "error": "Packet not found"}), 404
            
        raw_pkt = sniffer.raw_packets_history[target_index]
        
        # Parse detailed layers
        layers = []
        current_layer = raw_pkt
        while current_layer:
            layer_name = current_layer.name
            fields = {}
            for field in current_layer.fields_desc:
                val = current_layer.getfieldval(field.name)
                # Formatter
                if isinstance(val, bytes):
                    try:
                        val = val.decode('utf-8', errors='replace')
                    except Exception:
                        val = val.hex()
                elif isinstance(val, list):
                    val = [str(v) for v in val]
                else:
                    val = str(val)
                fields[field.name] = val
                
            layers.append({
                "name": layer_name,
                "fields": fields
            })
            
            # Recurse payload
            current_layer = current_layer.payload if hasattr(current_layer, 'payload') else None
            if current_layer and not isinstance(current_layer, Packet):
                # End recursion if payload is not a Scapy Packet class
                break
                
        # Generate standard side-by-side hex dump
        hex_dump_str = hexdump(raw_pkt, dump=True)
        
        # Extract raw binary payload (if any) as a base64 or UTF-8 snippet
        raw_payload = ""
        if raw_pkt.haslayer(Raw):
            try:
                raw_payload = raw_pkt[Raw].load.decode('utf-8', errors='replace')
            except Exception:
                raw_payload = raw_pkt[Raw].load.hex()
                
        return jsonify({
            "success": True,
            "id": packet_id,
            "layers": layers,
            "hexdump": hex_dump_str,
            "payload": raw_payload
        })

@app.route('/api/export', methods=['GET'])
def export_pcap():
    with sniffer.lock:
        if not sniffer.raw_packets_history:
            return jsonify({"success": False, "error": "No packets to export"}), 400
            
        # Write history to a temporary PCAP file
        temp_dir = tempfile.gettempdir()
        temp_pcap_path = os.path.join(temp_dir, "sniffer_capture.pcap")
        try:
            wrpcap(temp_pcap_path, sniffer.raw_packets_history)
            return send_file(
                temp_pcap_path,
                mimetype="application/vnd.tcpdump.pcap",
                as_attachment=True,
                download_name=f"capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            )
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to export PCAP: {str(e)}"}), 500

@app.route('/api/import', methods=['POST'])
def import_pcap():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file part"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No selected file"}), 400
        
    if file:
        # Save uploaded file to temp file
        temp_fd, temp_path = tempfile.mkstemp(suffix=".pcap")
        try:
            os.close(temp_fd)
            file.save(temp_path)
            
            # Read PCAP using Scapy
            packets = rdpcap(temp_path)
            parsed_summaries = sniffer.import_pcap_packets(packets)
            
            return jsonify({
                "success": True,
                "status": f"Successfully imported {len(parsed_summaries)} packets",
                "packets": parsed_summaries
            })
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to import PCAP: {str(e)}"}), 500
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.remove(temp_path)

@app.route('/api/stream')
def stream():
    def event_generator():
        # Register a new queue for this client
        q = queue.Queue()
        with sniffer.lock:
            sniffer.clients.append(q)
            
        try:
            # Yield pre-existing packets to catch client up quickly
            with sniffer.lock:
                initial_packets = list(sniffer.packets_history[-100:])
            for pkt in initial_packets:
                yield f"data: {json.dumps(pkt)}\n\n"
                
            # Stream new packets as they arrive
            while True:
                try:
                    # Non-blocking fetch with small timeout to allow checking connection
                    pkt = q.get(timeout=1.0)
                    yield f"data: {json.dumps(pkt)}\n\n"
                except queue.Empty:
                    # Keepalive heartbeat to prevent timeouts
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            # Deregister client queue
            with sniffer.lock:
                if q in sniffer.clients:
                    sniffer.clients.remove(q)
                    
    return Response(event_generator(), mimetype="text/event-stream")

if __name__ == '__main__':
    # Start the server on port 5000, listening on all interfaces
    app.run(host='0.0.0.0', port=5000, debug=True)