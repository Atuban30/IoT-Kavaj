from flask import Flask, Response, render_template, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, ICMP, Dot11
import json
import csv
import io
import threading
import time
import logging
import math
from collections import Counter
from datetime import datetime

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

is_capturing = False
packets = []
last_packet_time = None
packet_times = []
source_ips = []
pps_window = 1.0

def calculate_checksum_status(packet):
    if IP in packet:
        ip_checksum = packet[IP].chksum
        del packet[IP].chksum
        packet = packet.__class__(bytes(packet))
        return "Valid" if packet[IP].chksum == ip_checksum else "Invalid"
    return "N/A"

def calculate_tcp_flag_count(packet):
    if TCP in packet:
        flags = packet[TCP].flags
        return sum(1 for flag in ['F', 'S', 'R', 'P', 'A', 'U', 'E', 'C'] if flags & getattr(packet[TCP].flags, flag))
    return 0

def get_wifi_info(packet):
    if Dot11 in packet:
        try:
            if packet.haslayer(Dot11Beacon):
                ssid = packet[Dot11Beacon].info.decode('utf-8', errors='ignore') or "Hidden"
                channel = packet[Dot11Beacon].network_stats().get('channel', 'N/A')
                return f"SSID: {ssid}, Channel: {channel}"
            return "N/A"
        except:
            return "N/A"
    return "N/A"

def calculate_source_ip_entropy():
    if not source_ips or len(set(source_ips)) == 1:
        return 0.0
    counter = Counter(source_ips)
    total = len(source_ips)
    entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
    return round(max(0.0, entropy), 2)

def process_packet(packet):
    global last_packet_time, packet_times, source_ips
    if IP in packet:
        # Use nanosecond precision for timestamp
        current_time_ns = time.time_ns()
        current_time = current_time_ns / 1_000_000_000.0  # Convert to seconds
        # Validate timestamp (within reasonable range, e.g., today)
        current_day_start = time.time() - 86400  # 24 hours ago
        if not isinstance(current_time, float) or current_time <= current_day_start or current_time > time.time() + 3600:
            logging.error(f"Invalid timestamp: {current_time} (ns: {current_time_ns})")
            return

        time_delta = (current_time - last_packet_time) * 1000 if last_packet_time else 0
        last_packet_time = current_time

        packet_times.append(current_time)
        packet_times[:] = [t for t in packet_times if current_time - t <= pps_window]
        pps = len(packet_times) / pps_window if packet_times else 0
        logging.debug(f"PPS: {pps}, packet_times length: {len(packet_times)}")

        source_ips.append(packet[IP].src)
        source_ips[:] = source_ips[-1000:]
        src_ip_entropy = calculate_source_ip_entropy()

        # Format timestamp as human-readable string (YYYY-MM-DD HH:MM:SS.ssss)
        timestamp_str = datetime.fromtimestamp(current_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-2]

        packet_data = {
            'timestamp': timestamp_str,
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': 'Unknown',
            'ip_type': packet[IP].proto if IP in packet else 0,
            'length': len(packet),
            'time_delta': round(time_delta, 2),
            'pps': round(pps, 2),
            'src_ip_entropy': src_ip_entropy,
            'checksum_status': calculate_checksum_status(packet),
            'wifi_info': get_wifi_info(packet),
            'src_port': 0,
            'dst_port': 0,
            'syn_flag': 0,
            'ack_flag': 0,
            'ack_no': 0,
            'window_size': 0,
            'seq_no': 0,
            'tcp_flag_count': 0,
            'code': 0
        }

        if TCP in packet:
            packet_data.update({
                'protocol': 'TCP',
                'ip_type': 6,
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport,
                'syn_flag': 1 if packet[TCP].flags.S else 0,
                'ack_flag': 1 if packet[TCP].flags.A else 0,
                'ack_no': packet[TCP].ack,
                'window_size': packet[TCP].window,
                'seq_no': packet[TCP].seq,
                'tcp_flag_count': calculate_tcp_flag_count(packet)
            })
        elif UDP in packet:
            packet_data.update({
                'protocol': 'UDP',
                'ip_type': 17,
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
        elif ICMP in packet:
            packet_data.update({
                'protocol': 'ICMP',
                'ip_type': 1,
                'code': packet[ICMP].code
            })

        packets.append(packet_data)
        socketio.emit('new_packet', packet_data)

def capture_packets():
    sniff(prn=process_packet, filter="ip", stop_filter=lambda x: not is_capturing)

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/toggle-capture', methods=['POST'])
def toggle_capture():
    global is_capturing
    is_capturing = not is_capturing
    if is_capturing:
        threading.Thread(target=capture_packets, daemon=True).start()
    return {'isCapturing': is_capturing}

@app.route('/export/<format>')
def export(format):
    if format not in ['csv', 'json']:
        return {'error': 'Invalid format'}, 400

    output = io.StringIO()
    fieldnames = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'ip_type', 'length', 'time_delta', 'pps',
                  'src_ip_entropy', 'checksum_status', 'wifi_info', 'src_port', 'dst_port', 'syn_flag',
                  'ack_flag', 'ack_no', 'window_size', 'seq_no', 'tcp_flag_count', 'code']
    if format == 'csv':
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator='\n')
        writer.writeheader()
        for packet in packets:
            # Convert all fields to strings, ensure timestamp is human-readable
            packet_str = {k: str(v) for k, v in packet.items()}
            writer.writerow(packet_str)
        return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=packets.csv'})
    else:
        json.dump(packets, output)
        return Response(output.getvalue(), mimetype='application/json', headers={'Content-Disposition': 'attachment;filename=packets.json'})

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)