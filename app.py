import logging
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from scapy.all import sniff, ARP, IP, DNS, Raw, TCP
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from flask_socketio import SocketIO, emit
from flask_mail import Mail, Message
from twilio.rest import Client
import csv
import io
import os
from OpenSSL import crypto
import re
import base64
import time

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'rr6022799@gmail.com'
app.config['MAIL_PASSWORD'] = 'ugfh ubik rmzr zugb'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Configure Twilio
TWILIO_ACCOUNT_SID = 'your_account_sid'
TWILIO_AUTH_TOKEN = 'your_auth_token'
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
TWILIO_PHONE_NUMBER = '+1234567890'
ADMIN_PHONE_NUMBER = '+0987654321'

packet_stats = defaultdict(int)
attack_packets = defaultdict(list)
mitm_reports = []
captured_packets = []
historical_data = []
known_gateways = ["192.168.0.1"]
isolation_forest = IsolationForest(contamination=0.1)
is_capturing = False
known_dns_records = {"www.example.com": "93.184.216.34"}
known_certificates = {}
flow_stats = defaultdict(list)
current_flows = {}

# Configure Logging
logging.basicConfig(level=logging.INFO, filename='nids.log', filemode='a', format='%(asctime)s - %(message)s')

# User credentials for authentication
users = {
    'admin': 'admin',
    'viewer': 'viewer'
}

@app.route('/')
def index():
    return "Network Security and Intrusion Detection System Backend"

@app.route('/auth', methods=['POST'])
def auth():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if users.get(username) == password:
        return jsonify({'message': 'Authenticated', 'role': username})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global is_capturing
    is_capturing = True
    duration = request.json.get('duration', 60)
    try:
        sniff(prn=packet_callback, timeout=duration, store=False)
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")
    return jsonify({'message': 'Packet capturing started.'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global is_capturing
    is_capturing = False
    return jsonify({'message': 'Packet capturing stopped.'})

@app.route('/clear_packets', methods=['POST'])
def clear_packets():
    global captured_packets
    captured_packets = []
    return jsonify({'message': 'Captured packets cleared.'})

@app.route('/captured_packets', methods=['GET'])
def get_captured_packets():
    formatted_packets = []
    for packet in captured_packets:
        formatted_packet = {
            'src': packet['src'],
            'dst': packet['dst'],
            'protocol': packet['protocol'],
            'security_threats': packet.get('security_threats', 'N/A'),
            'compliance_monitoring': packet.get('compliance_monitoring', 'N/A'),
            'traffic_analysis': packet.get('traffic_analysis', 'N/A')
        }
        formatted_packets.append(formatted_packet)
    return jsonify(formatted_packets)


@app.route('/filter_packets', methods=['GET'])
def filter_packets():
    search_term = request.args.get('search', '').lower()
    filtered_packets = [packet for packet in captured_packets if 
                        search_term in packet['src'].lower() or 
                        search_term in packet['dst'].lower() or 
                        search_term in packet['protocol'].lower() or 
                        (packet.get('attack_type', 'N/A').lower() != 'n/a' and search_term in packet['attack_type'].lower())]
    return jsonify(filtered_packets)

@app.route('/download_packets', methods=['GET'])
def download_packets():
    try:
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(["Source IP", "Destination IP", "Protocol Summary", "Security Threats", "Compliance Monitoring", "Traffic Analysis", "Content Filtering", "Application Control", "Data Loss Prevention", "Real-Time Monitoring"])
        for packet in captured_packets:
            cw.writerow([packet['src'], packet['dst'], packet['protocol'], packet.get('security_threats', 'N/A'), packet.get('compliance_monitoring', 'N/A'), packet.get('traffic_analysis', 'N/A'), packet.get('content_filtering', 'N/A'), packet.get('application_control', 'N/A'), packet.get('data_loss_prevention', 'N/A'), packet.get('real_time_monitoring', 'N/A')])
        output = io.BytesIO()
        output.write(si.getvalue().encode('utf-8'))
        output.seek(0)
        return send_file(output, mimetype='text/csv', download_name='captured_packets.csv', as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_dpi', methods=['GET'])
def download_dpi():
    try:
        filepath = 'path/to/dpi_files.zip'
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_dfi', methods=['GET'])
def download_dfi():
    try:
        filepath = 'path/to/dfi_files.zip'
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_dci', methods=['GET'])
def download_dci():
    try:
        filepath = 'path/to/dci_files.zip'
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/network_attacks', methods=['GET'])
def network_attacks():
    return jsonify({
        'mitm_packets': packet_stats['mitm_packets'],
        'arp_spoofing_packets': packet_stats['arp_spoofing_packets'],
        'dns_spoofing_packets': packet_stats['dns_spoofing_packets'],
        'https_spoofing_packets': packet_stats['https_spoofing_packets'],
        'http_spoofing_packets': packet_stats['http_spoofing_packets'],
        'ip_spoofing_packets': packet_stats['ip_spoofing_packets'],
        'email_hijacking_packets': packet_stats['email_hijacking_packets'],
        'wifi_eavesdropping_packets': packet_stats['wifi_eavesdropping_packets'],
        'phishing_attacks': packet_stats['phishing_attacks'],
        'malware_attacks': packet_stats['malware_attacks'],
        'dos_attacks': packet_stats['dos_attacks'],
        'scanning_probing_attacks': packet_stats['scanning_probing_attacks'],
        'session_hijacking_attacks': packet_stats['session_hijacking_attacks'],
        'brute_force_attacks': packet_stats['brute_force_attacks'],
        'zero_day_attacks': packet_stats['zero_day_attacks'],
        'protocol_attacks': packet_stats['protocol_attacks'],
        'insider_threats': packet_stats['insider_threats'],
        'total_packets': packet_stats['total_packets']
    })

@app.route('/analyze_attacks', methods=['GET'])
def analyze_attacks():
    attack_type = request.args.get('type')
    if attack_type not in attack_packets:
        return jsonify([])
    return jsonify(attack_packets[attack_type])

@app.route('/logs', methods=['GET'])
def get_logs():
    with open('nids.log', 'r') as log_file:
        log_content = log_file.readlines()
    log_content.reverse()  # Arrange logs latest first
    return jsonify({'logs': ''.join(log_content)})

@app.route('/filter_logs', methods=['GET'])
def filter_logs():
    search_term = request.args.get('search', '').lower()
    with open('nids.log', 'r') as log_file:
        log_content = log_file.readlines()
    
    filtered_logs = [log for log in log_content if search_term in log.lower()]
    return jsonify({'logs': filtered_logs})

# @app.route('/filter_packets', methods=['GET'])
# def filter_packets():
#     protocol = request.args.get('protocol', '').lower()
#     src_ip = request.args.get('src_ip', '').lower()
#     dst_ip = request.args.get('dst_ip', '').lower()
#     attack_type = request.args.get('attack_type', '').lower()
    
#     filtered_packets = [packet for packet in captured_packets if
#                         (not protocol or protocol in packet['protocol'].lower()) and
#                         (not src_ip or src_ip in packet['src'].lower()) and
#                         (not dst_ip or dst_ip in packet['dst'].lower()) and
#                         (not attack_type or attack_type in packet['attack_type'].lower())]
#     return jsonify(filtered_packets)

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    if request.json.get('role') != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        open('nids.log', 'w').close()  # Clear the log file
        return jsonify({'message': 'Logs cleared.'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/content_inspection', methods=['GET'])
def content_inspection():
    formatted_packets = []
    for packet in captured_packets:
        if packet.get('content_filtering') or packet.get('application_control') or packet.get('data_loss_prevention') or packet.get('real_time_monitoring'):
            formatted_packet = {
                'src': packet['src'],
                'dst': packet['dst'],
                'content_filtering': packet.get('content_filtering', 'N/A'),
                'application_control': packet.get('application_control', 'N/A'),
                'data_loss_prevention': packet.get('data_loss_prevention', 'N/A'),
                'real_time_monitoring': packet.get('real_time_monitoring', 'N/A')
            }
            formatted_packets.append(formatted_packet)
    return jsonify(formatted_packets)




@app.route('/fetch_threat_intelligence', methods=['GET'])
def fetch_threat_intelligence():
    api_url = "https://api.xforce.ibmcloud.com/api/alerts/urgency"
    headers = {"Authorization": "Bearer YOUR_API_KEY"}
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({'error': 'Failed to fetch threat intelligence'}), 500

@app.route('/block_ip', methods=['POST'])
def block_ip():
    ip = request.json.get('ip')
    automate_response(ip)
    return jsonify({'message': f'Blocked IP {ip}.'})

@app.route('/download_mitm_report', methods=['GET'])
def download_mitm_report():
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Source IP", "Destination IP", "Protocol", "Details", "Attack Type"])
    for report in mitm_reports:
        cw.writerow([report['ip_src'], report['ip_dst'], report['protocol'], report['details'], report['attack_type']])
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    return send_file(output, mimetype='text/csv', download_name='MITM_Report.csv', as_attachment=True)


@app.route('/send_report', methods=['POST'])
def send_report():
    email = request.json.get('email')
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(["Source IP", "Destination IP", "Protocol", "Details", "Attack Type"])
    for report in mitm_reports:
        cw.writerow([report['ip_src'], report['ip_dst'], report['protocol'], report['details'], report['attack_type']])
    try:
        msg = Message(
            subject="MITM Report",
            sender=app.config['MAIL_USERNAME'],
            recipients=[email]
        )
        msg.body = "Please find the MITM report attached."
        msg.attach("MITM_Report.csv", "text/csv", si.getvalue())
        mail.send(msg)
        return jsonify({'message': 'Report sent successfully!'})
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        return jsonify({'error': str(e)}), 500

def automate_response(ip):
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

import numpy as np
from sklearn.ensemble import IsolationForest

# Initialize the Isolation Forest model
isolation_forest = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)

# Placeholder for training data (features extracted from normal network traffic)
# Example features: [packet_length, ttl, src_port, dst_port, tcp_flags]
training_data = [
    [60, 64, 443, 80, 16],
    [60, 64, 80, 443, 24],
    [52, 63, 443, 80, 16],
    # Add more training data here
]

# Fit the Isolation Forest model on the training data
isolation_forest.fit(training_data)

def extract_features(packet):
    # Extract relevant features from the packet for anomaly detection
    packet_length = len(packet)
    ttl = packet[IP].ttl if IP in packet else 0
    src_port = packet[TCP].sport if TCP in packet else 0
    dst_port = packet[TCP].dport if TCP in packet else 0
    tcp_flags = packet[TCP].flags if TCP in packet else 0
    return [packet_length, ttl, src_port, dst_port, tcp_flags]

def detect_mitm(packet):
    # Extract features from the packet
    features = extract_features(packet)
    
    # Predict anomaly score using Isolation Forest
    prediction = isolation_forest.predict([features])[0]
    
    # Return True if the packet is detected as an anomaly (possible MITM attack)
    return prediction == -1

def extract_and_inspect_content(packet):
    content = ""
    if packet.haslayer(Raw):
        content = packet[Raw].load.decode(errors='ignore')
    return content

def inspect_packet_content(content):
    threats_detected = {
        "security_threats": "N/A",
        "compliance_monitoring": "N/A",
        "traffic_analysis": "N/A",
        "content_filtering": "N/A",
        "application_control": "N/A",
        "data_loss_prevention": "N/A",
        "real_time_monitoring": "N/A"
    }
    if re.search(r"(virus|malware|trojan|worm)", content, re.IGNORECASE):
        threats_detected["security_threats"] = "yes"
    if re.search(r"(credit card|ssn|confidential)", content, re.IGNORECASE):
        threats_detected["compliance_monitoring"] = "yes"
    if re.search(r"(unauthorized access|suspicious activity)", content, re.IGNORECASE):
        threats_detected["traffic_analysis"] = "yes"
    if re.search(r"(blocked content|inappropriate content)", content, re.IGNORECASE):
        threats_detected["content_filtering"] = "yes"
    if re.search(r"(unauthorized app|risky app)", content, re.IGNORECASE):
        threats_detected["application_control"] = "yes"
    if re.search(r"(data leak|data breach)", content, re.IGNORECASE):
        threats_detected["data_loss_prevention"] = "yes"
    if re.search(r"(live threat|active monitoring)", content, re.IGNORECASE):
        threats_detected["real_time_monitoring"] = "yes"
    return threats_detected


def update_flow_stats(packet, ip_src, ip_dst):
    flow_key = (ip_src, ip_dst)
    current_time = time.time()
    if flow_key not in current_flows:
        current_flows[flow_key] = {'count': 0, 'start_time': current_time}
    current_flows[flow_key]['count'] += 1
    if current_time - current_flows[flow_key]['start_time'] > 10:  # Example threshold: 10 seconds
        flow_stats[flow_key].append(current_flows[flow_key])
        del current_flows[flow_key]

def detect_flow_anomalies():
    for flow, stats in flow_stats.items():
        avg_packet_count = sum(stat['count'] for stat in stats) / len(stats)
        if avg_packet_count > 100:  # Example threshold for anomaly
            packet_stats['dos_attacks'] += 1
            attack_details = {
                'ip_src': flow[0],
                'ip_dst': flow[1],
                'protocol': 'DoS',
                'details': 'Potential DoS attack detected based on flow analysis',
                'attack_type': 'DoS'
            }
            attack_packets['dos_attacks'].append(attack_details)
            log_attack('DoS', attack_details)
            send_alerts(attack_details)
            automate_response(flow[0])

def packet_callback(packet):
    global is_capturing
    if not is_capturing:
        return

    try:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            packet_stats['total_packets'] += 1

            data = {
                'total_packets': packet_stats['total_packets'],
                'src': ip_src,
                'dst': ip_dst,
                'protocol': packet.summary(),
                'security_threats': "N/A",
                'compliance_monitoring': "N/A",
                'traffic_analysis': "N/A",
                'content_filtering': "N/A",
                'application_control': "N/A",
                'data_loss_prevention': "N/A",
                'real_time_monitoring': "N/A"
            }

            # Perform deep packet inspection (DPI)
            if packet.haslayer(Raw):
                raw_content = packet[Raw].load.decode(errors='ignore')
                human_readable_content = convert_to_human_readable(raw_content)
                data['content'] = human_readable_content

            # Real-time protocol analysis
            if packet[IP].proto == 6:  # TCP
                packet_stats['tcp_packets'] += 1
            elif packet[IP].proto == 17:  # UDP
                packet_stats['udp_packets'] += 1

            captured_packets.append(data)
            store_historical_data(data)

            # MITM Detection using Isolation Forest (DCI)
            if detect_mitm(packet):
                packet_stats['mitm_packets'] += 1
                attack_details = {
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'protocol': 'IP',
                    'details': 'MITM attack detected',
                    'attack_type': 'MITM'
                }
                attack_packets['mitm_attacks'].append(attack_details)
                log_attack('MITM', attack_details)
                data['attack_type'] = 'MITM'
                data['security_threats'] = "yes"
                send_alerts(attack_details)
                automate_response(ip_src)

            # Perform content inspection and update flags
            content = extract_and_inspect_content(packet)
            threats = inspect_packet_content(content)
            data.update(threats)

            # Perform flow analysis (DFI) and update stats
            update_flow_stats(packet, ip_src, ip_dst)

            # Man-in-the-Middle (MITM) Attacks Detection and Prevention
            # 1. ARP Spoofing
            if packet.haslayer(ARP):
                if packet[ARP].op == 2:
                    arp_src = packet[ARP].psrc
                    arp_dst = packet[ARP].pdst
                    if arp_src in known_gateways or arp_dst in known_gateways:
                        packet_stats['arp_spoofing_packets'] += 1
                        attack_details = {
                            'ip_src': ip_src,
                            'ip_dst': ip_dst,
                            'protocol': 'ARP',
                            'details': 'MITM (ARP Spoofing) detected',
                            'attack_type': 'MITM (ARP Spoofing)'
                        }
                        attack_packets['arp_spoofing_attacks'].append(attack_details)
                        log_attack('MITM (ARP Spoofing)', attack_details)
                        data['attack_type'] = 'MITM (ARP Spoofing)'
                        data['security_threats'] = "yes"
                        send_alerts(attack_details)
                        automate_response(ip_src)
                        # Prevention: Static ARP Entries
                        os.system(f"arp -s {ip_src} {packet[ARP].hwsrc}")

            # 2. DNS Spoofing
            if packet.haslayer(DNS):
                dns_qry = packet[DNS].qd.qname.decode('utf-8') if packet[DNS].qd else ""
                dns_resp = packet[DNS].an.rdata if packet[DNS].an else ""
                if dns_qry in known_dns_records and dns_resp != known_dns_records[dns_qry]:
                    packet_stats['dns_spoofing_packets'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'DNS',
                        'details': f"DNS Spoofing detected. Query: {dns_qry}, Response: {dns_resp}",
                        'attack_type': 'MITM (DNS Spoofing)'
                    }
                    attack_packets['dns_spoofing_attacks'].append(attack_details)
                    log_attack('MITM (DNS Spoofing)', attack_details)
                    data['attack_type'] = 'MITM (DNS Spoofing)'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)
                    # Prevention: Secure DNS Servers
                    os.system("echo 'nameserver 8.8.8.8' > /etc/resolv.conf")

            # 3. SSL/TLS Hijacking
            if packet.haslayer(IP) and packet[IP].dport == 443:
                try:
                    cert = crypto.load_certificate(crypto.FILETYPE_PEM, packet[Raw].load)
                    cert_fingerprint = cert.digest("sha256").decode("utf-8")
                    if packet[IP].dst in known_certificates and known_certificates[packet[IP].dst] != cert_fingerprint:
                        packet_stats['https_spoofing_packets'] += 1
                        attack_details = {
                            'ip_src': ip_src,
                            'ip_dst': ip_dst,
                            'protocol': 'HTTPS',
                            'details': 'MITM (HTTPS Spoofing) detected: Certificate mismatch',
                            'attack_type': 'MITM (HTTPS Spoofing)'
                        }
                        attack_packets['https_spoofing_attacks'].append(attack_details)
                        log_attack('MITM (HTTPS Spoofing)', attack_details)
                        data['attack_type'] = 'MITM (HTTPS Spoofing)'
                        data['security_threats'] = "yes"
                        send_alerts(attack_details)
                        automate_response(ip_src)
                        # Prevention: Enforce HTTPS
                        os.system("iptables -A OUTPUT -p tcp --dport 80 -j REJECT")
                except Exception as e:
                    logging.error(f"Error processing HTTPS packet: {e}")

            # 4. HTTP Spoofing
            if packet.haslayer(IP) and packet[IP].dport == 80:
                http_headers = str(packet[Raw].load).lower() if packet.haslayer(Raw) else ""
                if "location:" in http_headers:
                    packet_stats['http_spoofing_packets'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'HTTP',
                        'details': 'MITM (HTTP Spoofing) detected: Unusual redirect',
                        'attack_type': 'MITM (HTTP Spoofing)'
                    }
                    attack_packets['http_spoofing_attacks'].append(attack_details)
                    log_attack('MITM (HTTP Spoofing)', attack_details)
                    data['attack_type'] = 'MITM (HTTP Spoofing)'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)

            # 5. IP Spoofing
            if is_ip_spoofed(packet):
                packet_stats['ip_spoofing_packets'] += 1
                attack_details = {
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'protocol': 'IP',
                    'details': 'MITM (IP Spoofing) detected: IP mismatch',
                    'attack_type': 'MITM (IP Spoofing)'
                }
                attack_packets['ip_spoofing_attacks'].append(attack_details)
                log_attack('MITM (IP Spoofing)', attack_details)
                data['attack_type'] = 'MITM (IP Spoofing)'
                data['security_threats'] = "yes"
                send_alerts(attack_details)
                automate_response(ip_src)
                # Prevention: Ingress and Egress Filtering
                os.system(f"iptables -A INPUT -s {ip_src} -j DROP")
                os.system(f"iptables -A OUTPUT -s {ip_src} -j DROP")
                # Network ACLs implementation (example logic)
                if not is_trusted_ip(ip_src):
                    os.system(f"iptables -A INPUT -s {ip_src} -j DROP")
                    os.system(f"iptables -A OUTPUT -s {ip_src} -j DROP")

            # 6. Email Hijacking
            if packet.haslayer(Raw):
                email_content = packet[Raw].load.decode('utf-8', errors='ignore')
                if "spoofed_email" in email_content:
                    packet_stats['email_hijacking_packets'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'Email',
                        'details': 'MITM (Email Hijacking) detected',
                        'attack_type': 'MITM (Email Hijacking)'
                    }
                    attack_packets['email_hijacking_attacks'].append(attack_details)
                    log_attack('MITM (Email Hijacking)', attack_details)
                    data['attack_type'] = 'MITM (Email Hijacking)'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)
                    # Prevention: Email Authentication (SPF, DKIM, DMARC)
                    os.system("spf_tool -c /etc/spf.conf")

            # 7. Wi-Fi Eavesdropping
            if packet.haslayer(Raw) and "eavesdropping" in packet[Raw].load.decode('utf-8', errors='ignore').lower():
                packet_stats['wifi_eavesdropping_packets'] += 1
                attack_details = {
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'protocol': 'Wi-Fi',
                    'details': 'MITM (Wi-Fi Eavesdropping) detected',
                    'attack_type': 'MITM (Wi-Fi Eavesdropping)'
                }
                attack_packets['wifi_eavesdropping_attacks'].append(attack_details)
                log_attack('MITM (Wi-Fi Eavesdropping)', attack_details)
                data['attack_type'] = 'MITM (Wi-Fi Eavesdropping)'
                data['security_threats'] = "yes"
                send_alerts(attack_details)
                automate_response(ip_src)
                # Prevention: WPA3 Encryption
                os.system("wpa_supplicant -c /etc/wpa_supplicant.conf")

            # Phishing Attacks Detection
            if packet.haslayer(Raw):
                email_content = packet[Raw].load.decode('utf-8', errors='ignore')
                if "phishing" in email_content.lower():
                    packet_stats['phishing_attacks'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'Email',
                        'details': 'Phishing detected',
                        'attack_type': 'Phishing'
                    }
                    attack_packets['phishing_attacks'].append(attack_details)
                    log_attack('Phishing', attack_details)
                    data['attack_type'] = 'Phishing'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)

            # Malware Attacks Detection
            if packet.haslayer(Raw):
                if "malware" in packet[Raw].load.decode('utf-8', errors='ignore').lower():
                    packet_stats['malware_attacks'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'Unknown',
                        'details': 'Malware detected',
                        'attack_type': 'Malware'
                    }
                    attack_packets['malware_attacks'].append(attack_details)
                    log_attack('Malware', attack_details)
                    data['attack_type'] = 'Malware'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)

            # Denial of Service (DoS) and Distributed Denial of Service (DDoS) Attacks Detection
            if len(captured_packets) > 0:
                if data['total_packets'] > (sum(stats['total_packets'] for stats in captured_packets) / len(captured_packets)) * 2:
                    packet_stats['dos_attacks'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'DoS',
                        'details': 'Denial of Service attack detected',
                        'attack_type': 'DoS'
                    }
                    attack_packets['dos_attacks'].append(attack_details)
                    log_attack('DoS', attack_details)
                    data['attack_type'] = 'DoS'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)
                    # Prevention: Rate Limiting, Traffic Filtering, Load Balancing
                    os.system("iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT")

            # Network Scanning and Probing Detection
            if packet.haslayer(IP):
                if len(captured_packets) > 10 and sum(1 for p in captured_packets[-10:] if p['src'] == ip_src) > 5:
                    packet_stats['scanning_probing_attacks'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'Scanning/Probing',
                        'details': 'Scanning/Probing detected',
                        'attack_type': 'Scanning/Probing'
                    }
                    attack_packets['scanning_probing_attacks'].append(attack_details)
                    log_attack('Scanning/Probing', attack_details)
                    data['attack_type'] = 'Scanning/Probing'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)
                    # Prevention: Firewall Rules, IDS
                    os.system("iptables -A INPUT -p tcp --dport 22 -j DROP")

            # Session Hijacking Detection
            if packet.haslayer(Raw):
                session_content = packet[Raw].load.decode('utf-8', errors='ignore')
                if "session" in session_content.lower():
                    packet_stats['session_hijacking_attacks'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'Session',
                        'details': 'Session Hijacking detected',
                        'attack_type': 'Session Hijacking'
                    }
                    attack_packets['session_hijacking_attacks'].append(attack_details)
                    log_attack('Session Hijacking', attack_details)
                    data['attack_type'] = 'Session Hijacking'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)

            # Brute Force Attacks Detection
            if packet.haslayer(Raw):
                brute_force_content = packet[Raw].load.decode('utf-8', errors='ignore')
                if "login failed" in brute_force_content.lower():
                    packet_stats['brute_force_attacks'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'Brute Force',
                        'details': 'Brute Force attack detected',
                        'attack_type': 'Brute Force'
                    }
                    attack_packets['brute_force_attacks'].append(attack_details)
                    log_attack('Brute Force', attack_details)
                    data['attack_type'] = 'Brute Force'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)
                    # Prevention: Account Lockout, MFA
                    os.system("pam_tally2 --user username --reset")

            # Zero-Day Exploits Detection
            if isolation_forest.fit_predict([packet])[0] == -1:
                packet_stats['zero_day_attacks'] += 1
                attack_details = {
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'protocol': 'Unknown',
                    'details': 'Zero-Day Exploit detected',
                    'attack_type': 'Zero-Day Exploit'
                }
                attack_packets['zero_day_attacks'].append(attack_details)
                log_attack('Zero-Day Exploit', attack_details)
                data['attack_type'] = 'Zero-Day Exploit'
                data['security_threats'] = "yes"
                send_alerts(attack_details)
                automate_response(ip_src)

            # Protocol Attacks Detection
            if packet.haslayer(IP):
                if packet[IP].proto not in [1, 6, 17]:  # ICMP, TCP, UDP
                    packet_stats['protocol_attacks'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'Protocol',
                        'details': 'Protocol attack detected',
                        'attack_type': 'Protocol'
                    }
                    attack_packets['protocol_attacks'].append(attack_details)
                    log_attack('Protocol', attack_details)
                    data['attack_type'] = 'Protocol'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)

            # Insider Threats Detection
            if packet.haslayer(Raw):
                if "confidential" in packet[Raw].load.decode('utf-8', errors='ignore').lower():
                    packet_stats['insider_threats'] += 1
                    attack_details = {
                        'ip_src': ip_src,
                        'ip_dst': ip_dst,
                        'protocol': 'Insider Threat',
                        'details': 'Insider Threat detected: Confidential information accessed',
                        'attack_type': 'Insider Threat'
                    }
                    attack_packets['insider_threats'].append(attack_details)
                    log_attack('Insider Threat', attack_details)
                    data['attack_type'] = 'Insider Threat'
                    data['security_threats'] = "yes"
                    send_alerts(attack_details)
                    automate_response(ip_src)

            # Detect flow anomalies
            detect_flow_anomalies()

            # Send packet data via WebSocket for real-time updates
            socketio.emit('packet_data', data)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

def convert_to_human_readable(content):
    readable_content = []

    # Example for decoding Base64 content
    if is_base64(content):
        decoded_content = base64.b64decode(content).decode('utf-8', 'ignore')
        readable_content.append(decoded_content)
    # HTTP content example
    elif "HTTP" in content:
        try:
            headers, body = content.split("\r\n\r\n", 1)
            readable_content.append(f"HTTP Headers:\n{headers}")
            readable_content.append(f"HTTP Body:\n{body}")
        except ValueError:
            readable_content.append(content)

    # Example for identifying and displaying email content
    elif any(keyword in content for keyword in ["MAIL", "EMAIL", "From:", "To:", "Subject:"]):
        readable_content.append(f"Email Content:\n{content}")

    # Identify and format URLs
    elif re.search(r'http[s]?://', content):
        urls = re.findall(r'http[s]?://\S+', content)
        readable_content.append("URLs:\n" + "\n".join(urls))

    # General readable format for other types of content
    else:
        readable_content.append(content)

    return "\n\n".join(readable_content)

def is_base64(string):
    try:
        if base64.b64encode(base64.b64decode(string)).decode('utf-8') == string:
            return True
    except Exception:
        return False
    return False

def log_attack(attack_type, details):
    logging.info(f"{attack_type} attack detected: {details}")

def store_historical_data(packet):
    historical_data.append(packet)

def send_alerts(details):
    send_email(details)
    send_sms(details)

def send_email(details):
    try:
        msg = Message(
            subject="Network Attack Detected",
            sender=app.config['MAIL_USERNAME'],
            recipients=['rr6022799@gmail.com']
        )
        msg.body = f"Details of the detected attack:\n\n{details}"
        mail.send(msg)
    except Exception as e:
        logging.error(f"Error sending email: {e}")

def send_sms(details):
    try:
        twilio_client.messages.create(
            body=f"Network Attack Detected: {details}",
            from_=TWILIO_PHONE_NUMBER,
            to=ADMIN_PHONE_NUMBER
        )
    except Exception as e:
        logging.error(f"Error sending SMS: {e}")

def is_ip_spoofed(packet):
    # Placeholder for actual IP spoofing detection logic
    return False

def is_trusted_ip(ip):
    # Placeholder for actual trusted IP check
    return False

def detect_flow_anomalies():
    for flow, stats in flow_stats.items():
        avg_packet_count = sum(stat['count'] for stat in stats) / len(stats)
        if avg_packet_count > 100:  # Example threshold for anomaly
            packet_stats['dos_attacks'] += 1
            attack_details = {
                'ip_src': flow[0],
                'ip_dst': flow[1],
                'protocol': 'DoS',
                'details': 'Potential DoS attack detected based on flow analysis',
                'attack_type': 'DoS'
            }
            attack_packets['dos_attacks'].append(attack_details)
            log_attack('DoS', attack_details)
            send_alerts(attack_details)
            automate_response(flow[0])

if __name__ == '__main__':
    socketio.run(app, debug=False, host='0.0.0.0', port=5000)

