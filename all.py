from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from scapy.all import sniff, ARP, IP, DNS, Raw, TCP, UDP
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from flask_socketio import SocketIO, emit
from flask_mail import Mail, Message
from twilio.rest import Client
import csv
import io
import os
import logging
import requests
from OpenSSL import crypto
from flask_talisman import Talisman
import win32com.client

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")
Talisman(app)

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'your-email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your-password'
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
captured_packets = []
historical_data = []
known_gateways = ["192.168.0.1"]
isolation_forest = IsolationForest(contamination=0.1)
is_capturing = False
known_dns_records = {"www.example.com": "93.184.216.34"}
known_certificates = {}  # Add your known certificates here
suspicious_urls = ['example-phish.com', 'malicious-site.com']
malware_signatures = ['malware-pattern-1', 'malware-pattern-2']

# Configure Logging
logging.basicConfig(level=logging.INFO, filename='nids.log', filemode='a', format='%(asctime)s - %(message)s')

# User credentials for authentication
users = {
    'admin': 'admin',
    'viewer': 'viewer'
}

@app.route('/')
def index():
    return "Network Intrusion Detection System Backend"

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
    sniff(prn=packet_callback, timeout=duration)
    return jsonify({'message': 'Packet capturing started.'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global is_capturing
    is_capturing = False
    return jsonify({'message': 'Packet capturing stopped.'})

@app.route('/download_packets', methods=['GET'])
def download_packets():
    try:
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(["Source IP", "Destination IP", "Protocol Summary", "Attack Type"])
        for packet in captured_packets:
            cw.writerow([packet['src'], packet['dst'], packet['protocol'], packet.get('attack_type', 'N/A')])
        output = io.BytesIO()
        output.write(si.getvalue().encode('utf-8'))
        output.seek(0)
        return send_file(output, mimetype='text/csv', download_name='captured_packets.csv', as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/network_attacks', methods=['GET'])
def network_attacks():
    total_packets = packet_stats['total_packets']
    return jsonify({
        'mitm_packets': packet_stats['mitm_packets'],
        'spoofing_packets': packet_stats['spoofing_packets'],
        'dns_spoofing_packets': packet_stats['dns_spoofing_packets'],
        'https_spoofing_packets': packet_stats['https_spoofing_packets'],
        'port_scanning_packets': packet_stats['port_scanning_packets'],
        'ddos_packets': packet_stats['ddos_packets'],
        'brute_force_packets': packet_stats['brute_force_packets'],
        'phishing_packets': packet_stats['phishing_packets'],
        'malware_packets': packet_stats['malware_packets'],
        'total_packets': total_packets,
        'mitm_percentage': (packet_stats['mitm_packets'] / total_packets) * 100 if total_packets else 0,
        'spoofing_percentage': (packet_stats['spoofing_packets'] / total_packets) * 100 if total_packets else 0,
        'dns_spoofing_percentage': (packet_stats['dns_spoofing_packets'] / total_packets) * 100 if total_packets else 0,
        'https_spoofing_percentage': (packet_stats['https_spoofing_packets'] / total_packets) * 100 if total_packets else 0,
        'port_scanning_percentage': (packet_stats['port_scanning_packets'] / total_packets) * 100 if total_packets else 0,
        'ddos_percentage': (packet_stats['ddos_packets'] / total_packets) * 100 if total_packets else 0,
        'brute_force_percentage': (packet_stats['brute_force_packets'] / total_packets) * 100 if total_packets else 0,
        'phishing_percentage': (packet_stats['phishing_packets'] / total_packets) * 100 if total_packets else 0,
        'malware_percentage': (packet_stats['malware_packets'] / total_packets) * 100 if total_packets else 0
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
        log_content = log_file.read()
    return jsonify({'logs': log_content})

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

def block_ip(ip):
    os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
    logging.info(f"Blocked IP: {ip}")

def automate_response(ip):
    block_ip(ip)

def send_email(attack_details):
    try:
        msg = Message('Network Attack Detected', sender='your-email@gmail.com', recipients=['admin@example.com'])
        msg.body = f"Attack Details: {attack_details}"
        mail.send(msg)
        logging.info("Email alert sent.")
    except Exception as e:
        logging.error(f"Failed to send email notification: {e}")

def send_sms(attack_details):
    try:
        message = twilio_client.messages.create(
            body=f"Network Attack Detected: {attack_details}",
            from_=TWILIO_PHONE_NUMBER,
            to=ADMIN_PHONE_NUMBER
        )
        logging.info("SMS alert sent.")
    except Exception as e:
        logging.error(f"Failed to send SMS notification: {e}")

# Detection Methods for Additional Attacks
def detect_port_scanning(packet):
    ip_src = packet[IP].src
    if packet.haslayer(TCP) or packet.haslayer(UDP):
        packet_stats['port_scanning_packets'] += 1
        attack_details = {'ip_src': ip_src, 'details': 'Port scanning detected'}
        attack_packets['port_scanning'].append(attack_details)
        log_attack('Port Scanning', attack_details)

def detect_ddos(packet):
    ip_dst = packet[IP].dst
    packet_stats['ddos_packets'] += 1
    attack_details = {'ip_dst': ip_dst, 'details': 'DDoS attack detected'}
    attack_packets['ddos'].append(attack_details)
    log_attack('DDoS Attack', attack_details)


def detect_brute_force(packet):
    if 'Failed login' in packet.summary():
        ip_src = packet[IP].src
        packet_stats['brute_force_packets'] += 1
        attack_details = {'ip_src': ip_src, 'details': 'Brute force attack detected'}
        attack_packets['brute_force'].append(attack_details)
        log_attack('Brute Force Attack', attack_details)

def detect_phishing(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        for url in suspicious_urls:
            if url in payload:
                packet_stats['phishing_packets'] += 1
                attack_details = {'url': url, 'details': 'Phishing attack detected'}
                attack_packets['phishing'].append(attack_details)
                log_attack('Phishing Attack', attack_details)

def detect_malware(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        for signature in malware_signatures:
            if signature in payload:
                packet_stats['malware_packets'] += 1
                attack_details = {'signature': signature, 'details': 'Malware detected'}
                attack_packets['malware'].append(attack_details)
                log_attack('Malware Traffic', attack_details)

def packet_callback(packet):
    global is_capturing
    if not is_capturing:
        return

    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_stats['total_packets'] += 1

        data = {
            'total_packets': packet_stats['total_packets'],
            'src': ip_src,
            'dst': ip_dst,
            'protocol': packet.summary()
        }

        captured_packets.append(data)
        store_historical_data(data)

        detect_port_scanning(packet)
        detect_ddos(packet)
        detect_brute_force(packet)
        detect_phishing(packet)
        detect_malware(packet)
        
        # ARP Spoofing Detection
        if packet.haslayer(ARP):
            arp_src = packet[ARP].psrc
            arp_dst = packet[ARP].pdst
            if arp_src in known_gateways or arp_dst in known_gateways:
                packet_stats['mitm_packets'] += 1
                attack_details = {
                    'ip_src': ip_src,
                    'ip_dst': ip_dst,
                    'protocol': 'ARP',
                    'details': packet.summary(),
                    'attack_type': 'MITM (ARP Spoofing)'
                }
                attack_packets['mitm_attacks'].append(attack_details)
                log_attack('MITM (ARP Spoofing)', attack_details)
                data['attack_type'] = 'MITM (ARP Spoofing)'
                send_email(str(attack_details))
                send_sms(str(attack_details))
                automate_response(ip_src)

        # Spoofing Detection
        if packet.haslayer(IP) and packet[IP].src in known_gateways and packet[IP].dst not in known_gateways:
            packet_stats['spoofing_packets'] += 1
            attack_details = {
                'ip_src': ip_src,
                'ip_dst': ip_dst,
                'protocol': 'IP',
                'details': packet.summary(),
                'attack_type': 'Spoofing'
            }
            attack_packets['spoofing_attacks'].append(attack_details)
            log_attack('Spoofing', attack_details)
            data['attack_type'] = 'Spoofing'
            automate_response(ip_src)

        # DNS Spoofing Detection
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
                    'attack_type': 'DNS Spoofing'
                }
                attack_packets['dns_spoofing_attacks'].append(attack_details)
                log_attack('DNS Spoofing', attack_details)
                data['attack_type'] = 'DNS Spoofing'
                automate_response(ip_src)

        # HTTPS Spoofing Detection
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
                        'details': 'HTTPS Spoofing detected: Certificate mismatch',
                        'attack_type': 'HTTPS Spoofing'
                    }
                    attack_packets['https_spoofing_attacks'].append(attack_details)
                    log_attack('HTTPS Spoofing', attack_details)
                    data['attack_type'] = 'HTTPS Spoofing'
                    automate_response(ip_src)
            except Exception as e:
                pass

        socketio.emit('packet_data', data)

def log_attack(attack_type, details):
    logging.info(f"{attack_type} attack detected: {details}")

def store_historical_data(packet):
    historical_data.append(packet)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)


# Backend Code Enhancement:
# Add Prevention Methods: Integrate methods to prevent various network attacks.

# Capture Metrics: Calculate the percentage of different types of attacks.

# Logging: Save logs for further analysis.

# Email and SMS Alerts: Notify the admin of detected attacks.

# IP Blocking: Automatically block IPs involved in malicious activities.

# pip install flask flask-cors scapy sklearn flask-socketio flask-mail twilio requests pyopenssl flask-talisman
