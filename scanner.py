# This script detects basic ARP spoofing, scans every __ seconds
# evil-twin.py

from scapy.all import *
import time

TARGET_SUBNET = "192.xxx.xx.0/24" # Target IP
SCAN_INTERVAL = 60

def scan(subnet):
    """
    Scan network with ARP
    """

    devices = dict()
    
    # Construct packet to broadcast
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request = ARP(pdst=subnet)
    packet = ether_frame / arp_request      

    result = srp(packet, timeout=3, verbose=0)[0]

    if result:
        # Build a table of IP -> MAC
        for sent, received in result:
            devices[received.psrc] = received.hwsrc
            if received.hwsrc != received[Ether].src:
                print("[ALERT] Possible spoofing detected. ARP/Ethernet mismatch!")
    else:
        print("No devices responded on this subnet.")

    return devices


def detect_changes(previous, current):
    """
    Compare and print alerts if something changed suspiciously
    """
    # Detection rule 1: IP changed MAC
    for ip, mac in current.items():
        if ip in previous:
            if previous[ip] != current[ip]:
                print(f"[ALERT] Possible spoofing detected. IP {ip} changed MAC from {previous[ip]} to {current[ip]}!")

    # Detection rule 2: one MAC claims multiple IPs
    mac_to_ips = dict()
    for ip, mac in current.items():
        mac_to_ips.setdefault(mac, []).append(ip)
    
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            print(f"[ALERT] Possible spoofing detected. MAC {mac} claims multiple IPs: {ips}")


previous_devices = scan(TARGET_SUBNET)

# Repeat forever
while True:
    # Sleep for 60 sec
    time.sleep(SCAN_INTERVAL)

    current_devices = scan(TARGET_SUBNET)
    detect_changes(previous_devices, current_devices)

    # Save this scan as the new “previous state”
    previous_devices = current_devices