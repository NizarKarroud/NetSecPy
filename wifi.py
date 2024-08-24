from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon
import time
import pywifi

wifi = pywifi.PyWiFi()
iface = wifi.interfaces()[0]  

iface.scan()
time.sleep(2)  

# def packet_handler(pkt):
#     if pkt.haslayer(Dot11Beacon):
#         # Check if the SSID is not broadcasted (hidden)
#         if not pkt.info:
#             print("Hidden Network Detected:")
#             print("SSID: Hidden")
#             print("BSSID:", pkt.addr3)
#             print("")

results = iface.scan_results()
networks = [result for result in results ]

for network in networks:
    print(f"Network: {network.ssid}, Signal Strength: {network.signal}")


# Sniff WiFi packets on the specified interface
