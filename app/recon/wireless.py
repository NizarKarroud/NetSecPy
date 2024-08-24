from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon
import pywifi

wifi = pywifi.PyWiFi()
iface = wifi.interfaces()[0]  

iface.scan()
results = iface.scan_results()
networks = [result for result in results ]

for network in networks:
    print(f"Network: {network.ssid}, Signal Strength: {network.signal}")
