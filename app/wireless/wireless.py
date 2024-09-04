from scapy.all import *
import time
import pywifi

wifi = pywifi.PyWiFi()
iface = wifi.interfaces()[0]  

iface.scan()
time.sleep(2)  



results = iface.scan_results()
networks = [result for result in results ]

for network in networks:
    print(f"Network: {network.ssid}, Signal Strength: {network.signal}")
