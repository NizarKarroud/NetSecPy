from scapy.all import conf, DHCP, IP, UDP, BOOTP, Ether, srp

conf.checkIPaddr = False

# Define the DHCP Discover packet
dhcp_discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr="E0:2B:E9:DD:D0:7E") /  # Use your MAC address here
    DHCP(options=[("message-type", "discover"), "end"])
)

# Print debug information
print("Sending DHCP Discover packet...")

# Send packet and capture responses
ans, unans = srp(dhcp_discover, timeout=5)

# Print the responses
if ans:
    for _, packet in ans:
        if packet and packet[1]:
            print("Response from:", packet[1][Ether].src, packet[1][IP].src)
else:
    print("No DHCP responses received.")
