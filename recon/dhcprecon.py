from scapy.all import conf, DHCP, IP, UDP, BOOTP, Ether, srp, get_if_list, getmacbyip

# Ensure elevated permissions
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
print("Sending DHCP Discover packet on interface:")

# Send packet and capture responses
ans, unans = srp(dhcp_discover, multi=True, timeout=5)

# Print the responses
if ans:
    for packet in ans:
        if packet and packet[1]:
            print("Response from:", packet[1][Ether].src, packet[1][IP].src)
else:
    print("No DHCP responses received.")


# class RogueDHCP:
#     def __init__(self , ip ) -> None:
#         self.__ip = ip