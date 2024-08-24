import psutil , socket

def get_subnet_mask(interface_name):
    for interface, addrs in psutil.net_if_addrs().items():
        if interface == interface_name:
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    return addr.netmask
    return None

# Example usage
interface_name = 'Wi-Fi'  # Replace with your interface name
subnet_mask = get_subnet_mask(interface_name)
print(f'Subnet Mask for {interface_name}: {subnet_mask}')



