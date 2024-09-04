from scapy.all import Ether, IP, TCP, Raw

class EthernetLayer(Ether):
    def __init__(self, src_mac: str, dst_mac: str) -> None:
        super().__init__(src=src_mac, dst=dst_mac)

class IpLayer(IP):
    def __init__(self, src_ip: str, dst_ip: str, ttl: int = 64) -> None:
        super().__init__(src=src_ip, dst=dst_ip, ttl=ttl)

class TransportLayer():
    def __init__(self, protocol, sport = None , dport= None ) -> None:
        self.sport = sport
        self.dport = dport
        self.protocol = protocol
        
class DataLayer(Raw):
    def __init__(self, payload: str) -> None:
        super().__init__(load=payload)

class PacketCrafter:
    def __init__(self) -> None:
        pass