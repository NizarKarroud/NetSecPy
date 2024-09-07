from scapy.all import Ether, IP, TCP, Raw , ETHER_TYPES , TCP_SERVICES, UDP_SERVICES ,SCTP_SERVICES , IP_PROTOS   


class EthernetLayer(Ether):
    ether_types = ETHER_TYPES.d

    def __init__(self, src_mac: str, dst_mac: str, type: int) -> None:
        
        if type not in EthernetLayer.ether_types.keys():
            raise ValueError(f"Invalid EtherType: {type}. Valid types are: {list(self.ether_types.keys())}")
        
        super().__init__(src=src_mac, dst=dst_mac, type=type)
    
    @classmethod
    def get_ether_type_name(cls, type: int) -> str:
        """Return the name of the EtherType if known."""
        return cls.ether_types.get(type, "Unknown EtherType")

class IpLayer(IP):
    tos_dict = {
        "Network Control" : 0b111 ,
        "Internetwork Control" : 0b110,
        "CRITIC/ECP" : 0b101 ,
        "Flash Override" : 0b100,
        "Flash" : 0b011,
        "Immediate" : 0b010,
        "Priority" : 0b001,
        "Routine" :0b000
    }

    def __init__(self, src_ip: str, dst_ip: str, tos : int = 0, len: int = None, id: int = 1, frag: int = 0, ttl: int = 64, 
                 version: int = 4, proto: int = 0):

        super().__init__(src=src_ip, dst=dst_ip, tos=tos, len=len, id=id, frag=frag, ttl=ttl, version=version, proto=proto)
    
    @classmethod
    def get_tos_value(cls, name: str) :
        """Return the name of the EtherType if known."""
        return cls.tos_dict.get(name , 0)
    
class TransportLayer():
    protocols = IP_PROTOS.d
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


if __name__ == "__main__":
    # GGP (Protocol 3)
    ggp_packet = IP(proto=3, src="192.168.1.1", dst="192.168.1.2") / Raw("Payload data")
    ggp_packet.show()