from scapy.all import Ether, ICMP , TCP , UDP ,IP, Raw , ETHER_TYPES , TCP_SERVICES, UDP_SERVICES  , IP_PROTOS ,sendp, send, srp, sr, sendpfast   


class PacketCrafter:
    ether_types = ETHER_TYPES.d

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
    ip_protocols = IP_PROTOS.d

    icmp_types_and_codes = {
        "echo-reply": {"type": 0, "code": 0},
        "dest-unreach": {
            "type": 3,
            "codes": {
                "network-unreachable": 0,
                "host-unreachable": 1,
                "protocol-unreachable": 2,
                "port-unreachable": 3,
                "fragmentation-needed": 4,
                "source-route-failed": 5
            }
        },
        "redirect": {
            "type": 5,
            "codes": {
                "network-redirect": 0,
                "host-redirect": 1,
                "TOS-network-redirect": 2,
                "TOS-host-redirect": 3
            }
        },
        "echo-request": {"type": 8, "code": 0},
        "time-exceeded": {
            "type": 11,
            "codes": {
                "ttl-zero-during-transit": 0,
                "ttl-zero-during-reassembly": 1
            }
        },
        "parameter-problem": {
            "type": 12,
            "codes": {
                "ip-header-bad": 0,
                "required-option-missing": 1,
                "2": 2
            }
        },
        "timestamp-request": {"type": 13, "code": 0},
        "timestamp-reply": {"type": 14, "code": 0},
        "information-request": {"type": 15, "code": 0},
        "information-response": {"type": 16, "code": 0},
        "address-mask-request": {"type": 17, "code": 0},
        "address-mask-reply": {"type": 18, "code": 0}
    }
    
    tcp_services = TCP_SERVICES.d
    udp_services = UDP_SERVICES.d

    flags = {
    'FIN': 'F',
    'SYN': 'S',
    'RST': 'R',
    'PSH': 'P',
    'ACK': 'A',
    'URG': 'U',
    'ECE': 'E',
    'CWR': 'C'
    }
    
    def __init__(self) -> None:
        self.packet = None  

    
    @classmethod
    def get_ether_type_name(cls, type: int) -> str:
        """Return the name of the EtherType if known."""
        return cls.ether_types.get(type, "Unknown EtherType")
    
    @classmethod
    def get_tos_value(cls, name: str) :
        """Return the name of the EtherType if known."""
        return cls.tos_dict.get(name , 0)
    
    @classmethod
    def get_icmp_type_and_code(cls, type_name, code_name=None):
        if type_name in cls.icmp_types_and_codes:
            icmp_type = cls.icmp_types_and_codes[type_name]["type"]
            if code_name and "codes" in cls.icmp_types_and_codes[type_name]:
                icmp_code = cls.icmp_types_and_codes[type_name]["codes"].get(code_name, 0)
            else:
                icmp_code = cls.icmp_types_and_codes[type_name]["code"]
            return icmp_type, icmp_code
        else:
            raise ValueError(f"Invalid ICMP type name: {type_name}")
    
    def Ethernet(self , src: str, dst: str, type: int = 0x9000) : 
        return Ether(src=src, dst=dst , type=type)
    
    def Ip(self, src_ip: str, dst_ip: str, tos : int = 0, len: int = None, id: int = 1, frag: int = 0, ttl: int = 64, version: int = 4, proto ='ip'):
        return IP(src=src_ip, dst=dst_ip, tos=tos, len=len, id=id, frag=frag, ttl=ttl, version=version, proto=proto)
    
    def icmp(self ,type_name=0, code_name=0):
        return ICMP(type=type_name,code=code_name)
    
    def tcp(self ,sport, dport , seq=0, ack=0 , flags="S"):
        return TCP(sport=sport, dport=dport, seq=seq, ack=ack, flags=flags) 
    
    def udp(self, sport, dport, length=None):
        return UDP(sport=sport, dport=dport, len=length)
    
    def data(self, payload):
        return Raw(load=payload)

    def craft_packet(self, ethernet_layer=None, ip_layer=None, transport_layer=None, data_layer=None):
        """Constructs a packet by stacking the provided layers."""
        layers = [layer for layer in [ethernet_layer, ip_layer, transport_layer, data_layer] if layer is not None]
        
        if layers:
            self.packet = layers[0]
            for layer in layers[1:]:
                self.packet = self.packet / layer
        else:
            self.packet = None

        return self.packet

    def display_packet(self):
        """Print the details of the crafted packet."""
        if self.packet:
            self.packet.show()
        else:
            print("No packet crafted yet.")

    # Layer 2: Send using sendp()
    def send_via_layer2(self):
        """Send the crafted packet at Layer 2 (Ethernet)."""
        if self.packet:
            sendp(self.packet)
        else:
            print("No packet crafted to send.")
        self.packet = None

    # Layer 3: Send using send()
    def send_via_layer3(self):
        """Send the crafted packet at Layer 3 (IP level)."""
        if self.packet:
            send(self.packet)
        else:
            print("No packet crafted to send.")
        self.packet = None

    # Layer 2: Send and Receive using srp()
    def send_receive_layer2(self):
        """Send and receive packets at Layer 2 (Ethernet)."""
        if self.packet:
            ans, unans = srp(self.packet, timeout=2)
            ans.show()
        else:
            print("No packet crafted to send.")
        self.packet = None

    # Layer 3: Send and Receive using sr()
    def send_receive_layer3(self):
        """Send and receive packets at Layer 3 (IP level)."""
        if self.packet:
            ans, unans = sr(self.packet, timeout=2)
            ans.show()
        else:
            print("No packet crafted to send.")

        self.packet = None
    
    # Layer 2: Send packets quickly using sendpfast()
    def send_fast_layer2(self):
        """Fast send at Layer 2 (Ethernet), useful for flooding."""
        if self.packet:
            sendpfast(self.packet)
        else:
            print("No packet crafted to send.")
        self.packet = None
        
