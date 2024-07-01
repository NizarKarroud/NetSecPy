from scapy.all import Ether, ARP, srp , sniff ,sr , IP , TCP
import pandas as pd
import ipaddress

class Scanner:
    def __init__(self, MAC, IP) -> None:
        self.__mac = MAC
        self.__ip = IP

    def arp_scan(self, network_ip, subnet_mask, **kwargs):
        try :
            path = kwargs.get("csv" , "data/arp.csv")
            timeout = kwargs.get("timeout" , 1)
            data = []
            network = ipaddress.ip_network(f'{network_ip}/{subnet_mask}', strict=False)
            hosts = [str(ip) for ip in network.hosts()]
            
            for host in hosts:
                arp_request = Ether(src=self.__mac, dst='FF:FF:FF:FF:FF:FF') / ARP(op=1, hwsrc=self.__mac, pdst=host, psrc=self.__ip)
                arp_response = srp(arp_request, timeout=timeout, verbose=False)[0]
                
                for _, packet in arp_response:
                    if packet and packet.haslayer(ARP) and packet[ARP].op == 2:  
                        data.append({
                            'IP Address': packet[ARP].psrc,
                            'MAC Address': packet[ARP].hwsrc
                        })
                pd.DataFrame(data).to_csv(path, index=False)
        except Exception as err :
            print(err)

    def tcp_syn_scan(self , dst_ip , **kwargs ):
        try:
            port = kwargs.get("port" , 80)
            ans,unans=sr( IP(dst=dst_ip) /TCP(dport=port,flags="S") )
            for sent, received in ans:
                if received.haslayer(TCP):
                    if received[TCP].flags == "SA":
                        print(f"{dst_ip} is up , {port} is open.")
                    elif received[TCP].flags == "RA":
                        print(f"{dst_ip} is up , {port} is closed.")
            if len(unans) > 0:
                print(f"No response from {len(unans)} packets.")

        except Exception as err :
            return err

    def tcp_ack_scan(self , dst_ip , **kwargs):
        try:
            port = kwargs.get("port" , 80)
            ans,unans=sr( IP(dst=dst_ip) /TCP(dport=port,flags="A") )

            for sent, received in ans:
                if received.haslayer(TCP) and received[TCP].flags == "R":
                    print(f"{dst_ip} is up (Received RST)")
                else:
                    print(f"{dst_ip} is down")
            if len(unans) > 0:
                print(f"No response from {len(unans)} packets.")

        except Exception as err :
            return err
        
    def udp_ping(self):
        try:
            ...
        except Exception as err :
            return err
        
    def icmp_ping(self):
        try:
            ...
        except Exception as err :
            return err
