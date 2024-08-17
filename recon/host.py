from scapy.all import Ether, ARP, srp  ,sr , IP , TCP , ICMP , UDP , traceroute , send , sr1 , fragment
import time
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
                arp_response = srp(arp_request, timeout=timeout)[0]
                for _, packet in arp_response:
                    print(packet)
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
            timeout = kwargs.get("timeout", 1)
            port = kwargs.get("port" , 80)
            fragmentation = kwargs.get("fragmentation", False)
            packet = IP(dst=dst_ip) /TCP(dport=port,flags="S")
            if fragmentation :
                packet = fragment(packet)          
            ans,unans=sr( packet , timeout=timeout )
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
            timeout = kwargs.get("timeout", 1)
            port = kwargs.get("port" , 80)
            ans,unans=sr( IP(dst=dst_ip) /TCP(dport=port,flags="A") , timeout=timeout)

            for sent, received in ans:
                if received.haslayer(TCP) and received[TCP].flags == "R":
                    print(f"{dst_ip} is up (Received RST)")
                else:
                    print(f"{dst_ip} is down")
            if len(unans) > 0:
                print(f"No response from {len(unans)} packets.")

        except Exception as err :
            return err
        
    def udp_ping(self , dst_ip , **kwargs):
        try:
            timeout = kwargs.get("timeout", 1)            
            port = kwargs.get("port" , 40125)
            ans,unans=sr(IP(dst=dst_ip)/UDP(dport = port) , timeout=timeout)
            for sent , received in ans :
                if received[ICMP].type== 3 :
                    print(f"{dst_ip} is up (ICMP port unreachable )")
                
        except Exception as err :
            return err
        
    def icmp(self , dst_ip , **kwargs):
        try:
            type = kwargs.get("type" , 8)
            timeout = kwargs.get("timeout", 1)

            ans,unans=sr(IP(dst=dst_ip)/ICMP(type = type) ,timeout=timeout)
            for sent , received in ans :
                if received.haslayer(ICMP) :
                    if (received[ICMP].type == 14 or received[ICMP].type == 0):
                        print(f"Device {dst_ip} is up ") 
                    elif received[ICMP].type == 3 :
                        print(f"Device {dst_ip} is down ") 

        except Exception as err :
            return err

    def tcp_traceroute(self , ip , **kwargs):
        try :
            dport = kwargs.get("dport" , 80)
            timeout = kwargs.get("timeout", 1)
            ans,unans=traceroute(ip , dport=dport , timeout=timeout , verbose=False)
            router_ips = list(dict.fromkeys([rcv.src for snd, rcv in ans]))

            print(router_ips)
        except Exception as err :
            return err
        
    def idle_scan(self, zombie, target, **kwargs):
        try:
            timeout = kwargs.get("timeout", 1)
            port = kwargs.get("port", 80)

            # Step 1: Probe the zombie's IP ID
            syn_ack_packet = IP(dst=zombie) / TCP(dport=port, flags="SA")
            response = sr1(syn_ack_packet, timeout=timeout, verbose=False)
            
            if response and response.haslayer(IP):
                initial_ip_id = response[IP].id
                print(f"Initial Zombie IP ID: {initial_ip_id}")
                
                # Step 2: Forge a SYN packet from the zombie to the target
                spoofed_syn_packet = IP(src=zombie, dst=target) / TCP(dport=port, flags="S")
                send(spoofed_syn_packet, verbose=False)
                
                time.sleep(1)
                
                # Step 3: Probe the zombie's IP ID again
                response = sr1(syn_ack_packet, timeout=timeout, verbose=False)
                
                if response and response.haslayer(IP):
                    new_ip_id = response[IP].id
                    print(f"New Zombie IP ID: {new_ip_id}")
                    
                    # Determine the state of the port based on IP ID increment
                    if new_ip_id == initial_ip_id + 2:
                        print(f"Port {port} on {target} is open.")
                    elif new_ip_id == initial_ip_id + 1:
                        print(f"Port {port} on {target} is closed.")
                    else:
                        print(f"Port {port} on {target} is filtered or closed.")
                else:
                    print("Failed to get new IP ID from the zombie.")
            else:
                print("Failed to get initial IP ID from the zombie.")
                
        except Exception as err:
            print(f"Error: {err}")

    def fin_scan(self , dst_ip , **kwargs):
        try :
            dport = kwargs.get("dport" , 80)
            timeout = kwargs.get("timeout", 1)
            fin_packet = IP(dst=dst_ip)/TCP(dport=dport,flags='F')
            resp , unans= sr(fin_packet , timeout=timeout)
            for sent, received in resp:
                if received.haslayer(TCP):
                    print(received[TCP])
        except Exception as err :
            print(err)

    
    def null_scan(self , dst_ip , **kwargs):
        try :
            dport = kwargs.get("dport" , 80)
            timeout = kwargs.get("timeout", 1)
            null_packet = IP(dst=dst_ip)/TCP(dport=dport , flags="")
            resp = sr(null_packet , timeout=timeout)
            for sent, received in resp:
                if received.haslayer(TCP):
                    print(received[TCP])
        except Exception as err :
            print(err)

    
    def xmas_scan(self , dst_ip , **kwargs):
        try :
            dport = kwargs.get("dport" , 80)
            timeout = kwargs.get("timeout", 1)
            xmas_packet = IP(dst=dst_ip)/TCP(dport=dport , flags="FPU")
            resp = sr(xmas_packet , timeout=timeout)
            for sent, received in resp:
                if received.haslayer(TCP):
                    print(received[TCP])
        except Exception as err :
            print(err)
    

# rogue dhcp , dns enumm , detect rogue AP , create them     , arp cache poisoning , mitm , cam overflow, ftp enum , ftp bounce scan
# firewalking , dns cache poisoning , Dos , DDos , ACL testingnnnnnnnnnnnnnnnnnnnnnnnnnn