from scapy.all import Ether, ARP, srp  ,sr , IP , TCP , ICMP , UDP , traceroute , send , sr1 
import subprocess
import ipaddress
from services.nmap import NmapCMD
class Scanner:
    def __init__(self, MAC, IP , subnet) -> None:
        self.__mac = MAC
        self.__ip = IP
        self.__subnet = subnet
        self._net_obj = ipaddress.ip_network(f'{self.__ip}/{self.__subnet}', strict=False)
        self.__hosts = [str(ip) for ip in self._net_obj.hosts()]
        self.__network = self._net_obj.with_prefixlen
        self._nmapcmd = NmapCMD()
    def arp_scan(self):

        return self._nmapcmd.run(["nmap", "-sn" , "-PR" ,self.__network])


    def tcp_syn_scan(self , dst_ip: str , timeout : int =1 , port : int =80 ):
        try:
            packet = IP(dst=dst_ip) /TCP(dport=port,flags="S")
            ans,unans=sr( packet , timeout=timeout )
            for sent, received in ans:
                if received.haslayer(TCP):
                    if received[TCP].flags == "SA":
                        return f"{dst_ip} is up , {port} is open."
                    elif received[TCP].flags == "RA":
                        return f"{dst_ip} is up , {port} is closed."
            if len(unans) > 0:
                return f"No response from {len(unans)} packets."

        except Exception as err :
            return err

    def tcp_ack_scan(self , dst_ip: str ,timeout : int =1 , port : int =80 ):
        try:
            ans,unans=sr( IP(dst=dst_ip) /TCP(dport=port,flags="A") , timeout=timeout)

            for sent, received in ans:
                if received.haslayer(TCP) and received[TCP].flags == "R":
                    return f"{dst_ip} is up (Received RST)"
                else:
                    return f"{dst_ip} is down"
            if len(unans) > 0:
                return f"No response from {len(unans)} packets."

        except Exception as err :
            return err
        
    def udp_ping(self , dst_ip: str ,timeout : int =1 , port : int =40125 ):
        try:
            ans,unans=sr(IP(dst=dst_ip)/UDP(dport = port) , timeout=timeout)
            for sent , received in ans :
                if received[ICMP].type== 3 :
                    return f"{dst_ip} is up (ICMP port unreachable )"
        except Exception as err :
            return err
        
    def icmp(self ,dst_ip: str , type : int =8 , timeout : int = 1):
        try:
            ans,unans=sr(IP(dst=dst_ip)/ICMP(type = type) ,timeout=timeout)
            for sent , received in ans :
                if received.haslayer(ICMP) :
                    if (received[ICMP].type == 14 or received[ICMP].type == 0):
                        return f"Device {dst_ip} is up "
                    elif received[ICMP].type == 3 :
                        return "Device {dst_ip} is down "

        except Exception as err :
            return err

    def tcp_traceroute(self , target_ip: str ):

        return self._nmapcmd.run(["nmap", "--traceroute"  , target_ip])

    def idle_scan(self , zombie_ip: str, target_ip: str):

        return self._nmapcmd.run(["nmap", "-Pn" , "-sI" , zombie_ip, target_ip])

    def fin_scan(self , target_ip : str):
 
        return self._nmapcmd.run(["nmap", "-sF"  , target_ip])
       
    def null_scan(self , target_ip: str ):

        return self._nmapcmd.run(["nmap", "-sN"  , target_ip])

    def xmas_scan(self , target_ip: str ):

        return self._nmapcmd.run(["nmap", "-sX"  , target_ip])
    
    def os(self,target_ip : str):

        return self._nmapcmd.run(["nmap", "-AO"  , target_ip])
