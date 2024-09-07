from services.nmap import NmapCMD

nmap = NmapCMD()

class DHCP :
    def __init__(self) -> None:
        self.scripts = {"Broadcast DHCP discover" : ["nmap" , "--script broadcast-dhcp-discover", "255.255.255.255"],
                        "Broadcast DHCP6 discover" : ["nmap", "-6" ,"--script broadcast-dhcp6-discover"],
                        "DHCP Discover" : ["nmap" ,"-sU" ,"-p" ,"67" ,"--script=dhcp-discover"]
                        }
        
    def run(self,command):
        return nmap.run(command)