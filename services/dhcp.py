from services.nmap import NmapCMD

nmap = NmapCMD()

class DHCP :
    def __init__(self) -> None:
        self.scripts = {
            "Broadcast DHCP discover": {
                "command":  ["nmap" , "--script broadcast-dhcp-discover", "255.255.255.255"],
                "argument": None  
            },
            "Broadcast DHCP6 discover": {
                "command":  ["nmap", "-6" ,"--script broadcast-dhcp6-discover"],
                "argument": None  
            },
            "DHCP Discover": {
                "command":  ["nmap" ,"-sU" ,"-p" ,"67" ,"--script=dhcp-discover"],
                "argument": None  
            }
        }

    def run(self,command):
        return nmap.run(command)