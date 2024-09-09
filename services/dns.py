from services.nmap import NmapCMD

nmap = NmapCMD()

class DNS :
    def __init__(self) -> None:
        self.scripts = {
            "Broadcast DNS Service Discovery": {
                "command": ["nmap", "--script=broadcast-dns-service-discovery"],
                "argument": None  
            },
            "DNS Brute Force": {
                "command": ["nmap", "--script=dns-brute"],
                "argument": "Target"
            },
            "Full DNS Scan": {
                "command": ["nmap", "-p", "53", "--script=dns-*"],
                "argument": "Target"  
            },
            "DNS Recursion Check": {
                "command": ["nmap", "-sU", "-p", "53", "--script=dns-recursion"],
                "argument": "Target"
            }
        }

        
    def run(self,command , target:str=None):
        if target:
            command.append(target.strip())
        return nmap.run(command)