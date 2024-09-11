import os
from datetime import datetime
from scapy.all import wrpcap

class Logger:
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),  "logs")        
    def __init__(self):
        self.current_date = datetime.now().strftime("%Y-%m-%d")
        self.current_time = datetime.now().strftime("%H-%M-%S")
        self.create_directory()
        
    def create_directory(self):
        if not os.path.exists(Logger.base_dir):
            os.makedirs(Logger.base_dir)
        self.date_dir = os.path.join(Logger.base_dir, self.current_date)
        if not os.path.exists(self.date_dir):
            os.makedirs(self.date_dir)

    def get_pcap_filename(self, start_time, end_time):
        if isinstance(start_time, str):
            start_time = datetime.strptime(start_time, "%H-%M-%S")
        if isinstance(end_time, str):
            end_time = datetime.strptime(end_time, "%H-%M-%S")
        start_str = start_time.strftime("%H-%M-%S")
        end_str = end_time.strftime("%H-%M-%S")
        return f"{start_str}_to_{end_str}.pcap"


    def save_pcap(self, packets):
        start_time = self.current_time
        end_time = datetime.now().strftime("%H-%M-%S")
        filename = self.get_pcap_filename(start_time, end_time)
        filepath = os.path.join(self.date_dir, filename)
        wrpcap(filepath , packets)



