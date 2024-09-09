import pandas as pd
from scapy.all import PcapReader, Packet 
import matplotlib.pyplot as plt
import networkx as nx
import sys , os
from datetime import datetime
import matplotlib.dates as mdates  

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from craft.craft import EthernetLayer  

class NTA:
    def __init__(self, packets=[], pcap_file=None) -> None:
        self.packets = packets
        self.file = pcap_file
        if self.file:
            self.load_packets(self.file)
        if self.packets:
            self.data = self.packet_to_data()

    def extract_fields(self, layer, prefix=''):
        fields_dict = {}
        if isinstance(layer, Packet):
            for field_name in layer.fields_desc:
                field_value = getattr(layer, field_name.name, None)

                fields_dict[prefix + field_name.name] = field_value
        return fields_dict

    def extract_packet_fields(self, pkt):
        fields_dict = {}
        layer = pkt
        while layer:
            layer_name = layer.__class__.__name__

            layer_fields = self.extract_fields(layer, prefix=layer_name + '_')
            fields_dict.update(layer_fields)

            layer = layer.payload
            if not isinstance(layer, Packet):
                break
        return fields_dict

    def packet_to_dataframe(self, packet):
        fields_dict = self.extract_packet_fields(packet)

        if 'Ether_type' in fields_dict:
            ether_type_value = fields_dict['Ether_type']
            ether_type_name = EthernetLayer.get_ether_type_name(ether_type_value)
            fields_dict['Ether_type'] = ether_type_name
        
        fields_dict['Timestamp'] = packet.time

        df = pd.DataFrame([fields_dict])
        return df

    def packet_to_data(self):
        packet_dataframes = []
        for packet in self.packets:
            df = self.packet_to_dataframe(packet)
            packet_dataframes.append(df)
        return pd.concat(packet_dataframes, ignore_index=True)

    def load_packets(self, file):
        with PcapReader(file) as pcap:
            for packet in pcap:
                self.packets.append(packet)

class EtherAnalyzer:
    def __init__(self, data) -> None:
        self.arp_data = data[[field for field in list(data.columns) if field.startswith('ARP') or field.startswith('Ether')] +["Timestamp"]].dropna()
        self.ether_data = data[[field for field in list(data.columns) if field.startswith('Ether')]+["Timestamp"]].dropna()

    def visualize_communication_graph(self):

        network = nx.from_pandas_edgelist(self.ether_data, source='Ether_src', target='Ether_dst', edge_attr='Ether_type')

        plt.figure(figsize=(10, 8))

        pos = nx.spring_layout(network, seed=42)

        nx.draw_networkx_nodes(network, pos, node_size=3000, node_color='skyblue', alpha=0.7)
        nx.draw_networkx_edges(network, pos, width=2, alpha=0.5, edge_color='gray')

        nx.draw_networkx_labels(network, pos, font_size=10, font_color='black', font_weight='bold')

        edge_labels = nx.get_edge_attributes(network, 'Ether_type')
        nx.draw_networkx_edge_labels(network, pos, edge_labels=edge_labels, font_color='red', font_size=8)

        plt.title("Ethernet Communication Graph")
        
        plt.show()

    def mac_frequency_analysis(self):
        ether_src_counts = self.ether_data['Ether_src'].value_counts()
        ether_dst_counts = self.ether_data['Ether_dst'].value_counts()

        plt.figure(figsize=(10, 6))
        ether_src_counts.plot(kind='bar', color='lightcoral', alpha=0.7)
        plt.title('Source MAC Address Frequency')
        plt.xlabel('MAC Address')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()


        plt.figure(figsize=(10, 6))
        ether_dst_counts.plot(kind='bar', color='lightblue', alpha=0.7)
        plt.title('Destination MAC Address Frequency')
        plt.xlabel('MAC Address')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

        return (ether_src_counts,ether_dst_counts)

    def mac_pair_analysis(self, top_n=10):
        # Group by source and destination MAC addresses, and count occurrences
        pair_counts = self.ether_data.groupby(['Ether_src', 'Ether_dst']).size().reset_index(name='count')
        
        # Create a new column that combines source and destination MAC addresses
        pair_counts['MAC_pair'] = pair_counts['Ether_src'] + ' -> ' + pair_counts['Ether_dst']
        
        # Sort and select the top N pairs
        top_pairs = pair_counts.sort_values(by='count', ascending=False).head(top_n)
        
        # Plot all pairs, but limit the display to the top N
        plt.figure(figsize=(14, 10))
        bars = plt.bar(top_pairs['MAC_pair'], top_pairs['count'], color='seagreen', alpha=0.7)
        plt.title(f'Top {top_n} Source-Destination MAC Address Pairs')
        plt.xlabel('Source and Destination MAC Address Pair')
        plt.ylabel('Count')

        # Improve x-tick labels
        plt.xticks(rotation=45, ha='right')  # Rotate and align x-tick labels
        plt.tight_layout()  # Ensure everything fits without overlap
        
        plt.show()

        # Return the entire dataset for further analysis if needed
        return pair_counts
    
    def analyze_traffic_types(self):
        ether_type_counts = self.ether_data['Ether_type'].value_counts()

        # Horizontal bar chart
        plt.figure(figsize=(10, 6))
        ether_type_counts.plot(kind='barh', color='lightblue', alpha=0.7)
        plt.title('Ether_type Breakdown')
        plt.xlabel('Count')
        plt.ylabel('Ether_type (Traffic Type)')
        plt.tight_layout()
        plt.show()

        return ether_type_counts

    def detect_arp_poisoning(self):
        # Filter for ARP packets with opcode 1 (ARP Request)
        arp_requests = self.arp_data[self.arp_data['ARP_op'] == 1]
        
        # Convert timestamps to datetime objects
        arp_requests['Timestamp'] = arp_requests['Timestamp'].apply(
            lambda ts: datetime.fromtimestamp(float(ts)) if pd.notnull(ts) else pd.NaT
        )

        # Drop rows with invalid timestamps
        arp_requests = arp_requests.dropna(subset=['Timestamp'])

        # Set 'Timestamp' column as the index
        arp_requests.set_index('Timestamp', inplace=True)

        # Count ARP requests per source MAC address
        arp_request_counts = arp_requests.groupby('Ether_src').size()

        # Calculate threshold for identifying high counts
        mean = arp_request_counts.mean()
        std_dev = arp_request_counts.std()
        threshold = mean + 3 * std_dev
        
        # Flag MAC addresses with high ARP request counts
        high_count_mac_addresses = arp_request_counts[arp_request_counts > threshold]
        
        # Plot ARP request counts per MAC address
        plt.figure(figsize=(12, 8))
        arp_request_counts.plot(kind='bar', color='lightcoral', alpha=0.7)
        plt.axhline(y=threshold, color='r', linestyle='--', label=f'Threshold ({threshold:.0f})')
        plt.title('ARP Requests Count per MAC Address')
        plt.xlabel('MAC Address')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.legend()
        plt.tight_layout()
        plt.show()

        # Plot high count MAC addresses
        if not high_count_mac_addresses.empty:
            plt.figure(figsize=(12, 8))
            high_count_mac_addresses.plot(kind='bar', color='lightblue', alpha=0.7)
            plt.title('High ARP Request Counts per MAC Address')
            plt.xlabel('MAC Address')
            plt.ylabel('Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.show()

        # Count ARP requests over time
        arp_requests_per_hour = arp_requests.resample('H').size()

        # Plot ARP request counts over time
        plt.figure(figsize=(14, 7))
        plt.plot(arp_requests_per_hour.index, arp_requests_per_hour.values, marker='o', linestyle='-', color='b')
        plt.title('ARP Request Counts Over Time')
        plt.xlabel('Time')
        plt.ylabel('ARP Request Count')
        plt.grid(True, linestyle='--', alpha=0.7)

        # Improve x-axis formatting
        ax = plt.gca()
        ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
        ax.xaxis.set_minor_locator(mdates.MinuteLocator(interval=15))
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))

        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()

        return arp_request_counts, high_count_mac_addresses
    
    
    def broadcast_traffic_analysis(self):
        broadcast_dst = 'ff:ff:ff:ff:ff:ff'
        
        # Filter rows with broadcast destination address
        broadcast_packets = self.ether_data[self.ether_data['Ether_dst'] == broadcast_dst]

        # Convert timestamps to datetime objects
        broadcast_packets.loc[:, 'Timestamp'] = broadcast_packets['Timestamp'].apply(
            lambda ts: datetime.fromtimestamp(float(ts)) if pd.notnull(ts) else pd.NaT
        )

        # Drop rows with invalid timestamps
        broadcast_packets = broadcast_packets.dropna(subset=['Timestamp'])

        # Set 'Timestamp' column as the index
        broadcast_packets.set_index('Timestamp', inplace=True)

        # Count the number of broadcast packets per hour
        broadcast_counts_per_hour = broadcast_packets.resample('H').size()

        # Plot broadcast traffic over time with a line plot
        plt.figure(figsize=(14, 7))
        plt.plot(broadcast_counts_per_hour.index, broadcast_counts_per_hour.values, marker='o', linestyle='-', color='b')
        plt.title('Broadcast Traffic Count per Hour')
        plt.xlabel('Hour')
        plt.ylabel('Broadcast Packet Count')
        plt.grid(True, linestyle='--', alpha=0.7)

        # Improve x-axis formatting
        ax = plt.gca()
        ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
        ax.xaxis.set_minor_locator(mdates.MinuteLocator(interval=15))
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))

        plt.xticks(rotation=45)
        plt.tight_layout()

        plt.show()

        # Return the broadcast packets and their count
        broadcast_count = len(broadcast_packets)
        return broadcast_packets, broadcast_count

   










# Example usage
nta = NTA(pcap_file="test.pcap")  
print(nta.data['Timestamp'].head(1))
ether_analyzer = EtherAnalyzer(nta.data)

# ether_analyzer.visualize_communication_graph()

# ether_analyzer.mac_frequency_analysis()

# ether_analyzer.analyze_traffic_types()

date , a = ether_analyzer.detect_arp_poisoning()
