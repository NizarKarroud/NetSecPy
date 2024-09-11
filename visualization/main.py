import pandas as pd
from scapy.all import PcapReader, Packet ,IP_PROTOS ,IP
import matplotlib.pyplot as plt
import networkx as nx
import sys , os
from datetime import datetime
import matplotlib.dates as mdates  
import plotly.graph_objects as go

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from craft.craft import PacketCrafter

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
            ether_type_name = PacketCrafter.get_ether_type_name(ether_type_value)
            fields_dict['Ether_type'] = ether_type_name
        
        fields_dict['Timestamp'] = packet.time
        if IP in packet:
            fields_dict['IP_proto'] = IP_PROTOS.d.get(int(packet[IP].proto) , f"{str(packet[IP].proto)}")

        df = pd.DataFrame([fields_dict])
        df['Timestamp'] = df['Timestamp'].apply(
            lambda ts: datetime.fromtimestamp(float(ts)) if pd.notnull(ts) else pd.NaT
        )   
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

    def visualize_ether_communication_graph(self):
        network = nx.from_pandas_edgelist(
            self.ether_data, 
            source='Ether_src', 
            target='Ether_dst', 
            edge_attr='Ether_type'
        )

        pos = nx.spring_layout(network, seed=42)
        
        edge_x = []
        edge_y = []
        edge_text = []
        for edge in network.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.append(x0)
            edge_x.append(x1)
            edge_y.append(y0)
            edge_y.append(y1)
            edge_text.append(network[edge[0]][edge[1]]['Ether_type'])

        edge_trace = go.Scatter(
            x=edge_x, 
            y=edge_y,
            mode='lines',   
            line=dict(width=0.5, color='#888'),
            hoverinfo='none'
        )

        edge_text_trace = go.Scatter(
            x=[(x0 + x1) / 2 for x0, x1 in zip(edge_x[::2], edge_x[1::2])],   
            y=[(y0 + y1) / 2 for y0, y1 in zip(edge_y[::2], edge_y[1::2])], 
            mode='text',  
            text=edge_text,   
            textposition='middle center', 
            textfont=dict(size=10, color='red'),  
            hoverinfo='none'
        )

        node_x = []
        node_y = []
        for node in network.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)

        node_trace = go.Scatter(
            x=node_x, 
            y=node_y,
            mode='markers+text',
            text=[node for node in network.nodes()],
            textposition='top center',
            marker=dict(size=10, color='#007ACC', line=dict(width=2, color='black')),
            hoverinfo='text'
        )

        fig = go.Figure(data=[edge_trace, edge_text_trace, node_trace],
                        layout=go.Layout(
                            title='Ethernet Communication Graph',
                            showlegend=False,
                            hovermode='closest',
                            xaxis=dict(showgrid=False, zeroline=False),
                            yaxis=dict(showgrid=False, zeroline=False)
                        ))

        fig.show()

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

        df_ether_src = ether_src_counts.reset_index()
        df_ether_src.columns = ['Ether_src', 'Count']

        df_ether_dst = ether_dst_counts.reset_index()
        df_ether_dst.columns = ['Ether_dst', 'Count']

        return (df_ether_src,df_ether_dst)

    def mac_pair_analysis(self):
        pair_counts = self.ether_data.groupby(['Ether_src', 'Ether_dst']).size().reset_index(name='count')
        
        pair_counts['MAC_pair'] = pair_counts['Ether_src'] + ' -> ' + pair_counts['Ether_dst']
        
        top_pairs = pair_counts.sort_values(by='count', ascending=False).head(10)
        
        plt.figure(figsize=(14, 10))
        bars = plt.bar(top_pairs['MAC_pair'], top_pairs['count'], color='seagreen', alpha=0.7)
        plt.title(f'Top {10} Source-Destination MAC Address Pairs')
        plt.xlabel('Source and Destination MAC Address Pair')
        plt.ylabel('Count')

        plt.xticks(rotation=45, ha='right')   
        plt.tight_layout()   
        
        plt.show()

        return pair_counts
    
    def analyze_traffic_types(self):
        ether_type_counts = self.ether_data['Ether_type'].value_counts()

        plt.figure(figsize=(10, 6))
        ether_type_counts.plot(kind='barh', color='lightblue', alpha=0.7)
        plt.title('Ether_type Breakdown')
        plt.xlabel('Count')
        plt.ylabel('Ether_type (Traffic Type)')
        plt.tight_layout()
        plt.show()

        ether_type_counts_df = ether_type_counts.reset_index()
        ether_type_counts_df.columns = ['Ether_type', 'Count']

        return ether_type_counts_df

    def detect_arp_scanning(self):
        try:
            arp_requests = self.arp_data[self.arp_data['ARP_op'] == 1]

            arp_requests = arp_requests.dropna(subset=['Timestamp'])

            arp_requests['Timestamp'] = pd.to_datetime(arp_requests['Timestamp'])

            arp_requests.set_index('Timestamp', inplace=True)

            arp_request_counts = arp_requests.groupby('Ether_src').size()

            mean = arp_request_counts.mean()
            std_dev = arp_request_counts.std()
            threshold = mean + 3 * std_dev
            
            high_count_mac_addresses = arp_request_counts[arp_request_counts > threshold]
            
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

            if not high_count_mac_addresses.empty:
                plt.figure(figsize=(12, 8))
                high_count_mac_addresses.plot(kind='bar', color='lightblue', alpha=0.7)
                plt.title('High ARP Request Counts per MAC Address')
                plt.xlabel('MAC Address')
                plt.ylabel('Count')
                plt.xticks(rotation=45)
                plt.tight_layout()
                plt.show()

            arp_requests_per_hour = arp_requests.resample('H').size()

            plt.figure(figsize=(14, 7))
            plt.plot(arp_requests_per_hour.index, arp_requests_per_hour.values, marker='o', linestyle='-', color='b')
            plt.title('ARP Request Counts Over Time')
            plt.xlabel('Time')
            plt.ylabel('ARP Request Count')
            plt.grid(True, linestyle='--', alpha=0.7)

            ax = plt.gca()
            ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
            ax.xaxis.set_minor_locator(mdates.MinuteLocator(interval=15))
            ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))

            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.show()

            return arp_request_counts

        except Exception as e:
            return None
        
    def broadcast_traffic_analysis(self):
        broadcast_dst = 'ff:ff:ff:ff:ff:ff'
        
        broadcast_packets = self.ether_data[self.ether_data['Ether_dst'] == broadcast_dst]


        broadcast_packets = broadcast_packets.dropna(subset=['Timestamp'])

        broadcast_packets.set_index('Timestamp', inplace=True)

        broadcast_counts_per_hour = broadcast_packets.resample('H').size()

        plt.figure(figsize=(14, 7))
        plt.plot(broadcast_counts_per_hour.index, broadcast_counts_per_hour.values, marker='o', linestyle='-', color='b')
        plt.title('Broadcast Traffic Count per Hour')
        plt.xlabel('Hour')
        plt.ylabel('Broadcast Packet Count')
        plt.grid(True, linestyle='--', alpha=0.7)

        ax = plt.gca()
        ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
        ax.xaxis.set_minor_locator(mdates.MinuteLocator(interval=15))
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))

        plt.xticks(rotation=45)
        plt.tight_layout()

        plt.show()

        return broadcast_packets

class IpAnalyzer:
    def __init__(self, data) -> None:
        self.ip_data = data[[field for field in list(data.columns) if field.startswith('IP_')]+["Timestamp"]].dropna()

    def monitor_high_traffic_ips(self):

        traffic_volume = self.ip_data.groupby('IP_src')['IP_len'].sum()


        mean_traffic = traffic_volume.mean()
        std_dev_traffic = traffic_volume.std()

        threshold = mean_traffic + 3 * std_dev_traffic

        high_traffic_ips = traffic_volume[traffic_volume > threshold]

        plt.figure(figsize=(12, 8))
        traffic_volume.plot(kind='bar', color='lightblue', alpha=0.7)
        plt.axhline(y=threshold, color='r', linestyle='--', label=f'Threshold ({threshold:.0f})')
        plt.title('Traffic Volume per Source IP')
        plt.xlabel('Source IP')
        plt.ylabel('Traffic Volume (Bytes)')
        plt.xticks(rotation=45, ha='right')
        plt.legend()
        plt.tight_layout()
        plt.show()

        if not high_traffic_ips.empty:
            plt.figure(figsize=(12, 8))
            high_traffic_ips.plot(kind='bar', color='salmon', alpha=0.7)
            plt.title('High Traffic Volume per Source IP')
            plt.xlabel('Source IP')
            plt.ylabel('Traffic Volume (Bytes)')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.show()

        return traffic_volume.to_frame(name='Total_IP_len')

    def analyze_ttl(self):
        ttl_data = self.ip_data[['IP_ttl']].dropna()
        
        plt.figure(figsize=(12, 6))
        ttl_data['IP_ttl'].plot(kind='hist', bins=50, color='skyblue', edgecolor='black')
        plt.title('Distribution of TTL Values')
        plt.xlabel('TTL Value')
        plt.ylabel('Frequency')
        plt.grid(True)
        plt.show()
        

        return ttl_data
    
    def visualize_ip_communication_graph(self): 
        network = nx.from_pandas_edgelist(
            self.ip_data, 
            source='IP_src', 
            target='IP_dst', 
            edge_attr='IP_proto'
        )

        pos = nx.spring_layout(network, seed=42)
        
        edge_x = []
        edge_y = []
        edge_text = []
        for edge in network.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.append(x0)
            edge_x.append(x1)
            edge_y.append(y0)
            edge_y.append(y1)
            edge_text.append(network[edge[0]][edge[1]]['IP_proto'])

        edge_trace = go.Scatter(
            x=edge_x, 
            y=edge_y,
            mode='lines',   
            line=dict(width=0.5, color='#888'),
            hoverinfo='none'
        )

        edge_text_trace = go.Scatter(
            x=[(x0 + x1) / 2 for x0, x1 in zip(edge_x[::2], edge_x[1::2])],   
            y=[(y0 + y1) / 2 for y0, y1 in zip(edge_y[::2], edge_y[1::2])],  
            mode='text',   
            text=edge_text,  
            textposition='middle center', 
            textfont=dict(size=10, color='red'),   
            hoverinfo='none'
        )

        node_x = []
        node_y = []
        for node in network.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)

        node_trace = go.Scatter(
            x=node_x, 
            y=node_y,
            mode='markers+text',
            text=[node for node in network.nodes()],
            textposition='top center',
            marker=dict(size=10, color='#007ACC', line=dict(width=2, color='black')),
            hoverinfo='text'
        )

        fig = go.Figure(data=[edge_trace, edge_text_trace, node_trace],
                        layout=go.Layout(
                            title='IP Communication Graph',
                            showlegend=False,
                            hovermode='closest',
                            xaxis=dict(showgrid=False, zeroline=False),
                            yaxis=dict(showgrid=False, zeroline=False)
                        ))

        fig.show()

    def ip_frequency_analysis(self):
        ip_src_counts = self.ip_data['IP_src'].value_counts()
        ip_dst_counts = self.ip_data['IP_dst'].value_counts()

        plt.figure(figsize=(10, 6))
        ip_src_counts.plot(kind='bar', color='lightcoral', alpha=0.7)
        plt.title('Source IP Address Frequency')
        plt.xlabel('IP Address')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')  
        plt.tight_layout()
        plt.show()

        plt.figure(figsize=(10, 6))
        ip_dst_counts.plot(kind='bar', color='lightblue', alpha=0.7)
        plt.title('Destination IP Address Frequency')
        plt.xlabel('IP Address')
        plt.ylabel('Count')
        plt.xticks(rotation=45, ha='right')  
        plt.tight_layout()
        plt.show()

        ip_src_df = ip_src_counts.reset_index()
        ip_src_df.columns = ['IP_src', 'Count']  

        ip_dst_df = ip_dst_counts.reset_index()
        ip_dst_df.columns = ['IP_dst', 'Count']  

        return ip_src_df, ip_dst_df

    def ip_pair_analysis(self, top_n=10):
        pair_counts = self.ip_data.groupby(['IP_src', 'IP_dst']).size().reset_index(name='count')
        
        pair_counts['IP_pair'] = pair_counts['IP_src'] + ' -> ' + pair_counts['IP_dst']
        
        top_pairs = pair_counts.sort_values(by='count', ascending=False).head(top_n)
        
        plt.figure(figsize=(14, 10))
        bars = plt.bar(top_pairs['IP_pair'], top_pairs['count'], color='seagreen', alpha=0.7)
        plt.title(f'Top {top_n} Source-Destination IP Address Pairs')
        plt.xlabel('Source and Destination IP Address Pair')
        plt.ylabel('Count')

        plt.xticks(rotation=45, ha='right' , fontsize=9) 
        plt.tight_layout()  
        
        plt.show()

        return pair_counts

class TransportAnalyzer:
    def __init__(self , data) -> None:
        self.tcp_data = data[['IP_src', 'IP_dst','TCP_sport', 'TCP_dport', 'TCP_flags','Timestamp']].dropna()
        self.udp_data = data[['IP_src', 'IP_dst','UDP_sport', 'UDP_dport', 'UDP_len' , 'Timestamp']].dropna()
    
    def detect_udp_port_scanning(self, std_multiplier=2):
        source_port_scan = self.udp_data.groupby(['IP_src', 'UDP_sport'])['UDP_dport'].nunique()

        # Calculate mean and standard deviation
        mean_ports = source_port_scan.mean()
        std_ports = source_port_scan.std()
        threshold = mean_ports + std_multiplier * std_ports

        # Identify source IP and source port combinations exceeding the threshold
        potential_scans = source_port_scan[source_port_scan > threshold]

        # Plot the results
        plt.figure(figsize=(12, 8))
        potential_scans.plot(kind='bar', color='orange', edgecolor='black')
        plt.axhline(threshold, color='red', linestyle='--', label=f'Threshold: {threshold:.2f} (Mean + {std_multiplier} * Std)')
        plt.title('Potential UDP Port Scanning Detection')
        plt.xlabel('Source IP and Source Port')
        plt.ylabel('Number of Unique Destination Ports')
        plt.legend()
        plt.xticks(rotation=90)  # Rotate x labels for better readability
        plt.tight_layout()
        plt.show()

    def analyze_udp_lengths(self, std_multiplier=2):
        """
        Analyze UDP packet lengths and detect outliers based on length.
        Threshold is dynamically calculated as mean + std_multiplier * standard deviation.
        """

        mean_len = self.udp_data['UDP_len'].mean()
        std_len = self.udp_data['UDP_len'].std()
        threshold = mean_len + std_multiplier * std_len

        plt.figure(figsize=(10, 6))
        self.udp_data['UDP_len'].plot(kind='hist', bins=30, color='blue', edgecolor='black' , density=True)
        plt.axvline(threshold, color='red', linestyle='--', label=f'Threshold: {threshold:.2f} (Mean + {std_multiplier} * Std)')
        plt.title('Distribution of UDP Packet Lengths')
        plt.xlabel('UDP Length')
        plt.ylabel('Frequency')
        plt.legend()
        plt.show()

        return self.udp_data[self.udp_data['UDP_len'] > threshold]
        
    def udp_port_distribution(self):
        # Plot for Source Port Distribution
        plt.figure(figsize=(12, 6))
        self.udp_data['UDP_sport'].value_counts().plot(kind='bar', color='red', edgecolor='black')
        plt.title('Source Port Distribution')
        plt.xlabel('Source Port')
        plt.ylabel('Count')        
        plt.tight_layout()
        plt.show()

        # Plot for Destination Port Distribution
        plt.figure(figsize=(12, 6))
        self.udp_data['UDP_dport'].value_counts().plot(kind='bar', color='red', edgecolor='black')
        plt.title('Destination Port Distribution')
        plt.xlabel('Destination Port')
        plt.ylabel('Count')


        plt.tight_layout()
        plt.show()

    def tcp_flags_distribution(self):
        flag_counts = self.tcp_data['TCP_flags'].value_counts()

        plt.figure(figsize=(12, 6))
        flag_counts.plot(kind='bar', color='purple', edgecolor='black')
        plt.title('TCP Flag Distribution')
        plt.xlabel('TCP Flags')
        plt.ylabel('Count')
        plt.show()

    def tcp_port_distribution(self):
        # Plot for Source Port Distribution
        plt.figure(figsize=(12, 6))
        self.tcp_data['TCP_sport'].value_counts().plot(kind='bar', color='red', edgecolor='black')
        plt.title('Source Port Distribution')
        plt.xlabel('Source Port')
        plt.ylabel('Count')        
        plt.tight_layout()
        plt.show()

        # Plot for Destination Port Distribution
        plt.figure(figsize=(12, 6))
        self.tcp_data['TCP_dport'].value_counts().plot(kind='bar', color='red', edgecolor='black')
        plt.title('Destination Port Distribution')
        plt.xlabel('Destination Port')
        plt.ylabel('Count')


        plt.tight_layout()
        plt.show()

    def detect_unusual_port_activity(self, num_std_dev=3):

        port_activity = self.tcp_data.groupby('TCP_dport').size()

        mean_activity = port_activity.mean()
        std_dev_activity = port_activity.std()
        threshold = mean_activity + (num_std_dev * std_dev_activity)
        

        # Find ports with activity above the threshold
        unusual_ports = port_activity[port_activity > threshold]

        # Plot the unusual port activity
        plt.figure(figsize=(10, 6))
        unusual_ports.plot(kind='bar', color='orange', edgecolor='black')
        plt.axhline(threshold, color='red', linestyle='--', label=f'Threshold: {threshold:.2f}')
        plt.title('Unusual Port Activity')
        plt.xlabel('Destination Port')
        plt.ylabel('Number of Packets')
        plt.legend()
        plt.show()

        if not unusual_ports.empty:
            return unusual_ports

    def analyze_ip_to_port_communication(self):

        ip_port_communication = self.tcp_data.groupby(['IP_src', 'TCP_dport']).size().unstack(fill_value=0)

        # Plot a heatmap of communication
        plt.figure(figsize=(12, 8))
        plt.imshow(ip_port_communication, cmap='viridis', aspect='auto')
        plt.colorbar(label='Number of Packets')
        plt.title('IP-to-Port Communication Heatmap')
        plt.xlabel('Destination Port')
        plt.ylabel('Source IP')
        plt.xticks(ticks=range(len(ip_port_communication.columns)), labels=ip_port_communication.columns, rotation=90)
        plt.yticks(ticks=range(len(ip_port_communication.index)), labels=ip_port_communication.index)
        plt.tight_layout()
        plt.show()