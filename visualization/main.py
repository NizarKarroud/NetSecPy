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
        # Create network graph
        network = nx.from_pandas_edgelist(
            self.ether_data, 
            source='Ether_src', 
            target='Ether_dst', 
            edge_attr='Ether_type'
        )

        # Define positions for nodes
        pos = nx.spring_layout(network, seed=42)
        
        # Create edge trace for the network graph
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
            # Get the protocol for the edge
            edge_text.append(network[edge[0]][edge[1]]['Ether_type'])

        # Edge trace
        edge_trace = go.Scatter(
            x=edge_x, 
            y=edge_y,
            mode='lines',  # Draw lines for edges
            line=dict(width=0.5, color='#888'),
            hoverinfo='none'
        )

        # Edge text trace
        edge_text_trace = go.Scatter(
            x=[(x0 + x1) / 2 for x0, x1 in zip(edge_x[::2], edge_x[1::2])],  # Midpoints of edges
            y=[(y0 + y1) / 2 for y0, y1 in zip(edge_y[::2], edge_y[1::2])],  # Midpoints of edges
            mode='text',  # Display text
            text=edge_text,  # Edge labels
            textposition='middle center', 
            textfont=dict(size=10, color='red'),  # Text styling
            hoverinfo='none'
        )

        # Create node trace
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

        # Create figure and plot
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
        # Group by source and destination MAC addresses, and count occurrences
        pair_counts = self.ether_data.groupby(['Ether_src', 'Ether_dst']).size().reset_index(name='count')
        
        # Create a new column that combines source and destination MAC addresses
        pair_counts['MAC_pair'] = pair_counts['Ether_src'] + ' -> ' + pair_counts['Ether_dst']
        
        # Sort and select the top N pairs
        top_pairs = pair_counts.sort_values(by='count', ascending=False).head(10)
        
        # Plot all pairs, but limit the display to the top N
        plt.figure(figsize=(14, 10))
        bars = plt.bar(top_pairs['MAC_pair'], top_pairs['count'], color='seagreen', alpha=0.7)
        plt.title(f'Top {10} Source-Destination MAC Address Pairs')
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

        ether_type_counts_df = ether_type_counts.reset_index()
        ether_type_counts_df.columns = ['Ether_type', 'Count']

        return ether_type_counts_df

    def detect_arp_scanning(self):
        try:
            # Filter for ARP packets with opcode 1 (ARP Request)
            arp_requests = self.arp_data[self.arp_data['ARP_op'] == 1]

            # Drop rows with invalid timestamps
            arp_requests = arp_requests.dropna(subset=['Timestamp'])

            # Ensure 'Timestamp' column is in datetime format
            arp_requests['Timestamp'] = pd.to_datetime(arp_requests['Timestamp'])

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

            return arp_request_counts

        except Exception as e:
            return None
        
    def broadcast_traffic_analysis(self):
        broadcast_dst = 'ff:ff:ff:ff:ff:ff'
        
        # Filter rows with broadcast destination address
        broadcast_packets = self.ether_data[self.ether_data['Ether_dst'] == broadcast_dst]


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

        return broadcast_packets

class IpAnalyzer:
    def __init__(self, data) -> None:
        self.ip_data = data[[field for field in list(data.columns) if field.startswith('IP_')]+["Timestamp"]].dropna()

    def monitor_high_traffic_ips(self):

        traffic_volume = self.ip_data.groupby('IP_src')['IP_len'].sum()

        # Check if traffic_volume is empty
        if traffic_volume.empty:
            print("No traffic data available for plotting.")
            return

        # Step 2: Statistical analysis to detect unusually high traffic volume
        mean_traffic = traffic_volume.mean()
        std_dev_traffic = traffic_volume.std()

        threshold = mean_traffic + 3 * std_dev_traffic

        # Step 3: Identify IP addresses with traffic volumes higher than the threshold
        high_traffic_ips = traffic_volume[traffic_volume > threshold]

        # Step 4: Plot the traffic volume for all IPs
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

        # Step 5: Plot the IPs with unusually high traffic volume
        if not high_traffic_ips.empty:
            plt.figure(figsize=(12, 8))
            high_traffic_ips.plot(kind='bar', color='salmon', alpha=0.7)
            plt.title('High Traffic Volume per Source IP')
            plt.xlabel('Source IP')
            plt.ylabel('Traffic Volume (Bytes)')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            plt.show()
        else:
            print("No IPs detected with unusually high traffic volume.")

        # Return IPs with high traffic
        return traffic_volume.to_frame(name='Total_IP_len')

    def analyze_ttl(self):
        ttl_data = self.ip_data[['IP_ttl']].dropna()
        
        # Plot TTL distribution
        plt.figure(figsize=(12, 6))
        ttl_data['IP_ttl'].plot(kind='hist', bins=50, color='skyblue', edgecolor='black')
        plt.title('Distribution of TTL Values')
        plt.xlabel('TTL Value')
        plt.ylabel('Frequency')
        plt.grid(True)
        plt.show()
        
        # Basic statistics
        mean_ttl = ttl_data['IP_ttl'].mean()
        std_dev_ttl = ttl_data['IP_ttl'].std()
        print(f"Mean TTL: {mean_ttl:.2f}")
        print(f"Standard Deviation of TTL: {std_dev_ttl:.2f}")

        return ttl_data
    
    def visualize_ip_communication_graph(self): 
        # Create network graph
        network = nx.from_pandas_edgelist(
            self.ip_data, 
            source='IP_src', 
            target='IP_dst', 
            edge_attr='IP_proto'
        )

        # Define positions for nodes
        pos = nx.spring_layout(network, seed=42)
        
        # Create edge trace for the network graph
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
            # Get the protocol for the edge
            edge_text.append(network[edge[0]][edge[1]]['IP_proto'])

        # Edge trace
        edge_trace = go.Scatter(
            x=edge_x, 
            y=edge_y,
            mode='lines',  # Draw lines for edges
            line=dict(width=0.5, color='#888'),
            hoverinfo='none'
        )

        # Edge text trace
        edge_text_trace = go.Scatter(
            x=[(x0 + x1) / 2 for x0, x1 in zip(edge_x[::2], edge_x[1::2])],  # Midpoints of edges
            y=[(y0 + y1) / 2 for y0, y1 in zip(edge_y[::2], edge_y[1::2])],  # Midpoints of edges
            mode='text',  # Display text
            text=edge_text,  # Edge labels
            textposition='middle center', 
            textfont=dict(size=10, color='red'),  # Text styling
            hoverinfo='none'
        )

        # Create node trace
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

        # Create figure and plot
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
        # Group by source and destination IP addresses, and count occurrences
        pair_counts = self.ip_data.groupby(['IP_src', 'IP_dst']).size().reset_index(name='count')
        
        # Create a new column that combines source and destination IP addresses
        pair_counts['IP_pair'] = pair_counts['IP_src'] + ' -> ' + pair_counts['IP_dst']
        
        # Sort and select the top N pairs
        top_pairs = pair_counts.sort_values(by='count', ascending=False).head(top_n)
        
        # Plot all pairs, but limit the display to the top N
        plt.figure(figsize=(14, 10))
        bars = plt.bar(top_pairs['IP_pair'], top_pairs['count'], color='seagreen', alpha=0.7)
        plt.title(f'Top {top_n} Source-Destination IP Address Pairs')
        plt.xlabel('Source and Destination IP Address Pair')
        plt.ylabel('Count')

        # Improve x-tick labels
        plt.xticks(rotation=45, ha='right' , fontsize=9) 
        plt.tight_layout()  
        
        plt.show()

        # Return the entire dataset for further analysis if needed
        return pair_counts

