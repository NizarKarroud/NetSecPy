import pandas as pd
from scapy.all import rdpcap, Packet

# # Path to your .pcap file
# pcap_file = 'saved.pcap'

# # Read the .pcap file
# packets = rdpcap(pcap_file)

# Function to extract fields from a layer and store them in a dictionary
def extract_fields(layer, prefix=''):
    fields_dict = {}
    if isinstance(layer, Packet):
        for field_name in layer.fields_desc:
            field_value = getattr(layer, field_name.name, None)
            # Use prefix to maintain layer hierarchy in dictionary keys
            fields_dict[prefix + field_name.name] = field_value
    return fields_dict

# Function to recursively extract fields from each layer and flatten the dictionary
def extract_packet_fields(pkt):
    fields_dict = {}
    layer = pkt
    while layer:
        layer_name = layer.__class__.__name__
        # Extract fields from the current layer
        layer_fields = extract_fields(layer, prefix=layer_name + '_')
        fields_dict.update(layer_fields)
        # Move to the next layer
        layer = layer.payload
        if not isinstance(layer, Packet):
            break
    return fields_dict

# Convert packet fields to DataFrame
def packet_to_dataframe(packet):
    fields_dict = extract_packet_fields(packet)
    # Create a DataFrame from the dictionary
    df = pd.DataFrame([fields_dict])
    return df

def packet_to_data(packets):
    packet_dataframes = []
    for packet in packets:
        df = packet_to_dataframe(packet)
        packet_dataframes.append(df)
    return pd.concat(packet_dataframes, ignore_index=True)

# print(packet_to_data(packets))

# print(packet[IP_PROTOS.d.get(packet[IP].proto ,packet[IP].proto ).upper()])
