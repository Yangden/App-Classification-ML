import os
import pandas as pd
from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.record import TLS
import numpy as np
import time

# Path to the main PCAP directory
pcap_dir = "./pcap"

# CSV file containing server name info
csv_file_path = "./sni/server_name_info_20241209_153014.csv"

# Define a list of server names
server_names = [
    "facebook",
]  # Replace with your actual server names

# Initialize a list to store flow-level data
data = []

# Load server name info CSV
server_info = pd.read_csv(csv_file_path)

# Filter rows where the "Server Name" column contains any substring in the server_names list
filtered_servers = server_info[
    server_info["Server Name"].apply(
        lambda x: any(server in x for server in server_names)
    )
]

# Create a dictionary for mapping server info
server_mapping = {}
for _, row in filtered_servers.iterrows():
    matched_label = next(
        (server for server in server_names if server in row["Server Name"]), None
    )
    if matched_label:
        if matched_label not in server_mapping:
            server_mapping[matched_label] = {
                "Source_IPs": set(),
                "Destination_IPs": set(),
            }
        server_mapping[matched_label]["Source_IPs"].add(row["Source IP"])
        server_mapping[matched_label]["Destination_IPs"].add(row["Destination IP"])


# Function to create a flow key
def create_flow_key(packet):
    if packet.haslayer(TCP):
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    else:
        return None  # Non-TCP packets are not considered

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Create a tuple that uniquely identifies the flow
    return (src_ip, dst_ip, sport, dport, proto)


# Start benchmarking
start_time = time.time()

# Process each PCAP file in the ./pcap directory
for pcap_file in os.listdir(pcap_dir):
    if pcap_file.endswith(".pcap"):
        file_path = os.path.join(pcap_dir, pcap_file)
        print(f"Processing file: {pcap_file}")

        # Read the PCAP file
        packets = rdpcap(file_path, count=100000)

        # Initialize a dictionary to store flows
        flows = {}

        # Group packets into flows
        for packet in packets:
            if packet.haslayer(IP):
                flow_key = create_flow_key(packet)
                if flow_key:
                    if flow_key not in flows:
                        flows[flow_key] = []
                    flows[flow_key].append(packet)

        # Process each flow
        for flow_key, flow_packets in flows.items():
            flow_lengths = []
            encrypted_payload = b""

            for pkt in flow_packets:
                if pkt.haslayer(TCP):
                    tcp_payload = pkt[TCP].payload
                    if tcp_payload:
                        try:
                            tcp_payload = bytes(pkt[TCP].payload)
                            tls_records = TLS(tcp_payload)
                            if tls_records:
                                flow_lengths.append(len(pkt))
                                encrypted_payload += tcp_payload
                        except Exception:
                            continue  # Skip packets that cannot be dissected

            if flow_lengths:
                # Determine label based on source or destination IP
                label = None
                for mapping_label, mapping_ips in server_mapping.items():
                    if (
                        flow_key[0] in mapping_ips["Source_IPs"]
                        or flow_key[1] in mapping_ips["Destination_IPs"]
                        or flow_key[0] in mapping_ips["Destination_IPs"]
                        or flow_key[1] in mapping_ips["Source_IPs"]
                    ):
                        label = mapping_label
                        break

                if label:
                    # Compute packet length distribution (percentiles)
                    percentiles = np.percentile(
                        flow_lengths, [10, 20, 30, 40, 50, 60, 70, 80, 90]
                    )
                    min_length = min(flow_lengths)
                    max_length = max(flow_lengths)
                    mean_length = np.mean(flow_lengths)
                    stddev_length = np.std(flow_lengths)
                    variance_length = np.var(flow_lengths)

                    # Add flow-level data to the dataset
                    data.append(
                        {
                            "Source_IP": flow_key[0],
                            "Destination_IP": flow_key[1],
                            "Percentile_10": percentiles[0],
                            "Percentile_20": percentiles[1],
                            "Percentile_30": percentiles[2],
                            "Percentile_40": percentiles[3],
                            "Percentile_50": percentiles[4],
                            "Percentile_60": percentiles[5],
                            "Percentile_70": percentiles[6],
                            "Percentile_80": percentiles[7],
                            "Percentile_90": percentiles[8],
                            "Min_Length": min_length,
                            "Max_Length": max_length,
                            "Mean_Length": mean_length,
                            "StdDev_Length": stddev_length,
                            "Variance_Length": variance_length,
                            "Encrypted_Flow_Payload": encrypted_payload.hex(),
                            "Label": label,  # Add label based on server info
                        }
                    )

# Save to CSV
df = pd.DataFrame(data)
output_file = "labeled_tls_flows_features.csv"
df.to_csv(output_file, index=False)

end_time = time.time()
elapsed_time = end_time - start_time

print(f"Features saved to {output_file}")
print(f"Time taken for processing: {elapsed_time:.2f} seconds")
