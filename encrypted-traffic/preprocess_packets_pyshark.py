import os
import pandas as pd
import numpy as np
import pyshark
import time

# Path to the main PCAP directory
pcap_dir = "./pcap"

# Initialize a list to store flow-level data
data = []


# Function to create a flow key
def create_flow_key(packet):
    """
    Create a unique flow key based on source/destination IPs and ports.
    """
    try:
        proto = packet.transport_layer  # TCP/UDP
        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        sport = packet[packet.transport_layer].srcport
        dport = packet[packet.transport_layer].dstport

        # Create a tuple that uniquely identifies the flow
        return (src_ip, dst_ip, sport, dport, proto)
    except AttributeError:
        return None  # Non-IP or non-TCP/UDP packets are ignored


# Start benchmarking
start_time = time.time()

# Process each folder and its PCAP files
for app_name in os.listdir(pcap_dir):
    app_folder = os.path.join(pcap_dir, app_name)
    if os.path.isdir(app_folder):  # Check if it's a folder
        print(f"Processing application: {app_name}")
        for pcap_file in os.listdir(app_folder):
            if pcap_file.endswith(".pcap"):
                file_path = os.path.join(app_folder, pcap_file)
                print(f"  Processing file: {pcap_file}")

                # Read the PCAP file using PyShark
                packets = pyshark.FileCapture(
                    file_path, keep_packets=False, include_raw=False, use_ek=True
                )

                # Initialize a dictionary to store flows
                flows = {}

                # Group packets into flows
                for packet in packets:
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
                        if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "payload"):
                            try:
                                tcp_payload = bytes.fromhex(
                                    pkt.tcp.payload.replace(":", "")
                                )
                                flow_lengths.append(len(tcp_payload))
                                encrypted_payload += tcp_payload
                            except Exception:
                                continue  # Skip packets that cannot be processed

                    if flow_lengths:
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
                                "Label": app_name,  # Add label from folder name
                            }
                        )

                # Close the pyshark FileCapture instance
                packets.close()

# Save to CSV
df = pd.DataFrame(data)
output_file = "all_tls_flows_features_with_stats_pyshark.csv"
df.to_csv(output_file, index=False)

end_time = time.time()
elapsed_time = end_time - start_time

print(f"Features saved to {output_file}")
print(f"Time taken for processing using PyShark: {elapsed_time:.2f} seconds")
