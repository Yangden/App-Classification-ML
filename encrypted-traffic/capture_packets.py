import pyshark
import csv
import signal
import sys
from datetime import datetime

# Output files
pcap_file = f"./pcap/captured_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
csv_file = f"./sni/server_name_info_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

# Initialize CSV file and write header
with open(csv_file, mode="w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(
        [
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Server Name",
        ]
    )

# Global running flag
running = True


def process_packet(packet):
    """
    Process each captured packet for QUIC, TLS, and IPSec.
    """
    try:
        # Extract packet details
        src_ip, src_port, dst_ip, dst_port, protocol, server_name = (
            None,
            None,
            None,
            None,
            None,
            None,
        )

        # Handle QUIC packets
        if "QUIC" in packet:
            protocol = "QUIC"
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
            print("QUIC Packet Detected")

            # Check for TLS handshake within QUIC for SNI
            if hasattr(packet.quic, "tls_handshake_extensions_server_name"):
                server_name = packet.quic.tls_handshake_extensions_server_name
                print(f"QUIC Server Name Found: {server_name}")
                save_to_csv(src_ip, src_port, dst_ip, dst_port, protocol, server_name)
            else:
                print("No Server Name Found in QUIC Packet")

        # Handle TLS packets
        if "TLS" in packet:
            protocol = "TLS"
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            print("TLS Packet Detected")

            # Check for SNI in TLS handshake
            if hasattr(packet.tls, "handshake_extensions_server_name"):
                server_name = packet.tls.handshake_extensions_server_name
                print(f"TLS Server Name Found: {server_name}")
                save_to_csv(src_ip, src_port, dst_ip, dst_port, protocol, server_name)
            else:
                print("No Server Name Found in TLS Packet")

        # Handle IPSec packets (ESP)
        if "ESP" in packet:  # ESP is the Encapsulating Security Payload for IPSec
            protocol = "IPSec (ESP)"
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            print("IPSec Packet Detected")
            server_name = "N/A"  # IPSec does not carry SNI-like information
            save_to_csv(src_ip, None, dst_ip, None, protocol, server_name)

    except AttributeError as e:
        print(f"AttributeError: {e}")


def save_to_csv(src_ip, src_port, dst_ip, dst_port, protocol, server_name):
    """
    Save the extracted information to the CSV file.
    """
    with open(csv_file, mode="a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([src_ip, src_port, dst_ip, dst_port, protocol, server_name])


def stop_capture(sig, frame):
    """
    Signal handler to stop the capture and exit gracefully.
    """
    global running
    print("\nStopping capture...")
    running = False
    print(f"Captured packets saved to {pcap_file}.")
    print(f"Server name details saved to {csv_file}.")
    sys.exit(0)


# Capture QUIC, TLS, and IPSec packets
capture_filter = "udp port 443 or tcp port 443 or proto 50"  # QUIC, TLS, and IPSec
capture = pyshark.LiveCapture(
    interface="en0",
    bpf_filter=capture_filter,
    output_file=pcap_file,  # Automatically save packets to PCAP
)

# Attach signal handler for Ctrl+C
signal.signal(signal.SIGINT, stop_capture)

print("Starting packet capture... Press Ctrl+C to stop.")
while running:
    try:
        for packet in capture.sniff_continuously(packet_count=0):
            process_packet(packet)
    except Exception as e:
        print(f"Error during capture: {e}")
