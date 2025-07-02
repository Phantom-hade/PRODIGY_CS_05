"""
Title       : Network Packet Analyzer
Author      : Larona B. Kwae
Date        : June 2025
PRODIGY_CS  : 05
Description : A packet sniffer tool that captures and analyzes network packets. 
""" 

# Import necessary functions from scapy
from scapy.all import sniff, IP, TCP, UDP, Raw

# Callback function to process each captured packet
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        print("\n=== Packet Captured ===")
        print(f"Source IP      : {src}")
        print(f"Destination IP : {dst}")
        print(f"Protocol       : {proto} ({get_protocol_name(proto)})")

        if Raw in packet:
            print(f"Payload        : {packet[Raw].load[:50]}...")  # First 50 bytes
        else:
            print("Payload        : None")

# Helper function to map protocol numbers to names
def get_protocol_name(proto_number):
    protocols = {6: "TCP", 17: "UDP", 1: "ICMP"}
    return protocols.get(proto_number, "Unknown")

# Start sniffing
print("Starting packet sniffing... Press Ctrl+C to stop.\n")
sniff(filter="ip", prn=process_packet, store=False)
