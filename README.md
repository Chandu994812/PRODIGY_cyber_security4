

# PRODIGY_cyber_security4



from scapy.all import sniff, IP, TCP, UDP

def packet_analyzer(packet):
    """
    Analyzes a captured network packet and displays relevant information.

    Args:
        packet (Packet): The captured network packet.
    """
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        print("=" * 50)
        print("Packet Information:")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")

        if protocol == 6:  # TCP
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
            print(f"Payload: {tcp_layer.payload}")
        elif protocol == 17:  # UDP
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            print(f"Source Port: {src_port}")
            print(f"Destination Port: {dst_port}")
            print(f"Payload: {udp_layer.payload}")
        else:
            print("Payload: N/A")
        print("=" * 50)

def start_packet_capture():
    """
    Starts the network packet capture and analysis.
    """
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(prn=packet_analyzer, store=False)

# Example usage
start_packet_capture()
