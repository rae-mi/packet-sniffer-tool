from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol
        if proto == 6:  # TCP
            protocol = "TCP"
        elif proto == 17:  # UDP
            protocol = "UDP"
        else:
            protocol = str(proto)

        # Display the packet information
        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst} | Protocol: {protocol}")

        # Display the payload if available
        if protocol == "TCP" and TCP in packet:
            print(f"Payload: {bytes(packet[TCP].payload)}")
        elif protocol == "UDP" and UDP in packet:
            print(f"Payload: {bytes(packet[UDP].payload)}")

def main():
    print("Starting packet sniffer...")
    # Start sniffing packets
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
