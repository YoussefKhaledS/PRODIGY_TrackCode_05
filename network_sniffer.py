from scapy.all import sniff, IP, TCP, UDP


def packet_handler(packet):
    source_ip = packet[IP].src
    distination_ip = packet[IP].dst
    protocol = packet[IP].proto
    if TCP in packet:
        protocol = "TCP"
    if UDP in packet:
        protocol = "UDP"

    payload = packet.payload
    print(
        f"Source IP: {source_ip}, Distination IP: {distination_ip}, Protocol: {protocol}, Payload: {payload}")


def main():
    sniff(prn=packet_handler, store=0)


main()
