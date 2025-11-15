from scapy.all import *
import os

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        with open("captured_packets.log", "a") as log_file:
            log_file.write(f"{ip_layer.src} -> {ip_layer.dst}\n")
            
def start_sniffing(interface=None, proto=None, srcIP=None, dstIP=None):
    print("[*] Starting packet sniffing...")
    if proto or srcIP or dstIP:
        filters = []
        if proto:
            filters.append(proto)
        if srcIP:
            filters.append(f"src host {srcIP}")
        if dstIP:
            filters.append(f"dst host {dstIP}")
        filter_str = " and ".join(filters)
        print(f"[*] Using filter: {filter_str}")
        sniff(filter=filter_str, prn=packet_callback, iface=interface, store=0)
    sniff(prn=packet_callback, iface=interface, store=0)

if __name__ == "__main__":
    print(get_if_list())
    interface = input("Enter the network interface to sniff on (leave blank for default): ")
    interface = interface if interface else None
    proto = input("Enter protocol to filter (tcp/udp/icmp) or leave blank for all: ").lower()
    proto = proto if proto in ['tcp', 'udp', 'icmp'] else None
    srcIP = input("Enter source IP to filter (leave blank for all): ")
    dstIP = input("Enter destination IP to filter (leave blank for all): ")
    start_sniffing(interface, proto, srcIP, dstIP)
    