from scapy.all import *
import sqlite3
#import os

count = 0
def packet_callback(packet):
    global count
    count += 1
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        print(f"{count}[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        # with open("captured_packets.log", "a") as log_file:
        #     log_file.write(f"{ip_layer.src} -> {ip_layer.dst}\n")
    else:
        print(f"{count}[+] New Packet: Non-IP Packet")
        packet.show()
        exit()
            
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
    conn = sqlite3.connect("packets.db")            # connect to the database
    cursor = conn.cursor()                          # create a cursor object
    cursor.execute("PRAGMA journal_mode=WAL;")      # enable WAL mode for better concurrency
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            length INTEGER,
            raw_data BLOB
        )
    """)
    conn.commit()
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)")  # Index for faster timestamp queries
    conn.commit()
    
    interface = input("Enter the network interface to sniff on (leave blank for default): ")
    interface = interface if interface else None
    proto = input("Enter protocol to filter (tcp/udp/icmp) or leave blank for all: ").lower()
    proto = proto if proto in ['tcp', 'udp', 'icmp'] else None
    srcIP = input("Enter source IP to filter (leave blank for all): ")
    dstIP = input("Enter destination IP to filter (leave blank for all): ")
    start_sniffing(interface, proto, srcIP, dstIP)
    