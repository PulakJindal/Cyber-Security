from scapy.all import *
import sqlite3
import argparse
import threading
import time

count = 0
def packet_callback(packet):
    global count
    count += 1
    #print(f"[{count}]"+packet.summary())
    print(f"[{count}] New Packet: {packet[0][1]} / {packet[Raw].load if packet.haslayer(Raw) else None}")
    # if packet.haslayer(DNS):
    #     count += 1
    #     ip_layer = packet.getlayer(DNS)
    #     print(f"{count}[+] New DNS Packet: {ip_layer.summary()}")
    #     print(f"{count}[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
    #     with open("captured_packets.csv", "a") as log_file:
    #         log_file.write(f"{ip_layer.src} -> {ip_layer.dst}\n")
    # else:
    #     print(f"{count}[+] New Packet: Non-IP Packet")
    #     other_layer = packet.getlayer(0)
    #     with open("captured_packets.csv", "a") as log_file:
    #         log_file.write(f"Non-IP Packet: {other_layer.summary()}\n")
            
def start_sniffing(interface=None, filter=None, cnt=0):
    print("[*] Starting packet sniffing...")
    sniff(count=int(cnt), prn=packet_callback, iface=interface)

def dbCreation():
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

def main():
    parser = argparse.ArgumentParser(
        prog = sniffer.py,
        description="Network Packet Sniffer"
        )
    
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on",
        type=str,
        )
    
    parser.add_argument(
        "-p", "--protocol",
        help="Protocol to filter (tcp/udp/icmp)",
        choices = ['tcp', 'udp', 'icmp', 'arp', 'tsl', 'http', 'https'],
        type=str,
        )
    
    parser.add_argument(
        "-sip", "--src_IP",
        help="Source IP to filter",
        type=str,
        )
    
    parser.add_argument(
        "-dip", "--dst_IP",
        help="Destination IP to filter",
        type=str,
        )
    
    parser.add_argument(
        "-c", "--count",
        help="Number of packets to capture (0 for unlimited)",
        type=int,
        default=0,
        )
    
    parser.add_argument(
        "-s", "--save",
        help="Save captured packets to database",
        type=bool,
        default=False,
    )
    
    parser.add_argument(
        "-dp", "--dst_port",
        help="Destination Port to filter",
        type=int,
    )
    
    parser.add_argument(
        "-sp", "--sr_port",
        help="Source Port to filter",
        type=int,
    )
    
    parser.add_argument(
        "-t", "--timeout",
        help="Duration to run the sniffer (in seconds)",
        type=int,
    )
    
    parser.add_argument(
        "-op", "--opend_socket",
        help="Open a raw socket for packet capturing",
        type=bool,
        default=False,
    )
    
    args = parser.parse_args()
    
    filters = []

    if args.src_ip:
        filters.append(f"src host {args.src_ip}")
    if args.dst_ip:
        filters.append(f"dst host {args.dst_ip}")
    if args.src_port:
        filters.append(f"src port {args.src_port}")
    if args.dst_port:
        filters.append(f"dst port {args.dst_port}")
    if args.protocol:
        filters.append(f"proto {args.protocol}")

    bpf_filter = " and ".join(filters) if filters else None

    if args.save:
        dbCreation()
    
    if args.timeout:
        sniff_thread = threading.Thread(target=start_sniffing, args=(args.interface, bpf_filter, args.count))
        sniff_thread.start()
        time.sleep(args.timeout)
        print("[*] Timeout reached, stopping sniffing...")
        # Note: Stopping sniffing gracefully is complex; this is a placeholder.
        
if __name__ == "__main__":
    main()
    
    
    