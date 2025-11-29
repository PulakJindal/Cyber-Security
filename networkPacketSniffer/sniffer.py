from scapy.all import *
import sqlite3
import argparse
import threading
import time
import queue
from collections import deque, namedtuple
from dataclasses import dataclass, field
import curses
import socket

PacketInfo = namedtuple("PacketInfo", ["ts", "summary", "src", "sport", "dst", "dport", "proto", "raw"])
packet_dqueue = deque(maxlen=1000)   
connection_table = {}

@dataclass
class ConnectionState:
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    state: str = "NEW"

def update_connection(pkt: PacketInfo):

    end1 = (pkt.src, pkt.sport)
    end2 = (pkt.dst, pkt.dport)

    if end1 <= end2:
        key = PacketInfo(pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.proto)
    else:
        key = PacketInfo(pkt.dst, pkt.dport, pkt.src, pkt.sport, pkt.proto)

    if key not in connection_table:
        connection_table[key] = ConnectionState()

    conn = connection_table[key]

    # Update stats
    conn.packet_count += 1
    conn.byte_count += len(pkt.raw)
    conn.last_seen = pkt.ts

    # TCP state tracking
    if pkt.proto == "TCP":
        flags = pkt.raw.sprintf("%TCP.flags%")
        if "S" in flags and "A" not in flags:
            conn.state = "SYN_SENT"
        elif "SA" in flags:
            conn.state = "ESTABLISHED"
        elif "F" in flags:
            conn.state = "FIN_WAIT"
        elif "R" in flags:
            conn.state = "RESET"
    elif pkt.proto == "UDP":
        if conn.state == "NEW":
            conn.state = "ACTIVE"

def pkt_to_info(pkt):
    ts = time.time()
    proto = None
    src = dst = sport = dport = None
    raw = None
    try:
        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            if TCP in pkt:
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                proto = ip.proto
            raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else None
        elif Ether in pkt:
            # Non-IP, show simple summary
            proto = "ETH"
            src = pkt[Ether].src
            dst = pkt[Ether].dst
        summary = pkt.summary()
    except Exception as e:
        # defensive
        summary = f"parse_error: {e}"
    return PacketInfo(ts=ts, summary=summary, src=src, sport=sport, dst=dst, dport=dport, proto=proto, raw=raw)

def packet_callback(packet):
    pktinfo = pkt_to_info(packet)
    # put into general UI queue
    try:
        packet_dqueue.put(pktinfo, block=False)
    except queue.Full:
        pass
    # add to connection structures
    update_connection(pktinfo)

def start_sniffing(interface=None, filter=None, cnt=0, openedSocket=False):
    print("[*] Starting packet sniffing...")
    sniff(count=int(cnt), prn=packet_callback, iface=interface, opened_socket=openedSocket, filter=filter)

def user_interaction():
    while True:
        cmd = input("Enter command (stats/stop/filter): ").strip().lower()
        if cmd == "stats":
            print("Showing stats...")
        elif cmd == "stop":
            print("Stopping sniffing...")
            break
        elif cmd.startswith("filter"):
            print(f"Changing filter to: {cmd.split(' ', 1)[1]}")
        else:
            print("Unknown command")

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

def dbInsertion():
    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()
    while True:
        time.sleep(5)
        # Placeholder for actual packet insertion logic
        # Example:
        # cursor.execute("INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, raw_data) VALUES (?, ?, ?, ?, ?, ?)", (timestamp, src_ip, dst_ip, protocol, length, raw_data))
        conn.commit()

def functionCaller(interface=None, filter=None, cnt=0, openedSocket=False, toSave=False):
    if toSave:
        dbCreation()
    start_sniffing(interface, filter, cnt, openedSocket)
    if toSave:
        dbInset_thread = threading.Thread(target=dbInsertion, daemon=True)
        dbInset_thread.start()

def parsesAndFilter():
    parser = argparse.ArgumentParser(
        prog = "sniffer.py",
        description="Network Packet Sniffer"
        )
    
    parser.add_argument(
        "-i", "--interface",
        default=get_if_list()[0],
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
        filters.append(f"src host {args.src_IP}")
    if args.dst_ip:
        filters.append(f"dst host {args.dst_IP}")
    if args.src_port:
        filters.append(f"src port {args.src_port}")
    if args.dst_port:
        filters.append(f"dst port {args.dst_port}")
    if args.protocol:
        filters.append(f"proto {args.protocol}")

    bpf_filter = " and ".join(filters) if filters else None
    
    return bpf_filter, args.timeout, args.interface, args.count, args.opend_socket, args.save
    

def main():
    
    bpf_filter, timeout, interface, count, opend_socket, save = parsesAndFilter()
    
    if timeout:
        sniff_thread = threading.Thread(target=functionCaller, args=(interface, bpf_filter, count, opend_socket, save))
        sniff_thread.start()
        time.sleep(timeout)
        print("[*] Timeout reached, stopping sniffing...")
    
    else:
        sniff_thread = threading.Thread(target=functionCaller, args=(interface, bpf_filter, count, opend_socket, save))
        sniff_thread.start()
        
    ui_thread = threading.Thread(target=user_interaction, deamon=True)

    sniff_thread.start()
    ui_thread.start()

    sniff_thread.join()
    ui_thread.join()
        
if __name__ == "__main__":
    main()
    
    
    