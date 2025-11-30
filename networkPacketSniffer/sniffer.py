from scapy.all import *
from scapy.sendrecv import AsyncSniffer
import sqlite3
import argparse
import threading
import time
import queue
from collections import deque, namedtuple
from dataclasses import dataclass, field
import curses
import socket
import platform

PacketInfo = namedtuple("PacketInfo", ["ts", "summary", "src", "sport", "dst", "dport", "proto", "raw", "flags"])
packet_dqueue = deque(maxlen=1000)   
connection_table = {}
db_queue = queue.Queue(maxsize=5000)
data_lock = threading.Lock()  # Thread safety for UI + sniffer

@dataclass
class ConnectionState:
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    state: str = "NEW"

def update_connection(pkt: PacketInfo):
    if pkt.src is None or pkt.dst is None:
        return

    end1 = (pkt.src, pkt.sport or 0)
    end2 = (pkt.dst, pkt.dport or 0)

    key = (min(end1, end2), max(end1, end2), pkt.proto)

    with data_lock:
        if key not in connection_table:
            connection_table[key] = ConnectionState()

        conn = connection_table[key]

        # Update stats
        conn.packet_count += 1
        conn.byte_count += len(pkt.raw or b"")
        conn.last_seen = pkt.ts

        # TCP state tracking
        if pkt.proto == "TCP":
            flags = pkt.flags or ""
            if "S" in flags and "A" not in flags:
                conn.state = "SYN_SENT"
            elif "SA" in flags or ("S" in flags and "A" in flags):
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
    raw = b""
    flags = None
    try:
        if IP in pkt:
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            if TCP in pkt:
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                try:
                    flags = pkt.sprintf("%TCP.flags%")
                except Exception:
                    flags = None
            elif UDP in pkt:
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                proto = ip.proto
            raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        elif Ether in pkt:
            # Non-IP, show simple summary
            proto = "ETH"
            src = pkt[Ether].src
            dst = pkt[Ether].dst
        summary = pkt.summary()
    except Exception as e:
        # defensive
        summary = f"parse_error: {e}"
    return PacketInfo(ts=ts, summary=summary, src=src, sport=sport, dst=dst, dport=dport, proto=proto, raw=raw, flags=flags)

def packet_callback(packet):
    try:
        pktinfo = pkt_to_info(packet)
        with data_lock:
            packet_dqueue.append(pktinfo)
        # Now pass PacketInfo (not the raw scapy packet)
        update_connection(pktinfo)
        try:
            db_queue.put(pktinfo, block=False)
        except queue.Full:
            # drop if DB queue is full
            pass
    except Exception as e:
        print(f"[!] Error in packet_callback: {e}")

def start_sniffing(interface=None, filter=None, cnt=0, openedSocket=False):
    print("[*] Starting packet sniffing...")
    sniff(count=int(cnt), prn=packet_callback, iface=interface, opened_socket=openedSocket, filter=filter)

def stop_after_timeout(sniffer, timeout):
    time.sleep(timeout)
    print("[*] Timeout reached, stopping sniffer...")
    sniffer.stop()

def curses_ui_loop(stdscr):
    curses.curs_set(0)  # hide cursor
    stdscr.nodelay(True)  # make getch non-blocking
    stdscr.timeout(150)  # refresh every 150ms

    # Colors (if available)
    if curses.has_colors():
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)   # focused bar
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK) # headings

    mode = "main"
    focus = "packets"
    selected_packet = 0
    selected_conn = 0
    scroll_packet = 0
    scroll_conn = 0

    detail_context = None
    running = True

    while running:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        left_w = max(30, width // 3)
        right_w = width - left_w - 1

        # draw vertical separator
        for y in range(height):
            try:
                stdscr.addch(y, left_w, curses.ACS_VLINE)
            except curses.error:
                pass

        # header
        header = " Sniffer - TAB switch panels - ENTER to open - d to back - q to quit "
        try:
            stdscr.addnstr(0, 1, header, width - 2, curses.color_pair(2) if curses.has_colors() else curses.A_BOLD)
        except curses.error:
            pass

        # take snapshots under lock
        with data_lock:
            packets_snapshot = list(packet_dqueue)
            connections_snapshot_items = list(connection_table.items())

        # Build connection display strings
        conn_strings = []
        for key, state in connections_snapshot_items:
            end1, end2, proto = key
            a_ip, a_port = end1
            b_ip, b_port = end2
            conn_str = f"{a_ip}:{a_port} <-> {b_ip}:{b_port} {proto or ''}"
            s = f"{conn_str} | pkts:{state.packet_count} bytes:{state.byte_count} st:{state.state}"
            conn_strings.append((s, key, state))

        pkt_total = len(packets_snapshot)
        conn_total = len(conn_strings)

        if selected_packet >= max(1, pkt_total):
            selected_packet = max(0, pkt_total - 1)
        if selected_conn >= max(1, conn_total):
            selected_conn = max(0, conn_total - 1)

        left_inner_h = height - 3
        right_inner_h = height - 3

        # Left panel: connections
        left_title = " Connections "
        try:
            stdscr.addnstr(1, 1, left_title, left_w - 2, curses.A_BOLD)
        except curses.error:
            pass

        if conn_total == 0:
            try:
                stdscr.addnstr(3, 1, "(no connections yet)", left_w - 2)
            except curses.error:
                pass
        else:
            if selected_conn < scroll_conn:
                scroll_conn = selected_conn
            elif selected_conn >= scroll_conn + left_inner_h:
                scroll_conn = selected_conn - left_inner_h + 1

            for i in range(scroll_conn, min(scroll_conn + left_inner_h, conn_total)):
                line = conn_strings[i][0]
                y = 2 + (i - scroll_conn)
                text = line[:left_w - 2]
                attr = curses.A_NORMAL
                if focus == "connections" and i == selected_conn and mode == "main":
                    attr = curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_REVERSE
                try:
                    stdscr.addnstr(y, 1, text, left_w - 2, attr)
                except curses.error:
                    pass

        # Right panel: packets
        right_title = " Packets (recent at bottom) "
        try:
            stdscr.addnstr(1, left_w + 2, right_title, right_w - 2, curses.A_BOLD)
        except curses.error:
            pass

        if pkt_total <= right_inner_h:
            pkt_start = 0
            pkt_end = pkt_total
        else:
            if selected_packet < pkt_total - right_inner_h:
                pkt_start = max(0, selected_packet - (right_inner_h // 2))
                if pkt_start + right_inner_h > pkt_total:
                    pkt_start = pkt_total - right_inner_h
            else:
                pkt_start = pkt_total - right_inner_h
            pkt_end = pkt_start + right_inner_h

        if pkt_total == 0:
            try:
                stdscr.addnstr(3, left_w + 2, "(no packets yet)", right_w - 2)
            except curses.error:
                pass
        else:
            for idx_display, idx in enumerate(range(pkt_start, pkt_end)):
                pkt = packets_snapshot[idx]
                display_line = f"{time.strftime('%H:%M:%S', time.localtime(pkt.ts))} {pkt.summary}"
                y = 2 + idx_display
                attr = curses.A_NORMAL
                if focus == "packets" and idx == selected_packet and mode == "main":
                    attr = curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_REVERSE
                try:
                    stdscr.addnstr(y, left_w + 2, display_line, right_w - 2, attr)
                except curses.error:
                    pass

        # footer
        footer = " ↑/↓:navigate  TAB:switch  ENTER:open  d:back  q:quit "
        try:
            stdscr.addnstr(height - 1, 1, footer[:width-2], width - 2, curses.A_DIM)
        except curses.error:
            pass

        stdscr.refresh()

        # handle keys
        try:
            ch = stdscr.getch()
        except curses.error:
            ch = -1

        if ch == -1:
            continue

        if ch == ord("\t"):
            if mode == "main":
                focus = "connections" if focus == "packets" else "packets"
        elif ch in (ord("q"), ord("Q")):
            running = False
            break
        elif mode == "main" and ch in (curses.KEY_UP, ord("k")):
            if focus == "packets" and pkt_total > 0:
                selected_packet = max(0, selected_packet - 1)
            elif focus == "connections" and conn_total > 0:
                selected_conn = max(0, selected_conn - 1)
        elif mode == "main" and ch in (curses.KEY_DOWN, ord("j")):
            if focus == "packets" and pkt_total > 0:
                selected_packet = min(pkt_total - 1, selected_packet + 1)
            elif focus == "connections" and conn_total > 0:
                selected_conn = min(conn_total - 1, selected_conn + 1)
        elif ch in (curses.KEY_ENTER, 10, 13):
            if mode == "main":
                if focus == "packets" and pkt_total > 0:
                    pkt = packets_snapshot[selected_packet]
                    detail_context = ("packet", pkt)
                    mode = "detail"
                elif focus == "connections" and conn_total > 0:
                    _, key, _ = conn_strings[selected_conn]
                    detail_context = ("conn", key)
                    mode = "detail"
        elif mode == "detail" and (ch == ord("d") or ch == ord("D")):
            mode = "main"
            detail_context = None

        # Detail view rendering
        if mode == "detail" and detail_context:
            stdscr.erase()
            dtype, data = detail_context
            if dtype == "packet":
                pkt = data
                title = f" Packet detail - {pkt.summary} (press d to go back)"
                stdscr.addnstr(0, 1, title[:width-2], width-2, curses.A_BOLD)
                info_lines = [
                    f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt.ts))}",
                    f"Proto: {pkt.proto}",
                    f"From: {pkt.src}:{pkt.sport}",
                    f"To  : {pkt.dst}:{pkt.dport}",
                    f"Flags: {pkt.flags or ''}",
                    f"Length: {len(pkt.raw or b'')}",
                ]
                y = 1
                for line in info_lines:
                    try:
                        stdscr.addnstr(y, 1, line[:width-2], width-2)
                    except curses.error:
                        pass
                    y += 1
            stdscr.refresh()
            continue

    return

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
        pkt = db_queue.get()  # BLOCKS until packet arrives

        cursor.execute("""
            INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, raw_data)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            pkt.ts, pkt.src, pkt.dst, pkt.proto, len(pkt.raw), pkt.raw
        ))
        conn.commit()

def functionCaller(interface=None, filter=None, cnt=0, openedSocket=False, toSave=False):
    print(f"[*] Starting sniffer on interface: {interface}")
    print(f"[*] Filter: {filter if filter else 'None'}")
    print(f"[*] Count: {cnt if cnt > 0 else 'Unlimited'}")
    
    if toSave:
        dbCreation()
        threading.Thread(target=dbInsertion, daemon=True).start()

    try:
        # On Windows, openedSocket should be False unless on Linux
        if openedSocket and platform.system() != "Linux":
            print("[!] Raw socket mode not supported on Windows, ignoring...")
            openedSocket = False

        sniffer = AsyncSniffer(
            iface=interface,
            filter=filter,
            count=cnt,
            prn=packet_callback,
            opened_socket=openedSocket if openedSocket else None
        )
        sniffer.start()
        print("[*] Sniffer started successfully!")
        return sniffer
    except Exception as e:
        print(f"[!] Error starting sniffer: {e}")
        print("[!] Make sure you have:")
        print("    1. Administrator privileges (required on Windows)")
        print("    2. Npcap or WinPcap installed (on Windows)")
        print("    3. A valid network interface")
        raise

def parsesAndFilter():
    # Get available interfaces
    try:
        interfaces = get_if_list()
        default_interface = interfaces[0] if interfaces else None
        if not default_interface:
            print("[!] Warning: No network interfaces found!")
    except Exception as e:
        print(f"[!] Warning: Could not get interface list: {e}")
        default_interface = None
    
    parser = argparse.ArgumentParser(
        prog = "sniffer.py",
        description="Network Packet Sniffer"
        )
    
    parser.add_argument(
        "-i", "--interface",
        default=default_interface,
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
        "-sp", "--src_port",
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

    if args.src_IP:
        filters.append(f"src host {args.src_IP}")
    if args.dst_IP:
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
    try:
        bpf_filter, timeout, interface, count, opend_socket, save = parsesAndFilter()
        
        if not interface:
            print("[!] Error: No network interface specified or available!")
            print("[*] Available interfaces:", get_if_list())
            return

        print(f"[*] Using interface: {interface}")
        print("[*] Starting packet capture...")
        print("[*] Note: On Windows, you need Administrator privileges!")

        # Start sniffer in background
        sniffer = functionCaller(interface, bpf_filter, count, opend_socket, save)

        # Give sniffer a moment to start
        time.sleep(0.5)

        # If timeout exists, wait for it in a small helper thread
        if timeout:
            threading.Thread(target=lambda: stop_after_timeout(sniffer, timeout), daemon=True).start()

        # Now start the curses UI (runs in main thread)
        curses.wrapper(curses_ui_loop)

        # When UI exits, stop sniffer
        sniffer.stop()
        print("Sniffer stopped. Exiting...")
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        
if __name__ == "__main__":
    main()
    
    
    