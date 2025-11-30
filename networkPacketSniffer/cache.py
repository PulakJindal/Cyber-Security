#!/usr/bin/env python3
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

# --- Data structures & globals ---
PacketInfo = namedtuple(
    "PacketInfo",
    ["ts", "summary", "src", "sport", "dst", "dport", "proto", "raw", "flags"]
)

packet_dqueue = deque(maxlen=1000)
connection_table = {}
db_queue = queue.Queue(maxsize=5000)

data_lock = threading.Lock()  # UI + sniffer safe access

@dataclass
class ConnectionState:
    
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    state: str = "NEW"

# ---------------- CONNECTION TRACKING ----------------
def update_connection(pkt: PacketInfo):
    print("Update connection function called.")
    if pkt.src is None or pkt.dst is None:
        return

    end1 = (pkt.src, pkt.sport or 0)
    end2 = (pkt.dst, pkt.dport or 0)
    key = (min(end1, end2), max(end1, end2), pkt.proto)

    with data_lock:
        if key not in connection_table:
            connection_table[key] = ConnectionState(first_seen=pkt.ts, last_seen=pkt.ts)
        conn = connection_table[key]
        conn.packet_count += 1
        conn.byte_count += len(pkt.raw or b"")
        conn.last_seen = pkt.ts

        if pkt.proto == "TCP":
            flags = pkt.flags or ""
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


# ---------------- PACKET PARSING ----------------
def pkt_to_info(pkt):
    print("Packet info function called")
    ts = time.time()
    proto = None
    src = dst = sport = dport = None
    raw = b""
    flags = None
    try:
        if IP in pkt:
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
            if TCP in pkt:
                proto = "TCP"
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                flags = pkt.sprintf("%TCP.flags%")
            elif UDP in pkt:
                proto = "UDP"
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
            else:
                proto = str(ip.proto)

            raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

        elif Ether in pkt:
            proto = "ETH"
            src, dst = pkt[Ether].src, pkt[Ether].dst

        summary = pkt.summary()

    except Exception as e:
        summary = f"parse_error: {e}"

    return PacketInfo(ts, summary, src, sport, dst, dport, proto, raw, flags)

# ---------------- CALLBACK ----------------
def packet_callback(packet):
    pktinfo = pkt_to_info(packet)
    
    print("Packet callback function called.")
    print("[+] Packet received:", pktinfo.summary)

    with data_lock:
        packet_dqueue.append(pktinfo)

    update_connection(pktinfo)

    try:
        db_queue.put(pktinfo, block=False)
    except queue.Full:
        pass


# ---------------- DB THREAD ----------------
def dbCreation():
    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
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
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON packets(timestamp)")
    conn.commit()
    conn.close()

def dbInsertion():
    conn = sqlite3.connect("packets.db")
    cursor = conn.cursor()
    while True:
        pkt = db_queue.get()
        try:
            cursor.execute("""
                INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, length, raw_data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                pkt.ts, pkt.src, pkt.dst, pkt.proto, len(pkt.raw), pkt.raw
            ))
            conn.commit()
        except Exception:
            pass


# ---------------- OS-INDEPENDENT SOCKET LOGIC ----------------
def get_os_safe_socket(interface, use_raw_socket):
    print("Os safe socket")
    """
    Windows/macOS → return None  
    Linux + use_raw_socket=True → return L2socket  
    """
    if not use_raw_socket:
        return None

    if platform.system() != "Linux":
        print("[!] Raw socket mode ignored: not supported on this OS.")
        return None

    # Linux only:
    try:
        s = conf.L2socket(iface=interface)
        print("[*] Using Linux raw L2 socket...")
        return s
    except Exception as e:
        print(f"[!] Failed to open raw L2 socket: {e}")
        return None


# ---------------- SNIFFER LAUNCHER ----------------
def functionCaller(interface=None, filter=None, cnt=0, use_raw_socket=False, toSave=False):
    print("Function caller function called")
    print(f"[*] Starting sniffer on interface: {interface}")
    print(f"[*] Filter: {filter if filter else 'None'}")
    print(f"[*] Count: {cnt if cnt > 0 else 'Unlimited'}")
    
    if toSave:
        dbCreation()
        threading.Thread(target=dbInsertion, daemon=True).start()

    opened_sock = get_os_safe_socket(interface, use_raw_socket)

    try:
        if opened_sock:
            if filter : 
                sniffer = AsyncSniffer(
                    iface=interface,
                    filter=filter,
                    count=cnt,
                    prn=packet_callback,
                    opened_socket=opened_sock
                )
            else : 
                sniffer = AsyncSniffer(
                    iface=interface,
                    count=cnt,
                    prn=packet_callback,
                    opened_socket=opened_sock
                )
        else:
            if filter : 
                sniffer = AsyncSniffer(
                    iface=interface,
                    filter=filter,
                    count=cnt,
                    prn=packet_callback
                )
            else : 
                print("Creating sniffer without filter")
                sniffer = AsyncSniffer(
                    iface=interface,
                    count=cnt,
                    prn=packet_callback
                )

        sniffer.start()
        print("[*] Sniffer started successfully!")
        # Give it a moment to initialize
        time.sleep(0.3)
        return sniffer
    except Exception as e:
        print(f"[!] ERROR starting sniffer: {e}")
        print("[!] Common issues on Windows:")
        print("    1. Need Administrator privileges - run as admin!")
        print("    2. Need Npcap or WinPcap installed")
        print("    3. Interface might be invalid")
        print(f"[*] Available interfaces: {get_if_list()}")
        raise


def stop_after_timeout(sniffer, timeout):
    print("Stop after timeout function")
    time.sleep(timeout)
    print("[*] Timeout reached, stopping sniffer...")
    try:
        sniffer.stop()
    except:
        pass


# ---------------- HEXDUMP ----------------
def hexdump_bytes(b: bytes, width=16):
    print("Hexdump function")
    lines = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hex_bytes = " ".join(f"{x:02x}" for x in chunk)
        ascii_str = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        lines.append((i, hex_bytes, ascii_str))
    if not lines:
        lines.append((0, "", ""))
    return lines


# ---------------- CURSES UI ----------------
def format_conn_key(key):
    print("Format connection key called.")
    # key = ((ip1, port1), (ip2, port2), proto)
    end1, end2, proto = key
    a_ip, a_port = end1
    b_ip, b_port = end2
    return f"{a_ip}:{a_port} <-> {b_ip}:{b_port} {proto or ''}"

def curses_ui_loop(stdscr):
    print("Curses UI loop function")
    curses.curs_set(0)  # hide cursor
    stdscr.nodelay(True)  # make getch non-blocking
    stdscr.timeout(150)  # refresh every 150ms

    # Colors (if available)
    if curses.has_colors():
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)   # focused bar
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK) # headings

    mode = "main"  # or "detail"
    focus = "packets"  # or "connections"
    selected_packet = 0
    selected_conn = 0
    scroll_packet = 0  # offset from top of visible packet list
    scroll_conn = 0

    detail_context = None  # ("packet", pktinfo) or ("conn", key)
    running = True

    while running:
        # print("1 Entered first while running loop")             #debuging purpose
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        # layout columns
        left_w = max(30, width // 3)  # left slightly smaller
        right_w = width - left_w - 1

        # print("2 left and right",left_w, right_w)             #debuging purpose

        # draw vertical separator
        for y in range(height):
            try:
                stdscr.addch(y, left_w, curses.ACS_VLINE)
            except curses.error:
                pass

        # header
        header = " Sniffer - TAB switch panels - ENTER to open - d to back - q to quit "
        try:
            stdscr.addnstr(0, 1, header, width - 2, curses.color_pair(2))
        except curses.error:
            pass

        # take snapshots under lock
        with data_lock:
            # print("3 data lock acquired for snapshots")             #debuging purpose
            
            packets_snapshot = list(packet_dqueue)  # oldest .. newest (left->right)
            connections_snapshot_items = list(connection_table.items())  # list of (key, state)

        # Build connection display strings
        conn_strings = []
        for key, state in connections_snapshot_items:
            
            # print("4 In connections snapshot items loop")             #debuging purpose
            
            s = f"{format_conn_key(key)} | pkts:{state.packet_count} bytes:{state.byte_count} st:{state.state}"
            conn_strings.append((s, key, state))

        # Packets: we want most recent at bottom on screen, but list is oldest..newest.
        # We'll display from start_index..end_index
        pkt_total = len(packets_snapshot)
        conn_total = len(conn_strings)

        # Ensure selected indices are valid
        if selected_packet >= max(1, pkt_total):
            selected_packet = max(0, pkt_total - 1)
        if selected_conn >= max(1, conn_total):
            selected_conn = max(0, conn_total - 1)

        # visible area calculation
        left_inner_h = height - 3  # leave 2 lines for footer/header
        right_inner_h = height - 3

        # Left panel: connections
        left_title = " Connections "
        try:
            stdscr.addnstr(1, 1, left_title, left_w - 2, curses.A_BOLD)
        except curses.error:
            pass

        # Draw connection items (scrolling)
        if conn_total == 0:
            try:
                stdscr.addnstr(3, 1, "(no connections yet)", left_w - 2)
            except curses.error:
                pass
        else:
            # ensure scroll_conn correct
            if selected_conn < scroll_conn:
                scroll_conn = selected_conn
            elif selected_conn >= scroll_conn + left_inner_h:
                scroll_conn = selected_conn - left_inner_h + 1

            for i in range(scroll_conn, min(scroll_conn + left_inner_h, conn_total)):
                
                # print("In connections display loop")             #debuging purpose
                
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

        # Determine packet window slice
        # We'll show last right_inner_h packets unless user scrolled up
        if pkt_total <= right_inner_h:
            pkt_start = 0
            pkt_end = pkt_total
        else:
            # default view shows last right_inner_h items
            # but selected_packet indexes into packets_snapshot
            # if selected_packet is near bottom, keep it visible
            if selected_packet < pkt_total - right_inner_h:
                # If user moved selection above bottom, we adjust start so selected visible
                pkt_start = max(0, selected_packet - (right_inner_h // 2))
                if pkt_start + right_inner_h > pkt_total:
                    pkt_start = pkt_total - right_inner_h
            else:
                pkt_start = pkt_total - right_inner_h
            pkt_end = pkt_start + right_inner_h

        # ensure selected_packet in [pkt_start, pkt_end)
        if pkt_total == 0:
            try:
                stdscr.addnstr(3, left_w + 2, "(no packets yet)", right_w - 2)
            except curses.error:
                pass
        else:
            for idx_display, idx in enumerate(range(pkt_start, pkt_end)):
                
                # print("In packets display loop")             #debuging purpose
                
                pkt = packets_snapshot[idx]
                display_line = f"{time.strftime('%H:%M:%S', time.localtime(pkt.ts))} {pkt.summary}"
                # show most recent at bottom visually — but we are drawing top->bottom
                y = 2 + idx_display
                attr = curses.A_NORMAL
                if focus == "packets" and idx == selected_packet and mode == "main":
                    attr = curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_REVERSE
                # truncate to right_w - 2
                try:
                    stdscr.addnstr(y, left_w + 2, display_line, right_w - 2, attr)
                except curses.error:
                    pass

        # footer / help
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
            # no input, loop
            continue

        # Normalize keys
        if ch == ord("\t"):  # TAB
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
        elif ch in (curses.KEY_ENTER, 10, 13):  # ENTER
            if mode == "main":
                if focus == "packets" and pkt_total > 0:
                    # open packet detail
                    with data_lock:
                        pkt = packets_snapshot[selected_packet]
                    detail_context = ("packet", pkt)
                    mode = "detail"
                elif focus == "connections" and conn_total > 0:
                    # open connection detail - show packets for this connection
                    _, key, _ = conn_strings[selected_conn]
                    detail_context = ("conn", key)
                    mode = "detail"
        elif mode == "detail" and (ch == ord("d") or ch == ord("D")):
            # go back to main
            mode = "main"
            detail_context = None
        elif mode == "main" and ch == ord("r"):
            # manual refresh: we simply loop and snapshots will update
            pass
        # end key handling

        # Detail view rendering if mode == "detail"
        if mode == "detail" and detail_context:
            stdscr.erase()
            # whole screen used for detail
            dtype, data = detail_context
            if dtype == "packet":
                pkt = data
                # header
                title = f" Packet detail - {pkt.summary} (press d to go back)"
                stdscr.addnstr(0, 1, title[:width-2], width-2, curses.A_BOLD)
                # basic info lines
                info_lines = [
                    f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt.ts))}",
                    f"Proto: {pkt.proto}",
                    f"From: {pkt.src}:{pkt.sport}",
                    f"To  : {pkt.dst}:{pkt.dport}",
                    f"Flags: {pkt.flags or ''}",
                    f"Length: {len(pkt.raw or b'')}",
                    "",
                    "Raw (hex + ASCII):"
                ]
                y = 1
                for line in info_lines:
                    try:
                        stdscr.addnstr(y, 1, line[:width-2], width-2)
                    except curses.error:
                        pass
                    y += 1

                # hex dump area: build lines
                hexd_lines = hexdump_bytes(pkt.raw or b"", width=16)
                # Start printing from y .. bottom-2
                max_lines = height - y - 2
                for i, (offset, hex_bytes, ascii_str) in enumerate(hexd_lines[:max_lines]):
                    left = f"{offset:04x}: "
                    # format hex into groups of two chars and pad
                    hex_display = " ".join(hex_bytes[i:i+2*2] for i in range(0, len(hex_bytes), 2)) if hex_bytes else ""
                    # simpler: print hex_bytes split into pairs with spacing every 8 bytes
                    # We'll just print the raw hex_bytes and ascii_str truncated appropriately
                    line = f"{left}{hex_bytes:<48}  {ascii_str}"
                    try:
                        stdscr.addnstr(y + i, 1, line[:width-2], width-2)
                    except curses.error:
                        pass

            elif dtype == "conn":
                key = data
                with data_lock:
                    state = connection_table.get(key)
                    # collect packets that match this connection from packet_dqueue
                    pkts_for_conn = []
                    for p in packet_dqueue:
                        e1 = (p.src, p.sport or 0)
                        e2 = (p.dst, p.dport or 0)
                        k = (min(e1, e2), max(e1, e2), p.proto)
                        if k == key:
                            pkts_for_conn.append(p)

                title = f" Connection detail - {format_conn_key(key)} (press d to go back)"
                try:
                    stdscr.addnstr(0, 1, title[:width-2], width-2, curses.A_BOLD)
                except curses.error:
                    pass
                y = 1
                conn_lines = [
                    f"First seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(state.first_seen)) if state else 'N/A'}",
                    f"Last  seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(state.last_seen)) if state else 'N/A'}",
                    f"Packets: {state.packet_count if state else 0}",
                    f"Bytes  : {state.byte_count if state else 0}",
                    f"State  : {state.state if state else 'N/A'}",
                    "",
                    "Packets for this connection (most recent last):"
                ]
                for line in conn_lines:
                    try:
                        stdscr.addnstr(y, 1, line[:width-2], width-2)
                    except curses.error:
                        pass
                    y += 1

                # list the packets (show last ~height-y)
                max_shown = height - y - 2
                start_index = max(0, len(pkts_for_conn) - max_shown)
                for i, p in enumerate(pkts_for_conn[start_index:]):
                    line = f"{time.strftime('%H:%M:%S', time.localtime(p.ts))} {p.summary}"
                    try:
                        stdscr.addnstr(y + i, 1, line[:width-2], width-2)
                    except curses.error:
                        pass

            # wait for keys in detail view (non-blocking)
            stdscr.refresh()
            # block until next keypress is processed in main loop: continue loop to read keys
            continue

    # end while running
    # When quitting, ensure we return and allow main to stop sniffer
    return


# ---------------- ARG PARSER ----------------
def parsesAndFilter():
    print("[*] Parsing arguments...")
    
    # Get available interfaces safely
    try:
        interfaces = get_if_list()
        default_interface = interfaces[0] if interfaces else None
        if not default_interface:
            print("[!] Warning: No network interfaces found!")
    except Exception as e:
        print(f"[!] Warning: Could not get interface list: {e}")
        default_interface = None
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface", default=default_interface, 
                        help="Network interface to sniff on")
    parser.add_argument("-p","--protocol")
    parser.add_argument("-sip","--src_IP")
    parser.add_argument("-dip","--dst_IP")
    parser.add_argument("-c","--count",type=int,default=0)
    parser.add_argument("-s","--save",action="store_true")
    parser.add_argument("-dp","--dst_port",type=int)
    parser.add_argument("-sp","--src_port",type=int)
    parser.add_argument("-t","--timeout",type=int)
    parser.add_argument("--raw_socket", action="store_true",
                        help="Use raw L2 socket (Linux only)")
    args = parser.parse_args()

    filters = []
    if args.src_IP: filters.append(f"src host {args.src_IP}")
    if args.dst_IP: filters.append(f"dst host {args.dst_IP}")
    if args.src_port: filters.append(f"src port {args.src_port}")
    if args.dst_port: filters.append(f"dst port {args.dst_port}")
    if args.protocol: 
        # Fix: Use proper BPF syntax (tcp, udp, icmp, not "proto tcp")
        protocol_lower = args.protocol.lower()
        if protocol_lower in ['tcp', 'udp', 'icmp']:
            filters.append(protocol_lower)
        else:
            filters.append(f"proto {args.protocol}")

    bpf = " and ".join(filters) if filters else None
    return bpf, args.timeout, args.interface, args.count, args.raw_socket, args.save


# ---------------- MAIN ----------------
def main():
    print("Main function called.")
    
    try:
        bpf_filter, timeout, interface, count, raw_socket, save = parsesAndFilter()
        
        if not interface:
            print("[!] ERROR: No network interface specified or available!")
            print(f"[*] Available interfaces: {get_if_list()}")
            return
        
        print(f"[*] Using interface: {interface}")
        print("[*] Starting packet capture...")
        if platform.system() == "Windows":
            print("[!] IMPORTANT: On Windows, you MUST run as Administrator!")
            print("[!] Also ensure Npcap or WinPcap is installed.")
        
        sniffer = functionCaller(interface, bpf_filter, count, raw_socket, save)

        if timeout:
            threading.Thread(target=lambda: stop_after_timeout(sniffer, timeout), daemon=True).start()

        try:
            curses.wrapper(curses_ui_loop)
        except KeyboardInterrupt:
            pass
        finally:
            try: 
                sniffer.stop()
            except: 
                pass
            time.sleep(0.2)
            print("Sniffer stopped. Exiting.")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
