from scapy.all import *
from scapy.arch.windows import get_windows_if_list
import sqlite3
import argparse
import threading
import time
import queue
from collections import deque, namedtuple
from dataclasses import dataclass, field
import curses
import platform
import logging
from datetime import datetime
import socket

# ---------------- WINDOWS NIC DETECTION ----------------
def get_active_windows_nic():
    try:
        interfaces = get_windows_if_list()
    except Exception:
        return None

    bad_keywords = [
        "virtual", "vmware", "hyper-v", "loopback", "bluetooth", "npcap",
        "wan miniport", "tunneling", "wifi direct", "kernel debug",
        "ndis", "lightweight filter", "wfp", "native wifi", "virtualbox", "vpn"
    ]

    # prefer interface used for default route
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = None

    candidates = []
    for iface in interfaces:
        name = iface.get("name", "").lower()
        desc = iface.get("description", "").lower()

        if any(b in name or b in desc for b in bad_keywords):
            continue

        ips = iface.get("ips", [])
        ipv4 = next((ip for ip in ips if "." in ip and not ip.startswith("169.254.")), None)
        if not ipv4:
            continue

        if local_ip and ipv4 == local_ip:
            return iface
        candidates.append(iface)

    if candidates:
        return candidates[0]
    return None


def scapy_npf_name(iface):
    guid = iface.get("guid", "").strip("{}")
    return f"\\Device\\NPF_{{{guid}}}"

def build_npf_map():
    npf_map = {}
    try:
        for iface in get_windows_if_list():
            guid = iface.get("guid", "").strip("{}")
            if not guid:
                continue
            npf = f"\\Device\\NPF_{{{guid}}}"
            npf_map[npf] = iface
    except Exception:
        pass
    return npf_map

# --- Data structures & globals ---
PacketInfo = namedtuple(
    "PacketInfo",
    ["ts", "summary", "src", "sport", "dst", "dport", "proto", "raw", "flags"]
)

packet_dqueue = deque(maxlen=5000)   # keep a larger history for detail/connection views
connection_table = {}
db_queue = queue.Queue(maxsize=10000)

data_lock = threading.Lock()  # protect packet_dqueue and connection_table

# Logging
logging.basicConfig(
    filename='sniffer_debug.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w'
)
logger = logging.getLogger(__name__)

@dataclass
class ConnectionState:
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    state: str = "NEW"

# ---------------- CONNECTION TRACKING ----------------
def update_connection(pkt: PacketInfo):
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
            elif "SA" in flags or ("S" in flags and "A" in flags):
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
                try:
                    flags = pkt.sprintf("%TCP.flags%")
                except Exception:
                    flags = None
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
    try:
        logger.info("PACKET CALLBACK CALLED")
        try:
            logger.debug(packet.summary())
        except Exception:
            logger.debug("Packet summary unavailable")
        pktinfo = pkt_to_info(packet)
        with data_lock:
            packet_dqueue.append(pktinfo)
        update_connection(pktinfo)
        try:
            db_queue.put(pktinfo, block=False)
        except queue.Full:
            # if DB queue full, drop
            pass
    except Exception as e:
        logger.error(f"Callback error: {e}", exc_info=True)

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
            """, (pkt.ts, pkt.src, pkt.dst, pkt.proto, len(pkt.raw), pkt.raw))
            conn.commit()
        except Exception:
            pass

# ---------------- SNIFFER LAUNCHER (threaded sniff) ----------------
def _sniff_thread_func(iface, bpf, count):
    params = {"prn": packet_callback, "store": False}
    if iface:
        params["iface"] = iface
    if bpf:
        params["filter"] = bpf
    if count and count > 0:
        params["count"] = count
    try:
        sniff(**params)
    except Exception as e:
        logger.error("Sniff thread error", exc_info=True)

def functionCaller(interface=None, filter=None, cnt=0, use_raw_socket=False, toSave=False):
    logger.info("Function caller function called")
    if toSave:
        dbCreation()
        threading.Thread(target=dbInsertion, daemon=True).start()

    # Validate on Windows vs NPF map
    if platform.system() == "Windows":
        try:
            npf_map = build_npf_map()
            if interface and interface not in npf_map:
                logger.warning("Requested interface not in NPF map; letting Scapy choose")
                interface = None
        except Exception:
            pass

    t = threading.Thread(target=_sniff_thread_func, args=(interface, filter, cnt), daemon=True)
    t.start()
    logger.info(f"Sniff thread started: {t}")
    return t

def stop_after_timeout(sniffer_thread, timeout):
    time.sleep(timeout)
    # daemon thread - will exit with process

# ---------------- HEXDUMP ----------------
def hexdump_bytes(b: bytes, width=16):
    lines = []
    for i in range(0, len(b), width):
        chunk = b[i:i+width]
        hex_bytes = " ".join(f"{x:02x}" for x in chunk)
        ascii_str = "".join(chr(x) if 32 <= x <= 126 else "." for x in chunk)
        lines.append((i, hex_bytes, ascii_str))
    if not lines:
        lines.append((0, "", ""))
    return lines

# ---------------- UI HELPERS ----------------
def format_conn_key(key):
    end1, end2, proto = key
    a_ip, a_port = end1
    b_ip, b_port = end2
    return f"{a_ip}:{a_port} <-> {b_ip}:{b_port} {proto or ''}"

def packets_for_connection_from_queue(q, key):
    res = []
    for p in q:
        e1 = (p.src, p.sport or 0)
        e2 = (p.dst, p.dport or 0)
        k = (min(e1, e2), max(e1, e2), p.proto)
        if k == key:
            res.append(p)
    return res

# ---------------- CURSES UI ----------------
def curses_ui_loop(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(150)

    if curses.has_colors():
        curses.start_color()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)

    # UI state
    mode = "main"  # main / packet_detail / conn_detail
    focus = "packets"  # "packets" or "connections"

    # indices are ALWAYS relative to packets_snapshot (oldest->newest) and conn_strings list
    selected_packet_idx = 0
    selected_conn_idx = 0

    # scroll offsets for visible windows
    scroll_packet = 0
    scroll_conn = 0

    # auto-follow flags; if True, follow new packets / connections
    auto_scroll_packets = True
    auto_scroll_connections = True

    detail_context = None  # ("packet", pkt) or ("conn", key)

    running = True
    while running:
        stdscr.erase()
        height, width = stdscr.getmaxyx()
        left_w = max(30, width // 3)
        right_w = width - left_w - 1

        # Snapshots
        with data_lock:
            packets_snapshot = list(packet_dqueue)  # oldest .. newest
            connections_snapshot_items = list(connection_table.items())

        # Build connection strings
        conn_strings = []
        for key, state in connections_snapshot_items:
            s = f"{format_conn_key(key)} | pkts:{state.packet_count} bytes:{state.byte_count} st:{state.state}"
            conn_strings.append((s, key, state))

        pkt_total = len(packets_snapshot)
        conn_total = len(conn_strings)

        # visible inner heights
        left_inner_h = height - 4
        right_inner_h = height - 4

        # Clamp selections
        if pkt_total == 0:
            selected_packet_idx = 0
            scroll_packet = 0
        else:
            selected_packet_idx = max(0, min(selected_packet_idx, pkt_total - 1))

        selected_conn_idx = max(0, min(selected_conn_idx, max(0, conn_total - 1)))

        # === Render different modes ===
        if mode == "packet_detail" and detail_context and detail_context[0] == "packet":
            # Left panel: show connections live (normal)
            left_title = f" Connections {len(connection_table)} "
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
                # connection scroll behavior (auto/follow logic)
                if auto_scroll_connections:
                    scroll_conn = max(0, conn_total - left_inner_h)
                else:
                    if selected_conn_idx < scroll_conn:
                        scroll_conn = selected_conn_idx
                    elif selected_conn_idx >= scroll_conn + left_inner_h:
                        scroll_conn = selected_conn_idx - left_inner_h + 1
                    scroll_conn = max(0, min(scroll_conn, max(0, conn_total - left_inner_h)))

                for i in range(scroll_conn, min(scroll_conn + left_inner_h, conn_total)):
                    line = conn_strings[i][0]
                    y = 2 + (i - scroll_conn)
                    attr = curses.A_NORMAL
                    if focus == "connections" and i == selected_conn_idx:
                        attr = curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_REVERSE
                    try:
                        stdscr.addnstr(y, 1, line[:left_w - 2], left_w - 2, attr)
                    except curses.error:
                        pass

            # Right panel: show packet detail for the chosen packet
            _, pkt = detail_context
            title = f" Packet detail - {pkt.summary} (press d to go back)"
            try:
                stdscr.addnstr(0, left_w + 2, title[:right_w - 2], right_w - 2, curses.A_BOLD)
            except curses.error:
                pass

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
                    stdscr.addnstr(y, left_w + 2, line[:right_w - 2], right_w - 2)
                except curses.error:
                    pass
                y += 1

            hexd_lines = hexdump_bytes(pkt.raw or b"", width=16)
            max_lines = height - y - 2
            for i, (offset, hex_bytes, ascii_str) in enumerate(hexd_lines[:max_lines]):
                line = f"{offset:04x}: {hex_bytes:<48}  {ascii_str}"
                try:
                    stdscr.addnstr(y + i, left_w + 2, line[:right_w - 2], right_w - 2)
                except curses.error:
                    pass

            footer = " d:back  q:quit "
            try:
                stdscr.addnstr(height - 1, 1, footer[:width - 2], width - 2, curses.A_DIM)
            except curses.error:
                pass

            stdscr.refresh()

            # key handling in packet_detail
            try:
                ch = stdscr.getch()
            except curses.error:
                ch = -1
            if ch == -1:
                continue
            if ch in (ord("d"), ord("D")):
                mode = "main"
                detail_context = None
            elif ch in (ord("q"), ord("Q")):
                return
            elif ch == ord("\t"):
                focus = "connections" if focus == "packets" else "packets"
            elif ch in (curses.KEY_UP, ord("k")):
                if focus == "packets" and pkt_total > 0:
                    selected_packet_idx = max(0, selected_packet_idx - 1)
                    auto_scroll_packets = False
                elif focus == "connections" and conn_total > 0:
                    selected_conn_idx = max(0, selected_conn_idx - 1)
                    auto_scroll_connections = False
            elif ch in (curses.KEY_DOWN, ord("j")):
                if focus == "packets" and pkt_total > 0:
                    selected_packet_idx = min(pkt_total - 1, selected_packet_idx + 1)
                    auto_scroll_packets = (selected_packet_idx == pkt_total - 1)
                elif focus == "connections" and conn_total > 0:
                    selected_conn_idx = min(conn_total - 1, selected_conn_idx + 1)
                    auto_scroll_connections = (selected_conn_idx == conn_total - 1)
            elif ch in (10, 13):
                # ENTER: allow drilling further or switching context
                if focus == "packets" and pkt_total > 0:
                    with data_lock:
                        pkt = packets_snapshot[selected_packet_idx]
                    detail_context = ("packet", pkt)
                    mode = "packet_detail"
                elif focus == "connections" and conn_total > 0:
                    _, key, _ = conn_strings[selected_conn_idx]
                    detail_context = ("conn", key)
                    mode = "conn_detail"
            continue  # refresh

        if mode == "conn_detail" and detail_context and detail_context[0] == "conn":
            key = detail_context[1]
            # Left panel: filtered packets for selected connection (live)
            with data_lock:
                pkts_for_conn = packets_for_connection_from_queue(packet_dqueue, key)

            left_title = f" Connection: {format_conn_key(key)} (filtered) "
            try:
                stdscr.addnstr(1, 1, left_title[:left_w - 2], left_w - 2, curses.A_BOLD)
            except curses.error:
                pass

            total_conn_pkts = len(pkts_for_conn)
            if total_conn_pkts == 0:
                try:
                    stdscr.addnstr(3, 1, "(no packets for this connection yet)", left_w - 2)
                except curses.error:
                    pass
            else:
                # show last left_inner_h packets
                start = max(0, total_conn_pkts - left_inner_h)
                display_list = pkts_for_conn[start:]
                for i, p in enumerate(display_list):
                    y = 2 + i
                    line = f"{time.strftime('%H:%M:%S', time.localtime(p.ts))} {p.summary}"
                    try:
                        stdscr.addnstr(y, 1, line[:left_w - 2], left_w - 2)
                    except curses.error:
                        pass

            # Right panel: show ALL packets live with scroll logic
            right_title = " Packets (recent at bottom) "
            try:
                stdscr.addnstr(1, left_w + 2, right_title, right_w - 2, curses.A_BOLD)
            except curses.error:
                pass

            # Packet scroll logic (auto-follow unless user scrolled)
            if pkt_total <= right_inner_h:
                pkt_start = 0
                pkt_end = pkt_total
                scroll_packet = 0
                auto_scroll_packets = True
            else:
                if auto_scroll_packets:
                    pkt_start = pkt_total - right_inner_h
                else:
                    if selected_packet_idx < scroll_packet:
                        scroll_packet = selected_packet_idx
                    elif selected_packet_idx >= scroll_packet + right_inner_h:
                        scroll_packet = selected_packet_idx - right_inner_h + 1
                    # clamp
                    scroll_packet = max(0, min(scroll_packet, pkt_total - right_inner_h))
                    pkt_start = scroll_packet
                pkt_end = min(pkt_start + right_inner_h, pkt_total)

            for idx_display, idx in enumerate(range(pkt_start, pkt_end)):
                pkt = packets_snapshot[idx]
                display_line = f"{time.strftime('%H:%M:%S', time.localtime(pkt.ts))} {pkt.summary}"
                y = 2 + idx_display
                attr = curses.A_NORMAL
                if focus == "packets" and idx == selected_packet_idx:
                    attr = curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_REVERSE
                try:
                    stdscr.addnstr(y, left_w + 2, display_line[:right_w - 2], right_w - 2, attr)
                except curses.error:
                    pass

            footer = " d:back  q:quit "
            try:
                stdscr.addnstr(height - 1, 1, footer[:width - 2], width - 2, curses.A_DIM)
            except curses.error:
                pass

            stdscr.refresh()

            # keys in conn_detail
            try:
                ch = stdscr.getch()
            except curses.error:
                ch = -1
            if ch == -1:
                continue
            if ch in (ord("d"), ord("D")):
                mode = "main"
                detail_context = None
            elif ch in (ord("q"), ord("Q")):
                return
            elif ch == ord("\t"):
                focus = "connections" if focus == "packets" else "packets"
                if focus == "connections":
                    auto_scroll_connections = False
            elif ch in (curses.KEY_UP, ord("k")):
                if focus == "packets" and pkt_total > 0:
                    selected_packet_idx = max(0, selected_packet_idx - 1)
                    auto_scroll_packets = False
                elif focus == "connections" and conn_total > 0:
                    selected_conn_idx = max(0, selected_conn_idx - 1)
                    auto_scroll_connections = False
            elif ch in (curses.KEY_DOWN, ord("j")):
                if focus == "packets" and pkt_total > 0:
                    selected_packet_idx = min(pkt_total - 1, selected_packet_idx + 1)
                    auto_scroll_packets = (selected_packet_idx == pkt_total - 1)
                elif focus == "connections" and conn_total > 0:
                    selected_conn_idx = min(conn_total - 1, selected_conn_idx + 1)
                    auto_scroll_connections = (selected_conn_idx == conn_total - 1)
            elif ch in (10, 13):
                if focus == "packets" and pkt_total > 0:
                    with data_lock:
                        pkt = packets_snapshot[selected_packet_idx]
                    detail_context = ("packet", pkt)
                    mode = "packet_detail"
                elif focus == "connections" and conn_total > 0:
                    _, key2, _ = conn_strings[selected_conn_idx]
                    detail_context = ("conn", key2)
                    mode = "conn_detail"
            continue

        # === MAIN MODE: draw both panels ===
        # Left panel: connections (live)
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
            # connection scrolling behavior
            if auto_scroll_connections:
                scroll_conn = max(0, conn_total - left_inner_h)
            else:
                if selected_conn_idx < scroll_conn:
                    scroll_conn = selected_conn_idx
                elif selected_conn_idx >= scroll_conn + left_inner_h:
                    scroll_conn = selected_conn_idx - left_inner_h + 1
                scroll_conn = max(0, min(scroll_conn, max(0, conn_total - left_inner_h)))

            for i in range(scroll_conn, min(scroll_conn + left_inner_h, conn_total)):
                line = conn_strings[i][0]
                y = 2 + (i - scroll_conn)
                attr = curses.A_NORMAL
                if focus == "connections" and i == selected_conn_idx:
                    attr = curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_REVERSE
                try:
                    stdscr.addnstr(y, 1, line[:left_w - 2], left_w - 2, attr)
                except curses.error:
                    pass

        # Right panel: packets (recent at bottom) with scroll + auto-follow logic
        right_title = " Packets (recent at bottom) "
        try:
            stdscr.addnstr(1, left_w + 2, right_title, right_w - 2, curses.A_BOLD)
        except curses.error:
            pass

        # compute view window for packets
        if pkt_total <= right_inner_h:
            pkt_start = 0
            pkt_end = pkt_total
            scroll_packet = 0
            auto_scroll_packets = True
        else:
            visible_h = right_inner_h
            if auto_scroll_packets:
                pkt_start = pkt_total - visible_h
            else:
                # ensure selection visible
                if selected_packet_idx < scroll_packet:
                    scroll_packet = selected_packet_idx
                elif selected_packet_idx >= scroll_packet + visible_h:
                    scroll_packet = selected_packet_idx - visible_h + 1
                scroll_packet = max(0, min(scroll_packet, pkt_total - visible_h))
                pkt_start = scroll_packet
            pkt_end = min(pkt_start + visible_h, pkt_total)

        # render packets
        for idx_display, idx in enumerate(range(pkt_start, pkt_end)):
            pkt = packets_snapshot[idx]
            display_line = f"{time.strftime('%H:%M:%S', time.localtime(pkt.ts))} {pkt.summary}"
            y = 2 + idx_display
            attr = curses.A_NORMAL
            if focus == "packets" and idx == selected_packet_idx and mode == "main":
                attr = curses.color_pair(1) | curses.A_BOLD if curses.has_colors() else curses.A_REVERSE
            try:
                stdscr.addnstr(y, left_w + 2, display_line[:right_w - 2], right_w - 2, attr)
            except curses.error:
                pass

        # footer
        footer = " ↑/↓:navigate  TAB:switch  ENTER:open  d:back  q:quit "
        try:
            stdscr.addnstr(height - 1, 1, footer[:width - 2], width - 2, curses.A_DIM)
        except curses.error:
            pass

        stdscr.refresh()

        # === key handling for main mode ===
        try:
            ch = stdscr.getch()
        except curses.error:
            ch = -1
        if ch == -1:
            continue

        if ch == ord("\t"):
            focus = "connections" if focus == "packets" else "packets"
            # switching focus means user is interacting; disable auto-follow on the other list
            if focus == "connections":
                auto_scroll_packets = False
            else:
                auto_scroll_connections = False

        elif ch in (ord("q"), ord("Q")):
            running = False
            break

        elif ch in (curses.KEY_UP, ord("k")):
            if focus == "packets" and pkt_total > 0:
                selected_packet_idx = max(0, selected_packet_idx - 1)
                auto_scroll_packets = False
            elif focus == "connections" and conn_total > 0:
                selected_conn_idx = max(0, selected_conn_idx - 1)
                auto_scroll_connections = False

        elif ch in (curses.KEY_DOWN, ord("j")):
            if focus == "packets" and pkt_total > 0:
                selected_packet_idx = min(pkt_total - 1, selected_packet_idx + 1)
                auto_scroll_packets = (selected_packet_idx == pkt_total - 1)
            elif focus == "connections" and conn_total > 0:
                selected_conn_idx = min(conn_total - 1, selected_conn_idx + 1)
                auto_scroll_connections = (selected_conn_idx == conn_total - 1)

        elif ch in (10, 13):  # ENTER
            if focus == "packets" and pkt_total > 0:
                with data_lock:
                    pkt = packets_snapshot[selected_packet_idx]
                detail_context = ("packet", pkt)
                mode = "packet_detail"
            elif focus == "connections" and conn_total > 0:
                _, key, _ = conn_strings[selected_conn_idx]
                detail_context = ("conn", key)
                mode = "conn_detail"

        elif ch == ord("r"):
            # manual refresh noop; snapshots are auto-updated
            pass

    # end while
    return

# ---------------- ARG PARSER ----------------
def parsesAndFilter():
    print("[*] Parsing arguments...")
    if platform.system() == "Windows":
        active_nic = get_active_windows_nic()
        if active_nic:
            default_interface = scapy_npf_name(active_nic)
            print(f"[*] Auto-selected NIC: {active_nic.get('name')} -> {default_interface}")
        else:
            print("[!] No active NIC found! Falling back to Scapy's list.")
            try:
                default_interface = get_if_list()[0]
            except Exception:
                default_interface = None
    else:
        try:
            default_interface = get_if_list()[0]
        except Exception:
            default_interface = None

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", default=default_interface, help="Network interface to sniff on")
    parser.add_argument("-p", "--protocol")
    parser.add_argument("-sip", "--src_IP")
    parser.add_argument("-dip", "--dst_IP")
    parser.add_argument("-c", "--count", type=int, default=0)
    parser.add_argument("-s", "--save", action="store_true")
    parser.add_argument("-dp", "--dst_port", type=int)
    parser.add_argument("-sp", "--src_port", type=int)
    parser.add_argument("-t", "--timeout", type=int)
    parser.add_argument("--raw_socket", action="store_true", help="Use raw L2 socket (Linux only)")
    parser.add_argument("--list", action="store_true", help="List all interfaces and exit")

    args = parser.parse_args()

    if args.list:
        try:
            for x in get_windows_if_list():
                print(x)
        except Exception:
            print(get_if_list())
        exit(0)

    filters = []
    if args.src_IP: filters.append(f"src host {args.src_IP}")
    if args.dst_IP: filters.append(f"dst host {args.dst_IP}")
    if args.src_port: filters.append(f"src port {args.src_port}")
    if args.dst_port: filters.append(f"dst port {args.dst_port}")
    if args.protocol:
        proto = args.protocol.lower()
        if proto in ['tcp', 'udp', 'icmp']:
            filters.append(proto)
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
            try:
                print("[*] Available interfaces:", get_windows_if_list())
            except Exception:
                pass
            return

        # Normalize double-escaped CLI backslashes
        if platform.system() == "Windows" and interface:
            interface = interface.replace('\\\\', '\\')

        print(f"[*] Using interface: {interface}")
        print("[*] Starting packet capture...")
        print(f"[*] Debug log will be written to: sniffer_debug.log")

        if platform.system() == "Windows":
            print("[!] IMPORTANT: On Windows, run as Administrator and ensure Npcap is installed.")
            try:
                npf_map = build_npf_map()
                print(f"[*] Available NPF interfaces: {list(npf_map.keys())[:8]} (truncated)")
            except Exception:
                pass

        logger.info("Starting main sniffer...")
        sniffer_thread = functionCaller(interface, bpf_filter, count, raw_socket, save)

        print("[*] Waiting for packets...")

        if timeout:
            threading.Thread(target=lambda: stop_after_timeout(sniffer_thread, timeout), daemon=True).start()

        try:
            curses.wrapper(curses_ui_loop)
        except KeyboardInterrupt:
            pass
        finally:
            # daemon sniff thread ends with process
            time.sleep(0.2)
            print("Sniffer stopped. Exiting.")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
