# two_pane_sniffer.py
import threading
import queue
import time
from collections import deque, namedtuple
import curses
import socket

from scapy.all import sniff, IP, TCP, UDP, Raw, Ether

# ---- Data structures ----
PacketInfo = namedtuple("PacketInfo", ["ts", "summary", "src", "sport", "dst", "dport", "proto", "raw"])

class Connection:
    def __init__(self, key):
        self.key = key            # canonical key (ipA,portA,ipB,portB,proto)
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.packets = deque(maxlen=1000)  # recent packets for this connection
        self.id = None  # will be set when added to index list

    def add_packet(self, pktinfo: PacketInfo):
        self.packets.append(pktinfo)
        self.last_seen = pktinfo.ts

# ---- Globals ----
packet_queue = queue.Queue()   # UI consumes from here to display live
connections = {}               # key -> Connection
connections_index = []         # ordered list of keys (for UI indexing)
connections_lock = threading.Lock()
selected_conn_key = None       # current UI-selected connection (None = show all)
stop_event = threading.Event()

# ---- Helpers ----
def canonical_conn_key(src, sport, dst, dport, proto):
    """
    Return canonical key so that (A:p1)->(B:p2) and (B:p2)->(A:p1) map to same conn.
    Key format: (ip1, sport1, ip2, sport2, proto) where (ip1,sport1) <= (ip2,sport2) lexicographically
    """
    a = (src, sport)
    b = (dst, dport)
    if a <= b:
        return (src, sport, dst, dport, proto)
    else:
        return (dst, dport, src, sport, proto)

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

def add_packet_to_connection(pktinfo: PacketInfo):
    if pktinfo.src is None or pktinfo.dst is None:
        # no IP layer, ignore for connection grouping (still send to general queue)
        return None
    key = canonical_conn_key(pktinfo.src, pktinfo.sport or 0, pktinfo.dst, pktinfo.dport or 0, pktinfo.proto)
    with connections_lock:
        conn = connections.get(key)
        if conn is None:
            conn = Connection(key)
            conn.id = len(connections_index)
            connections[key] = conn
            connections_index.append(key)
        conn.add_packet(pktinfo)
    return key

# ---- Scapy callback ----
def packet_callback(pkt):
    pktinfo = pkt_to_info(pkt)
    # put into general UI queue
    try:
        packet_queue.put(pktinfo, block=False)
    except queue.Full:
        pass
    # add to connection structures
    add_packet_to_connection(pktinfo)

# ---- Sniffing thread ----
def start_sniff(interface=None, bpf_filter=None, count=0, opened_socket=False):
    # Run sniff in background (daemon thread) - stop by exiting program (or eventually add stop_filter)
    sniff(prn=packet_callback, iface=interface, filter=bpf_filter, store=False, count=int(count))

# ---- Curses UI ----
def draw_ui(stdscr):
    global selected_conn_key
    curses.curs_set(0)
    stdscr.nodelay(True)  # make getch non-blocking
    height, width = stdscr.getmaxyx()
    left_w = max(30, int(width * 0.35))
    right_w = width - left_w - 1

    # windows
    left_win = curses.newwin(height - 2, left_w, 1, 0)
    right_win = curses.newwin(height - 2, right_w, 1, left_w + 1)
    status_win = curses.newwin(1, width, 0, 0)
    help_win = curses.newwin(1, width, height - 1, 0)

    conn_idx = 0  # cursor in left pane

    packets_display = deque(maxlen=500)  # store recent packets for right pane (global/all or filtered)

    while not stop_event.is_set():
        # Grab packets from queue
        try:
            while True:
                pktinfo = packet_queue.get_nowait()
                packets_display.appendleft(pktinfo)
        except queue.Empty:
            pass

        # Build left pane content (connections)
        left_win.erase()
        left_win.box()
        left_win.addstr(0, 2, " Connections ")

        with connections_lock:
            total_conns = len(connections_index)
            # compute active mark (last 60s)
            now = time.time()
            for idx, key in enumerate(connections_index):
                if idx >= height - 4:
                    break  # fit
                conn = connections.get(key)
                if conn is None:
                    continue
                a_ip, a_port, b_ip, b_port, proto = key
                last = int(now - conn.last_seen)
                active = "*" if last < 60 else " "
                highlight = curses.A_REVERSE if idx == conn_idx else curses.A_NORMAL
                label = f"{idx:2d} {active} {a_ip}:{a_port}->{b_ip}:{b_port} {proto} ({len(conn.packets)})"
                # truncate label if too long
                if len(label) > left_w - 2:
                    label = label[:left_w-5] + "..."
                left_win.addnstr(1 + idx, 1, label, left_w - 2, highlight)

        # Right pane: packets (either all or selected connection)
        right_win.erase()
        right_win.box()
        right_win.addstr(0, 2, " Packets (latest first) ")
        # determine which list to show
        if selected_conn_key is None:
            # show from packets_display (global)
            display_list = list(packets_display)[: (height - 4)]
        else:
            with connections_lock:
                conn = connections.get(selected_conn_key)
                if conn:
                    display_list = list(reversed(conn.packets))[-(height - 4):]  # show most recent at top
                    display_list = list(reversed(display_list))
                else:
                    display_list = []

        # print them
        for row, pkt in enumerate(display_list[:height - 4]):
            txt = f"{time.strftime('%H:%M:%S', time.localtime(pkt.ts))} {pkt.summary}"
            if len(txt) > right_w - 2:
                txt = txt[:right_w - 5] + "..."
            right_win.addnstr(1 + row, 1, txt, right_w - 2)

        # status & help
        status_text = f"Conns: {len(connections_index)}  Selected: {connections_index.index(selected_conn_key) if selected_conn_key in connections_index else 'All' }"
        status_win.erase()
        status_win.addnstr(0, 0, status_text, width - 1)

        help_text = "Up/Down: navigate  Enter: select/deselect  d: clear filter  q: quit"
        help_win.erase()
        help_win.addnstr(0, 0, help_text, width - 1)

        # refresh windows
        status_win.noutrefresh()
        left_win.noutrefresh()
        right_win.noutrefresh()
        help_win.noutrefresh()
        curses.doupdate()

        # handle input
        try:
            key = stdscr.getch()
            if key == curses.KEY_UP:
                conn_idx = max(0, conn_idx - 1)
            elif key == curses.KEY_DOWN:
                with connections_lock:
                    conn_idx = min(len(connections_index) - 1, conn_idx + 1) if connections_index else 0
            elif key in (curses.KEY_ENTER, 10, 13):  # Enter: select that connection as filter
                with connections_lock:
                    if 0 <= conn_idx < len(connections_index):
                        selected_conn_key = connections_index[conn_idx]
            elif key in (ord('d'), ord('D')):  # deselect / clear filter
                selected_conn_key = None
            elif key in (ord('q'), ord('Q')):
                stop_event.set()
                break
            else:
                pass
        except curses.error:
            pass

        time.sleep(0.1)

# ---- Main / runner ----
def main():
    import argparse
    parser = argparse.ArgumentParser("two_pane_sniffer")
    parser.add_argument("-i", "--interface", help="Interface to sniff on", default=None)
    parser.add_argument("-f", "--filter", help="BPF filter", default=None)
    parser.add_argument("-c", "--count", help="Number of packets (0 = unlimited)", default=0)
    args = parser.parse_args()

    sniff_thread = threading.Thread(target=start_sniff, kwargs={
        "interface": args.interface,
        "bpf_filter": args.filter,
        "count": args.count
    }, daemon=True)
    sniff_thread.start()

    try:
        curses.wrapper(draw_ui)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        stop_event.set()
        time.sleep(0.2)  # give background thread a moment
        print("Exiting...")

if __name__ == "__main__":
    main()
