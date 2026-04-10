"""
packet_capture.py — Live network packet capture using Scapy.

Provides:
  - PacketCapture class that sniffs on a chosen interface
  - Extracts structured metadata from each packet (IP, ports, flags, etc.)
  - Maintains rolling statistics (packets/sec, protocol distribution)
  - Thread-safe packet queue for downstream consumers
"""

import time
import threading
from collections import defaultdict, deque
from typing import Optional, Callable

from scapy.all import (
    sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Ether,
    conf, get_if_list, get_if_addr
)


class PacketInfo:
    """Lightweight data class holding extracted fields from a single packet."""

    __slots__ = [
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "flags", "payload_size", "src_mac", "dst_mac",
        "dns_query", "dns_answers", "raw_summary",
    ]

    def __init__(self):
        self.timestamp: float = 0.0
        self.src_ip: str = ""
        self.dst_ip: str = ""
        self.src_port: Optional[int] = None
        self.dst_port: Optional[int] = None
        self.protocol: str = ""
        self.flags: str = ""            # TCP flags string: SYN, ACK, etc.
        self.payload_size: int = 0
        self.src_mac: str = ""
        self.dst_mac: str = ""
        self.dns_query: Optional[str] = None
        self.dns_answers: list[str] = []
        self.raw_summary: str = ""

    def to_dict(self) -> dict:
        return {attr: getattr(self, attr) for attr in self.__slots__}


class PacketCapture:
    """
    Async packet sniffer running in a background thread.

    Usage:
        cap = PacketCapture(interface="eth0")
        cap.start(callback=my_handler)   # my_handler(PacketInfo) called per packet
        ...
        cap.stop()
    """

    def __init__(self, config: dict):
        self.interface: Optional[str] = config.get("interface")
        self.bpf_filter: str = config.get("filter", "")
        self.snaplen: int = config.get("snaplen", 65535)
        self.promisc: bool = config.get("promisc", True)
        self.timeout: int = config.get("timeout", 0)

        # Rolling stats
        self.total_packets: int = 0
        self.protocol_counts: dict[str, int] = defaultdict(int)
        self.packets_per_second: float = 0.0
        self._pps_window: deque = deque(maxlen=100)  # timestamps of last 100 pkts

        # Thread control
        self._running = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._callback: Optional[Callable] = None

        # ARP table for spoof detection: maps IP -> set of MACs seen
        self.arp_table: dict[str, set[str]] = defaultdict(set)

        # DNS response cache: maps query -> list of (answer_set, timestamp)
        self.dns_cache: dict[str, list] = defaultdict(list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def start(self, callback: Callable[[PacketInfo], None]):
        """Begin capturing packets in a daemon thread."""
        if self._running.is_set():
            return  # Already running

        self._callback = callback
        self._running.set()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the capture thread to stop."""
        self._running.clear()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    @property
    def is_running(self) -> bool:
        return self._running.is_set()

    def get_stats(self) -> dict:
        """Return a snapshot of capture statistics."""
        return {
            "total_packets": self.total_packets,
            "packets_per_second": round(self.packets_per_second, 2),
            "protocol_distribution": dict(self.protocol_counts),
        }

    # ------------------------------------------------------------------
    # Internal capture loop
    # ------------------------------------------------------------------
    def _capture_loop(self):
        """Runs in a background thread; calls Scapy sniff."""
        sniff_kwargs = {
            "prn": self._process_packet,      # callback per packet
            "store": False,                    # don't keep packets in memory
            "stop_filter": lambda _: not self._running.is_set(),
        }
        if self.interface:
            sniff_kwargs["iface"] = self.interface
        if self.bpf_filter:
            sniff_kwargs["filter"] = self.bpf_filter
        if self.timeout and self.timeout > 0:
            sniff_kwargs["timeout"] = self.timeout

        try:
            sniff(**sniff_kwargs)
        except PermissionError:
            print("[!] Packet capture requires root/admin privileges.")
            self._running.clear()
        except Exception as e:
            print(f"[!] Capture error: {e}")
            self._running.clear()

    def _process_packet(self, pkt):
        """Parse one raw Scapy packet into a PacketInfo and invoke the callback."""
        info = PacketInfo()
        info.timestamp = time.time()
        info.raw_summary = pkt.summary()

        # --- Ethernet layer ---
        if pkt.haslayer(Ether):
            info.src_mac = pkt[Ether].src
            info.dst_mac = pkt[Ether].dst

        # --- ARP layer (no IP) ---
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            info.protocol = "ARP"
            info.src_ip = arp.psrc      # protocol source = claimed IP
            info.dst_ip = arp.pdst
            # Track MAC-to-IP bindings for spoof detection
            if arp.op == 2:  # ARP reply (is-at)
                self.arp_table[arp.psrc].add(arp.hwsrc)
            self._finalize(info)
            return

        # --- IP layer ---
        if pkt.haslayer(IP):
            info.src_ip = pkt[IP].src
            info.dst_ip = pkt[IP].dst
            info.payload_size = len(pkt[IP].payload)
        elif pkt.haslayer(IPv6):
            info.src_ip = pkt[IPv6].src
            info.dst_ip = pkt[IPv6].dst
            info.payload_size = len(pkt[IPv6].payload)
        else:
            # Non-IP, non-ARP — skip deeper parsing
            info.protocol = "OTHER"
            self._finalize(info)
            return

        # --- Transport layer ---
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info.protocol = "TCP"
            info.src_port = tcp.sport
            info.dst_port = tcp.dport
            # Convert flag integer to human-readable string
            info.flags = str(tcp.flags)  # e.g. "S", "SA", "FA", "PA"
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            info.protocol = "UDP"
            info.src_port = udp.sport
            info.dst_port = udp.dport
        elif pkt.haslayer(ICMP):
            info.protocol = "ICMP"

        # --- DNS layer ---
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            # Extract query name
            if dns.qd:
                try:
                    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                    info.dns_query = qname
                except Exception:
                    pass
            # Extract answers (responses)
            if dns.ancount and dns.ancount > 0:
                answers = []
                for i in range(dns.ancount):
                    try:
                        rdata = dns.an[i].rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode("utf-8", errors="ignore")
                        answers.append(str(rdata))
                    except Exception:
                        pass
                info.dns_answers = answers
                # Cache for poisoning detection
                if info.dns_query:
                    self.dns_cache[info.dns_query].append(
                        (set(answers), info.timestamp)
                    )

        self._finalize(info)

    def _finalize(self, info: PacketInfo):
        """Update stats and invoke the user callback."""
        self.total_packets += 1
        self.protocol_counts[info.protocol] += 1

        # Packets-per-second calculation using sliding window
        now = time.time()
        self._pps_window.append(now)
        if len(self._pps_window) >= 2:
            elapsed = self._pps_window[-1] - self._pps_window[0]
            if elapsed > 0:
                self.packets_per_second = len(self._pps_window) / elapsed

        # Fire the downstream callback
        if self._callback:
            try:
                self._callback(info)
            except Exception as e:
                print(f"[!] Callback error: {e}")


def list_interfaces() -> list[dict]:
    """Utility: list available network interfaces with addresses."""
    result = []
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
        except Exception:
            addr = "unknown"
        result.append({"name": iface, "address": addr})
    return result
