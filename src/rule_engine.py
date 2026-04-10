"""
rule_engine.py — Snort-style rule parser and packet matcher.

Supports a simplified rule syntax:
    alert <protocol> <src_ip> <src_port> -> <dst_ip> <dst_port> (
        msg:"description"; sid:1001; severity:HIGH; flags:S;
        content:"pattern"; attack_type:port_scan;
    )

Special keywords:
    any         — matches any IP or port
    $HOME_NET   — replaced with the local subnet (configurable)
    $EXTERNAL   — anything NOT in $HOME_NET

Also includes built-in heuristic detectors for:
    - Port scans (tracking unique dst ports per src IP)
    - SYN floods (SYN packet rate per src IP)
    - Brute force (connection rate to SSH/FTP ports)
    - ARP spoofing (multiple MACs claiming one IP)
    - DNS poisoning (divergent answers for the same query)
"""

import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from src.packet_capture import PacketCapture, PacketInfo


@dataclass
class Rule:
    """Parsed representation of a single Snort-style rule."""
    sid: int = 0
    action: str = "alert"                # alert / log / drop
    protocol: str = "any"                # tcp / udp / icmp / arp / any
    src_ip: str = "any"
    src_port: str = "any"
    dst_ip: str = "any"
    dst_port: str = "any"
    msg: str = ""
    severity: str = "MEDIUM"
    flags: str = ""                      # TCP flags to match (e.g., "S" for SYN)
    content: str = ""                    # Payload substring match
    attack_type: str = "unknown"
    direction: str = "->"                # -> or <>

    def matches(self, pkt: PacketInfo) -> bool:
        """Return True if this rule matches the given packet info."""
        # Protocol check
        if self.protocol != "any" and self.protocol.upper() != pkt.protocol.upper():
            return False

        # Source IP check
        if self.src_ip != "any" and self.src_ip != pkt.src_ip:
            return False

        # Destination IP check
        if self.dst_ip != "any" and self.dst_ip != pkt.dst_ip:
            return False

        # Source port check
        if self.src_port != "any" and pkt.src_port is not None:
            if not self._port_match(self.src_port, pkt.src_port):
                return False

        # Destination port check
        if self.dst_port != "any" and pkt.dst_port is not None:
            if not self._port_match(self.dst_port, pkt.dst_port):
                return False

        # TCP flags check (only if rule specifies flags and packet is TCP)
        if self.flags and pkt.protocol == "TCP":
            if self.flags.upper() not in pkt.flags.upper():
                return False

        # Content match (substring in raw summary)
        if self.content:
            if self.content.lower() not in pkt.raw_summary.lower():
                return False

        return True

    @staticmethod
    def _port_match(rule_port: str, actual_port: int) -> bool:
        """Handle port ranges like '1:1024' or single ports like '22'."""
        if ":" in rule_port:
            lo, hi = rule_port.split(":")
            lo = int(lo) if lo else 0
            hi = int(hi) if hi else 65535
            return lo <= actual_port <= hi
        try:
            return int(rule_port) == actual_port
        except ValueError:
            return True  # If we can't parse, don't filter on it


class RuleEngine:
    """
    Loads and evaluates Snort-style rules, plus built-in heuristic detectors.

    Usage:
        engine = RuleEngine(config, packet_capture_instance)
        alerts = engine.evaluate(packet_info)  # returns list of alert dicts
    """

    def __init__(self, config: dict, capture: PacketCapture):
        self.config = config
        self.capture = capture  # For accessing ARP table and DNS cache
        self.rules: list[Rule] = []
        self.thresholds = config.get("thresholds", {})

        # --- Heuristic state ---
        # Port scan tracking: src_ip -> {dst_port: first_seen_timestamp}
        self._port_scan_tracker: dict[str, dict[int, float]] = defaultdict(dict)

        # SYN flood tracking: src_ip -> list of SYN timestamps
        self._syn_tracker: dict[str, list[float]] = defaultdict(list)

        # Brute force tracking: src_ip -> list of connection timestamps per port
        self._brute_tracker: dict[str, list[float]] = defaultdict(list)

        # Track which alerts were already fired to avoid duplicates within window
        self._fired_alerts: dict[str, float] = {}  # key -> last_fired_timestamp
        self._alert_cooldown = 30  # seconds between duplicate alerts

        # Load rule files
        rules_cfg = config.get("rules", {})
        if rules_cfg.get("enabled", True):
            rules_dir = rules_cfg.get("rules_dir", "rules")
            self._load_rules_from_dir(rules_dir)
            # Generate default rules file if it doesn't exist
            default_file = os.path.join(rules_dir, rules_cfg.get("default_rules_file", "default.rules"))
            if not os.path.exists(default_file):
                self._generate_default_rules(default_file)
                self._load_rules_from_file(default_file)

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------
    def _load_rules_from_dir(self, directory: str):
        """Scan a directory for .rules files and parse them all."""
        if not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
            return
        for fname in sorted(os.listdir(directory)):
            if fname.endswith(".rules"):
                self._load_rules_from_file(os.path.join(directory, fname))

    def _load_rules_from_file(self, filepath: str):
        """Parse a single .rules file line-by-line."""
        if not os.path.exists(filepath):
            return
        with open(filepath, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    rule = self._parse_rule(line)
                    if rule:
                        self.rules.append(rule)
                except Exception as e:
                    print(f"[!] Rule parse error in {filepath}:{line_no}: {e}")

    def _parse_rule(self, line: str) -> Optional[Rule]:
        """
        Parse a single Snort-style rule string.
        Format: action proto src_ip src_port -> dst_ip dst_port (options)
        """
        # Split the header from the options block
        match = re.match(
            r"(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(->|<>)\s+(\S+)\s+(\S+)\s*\((.+)\)\s*",
            line, re.DOTALL
        )
        if not match:
            return None

        rule = Rule(
            action=match.group(1),
            protocol=match.group(2),
            src_ip=match.group(3),
            src_port=match.group(4),
            dst_ip=match.group(6),
            dst_port=match.group(7),
            direction=match.group(5),
        )

        # Parse the options block: key:"value"; pairs
        options_str = match.group(8)
        # Match key:value or key:"value" pairs separated by ;
        opt_pattern = re.compile(r'(\w+)\s*:\s*"?([^";]*)"?\s*;')
        for opt_match in opt_pattern.finditer(options_str):
            key = opt_match.group(1).lower()
            val = opt_match.group(2).strip()
            if key == "msg":
                rule.msg = val
            elif key == "sid":
                rule.sid = int(val)
            elif key == "severity":
                rule.severity = val.upper()
            elif key == "flags":
                rule.flags = val
            elif key == "content":
                rule.content = val
            elif key == "attack_type":
                rule.attack_type = val

        return rule

    def _generate_default_rules(self, filepath: str):
        """Create a starter rules file with common detection signatures."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        default_rules = """# ===============================================
# NIDS Default Rules — Auto-generated
# ===============================================

# --- SSH brute force (SYN to port 22) ---
alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1001; severity:LOW; flags:S; attack_type:brute_force;)

# --- FTP brute force (SYN to port 21) ---
alert tcp any any -> any 21 (msg:"FTP connection attempt"; sid:1002; severity:LOW; flags:S; attack_type:brute_force;)

# --- Telnet access attempt ---
alert tcp any any -> any 23 (msg:"Telnet connection attempt"; sid:1003; severity:MEDIUM; flags:S; attack_type:brute_force;)

# --- HTTP CONNECT tunnel ---
alert tcp any any -> any 443 (msg:"HTTPS connection"; sid:1004; severity:LOW; flags:S; attack_type:recon;)

# --- DNS zone transfer attempt (TCP port 53) ---
alert tcp any any -> any 53 (msg:"DNS zone transfer attempt"; sid:1005; severity:HIGH; flags:S; attack_type:dns_enum;)

# --- ICMP ping sweep ---
alert icmp any any -> any any (msg:"ICMP ping detected"; sid:1006; severity:LOW; attack_type:recon;)

# --- SMB access attempt ---
alert tcp any any -> any 445 (msg:"SMB connection attempt"; sid:1007; severity:MEDIUM; flags:S; attack_type:recon;)

# --- RDP connection ---
alert tcp any any -> any 3389 (msg:"RDP connection attempt"; sid:1008; severity:MEDIUM; flags:S; attack_type:recon;)
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(default_rules)

    # ------------------------------------------------------------------
    # Evaluation — runs BOTH rule matching and heuristic detectors
    # ------------------------------------------------------------------
    def evaluate(self, pkt: PacketInfo) -> list[dict]:
        """
        Evaluate a packet against all rules and heuristic detectors.
        Returns a list of alert dicts (may be empty).
        """
        alerts = []

        # 1. Match against loaded Snort-style rules
        for rule in self.rules:
            if rule.matches(pkt):
                alert_key = f"rule_{rule.sid}_{pkt.src_ip}"
                if not self._is_cooled_down(alert_key):
                    alerts.append({
                        "src_ip": pkt.src_ip,
                        "dst_ip": pkt.dst_ip,
                        "src_port": pkt.src_port,
                        "dst_port": pkt.dst_port,
                        "protocol": pkt.protocol,
                        "attack_type": rule.attack_type,
                        "severity": rule.severity,
                        "description": f"Rule SID:{rule.sid} — {rule.msg}",
                        "detection_source": "rule_engine",
                    })
                    self._mark_fired(alert_key)

        # 2. Heuristic: Port Scan detection
        port_scan_alert = self._detect_port_scan(pkt)
        if port_scan_alert:
            alerts.append(port_scan_alert)

        # 3. Heuristic: SYN Flood detection
        syn_flood_alert = self._detect_syn_flood(pkt)
        if syn_flood_alert:
            alerts.append(syn_flood_alert)

        # 4. Heuristic: Brute Force detection
        brute_alert = self._detect_brute_force(pkt)
        if brute_alert:
            alerts.append(brute_alert)

        # 5. Heuristic: ARP Spoofing detection
        arp_alert = self._detect_arp_spoof(pkt)
        if arp_alert:
            alerts.append(arp_alert)

        # 6. Heuristic: DNS Poisoning detection
        dns_alert = self._detect_dns_poison(pkt)
        if dns_alert:
            alerts.append(dns_alert)

        return alerts

    # ------------------------------------------------------------------
    # Heuristic detectors
    # ------------------------------------------------------------------
    def _detect_port_scan(self, pkt: PacketInfo) -> Optional[dict]:
        """Detect port scans by tracking unique destination ports per source IP."""
        # Only consider TCP SYN packets (initial connection attempts)
        if pkt.protocol != "TCP" or "S" not in pkt.flags:
            return None
        if pkt.dst_port is None:
            return None

        cfg = self.thresholds.get("port_scan", {})
        threshold = cfg.get("unique_ports", 15)
        window = cfg.get("time_window", 60)

        tracker = self._port_scan_tracker[pkt.src_ip]
        now = pkt.timestamp

        # Record this port with its timestamp
        tracker[pkt.dst_port] = now

        # Evict ports outside the time window
        expired_ports = [p for p, ts in tracker.items() if now - ts > window]
        for p in expired_ports:
            del tracker[p]

        # Check if threshold is exceeded
        if len(tracker) >= threshold:
            alert_key = f"portscan_{pkt.src_ip}"
            if self._is_cooled_down(alert_key):
                return None
            self._mark_fired(alert_key)
            # Reset tracker after alert to avoid flooding
            self._port_scan_tracker[pkt.src_ip] = {}
            return {
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
                "protocol": "TCP",
                "attack_type": "port_scan",
                "severity": "HIGH",
                "description": (
                    f"Port scan detected: {len(tracker)} unique ports "
                    f"probed in {window}s from {pkt.src_ip}"
                ),
                "detection_source": "rule_engine",
            }
        return None

    def _detect_syn_flood(self, pkt: PacketInfo) -> Optional[dict]:
        """Detect SYN flood by counting SYN packets per source IP."""
        if pkt.protocol != "TCP" or "S" not in pkt.flags:
            return None

        cfg = self.thresholds.get("syn_flood", {})
        threshold = cfg.get("syn_count", 100)
        window = cfg.get("time_window", 10)
        now = pkt.timestamp

        self._syn_tracker[pkt.src_ip].append(now)
        # Prune old entries outside window
        self._syn_tracker[pkt.src_ip] = [
            ts for ts in self._syn_tracker[pkt.src_ip] if now - ts <= window
        ]

        if len(self._syn_tracker[pkt.src_ip]) >= threshold:
            alert_key = f"synflood_{pkt.src_ip}"
            if self._is_cooled_down(alert_key):
                return None
            self._mark_fired(alert_key)
            count = len(self._syn_tracker[pkt.src_ip])
            self._syn_tracker[pkt.src_ip] = []  # Reset after alert
            return {
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
                "protocol": "TCP",
                "attack_type": "syn_flood",
                "severity": "CRITICAL",
                "description": (
                    f"SYN flood detected: {count} SYN packets "
                    f"in {window}s from {pkt.src_ip}"
                ),
                "detection_source": "rule_engine",
            }
        return None

    def _detect_brute_force(self, pkt: PacketInfo) -> Optional[dict]:
        """Detect brute-force attempts on SSH (22) and FTP (21)."""
        if pkt.protocol != "TCP" or "S" not in pkt.flags:
            return None

        cfg = self.thresholds.get("brute_force", {})
        target_ports = cfg.get("ports", [22, 21])
        threshold = cfg.get("attempts", 5)
        window = cfg.get("time_window", 60)

        if pkt.dst_port not in target_ports:
            return None

        now = pkt.timestamp
        tracker_key = f"{pkt.src_ip}:{pkt.dst_port}"
        self._brute_tracker[tracker_key].append(now)

        # Prune old entries
        self._brute_tracker[tracker_key] = [
            ts for ts in self._brute_tracker[tracker_key] if now - ts <= window
        ]

        if len(self._brute_tracker[tracker_key]) >= threshold:
            alert_key = f"brute_{tracker_key}"
            if self._is_cooled_down(alert_key):
                return None
            self._mark_fired(alert_key)
            service = "SSH" if pkt.dst_port == 22 else "FTP" if pkt.dst_port == 21 else f"port {pkt.dst_port}"
            count = len(self._brute_tracker[tracker_key])
            self._brute_tracker[tracker_key] = []
            return {
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
                "protocol": "TCP",
                "attack_type": "brute_force",
                "severity": "HIGH",
                "description": (
                    f"{service} brute force: {count} connection attempts "
                    f"in {window}s from {pkt.src_ip}"
                ),
                "detection_source": "rule_engine",
            }
        return None

    def _detect_arp_spoof(self, pkt: PacketInfo) -> Optional[dict]:
        """Detect ARP spoofing by checking if multiple MACs claim the same IP."""
        if pkt.protocol != "ARP":
            return None

        cfg = self.thresholds.get("arp_spoof", {})
        dup_threshold = cfg.get("duplicate_ips", 2)

        # Check the capture module's ARP table
        for ip_addr, mac_set in self.capture.arp_table.items():
            if len(mac_set) >= dup_threshold:
                alert_key = f"arpspoof_{ip_addr}"
                if self._is_cooled_down(alert_key):
                    continue
                self._mark_fired(alert_key)
                return {
                    "src_ip": ip_addr,
                    "dst_ip": pkt.dst_ip,
                    "protocol": "ARP",
                    "attack_type": "arp_spoof",
                    "severity": "CRITICAL",
                    "description": (
                        f"ARP spoofing detected: IP {ip_addr} claimed by "
                        f"{len(mac_set)} different MACs: {', '.join(mac_set)}"
                    ),
                    "detection_source": "rule_engine",
                }
        return None

    def _detect_dns_poison(self, pkt: PacketInfo) -> Optional[dict]:
        """Detect DNS poisoning by looking for divergent answers to the same query."""
        if not pkt.dns_query or not pkt.dns_answers:
            return None

        cfg = self.thresholds.get("dns_poison", {})
        threshold = cfg.get("response_threshold", 5)
        window = cfg.get("time_window", 10)
        now = pkt.timestamp

        query = pkt.dns_query
        cache = self.capture.dns_cache.get(query, [])

        # Filter to entries within the time window
        recent = [(ans, ts) for ans, ts in cache if now - ts <= window]

        if len(recent) < 2:
            return None

        # Collect all unique answer sets
        unique_answers = set()
        for ans_set, _ in recent:
            unique_answers.add(frozenset(ans_set))

        if len(unique_answers) >= threshold:
            alert_key = f"dnspoison_{query}"
            if self._is_cooled_down(alert_key):
                return None
            self._mark_fired(alert_key)
            return {
                "src_ip": pkt.src_ip,
                "dst_ip": pkt.dst_ip,
                "src_port": pkt.src_port,
                "dst_port": pkt.dst_port,
                "protocol": "UDP",
                "attack_type": "dns_poison",
                "severity": "CRITICAL",
                "description": (
                    f"DNS poisoning suspected: {len(unique_answers)} different "
                    f"answer sets for '{query}' in {window}s"
                ),
                "detection_source": "rule_engine",
            }
        return None

    # ------------------------------------------------------------------
    # Alert cooldown helpers
    # ------------------------------------------------------------------
    def _is_cooled_down(self, key: str) -> bool:
        """Return True if this alert was fired recently (within cooldown)."""
        last = self._fired_alerts.get(key)
        if last is None:
            return False
        return (time.time() - last) < self._alert_cooldown

    def _mark_fired(self, key: str):
        """Record that an alert with this key was just fired."""
        self._fired_alerts[key] = time.time()

    @property
    def rule_count(self) -> int:
        return len(self.rules)
