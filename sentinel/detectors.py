"""Detectores do mini IDS.

Cada detector recebe pacote por pacote (método feed) e devolve alertas
quando a regra bate. Usar o tempo do próprio pacote, e não o relógio do
computador, é o que permite analisar um .pcap antigo com a mesma lógica.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP


@dataclass
class Alert:
    time: float
    rule: str
    severity: str
    source: str
    detail: str
    mitre: str


class PortScanDetector:
    """Um IP mandando SYN para muitas portas diferentes em pouco tempo."""

    def __init__(self, ports: int = 15, window: float = 10.0):
        self.ports, self.window = ports, window
        self.seen: dict[tuple[str, str], deque] = defaultdict(deque)
        self.alerted: set[tuple[str, str]] = set()

    def feed(self, pkt) -> Alert | None:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return None
        flags = pkt[TCP].flags
        if not (flags & 0x02) or (flags & 0x10):  # quero SYN sem ACK
            return None
        key = (pkt[IP].src, pkt[IP].dst)
        q = self.seen[key]
        q.append((float(pkt.time), pkt[TCP].dport))
        while q and float(pkt.time) - q[0][0] > self.window:
            q.popleft()
        distinct = {port for _, port in q}
        if len(distinct) >= self.ports and key not in self.alerted:
            self.alerted.add(key)
            return Alert(float(pkt.time), "port scan", "alta", key[0],
                         f"SYN para {len(distinct)} portas de {key[1]} em {self.window:.0f}s", "T1046")
        return None


class ArpSpoofDetector:
    """O mesmo IP aparecendo com um MAC diferente, sinal de man-in-the-middle."""

    def __init__(self):
        self.table: dict[str, str] = {}

    def feed(self, pkt) -> Alert | None:
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:  # 2 é "is-at", a resposta
            return None
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc.lower()
        old = self.table.get(ip)
        self.table[ip] = mac
        if old and old != mac:
            return Alert(float(pkt.time), "ARP spoofing", "critica", mac,
                         f"{ip} mudou de {old} para {mac}", "T1557.002")
        return None


class IcmpFloodDetector:
    """Muitos pings do mesmo IP em um segundo."""

    def __init__(self, per_second: int = 50):
        self.limit = per_second
        self.buckets: dict[str, deque] = defaultdict(deque)
        self.alerted: set[str] = set()

    def feed(self, pkt) -> Alert | None:
        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)) or pkt[ICMP].type != 8:
            return None
        src, now = pkt[IP].src, float(pkt.time)
        q = self.buckets[src]
        q.append(now)
        while q and now - q[0] > 1.0:
            q.popleft()
        if len(q) >= self.limit and src not in self.alerted:
            self.alerted.add(src)
            return Alert(now, "ICMP flood", "media", src, f"{len(q)} echo requests em 1s", "T1498")
        return None


class Stats:
    def __init__(self):
        self.protocols = Counter()
        self.talkers = Counter()
        self.packets = 0

    def feed(self, pkt) -> None:
        self.packets += 1
        if pkt.haslayer(ARP):
            self.protocols["ARP"] += 1
        elif pkt.haslayer(IP):
            self.talkers[pkt[IP].src] += 1
            if pkt.haslayer(TCP):
                self.protocols["TCP"] += 1
            elif pkt.haslayer(UDP):
                self.protocols["UDP"] += 1
            elif pkt.haslayer(ICMP):
                self.protocols["ICMP"] += 1
            else:
                self.protocols["IP outro"] += 1
        else:
            self.protocols["outro"] += 1


class Sentinel:
    def __init__(self, scan_ports=15, scan_window=10.0, icmp_rate=50):
        self.detectors = [PortScanDetector(scan_ports, scan_window), ArpSpoofDetector(), IcmpFloodDetector(icmp_rate)]
        self.stats = Stats()
        self.alerts: list[Alert] = []

    def feed(self, pkt) -> list[Alert]:
        self.stats.feed(pkt)
        new = [a for a in (d.feed(pkt) for d in self.detectors) if a]
        self.alerts.extend(new)
        return new
