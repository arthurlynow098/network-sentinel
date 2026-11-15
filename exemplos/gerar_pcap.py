"""Monta um .pcap de laboratório com tráfego normal e três anomalias.

Nada é enviado para a rede. Os pacotes são criados em memória e gravados
direto no arquivo. Os IPs são de faixas privadas e de documentação.
"""
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

T0 = 1_794_000_000.0  # um horário qualquer de 2026
packets = []


def add(pkt, t):
    pkt.time = T0 + t
    packets.append(pkt)


GW_IP, GW_MAC = "192.168.0.1", "aa:bb:cc:00:00:01"
PC_IP, PC_MAC = "192.168.0.20", "aa:bb:cc:00:00:20"
ATTACKER_MAC = "de:ad:be:ef:00:66"

# tráfego normal, DNS e uma navegação HTTPS
for i in range(20):
    add(Ether() / IP(src=PC_IP, dst="192.168.0.1") / UDP(sport=50000 + i, dport=53) / Raw(b"q"), i * 0.5)
    add(Ether() / IP(src=PC_IP, dst="203.0.113.10") / TCP(sport=51000 + i, dport=443, flags="PA"), i * 0.5 + 0.1)

# ARP normal, o gateway se anunciando
add(Ether(src=GW_MAC) / ARP(op=2, psrc=GW_IP, hwsrc=GW_MAC, pdst=PC_IP, hwdst=PC_MAC), 1)

# anomalia 1, varredura de portas de uma máquina da rede
for i, port in enumerate(range(20, 60)):
    add(Ether() / IP(src="192.168.0.66", dst="192.168.0.20") / TCP(sport=40000, dport=port, flags="S"), 12 + i * 0.05)

# anomalia 2, alguém respondendo ARP dizendo que é o gateway
add(Ether(src=ATTACKER_MAC) / ARP(op=2, psrc=GW_IP, hwsrc=ATTACKER_MAC, pdst=PC_IP, hwdst=PC_MAC), 20)

# anomalia 3, rajada de pings
for i in range(80):
    add(Ether() / IP(src="198.51.100.7", dst=PC_IP) / ICMP(type=8), 25 + i * 0.01)

packets.sort(key=lambda p: p.time)
out = Path(__file__).with_name("laboratorio.pcap")
wrpcap(str(out), packets)
print(f"{len(packets)} pacotes gravados em {out.name}")
