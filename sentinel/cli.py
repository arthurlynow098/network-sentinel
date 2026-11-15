from __future__ import annotations

import argparse
import sys
from datetime import datetime

from .detectors import Sentinel

COLOR = {"critica": "\033[91m", "alta": "\033[93m", "media": "\033[96m"}
RESET = "\033[0m"


def show(alert, color: bool) -> None:
    when = datetime.fromtimestamp(alert.time).strftime("%H:%M:%S")
    c, r = (COLOR[alert.severity], RESET) if color else ("", "")
    print(f"  {c}{when} [{alert.severity}] {alert.rule}{r} de {alert.source}, {alert.detail} ({alert.mitre})")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel", description="Mini IDS que detecta port scan, ARP spoofing e ICMP flood.")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="analisa um arquivo de captura")
    src.add_argument("--iface", help="escuta ao vivo numa interface (precisa de admin)")
    p.add_argument("--portas", type=int, default=15, help="portas distintas para considerar port scan")
    p.add_argument("--janela", type=float, default=10.0, help="janela do port scan em segundos")
    p.add_argument("--icmp", type=int, default=50, help="pings por segundo para considerar flood")
    p.add_argument("--sem-cor", action="store_true")
    return p


def report(sentinel: Sentinel) -> None:
    st = sentinel.stats
    print(f"\n  {st.packets} pacotes analisados")
    print("  protocolos  " + "  ".join(f"{k} {v}" for k, v in st.protocols.most_common()))
    print("  quem mais falou")
    for ip, n in st.talkers.most_common(5):
        print(f"    {ip:<18}{n}")
    print(f"\n  {len(sentinel.alerts)} alerta(s)\n")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    sentinel = Sentinel(args.portas, args.janela, args.icmp)
    color = not args.sem_cor and sys.stdout.isatty()

    if args.pcap:
        from scapy.utils import PcapReader

        print(f"\n  lendo {args.pcap}\n")
        with PcapReader(args.pcap) as reader:
            for pkt in reader:
                for alert in sentinel.feed(pkt):
                    show(alert, color)
    else:
        from scapy.sendrecv import sniff

        print(f"\n  escutando {args.iface}, Ctrl+C para parar\n")
        sniff(iface=args.iface, store=False,
              prn=lambda pkt: [show(a, color) for a in sentinel.feed(pkt)])
    report(sentinel)
    return 1 if sentinel.alerts else 0
