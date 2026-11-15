from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import ARP, Ether

from sentinel.cli import main
from sentinel.detectors import ArpSpoofDetector, IcmpFloodDetector, PortScanDetector

PCAP = Path(__file__).resolve().parent.parent / "exemplos" / "laboratorio.pcap"


def at(pkt, t):
    pkt.time = t
    return pkt


def syn(port, t, src="10.0.0.5"):
    return at(IP(src=src, dst="10.0.0.1") / TCP(dport=port, flags="S"), t)


def test_port_scan_rapido_dispara():
    det = PortScanDetector(ports=10, window=5)
    alerts = [det.feed(syn(p, p * 0.1)) for p in range(1, 15)]
    assert sum(a is not None for a in alerts) == 1


def test_varredura_lenta_nao_dispara():
    det = PortScanDetector(ports=10, window=5)
    assert all(det.feed(syn(p, p * 2.0)) is None for p in range(1, 15))


def test_syn_ack_nao_conta_como_scan():
    det = PortScanDetector(ports=3, window=5)
    pkts = [at(IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=p, flags="SA"), 0) for p in range(10)]
    assert all(det.feed(p) is None for p in pkts)


def test_arp_com_mac_trocado():
    det = ArpSpoofDetector()
    assert det.feed(at(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa"), 0)) is None
    alert = det.feed(at(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:bb"), 1))
    assert alert.rule == "ARP spoofing" and alert.severity == "critica"


def test_icmp_flood():
    det = IcmpFloodDetector(per_second=20)
    hits = [det.feed(at(IP(src="10.0.0.9", dst="10.0.0.1") / ICMP(type=8), i * 0.01)) for i in range(30)]
    assert sum(h is not None for h in hits) == 1


def test_pcap_de_exemplo_tem_tres_alertas(capsys):
    assert main(["--pcap", str(PCAP), "--sem-cor"]) == 1
    out = capsys.readouterr().out
    assert "port scan" in out and "ARP spoofing" in out and "ICMP flood" in out
