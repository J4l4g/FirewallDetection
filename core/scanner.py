# /core/sacanner.py

from scapy.all import IP, TCP, sr1
import random

def run_test(target, port):
    results = {}

    # Generar un puerto aleatorio de origen
    sport = random.randint(1024, 65535)

    # Paquetes SYN, ACK, FIN, NULL, XMAS, RST

    packet_types =  {
        "SYN": "S",
        "ACK": "A",
        "FIN": "F",
        "NULL": "",
        "XMAS": "FPU",
        "RST": "R"
    }

    for name, flags in packet_types.items():
        pkt = IP(dst=target)/TCP(dport=port, flags="S", sport=sport)
        resp = sr1(pkt, timeout=2, verbose=0)
        results[name] = resp.summary() if resp else "No response"

    return results