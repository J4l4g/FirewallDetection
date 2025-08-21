# /core/scanner.py

from scapy.all import IP, TCP, sr1
import random
from core.suggestions import get_diagnosis, get_recommendation
from utils.colors import Colors

def run_test(target, port, quick=False):
    results = {}
    sport = random.randint(1024, 65535)

    packet_types = {
        "SYN": "S",
        "ACK": "A",
        "FIN": "F",
        "NULL": "",
        "XMAS": "FPU",
        "RST": "R"
    }

    if quick:
        packet_types = {k: v for k, v in packet_types.items() if k in ["SYN", "ACK"]}

    for name, flags in packet_types.items():
        pkt = IP(dst=target)/TCP(dport=port, flags=flags, sport=sport)
        resp = sr1(pkt, timeout=2, verbose=0)
        results[name] = resp.summary() if resp else "No response"

    return results

def display_results(results):
    print(Colors.MAGENTA + "\n[+] Resultados crudos:" + Colors.RESET)
    for pkt, resp in results.items():
        if "RST" in resp:
            color = Colors.GREEN
        elif "No response" in resp:
            color = Colors.RED
        else:
            color = Colors.YELLOW
        print(color + f"[!] {pkt} -> {resp}" + Colors.RESET)

def run_full_scan(target, port, quick=False):
    results = run_test(target, port, quick=quick)
    display_results(results)

    diagnosis = get_diagnosis(results)

    print(Colors.MAGENTA + "\n[+] Diagnóstico" + Colors.RESET)
    if diagnosis:
        for d in diagnosis:
            print(Colors.BLUE + f" - {d}" + Colors.RESET)
    else:
        print(Colors.BLUE + " - No hay información suficiente para diagnóstico" + Colors.RESET)

    recs = get_recommendation(results, use_raw=True)

    print(Colors.MAGENTA + "\n[+] Técnicas recomendadas:" + Colors.RESET)
    for r in recs:
        print(Colors.GREEN + f" - {r}" + Colors.RESET)
