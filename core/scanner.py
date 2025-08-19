# /core/sacanner.py

from scapy.all import IP, TCP, sr1
import random

def run_test(target, port):
    results = {}

    # Generar un puerto aleatorio de origen
    sport = random.randint(1024, 65535)

    # Paquete SYN
    syn = IP(dst=target)/TCP(dport=port, flags="S", sport=sport)
    resp_syn = sr1(syn, timeout=2, verbose=0)
    results["SYN"] = resp_syn.summary() if resp_syn else "No response"

    # Paquete ACK
    ack = IP(dst=target)/TCP(dport=port, flags="A", sport=sport)
    resp_ack = sr1(ack, timeout=2, verbose=0)
    results["ACK"] = resp_ack.summary() if resp_ack else "No response"

    # Paquete FIN
    fin = IP(dst=target)/TCP(dport=port, flags="F", sport=sport)
    resp_fin = sr1(fin, timeout=2, verbose=0)
    results["FIN"] = resp_fin.summary() if resp_fin else "No response"

    # Paquete NULL (Sin flags)
    null = IP(dst=target)/TCP(dport=port, flags="", sport=sport)
    resp_null = sr1(null, timeout=2, verbose=0)
    results["NULL"] = resp_null.summary() if resp_null else "No response"

    # Paquete XMAS (FIN + PSH + URG)
    xmas = IP(dst=target)/TCP(dport=port, flags="FPU", sport=sport)
    resp_xmas = sr1(xmas, timeout=2, verbose=0)
    results["XMAS"] = resp_xmas.summary() if resp_xmas else "No response"

    # Paquete RST (opcional, puede dar info sobre filtrado)
    rst = IP(dst=target)/TCP(dport=port, flags="R", sport=sport)
    resp_rst = sr1(rst, timeout=2, verbose=0)
    results["RST"] = resp_rst.summary() if resp_rst else "No response"

    return results