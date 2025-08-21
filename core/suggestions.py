# /core/suggestions.py

def get_diagnosis(results):
    diagnosis = []

    for pkt, resp in results.items():
        if pkt == "SYN":
            if "SA" in resp:
                diagnosis.append("Puerto abierto, sin firewall")
            elif "RST" in resp:
                diagnosis.append("Puerto cerrado, sin firewall")
            elif "dest-unreach" in resp or "No response" in resp:
                diagnosis.append("Firewall DROP o filtrando SYN")
            elif "ICMP" in resp:
                diagnosis.append("Firewall REJECT explícito")

        elif pkt == "ACK":
            if "No response" in resp or "dest-unreach" in resp:
                diagnosis.append("Firewall stateful descarta ACK inválidos")
            elif "RST" in resp:
                diagnosis.append("Camino limpio, sin filtrado stateful")

        elif pkt == "FIN":
            if "No response" in resp:
                diagnosis.append("Firewall filtrando FIN huérfanos o stack ignora")
            elif "RST" in resp:
                diagnosis.append("Puerto cerrado, camino limpio")

        elif pkt == "NULL":
            if "No response" in resp:
                diagnosis.append("Firewall filtra paquetes NULL")
            elif "RST" in resp:
                diagnosis.append("Puerto cerrado, sin filtrado NULL")

        elif pkt == "XMAS":
            if "No response" in resp:
                diagnosis.append("Firewall filtra paquetes XMAS")
            elif "RST" in resp:
                diagnosis.append("Puerto cerrado, camino limpio para XMAS")

        elif pkt == "RST":
            if "No response" in resp:
                diagnosis.append("Firewall bloquea RST")
            elif "RST" in resp:
                diagnosis.append("Puerto cerrado, RST recibido correctamente")

    return diagnosis

def get_recommendation(results_or_diag, use_raw=False):
    recs = []

    if use_raw:
        results = results_or_diag
        for pkt, resp in results.items():
            if pkt == "SYN":
                if "No response" in resp:
                    recs.append("Probar manipulación de puerto origen (ej. 53 o 443)")
                elif "dest-unreach" in resp or "ICMP" in resp:
                    recs.append("Intentar tunneling (ICMP, HTTP)")
            elif pkt == "ACK":
                if "No response" in resp or "dest-unreach" in resp:
                    recs.append("Probar fragmentación de paquetes (-f en nmap)")
            elif pkt in ["FIN", "NULL", "XMAS"]:
                if "No response" in resp:
                    recs.append("Intentar técnicas de evasión de firewall avanzadas (-MTU, --data-length)")
            elif pkt == "RST":
                if "No response" in resp:
                    recs.append("Probar manipulación de puerto origen (ej. 53 o 443)")
    else:
        diagnosis = results_or_diag
        for diag in diagnosis:
            if "Firewall DROP" in diag or "Firewall filtra" in diag:
                recs.append("Probar técnicas de evasión avanzadas (fragmentación, --data-length, -f)")
            elif "Puerto abierto" in diag:
                recs.append("Escaneo estándar suficiente")
            elif "Puerto cerrado" in diag:
                recs.append("Considerar reintentos o análisis de RST")
        if not recs:
            recs.append("Prueba técnicas generales de evasión con Nmap (--data-length, --source-port, -f)")

    # Eliminar duplicados manteniendo orden
    seen = set()
    recs_clean = []
    for r in recs:
        if r not in seen:
            recs_clean.append(r)
            seen.add(r)

    return recs_clean
