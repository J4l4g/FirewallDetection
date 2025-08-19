# /core/suggestions.py

def get_diagnosis(results):
    """
    Genera un diagnóstico basado en las respuestas de los paquetes.
    results: dict con claves ["SYN", "ACK", "FIN", "NULL", "XMAS", "RST"]
    y valores tipo "SA", "RST", "No response", etc.
    """
    diagnosis = []

    # Analizar SYN
    syn = results.get("SYN", "No response")
    if "SA" in syn:
        diagnosis.append("Puerto abierto, sin firewall")
    elif "RST" in syn:
        diagnosis.append("Puerto cerrado, sin firewall")
    elif "No response" in syn:
        diagnosis.append("Firewall DROP o filtrando SYN")
    elif "ICMP" in syn:
        diagnosis.append("Firewall REJECT explícito")

    # Analizar ACK
    ack = results.get("ACK", "No response")
    if "No response" in ack:
        diagnosis.append("Firewall stateful descarta ACK inválidos")
    elif "RST" in ack:
        diagnosis.append("Camino limpio, sin filtrado stateful")

    # Analizar FIN
    fin = results.get("FIN", "No response")
    if "No response" in fin:
        diagnosis.append("Firewall filtrando FIN huérfanos o stack ignora")
    elif "RST" in fin:
        diagnosis.append("Puerto cerrado, camino limpio")

    # Analizar NULL
    null = results.get("NULL", "No response")
    if "No response" in null:
        diagnosis.append("Firewall filtra paquetes NULL")
    elif "RST" in null:
        diagnosis.append("Puerto cerrado, sin filtrado NULL")

    # Analizar XMAS
    xmas = results.get("XMAS", "No response")
    if "No response" in xmas:
        diagnosis.append("Firewall filtra paquetes XMAS")
    elif "RST" in xmas:
        diagnosis.append("Puerto cerrado, camino limpio para XMAS")

    # Analizar RST
    rst = results.get("RST", "No response")
    if "No response" in rst:
        diagnosis.append("Firewall bloquea RST")
    elif "RST" in rst:
        diagnosis.append("Puerto cerrado, RST recibido correctamente")

    return diagnosis


def get_recommendation(diagnosis):
    """
    Genera recomendaciones automáticas según el diagnóstico.
    """
    recs = []

    diag_str = " ".join(diagnosis).lower()

    if "stateful" in diag_str:
        recs.append("Probar fragmentación de paquetes (-f en nmap)")
        recs.append("Intentar tunneling (ICMP, HTTP)")

    if "filtra paquetes null" in diag_str or "filtra paquetes xmas" in diag_str:
        recs.append("Intentar técnicas de evasión de firewall avanzadas (-MTU, --data-length)")

    if "drop" in diag_str or "bloquea rst" in diag_str:
        recs.append("Probar manipulación de puerto origen (ej. 53 o 443)")

    if not recs:
        recs.append("Prueba técnicas generales de evasión con Nmap (--data-length, --source-port, -f)")

    return recs
