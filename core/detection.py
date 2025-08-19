# /core/detection.py

def analyze(results):
    """
    Recibe diccionario con respuesta de SYN/ACK/FIN
    y devuelve un diagnostico simple
    """

    if all(v == "No response" for v in results.values()):
        return "Posible firewall stateful (ninguna respuesta)"
    
    if "ICMP" in str(results.values()):
        return "Posible filtrado por ACL / firewall básico"
    
    if "RST" in str(results.values()):
        return "Probablemente no hay firewall o el host rechaza conexiones"
    
    return "No se puedo determinar con certeza"
