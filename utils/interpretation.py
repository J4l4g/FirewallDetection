from colorama import Style, init
from tabulate import tabulate
from utils.colors import Colors

def mostrar_tablas():
    print(Colors.CYAN + Style.BRIGHT + "\n📘 Tabla de interpretación de respuestas\n" + Colors.RESET)

    # === SYN PACKETS ===
    syn_table = [
        [Colors.GREEN + "SA (SYN-ACK)" + Colors.RESET, "Puerto ABIERTO, sin firewall"],
        [Colors.RED + "RST" + Colors.RESET, "Puerto CERRADO, sin firewall"],
        [Colors.MAGENTA + "No respuesta" + Colors.RESET, "Firewall básico (DROP)"],
        [Colors.BLUE + "ICMP Prohibited" + Colors.RESET, "Firewall con REJECT (explícito)"],
    ]
    print(Colors.YELLOW + "\n=== SYN Packets ===" + Colors.RESET)
    print(tabulate(syn_table, headers=[Colors.CYAN + "Respuesta" + Colors.RESET, Colors.CYAN + "Interpretación" + Colors.RESET], tablefmt="fancy_grid"))

    # === ACK PACKETS ===
    ack_table = [
        [Colors.RED + "RST" + Colors.RESET, "Camino limpio, sin filtrado stateful"],
        [Colors.MAGENTA + "No respuesta" + Colors.RESET, "Firewall stateful descarta ACK inválidos"],
    ]
    print(Colors.YELLOW + "\n=== ACK Packets ===" + Colors.RESET)
    print(tabulate(ack_table, headers=[Colors.CYAN + "Respuesta" + Colors.RESET, Colors.CYAN + "Interpretación" + Colors.RESET], tablefmt="fancy_grid"))

    # === FIN PACKETS ===
    fin_table = [
        [Colors.RED + "RST" + Colors.RESET, "Puerto cerrado, camino limpio"],
        [Colors.MAGENTA + "No respuesta" + Colors.RESET, "Firewall filtrando anomalías o stack ignora FIN huérfanos"],
    ]
    print(Colors.YELLOW + "\n=== FIN Packets ===" + Colors.RESET)
    print(tabulate(fin_table, headers=[Colors.CYAN + "Respuesta" + Colors.RESET, Colors.CYAN + "Interpretación" + Colors.RESET], tablefmt="fancy_grid"))

    # === NULL PACKETS ===
    null_table = [
        [Colors.RED + "RST" + Colors.RESET, "Puerto cerrado, sin filtrado"],
        [Colors.MAGENTA + "No respuesta" + Colors.RESET, "Firewall filtra paquetes nulos"],
    ]
    print(Colors.YELLOW + "\n=== NULL Packets ===" + Colors.RESET)
    print(tabulate(null_table, headers=[Colors.CYAN + "Respuesta" + Colors.RESET, Colors.CYAN + "Interpretación" + Colors.RESET], tablefmt="fancy_grid"))

    # === XMAS PACKETS ===
    xmas_table = [
        [Colors.RED + "RST" + Colors.RESET, "Puerto cerrado, camino limpio"],
        [Colors.MAGENTA + "No respuesta" + Colors.RESET, "Firewall filtra paquetes XMAS"],
    ]
    print(Colors.YELLOW + "\n=== XMAS Packets ===" + Colors.RESET)
    print(tabulate(xmas_table, headers=[Colors.CYAN + "Respuesta" + Colors.RESET, Colors.CYAN + "Interpretación" + Colors.RESET], tablefmt="fancy_grid"))

    # === RST PACKETS ===
    rst_table = [
        [Colors.GREEN + "RST" + Colors.RESET, "Camino libre, puerto cerrado aceptando RST"],
        [Colors.MAGENTA + "No respuesta" + Colors.RESET, "Firewall bloquea RST"],
    ]
    print(Colors.YELLOW + "\n=== RST Packets ===" + Colors.RESET)
    print(tabulate(rst_table, headers=[Colors.CYAN + "Respuesta" + Colors.RESET, Colors.CYAN + "Interpretación" + Colors.RESET], tablefmt="fancy_grid"))

    # === RESUMEN ===
    resumen_table = [
        ["SA en SYN", "Abierto"],
        ["RST en SYN", "Cerrado"],
        ["No respuesta en SYN", "Firewall DROP"],
        ["ACK sin respuesta", "Firewall stateful"],
        ["FIN sin respuesta", "Firewall/stack ignora"],
        ["NULL sin respuesta", "Firewall filtra paquetes nulos"],
        ["XMAS sin respuesta", "Firewall filtra paquetes XMAS"],
        ["RST sin respuesta", "Firewall bloquea RST"],
    ]
    print(Colors.CYAN + "\n⚡ Resumen rápido:" + Colors.RESET)
    print(tabulate(resumen_table, headers=[Colors.CYAN + "Situación" + Colors.RESET, Colors.CYAN + "Conclusión" + Colors.RESET], tablefmt="grid"))
