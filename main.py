#!/usr/bin/env python3
import argparse
import pyfiglet
from colorama import Fore, Style, init
from core import scanner, detection, suggestions
from utils.interpretation import mostrar_tablas
from utils.colors import Colors
from utils.messagesTool import mostrar_uso, descripcion_tool, error_falta_argumentos, option_help, option_target, option_port, option_interpretacion
#from utils.messagesTool import error_falta_argumentos
#from utils.messagesTool import descripcion_tool



# Inicializar colorama
init(autoreset=True)

# Banner de arranque
def banner():
    ascii_banner = pyfiglet.figlet_format("FireWall Detection")
    print(Colors.RED + ascii_banner + Colors.RESET)
    # print(Fore.GREEN + "\n JaLag\n" + Style.RESET_ALL)
    print(Colors.YELLOW + "🔥 Herramienta (básica) de detección de firewalls 🔥\n\n\n" + Colors.RESET)

# Errores personalizados
class CustomParser(argparse.ArgumentParser):
    def error(self, message):
        # Imprimir mensaje de error personalizado
        mostrar_uso() # Mostar uso de la heramienta
        print(f"{message}") # Mensaje de error
        exit(1) # Salir con el codigo de error

# Imprimir por pantalla la ayuda de forma personalizada
    def print_help(self):
        # Descripcion de la herramienta
        descripcion_tool()
        # Uso de la herramienta
        mostrar_uso()
        # Upciones de uso
        print("\nOpciones:")
        option_help()
        option_target()
        option_port()
        option_interpretacion()
        exit(0)

def main():
    banner()

    # Arumento de la CLI
    parser = CustomParser(
        prog="", # Qita main.py de los errores
        add_help=False # Desactiva el -h por defecto
        )
    parser.add_argument("-h", "--help", action="help", help="Muestra este mensaje de ayuda")
    parser.add_argument("-t", "--target", help="IP o dominio objetivo")
    parser.add_argument("-p", "--port", type=int, help="Puerto a probar")
    parser.add_argument("-i", "--interpretacion", action="store_true", help="Muestra tabla de interpretación de resultados")
    args = parser.parse_args()

    # Solo ver la interpretacion de tablas
    if args.interpretacion:
        mostrar_tablas()
        return
    
    # Si no se quiere ver la interpretacion, tarjet y puerto obligatorio
    if not args.target or not args.port:
        error_falta_argumentos()

    # Escaneo normal    
    print(Colors.CYAN + f"[+] Escaneando {args.target}:{args.port}...\n" + Colors.RESET)

    # Lanzar pruebas (SYN, ACK, FIN)
    results = scanner.run_test(args.target, args.port)

    # Mostrar resultados crudos
    for pkt, resp in results.items():
        color = Colors.GREEN if "RST" in resp else Colors.RED if "No response" in resp else Colors.YELLOW
        print(color + f"[!] {pkt} -> {resp}" + Colors.RESET)

    # Diagnóstico en base a las respuestas
    # diagnosis = detection.analyze(results)
    # print(Colors.MAGENTA+ f"\n[+] Diagnóstico: {diagnosis}" + Colors.RESET)

    # Sugerencias de bypass según el diagnóstico
    # Basar recomendaciones en los resultados crudos
    recs = []
    if "No response" in results.get("SYN", ""):
            recs.append("Probar manipulación de puerto origen (ej. 53 o 443)")

    if "No response" in results.get("ACK", ""):
            recs.append("Probar fragmentación de paquetes (-f en nmap)")

    if "No response" in results.get("NULL", "") or "No response" in results.get("XMAS", ""):
            recs.append("Intentar técnicas de evasión de firewall avanzadas (-MTU, --data-length)")

    if not recs:
        recs.append("Prueba técnicas generales de evasión con Nmap (--data-length, --source-port, -f)")

        # Generar recomendaciones basadas en los resultados
        recs = suggestions.get_recommendation(results)

        # Mostrar recomendaciones
        print(Colors.BLUE + "\n[+] Técnicas recomendadas:" + Colors.RESET)
        for r in recs:
            print(Colors.GREEN + f" - {r}" + Colors.RESET)

if __name__ == "__main__":
    main()