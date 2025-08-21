#!/usr/bin/env python3
import argparse
import pyfiglet
from colorama import init
from core import scanner
from utils.colors import Colors
from utils.interpretation import mostrar_tablas
from utils.messagesTool import mostrar_uso, descripcion_tool, error_falta_argumentos, option_help, option_target, option_port, option_interpretacion

# Inicializar colorama
init(autoreset=True)

def banner():
    ascii_banner = pyfiglet.figlet_format("FireWall Detection")
    print(Colors.RED + ascii_banner + Colors.RESET)
    print(Colors.YELLOW + "🔥 Herramienta (básica) de detección de firewalls 🔥\n\n\n" + Colors.RESET)

class CustomParser(argparse.ArgumentParser):
    def error(self, message):
        mostrar_uso()
        print(f"{message}")
        exit(1)

    def print_help(self):
        descripcion_tool()
        mostrar_uso()
        print("\nOpciones:")
        option_help()
        option_target()
        option_port()
        option_interpretacion()
        exit(0)

def main():
    banner()

    parser = CustomParser(prog="", add_help=False)
    parser.add_argument("-h", "--help", action="help", help="Muestra este mensaje de ayuda")
    parser.add_argument("-t", "--target", help="IP o dominio objetivo")
    parser.add_argument("-p", "--port", type=int, help="Puerto a probar")
    parser.add_argument("-i", "--interpretacion", action="store_true", help="Muestra tabla de interpretación de resultados")
    parser.add_argument("--quick", action="store_true", help="Escaneo rápido (solo SYN y ACK)")
    args = parser.parse_args()

    if args.interpretacion:
        mostrar_tablas()
        return

    if not args.target or not args.port:
        error_falta_argumentos()

    print(Colors.CYAN + f"[+] Escaneando {args.target}:{args.port}...\n" + Colors.RESET)
    scanner.run_full_scan(args.target, args.port, quick=args.quick)

if __name__ == "__main__":
    main()
