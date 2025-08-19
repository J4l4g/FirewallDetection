from utils.colors import Colors
import sys

def mostrar_uso():
    print(Colors.CYAN + "\nUso: " + Colors.RESET + "python3 main.py -t <target> -p <port>" + Colors.RESET)

def descripcion_tool():
    print("FireWall Detection es una herramienta (Básica) realizada con Python y Scapy para la deteccion de firewall\ny poder obtener ayudas para en un futuro poder vulnerarlos, o simplemente enumerlos\n")

def option_help():
    print("  -h, --help            Muestra este mensaje de ayuda")

def option_target():
    print("  -t, --target TARGET   IP o dominio objetivo")

def option_port():
     print("  -p, --port PORT       Puerto a probar")

def option_interpretacion():
        print("  -i, --interpretacion  Muestra tabla de interpretación de resultados")

def error_falta_argumentos():
    print(Colors.RED + "\n[!] Los argumentos -t/--target y -p/--port son obligatorios salvo que uses -i o -h" + Colors.RESET)
    sys.exit(1)
