from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

# Coler personalizados
class Colors:
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    MAGENTA = Fore.MAGENTA
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE

    RESET = Style.RESET_ALL
    BRIGHT = Style.BRIGHT
    DIM = Style.DIM
    NORMAL = Style.NORMAL

    # Atajos
    SUCCESS = GREEN + BRIGHT
    ERROR = RED + BRIGHT
    WARNING = YELLOW + BRIGHT
    INFO = CYAN + NORMAL